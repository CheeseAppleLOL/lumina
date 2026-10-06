"""Windows state backend for Chrome Companion.

This is the Windows counterpart of state_posix.py. It deliberately uses the
experimentally verified NT handle-relative primitives from win32_primitives.py.
Directory handles are exposed as CRT file descriptors so existing installer
callers can continue to use os.close().
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from chrome_companion import protocol
from chrome_companion.win32_primitives import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DIRECTORY_FILE,
    FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_SYNCHRONOUS_IO_NONALERT,
    FILE_WRITE_DATA,
    FILE_APPEND_DATA,
    FILE_OPEN,
    FILE_OPEN_IF,
    FILE_CREATE,
    FILE_NON_DIRECTORY_FILE,
    FILE_WRITE_ATTRIBUTES,
    DELETE,
    SYNCHRONIZE,
    STATUS_ACCESS_DENIED,
    STATUS_REPARSE_POINT_ENCOUNTERED,
    STATUS_SUCCESS,
    close_handle,
    delete_file_handle,
    get_file_attributes,
    open_directory_absolute,
    open_directory_relative,
    open_file_relative,
    rename_replace_relative,
    write_all,
    flush_file,
)

COMPANION_DIRNAME = "chrome_companion"
INSTALL_FILENAME = "install.json"
PAIRING_FILENAME = "pairing.json"
STATE_VERSION = 1
_TEMP_ATTEMPTS = 16
_MAX_STATE_BYTES = 1 << 20


class StateError(Exception):
    """Local companion state is missing, malformed, or insecurely stored."""


@dataclass(frozen=True)
class InstallRecord:
    extension_origin: str
    socket_path: str
    installed_at: float


@dataclass(frozen=True)
class PairingRecord:
    instance_id: str
    extension_origin: str
    paired_at: float


def companion_dir(data_dir) -> Path:
    return Path(data_dir) / COMPANION_DIRNAME


def absolute_path(path) -> Path:
    text = os.fspath(path)
    if not os.path.isabs(text):
        text = os.path.join(os.getcwd(), text)
    return Path(text)


def _sid_bytes_for_current_user() -> bytes:
    # GetTokenInformation(TokenUser) -> SID bytes. This is used only for the
    # identity-scoped pipe name in this slice; ACL authorization belongs to the
    # transport layer.
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    token = ctypes.c_void_p()
    if not advapi.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), ctypes.FormatError(ctypes.get_last_error()))
    try:
        size = ctypes.c_ulong()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not size.value:
            raise OSError(ctypes.get_last_error(), "GetTokenInformation size failed")
        buf = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buf, size.value, ctypes.byref(size)):
            err=ctypes.get_last_error(); raise OSError(err, ctypes.FormatError(err))
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        # TOKEN_USER starts with a SID_AND_ATTRIBUTES containing the SID ptr.
        sid = ctypes.cast(sid_ptr, ctypes.POINTER(ctypes.c_ubyte))
        # Read SID length from the SID itself.
        sid_len = int(sid[1]) + 8 + int(sid[0]) * 4
        return ctypes.string_at(sid_ptr, sid_len)
    finally:
        kernel32.CloseHandle(token)


def _current_sid_string() -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    sid = _sid_bytes_for_current_user()
    sid_buf = ctypes.create_string_buffer(sid)
    out = ctypes.c_wchar_p()
    if not advapi.ConvertSidToStringSidW(ctypes.byref(sid_buf), ctypes.byref(out)):
        err=ctypes.get_last_error(); raise OSError(err, ctypes.FormatError(err))
    try:
        return out.value
    finally:
        ctypes.WinDLL("kernel32", use_last_error=True).LocalFree(out)


def _fd_from_handle(handle) -> int:
    """Adopt a Win32 HANDLE into a CRT file descriptor.

    ``wintypes.HANDLE`` is a ``ctypes.c_void_p`` on 64-bit Windows.  On
    Python 3.14, converting that ctypes object with ``int(handle)`` does not
    yield the native handle value; ``handle.value`` is the authoritative
    integer HANDLE.
    """
    import msvcrt

    value = getattr(handle, "value", handle)
    if value is None:
        close_handle(handle)
        raise OSError("invalid NULL handle")
    value = int(value)

    fd = msvcrt.open_osfhandle(value, 0)
    if fd < 0:
        close_handle(handle)
        raise OSError("open_osfhandle failed")
    return fd


def _handle_from_fd(fd: int):
    import msvcrt
    return ctypes.c_void_p(msvcrt.get_osfhandle(fd))


def _close_handle(fd: int) -> None:
    os.close(fd)


def _is_reparse(handle) -> bool:
    return bool(get_file_attributes(handle) & FILE_ATTRIBUTE_REPARSE_POINT)


def _split_absolute(path: Path) -> tuple[str, list[str]]:
    text = os.fspath(path)
    if not os.path.isabs(text):
        raise StateError(f"path is not absolute: {path}")
    drive, tail = os.path.splitdrive(text)
    if not drive or not tail.startswith(("\\", "/")):
        raise StateError(f"unsupported Windows path: {path}")
    # This first slice intentionally supports local drive paths. UNC support is
    # a separate transport/filesystem decision and is not silently approximated.
    if drive.startswith("\\\\"):
        raise StateError(f"UNC paths are not supported by the Windows state backend: {path}")
    parts = [p for p in tail.replace("/", "\\").split("\\") if p not in ("", ".")]
    return drive + "\\", parts


def _open_root(path: Path, *, create: bool) -> int:
    root_path, parts = _split_absolute(path)
    try:
        root = open_directory_absolute(root_path)
    except OSError as exc:
        raise StateError(f"refusing {path}: cannot open drive root") from exc
    try:
        if _is_reparse(root):
            raise StateError(f"refusing {path}: drive root is a reparse point")
        current = root
        for index, name in enumerate(parts):
            status, child = open_directory_relative(current, name, create=create)
            if status != STATUS_SUCCESS:
                if create and status == STATUS_ACCESS_DENIED:
                    raise StateError(f"refusing {path}: cannot create directory component {name}")
                if status == STATUS_REPARSE_POINT_ENCOUNTERED:
                    raise StateError(f"refusing {path}: reparse point encountered")
                raise StateError(f"refusing {path}: NtCreateFile status 0x{status:08X}")
            if child is None:
                raise StateError(f"refusing {path}: directory component could not be opened")
            if _is_reparse(child):
                close_handle(child); raise StateError(f"refusing {path}: reparse point encountered")
            if current != root:
                close_handle(current)
            current = child
        return _fd_from_handle(current)
    except BaseException:
        try: close_handle(current)
        except Exception: pass
        raise


def ensure_private_dir(path) -> Path:
    path = absolute_path(path)
    fd = open_trusted_dir(path, create=True, private=True)
    os.close(fd)
    return path


def open_trusted_dir(path, *, create: bool = False, private: bool = False) -> int:
    # Windows ACLs are inherited from the parent; this slice requires the
    # resulting object not to be a reparse point and relies on the user's
    # normal per-user LocalAppData/temp ACL. A later ACL-audit slice will make
    # explicit non-owner ACE checks before production use.
    return _open_root(absolute_path(path), create=create)


def open_private_subdir(parent_fd: int, name: str, *, create: bool, path) -> int:
    parent = _handle_from_fd(parent_fd)
    status, child = open_directory_relative(parent, name, create=create)
    if status != STATUS_SUCCESS or child is None:
        if status == STATUS_REPARSE_POINT_ENCOUNTERED:
            raise StateError(f"refusing {path}: reparse point encountered")
        raise StateError(f"refusing {path}: NtCreateFile status 0x{status:08X}")
    if _is_reparse(child):
        close_handle(child); raise StateError(f"refusing {path}: reparse point encountered")
    return _fd_from_handle(child)


def open_companion_dir(data_dir, *, create: bool) -> int:
    base = open_trusted_dir(data_dir, create=create, private=False)
    try:
        return open_private_subdir(base, COMPANION_DIRNAME, create=create, path=companion_dir(data_dir))
    finally:
        os.close(base)


def check_data_dir(data_dir) -> bool:
    try:
        fd = open_trusted_dir(data_dir, create=False, private=False)
    except StateError:
        if not absolute_path(data_dir).exists():
            return False
        raise
    os.close(fd)
    return True


def _temp_token() -> str:
    return secrets.token_hex(8)


def write_file_at(dir_fd: int, name: str, data: bytes, *, mode: int, path) -> None:
    parent = _handle_from_fd(dir_fd)
    # Existing target must be an ordinary file. OPEN_REPARSE_POINT + the
    # attribute check prevents silently following a final reparse point.
    status, existing = open_file_relative(
        parent, name,
        desired_access=FILE_READ_ATTRIBUTES,
        create_disposition=FILE_OPEN,
        create_options=FILE_NON_DIRECTORY_FILE,
    )
    if status == STATUS_SUCCESS and existing is not None:
        try:
            if _is_reparse(existing):
                raise StateError(f"refusing to replace {path}: reparse point")
        finally:
            close_handle(existing)
    elif status not in (0xC0000034,):  # STATUS_OBJECT_NAME_NOT_FOUND
        if status != STATUS_SUCCESS:
            # A missing file is expected; other failures are not.
            if status != 0xC0000034:
                raise StateError(f"refusing to replace {path}: NtCreateFile status 0x{status:08X}")

    tmp = None
    try:
        for _ in range(_TEMP_ATTEMPTS):
            candidate = f".{name}.{_temp_token()}.tmp"
            status, handle = open_file_relative(
                parent, candidate,
                desired_access=FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                create_disposition=FILE_CREATE,
                create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            )
            if status == STATUS_SUCCESS:
                tmp = candidate
                break
        if tmp is None or handle is None:
            raise StateError(f"cannot create a private temporary file next to {path}")
        try:
            write_all(handle, data)
            flush_file(handle)
        finally:
            close_handle(handle)
        status, target_dir_handle = (STATUS_SUCCESS, parent)
        status = rename_replace_relative(_handle_from_fd(dir_fd), target_dir_handle, name) if False else STATUS_SUCCESS
        # The rename primitive operates on an opened source handle, so reopen
        # the temporary file by handle-relative name before renaming it.
        status, source = open_file_relative(parent, tmp, desired_access=DELETE | FILE_READ_ATTRIBUTES,
                                            create_disposition=FILE_OPEN,
                                            create_options=FILE_NON_DIRECTORY_FILE)
        if status != STATUS_SUCCESS or source is None:
            raise StateError(f"temporary file disappeared before publish: 0x{status:08X}")
        try:
            status = rename_replace_relative(source, parent, name)
        finally:
            close_handle(source)
        if status != STATUS_SUCCESS:
            raise StateError(f"atomic replacement failed: NtSetInformationFile status 0x{status:08X}")
    finally:
        if tmp is not None:
            # If rename succeeded this is already absent. If it failed, remove
            # only the exact temporary name relative to the anchored parent.
            try:
                _delete_regular_at(dir_fd, tmp)
            except OSError:
                pass


def write_private_json_at(dir_fd: int, name: str, value: dict, *, path) -> None:
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    write_file_at(dir_fd, name, text.encode("utf-8"), mode=0o600, path=path)


def write_private_json(path, value: dict) -> None:
    path = Path(path)
    fd = open_trusted_dir(path.parent, create=True, private=True)
    try: write_private_json_at(fd, path.name, value, path=path)
    finally: os.close(fd)


def read_private_json_at(dir_fd: int, name: str, *, path) -> dict | None:
    parent = _handle_from_fd(dir_fd)
    status, handle = open_file_relative(parent, name, desired_access=FILE_READ_ATTRIBUTES | 0x1,
                                        create_disposition=FILE_OPEN,
                                        create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)
    if status == 0xC0000034:
        return None
    if status != STATUS_SUCCESS or handle is None:
        raise StateError(f"not a regular file: {path}")
    try:
        if _is_reparse(handle):
            raise StateError(f"not a regular file: {path}")
        # Use the CRT fd only after the NT handle has been securely acquired.
        fd = _fd_from_handle(handle); handle = None
        try:
            chunks=[]; size=0
            while size <= _MAX_STATE_BYTES:
                chunk=os.read(fd,65536)
                if not chunk: break
                chunks.append(chunk); size += len(chunk)
        finally: os.close(fd)
    finally:
        if handle is not None:
            close_handle(handle)
    if size > _MAX_STATE_BYTES:
        raise StateError(f"unreadable state file {path}: state file too large")
    try: value=json.loads(b"".join(chunks).decode("utf-8"))
    except ValueError as exc: raise StateError(f"unreadable state file {path}: {exc}") from exc
    if not isinstance(value,dict) or value.get("version") != STATE_VERSION:
        raise StateError(f"unsupported state file {path}")
    return value


def read_private_json(path) -> dict | None:
    path=Path(path)
    try: fd=open_trusted_dir(path.parent,private=True)
    except StateError: return None if not path.parent.exists() else (_ for _ in ()).throw(StateError(f"refusing {path}: insecure directory"))
    try: return read_private_json_at(fd,path.name,path=path)
    finally: os.close(fd)


def _delete_regular_at(dir_fd: int, name: str) -> bool:
    parent = _handle_from_fd(dir_fd)
    status, handle = open_file_relative(
        parent,
        name,
        desired_access=DELETE | FILE_READ_ATTRIBUTES,
        create_disposition=FILE_OPEN,
        create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    if status == 0xC0000034:
        return False
    if status != STATUS_SUCCESS or handle is None:
        return False
    try:
        if _is_reparse(handle):
            return False
        delete_status = delete_file_handle(handle)
        if delete_status != STATUS_SUCCESS:
            raise OSError(f"NtSetInformationFile delete failed: 0x{delete_status:08X}")
        return True
    finally:
        close_handle(handle)


def remove_regular_at(dir_fd: int, name: str) -> bool:
    return _delete_regular_at(dir_fd, name)


def default_socket_path(companion_fd:int,data_dir)->str:
    sid=_current_sid_string()
    digest=hashlib.sha256(sid.encode("utf-8")).hexdigest()[:12]
    return rf"\\.\pipe\lumina-companion-{digest}"


def normalize_instance_id(text)->str:
    if not isinstance(text,str): raise StateError("instance ID must be text")
    cleaned="".join(ch for ch in text.strip().lower() if ch not in "- ")
    if not protocol.is_hex_id(cleaned): raise StateError("instance ID must be 32 hex characters (dashes optional)")
    return cleaned


def format_instance_id(instance_id:str)->str:
    return "-".join(instance_id[i:i+4] for i in range(0,len(instance_id),4))


def instance_fingerprint(instance_id:str)->str:
    return hashlib.sha256(instance_id.encode("utf-8")).hexdigest()[:12]


def _open_existing_companion_dir(data_dir):
    try:return open_companion_dir(data_dir,create=False)
    except StateError:return None


def load_install(data_dir):
    fd=_open_existing_companion_dir(data_dir)
    if fd is None:return None
    try:value=read_private_json_at(fd,INSTALL_FILENAME,path=companion_dir(data_dir)/INSTALL_FILENAME)
    finally:os.close(fd)
    if value is None:return None
    origin=value.get("extension_origin"); socket_path=value.get("socket_path")
    if protocol.extension_id_from_origin(origin) is None:raise StateError("install.json has an invalid extension origin")
    if not isinstance(socket_path,str) or not socket_path:raise StateError("install.json has an invalid socket path")
    return InstallRecord(origin,socket_path,float(value.get("installed_at",0)))


def save_install_at(dir_fd,data_dir,*,extension_id,socket_path):
    origin=protocol.extension_origin(extension_id)
    if not isinstance(socket_path,str) or not socket_path:raise StateError("socket path must be non-empty")
    record=InstallRecord(origin,socket_path,time.time())
    write_private_json_at(dir_fd,INSTALL_FILENAME,{"version":STATE_VERSION,"extension_origin":origin,"socket_path":socket_path,"installed_at":record.installed_at},path=companion_dir(data_dir)/INSTALL_FILENAME)
    return record


def save_install(data_dir,*,extension_id,socket_path):
    fd=open_companion_dir(data_dir,create=True)
    try:return save_install_at(fd,data_dir,extension_id=extension_id,socket_path=socket_path)
    finally:os.close(fd)


def load_pairing(data_dir):
    fd=_open_existing_companion_dir(data_dir)
    if fd is None:return None
    try:value=read_private_json_at(fd,PAIRING_FILENAME,path=companion_dir(data_dir)/PAIRING_FILENAME)
    finally:os.close(fd)
    if value is None:return None
    instance_id=value.get("instance_id"); origin=value.get("extension_origin")
    if not protocol.is_hex_id(instance_id) or protocol.extension_id_from_origin(origin) is None:raise StateError("pairing.json is malformed")
    return PairingRecord(instance_id,origin,float(value.get("paired_at",0)))


def save_pairing(data_dir,*,instance_id,extension_origin):
    instance_id=normalize_instance_id(instance_id)
    if protocol.extension_id_from_origin(extension_origin) is None:raise StateError("invalid extension origin")
    record=PairingRecord(instance_id,extension_origin,time.time())
    fd=open_companion_dir(data_dir,create=True)
    try:write_private_json_at(fd,PAIRING_FILENAME,{"version":STATE_VERSION,"instance_id":instance_id,"extension_origin":extension_origin,"paired_at":record.paired_at},path=companion_dir(data_dir)/PAIRING_FILENAME)
    finally:os.close(fd)
    return record


def clear_pairing(data_dir):
    install=load_install(data_dir); fd=_open_existing_companion_dir(data_dir)
    if fd is None:return False
    try:
        if not _delete_regular_at(fd, PAIRING_FILENAME):
            return False
        from chrome_companion.owner_control import retire_live_connection
        try:retire_live_connection(install.socket_path if install else None,"unpaired")
        except OSError as exc:raise StateError(f"pairing removed but live connection retirement was not confirmed: {exc}") from exc
        return True
    finally:os.close(fd)
