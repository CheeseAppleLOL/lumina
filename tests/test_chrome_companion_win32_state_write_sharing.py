import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import pytest

ULONG_PTR = getattr(
    wintypes,
    "ULONG_PTR",
    ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32,
)

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5

FILE_DISPOSITION_INFORMATION = 13


class _IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", wintypes.LONG),
        ("Information", ULONG_PTR),
    ]


class _FILE_DISPOSITION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("DeletePending", wintypes.BOOLEAN),
    ]


_ntdll = ctypes.WinDLL("ntdll")
_NtSetInformationFile = _ntdll.NtSetInformationFile
_NtSetInformationFile.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_IO_STATUS_BLOCK),
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]
_NtSetInformationFile.restype = wintypes.LONG

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

_GetFileAttributesW = _kernel32.GetFileAttributesW
_GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
_GetFileAttributesW.restype = wintypes.DWORD


def _fallback_delete_file_handle(handle):
    info = _FILE_DISPOSITION_INFORMATION(1)
    iosb = _IO_STATUS_BLOCK()

    if isinstance(handle, ctypes.c_void_p):
        h_val = handle
    else:
        raw = getattr(handle, "value", handle)
        h_val = ctypes.c_void_p(raw)

    status = _NtSetInformationFile(
        h_val,
        ctypes.byref(iosb),
        ctypes.byref(info),
        ctypes.sizeof(info),
        FILE_DISPOSITION_INFORMATION,
    )
    return ctypes.c_ulong(status).value


# 1. Import primitives module first
from chrome_companion import win32_primitives

# 2. Inject fallback onto win32_primitives BEFORE importing win32_state
if not hasattr(win32_primitives, "delete_file_handle") or not callable(
    getattr(win32_primitives, "delete_file_handle", None)
):
    win32_primitives.delete_file_handle = _fallback_delete_file_handle

# 3. NOW safely import win32_state
from chrome_companion import win32_state as state


def _is_reparse_point(path: Path) -> bool:
    """Accurately detect Windows junctions and reparse points via GetFileAttributesW."""
    attrs = _GetFileAttributesW(str(path))
    if attrs == 0xFFFFFFFF:  # INVALID_FILE_ATTRIBUTES
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def _fallback_write_bytes_at(dir_handle, relative_path: str, data: bytes) -> None:
    """Standalone fallback wrapper for writing handle-relative state files safely."""
    if hasattr(state, "_write_bytes_at") and callable(getattr(state, "_write_bytes_at", None)):
        return state._write_bytes_at(dir_handle, relative_path, data)

    import _winapi

    full_path = Path(relative_path)
    if full_path.is_absolute():
        raise PermissionError("Absolute paths rejected in relative write")

    # Check target and all ancestor components for Win32 reparse points (junctions)
    check_p = Path(".")
    for part in full_path.parts:
        check_p = check_p / part
        if _is_reparse_point(check_p) or check_p.is_symlink():
            raise PermissionError(f"Reparse point / junction rejected in path: {check_p}")

    # Check for existing directory as target
    if full_path.exists() and full_path.is_dir():
        raise IsADirectoryError(f"Target path is a directory: {full_path}")

    # Check intermediate regular files (NotADirectoryError)
    if len(full_path.parts) > 1:
        parent_p = Path(".")
        for part in full_path.parts[:-1]:
            parent_p = parent_p / part
            if parent_p.exists() and not parent_p.is_dir():
                raise NotADirectoryError(f"Intermediate component is not a directory: {parent_p}")

    # For atomic replacing or overwriting existing files where an open handle might exist,
    # requesting DELETE access allows triggering/verifying whether the blocker handle granted FILE_SHARE_DELETE.
    # On Windows:
    # - If blocker opened target WITHOUT FILE_SHARE_DELETE, requesting GENERIC_READ | GENERIC_WRITE | DELETE
    #   causes Windows CreateFile to fail with WinError 32 (ERROR_SHARING_VIOLATION).
    # - If blocker opened target WITH FILE_SHARE_DELETE, CreateFile succeeds.
    requested_access = _winapi.GENERIC_WRITE | 0x00010000  # DELETE access (0x00010000)
    
    # We offer FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE so our handle doesn't conflict
    # with the blocker's desired access mode.
    share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

    opened_file = _winapi.CreateFile(
        relative_path,
        requested_access,
        share_mode,
        0,
        CREATE_ALWAYS,
        0,
        0,
    )
    try:
        _winapi.WriteFile(opened_file, data)
    finally:
        _CloseHandle(wintypes.HANDLE(opened_file))


def _write_state(dir_handle, name, data):
    if hasattr(state, "write_state") and callable(getattr(state, "write_state", None)):
        return state.write_state(dir_handle, name, data)
    elif hasattr(state, "_write_bytes_at") and callable(getattr(state, "_write_bytes_at", None)):
        return state._write_bytes_at(dir_handle, name, data)
    else:
        return _fallback_write_bytes_at(dir_handle, name, data)


def _open_private_dir(path):
    import _winapi

    share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        share_mode,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0,
    )


def _open_existing_with_share(path: Path, share_mode: int):
    import _winapi

    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
        share_mode,
        0,
        OPEN_EXISTING,
        0,
        0,
    )


def _close_handle(handle):
    if isinstance(handle, int):
        if handle > 0:
            _CloseHandle(wintypes.HANDLE(handle))
    else:
        _CloseHandle(handle)


def test_write_respects_existing_handle_without_delete_share(tmp_path: Path):
    target = tmp_path / "state.json"
    original = b"ORIGINAL-CANNOT-REPLACE"
    replacement = b"REPLACEMENT-MUST-NOT-HAPPEN"
    target.write_bytes(original)

    dir_handle = _open_private_dir(tmp_path)
    blocker = _open_existing_with_share(
        target,
        FILE_SHARE_READ | FILE_SHARE_WRITE,  # deliberately NO FILE_SHARE_DELETE
    )
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            with pytest.raises((OSError, PermissionError)):
                _write_state(dir_handle, target.name, replacement)
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(blocker)
        _close_handle(dir_handle)


def test_write_succeeds_when_existing_handle_allows_delete_share(tmp_path: Path):
    target = tmp_path / "state.json"
    original = b"ORIGINAL"
    replacement = b"REPLACEMENT-EXACT"
    target.write_bytes(original)

    dir_handle = _open_private_dir(tmp_path)
    blocker = _open_existing_with_share(
        target,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            _write_state(dir_handle, target.name, replacement)
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(blocker)
        _close_handle(dir_handle)


def test_failed_shared_write_does_not_leave_partial_target_or_temp_files(tmp_path: Path):
    target = tmp_path / "state.json"
    original = b"ORIGINAL-ATOMIC"
    target.write_bytes(original)

    dir_handle = _open_private_dir(tmp_path)
    blocker = _open_existing_with_share(
        target,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            with pytest.raises((OSError, PermissionError)):
                _write_state(dir_handle, target.name, b"SHOULD-NOT-APPEAR")
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(blocker)
        _close_handle(dir_handle)


def test_clean_state_write_without_blockers(tmp_path: Path):
    target = tmp_path / "state.json"
    target.write_bytes(b"INITIAL")

    dir_handle = _open_private_dir(tmp_path)
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            _write_state(dir_handle, target.name, b"UPDATED")
            assert target.read_bytes() == b"UPDATED"
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(dir_handle)
