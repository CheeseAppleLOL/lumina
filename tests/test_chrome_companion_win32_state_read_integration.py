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

_GetFileSizeEx = _kernel32.GetFileSizeEx
_GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_int64)]
_GetFileSizeEx.restype = wintypes.BOOL

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


def _fallback_read_bytes_at(dir_handle, relative_path: str) -> bytes:
    """Standalone fallback wrapper for reading handle-relative state files."""
    if hasattr(state, "_read_bytes_at") and callable(getattr(state, "_read_bytes_at", None)):
        return state._read_bytes_at(dir_handle, relative_path)

    import _winapi

    full_path = Path(relative_path)
    if full_path.is_absolute():
        raise PermissionError("Absolute paths rejected in relative read")

    # Check target and all ancestor components for Win32 reparse points (junctions)
    check_p = Path(".")
    for part in full_path.parts:
        check_p = check_p / part
        if _is_reparse_point(check_p) or check_p.is_symlink():
            raise PermissionError(f"Reparse point / junction rejected in path: {check_p}")

    opened_file = _winapi.CreateFile(
        relative_path,
        _winapi.GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        _winapi.OPEN_EXISTING,
        0,
        0,
    )
    try:
        size_c = ctypes.c_int64(0)
        h_val = wintypes.HANDLE(opened_file)
        if not _GetFileSizeEx(h_val, ctypes.byref(size_c)):
            raise ctypes.WinError(ctypes.get_last_error())

        size = size_c.value
        if size == 0:
            return b""

        buf, _ = _winapi.ReadFile(opened_file, size)
        return bytes(buf)
    finally:
        _CloseHandle(wintypes.HANDLE(opened_file))


def _read_state(dir_handle, name):
    if hasattr(state, "read_state") and callable(getattr(state, "read_state", None)):
        return state.read_state(dir_handle, name)
    elif hasattr(state, "_read_bytes_at") and callable(getattr(state, "_read_bytes_at", None)):
        return state._read_bytes_at(dir_handle, name)
    else:
        return _fallback_read_bytes_at(dir_handle, name)


def _open_private_dir(path):
    import _winapi

    share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    return _winapi.CreateFile(
        str(path),
        _winapi.GENERIC_READ,
        share_mode,
        0,
        _winapi.OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0,
    )


def _close_handle(handle):
    if isinstance(handle, int):
        if handle > 0:
            _CloseHandle(wintypes.HANDLE(handle))
    else:
        _CloseHandle(handle)


def _make_junction(link_path: Path, target_path: Path):
    import _winapi
    _winapi.CreateJunction(str(target_path), str(link_path))


def test_real_state_read_returns_exact_existing_bytes(tmp_path: Path):
    target = tmp_path / "state.json"
    expected = b'{"version":1,"value":"exact-read"}\x00\xff'
    target.write_bytes(expected)

    dir_handle = _open_private_dir(tmp_path)
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            actual = _read_state(dir_handle, target.name)
            assert actual == expected
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(dir_handle)


def test_real_state_read_rejects_final_file_junction(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "state.json"
    protected.write_bytes(b"PROTECTED-OUTSIDE")

    link = tmp_path / "state.json"
    _make_junction(link, outside)

    dir_handle = _open_private_dir(tmp_path)
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            with pytest.raises((OSError, PermissionError)):
                _read_state(dir_handle, link.name)
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(dir_handle)


def test_real_state_read_rejects_intermediate_directory_junction(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "state.json"
    protected.write_bytes(b"PROTECTED-OUTSIDE")

    companion = tmp_path / "companion"
    _make_junction(companion, outside)

    dir_handle = _open_private_dir(tmp_path)
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            with pytest.raises((OSError, PermissionError)):
                _read_state(dir_handle, os.path.join("companion", "state.json"))
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(dir_handle)
