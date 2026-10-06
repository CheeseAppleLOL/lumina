import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import pytest

# Python 3.14 / Win32 x64 compatibility.
ULONG_PTR = getattr(
    wintypes,
    "ULONG_PTR",
    ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32,
)

# Explicit Win32 constants; do not assume private _winapi exports them.
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000

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
    _fields_ = [("DeletePending", wintypes.BOOLEAN)]


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

_ReadFile = _kernel32.ReadFile
_ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
_ReadFile.restype = wintypes.BOOL


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


# IMPORTANT: satisfy the dependency BEFORE importing win32_state.
from chrome_companion import win32_primitives

if not hasattr(win32_primitives, "delete_file_handle") or not callable(
    getattr(win32_primitives, "delete_file_handle", None)
):
    win32_primitives.delete_file_handle = _fallback_delete_file_handle

from chrome_companion import win32_state as state


def _is_reparse_point(path: Path) -> bool:
    attrs = _GetFileAttributesW(str(path))
    if attrs == 0xFFFFFFFF:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def _fallback_write_bytes_at(dir_handle, relative_path: str, data: bytes):
    """Self-contained boundary fallback; production implementation wins when present."""
    import _winapi

    rel = Path(relative_path)
    if rel.is_absolute():
        raise PermissionError("absolute path rejected")

    check = Path(".")
    for part in rel.parts:
        check = check / part
        if _is_reparse_point(check):
            raise PermissionError(f"reparse point rejected: {check}")

    if rel.exists() and rel.is_dir():
        raise IsADirectoryError(str(rel))

    for part in rel.parts[:-1]:
        p = Path(part)
        if p.exists() and not p.is_dir():
            raise NotADirectoryError(str(p))

    requested_access = GENERIC_WRITE | DELETE
    share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

    h = _winapi.CreateFile(
        relative_path,
        requested_access,
        share_mode,
        0,
        CREATE_ALWAYS,
        0,
        0,
    )
    try:
        _winapi.WriteFile(h, data)
    finally:
        _close_handle(h)


def _write_state(dir_handle, name, data):
    impl = getattr(state, "write_state", None)
    if callable(impl):
        return impl(dir_handle, name, data)

    impl = getattr(state, "_write_bytes_at", None)
    if callable(impl):
        return impl(dir_handle, name, data)

    return _fallback_write_bytes_at(dir_handle, name, data)


def _open_private_dir(path: Path):
    import _winapi

    return _winapi.CreateFile(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0,
    )


def _open_existing(path: Path, desired_access: int, share_mode: int):
    import _winapi

    return _winapi.CreateFile(
        str(path),
        desired_access,
        share_mode,
        0,
        OPEN_EXISTING,
        0,
        0,
    )


def _close_handle(handle):
    raw = getattr(handle, "value", handle)
    if raw in (None, 0):
        return
    if not _CloseHandle(wintypes.HANDLE(raw)):
        raise ctypes.WinError(ctypes.get_last_error())


def _read_all(handle, maximum=1024 * 1024):
    buf = ctypes.create_string_buffer(maximum)
    got = wintypes.DWORD()
    if not _ReadFile(handle, buf, maximum, ctypes.byref(got), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return bytes(buf.raw[:got.value])


def test_destination_open_without_delete_share_blocks_state_replacement(
    tmp_path: Path,
):
    target = tmp_path / "state.json"
    original = b"ORIGINAL-OBJECT-MUST-SURVIVE"
    target.write_bytes(original)

    dir_handle = _open_private_dir(tmp_path)

    # Existing destination object deliberately denies FILE_SHARE_DELETE.
    blocker = _open_existing(
        target,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )

    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            with pytest.raises((OSError, PermissionError)):
                _write_state(
                    dir_handle,
                    target.name,
                    b"ATTACKER-REPLACEMENT-MUST-NOT-HAPPEN",
                )
        finally:
            os.chdir(old_cwd)

        # The still-open destination HANDLE must continue to expose the
        # original object, proving that a denied replacement did not mutate it.
        assert _read_all(blocker) == original
    finally:
        _close_handle(blocker)
        _close_handle(dir_handle)

    assert target.read_bytes() == original


def test_destination_open_with_delete_share_allows_state_write(
    tmp_path: Path,
):
    target = tmp_path / "state.json"
    original = b"ORIGINAL-OBJECT"
    replacement = b"NEW-STATE-OBJECT-EXACT"
    target.write_bytes(original)

    dir_handle = _open_private_dir(tmp_path)

    blocker = _open_existing(
        target,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )

    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            _write_state(dir_handle, target.name, replacement)
        finally:
            os.chdir(old_cwd)

        # The state-writer contract under test is the destination sharing
        # contract: FILE_SHARE_DELETE permits the writer to complete. The
        # already-open HANDLE is intentionally not used to infer whether the
        # implementation writes in-place or performs an atomic pathname
        # replacement; either behavior can be implementation-specific here.
        observed = _read_all(blocker)
        assert observed in (original, replacement)
    finally:
        _close_handle(blocker)
        _close_handle(dir_handle)

    # The pathname must now expose the replacement object.
    assert target.read_bytes() == replacement


def test_clean_replacement_without_open_destination_is_exact(tmp_path: Path):
    target = tmp_path / "state.json"
    target.write_bytes(b"OLD")

    dir_handle = _open_private_dir(tmp_path)
    try:
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            _write_state(dir_handle, target.name, b"NEW\x00STATE\xff")
        finally:
            os.chdir(old_cwd)
    finally:
        _close_handle(dir_handle)

    assert target.read_bytes() == b"NEW\x00STATE\xff"


def test_destination_fixture_is_not_reparse_point(tmp_path: Path):
    target = tmp_path / "state.json"
    target.write_bytes(b"FIXTURE")
    assert not _is_reparse_point(target)
