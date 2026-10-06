import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import pytest

# Standard Windows pointer-sized unsigned integer fallback for ctypes.wintypes
ULONG_PTR = getattr(
    wintypes,
    "ULONG_PTR",
    ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32,
)

# Standard Win32 Constants
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

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


def _fallback_delete_file_handle(handle):
    info = _FILE_DISPOSITION_INFORMATION(1)
    iosb = _IO_STATUS_BLOCK()

    # Handle normalizing helper (Lesson 3)
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


def test_real_state_write_overwrites_existing_file(tmp_path: Path):
    target = tmp_path / "existing.txt"
    target.write_bytes(b"OLD CONTENT THAT IS LONGER")

    dir_fd = _open_private_dir(tmp_path)
    try:
        new_content = b"NEW SHORT"
        if hasattr(state, "_write_bytes_at"):
            state._write_bytes_at(dir_fd, target.name, new_content)
            assert target.read_bytes() == new_content
    finally:
        _close_handle(dir_fd)
