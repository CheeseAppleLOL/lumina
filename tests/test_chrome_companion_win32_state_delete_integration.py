import ctypes
import os
import subprocess
from pathlib import Path
from ctypes import wintypes

import pytest


# ---------------------------------------------------------------------------
# ctypes compatibility
# ---------------------------------------------------------------------------

ULONG_PTR = getattr(
    wintypes,
    "ULONG_PTR",
    ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32,
)


# ---------------------------------------------------------------------------
# Win32 constants are defined locally instead of assuming _winapi exports
# them.  This keeps the diagnostic independent of CPython's private
# _winapi constant surface.
# ---------------------------------------------------------------------------

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


# ---------------------------------------------------------------------------
# Standalone deletion fallback.
#
# The production delete_file_handle() may not exist yet.  This fallback lets
# the diagnostic exercise the REAL win32_state._delete_regular_at() caller
# without making the diagnostic depend on an unfinished production wrapper.
# ---------------------------------------------------------------------------

STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
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


def _status_u32(value):
    return ctypes.c_ulong(value).value


def _as_handle_pointer(handle):
    """Normalize CPython/ctypes HANDLE representations for Python 3.14."""
    if isinstance(handle, ctypes.c_void_p):
        return handle
    if hasattr(handle, "value"):
        return ctypes.c_void_p(handle.value)
    return ctypes.c_void_p(handle)


def _fallback_delete_file_handle(handle):
    info = _FILE_DISPOSITION_INFORMATION(1)
    iosb = _IO_STATUS_BLOCK()

    status = _NtSetInformationFile(
        _as_handle_pointer(handle),
        ctypes.byref(iosb),
        ctypes.byref(info),
        ctypes.sizeof(info),
        FILE_DISPOSITION_INFORMATION,
    )
    return _status_u32(status)


# Install the fallback only when the production wrapper is absent.
from chrome_companion import win32_primitives as _primitives

if not callable(getattr(_primitives, "delete_file_handle", None)):
    _primitives.delete_file_handle = _fallback_delete_file_handle


# Import the REAL state module after the fallback is available.
import chrome_companion.win32_state as _state


def _open_private_dir(path):
    """
    Return a CRT fd whose underlying Windows HANDLE refers to `path`.

    The path is explicitly converted to str before entering the Win32 API.
    The CRT fd is intentional: win32_state._delete_regular_at() expects a
    POSIX-style fd and obtains its Windows HANDLE through its own
    _handle_from_fd() boundary.
    """
    import _winapi
    import msvcrt

    handle = _winapi.CreateFile(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0,
    )

    # CPython's _winapi returns an integer HANDLE on Windows.  Convert it to
    # a CRT fd so the actual state-layer fd -> HANDLE path is exercised.
    return msvcrt.open_osfhandle(handle, os.O_RDONLY)


def test_real_state_delete_regular_at_deletes_regular_file(tmp_path: Path):
    target = tmp_path / "target.txt"
    target.write_bytes(b"DELETE-ME")

    dir_fd = _open_private_dir(tmp_path)
    try:
        result = _state._delete_regular_at(dir_fd, target.name)
        assert result is True
        assert not target.exists()
    finally:
        os.close(dir_fd)


def test_real_state_delete_regular_at_missing_file_is_false(tmp_path: Path):
    dir_fd = _open_private_dir(tmp_path)
    try:
        result = _state._delete_regular_at(dir_fd, "does-not-exist.txt")
        assert result is False
    finally:
        os.close(dir_fd)


def test_real_state_delete_regular_at_does_not_follow_final_directory_junction(
    tmp_path: Path,
):
    outside = tmp_path / "outside"
    root = tmp_path / "root"
    outside.mkdir()
    root.mkdir()

    protected = outside / "protected.txt"
    protected.write_bytes(b"OUTSIDE")

    junction = root / "target.txt"

    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(
            "directory junction creation unavailable: "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )

    dir_fd = _open_private_dir(root)
    try:
        result = _state._delete_regular_at(dir_fd, junction.name)
        assert result is False
        assert protected.read_bytes() == b"OUTSIDE"
        assert junction.is_dir()
    finally:
        os.close(dir_fd)
