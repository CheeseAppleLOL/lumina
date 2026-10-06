
"""Slice 12: Windows state rename cross-volume boundary.

Standalone diagnostic/integration test. It exercises the real
chrome_companion.win32_primitives.rename_replace_relative when present,
with an in-file low-level fallback for the primitive if needed.
"""
from __future__ import annotations

import ctypes
import os
import shutil
from pathlib import Path

import pytest
from ctypes import wintypes

STATUS_SUCCESS = 0x00000000
STATUS_NOT_SAME_DEVICE = 0xC00000D4

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_OPEN = 0x00000001
OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

ntdll.NtCreateFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), wintypes.ULONG, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
    wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
]
ntdll.NtCreateFile.restype = wintypes.LONG
ntdll.NtSetInformationFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG,
    wintypes.ULONG,
]
ntdll.NtSetInformationFile.restype = wintypes.LONG

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR)]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", wintypes.ULONG), ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p)]

class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_void_p)]

class FILE_RENAME_INFORMATION_BASE(ctypes.Structure):
    _fields_ = [("ReplaceIfExists", wintypes.BOOLEAN), ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.ULONG)]

FILENAME_OFFSET = (
    FILE_RENAME_INFORMATION_BASE.FileNameLength.offset + ctypes.sizeof(wintypes.ULONG)
)

def _handle_value(h):
    if isinstance(h, ctypes.c_void_p):
        return h.value
    v = getattr(h, "value", None)
    return v if v is not None else int(h)

def _close(h):
    if h is not None and _handle_value(h):
        kernel32.CloseHandle(wintypes.HANDLE(_handle_value(h)))

def _fallback_open_relative(root_handle, name, desired_access):
    name = str(name)
    root = wintypes.HANDLE(_handle_value(root_handle))
    us = UNICODE_STRING()
    buf = ctypes.create_unicode_buffer(name)
    us.Length = len(name.encode("utf-16-le"))
    us.MaximumLength = us.Length + 2
    us.Buffer = ctypes.cast(buf, wintypes.LPWSTR)
    oa = OBJECT_ATTRIBUTES(
        ctypes.sizeof(OBJECT_ATTRIBUTES), root, ctypes.pointer(us),
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, None, None
    )
    iosb = IO_STATUS_BLOCK()
    out = wintypes.HANDLE()
    status = ntdll.NtCreateFile(
        ctypes.byref(out), desired_access | SYNCHRONIZE,
        ctypes.byref(oa), ctypes.byref(iosb), None, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        None, 0
    )
    return status & 0xFFFFFFFF, out if _handle_value(out) else None

def _fallback_rename_replace_relative(source_handle, destination_dir_handle, name):
    name = str(name)
    encoded = name.encode("utf-16-le")
    total = FILENAME_OFFSET + len(encoded)
    buf = ctypes.create_string_buffer(total)
    ctypes.cast(buf, ctypes.POINTER(wintypes.BOOLEAN))[0] = True
    ctypes.cast(ctypes.byref(buf, 4), ctypes.POINTER(wintypes.HANDLE))[0] = wintypes.HANDLE(
        _handle_value(destination_dir_handle)
    )
    ctypes.cast(ctypes.byref(buf, 4 + ctypes.sizeof(wintypes.HANDLE)),
                ctypes.POINTER(wintypes.ULONG))[0] = len(encoded)
    ctypes.memmove(ctypes.addressof(buf) + FILENAME_OFFSET, encoded, len(encoded))
    iosb = IO_STATUS_BLOCK()
    status = ntdll.NtSetInformationFile(
        wintypes.HANDLE(_handle_value(source_handle)), ctypes.byref(iosb),
        ctypes.byref(buf), total, 10  # FileRenameInformation
    )
    return status & 0xFFFFFFFF

def _open_dir(path):
    h = kernel32.CreateFileW(
        str(path), 0x0001 | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0, 3, 0x02000000 | 0x00400000, 0
    )
    if _handle_value(h) in (None, -1):
        raise ctypes.WinError(ctypes.get_last_error())
    return h

def _primitive():
    try:
        from chrome_companion.win32_primitives import (
            open_file_relative, rename_replace_relative,
        )
        return open_file_relative, rename_replace_relative
    except (ImportError, AttributeError):
        return _fallback_open_relative, _fallback_rename_replace_relative

def test_cross_volume_relative_rename_is_rejected_without_partial_replacement(tmp_path: Path):
    """Cross-volume destination must not silently degrade into copy/delete."""
    # A relative RootDirectory rename cannot cross volumes. The test uses
    # an explicitly different Windows volume when one is available.
    volumes = []
    for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        p = Path(f"{drive}:\\")
        if p.exists():
            try:
                if os.path.splitdrive(str(tmp_path))[0].upper() != f"{drive}:":
                    volumes.append(p)
            except OSError:
                pass

    if not volumes:
        pytest.skip("No second accessible Windows volume is available")

    src = tmp_path / "source.bin"
    src.write_bytes(b"CROSS-VOLUME-SOURCE")
    destination_root = volumes[0] / f"lumina_slice12_{os.getpid()}"
    try:
        destination_root.mkdir()
    except OSError as exc:
        pytest.skip(f"Cannot create test directory on second volume: {exc}")

    src_dir = _open_dir(tmp_path)
    dst_dir = _open_dir(destination_root)
    open_relative, rename_relative = _primitive()
    source_handle = None
    try:
        status, source_handle = open_relative(
            src_dir, src.name,
            desired_access=DELETE | GENERIC_READ,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        assert source_handle is not None

        status = rename_relative(source_handle, dst_dir, "destination.bin")
        assert status == STATUS_NOT_SAME_DEVICE, hex(status)

        # The source HANDLE requests DELETE access. On Windows, a later
        # pathname-based open may be rejected while that HANDLE is still
        # alive, even though the HANDLE itself was opened with permissive
        # sharing. Close the tested source HANDLE before using pathlib so
        # this assertion measures the pathname state, not share semantics.
        _close(source_handle)
        source_handle = None

        assert src.read_bytes() == b"CROSS-VOLUME-SOURCE"
        assert not (destination_root / "destination.bin").exists()
    finally:
        _close(source_handle)
        _close(src_dir)
        _close(dst_dir)
        shutil.rmtree(destination_root, ignore_errors=True)
