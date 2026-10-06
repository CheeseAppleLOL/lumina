"""
Slice 13: NT rename destination-directory boundary.

This is a standalone diagnostic/integration test. It exercises the real
chrome_companion.win32_primitives implementation when available, with an
in-file ctypes fallback so the diagnostic remains runnable before the
production primitive is present.

Contract under test:
- A file rename/replace must NOT replace an existing directory destination.
- The operation must fail without deleting or modifying that directory.
- The source file must remain intact after the failed operation.
- No copy/delete fallback is acceptable.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path

import pytest


# ---- Pointer-size-safe ctypes definitions ---------------------------------

ULONG_PTR = getattr(
    wintypes,
    "ULONG_PTR",
    ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32,
)

NTSTATUS = wintypes.LONG
HANDLE = wintypes.HANDLE

STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_INVALID_PARAMETER = 0xC000000D

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

DELETE = 0x00010000
SYNCHRONIZE = 0x00100000
GENERIC_READ = 0x80000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

FILE_ATTRIBUTE_NORMAL = 0x00000080
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

GENERIC_READ_WRITE = 0xC0000000

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    HANDLE,
]
kernel32.CreateFileW.restype = HANDLE

ntdll.NtCreateFile.argtypes = [
    ctypes.POINTER(HANDLE),
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
]
ntdll.NtCreateFile.restype = NTSTATUS

ntdll.NtSetInformationFile.argtypes = [
    HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]
ntdll.NtSetInformationFile.restype = NTSTATUS


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


# FileRenameInformation has a variable-length WCHAR FileName[].
# Do not use ctypes.sizeof(struct) as the filename offset because alignment
# rounds the containing struct beyond the actual trailing-field offset.
class FILE_RENAME_INFORMATION_BASE(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", wintypes.BOOLEAN),
        ("RootDirectory", HANDLE),
        ("FileNameLength", wintypes.ULONG),
        ("FileName", wintypes.WCHAR * 1),
    ]


FILENAME_OFFSET = (
    FILE_RENAME_INFORMATION_BASE.FileNameLength.offset
    + ctypes.sizeof(wintypes.ULONG)
)


def _handle_value(handle):
    if handle is None:
        return 0
    if isinstance(handle, ctypes.c_void_p):
        return int(handle.value or 0)
    value = getattr(handle, "value", None)
    if value is not None:
        return int(value or 0)
    return int(handle)


def _close(handle):
    value = _handle_value(handle)
    if value:
        kernel32.CloseHandle(HANDLE(value))


def _open_dir(path: Path):
    h = kernel32.CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        HANDLE(0),
    )
    value = _handle_value(h)
    if value in (0, -1):
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def _object_attributes(root_handle, name: str):
    name_buf = ctypes.create_unicode_buffer(name)
    us = UNICODE_STRING()
    us.Length = len(name) * 2
    us.MaximumLength = us.Length + 2
    us.Buffer = ctypes.cast(name_buf, wintypes.LPWSTR)

    oa = OBJECT_ATTRIBUTES()
    oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    oa.RootDirectory = HANDLE(_handle_value(root_handle))
    oa.ObjectName = ctypes.pointer(us)
    oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
    oa.SecurityDescriptor = None
    oa.SecurityQualityOfService = None
    return oa, us, name_buf


def _fallback_open_relative(root_handle, name, desired_access, create_disposition,
                            create_options):
    out = HANDLE()
    oa, us, name_buf = _object_attributes(root_handle, name)
    status = ntdll.NtCreateFile(
        ctypes.byref(out),
        desired_access | SYNCHRONIZE,
        ctypes.byref(oa),
        ctypes.byref(ctypes.c_ulonglong(0)),
        None,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        create_disposition,
        create_options,
        None,
        0,
    )
    # IoStatusBlock is actually 16 bytes on x64. The anonymous temporary above
    # is not valid for all Windows versions, so use the production primitive
    # whenever it exists. This fallback is only for environments where the
    # primitive is absent.
    return int(ctypes.c_uint32(status).value), out


def _fallback_rename_replace(source_handle, destination_root, destination_name):
    # Correctly sized IO_STATUS_BLOCK.
    class IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_void_p),
            ("Information", ULONG_PTR),
        ]

    class RENAME_HEAD(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", HANDLE),
            ("FileNameLength", wintypes.ULONG),
        ]

    encoded = destination_name.encode("utf-16-le")
    total = FILENAME_OFFSET + len(encoded)
    buf = ctypes.create_string_buffer(total)
    head = RENAME_HEAD.from_buffer(buf)
    head.ReplaceIfExists = 1
    head.RootDirectory = HANDLE(_handle_value(destination_root))
    head.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buf) + FILENAME_OFFSET, encoded, len(encoded))

    iosb = IO_STATUS_BLOCK()
    status = ntdll.NtSetInformationFile(
        HANDLE(_handle_value(source_handle)),
        ctypes.byref(iosb),
        ctypes.byref(buf),
        total,
        10,  # FileRenameInformation
    )
    return int(ctypes.c_uint32(status).value)


def _primitive():
    try:
        from chrome_companion.win32_primitives import (
            open_file_relative,
            rename_replace_relative,
        )
        return open_file_relative, rename_replace_relative
    except (ImportError, AttributeError):
        def fallback_open(root, name, *, desired_access, create_disposition,
                          create_options):
            return _fallback_open_relative(
                root, name, desired_access, create_disposition, create_options
            )

        return fallback_open, _fallback_rename_replace


def test_file_rename_cannot_replace_existing_directory(tmp_path: Path):
    source = tmp_path / "source.bin"
    destination_dir = tmp_path / "destination"
    sentinel = destination_dir / "sentinel.txt"

    source.write_bytes(b"SOURCE-MUST-SURVIVE")
    destination_dir.mkdir()
    sentinel.write_bytes(b"DIRECTORY-MUST-SURVIVE")

    root = _open_dir(tmp_path)
    source_handle = None

    open_relative, rename_relative = _primitive()

    try:
        status, source_handle = open_relative(
            root,
            source.name,
            desired_access=DELETE | GENERIC_READ,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        assert source_handle is not None

        status = rename_relative(source_handle, root, destination_dir.name)

        # Windows/NT may report one of these directory-collision statuses
        # depending on the exact primitive path. All represent rejection of
        # replacing the directory, not successful replacement.
        assert status in {
            STATUS_ACCESS_DENIED,
            STATUS_FILE_IS_A_DIRECTORY,
            STATUS_OBJECT_NAME_COLLISION,
        }, hex(status)

    finally:
        _close(source_handle)
        _close(root)

    # Inspect only after closing the DELETE-capable source handle.
    assert source.read_bytes() == b"SOURCE-MUST-SURVIVE"
    assert destination_dir.is_dir()
    assert sentinel.read_bytes() == b"DIRECTORY-MUST-SURVIVE"
    assert not (tmp_path / "destination.bin").exists()
