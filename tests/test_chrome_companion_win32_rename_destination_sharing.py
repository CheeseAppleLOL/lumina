"""
Slice 14 r2: raw NT FileRenameInformation destination-open semantics.

Controlled A/B experiment for legacy FileRenameInformation with
ReplaceIfExists=TRUE.

Microsoft's FileRenameInformation specification documents STATUS_ACCESS_DENIED
when the target file is open and ReplaceIfExists is nonzero. Therefore this
test does NOT claim FILE_SHARE_DELETE makes an already-open destination
replaceable.

Cases:
A. Destination closed -> replacement succeeds.
B. Destination open without FILE_SHARE_DELETE -> replacement is rejected.
C. Destination open WITH FILE_SHARE_DELETE -> replacement is also rejected.

The important distinction is that FILE_SHARE_DELETE controls whether another
open may request delete access; it does not by itself make the legacy
ReplaceIfExists rename operation safe against an already-open target.

No production code is modified. A standalone ctypes fallback is included.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

import pytest


ULONG_PTR = getattr(
    wintypes,
    "ULONG_PTR",
    ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32,
)
HANDLE = wintypes.HANDLE

STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

DELETE = 0x00010000
SYNCHRONIZE = 0x00100000
GENERIC_READ = 0x80000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 1
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

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
ntdll.NtCreateFile.restype = wintypes.LONG

ntdll.NtSetInformationFile.argtypes = [
    HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]
ntdll.NtSetInformationFile.restype = wintypes.LONG


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


FILENAME_OFFSET = RENAME_HEAD.FileNameLength.offset + ctypes.sizeof(wintypes.ULONG)


def _value(handle):
    if handle is None:
        return 0
    if isinstance(handle, ctypes.c_void_p):
        return int(handle.value or 0)
    value = getattr(handle, "value", None)
    if value is not None:
        return int(value or 0)
    return int(handle)


def _close(handle):
    value = _value(handle)
    if value:
        kernel32.CloseHandle(HANDLE(value))


def _open_dir(path: Path):
    h = kernel32.CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        HANDLE(0),
    )
    if _value(h) in (0, -1):
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def _open_existing(path: Path, share: int):
    h = kernel32.CreateFileW(
        str(path),
        GENERIC_READ,
        share,
        0,
        OPEN_EXISTING,
        0,
        HANDLE(0),
    )
    if _value(h) in (0, -1):
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def _oa(root, name: str):
    name_buf = ctypes.create_unicode_buffer(name)
    us = UNICODE_STRING()
    us.Length = len(name) * 2
    us.MaximumLength = us.Length + 2
    us.Buffer = ctypes.cast(name_buf, wintypes.LPWSTR)

    oa = OBJECT_ATTRIBUTES()
    oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    oa.RootDirectory = HANDLE(_value(root))
    oa.ObjectName = ctypes.pointer(us)
    oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
    return oa, us, name_buf


def _fallback_open(root, name, *, desired_access, create_disposition,
                   create_options):
    out = HANDLE()
    oa, us, name_buf = _oa(root, name)
    iosb = IO_STATUS_BLOCK()
    status = ntdll.NtCreateFile(
        ctypes.byref(out),
        desired_access | SYNCHRONIZE,
        ctypes.byref(oa),
        ctypes.byref(iosb),
        None,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        create_disposition,
        create_options,
        None,
        0,
    )
    return ctypes.c_uint32(status).value, out


def _fallback_rename(source, destination_root, destination_name):
    encoded = destination_name.encode("utf-16-le")
    total = FILENAME_OFFSET + len(encoded)
    buf = ctypes.create_string_buffer(total)

    head = RENAME_HEAD.from_buffer(buf)
    head.ReplaceIfExists = 1
    head.RootDirectory = HANDLE(_value(destination_root))
    head.FileNameLength = len(encoded)
    ctypes.memmove(
        ctypes.addressof(buf) + FILENAME_OFFSET,
        encoded,
        len(encoded),
    )

    iosb = IO_STATUS_BLOCK()
    status = ntdll.NtSetInformationFile(
        HANDLE(_value(source)),
        ctypes.byref(iosb),
        ctypes.byref(buf),
        total,
        10,  # FileRenameInformation
    )
    return ctypes.c_uint32(status).value


def _primitive():
    try:
        from chrome_companion.win32_primitives import (
            open_file_relative,
            rename_replace_relative,
        )
        return open_file_relative, rename_replace_relative
    except (ImportError, AttributeError):
        return _fallback_open, _fallback_rename


def _make_fixture(tmp_path: Path):
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"SOURCE-REPLACEMENT")
    destination.write_bytes(b"DESTINATION-ORIGINAL")
    return source, destination


def test_closed_destination_allows_replace(tmp_path: Path):
    source, destination = _make_fixture(tmp_path)
    root = _open_dir(tmp_path)
    source_handle = None

    try:
        open_relative, rename_relative = _primitive()
        status, source_handle = open_relative(
            root,
            source.name,
            desired_access=DELETE | GENERIC_READ,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        assert source_handle is not None

        status = rename_relative(source_handle, root, destination.name)
        assert status == STATUS_SUCCESS, hex(status)

    finally:
        _close(source_handle)
        _close(root)

    assert destination.read_bytes() == b"SOURCE-REPLACEMENT"
    assert not source.exists()


@pytest.mark.parametrize(
    "share",
    [
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    ],
    ids=["no-delete-share", "delete-share"],
)
def test_open_destination_blocks_legacy_replace_even_with_delete_share(
    tmp_path: Path, share: int
):
    source, destination = _make_fixture(tmp_path)

    root = _open_dir(tmp_path)
    source_handle = None
    blocker = None

    try:
        blocker = _open_existing(destination, share)

        open_relative, rename_relative = _primitive()
        status, source_handle = open_relative(
            root,
            source.name,
            desired_access=DELETE | GENERIC_READ,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        assert source_handle is not None

        status = rename_relative(source_handle, root, destination.name)

        # Microsoft documents STATUS_ACCESS_DENIED when the target is open
        # and ReplaceIfExists is nonzero for FileRenameInformation.
        assert status == STATUS_ACCESS_DENIED, hex(status)

    finally:
        _close(source_handle)
        _close(blocker)
        _close(root)

    assert source.read_bytes() == b"SOURCE-REPLACEMENT"
    assert destination.read_bytes() == b"DESTINATION-ORIGINAL"
