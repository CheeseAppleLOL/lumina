"""Windows filesystem primitives for the Chrome Companion state backend.

These operations are based on experimentally verified Windows NT semantics:

* NtCreateFile with RootDirectory for descriptor-relative acquisition.
* OBJ_DONT_REPARSE for rejecting reparse-point traversal.
* Native Windows HANDLE ownership and CloseHandle cleanup.
* FlushFileBuffers for durable writes.
* NtSetInformationFile(FileRenameInformation) with RootDirectory for
  relative atomic replacement.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Optional, Tuple


# ---------------------------------------------------------------------------
# Special Handle Values
# ---------------------------------------------------------------------------

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ---------------------------------------------------------------------------
# NTSTATUS values
# ---------------------------------------------------------------------------

STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B
STATUS_NOT_SAME_DEVICE = 0xC00000D4
STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA


def status_u32(status: int) -> int:
    """Normalize a signed/unsigned NTSTATUS value to uint32."""
    return int(status) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# NT object / access constants
# ---------------------------------------------------------------------------

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_APPEND_DATA = 0x00000004
FILE_READ_ATTRIBUTES = 0x00000080
FILE_WRITE_ATTRIBUTES = 0x00000100

DELETE = 0x00010000
SYNCHRONIZE = 0x00100000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001
FILE_CREATE = 0x00000002
FILE_OPEN_IF = 0x00000003

FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

FILE_OPEN_REPARSE_POINT = 0x00200000

FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

FILE_RENAME_INFORMATION = 10
FILE_DISPOSITION_INFORMATION = 13


# ---------------------------------------------------------------------------
# Win32 constants used by CreateFileW
# ---------------------------------------------------------------------------

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5

FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


# ---------------------------------------------------------------------------
# Pointer-sized helpers
# ---------------------------------------------------------------------------

ULONG_PTR = getattr(
    wintypes,
    "ULONG_PTR",
    ctypes.c_uint64
    if ctypes.sizeof(ctypes.c_void_p) == 8
    else ctypes.c_uint32,
)


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", wintypes.LPVOID),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", wintypes.LONG),
        ("Information", ULONG_PTR),
    ]


class FILE_RENAME_INFORMATION_BASE(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", wintypes.BOOLEAN),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.ULONG),
    ]


class FILE_DISPOSITION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("DeleteFile", wintypes.BOOLEAN),
    ]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


# ---------------------------------------------------------------------------
# DLL bindings
# ---------------------------------------------------------------------------

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll")

CreateFileW = _kernel32.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
CreateFileW.restype = wintypes.HANDLE

CloseHandle = _kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

WriteFile = _kernel32.WriteFile
WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
WriteFile.restype = wintypes.BOOL

ReadFile = _kernel32.ReadFile
ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
ReadFile.restype = wintypes.BOOL

FlushFileBuffers = _kernel32.FlushFileBuffers
FlushFileBuffers.argtypes = [wintypes.HANDLE]
FlushFileBuffers.restype = wintypes.BOOL

GetFileInformationByHandle = _kernel32.GetFileInformationByHandle
GetFileInformationByHandle.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
]
GetFileInformationByHandle.restype = wintypes.BOOL

NtCreateFile = _ntdll.NtCreateFile
NtCreateFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    wintypes.LPVOID,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.LPVOID,
    wintypes.ULONG,
]
NtCreateFile.restype = wintypes.LONG

NtSetInformationFile = _ntdll.NtSetInformationFile
NtSetInformationFile.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(IO_STATUS_BLOCK),
    wintypes.LPVOID,
    wintypes.ULONG,
    wintypes.ULONG,
]
NtSetInformationFile.restype = wintypes.LONG


# ---------------------------------------------------------------------------
# HANDLE helpers
# ---------------------------------------------------------------------------

def normalize_handle(handle) -> int:
    """Return a raw integer HANDLE value from common ctypes representations."""
    if handle is None:
        raise ValueError("HANDLE is None")

    if isinstance(handle, ctypes.c_void_p):
        value = handle.value
    elif hasattr(handle, "value"):
        value = handle.value
    else:
        value = handle

    if value is None:
        raise ValueError("HANDLE is NULL")

    value = int(value)

    if value == 0:
        raise ValueError("HANDLE is NULL")

    if value == INVALID_HANDLE_VALUE:
        raise ValueError("HANDLE is INVALID_HANDLE_VALUE")

    return value


def close_handle(handle) -> None:
    """Close a raw Windows kernel HANDLE."""
    if handle is None:
        return

    try:
        value = normalize_handle(handle)
    except ValueError:
        return

    if not CloseHandle(wintypes.HANDLE(value)):
        raise ctypes.WinError(ctypes.get_last_error())


# ---------------------------------------------------------------------------
# OBJECT_ATTRIBUTES
# ---------------------------------------------------------------------------

def _object_attributes(
    root_handle,
    name: str,
    *,
    dont_reparse: bool = True,
):
    """Build OBJECT_ATTRIBUTES for a name relative to root_handle."""
    name = str(name)

    name_buffer = ctypes.create_unicode_buffer(name)

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    byte_length = len(name) * ctypes.sizeof(wintypes.WCHAR)

    unicode_string = UNICODE_STRING(
        byte_length,
        byte_length + ctypes.sizeof(wintypes.WCHAR),
        ctypes.cast(name_buffer, wintypes.LPWSTR),
    )

    attributes = OBJ_CASE_INSENSITIVE

    if dont_reparse:
        attributes |= OBJ_DONT_REPARSE

    root_value = normalize_handle(root_handle)

    object_attributes = OBJECT_ATTRIBUTES(
        ctypes.sizeof(OBJECT_ATTRIBUTES),
        wintypes.HANDLE(root_value),
        ctypes.cast(
            ctypes.pointer(unicode_string),
            wintypes.LPVOID,
        ),
        attributes,
        None,
        None,
    )

    return object_attributes, unicode_string, name_buffer


# ---------------------------------------------------------------------------
# Absolute directory acquisition
# ---------------------------------------------------------------------------

def open_directory_absolute(path: str | Path):
    """Open a directory itself without traversing its final reparse point.

    The returned value is a Windows kernel HANDLE.
    """
    path = str(path)

    handle = CreateFileW(
        path,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT,
        0,
    )

    if handle == wintypes.HANDLE(-1).value:
        return None

    return handle


# ---------------------------------------------------------------------------
# Relative directory acquisition
# ---------------------------------------------------------------------------

def open_directory_relative(
    parent_handle,
    name: str,
    *,
    create: bool = False,
):
    """Open a directory relative to an already-open directory HANDLE.

    Returns:
        (NTSTATUS, HANDLE-or-None)
    """
    parent_value = normalize_handle(parent_handle)

    object_attributes, unicode_string, name_buffer = _object_attributes(
        parent_value,
        str(name),
        dont_reparse=True,
    )

    del unicode_string, name_buffer

    io_status = IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()

    disposition = FILE_OPEN_IF if create else FILE_OPEN

    status = NtCreateFile(
        ctypes.byref(handle),
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        disposition,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0,
    )

    status = status_u32(status)

    if status != STATUS_SUCCESS:
        return status, None

    return status, handle


# ---------------------------------------------------------------------------
# Relative file acquisition
# ---------------------------------------------------------------------------

def open_file_relative(
    parent_handle,
    name: str,
    *,
    desired_access: int,
    create_disposition: int = FILE_OPEN,
    create_options: int = (
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    ),
):
    """Open a file relative to an already-open directory HANDLE.

    OBJ_DONT_REPARSE is applied to the object-name lookup.

    Returns:
        (NTSTATUS, HANDLE-or-None)
    """
    parent_value = normalize_handle(parent_handle)

    object_attributes, unicode_string, name_buffer = _object_attributes(
        parent_value,
        str(name),
        dont_reparse=True,
    )

    del unicode_string, name_buffer

    io_status = IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()

    status = NtCreateFile(
        ctypes.byref(handle),
        desired_access | SYNCHRONIZE,
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        create_disposition,
        create_options,
        None,
        0,
    )

    status = status_u32(status)

    if status != STATUS_SUCCESS:
        return status, None

    return status, handle


# ---------------------------------------------------------------------------
# Basic HANDLE I/O
# ---------------------------------------------------------------------------

def write_all(handle, data: bytes) -> None:
    """Write all bytes to a synchronous HANDLE."""
    value = normalize_handle(handle)

    payload = bytes(data)

    if not payload:
        return

    buffer = ctypes.create_string_buffer(payload)
    total = 0

    while total < len(payload):
        remaining = len(payload) - total
        written = wintypes.DWORD()

        ok = WriteFile(
            wintypes.HANDLE(value),
            ctypes.byref(buffer, total),
            remaining,
            ctypes.byref(written),
            None,
        )

        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

        count = int(written.value)

        if count <= 0:
            raise OSError("WriteFile made no forward progress")

        total += count


def read_all(handle, size: int) -> bytes:
    """Read exactly up to size bytes from a synchronous HANDLE."""
    value = normalize_handle(handle)

    if size < 0:
        raise ValueError("size must be non-negative")

    if size == 0:
        return b""

    buffer = ctypes.create_string_buffer(size)
    total = 0

    while total < size:
        remaining = size - total
        read_count = wintypes.DWORD()

        ok = ReadFile(
            wintypes.HANDLE(value),
            ctypes.byref(buffer, total),
            remaining,
            ctypes.byref(read_count),
            None,
        )

        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

        count = int(read_count.value)

        if count <= 0:
            break

        total += count

    return buffer.raw[:total]


def flush_file(handle) -> None:
    """Flush buffered file data to the filesystem."""
    value = normalize_handle(handle)

    if not FlushFileBuffers(wintypes.HANDLE(value)):
        raise ctypes.WinError(ctypes.get_last_error())


# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------

def get_file_attributes(handle) -> int:
    """Return Win32 file attributes for an open HANDLE."""
    value = normalize_handle(handle)

    info = BY_HANDLE_FILE_INFORMATION()

    if not GetFileInformationByHandle(
        wintypes.HANDLE(value),
        ctypes.byref(info),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    return int(info.dwFileAttributes)


def get_file_information(handle) -> BY_HANDLE_FILE_INFORMATION:
    """Return BY_HANDLE_FILE_INFORMATION for an open HANDLE."""
    value = normalize_handle(handle)

    info = BY_HANDLE_FILE_INFORMATION()

    if not GetFileInformationByHandle(
        wintypes.HANDLE(value),
        ctypes.byref(info),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    return info


# ---------------------------------------------------------------------------
# File deletion
# ---------------------------------------------------------------------------

def delete_file_handle(handle) -> int:
    """Mark an open file HANDLE for deletion.

    This uses FileDispositionInformation and therefore requires DELETE
    access on the HANDLE.

    Returns the normalized NTSTATUS.
    """
    value = normalize_handle(handle)

    disposition = FILE_DISPOSITION_INFORMATION(1)
    io_status = IO_STATUS_BLOCK()

    status = NtSetInformationFile(
        wintypes.HANDLE(value),
        ctypes.byref(io_status),
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
        FILE_DISPOSITION_INFORMATION,
    )

    return status_u32(status)


# ---------------------------------------------------------------------------
# Destination filename validation
# ---------------------------------------------------------------------------

def validate_relative_filename(name: str) -> str:
    """Validate that name is exactly one safe Windows filename component.

    The state backend uses this boundary so rename destinations cannot
    introduce traversal, nested paths, absolute paths, ADS, wildcards,
    controls, or ambiguous trailing-dot/space names.
    """
    name = str(name)

    if not name:
        raise ValueError("empty filename")

    if name in {".", ".."}:
        raise ValueError("dot filename")

    if "\x00" in name:
        raise ValueError("NUL in filename")

    for char in name:
        if ord(char) < 0x20:
            raise ValueError("control character in filename")

    if any(char in name for char in "\\/:*?\"<>|"):
        raise ValueError("path or wildcard character in filename")

    if name.endswith(" ") or name.endswith("."):
        raise ValueError("trailing dot/space in filename")

    if len(name.encode("utf-16-le")) // 2 > 255:
        raise ValueError("filename exceeds 255 UTF-16 code units")

    return name


# ---------------------------------------------------------------------------
# Relative atomic replacement
# ---------------------------------------------------------------------------

def rename_replace_relative(
    source_handle,
    destination_directory_handle,
    destination_name: str,
) -> int:
    """Atomically replace destination_name with source_handle.

    destination_name must be a single validated filename component.

    Uses the native FileRenameInformation structure with:

        ReplaceIfExists = TRUE
        RootDirectory = destination_directory_handle

    Returns the normalized NTSTATUS.
    """
    destination_name = validate_relative_filename(destination_name)

    source_value = normalize_handle(source_handle)
    destination_value = normalize_handle(destination_directory_handle)

    filename_bytes = destination_name.encode("utf-16-le")

    filename_offset = (
        FILE_RENAME_INFORMATION_BASE.FileNameLength.offset
        + ctypes.sizeof(wintypes.ULONG)
    )

    total_size = filename_offset + len(filename_bytes)

    buffer = ctypes.create_string_buffer(total_size)

    replace_if_exists = wintypes.BOOLEAN(1)
    root_directory = wintypes.HANDLE(destination_value)
    filename_length = wintypes.ULONG(len(filename_bytes))

    ctypes.memmove(
        ctypes.addressof(buffer),
        ctypes.byref(replace_if_exists),
        ctypes.sizeof(replace_if_exists),
    )

    ctypes.memmove(
        ctypes.addressof(buffer)
        + FILE_RENAME_INFORMATION_BASE.RootDirectory.offset,
        ctypes.byref(root_directory),
        ctypes.sizeof(root_directory),
    )

    ctypes.memmove(
        ctypes.addressof(buffer)
        + FILE_RENAME_INFORMATION_BASE.FileNameLength.offset,
        ctypes.byref(filename_length),
        ctypes.sizeof(filename_length),
    )

    ctypes.memmove(
        ctypes.addressof(buffer) + filename_offset,
        filename_bytes,
        len(filename_bytes),
    )

    io_status = IO_STATUS_BLOCK()

    status = NtSetInformationFile(
        wintypes.HANDLE(source_value),
        ctypes.byref(io_status),
        ctypes.cast(buffer, wintypes.LPVOID),
        total_size,
        FILE_RENAME_INFORMATION,
    )

    return status_u32(status)