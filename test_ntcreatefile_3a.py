"""
Test 3A - NtCreateFile handle-relative open

Question:
    Can NtCreateFile open an ordinary file relative to an already-open
    directory HANDLE supplied through OBJECT_ATTRIBUTES.RootDirectory?

    Test both:
        - without OBJ_DONT_REPARSE
        - with OBJ_DONT_REPARSE

This is a standalone capability test.
It does not touch Lumina.
"""

from __future__ import annotations

import ctypes
import shutil
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# DLLs
# ---------------------------------------------------------------------------

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


# ---------------------------------------------------------------------------
# Basic types
# ---------------------------------------------------------------------------

HANDLE = ctypes.c_void_p
NTSTATUS = ctypes.c_long
ULONG = ctypes.c_ulong
ACCESS_MASK = ctypes.c_ulong


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STATUS_SUCCESS = 0x00000000

GENERIC_READ = 0x80000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001

FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.c_wchar_p),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    class STATUS_UNION(ctypes.Union):
        _fields_ = [
            ("Status", NTSTATUS),
            ("Pointer", ctypes.c_void_p),
        ]

    _anonymous_ = ("u",)

    _fields_ = [
        ("u", STATUS_UNION),
        ("Information", ctypes.c_size_t),
    ]


# ---------------------------------------------------------------------------
# Function declarations
# ---------------------------------------------------------------------------

NtCreateFile = ntdll.NtCreateFile
NtCreateFile.argtypes = [
    ctypes.POINTER(HANDLE),
    ACCESS_MASK,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    ctypes.c_void_p,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ctypes.c_void_p,
    ULONG,
]
NtCreateFile.restype = NTSTATUS


CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
    HANDLE,
]
CreateFileW.restype = HANDLE


CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = ctypes.c_int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def handle_value(handle) -> int:
    """
    Normalize a ctypes handle or Python int into an integer handle value.
    """

    if isinstance(handle, int):
        return handle

    value = getattr(handle, "value", None)

    if value is None:
        return 0

    return int(value)


def valid_handle(handle) -> bool:
    value = handle_value(handle)

    if value == 0:
        return False

    if value == INVALID_HANDLE_VALUE:
        return False

    return True


def close_handle(handle):
    if valid_handle(handle):
        CloseHandle(handle)


def status_u32(value) -> int:
    if isinstance(value, int):
        return value & 0xFFFFFFFF

    return value.value & 0xFFFFFFFF


def status_name(status: int) -> str:
    names = {
        0x00000000: "STATUS_SUCCESS",
        0xC000000D: "STATUS_INVALID_PARAMETER",
        0xC0000022: "STATUS_ACCESS_DENIED",
        0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC000050B: "STATUS_REPARSE_POINT_ENCOUNTERED",
    }

    return names.get(status, "UNKNOWN")


def open_directory(path: Path):
    """
    Open an ordinary Windows directory handle suitable for RootDirectory.
    """

    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    OPEN_EXISTING = 3

    handle = CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    if not valid_handle(handle):
        error = ctypes.get_last_error()
        raise RuntimeError(
            f"CreateFileW failed opening directory: Win32 error {error}"
        )

    return handle


def nt_open_relative(root_handle, name: str, dont_reparse: bool):
    """
    Open `name` relative to root_handle using NtCreateFile.
    """

    name_buffer = ctypes.create_unicode_buffer(name)

    unicode_name = UNICODE_STRING()
    unicode_name.Length = len(name.encode("utf-16-le"))
    unicode_name.MaximumLength = ctypes.sizeof(name_buffer)
    unicode_name.Buffer = ctypes.cast(
        name_buffer,
        ctypes.c_wchar_p,
    )

    object_attributes = OBJECT_ATTRIBUTES()
    object_attributes.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)

    # RootDirectory is a HANDLE. Convert the Python int returned by
    # CreateFileW into the ctypes handle type expected by the structure.
    object_attributes.RootDirectory = HANDLE(
        handle_value(root_handle)
    )

    object_attributes.ObjectName = ctypes.pointer(unicode_name)
    object_attributes.Attributes = OBJ_CASE_INSENSITIVE

    if dont_reparse:
        object_attributes.Attributes |= OBJ_DONT_REPARSE

    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    io_status = IO_STATUS_BLOCK()
    result_handle = HANDLE()

    create_options = (
        FILE_NON_DIRECTORY_FILE
        | FILE_SYNCHRONOUS_IO_NONALERT
    )

    status = NtCreateFile(
        ctypes.byref(result_handle),
        GENERIC_READ,
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        create_options,
        None,
        0,
    )

    status = status_u32(status)

    if status == STATUS_SUCCESS:
        close_handle(result_handle)

    return status


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("TEST 3A - NtCreateFile RootDirectory")
    print("=" * 72)

    print(f"Python: {sys.version}")
    print(
        f"Pointer size: "
        f"{ctypes.sizeof(ctypes.c_void_p) * 8}-bit"
    )

    version = sys.getwindowsversion()

    print(
        f"Windows: {version.major}.{version.minor}"
        f" build {version.build}"
    )

    print(
        f"OBJ_CASE_INSENSITIVE = "
        f"0x{OBJ_CASE_INSENSITIVE:08X}"
    )

    print(
        f"OBJ_DONT_REPARSE     = "
        f"0x{OBJ_DONT_REPARSE:08X}"
    )

    print()

    root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntcreate_3a_"
        )
    )

    print(f"Test directory: {root}")
    print()

    root_handle = None

    try:
        real = root / "real"
        real.mkdir()

        target = real / "target.txt"
        target.write_text(
            "NtCreateFile relative-open test\n",
            encoding="utf-8",
        )

        print("Created:")
        print(f"  {target}")
        print()

        root_handle = open_directory(root)

        print(
            "Opened RootDirectory HANDLE successfully."
        )

        print(
            f"  HANDLE = 0x{handle_value(root_handle):X}"
        )

        print()

        # ---------------------------------------------------------------
        # Test 1
        # ---------------------------------------------------------------

        print(
            "Test 1: ordinary relative file WITHOUT "
            "OBJ_DONT_REPARSE"
        )

        status1 = nt_open_relative(
            root_handle,
            "real\\target.txt",
            False,
        )

        print(
            f"  NTSTATUS: 0x{status1:08X}"
            f" ({status_name(status1)})"
        )

        test1 = status1 == STATUS_SUCCESS

        print(
            "  RESULT:",
            "PASS" if test1 else "FAIL",
        )

        print()

        # ---------------------------------------------------------------
        # Test 2
        # ---------------------------------------------------------------

        print(
            "Test 2: ordinary relative file WITH "
            "OBJ_DONT_REPARSE"
        )

        status2 = nt_open_relative(
            root_handle,
            "real\\target.txt",
            True,
        )

        print(
            f"  NTSTATUS: 0x{status2:08X}"
            f" ({status_name(status2)})"
        )

        test2 = status2 == STATUS_SUCCESS

        print(
            "  RESULT:",
            "PASS" if test2 else "FAIL",
        )

        print()
        print("=" * 72)

        if test1 and test2:
            print("RESULT: PASS")
            print()
            print(
                "NtCreateFile successfully performed an ordinary "
                "handle-relative open both with and without "
                "OBJ_DONT_REPARSE."
            )

            return 0

        print("RESULT: FAIL")
        print()
        print(
            "The basic handle-relative open capability did not "
            "behave as expected."
        )

        return 1

    finally:
        close_handle(root_handle)

        try:
            shutil.rmtree(root)
        except Exception as exc:
            print(
                f"WARNING: cleanup failed: {exc}"
            )


if __name__ == "__main__":
    raise SystemExit(main())