"""
Test 3C v1 - NtCreateFile junction rejection with OBJ_DONT_REPARSE

Purpose:
    Test whether OBJ_DONT_REPARSE prevents NtCreateFile from traversing
    an intermediate directory junction.

Control established by:
    test_ntcreatefile_3b.py

3B behavior:
    Without OBJ_DONT_REPARSE, the junction was traversed and the
    OUTSIDE target was successfully opened.

This test performs the same operation but adds OBJ_DONT_REPARSE.

Success criteria:
    1. NtCreateFile does NOT successfully open the target through
       the junction.
    2. The expected reparse-related failure is observed.
    3. The outside target is therefore not opened.

This is a standalone capability test.
It does not touch Lumina.
"""

from __future__ import annotations

import ctypes
import shutil
import subprocess
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
DWORD = ctypes.c_ulong
BOOL = ctypes.c_int


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STATUS_SUCCESS = 0x00000000

STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B

GENERIC_READ = 0x80000000
SYNCHRONIZE = 0x00100000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001

FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

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
CloseHandle.restype = BOOL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def handle_value(handle) -> int:
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
        STATUS_SUCCESS: "STATUS_SUCCESS",
        STATUS_INVALID_PARAMETER: "STATUS_INVALID_PARAMETER",
        STATUS_ACCESS_DENIED: "STATUS_ACCESS_DENIED",
        STATUS_OBJECT_NAME_NOT_FOUND: "STATUS_OBJECT_NAME_NOT_FOUND",
        STATUS_OBJECT_PATH_NOT_FOUND: "STATUS_OBJECT_PATH_NOT_FOUND",
        STATUS_REPARSE_POINT_ENCOUNTERED:
            "STATUS_REPARSE_POINT_ENCOUNTERED",
    }

    return names.get(status, "UNKNOWN")


def open_directory(path: Path):
    handle = CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ
        | FILE_SHARE_WRITE
        | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    if not valid_handle(handle):
        error = ctypes.get_last_error()

        raise RuntimeError(
            f"CreateFileW failed opening directory: "
            f"Win32 error {error}"
        )

    return handle


def create_junction(link_path: Path, target_path: Path):
    """
    Create a directory junction using the Windows mklink command.
    """

    result = subprocess.run(
        [
            "cmd.exe",
            "/c",
            "mklink",
            "/J",
            str(link_path),
            str(target_path),
        ],
        capture_output=True,
        text=True,
        encoding="mbcs",
        errors="replace",
    )

    if result.returncode != 0:
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        raise RuntimeError(
            "mklink /J failed.\n"
            f"return code: {result.returncode}\n"
            f"stdout: {stdout}\n"
            f"stderr: {stderr}"
        )

    if not link_path.exists():
        raise RuntimeError(
            "mklink reported success but the junction "
            "does not exist."
        )


def remove_junction(path: Path):
    """
    Remove a directory junction without recursively deleting
    its target directory.
    """

    result = subprocess.run(
        [
            "cmd.exe",
            "/c",
            "rmdir",
            str(path),
        ],
        capture_output=True,
        text=True,
        encoding="mbcs",
        errors="replace",
    )

    if result.returncode != 0:
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        raise RuntimeError(
            "rmdir junction cleanup failed.\n"
            f"return code: {result.returncode}\n"
            f"stdout: {stdout}\n"
            f"stderr: {stderr}"
        )


def nt_open_relative(
    root_handle,
    name: str,
):
    """
    Open name relative to root_handle using NtCreateFile.

    Parameters intentionally match the successful 3A v2 Case C:

        DesiredAccess =
            GENERIC_READ | SYNCHRONIZE

        CreateOptions =
            FILE_NON_DIRECTORY_FILE
            | FILE_SYNCHRONOUS_IO_NONALERT

    The only security-relevant change from 3B is:

        OBJ_DONT_REPARSE
    """

    name_buffer = ctypes.create_unicode_buffer(name)

    unicode_name = UNICODE_STRING()

    unicode_name.Length = len(
        name.encode("utf-16-le")
    )

    unicode_name.MaximumLength = ctypes.sizeof(
        name_buffer
    )

    unicode_name.Buffer = ctypes.cast(
        name_buffer,
        ctypes.c_wchar_p,
    )

    object_attributes = OBJECT_ATTRIBUTES()

    object_attributes.Length = ctypes.sizeof(
        OBJECT_ATTRIBUTES
    )

    object_attributes.RootDirectory = HANDLE(
        handle_value(root_handle)
    )

    object_attributes.ObjectName = ctypes.pointer(
        unicode_name
    )

    # This is the ONLY material difference from 3B:
    # OBJ_DONT_REPARSE is enabled.
    object_attributes.Attributes = (
        OBJ_CASE_INSENSITIVE
        | OBJ_DONT_REPARSE
    )

    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    io_status = IO_STATUS_BLOCK()
    result_handle = HANDLE()

    create_options = (
        FILE_NON_DIRECTORY_FILE
        | FILE_SYNCHRONOUS_IO_NONALERT
    )

    desired_access = (
        GENERIC_READ
        | SYNCHRONIZE
    )

    status = NtCreateFile(
        ctypes.byref(result_handle),
        desired_access,
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        0,
        FILE_SHARE_READ
        | FILE_SHARE_WRITE
        | FILE_SHARE_DELETE,
        FILE_OPEN,
        create_options,
        None,
        0,
    )

    status = status_u32(status)

    return status, result_handle


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("TEST 3C v1 - NtCreateFile Junction Rejection")
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

    print()

    print("Control established by 3B v1:")
    print(
        "  Without OBJ_DONT_REPARSE:"
    )
    print(
        "    STATUS_SUCCESS"
    )
    print(
        "    Junction was traversed"
    )
    print(
        "    Outside target was opened"
    )

    print()

    print("3C condition:")
    print(
        "  OBJ_DONT_REPARSE = ENABLED"
    )

    print()

    root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntcreate_3c_"
        )
    )

    outside = root / "outside"
    real = root / "real"
    junction = root / "junction"

    root_handle = None
    target_handle = None

    try:
        # ---------------------------------------------------------------
        # Build the same logical tree used by 3B
        # ---------------------------------------------------------------

        outside.mkdir()
        real.mkdir()

        outside_target = outside / "target.txt"
        real_target = real / "target.txt"

        outside_marker = (
            "OUTSIDE_TARGET_MARKER_3C\n"
        )

        real_marker = (
            "REAL_TARGET_MARKER_3C\n"
        )

        outside_target.write_text(
            outside_marker,
            encoding="utf-8",
        )

        real_target.write_text(
            real_marker,
            encoding="utf-8",
        )

        print("Created test tree:")

        print(
            f"  Root:            {root}"
        )

        print(
            f"  Real target:     {real_target}"
        )

        print(
            f"  Outside target:  {outside_target}"
        )

        print()

        # ---------------------------------------------------------------
        # Create junction
        # ---------------------------------------------------------------

        print("Creating directory junction:")

        print(
            f"  Junction: {junction}"
        )

        print(
            f"  Target:   {outside}"
        )

        create_junction(
            junction,
            outside,
        )

        print(
            "  Junction creation: PASS"
        )

        print()

        # ---------------------------------------------------------------
        # Open RootDirectory
        # ---------------------------------------------------------------

        root_handle = open_directory(root)

        print(
            "Opened RootDirectory HANDLE successfully."
        )

        print(
            f"  HANDLE = 0x{handle_value(root_handle):X}"
        )

        print()

        # ---------------------------------------------------------------
        # Attempt relative open through junction
        # ---------------------------------------------------------------

        relative_name = "junction\\target.txt"

        print(
            "Attempting NtCreateFile relative open:"
        )

        print(
            f"  RootDirectory = "
            f"0x{handle_value(root_handle):X}"
        )

        print(
            f"  ObjectName    = {relative_name}"
        )

        print(
            "  OBJ_DONT_REPARSE = YES"
        )

        print()

        status, target_handle = nt_open_relative(
            root_handle,
            relative_name,
        )

        print(
            f"  NTSTATUS = 0x{status:08X}"
            f" ({status_name(status)})"
        )

        # ---------------------------------------------------------------
        # Success would be a security failure for this test
        # ---------------------------------------------------------------

        if status == STATUS_SUCCESS:
            print()
            print(
                "  NtCreateFile open: UNEXPECTED SUCCESS"
            )

            print()
            print("=" * 72)
            print("RESULT: FAIL")
            print("=" * 72)
            print()
            print(
                "OBJ_DONT_REPARSE did not prevent traversal "
                "through the directory junction."
            )

            print()
            print(
                "This requires further investigation before the "
                "primitive can be treated as a reparse-safe "
                "replacement for the POSIX descriptor-relative "
                "state operations."
            )

            return 1

        # ---------------------------------------------------------------
        # Expected rejection
        # ---------------------------------------------------------------

        print()
        print(
            "  Junction traversal was rejected."
        )

        if status == STATUS_REPARSE_POINT_ENCOUNTERED:
            print(
                "  Rejection status matches "
                "STATUS_REPARSE_POINT_ENCOUNTERED."
            )

            print()
            print("=" * 72)
            print("RESULT: PASS")
            print("=" * 72)
            print()
            print(
                "OBJ_DONT_REPARSE prevented NtCreateFile from "
                "traversing the intermediate directory junction."
            )

            print()
            print(
                "The outside target was not opened."
            )

            return 0

        # ---------------------------------------------------------------
        # Rejected, but with an unexpected status
        # ---------------------------------------------------------------

        print(
            "  WARNING: rejection status was not the expected "
            "STATUS_REPARSE_POINT_ENCOUNTERED."
        )

        print()
        print("=" * 72)
        print("RESULT: INCONCLUSIVE")
        print("=" * 72)
        print()
        print(
            "The junction was not opened, but the returned "
            "NTSTATUS requires investigation."
        )

        return 2

    finally:
        close_handle(target_handle)
        close_handle(root_handle)

        try:
            if junction.exists() or junction.is_symlink():
                remove_junction(junction)
        except Exception as exc:
            print(
                f"WARNING: junction cleanup failed: {exc}"
            )

        try:
            shutil.rmtree(root)
        except Exception as exc:
            print(
                f"WARNING: test directory cleanup failed: {exc}"
            )


if __name__ == "__main__":
    raise SystemExit(main())