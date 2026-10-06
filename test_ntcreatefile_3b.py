"""
Test 3B v1 - NtCreateFile junction traversal without OBJ_DONT_REPARSE

Purpose:
    Establish the baseline behavior when NtCreateFile performs a
    handle-relative open through a Windows directory junction.

Expected control behavior:
    Without OBJ_DONT_REPARSE, a junction should be traversable.

This test deliberately does NOT use OBJ_DONT_REPARSE.

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

GENERIC_READ = 0x80000000
SYNCHRONIZE = 0x00100000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001

FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

OBJ_CASE_INSENSITIVE = 0x00000040

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


ReadFile = kernel32.ReadFile
ReadFile.argtypes = [
    HANDLE,
    ctypes.c_void_p,
    DWORD,
    ctypes.POINTER(DWORD),
    ctypes.c_void_p,
]
ReadFile.restype = BOOL


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
        0x00000000: "STATUS_SUCCESS",
        0xC000000D: "STATUS_INVALID_PARAMETER",
        0xC0000022: "STATUS_ACCESS_DENIED",
        0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC000050B: "STATUS_REPARSE_POINT_ENCOUNTERED",
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
    Create a directory junction using the native Windows mklink command.

    This requires no elevation when used inside the user's writable
    temporary directory.
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
    Remove a junction without recursively deleting its target.
    """

    if not path.exists() and not path.is_symlink():
        return

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

    This uses the known-good 3A v2 parameter combination:

        DesiredAccess =
            GENERIC_READ | SYNCHRONIZE

        CreateOptions =
            FILE_NON_DIRECTORY_FILE
            | FILE_SYNCHRONOUS_IO_NONALERT
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

    # Deliberately no OBJ_DONT_REPARSE.
    object_attributes.Attributes = OBJ_CASE_INSENSITIVE

    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    io_status = IO_STATUS_BLOCK()
    result_handle = HANDLE()

    create_options = (
        FILE_NON_DIRECTORY_FILE
        | FILE_SYNCHRONOUS_IO_NONALERT
    )

    desired_access = GENERIC_READ | SYNCHRONIZE

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


def read_handle(handle, count: int = 4096) -> bytes:
    buffer = ctypes.create_string_buffer(count)
    bytes_read = DWORD(0)

    ok = ReadFile(
        handle,
        buffer,
        count,
        ctypes.byref(bytes_read),
        None,
    )

    if not ok:
        error = ctypes.get_last_error()

        raise RuntimeError(
            f"ReadFile failed: Win32 error {error}"
        )

    return buffer.raw[:bytes_read.value]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("TEST 3B v1 - NtCreateFile Junction Traversal")
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

    print(
        "Control condition:"
    )

    print(
        "  OBJ_DONT_REPARSE = NOT USED"
    )

    print(
        "  Expected behavior: junction traversal is allowed"
    )

    print()

    root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntcreate_3b_"
        )
    )

    outside = root / "outside"
    real = root / "real"
    junction = root / "junction"

    root_handle = None
    target_handle = None
    junction_removed = False

    try:
        # ---------------------------------------------------------------
        # Build test tree
        # ---------------------------------------------------------------

        outside.mkdir()
        real.mkdir()

        outside_target = outside / "target.txt"
        real_target = real / "target.txt"

        outside_marker = (
            "OUTSIDE_TARGET_MARKER_3B\n"
        )

        real_marker = (
            "REAL_TARGET_MARKER_3B\n"
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
        # Perform relative open through junction
        # ---------------------------------------------------------------

        relative_name = "junction\\target.txt"

        print(
            "Attempting NtCreateFile relative open:"
        )

        print(
            f"  RootDirectory = 0x{handle_value(root_handle):X}"
        )

        print(
            f"  ObjectName    = {relative_name}"
        )

        print(
            "  OBJ_DONT_REPARSE = NO"
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

        if status != STATUS_SUCCESS:
            print()
            print(
                "RESULT: FAIL"
            )
            print()
            print(
                "The control case did not traverse the junction."
            )

            return 1

        print(
            "  NtCreateFile open: PASS"
        )

        # ---------------------------------------------------------------
        # Verify which target was opened
        # ---------------------------------------------------------------

        data = read_handle(
            target_handle,
            4096,
        )

        decoded = data.decode(
            "utf-8",
            errors="replace",
        )

        print()

        print(
            "Read from returned file HANDLE:"
        )

        print(
            f"  {decoded!r}"
        )

        expected = outside_marker.strip()

        if expected in decoded:
            print(
                "  Target verification: PASS"
            )

            print()
            print("=" * 72)
            print("RESULT: PASS")
            print("=" * 72)
            print()
            print(
                "NtCreateFile successfully traversed the directory "
                "junction when OBJ_DONT_REPARSE was not supplied."
            )

            print()
            print(
                "The returned HANDLE resolved to the OUTSIDE "
                "directory target, not the real directory."
            )

            return 0

        if real_marker.strip() in decoded:
            print(
                "  Target verification: FAIL"
            )

            print()
            print(
                "The returned HANDLE unexpectedly opened the "
                "real target instead of following the junction."
            )

            return 1

        print(
            "  Target verification: FAIL"
        )

        print()
        print(
            "The open succeeded, but the returned file contents "
            "did not identify either expected target."
        )

        return 1

    finally:
        close_handle(target_handle)
        close_handle(root_handle)

        try:
            if junction.exists() or junction.is_symlink():
                remove_junction(junction)
                junction_removed = True
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