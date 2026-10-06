#!/usr/bin/env python3
"""
Standalone Windows capability test v10.

Purpose:
    Prove that the directory HANDLE used as RootDirectory can itself be
    acquired safely with NtCreateFile + OBJ_DONT_REPARSE.

This test closes an important gap left by the earlier tests.

Test structure:

    parent
    +-- real_root
    |   +-- marker.txt
    |
    +-- root_junction -> real_root

Case A:
    Securely open "real_root" relative to a securely opened parent HANDLE
    using OBJ_DONT_REPARSE.

    Expected:
        STATUS_SUCCESS

Case B:
    Attempt to securely open "root_junction" relative to the same parent
    HANDLE using OBJ_DONT_REPARSE.

    Expected:
        STATUS_REPARSE_POINT_ENCOUNTERED

If Case B succeeded, the test would demonstrate that the initial root
acquisition is not protected against reparse traversal.

This test does NOT claim complete state-backend security. It specifically
tests the initial RootDirectory acquisition primitive needed before the
already-proven child-relative operations.

No Lumina source files are modified.
"""

from __future__ import annotations

import ctypes
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


# ---------------------------------------------------------------------------
# Windows API setup
# ---------------------------------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

GENERIC_READ = 0x80000000
SYNCHRONIZE = 0x00100000

FILE_READ_ATTRIBUTES = 0x00000080

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

OPEN_EXISTING = 3
FILE_OPEN = 0x00000001

FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

STATUS_SUCCESS = 0x00000000
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B


# ---------------------------------------------------------------------------
# NT structures
# ---------------------------------------------------------------------------

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_void_p),
        ("Information", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# API prototypes
# ---------------------------------------------------------------------------

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
CreateFileW.restype = wintypes.HANDLE


CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


NtCreateFile = ntdll.NtCreateFile
NtCreateFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
]
NtCreateFile.restype = wintypes.LONG


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def status_u32(status: int) -> int:
    return ctypes.c_uint32(status).value


def status_hex(status: int) -> str:
    return f"0x{status_u32(status):08X}"


def close_handle(handle) -> None:
    if handle is None:
        return

    if handle == INVALID_HANDLE_VALUE:
        return

    try:
        CloseHandle(handle)
    except Exception:
        pass


def win_error(prefix: str) -> OSError:
    error = ctypes.get_last_error()
    return OSError(
        error,
        f"{prefix}: Win32 error {error}: "
        f"{ctypes.FormatError(error).strip()}",
    )


def open_directory_win32(path: Path):
    """
    Open an ordinary directory HANDLE for use as RootDirectory.

    This is deliberately only the parent HANDLE. The child/root name is
    opened through NtCreateFile so that OBJ_DONT_REPARSE is exercised.
    """

    handle = CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    if handle == INVALID_HANDLE_VALUE:
        raise win_error(
            f"CreateFileW(directory={path!s})"
        )

    return handle


def make_relative_object_attributes(
    root_handle,
    object_name: str,
):
    """
    Build OBJECT_ATTRIBUTES for:

        RootDirectory = root_handle
        ObjectName    = object_name
        Attributes    = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
    """

    name_buffer = ctypes.create_unicode_buffer(object_name)
    encoded = object_name.encode("utf-16-le")

    unicode_name = UNICODE_STRING(
        len(encoded),
        len(encoded) + 2,
        ctypes.cast(name_buffer, wintypes.LPWSTR),
    )

    object_attributes = OBJECT_ATTRIBUTES()

    object_attributes.Length = ctypes.sizeof(
        OBJECT_ATTRIBUTES
    )
    object_attributes.RootDirectory = root_handle
    object_attributes.ObjectName = ctypes.pointer(
        unicode_name
    )
    object_attributes.Attributes = (
        OBJ_CASE_INSENSITIVE
        | OBJ_DONT_REPARSE
    )

    return (
        object_attributes,
        unicode_name,
        name_buffer,
    )


def nt_open_directory_relative(
    parent_handle,
    object_name: str,
):
    """
    Open one existing directory relative to parent_handle.

    The call deliberately uses:

        OBJ_DONT_REPARSE
        FILE_DIRECTORY_FILE
        FILE_SYNCHRONOUS_IO_NONALERT
        SYNCHRONIZE

    SYNCHRONIZE is required when using the synchronous CreateOption.
    This was established by the earlier v3A tests.
    """

    (
        object_attributes,
        unicode_name,
        name_buffer,
    ) = make_relative_object_attributes(
        parent_handle,
        object_name,
    )

    handle = wintypes.HANDLE()
    io_status = IO_STATUS_BLOCK()

    desired_access = (
        FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
    )

    create_options = (
        FILE_DIRECTORY_FILE
        | FILE_SYNCHRONOUS_IO_NONALERT
    )

    status = NtCreateFile(
        ctypes.byref(handle),
        desired_access,
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        FILE_ATTRIBUTE_NORMAL,
        (
            FILE_SHARE_READ
            | FILE_SHARE_WRITE
            | FILE_SHARE_DELETE
        ),
        FILE_OPEN,
        create_options,
        None,
        0,
    )

    # Keep Python backing objects alive until NtCreateFile returns.
    _ = (
        unicode_name,
        name_buffer,
    )

    return status_u32(status), handle


def create_junction(junction: Path, target: Path) -> None:
    result = subprocess.run(
        [
            "cmd.exe",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(target),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "mklink /J failed:\n"
            f"return code: {result.returncode}\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )

    if not junction.exists():
        raise RuntimeError(
            "mklink reported success but the junction "
            "does not exist."
        )


# ---------------------------------------------------------------------------
# Case A
# ---------------------------------------------------------------------------

def case_a(parent: Path, real_root: Path) -> bool:
    print("-" * 72)
    print("CASE A - Normal RootDirectory Acquisition")
    print("-" * 72)
    print()

    parent_handle = None
    root_handle = None

    try:
        parent_handle = open_directory_win32(parent)

        print("Parent HANDLE: PASS")
        print(
            "Opening real_root with "
            "RootDirectory + OBJ_DONT_REPARSE..."
        )

        status, root_handle = nt_open_directory_relative(
            parent_handle,
            real_root.name,
        )

        print(
            f"NtCreateFile status: "
            f"{status_hex(status)}"
        )

        if status != STATUS_SUCCESS:
            print("Normal root acquisition: FAIL")
            return False

        print("Root HANDLE acquisition: PASS")

        if root_handle.value in (
            None,
            0,
            INVALID_HANDLE_VALUE,
        ):
            print("Returned HANDLE validation: FAIL")
            return False

        print("Returned HANDLE validation: PASS")
        print()
        print("CASE A RESULT: PASS")

        return True

    finally:
        close_handle(root_handle)
        close_handle(parent_handle)


# ---------------------------------------------------------------------------
# Case B
# ---------------------------------------------------------------------------

def case_b(parent: Path, root_junction: Path) -> bool:
    print("-" * 72)
    print("CASE B - Reparse-Point RootDirectory Acquisition")
    print("-" * 72)
    print()

    parent_handle = None
    root_handle = None

    try:
        parent_handle = open_directory_win32(parent)

        print("Parent HANDLE: PASS")
        print(
            "Attempting to open root_junction with "
            "RootDirectory + OBJ_DONT_REPARSE..."
        )

        status, root_handle = nt_open_directory_relative(
            parent_handle,
            root_junction.name,
        )

        print(
            f"NtCreateFile status: "
            f"{status_hex(status)}"
        )

        if status == STATUS_REPARSE_POINT_ENCOUNTERED:
            print(
                "Reparse-point root rejection: PASS "
                "(STATUS_REPARSE_POINT_ENCOUNTERED)"
            )
            print()
            print("CASE B RESULT: PASS")
            return True

        if status == STATUS_SUCCESS:
            print(
                "SECURITY FAILURE: the root junction "
                "was followed."
            )
            return False

        print(
            "Unexpected NTSTATUS while opening the "
            f"root junction: {status_hex(status)}"
        )
        return False

    finally:
        close_handle(root_handle)
        close_handle(parent_handle)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if sys.platform != "win32":
        print("ERROR: This test requires Windows.")
        return 2

    print("=" * 72)
    print("TEST - NtCreateFile RootDirectory Security v10")
    print("=" * 72)
    print()

    print(f"Python: {sys.version}")
    print(
        f"Pointer size: "
        f"{ctypes.sizeof(ctypes.c_void_p) * 8}-bit"
    )

    version = sys.getwindowsversion()

    print(
        f"Windows: "
        f"{version.major}.{version.minor} "
        f"build {version.build}"
    )

    print()
    print("This test verifies:")
    print(
        "  1. A normal root directory can be opened "
        "relative to a parent HANDLE."
    )
    print(
        "  2. OBJ_DONT_REPARSE blocks acquisition of a "
        "root directory that is itself a junction."
    )
    print()

    test_root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntroot_security_v10_"
        )
    )

    parent = test_root / "parent"
    real_root = parent / "real_root"
    root_junction = parent / "root_junction"
    outside = test_root / "outside"

    parent.mkdir()
    real_root.mkdir()
    outside.mkdir()

    marker = real_root / "marker.txt"
    marker.write_text(
        "REAL_ROOT_MARKER\n",
        encoding="utf-8",
    )

    print(f"Test root: {test_root}")
    print(f"Parent: {parent}")
    print(f"Real root: {real_root}")
    print(f"Outside: {outside}")
    print()

    case_a_result = False
    case_b_result = False

    try:
        print("Creating root_junction -> real_root...")

        create_junction(
            root_junction,
            real_root,
        )

        print("Junction creation: PASS")
        print()

        case_a_result = case_a(
            parent,
            real_root,
        )

        print()

        case_b_result = case_b(
            parent,
            root_junction,
        )

        print()
        print("=" * 72)

        if case_a_result and case_b_result:
            print("RESULT: PASS")
            print("=" * 72)
            print()
            print(
                "Verified in the tested Windows environment:"
            )
            print(
                "  1. A normal directory can be opened as "
                "a RootDirectory-relative object."
            )
            print(
                "  2. OBJ_DONT_REPARSE is honored while "
                "acquiring that root."
            )
            print(
                "  3. A directory junction cannot be "
                "followed during root acquisition."
            )
            print()
            print(
                "This closes the initial-root acquisition "
                "gap, but does not by itself establish "
                "complete Windows/POSIX state-backend "
                "parity."
            )
            return 0

        print("RESULT: FAIL")
        print("=" * 72)
        print(
            f"Case A: "
            f"{'PASS' if case_a_result else 'FAIL'}"
        )
        print(
            f"Case B: "
            f"{'PASS' if case_b_result else 'FAIL'}"
        )

        return 1

    finally:
        try:
            shutil.rmtree(test_root)
            print()
            print(f"Cleaned up: {test_root}")
        except Exception as exc:
            print()
            print(
                "WARNING: Could not remove test directory: "
                f"{test_root}"
            )
            print(f"Cleanup error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main)