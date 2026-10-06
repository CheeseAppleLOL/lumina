"""
Standalone Windows NT CreateFile / RootDirectory / OBJ_DONT_REPARSE test.

Purpose:
    Determine whether NtCreateFile can:

      1. Open ordinary files relative to an already-open directory HANDLE.
      2. Open ordinary directories relative to an already-open directory HANDLE.
      3. Follow a junction when OBJ_DONT_REPARSE is NOT supplied.
      4. Reject a final-component junction when OBJ_DONT_REPARSE IS supplied.
      5. Reject an intermediate junction when OBJ_DONT_REPARSE IS supplied.
      6. Attempt equivalent file/directory symlink tests when the environment
         permits creation of symlinks.

This is a capability experiment only.
It does NOT modify Lumina.

Target:
    Windows 10 / Windows 11
    Python 3.x, 64-bit

Important:
    This uses the native NT API directly through ctypes.
    Results are reported using NTSTATUS values rather than translating them
    prematurely into Win32 errors.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Basic ctypes definitions
# ---------------------------------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")


HANDLE = ctypes.c_void_p
NTSTATUS = ctypes.c_long
ULONG = ctypes.c_ulong
ACCESS_MASK = ctypes.c_ulong
DWORD = ctypes.c_ulong
BOOLEAN = ctypes.c_ubyte
WCHAR = ctypes.c_wchar


# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

GENERIC_READ = 0x80000000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001

FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

# OBJECT_ATTRIBUTES attributes.
OBJ_CASE_INSENSITIVE = 0x00000040

# Important:
# Verified value from Windows OBJECT_ATTRIBUTES documentation.
OBJ_DONT_REPARSE = 0x00001000

# NTSTATUS values relevant to this experiment.
STATUS_SUCCESS = 0x00000000
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_ACCESS_DENIED = 0xC0000022


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
    class _STATUS_UNION(ctypes.Union):
        _fields_ = [
            ("Status", NTSTATUS),
            ("Pointer", ctypes.c_void_p),
        ]

    _anonymous_ = ("u",)

    _fields_ = [
        ("u", _STATUS_UNION),
        ("Information", ctypes.c_size_t),
    ]


# ---------------------------------------------------------------------------
# Function prototypes
# ---------------------------------------------------------------------------

NtCreateFile = ntdll.NtCreateFile
NtCreateFile.argtypes = [
    ctypes.POINTER(HANDLE),       # FileHandle
    ACCESS_MASK,                  # DesiredAccess
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    ctypes.c_void_p,              # AllocationSize
    ULONG,                        # FileAttributes
    ULONG,                        # ShareAccess
    ULONG,                        # CreateDisposition
    ULONG,                        # CreateOptions
    ctypes.c_void_p,              # EaBuffer
    ULONG,                        # EaLength
]
NtCreateFile.restype = NTSTATUS


CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = ctypes.c_int


CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    ctypes.c_wchar_p,
    DWORD,
    DWORD,
    ctypes.c_void_p,
    DWORD,
    DWORD,
    HANDLE,
]
CreateFileW.restype = HANDLE


GetLastError = kernel32.GetLastError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ntstatus_u32(status) -> int:
    """
    Normalize ctypes.c_long / Python int into an unsigned 32-bit NTSTATUS.
    """
    if isinstance(status, int):
        value = status
    else:
        value = status.value

    return value & 0xFFFFFFFF


def ntstatus_name(status: int) -> str:
    status = status & 0xFFFFFFFF

    names = {
        STATUS_SUCCESS: "STATUS_SUCCESS",
        STATUS_REPARSE_POINT_ENCOUNTERED: "STATUS_REPARSE_POINT_ENCOUNTERED",
        STATUS_OBJECT_NAME_NOT_FOUND: "STATUS_OBJECT_NAME_NOT_FOUND",
        STATUS_OBJECT_PATH_NOT_FOUND: "STATUS_OBJECT_PATH_NOT_FOUND",
        STATUS_INVALID_PARAMETER: "STATUS_INVALID_PARAMETER",
        STATUS_ACCESS_DENIED: "STATUS_ACCESS_DENIED",
    }

    return names.get(status, "UNKNOWN_STATUS")


def close_handle(handle) -> None:
    if handle:
        try:
            CloseHandle(handle)
        except Exception:
            pass


def is_valid_handle(handle) -> bool:
    if not handle:
        return False

    value = handle.value if hasattr(handle, "value") else handle

    if value is None:
        return False

    if value == 0:
        return False

    if value == INVALID_HANDLE_VALUE:
        return False

    return True


def make_unicode_string(text: str):
    """
    Keep the backing Python string alive while the NT call is executing.
    """
    buffer = ctypes.create_unicode_buffer(text)

    us = UNICODE_STRING()
    us.Length = len(text.encode("utf-16-le"))
    us.MaximumLength = ctypes.sizeof(buffer)
    us.Buffer = ctypes.cast(buffer, ctypes.c_wchar_p)

    return us, buffer


def open_directory_win32(path: Path):
    """
    Open a directory using ordinary Win32 CreateFileW.

    This handle is then supplied as OBJECT_ATTRIBUTES.RootDirectory.
    """

    handle = CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        3,  # OPEN_EXISTING
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        None,
    )

    if not is_valid_handle(handle):
        error = ctypes.get_last_error()
        raise RuntimeError(
            f"CreateFileW directory failed: Win32 error {error}"
        )

    return handle


def nt_open_relative(
    root_handle,
    relative_name: str,
    *,
    dont_reparse: bool,
    directory: bool,
):
    """
    NtCreateFile using:

        RootDirectory = existing directory HANDLE
        ObjectName    = relative component/path

    Returns:
        (handle, status, io_information)
    """

    unicode_name, backing = make_unicode_string(relative_name)

    object_attributes = OBJECT_ATTRIBUTES()
    object_attributes.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    object_attributes.RootDirectory = root_handle
    object_attributes.ObjectName = ctypes.pointer(unicode_name)

    attributes = OBJ_CASE_INSENSITIVE

    if dont_reparse:
        attributes |= OBJ_DONT_REPARSE

    object_attributes.Attributes = attributes
    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    io_status = IO_STATUS_BLOCK()
    result_handle = HANDLE()

    create_options = FILE_SYNCHRONOUS_IO_NONALERT

    if directory:
        create_options |= FILE_DIRECTORY_FILE
    else:
        create_options |= FILE_NON_DIRECTORY_FILE

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

    status_u32 = ntstatus_u32(status)

    # Keep the backing buffer alive through the call.
    _ = backing

    if status_u32 == STATUS_SUCCESS:
        return result_handle, status_u32, io_status.Information

    return None, status_u32, io_status.Information


def print_result(label: str, passed: bool, detail: str = ""):
    state = "PASS" if passed else "FAIL"
    if detail:
        print(f"[{state}] {label}: {detail}")
    else:
        print(f"[{state}] {label}")


def run_nt_open_test(
    label: str,
    root_handle,
    relative_name: str,
    *,
    dont_reparse: bool,
    directory: bool,
    expected_success: bool,
    expected_status: int | None = None,
):
    handle, status, information = nt_open_relative(
        root_handle,
        relative_name,
        dont_reparse=dont_reparse,
        directory=directory,
    )

    name = ntstatus_name(status)

    if expected_status is not None:
        passed = status == expected_status
    elif expected_success:
        passed = status == STATUS_SUCCESS
    else:
        passed = status != STATUS_SUCCESS

    detail = (
        f"status 0x{status:08X} ({name})"
        f", reparse={'ON' if dont_reparse else 'OFF'}"
    )

    print_result(label, passed, detail)

    if handle is not None:
        close_handle(handle)

    return passed, status


def create_junction(link: Path, target: Path) -> bool:
    """
    Create a directory junction with mklink /J.

    This normally does not require administrator privileges.
    """

    if link.exists() or link.is_symlink():
        return False

    result = subprocess.run(
        [
            "cmd.exe",
            "/c",
            "mklink",
            "/J",
            str(link),
            str(target),
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0 and link.exists():
        return True

    print("    mklink /J failed:")
    print(f"      stdout: {result.stdout.strip()}")
    print(f"      stderr: {result.stderr.strip()}")

    return False


def create_file_symlink(link: Path, target: Path) -> bool:
    if link.exists() or link.is_symlink():
        return False

    try:
        link.symlink_to(target, target_is_directory=False)
        return True
    except OSError as exc:
        print(f"    file symlink creation skipped: {exc}")
        return False


def create_dir_symlink(link: Path, target: Path) -> bool:
    if link.exists() or link.is_symlink():
        return False

    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except OSError as exc:
        print(f"    directory symlink creation skipped: {exc}")
        return False


def print_environment():
    print("=" * 72)
    print("Environment")
    print("=" * 72)
    print(f"Python:      {sys.version}")
    print(f"Executable:  {sys.executable}")
    print(f"Pointer size:{ctypes.sizeof(ctypes.c_void_p) * 8}-bit")

    try:
        version = sys.getwindowsversion()
        print(
            f"Windows:     {version.major}.{version.minor}"
            f" build {version.build}"
        )
    except Exception as exc:
        print(f"Windows:     unavailable ({exc})")

    print(f"OBJ_CASE_INSENSITIVE = 0x{OBJ_CASE_INSENSITIVE:08X}")
    print(f"OBJ_DONT_REPARSE     = 0x{OBJ_DONT_REPARSE:08X}")
    print()


def main() -> int:
    print_environment()

    test_root = Path(tempfile.mkdtemp(prefix="lumina_ntcreate_test_"))

    print("=" * 72)
    print("Test workspace")
    print("=" * 72)
    print(test_root)
    print()

    try:
        # ---------------------------------------------------------------
        # Build filesystem topology
        # ---------------------------------------------------------------

        real = test_root / "real"
        real.mkdir()

        target_dir = real / "target_dir"
        target_dir.mkdir()

        target_file = real / "target.txt"
        target_file.write_text(
            "NTCREATEFILE TEST TARGET\n",
            encoding="utf-8",
        )

        # This is the object that should be reached through the junction.
        nested_dir = target_dir / "nested"
        nested_dir.mkdir()

        nested_file = nested_dir / "nested.txt"
        nested_file.write_text(
            "NESTED TARGET\n",
            encoding="utf-8",
        )

        # Junction pointing at real directory.
        junction = test_root / "junction"
        junction_created = create_junction(junction, real)

        print("=" * 72)
        print("Filesystem topology")
        print("=" * 72)
        print(f"real directory:       {real}")
        print(f"target file:          {target_file}")
        print(f"junction created:     {junction_created}")

        if junction_created:
            print(f"junction ->           {real}")

        print()

        # ---------------------------------------------------------------
        # Open the test root as the RootDirectory handle.
        # ---------------------------------------------------------------

        root_handle = open_directory_win32(test_root)

        print("=" * 72)
        print("RootDirectory handle")
        print("=" * 72)
        print("Successfully opened test-root directory HANDLE.")
        print()

        total = 0
        passed = 0

        def check(*args, **kwargs):
            nonlocal total, passed
            total += 1
            ok, _ = run_nt_open_test(*args, **kwargs)
            if ok:
                passed += 1

        # ---------------------------------------------------------------
        # CONTROL TESTS
        # ---------------------------------------------------------------

        print("=" * 72)
        print("CONTROL TESTS: ordinary relative opens")
        print("=" * 72)

        check(
            "A1 ordinary relative file, OBJ_DONT_REPARSE",
            root_handle,
            "real\\target.txt",
            dont_reparse=True,
            directory=False,
            expected_success=True,
        )

        check(
            "A2 ordinary relative directory, OBJ_DONT_REPARSE",
            root_handle,
            "real\\target_dir",
            dont_reparse=True,
            directory=True,
            expected_success=True,
        )

        # ---------------------------------------------------------------
        # JUNCTION POSITIVE CONTROLS
        # ---------------------------------------------------------------

        print()
        print("=" * 72)
        print("JUNCTION TESTS WITHOUT OBJ_DONT_REPARSE")
        print("=" * 72)

        if junction_created:
            # Final component is the junction itself.
            check(
                "B1 final junction WITHOUT OBJ_DONT_REPARSE",
                root_handle,
                "junction",
                dont_reparse=False,
                directory=True,
                expected_success=True,
            )

            # Intermediate component is the junction.
            check(
                "B2 intermediate junction WITHOUT OBJ_DONT_REPARSE",
                root_handle,
                "junction\\target.txt",
                dont_reparse=False,
                directory=False,
                expected_success=True,
            )

        else:
            print("[SKIP] Junction tests could not be created.")

        # ---------------------------------------------------------------
        # JUNCTION NEGATIVE TESTS
        # ---------------------------------------------------------------

        print()
        print("=" * 72)
        print("JUNCTION TESTS WITH OBJ_DONT_REPARSE")
        print("=" * 72)

        if junction_created:
            check(
                "C1 final junction WITH OBJ_DONT_REPARSE",
                root_handle,
                "junction",
                dont_reparse=True,
                directory=True,
                expected_success=False,
                expected_status=STATUS_REPARSE_POINT_ENCOUNTERED,
            )

            check(
                "C2 intermediate junction WITH OBJ_DONT_REPARSE",
                root_handle,
                "junction\\target.txt",
                dont_reparse=True,
                directory=False,
                expected_success=False,
                expected_status=STATUS_REPARSE_POINT_ENCOUNTERED,
            )

        else:
            print("[SKIP] Junction tests could not be created.")

        # ---------------------------------------------------------------
        # SYMLINK TESTS
        # ---------------------------------------------------------------

        print()
        print("=" * 72)
        print("SYMLINK TESTS")
        print("=" * 72)

        file_link = test_root / "file_link"
        dir_link = test_root / "dir_link"

        file_link_created = create_file_symlink(
            file_link,
            target_file,
        )

        dir_link_created = create_dir_symlink(
            dir_link,
            real,
        )

        if file_link_created:
            print(f"Created file symlink: {file_link} -> {target_file}")

            check(
                "D1 file symlink WITHOUT OBJ_DONT_REPARSE",
                root_handle,
                "file_link",
                dont_reparse=False,
                directory=False,
                expected_success=True,
            )

            check(
                "D2 file symlink WITH OBJ_DONT_REPARSE",
                root_handle,
                "file_link",
                dont_reparse=True,
                directory=False,
                expected_success=False,
                expected_status=STATUS_REPARSE_POINT_ENCOUNTERED,
            )
        else:
            print("[SKIP] File symlink unavailable.")

        if dir_link_created:
            print(f"Created directory symlink: {dir_link} -> {real}")

            check(
                "D3 directory symlink WITHOUT OBJ_DONT_REPARSE",
                root_handle,
                "dir_link\\target.txt",
                dont_reparse=False,
                directory=False,
                expected_success=True,
            )

            check(
                "D4 directory symlink WITH OBJ_DONT_REPARSE",
                root_handle,
                "dir_link\\target.txt",
                dont_reparse=True,
                directory=False,
                expected_success=False,
                expected_status=STATUS_REPARSE_POINT_ENCOUNTERED,
            )
        else:
            print("[SKIP] Directory symlink unavailable.")

        close_handle(root_handle)

        # ---------------------------------------------------------------
        # Summary
        # ---------------------------------------------------------------

        print()
        print("=" * 72)
        print("RESULT")
        print("=" * 72)

        print(f"Passed: {passed}/{total}")

        if passed == total:
            print()
            print("RESULT: PASS")
            print()
            print(
                "All executed capability tests matched their expected "
                "behavior."
            )
            return 0

        print()
        print("RESULT: FAIL")
        print()
        print(
            "At least one executed capability test did not match the "
            "expected behavior."
        )
        return 1

    finally:
        # Cleanup.
        try:
            shutil.rmtree(test_root)
        except Exception as exc:
            print()
            print(f"WARNING: cleanup failed: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())