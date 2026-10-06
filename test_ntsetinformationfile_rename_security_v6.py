#!/usr/bin/env python3
"""
TEST - NtSetInformationFile Atomic Replacement Security v6

Purpose
-------
Validate the Windows NT-native primitives needed for secure, handle-relative
atomic replacement:

    NtCreateFile(
        RootDirectory=<directory HANDLE>,
        ObjectName=<relative name>,
        OBJ_DONT_REPARSE
    )

    +
    
    NtSetInformationFile(
        FileRenameInformation,
        ReplaceIfExists=TRUE,
        RootDirectory=<directory HANDLE>,
        FileName=<relative name>
    )

Two cases are tested:

    CASE A
        Normal atomic replacement of an existing regular file.

    CASE B
        Attempted replacement where the destination name is a directory
        junction pointing outside the test root.

Security expectations
---------------------
CASE A:
    - Replacement succeeds.
    - Existing destination is replaced.
    - Temporary source name disappears.
    - Final destination contains replacement contents.

CASE B:
    - Rename must NOT modify the outside protected file.
    - Rename must NOT successfully replace/traverse the destination junction.
    - A non-successful NTSTATUS with the junction and outside file preserved
      is treated as PASS.

This is a standalone capability test. It does not modify Lumina source files.

Tested target environment:
    Windows 10 build 19045
    Python 3.14.x

IMPORTANT:
    This test intentionally uses ntdll.NtCreateFile and
    ntdll.NtSetInformationFile directly. It is not an implementation of the
    final Lumina state backend.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


# ============================================================================
# Windows constants
# ============================================================================

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# DesiredAccess
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000

# ShareAccess
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

# Create disposition
FILE_OPEN = 0x00000001

# CreateOptions
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

# ObjectAttributes
OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

# NtCreateFile access mask needed for a synchronous handle.
SOURCE_DESIRED_ACCESS = (
    GENERIC_READ
    | GENERIC_WRITE
    | DELETE
    | SYNCHRONIZE
)

# NtSetInformationFile
FileRenameInformation = 10

# NTSTATUS values
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B

# Win32 file creation
CREATE_NEW = 1
OPEN_EXISTING = 3

# Directory opening
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

# File attributes
FILE_ATTRIBUTE_NORMAL = 0x00000080


# ============================================================================
# ctypes structures
# ============================================================================

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


# ============================================================================
# API prototypes
# ============================================================================

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


WriteFile = kernel32.WriteFile
WriteFile.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
WriteFile.restype = wintypes.BOOL


FlushFileBuffers = kernel32.FlushFileBuffers
FlushFileBuffers.argtypes = [wintypes.HANDLE]
FlushFileBuffers.restype = wintypes.BOOL


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


NtSetInformationFile = ntdll.NtSetInformationFile
NtSetInformationFile.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(IO_STATUS_BLOCK),
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]
NtSetInformationFile.restype = wintypes.LONG


# ============================================================================
# Utility functions
# ============================================================================

def ntstatus_u32(status: int) -> int:
    """Return NTSTATUS as an unsigned 32-bit integer."""
    return ctypes.c_uint32(status).value


def ntstatus_hex(status: int) -> str:
    """Format NTSTATUS in the form used by the Windows documentation."""
    return f"0x{ntstatus_u32(status):08X}"


def ntstatus_success(status: int) -> bool:
    """
    NTSTATUS success test.

    NTSTATUS values are signed 32-bit values. Any status with the high bit
    clear is a success/informational result.
    """
    return ntstatus_u32(status) < 0x80000000


def win_error(prefix: str) -> OSError:
    error = ctypes.get_last_error()
    return OSError(
        error,
        f"{prefix}: Win32 error {error}: "
        f"{ctypes.FormatError(error).strip()}",
    )


def check_handle(handle, description: str):
    if handle is None or handle == INVALID_HANDLE_VALUE:
        raise win_error(description)
    return handle


def close_handle(handle) -> None:
    if handle is None or handle == INVALID_HANDLE_VALUE:
        return

    try:
        CloseHandle(handle)
    except Exception:
        pass


def read_text(path: Path) -> str:
    """
    Read a small UTF-8 test marker.

    This helper is deliberately simple because it is only used for verifying
    the test fixture after the NT-level operation.
    """
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def make_unicode_string(text: str):
    """
    Build a UNICODE_STRING whose backing buffer remains alive for the caller.
    """
    buffer = ctypes.create_unicode_buffer(text)

    encoded_length = len(text.encode("utf-16-le"))

    value = UNICODE_STRING()
    value.Length = encoded_length
    value.MaximumLength = encoded_length + 2
    value.Buffer = ctypes.cast(buffer, wintypes.LPWSTR)

    return value, buffer


def build_object_attributes(
    object_name: str,
    root_directory,
    attributes: int,
):
    """
    Construct OBJECT_ATTRIBUTES for an NT relative open.

    The returned UNICODE_STRING and backing buffer must remain alive until the
    NtCreateFile call completes.
    """
    unicode_name, name_buffer = make_unicode_string(object_name)

    object_attributes = OBJECT_ATTRIBUTES()
    object_attributes.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    object_attributes.RootDirectory = root_directory
    object_attributes.ObjectName = ctypes.pointer(unicode_name)
    object_attributes.Attributes = attributes
    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    return object_attributes, unicode_name, name_buffer


def open_directory_handle(path: Path):
    """
    Open a directory HANDLE suitable for use as NtCreateFile RootDirectory
    and NtSetInformationFile FileRenameInformation RootDirectory.
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

    return check_handle(
        handle,
        f"CreateFileW(directory={str(path)!r})",
    )


def create_regular_file(path: Path, contents: str) -> None:
    """
    Create a normal regular file using ordinary Python file I/O.

    This is fixture setup only. The security-sensitive source open is done
    with NtCreateFile below.
    """
    write_text(path, contents)


def create_junction(junction: Path, target: Path) -> None:
    """
    Create a directory junction using mklink /J.
    """
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
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        raise RuntimeError(
            "mklink /J failed.\n"
            f"return code: {result.returncode}\n"
            f"stdout: {stdout}\n"
            f"stderr: {stderr}"
        )

    if not junction.exists():
        raise RuntimeError(
            f"mklink reported success but junction does not exist: {junction}"
        )


# ============================================================================
# NT-native file operations
# ============================================================================

def nt_open_relative_file(
    root_handle,
    relative_name: str,
    *,
    desired_access: int = SOURCE_DESIRED_ACCESS,
    create_options: int = (
        FILE_NON_DIRECTORY_FILE
        | FILE_SYNCHRONOUS_IO_NONALERT
    ),
    object_attributes: int = (
        OBJ_CASE_INSENSITIVE
        | OBJ_DONT_REPARSE
    ),
):
    """
    Open a file relative to an already-open directory HANDLE.

    OBJ_DONT_REPARSE is intentionally enabled.

    The caller owns the returned HANDLE.
    """
    attributes, unicode_name, name_buffer = build_object_attributes(
        relative_name,
        root_handle,
        object_attributes,
    )

    handle = wintypes.HANDLE()
    io_status = IO_STATUS_BLOCK()

    status = NtCreateFile(
        ctypes.byref(handle),
        desired_access,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        create_options,
        None,
        0,
    )

    # Keep references alive through the call explicitly. They normally remain
    # alive anyway, but these assignments make the lifetime requirement clear.
    _ = unicode_name
    _ = name_buffer

    return ntstatus_u32(status), handle


def write_and_flush(handle, contents: bytes) -> None:
    """
    Write replacement contents through the NT-opened source HANDLE and flush
    the file buffers.
    """
    buffer = ctypes.create_string_buffer(contents)
    written = wintypes.DWORD()

    ok = WriteFile(
        handle,
        ctypes.byref(buffer),
        len(contents),
        ctypes.byref(written),
        None,
    )

    if not ok:
        raise win_error("WriteFile")

    if written.value != len(contents):
        raise RuntimeError(
            f"WriteFile wrote {written.value} bytes; "
            f"expected {len(contents)}"
        )

    if not FlushFileBuffers(handle):
        raise win_error("FlushFileBuffers")


def build_file_rename_information(
    root_directory_handle,
    destination_name: str,
    *,
    replace_if_exists: bool = True,
):
    """
    Construct the FILE_RENAME_INFORMATION buffer used by
    NtSetInformationFile.

    Layout used by Windows for FileRenameInformation:

        offset 0   : ReplaceIfExists
        offset 8   : RootDirectory
        offset 16  : FileNameLength
        offset 20  : FileName[...]
    """
    encoded_name = destination_name.encode("utf-16-le")
    name_length = len(encoded_name)

    header_size = 20
    total_size = header_size + name_length

    buffer = ctypes.create_string_buffer(total_size)

    # BOOLEAN ReplaceIfExists at offset 0.
    ctypes.c_ubyte.from_buffer(buffer, 0).value = (
        1 if replace_if_exists else 0
    )

    # RootDirectory HANDLE at offset 8.
    ctypes.c_void_p.from_buffer(buffer, 8).value = int(
        root_directory_handle
    )

    # FileNameLength ULONG at offset 16.
    ctypes.c_uint32.from_buffer(buffer, 16).value = name_length

    # UTF-16LE destination name at offset 20.
    ctypes.memmove(
        ctypes.addressof(buffer) + header_size,
        encoded_name,
        name_length,
    )

    return buffer, total_size


def nt_relative_replace(
    source_handle,
    root_directory_handle,
    destination_name: str,
) -> int:
    """
    Perform:

        NtSetInformationFile(
            source_handle,
            FileRenameInformation,
            ReplaceIfExists=TRUE,
            RootDirectory=root_directory_handle,
            FileName=destination_name
        )
    """
    rename_buffer, rename_size = build_file_rename_information(
        root_directory_handle,
        destination_name,
        replace_if_exists=True,
    )

    io_status = IO_STATUS_BLOCK()

    status = NtSetInformationFile(
        source_handle,
        ctypes.byref(io_status),
        ctypes.byref(rename_buffer),
        rename_size,
        FileRenameInformation,
    )

    return ntstatus_u32(status)


# ============================================================================
# CASE A
# ============================================================================

def test_normal_atomic_replacement(root: Path) -> bool:
    print("-" * 72)
    print("CASE A - Normal Atomic Replacement")
    print("-" * 72)
    print()

    target = root / "target.txt"
    temporary = root / "temporary_source.txt"

    original_contents = "ORIGINAL_TARGET_CONTENT\n"
    replacement_contents = "NEW_REPLACEMENT_CONTENT\n"

    create_regular_file(target, original_contents)

    print(f"Existing target: {target}")

    root_handle = None
    source_handle = None

    try:
        root_handle = open_directory_handle(root)
        print("Root HANDLE: PASS")

        # Create the source fixture first. The actual security-sensitive
        # source open below is NT-relative with OBJ_DONT_REPARSE.
        create_regular_file(temporary, replacement_contents)

        print(
            "Creating temporary source with "
            "RootDirectory + OBJ_DONT_REPARSE..."
        )

        status, source_handle = nt_open_relative_file(
            root_handle,
            temporary.name,
        )

        print(f"NtCreateFile status: {ntstatus_hex(status)}")

        if not ntstatus_success(status):
            print("Temporary source HANDLE: FAIL")
            return False

        print("Temporary source HANDLE: PASS")

        # The file was already populated by fixture setup. Flush it through
        # the NT handle as an additional verification of HANDLE access.
        write_and_flush_handle(source_handle, replacement_contents.encode())
        print("Write + FlushFileBuffers: PASS")

        print()
        print("Calling NtSetInformationFile(FileRenameInformation)...")

        status = nt_relative_replace(
            source_handle,
            root_handle,
            target.name,
        )

        print(
            f"NtSetInformationFile status: "
            f"{ntstatus_hex(status)}"
        )

        if status != STATUS_SUCCESS:
            print("Relative replacement: FAIL")
            return False

        print("Relative replacement: PASS")

    finally:
        # The renamed HANDLE must be closed before the normal Python reopen.
        close_handle(source_handle)
        source_handle = None
        print("Renamed HANDLE closed: PASS")

        close_handle(root_handle)
        root_handle = None

    if temporary.exists():
        print("Source removal: FAIL")
        return False

    print("Source removal: PASS")

    if not target.exists():
        print("Final target exists: FAIL")
        return False

    final_contents = read_text(target)
    print(f"Final target contents: {final_contents!r}")

    if final_contents != replacement_contents:
        print("Destination replacement verification: FAIL")
        return False

    print("Destination replacement verification: PASS")
    print()
    print("CASE A RESULT: PASS")
    return True


# ============================================================================
# CASE B
# ============================================================================

def test_junction_destination(root: Path) -> bool:
    print("-" * 72)
    print("CASE B - Reparse-Point Destination")
    print("-" * 72)
    print()

    outside = root / "outside"
    outside_marker = outside / "protected.txt"
    destination_junction = root / "target_junction"
    temporary = root / "temporary_source_b.txt"

    outside.mkdir()

    protected_contents = "OUTSIDE_MUST_NOT_CHANGE\n"
    replacement_contents = "MUST_NOT_REPLACE_JUNCTION\n"

    write_text(outside_marker, protected_contents)

    print(f"Outside directory: {outside}")
    print(f"Outside protected file: {outside_marker}")
    print(f"Destination junction: {destination_junction}")

    create_junction(destination_junction, outside)

    print("Destination junction creation: PASS")

    root_handle = None
    source_handle = None

    try:
        root_handle = open_directory_handle(root)
        print("Root HANDLE: PASS")

        create_regular_file(temporary, replacement_contents)

        print("Creating temporary source...")

        status, source_handle = nt_open_relative_file(
            root_handle,
            temporary.name,
        )

        print(f"NtCreateFile status: {ntstatus_hex(status)}")

        if not ntstatus_success(status):
            print("Temporary source HANDLE: FAIL")
            return False

        write_and_flush_handle(
            source_handle,
            replacement_contents.encode(),
        )
        print("Temporary source write + flush: PASS")

        print()
        print("Attempting to replace the junction destination...")

        status = nt_relative_replace(
            source_handle,
            root_handle,
            destination_junction.name,
        )

        print(
            f"NtSetInformationFile status: "
            f"{ntstatus_hex(status)}"
        )

        if status == STATUS_SUCCESS:
            print()
            print(
                "SECURITY FAILURE: NtSetInformationFile successfully "
                "replaced the reparse-point destination."
            )
            return False

        # A failed operation is expected here. Preserve the exact status in
        # the output rather than assuming that every rejection must have the
        # same NTSTATUS.
        print(
            "Rename did not succeed against the reparse-point "
            "destination."
        )

    finally:
        close_handle(source_handle)
        source_handle = None

        close_handle(root_handle)
        root_handle = None

    # Verify the security-sensitive postconditions after all handles are
    # closed. These checks are deliberately outside the NT operation itself.
    outside_exists = outside_marker.exists()
    junction_exists = destination_junction.exists()
    source_exists = temporary.exists()

    outside_contents = None
    if outside_exists:
        outside_contents = read_text(outside_marker)

    print()
    print(f"Outside protected file exists: {outside_exists}")

    if outside_contents is not None:
        print(
            f"Outside protected file contents: "
            f"{outside_contents!r}"
        )
    else:
        print("Outside protected file contents: <missing>")

    print(f"Destination junction exists: {junction_exists}")
    print(f"Temporary source name exists: {source_exists}")

    if not outside_exists:
        print()
        print(
            "SECURITY FAILURE: outside protected file was removed."
        )
        return False

    if outside_contents != protected_contents:
        print()
        print(
            "SECURITY FAILURE: outside protected file contents changed."
        )
        return False

    if not junction_exists:
        print()
        print(
            "SECURITY FAILURE: destination junction disappeared."
        )
        return False

    if not source_exists:
        print()
        print(
            "SECURITY FAILURE: temporary source disappeared even "
            "though replacement against the junction did not succeed."
        )
        return False

    if status == STATUS_ACCESS_DENIED:
        print(
            "Destination junction preservation: PASS "
            "(STATUS_ACCESS_DENIED)"
        )
    elif status == STATUS_REPARSE_POINT_ENCOUNTERED:
        print(
            "Destination junction preservation: PASS "
            "(STATUS_REPARSE_POINT_ENCOUNTERED)"
        )
    else:
        print(
            "Destination junction preservation: PASS "
            f"(non-success NTSTATUS {ntstatus_hex(status)})"
        )

    print()
    print("CASE B RESULT: PASS")
    return True


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    if sys.platform != "win32":
        print("ERROR: This test requires Windows.")
        return 2

    print("=" * 72)
    print("TEST - NtSetInformationFile Atomic Replacement Security v6")
    print("=" * 72)
    print()
    print(f"Python: {sys.version}")
    print(f"Pointer size: {ctypes.sizeof(ctypes.c_void_p) * 8}-bit")

    version = sys.getwindowsversion()

    print(
        f"Windows: "
        f"{version.major}.{version.minor} "
        f"build {version.build}"
    )

    print()
    print("This test combines:")
    print("  NtCreateFile(RootDirectory + OBJ_DONT_REPARSE)")
    print("  + NtSetInformationFile(FileRenameInformation)")
    print("  + ReplaceIfExists = TRUE")
    print()

    root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntrename_security_v6_"
        )
    )

    print(f"Test root: {root}")
    print()

    case_a = False
    case_b = False

    try:
        case_a = test_normal_atomic_replacement(root)

        print()

        case_b = test_junction_destination(root)

        print()
        print("=" * 72)

        if case_a and case_b:
            print("RESULT: PASS")
            print("=" * 72)
            print()
            print("Verified on this Windows environment:")
            print(
                "  1. NtCreateFile can open a relative regular file "
                "from a directory HANDLE."
            )
            print(
                "  2. OBJ_DONT_REPARSE can be used on that NT-relative "
                "open."
            )
            print(
                "  3. NtSetInformationFile(FileRenameInformation) "
                "accepts a directory HANDLE as RootDirectory."
            )
            print(
                "  4. ReplaceIfExists=TRUE performs the expected "
                "atomic replacement."
            )
            print(
                "  5. A destination directory junction was not "
                "successfully replaced/traversed."
            )
            print(
                "  6. The protected file outside the test root "
                "remained unchanged."
            )
            print()
            print(
                "This establishes the tested NT primitives for the "
                "specific scenarios above."
            )
            print(
                "It does NOT by itself establish complete POSIX "
                "state-backend parity, crash-durability parity, "
                "all reparse-point types, or all namespace-race "
                "conditions."
            )
            return 0

        print("RESULT: FAIL")
        print("=" * 72)
        print()
        print(f"Case A: {'PASS' if case_a else 'FAIL'}")
        print(f"Case B: {'PASS' if case_b else 'FAIL'}")
        return 1

    finally:
        try:
            shutil.rmtree(root)
            print()
            print(f"Cleaned up: {root}")
        except Exception as exc:
            print()
            print(
                f"WARNING: Could not remove test directory: "
                f"{root}"
            )
            print(f"Cleanup error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())