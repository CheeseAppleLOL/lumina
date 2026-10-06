#!/usr/bin/env python3
"""
Standalone Windows capability test v8.

Tests:
  A) NtCreateFile relative to a directory HANDLE with OBJ_DONT_REPARSE,
     followed by NtSetInformationFile(FileRenameInformation) replacement.
  B) The same rename against a destination directory junction.

CASE A passes only if:
  - the NT-relative source open succeeds,
  - the replacement write succeeds,
  - NtSetInformationFile succeeds,
  - the source name disappears,
  - the final destination contains exactly the expected replacement data.

CASE B passes only if:
  - the rename does not succeed,
  - the outside protected file remains unchanged,
  - the destination junction remains present,
  - the temporary source remains present.

This is a standalone capability test. It does not modify Lumina source files.
"""

from __future__ import annotations

import ctypes
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001

FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

OPEN_EXISTING = 3

FileRenameInformation = 10

STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B

SOURCE_DESIRED_ACCESS = (
    GENERIC_READ
    | GENERIC_WRITE
    | DELETE
    | SYNCHRONIZE
)


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


def status_u32(status: int) -> int:
    return ctypes.c_uint32(status).value


def status_hex(status: int) -> str:
    return f"0x{status_u32(status):08X}"


def status_success(status: int) -> bool:
    return status_u32(status) < 0x80000000


def win_error(prefix: str) -> OSError:
    error = ctypes.get_last_error()
    return OSError(
        error,
        f"{prefix}: Win32 error {error}: "
        f"{ctypes.FormatError(error).strip()}",
    )


def close_handle(handle) -> None:
    if handle is not None and handle != INVALID_HANDLE_VALUE:
        try:
            CloseHandle(handle)
        except Exception:
            pass


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def create_empty_file(path: Path) -> None:
    """
    Create a zero-length source fixture.

    The NT WriteFile operation in these tests is intentionally responsible
    for supplying the complete source contents. Starting from an empty file
    avoids testing file-position/truncation behavior unrelated to the rename.
    """
    path.write_bytes(b"")


def open_directory(path: Path):
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
        raise win_error(f"CreateFileW(directory={path!s})")

    return handle


def make_object_attributes(name: str, root_handle):
    backing = ctypes.create_unicode_buffer(name)
    encoded = name.encode("utf-16-le")

    unicode_string = UNICODE_STRING(
        len(encoded),
        len(encoded) + 2,
        ctypes.cast(backing, wintypes.LPWSTR),
    )

    object_attributes = OBJECT_ATTRIBUTES()
    object_attributes.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    object_attributes.RootDirectory = root_handle
    object_attributes.ObjectName = ctypes.pointer(unicode_string)
    object_attributes.Attributes = (
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
    )

    return object_attributes, unicode_string, backing


def nt_open_relative_file(root_handle, name: str):
    object_attributes, unicode_string, backing = (
        make_object_attributes(name, root_handle)
    )

    handle = wintypes.HANDLE()
    io_status = IO_STATUS_BLOCK()

    status = NtCreateFile(
        ctypes.byref(handle),
        SOURCE_DESIRED_ACCESS,
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0,
    )

    _ = (unicode_string, backing)

    return status_u32(status), handle


def write_and_flush(handle, data: bytes) -> None:
    buffer = ctypes.create_string_buffer(data)
    written = wintypes.DWORD()

    if not WriteFile(
        handle,
        ctypes.byref(buffer),
        len(data),
        ctypes.byref(written),
        None,
    ):
        raise win_error("WriteFile")

    if written.value != len(data):
        raise RuntimeError(
            f"WriteFile wrote {written.value} bytes; "
            f"expected {len(data)}"
        )

    if not FlushFileBuffers(handle):
        raise win_error("FlushFileBuffers")


def make_rename_buffer(root_handle, destination: str):
    encoded_name = destination.encode("utf-16-le")
    buffer_size = 20 + len(encoded_name)

    buffer = ctypes.create_string_buffer(buffer_size)

    # FILE_RENAME_INFORMATION.ReplaceIfExists
    ctypes.c_ubyte.from_buffer(buffer, 0).value = 1

    # FILE_RENAME_INFORMATION.RootDirectory
    ctypes.c_void_p.from_buffer(buffer, 8).value = int(root_handle)

    # FILE_RENAME_INFORMATION.FileNameLength
    ctypes.c_uint32.from_buffer(buffer, 16).value = len(encoded_name)

    # FILE_RENAME_INFORMATION.FileName
    ctypes.memmove(
        ctypes.addressof(buffer) + 20,
        encoded_name,
        len(encoded_name),
    )

    return buffer, buffer_size


def nt_replace(source_handle, root_handle, destination: str) -> int:
    buffer, buffer_size = make_rename_buffer(
        root_handle,
        destination,
    )

    io_status = IO_STATUS_BLOCK()

    status = NtSetInformationFile(
        source_handle,
        ctypes.byref(io_status),
        ctypes.byref(buffer),
        buffer_size,
        FileRenameInformation,
    )

    return status_u32(status)


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
            f"mklink reported success but junction does not exist: "
            f"{junction}"
        )


def case_a(root: Path) -> bool:
    print("-" * 72)
    print("CASE A - Normal Atomic Replacement")
    print("-" * 72)
    print()

    target = root / "target.txt"
    source = root / "temporary_source.txt"

    original = "ORIGINAL_TARGET_CONTENT\n"
    replacement = "NEW_REPLACEMENT_CONTENT\n"

    write_text(target, original)

    # IMPORTANT:
    # The source starts empty. The NT WriteFile below therefore supplies
    # exactly the intended replacement contents without appending to a
    # pre-existing fixture payload.
    create_empty_file(source)

    print(f"Existing target: {target}")

    root_handle = None
    source_handle = None

    try:
        root_handle = open_directory(root)
        print("Root HANDLE: PASS")

        print(
            "Creating temporary source with "
            "RootDirectory + OBJ_DONT_REPARSE..."
        )

        status, source_handle = nt_open_relative_file(
            root_handle,
            source.name,
        )

        print(f"NtCreateFile status: {status_hex(status)}")

        if not status_success(status):
            print("Temporary source HANDLE: FAIL")
            return False

        print("Temporary source HANDLE: PASS")

        write_and_flush(
            source_handle,
            replacement.encode("utf-8"),
        )

        print("Write + FlushFileBuffers: PASS")
        print()
        print(
            "Calling NtSetInformationFile(FileRenameInformation)..."
        )

        rename_status = nt_replace(
            source_handle,
            root_handle,
            target.name,
        )

        print(
            f"NtSetInformationFile status: "
            f"{status_hex(rename_status)}"
        )

        if rename_status != STATUS_SUCCESS:
            print("Relative replacement: FAIL")
            return False

        print("Relative replacement: PASS")

    finally:
        close_handle(source_handle)
        print("Renamed HANDLE closed: PASS")
        close_handle(root_handle)

    if source.exists():
        print("Source removal: FAIL")
        return False

    print("Source removal: PASS")

    if not target.exists():
        print("Final target exists: FAIL")
        return False

    final_contents = read_text(target)

    print(f"Final target contents: {final_contents!r}")

    if final_contents != replacement:
        print("Destination replacement verification: FAIL")
        return False

    print("Destination replacement verification: PASS")
    print()
    print("CASE A RESULT: PASS")

    return True


def case_b(root: Path) -> bool:
    print("-" * 72)
    print("CASE B - Reparse-Point Destination")
    print("-" * 72)
    print()

    outside = root / "outside"
    outside_marker = outside / "protected.txt"
    destination_junction = root / "target_junction"
    source = root / "temporary_source_b.txt"

    outside.mkdir()

    protected_contents = "OUTSIDE_MUST_NOT_CHANGE\n"
    replacement_contents = "MUST_NOT_REPLACE_JUNCTION\n"

    write_text(
        outside_marker,
        protected_contents,
    )

    print(f"Outside directory: {outside}")
    print(f"Outside protected file: {outside_marker}")
    print(f"Destination junction: {destination_junction}")

    create_junction(
        destination_junction,
        outside,
    )

    print("Destination junction creation: PASS")

    root_handle = None
    source_handle = None
    rename_status = None

    try:
        root_handle = open_directory(root)
        print("Root HANDLE: PASS")

        # Start the source empty for the same reason as Case A.
        create_empty_file(source)

        print("Creating temporary source...")

        status, source_handle = nt_open_relative_file(
            root_handle,
            source.name,
        )

        print(f"NtCreateFile status: {status_hex(status)}")

        if not status_success(status):
            print("Temporary source HANDLE: FAIL")
            return False

        write_and_flush(
            source_handle,
            replacement_contents.encode("utf-8"),
        )

        print("Temporary source write + flush: PASS")
        print()
        print("Attempting to replace the junction destination...")

        rename_status = nt_replace(
            source_handle,
            root_handle,
            destination_junction.name,
        )

        print(
            f"NtSetInformationFile status: "
            f"{status_hex(rename_status)}"
        )

    finally:
        close_handle(source_handle)
        close_handle(root_handle)

    outside_exists = outside_marker.exists()
    junction_exists = destination_junction.exists()
    source_exists = source.exists()

    outside_contents = (
        read_text(outside_marker)
        if outside_exists
        else None
    )

    print()
    print(
        f"Outside protected file exists: "
        f"{outside_exists}"
    )
    print(
        f"Outside protected file contents: "
        f"{outside_contents!r}"
    )
    print(
        f"Destination junction exists: "
        f"{junction_exists}"
    )
    print(
        f"Temporary source name exists: "
        f"{source_exists}"
    )

    if rename_status == STATUS_SUCCESS:
        print(
            "SECURITY FAILURE: junction destination "
            "was replaced."
        )
        return False

    if not outside_exists:
        print(
            "SECURITY FAILURE: outside protected file "
            "disappeared."
        )
        return False

    if outside_contents != protected_contents:
        print(
            "SECURITY FAILURE: outside protected file "
            "changed."
        )
        return False

    if not junction_exists:
        print(
            "SECURITY FAILURE: destination junction "
            "disappeared."
        )
        return False

    if not source_exists:
        print(
            "SECURITY FAILURE: temporary source disappeared "
            "even though replacement against the junction "
            "did not succeed."
        )
        return False

    if rename_status == STATUS_ACCESS_DENIED:
        print(
            "Destination junction preservation: PASS "
            "(STATUS_ACCESS_DENIED)"
        )
    elif rename_status == STATUS_REPARSE_POINT_ENCOUNTERED:
        print(
            "Destination junction preservation: PASS "
            "(STATUS_REPARSE_POINT_ENCOUNTERED)"
        )
    else:
        print(
            "Destination junction preservation: PASS "
            f"(non-success NTSTATUS "
            f"{status_hex(rename_status)})"
        )

    print()
    print("CASE B RESULT: PASS")

    return True


def main() -> int:
    if sys.platform != "win32":
        print("ERROR: This test requires Windows.")
        return 2

    print("=" * 72)
    print(
        "TEST - NtSetInformationFile Atomic Replacement "
        "Security v8"
    )
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
    print("This test combines:")
    print(
        "  NtCreateFile("
        "RootDirectory + OBJ_DONT_REPARSE)"
    )
    print(
        "  + NtSetInformationFile("
        "FileRenameInformation)"
    )
    print("  + ReplaceIfExists = TRUE")
    print()

    root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntrename_security_v8_"
        )
    )

    print(f"Test root: {root}")
    print()

    case_a_result = False
    case_b_result = False

    try:
        case_a_result = case_a(root)

        print()

        case_b_result = case_b(root)

        print()
        print("=" * 72)

        if case_a_result and case_b_result:
            print("RESULT: PASS")
            print("=" * 72)
            print()
            print("Verified in the tested Windows environment:")
            print(
                "  1. Relative NtCreateFile from a directory "
                "HANDLE works."
            )
            print(
                "  2. OBJ_DONT_REPARSE is accepted for that "
                "relative open."
            )
            print(
                "  3. Relative FileRenameInformation replacement "
                "works."
            )
            print(
                "  4. Normal replacement produces exactly the "
                "expected final contents."
            )
            print(
                "  5. A destination directory junction was not "
                "replaced."
            )
            print(
                "  6. The protected outside file remained "
                "unchanged."
            )
            print()
            print(
                "This does not establish complete "
                "Windows/POSIX state-backend parity."
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
            shutil.rmtree(root)
            print()
            print(f"Cleaned up: {root}")
        except Exception as exc:
            print()
            print(
                "WARNING: Could not remove test directory: "
                f"{root}"
            )
            print(f"Cleanup error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())