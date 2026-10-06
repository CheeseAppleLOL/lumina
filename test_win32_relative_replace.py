import argparse
import ctypes
import os
import shutil
import sys
import tempfile
from pathlib import Path
from ctypes import wintypes


# ============================================================================
# NT / Windows constants
# ============================================================================

# FILE_INFORMATION_CLASS
FileRenameInformation = 10

# Desired access
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000

# File share modes
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

# CreateFile disposition
OPEN_EXISTING = 3

# CreateFile flags
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

# NT status
STATUS_SUCCESS = 0x00000000


# ============================================================================
# Windows API setup
# ============================================================================

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")


CreateFileW = kernel32.CreateFileW
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


CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


# NTSTATUS is a 32-bit signed integer.
#
# ctypes will return a normal Python int for this function because the
# restype is a scalar ctypes integer type. We therefore normalize it
# explicitly rather than assuming the return object has a .value member.
NtSetInformationFile = ntdll.NtSetInformationFile
NtSetInformationFile.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]
NtSetInformationFile.restype = ctypes.c_long


# Converts an NTSTATUS to the corresponding Win32 error code.
RtlNtStatusToDosError = ntdll.RtlNtStatusToDosError
RtlNtStatusToDosError.argtypes = [
    ctypes.c_long,
]
RtlNtStatusToDosError.restype = wintypes.ULONG


INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


# ============================================================================
# NTSTATUS helpers
# ============================================================================

def normalize_ntstatus(status):
    """
    Normalize ctypes/Python NTSTATUS values to an unsigned 32-bit integer.

    Depending on ctypes conversion behavior, the value may arrive as a
    Python int or a ctypes scalar. This function deliberately handles both.
    """
    if hasattr(status, "value"):
        status = status.value

    return int(status) & 0xFFFFFFFF


def ntstatus_to_signed(status):
    """
    Return NTSTATUS as a signed 32-bit integer suitable for ctypes calls.
    """
    unsigned = normalize_ntstatus(status)

    if unsigned & 0x80000000:
        return unsigned - 0x100000000

    return unsigned


def ntstatus_dos_error(status):
    """
    Convert NTSTATUS to a Win32 error code.
    """
    signed_status = ntstatus_to_signed(status)

    return int(
        RtlNtStatusToDosError(
            ctypes.c_long(signed_status)
        )
    )


def format_ntstatus(status):
    """
    Format the NTSTATUS and its corresponding Win32 error.
    """
    raw = normalize_ntstatus(status)
    dos_error = ntstatus_dos_error(status)

    try:
        message = ctypes.FormatError(dos_error).strip()
    except Exception:
        message = ""

    if message:
        return (
            f"NTSTATUS 0x{raw:08X}; "
            f"Win32 error {dos_error}: {message}"
        )

    return (
        f"NTSTATUS 0x{raw:08X}; "
        f"Win32 error {dos_error}"
    )


# ============================================================================
# General helpers
# ============================================================================

def win32_error(prefix):
    error = ctypes.get_last_error()

    try:
        message = ctypes.FormatError(error).strip()
    except Exception:
        message = ""

    if message:
        return f"{prefix}: Win32 error {error}: {message}"

    return f"{prefix}: Win32 error {error}"


def check_handle(handle, description):
    if handle == INVALID_HANDLE_VALUE or handle is None:
        raise RuntimeError(
            win32_error(f"{description} failed")
        )

    return handle


def close_handle(handle):
    if handle not in (None, INVALID_HANDLE_VALUE):
        CloseHandle(handle)


def open_directory(path):
    """
    Open an existing directory and return its Windows HANDLE.

    FILE_FLAG_BACKUP_SEMANTICS is required for CreateFileW to open
    a directory.
    """
    handle = CreateFileW(
        str(path),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    return check_handle(
        handle,
        "CreateFileW(directory)",
    )


def open_file_for_rename(path):
    """
    Open the source file with DELETE access.

    DELETE access is required for a rename.
    """
    handle = CreateFileW(
        str(path),
        DELETE | GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )

    return check_handle(
        handle,
        f"CreateFileW(rename source {path.name})",
    )


def write_file(path, data):
    """
    Create/write a test file using ordinary Python I/O.

    The only operation under investigation is the NT rename.
    """
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


# ============================================================================
# FILE_RENAME_INFORMATION
# ============================================================================

def build_file_rename_information(
    root_directory_handle,
    target_name,
):
    """
    Construct a variable-sized FILE_RENAME_INFORMATION structure.

    Relevant layout on 64-bit Windows:

        offset  0: DWORD ReplaceIfExists / Flags
        offset  8: HANDLE RootDirectory
        offset 16: ULONG FileNameLength
        offset 20: WCHAR FileName[1]

    FileNameLength is measured in BYTES and does not include a
    terminating NUL.

    For this test:

        ReplaceIfExists = TRUE
        RootDirectory   = destination directory HANDLE
        FileName        = relative filename
    """
    encoded_name = target_name.encode("utf-16-le")
    name_length = len(encoded_name)

    file_name_offset = 20

    # Extra WCHAR is only for a convenient terminating NUL.
    # It is NOT included in FileNameLength.
    buffer_size = (
        file_name_offset
        + name_length
        + 2
    )

    buffer = ctypes.create_string_buffer(
        buffer_size
    )

    # ReplaceIfExists = TRUE
    ctypes.c_uint32.from_buffer(
        buffer,
        0,
    ).value = 1

    # RootDirectory = destination directory HANDLE.
    #
    # HANDLE is pointer-sized, so c_void_p is used.
    ctypes.c_void_p.from_buffer(
        buffer,
        8,
    ).value = int(root_directory_handle)

    # FileNameLength = byte length, excluding terminating NUL.
    ctypes.c_uint32.from_buffer(
        buffer,
        16,
    ).value = name_length

    # Variable-length FileName begins at byte offset 20.
    ctypes.memmove(
        ctypes.addressof(buffer) + file_name_offset,
        encoded_name,
        name_length,
    )

    # Optional terminating WCHAR.
    ctypes.c_uint16.from_buffer(
        buffer,
        file_name_offset + name_length,
    ).value = 0

    return buffer, buffer_size


# ============================================================================
# NT relative rename
# ============================================================================

def nt_relative_replace(
    source_handle,
    directory_handle,
    target_name,
):
    """
    Perform:

        source_handle
            ->
        directory_handle + target_name

    through:

        ntdll!NtSetInformationFile

    using:

        FileRenameInformation
        ReplaceIfExists = TRUE
        RootDirectory   = destination directory HANDLE
        FileName        = relative filename
    """

    rename_buffer, rename_buffer_size = (
        build_file_rename_information(
            directory_handle,
            target_name,
        )
    )

    # IO_STATUS_BLOCK:
    #
    # typedef struct _IO_STATUS_BLOCK {
    #     union {
    #         NTSTATUS Status;
    #         PVOID Pointer;
    #     };
    #     ULONG_PTR Information;
    # } IO_STATUS_BLOCK;
    #
    # On 64-bit Windows this is 16 bytes.
    io_status_block = ctypes.create_string_buffer(
        ctypes.sizeof(ctypes.c_void_p) * 2
    )

    status = NtSetInformationFile(
        source_handle,
        ctypes.cast(
            io_status_block,
            ctypes.c_void_p,
        ),
        ctypes.cast(
            rename_buffer,
            ctypes.c_void_p,
        ),
        rename_buffer_size,
        FileRenameInformation,
    )

    # Normalize immediately. From here onward we deliberately treat
    # NTSTATUS as an integer rather than accessing .value.
    status = normalize_ntstatus(status)

    if status != STATUS_SUCCESS:
        raise RuntimeError(
            "NtSetInformationFile(FileRenameInformation) failed: "
            + format_ntstatus(status)
        )

    return status


# ============================================================================
# Output helpers
# ============================================================================

def print_header():
    print("=" * 72)
    print(
        "Windows NtSetInformationFile relative-replace test"
    )
    print("=" * 72)
    print()


def pass_step(number, description):
    print(
        f"[{number}/6] {description:<39} PASS"
    )


def fail_result(message):
    print()
    print("=" * 72)
    print("RESULT: FAIL")
    print("=" * 72)
    print()
    print(message)


def success_result():
    print()
    print("=" * 72)
    print("RESULT: PASS")
    print("=" * 72)
    print()
    print(
        "NtSetInformationFile(FileRenameInformation) accepted:"
    )
    print(
        "  - a directory HANDLE in RootDirectory"
    )
    print(
        "  - a relative destination filename"
    )
    print(
        "  - ReplaceIfExists = TRUE"
    )
    print()
    print(
        "The existing target file was replaced and the "
        "temporary source file disappeared."
    )


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Test NtSetInformationFile(FileRenameInformation) "
            "with a directory HANDLE in RootDirectory."
        )
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help=(
            "Optional existing directory under which the isolated "
            "test directory will be created."
        ),
    )

    parser.add_argument(
        "--keep",
        action="store_true",
        help="Keep the temporary test directory.",
    )

    args = parser.parse_args()

    print(f"Python: {sys.version}")
    print(
        "Architecture: "
        f"{'64-bit' if sys.maxsize > 2**32 else '32-bit'}"
    )
    print()

    print_header()

    target_name = "install.json"
    temporary_name = "tmp_validation.tmp"

    test_root = None
    directory_handle = None
    source_handle = None

    try:
        # ------------------------------------------------------------------
        # Create isolated test directory.
        # ------------------------------------------------------------------
        if args.root is None:
            parent = Path(tempfile.gettempdir())
        else:
            parent = args.root

            if not parent.exists():
                raise RuntimeError(
                    f"Specified --root does not exist: {parent}"
                )

            if not parent.is_dir():
                raise RuntimeError(
                    f"Specified --root is not a directory: {parent}"
                )

        test_root = Path(
            tempfile.mkdtemp(
                prefix="lumina_nt_rename_test_",
                dir=str(parent),
            )
        )

        target_path = test_root / target_name
        temporary_path = test_root / temporary_name

        print(f"Test directory : {test_root}")
        print(f"Target         : {target_name}")
        print(f"Temporary file : {temporary_name}")
        print()
        print(
            "Rename destination supplied to Windows:"
        )
        print(
            f"    {target_name}"
        )
        print()
        print(
            "Directory HANDLE supplied as RootDirectory."
        )
        print()
        print(
            "API under test:"
        )
        print(
            "    ntdll!NtSetInformationFile"
        )
        print(
            "Information class:"
        )
        print(
            "    FileRenameInformation (10)"
        )
        print()

        # ------------------------------------------------------------------
        # [1] Create existing destination.
        # ------------------------------------------------------------------
        original_data = b'{"state":"original"}\n'

        write_file(
            target_path,
            original_data,
        )

        pass_step(
            1,
            "Created existing target file",
        )

        # ------------------------------------------------------------------
        # [2] Open destination directory.
        # ------------------------------------------------------------------
        directory_handle = open_directory(
            test_root,
        )

        print(
            f"      HANDLE = 0x{int(directory_handle):X}"
        )

        pass_step(
            2,
            "Opened directory HANDLE",
        )

        # ------------------------------------------------------------------
        # [3] Create replacement source.
        # ------------------------------------------------------------------
        replacement_data = b'{"state":"replacement"}\n'

        write_file(
            temporary_path,
            replacement_data,
        )

        pass_step(
            3,
            "Created replacement temp file",
        )

        # ------------------------------------------------------------------
        # [4] Open source with DELETE access.
        # ------------------------------------------------------------------
        source_handle = open_file_for_rename(
            temporary_path,
        )

        pass_step(
            4,
            "Opened source file with DELETE access",
        )

        # ------------------------------------------------------------------
        # [5] NT relative rename.
        # ------------------------------------------------------------------
        print()
        print(
            "Calling NtSetInformationFile("
            "FileRenameInformation)..."
        )

        status = nt_relative_replace(
            source_handle,
            directory_handle,
            target_name,
        )

        print(
            "      "
            + format_ntstatus(status)
        )

        pass_step(
            5,
            "Performed NT relative replacement",
        )

        # Close source before verification.
        close_handle(source_handle)
        source_handle = None

        # ------------------------------------------------------------------
        # [6] Verify filesystem result.
        # ------------------------------------------------------------------
        if not target_path.exists():
            raise RuntimeError(
                "NtSetInformationFile returned success, but the "
                "destination file does not exist."
            )

        actual_data = target_path.read_bytes()

        if actual_data != replacement_data:
            raise RuntimeError(
                "Destination exists, but its contents do not match "
                "the replacement data."
            )

        if temporary_path.exists():
            raise RuntimeError(
                "NtSetInformationFile returned success, but the "
                "temporary source file still exists."
            )

        pass_step(
            6,
            "Verified target replacement and source removal",
        )

        success_result()

        return 0

    except Exception as exc:
        fail_result(str(exc))
        return 1

    finally:
        if source_handle is not None:
            close_handle(source_handle)

        if directory_handle is not None:
            close_handle(directory_handle)

        if test_root is not None:
            if args.keep:
                print()
                print(
                    f"Kept test directory: {test_root}"
                )
            else:
                try:
                    shutil.rmtree(test_root)
                    print()
                    print(
                        f"Cleaned up: {test_root}"
                    )
                except Exception as exc:
                    print()
                    print(
                        f"WARNING: Could not clean up "
                        f"{test_root}: {exc}"
                    )


if __name__ == "__main__":
    raise SystemExit(main())