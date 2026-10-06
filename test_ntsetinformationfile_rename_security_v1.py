import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


# ========================================================================
# TEST - NtSetInformationFile Atomic Replacement Security v1
#
# Purpose:
#
#   Combine the two primitives already demonstrated independently:
#
#       1. NtCreateFile
#          RootDirectory + relative name + OBJ_DONT_REPARSE
#
#       2. NtSetInformationFile
#          FileRenameInformation + RootDirectory +
#          ReplaceIfExists = TRUE
#
#   Test both:
#
#       A. Normal destination replacement
#
#       B. Malicious final-component directory junction
#
# Expected:
#
#   A. Normal destination:
#        PASS
#        Existing destination is atomically replaced by source.
#
#   B. Junction destination:
#        The rename must NOT traverse the junction and modify anything
#        outside the protected root.
#
#        Because the destination is a directory junction and the source
#        is a regular file, Windows may reject the replacement with an
#        appropriate error such as STATUS_ACCESS_DENIED.
#
#        The important security condition is:
#
#          - no outside file is modified
#          - no outside file is deleted
#          - the junction is not followed as a destination directory
#
# This test does NOT claim to prove behavior for a final-component
# symbolic-link file. That remains a separate test because the current
# environment does not permit creation of ordinary symbolic links.
#
# ========================================================================


# ------------------------------------------------------------------------
# NTSTATUS
# ------------------------------------------------------------------------

STATUS_SUCCESS = 0x00000000

STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_NOT_SAME_DEVICE = 0xC00000D4


# ------------------------------------------------------------------------
# NtCreateFile access
# ------------------------------------------------------------------------

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000


# ------------------------------------------------------------------------
# Sharing
# ------------------------------------------------------------------------

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004


# ------------------------------------------------------------------------
# NtCreateFile create disposition
# ------------------------------------------------------------------------

FILE_CREATE = 0x00000002
FILE_OPEN = 0x00000001


# ------------------------------------------------------------------------
# NtCreateFile options
# ------------------------------------------------------------------------

FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020


# ------------------------------------------------------------------------
# OBJECT_ATTRIBUTES
# ------------------------------------------------------------------------

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000


# ------------------------------------------------------------------------
# NtSetInformationFile
# ------------------------------------------------------------------------

FILE_RENAME_INFORMATION_CLASS = 10


# ------------------------------------------------------------------------
# Win32 CreateFileW
# ------------------------------------------------------------------------

OPEN_EXISTING = 3

FILE_LIST_DIRECTORY = 0x0001
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


# ------------------------------------------------------------------------
# Win32 file I/O
# ------------------------------------------------------------------------

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ------------------------------------------------------------------------
# NT types
# ------------------------------------------------------------------------

ULONG = wintypes.ULONG
USHORT = wintypes.USHORT
WCHAR = wintypes.WCHAR
HANDLE = wintypes.HANDLE
NTSTATUS = ctypes.c_long


# ------------------------------------------------------------------------
# NT structures
# ------------------------------------------------------------------------

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", ctypes.POINTER(WCHAR)),
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

    _fields_ = [
        ("StatusUnion", _STATUS_UNION),
        ("Information", ctypes.c_size_t),
    ]


# ------------------------------------------------------------------------
# DLLs
# ------------------------------------------------------------------------

ntdll = ctypes.WinDLL(
    "ntdll.dll"
)

kernel32 = ctypes.WinDLL(
    "kernel32.dll",
    use_last_error=True,
)


# ------------------------------------------------------------------------
# NtCreateFile
# ------------------------------------------------------------------------

NtCreateFile = ntdll.NtCreateFile

NtCreateFile.argtypes = [
    ctypes.POINTER(HANDLE),
    wintypes.DWORD,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
]

NtCreateFile.restype = NTSTATUS


# ------------------------------------------------------------------------
# NtSetInformationFile
# ------------------------------------------------------------------------

NtSetInformationFile = ntdll.NtSetInformationFile

NtSetInformationFile.argtypes = [
    HANDLE,
    ctypes.POINTER(IO_STATUS_BLOCK),
    ctypes.c_void_p,
    wintypes.ULONG,
    wintypes.ULONG,
]

NtSetInformationFile.restype = NTSTATUS


# ------------------------------------------------------------------------
# NtClose
# ------------------------------------------------------------------------

NtClose = ntdll.NtClose

NtClose.argtypes = [
    HANDLE,
]

NtClose.restype = NTSTATUS


# ------------------------------------------------------------------------
# Win32 CreateFileW
# ------------------------------------------------------------------------

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

CreateFileW.restype = HANDLE


# ------------------------------------------------------------------------
# Win32 CloseHandle
# ------------------------------------------------------------------------

CloseHandle = kernel32.CloseHandle

CloseHandle.argtypes = [
    HANDLE,
]

CloseHandle.restype = wintypes.BOOL


# ------------------------------------------------------------------------
# Win32 WriteFile
# ------------------------------------------------------------------------

WriteFile = kernel32.WriteFile

WriteFile.argtypes = [
    HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]

WriteFile.restype = wintypes.BOOL


# ------------------------------------------------------------------------
# Win32 FlushFileBuffers
# ------------------------------------------------------------------------

FlushFileBuffers = kernel32.FlushFileBuffers

FlushFileBuffers.argtypes = [
    HANDLE,
]

FlushFileBuffers.restype = wintypes.BOOL


# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------

def u32_status(status):
    return ctypes.c_ulong(status).value


def ntstatus_hex(status):
    return f"0x{u32_status(status):08X}"


def win_error_text(error):
    return ctypes.FormatError(error).strip()


def make_unicode_string(text):
    buffer = ctypes.create_unicode_buffer(
        text
    )

    value = UNICODE_STRING()

    value.Length = (
        len(text) * ctypes.sizeof(WCHAR)
    )

    value.MaximumLength = (
        value.Length +
        ctypes.sizeof(WCHAR)
    )

    value.Buffer = ctypes.cast(
        buffer,
        ctypes.POINTER(WCHAR),
    )

    return value, buffer


def close_nt_handle(handle):
    if handle is None:
        return

    try:
        value = handle.value
    except AttributeError:
        value = None

    if value in (
        None,
        0,
        INVALID_HANDLE_VALUE,
    ):
        return

    NtClose(handle)


def close_win32_handle(handle):
    if handle is None:
        return

    if handle == HANDLE(
        INVALID_HANDLE_VALUE
    ).value:
        return

    CloseHandle(handle)


def create_junction(
    link_path,
    target_path,
):
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
        encoding="utf-8",
        errors="replace",
    )

    return (
        result.returncode,
        result.stdout.strip(),
        result.stderr.strip(),
    )


def open_root_directory(root):
    """
    Open root using Win32 CreateFileW.

    IMPORTANT:
        OPEN_EXISTING = 3 is the Win32 value.

        FILE_OPEN = 1 is an NT value and must not be used here.
    """

    handle = CreateFileW(
        str(root),

        FILE_LIST_DIRECTORY |
        SYNCHRONIZE,

        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE,

        None,

        OPEN_EXISTING,

        FILE_FLAG_BACKUP_SEMANTICS,

        None,
    )

    if (
        handle ==
        HANDLE(INVALID_HANDLE_VALUE).value
    ):
        error = ctypes.get_last_error()

        return (
            None,
            error,
            win_error_text(error),
        )

    return (
        handle,
        0,
        "",
    )


def nt_create_file_relative(
    root_handle,
    name,
    create_disposition,
    desired_access,
    create_options,
    dont_reparse=True,
):
    """
    NtCreateFile relative to an already-open directory HANDLE.
    """

    name_u, name_buffer = make_unicode_string(
        name
    )

    attributes = OBJ_CASE_INSENSITIVE

    if dont_reparse:
        attributes |= OBJ_DONT_REPARSE

    object_attributes = OBJECT_ATTRIBUTES()

    object_attributes.Length = (
        ctypes.sizeof(
            OBJECT_ATTRIBUTES
        )
    )

    object_attributes.RootDirectory = (
        root_handle
    )

    object_attributes.ObjectName = (
        ctypes.pointer(name_u)
    )

    object_attributes.Attributes = (
        attributes
    )

    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    io_status = IO_STATUS_BLOCK()

    result_handle = HANDLE()

    status = NtCreateFile(
        ctypes.byref(result_handle),

        desired_access,

        ctypes.byref(
            object_attributes
        ),

        ctypes.byref(
            io_status
        ),

        None,

        0,

        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE,

        create_disposition,

        create_options,

        None,

        0,
    )

    # Keep backing buffer alive through syscall.
    _ = name_buffer

    return (
        status,
        result_handle,
        io_status,
    )


def write_and_flush(
    handle,
    text,
):
    payload = text.encode(
        "utf-8"
    )

    buffer = ctypes.create_string_buffer(
        payload
    )

    written = wintypes.DWORD()

    ok = WriteFile(
        handle,
        ctypes.cast(
            buffer,
            ctypes.c_void_p,
        ),
        len(payload),
        ctypes.byref(written),
        None,
    )

    if not ok:
        error = ctypes.get_last_error()

        return (
            False,
            f"WriteFile failed: "
            f"{error}: "
            f"{win_error_text(error)}",
        )

    if written.value != len(payload):
        return (
            False,
            "WriteFile returned a short write: "
            f"{written.value} of {len(payload)} bytes",
        )

    if not FlushFileBuffers(
        handle
    ):
        error = ctypes.get_last_error()

        return (
            False,
            f"FlushFileBuffers failed: "
            f"{error}: "
            f"{win_error_text(error)}",
        )

    return (
        True,
        "",
    )


def build_file_rename_information(
    root_handle,
    filename,
    replace_if_exists=True,
):
    """
    Build the native FILE_RENAME_INFORMATION buffer.

    x64 layout used here:

        offset  0: ReplaceIfExists / BOOLEAN
        offset  1: padding
        offset  8: RootDirectory HANDLE
        offset 16: FileNameLength ULONG
        offset 20: FileName WCHAR[]

    The native structure is variable-length.
    """

    filename_bytes = (
        filename.encode(
            "utf-16-le"
        )
    )

    filename_length = len(
        filename_bytes
    )

    header_size = 20

    total_size = (
        header_size +
        filename_length
    )

    buffer = ctypes.create_string_buffer(
        total_size
    )

    # ReplaceIfExists BOOLEAN.
    buffer[0] = (
        1
        if replace_if_exists
        else 0
    )

    # Bytes 1..7 are padding.

    root_value = (
        root_handle.value
    )

    ctypes.memmove(
        ctypes.addressof(buffer) + 8,
        ctypes.byref(
            ctypes.c_void_p(
                root_value
            )
        ),
        ctypes.sizeof(
            ctypes.c_void_p
        ),
    )

    ctypes.memmove(
        ctypes.addressof(buffer) + 16,
        ctypes.byref(
            ctypes.c_ulong(
                filename_length
            )
        ),
        ctypes.sizeof(
            ctypes.c_ulong
        ),
    )

    ctypes.memmove(
        ctypes.addressof(buffer) + 20,
        filename_bytes,
        filename_length,
    )

    return (
        buffer,
        total_size,
    )


def nt_rename_relative(
    source_handle,
    root_handle,
    destination_name,
    replace_if_exists=True,
):
    """
    Rename an already-open source HANDLE to a destination name
    relative to root_handle.
    """

    info_buffer, info_size = (
        build_file_rename_information(
            root_handle,
            destination_name,
            replace_if_exists,
        )
    )

    io_status = IO_STATUS_BLOCK()

    status = NtSetInformationFile(
        source_handle,
        ctypes.byref(
            io_status
        ),
        ctypes.cast(
            info_buffer,
            ctypes.c_void_p,
        ),
        info_size,
        FILE_RENAME_INFORMATION_CLASS,
    )

    # Keep buffer alive through syscall.
    _ = info_buffer

    return (
        status,
        io_status,
    )


def read_text(path):
    return Path(path).read_text(
        encoding="utf-8"
    )


def print_environment():
    version = sys.getwindowsversion()

    print(
        f"Python: {sys.version}"
    )

    print(
        f"Pointer size: "
        f"{ctypes.sizeof(ctypes.c_void_p) * 8}-bit"
    )

    print(
        f"Windows: "
        f"{version.major}.{version.minor} "
        f"build {version.build}"
    )

    print()


# ------------------------------------------------------------------------
# Test A - Normal destination
# ------------------------------------------------------------------------

def test_normal_replacement(root):
    print("-" * 72)
    print("CASE A - Normal Atomic Replacement")
    print("-" * 72)
    print()

    target = root / "target.txt"

    target.write_text(
        "OLD_DESTINATION_CONTENT\n",
        encoding="utf-8",
    )

    print(
        f"Existing target: {target}"
    )

    root_handle, error, error_text = (
        open_root_directory(root)
    )

    if root_handle is None:
        print(
            f"Root open failed: "
            f"{error}: {error_text}"
        )
        return False

    source_handle = None

    try:
        print(
            "Root HANDLE: PASS"
        )

        status, source_handle, _ = (
            nt_create_file_relative(
                root_handle,
                "lumina_replace_temp_a.tmp",

                FILE_CREATE,

                GENERIC_READ |
                GENERIC_WRITE |
                DELETE |
                SYNCHRONIZE,

                FILE_NON_DIRECTORY_FILE |
                FILE_SYNCHRONOUS_IO_NONALERT,

                dont_reparse=True,
            )
        )

        print(
            "Creating temporary source with "
            "RootDirectory + OBJ_DONT_REPARSE..."
        )

        print(
            f"NtCreateFile status: "
            f"{ntstatus_hex(status)}"
        )

        if u32_status(status) != STATUS_SUCCESS:
            print(
                "Temporary source creation failed."
            )
            return False

        print(
            "Temporary source HANDLE: PASS"
        )

        ok, message = write_and_flush(
            source_handle,
            "NEW_REPLACEMENT_CONTENT\n",
        )

        if not ok:
            print(message)
            return False

        print(
            "Write + FlushFileBuffers: PASS"
        )

        print()
        print(
            "Calling NtSetInformationFile("
            "FileRenameInformation)..."
        )

        status, _ = nt_rename_relative(
            source_handle,
            root_handle,
            "target.txt",
            replace_if_exists=True,
        )

        print(
            f"NtSetInformationFile status: "
            f"{ntstatus_hex(status)}"
        )

        if u32_status(status) != STATUS_SUCCESS:
            print(
                "Normal replacement failed."
            )
            return False

        print(
            "Relative replacement: PASS"
        )

        # The source name should no longer exist.
        source_path = (
            root /
            "lumina_replace_temp_a.tmp"
        )

        if source_path.exists():
            print(
                "FAIL: source temporary name "
                "still exists after rename."
            )
            return False

        print(
            "Source removal: PASS"
        )

        # Verify target contents.
        contents = read_text(
            target
        )

        print(
            f"Final target contents: "
            f"{contents!r}"
        )

        if contents != (
            "NEW_REPLACEMENT_CONTENT\n"
        ):
            print(
                "FAIL: destination content "
                "was not replaced correctly."
            )
            return False

        print(
            "Destination replacement: PASS"
        )

        print()
        print(
            "CASE A RESULT: PASS"
        )

        return True

    finally:
        close_nt_handle(
            source_handle
        )

        close_win32_handle(
            root_handle
        )


# ------------------------------------------------------------------------
# Test B - Junction destination
# ------------------------------------------------------------------------

def test_junction_destination(root):
    print()
    print("-" * 72)
    print("CASE B - Reparse-Point Destination")
    print("-" * 72)
    print()

    target_name = "target_junction"

    junction_path = (
        root /
        target_name
    )

    outside = (
        root /
        "outside"
    )

    outside.mkdir()

    outside_marker = (
        outside /
        "protected.txt"
    )

    outside_marker.write_text(
        "OUTSIDE_MUST_NOT_CHANGE\n",
        encoding="utf-8",
    )

    print(
        f"Outside directory: {outside}"
    )

    print(
        f"Outside protected file: "
        f"{outside_marker}"
    )

    print(
        f"Destination junction: "
        f"{junction_path}"
    )

    rc, stdout, stderr = create_junction(
        junction_path,
        outside,
    )

    if stdout:
        print(
            f"mklink stdout: {stdout}"
        )

    if stderr:
        print(
            f"mklink stderr: {stderr}"
        )

    if (
        rc != 0
        or not junction_path.exists()
    ):
        print()
        print(
            "Could not create destination "
            "junction."
        )

        print(
            "CASE B RESULT: INCONCLUSIVE"
        )

        return None

    print(
        "Destination junction creation: PASS"
    )

    root_handle, error, error_text = (
        open_root_directory(root)
    )

    if root_handle is None:
        print(
            f"Root open failed: "
            f"{error}: {error_text}"
        )
        return None

    source_handle = None

    try:
        print(
            "Root HANDLE: PASS"
        )

        # Create a regular source file.
        status, source_handle, _ = (
            nt_create_file_relative(
                root_handle,
                "lumina_replace_temp_b.tmp",

                FILE_CREATE,

                GENERIC_READ |
                GENERIC_WRITE |
                DELETE |
                SYNCHRONIZE,

                FILE_NON_DIRECTORY_FILE |
                FILE_SYNCHRONOUS_IO_NONALERT,

                dont_reparse=True,
            )
        )

        print(
            "Creating temporary source..."
        )

        print(
            f"NtCreateFile status: "
            f"{ntstatus_hex(status)}"
        )

        if u32_status(status) != STATUS_SUCCESS:
            print(
                "Could not create temporary source."
            )
            return None

        ok, message = write_and_flush(
            source_handle,
            "MUST_NOT_REACH_OUTSIDE\n",
        )

        if not ok:
            print(message)
            return None

        print(
            "Temporary source write + flush: PASS"
        )

        print()
        print(
            "Attempting to replace the "
            "junction destination..."
        )

        status, _ = nt_rename_relative(
            source_handle,
            root_handle,
            target_name,
            replace_if_exists=True,
        )

        print(
            f"NtSetInformationFile status: "
            f"{ntstatus_hex(status)}"
        )

        # ---------------------------------------------------------------
        # Security verification.
        #
        # A successful rename here would be interesting but is not by
        # itself enough to call it secure. We therefore verify the
        # outside target regardless of status.
        # ---------------------------------------------------------------

        outside_contents = read_text(
            outside_marker
        )

        junction_still_exists = (
            junction_path.exists()
        )

        outside_still_exists = (
            outside_marker.exists()
        )

        print()
        print(
            f"Outside protected file exists: "
            f"{outside_still_exists}"
        )

        print(
            f"Outside protected file contents: "
            f"{outside_contents!r}"
        )

        print(
            f"Destination junction exists: "
            f"{junction_still_exists}"
        )

        if not outside_still_exists:
            print()
            print(
                "SECURITY FAILURE:"
            )

            print(
                "The outside protected file "
                "was deleted."
            )

            print(
                "CASE B RESULT: SECURITY FAILURE"
            )

            return False

        if outside_contents != (
            "OUTSIDE_MUST_NOT_CHANGE\n"
        ):
            print()
            print(
                "SECURITY FAILURE:"
            )

            print(
                "The outside protected file "
                "was modified."
            )

            print(
                "CASE B RESULT: SECURITY FAILURE"
            )

            return False

        print(
            "Outside target preservation: PASS"
        )

        # ---------------------------------------------------------------
        # A regular-file rename onto a directory junction should not
        # silently turn into a traversal into the junction target.
        #
        # We accept a non-success NTSTATUS here as the expected safe
        # outcome.
        # ---------------------------------------------------------------

        if u32_status(status) == STATUS_SUCCESS:
            print()
            print(
                "WARNING:"
            )

            print(
                "NtSetInformationFile reported "
                "STATUS_SUCCESS while the destination "
                "was a directory junction."
            )

            print(
                "The outside target was nevertheless "
                "preserved."
            )

            print(
                "This requires additional investigation "
                "before treating the primitive as production-safe."
            )

            print(
                "CASE B RESULT: INCONCLUSIVE"
            )

            return None

        print(
            "Destination junction was not "
            "successfully traversed/replaced."
        )

        print(
            "Junction destination preservation: PASS"
        )

        print()
        print(
            "CASE B RESULT: PASS"
        )

        return True

    finally:
        close_nt_handle(
            source_handle
        )

        close_win32_handle(
            root_handle
        )


# ------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------

def main():
    print("=" * 72)
    print(
        "TEST - NtSetInformationFile "
        "Atomic Replacement Security v1"
    )
    print("=" * 72)

    print_environment()

    print(
        "This test combines:"
    )

    print(
        "  NtCreateFile("
        "RootDirectory + OBJ_DONT_REPARSE)"
    )

    print(
        "  + NtSetInformationFile("
        "FileRenameInformation)"
    )

    print(
        "  + ReplaceIfExists = TRUE"
    )

    print()

    root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntrename_security_v1_"
        )
    )

    print(
        f"Test root: {root}"
    )

    print()

    case_a = False
    case_b = None

    try:
        case_a = test_normal_replacement(
            root
        )

        case_b = test_junction_destination(
            root
        )

        print()
        print("=" * 72)
        print("OVERALL RESULT")
        print("=" * 72)

        print(
            f"Case A - normal replacement: "
            f"{'PASS' if case_a else 'FAIL'}"
        )

        if case_b is True:
            print(
                "Case B - junction destination: PASS"
            )
        elif case_b is False:
            print(
                "Case B - junction destination: "
                "SECURITY FAILURE"
            )
        else:
            print(
                "Case B - junction destination: "
                "INCONCLUSIVE"
            )

        print()

        if case_a and case_b is True:
            print(
                "RESULT: PASS"
            )
            return 0

        if case_b is False:
            print(
                "RESULT: SECURITY FAILURE"
            )
            return 1

        print(
            "RESULT: INCONCLUSIVE"
        )
        return 2

    finally:
        shutil.rmtree(
            root,
            ignore_errors=True,
        )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )