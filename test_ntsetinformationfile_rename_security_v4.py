import ctypes
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


# ========================================================================
# TEST - NtSetInformationFile Atomic Replacement Security v4
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
# v4 correction:
#
#   v3 successfully performed the NT rename, but ordinary Python
#   verification failed because the renamed source HANDLE remained open.
#
#   Windows file sharing semantics can prevent a second open while an
#   existing HANDLE has restrictive sharing/access state.
#
#   v4 therefore:
#
#       1. Performs the rename.
#       2. Verifies the renamed file through the existing HANDLE.
#       3. Closes that HANDLE.
#       4. Reopens the destination through ordinary Python I/O.
#
#   This isolates the actual NT rename result from the verification
#   handle-lifetime issue.
#
# Security interpretation:
#
#   Case B deliberately distinguishes:
#
#       - SECURITY FAILURE:
#           outside object was modified/deleted.
#
#       - PASS:
#           rename was rejected and outside object remained untouched.
#
#       - INCONCLUSIVE:
#           Windows reports STATUS_SUCCESS against a junction destination.
#           In that case the test records the post-state for further
#           investigation rather than assuming either safety or danger.
#
# This test does NOT establish behavior for a final-component ordinary
# file symbolic link. The current environment has not permitted creation
# of that type of link.
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
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B


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

FILE_OPEN = 0x00000001
FILE_CREATE = 0x00000002


# ------------------------------------------------------------------------
# NtCreateFile options
# ------------------------------------------------------------------------

FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
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
# HANDLE constants
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
    HANDLE,
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
# Win32 ReadFile
# ------------------------------------------------------------------------

ReadFile = kernel32.ReadFile

ReadFile.argtypes = [
    HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]

ReadFile.restype = wintypes.BOOL


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


def handle_value(handle):
    """
    Normalize a HANDLE representation to an integer pointer value.
    """

    if isinstance(handle, int):
        return handle

    value = getattr(
        handle,
        "value",
        None,
    )

    if value is None:
        return int(handle)

    return int(value)


def handle_object(handle):
    return HANDLE(
        handle_value(handle)
    )


def make_unicode_string(text):
    buffer = ctypes.create_unicode_buffer(
        text
    )

    value = UNICODE_STRING()

    value.Length = (
        len(text) *
        ctypes.sizeof(WCHAR)
    )

    value.MaximumLength = (
        value.Length +
        ctypes.sizeof(WCHAR)
    )

    value.Buffer = ctypes.cast(
        buffer,
        ctypes.POINTER(WCHAR),
    )

    return (
        value,
        buffer,
    )


def close_nt_handle(handle):
    if handle is None:
        return

    try:
        value = handle_value(handle)
    except (TypeError, ValueError):
        return

    if value in (
        None,
        0,
        INVALID_HANDLE_VALUE,
    ):
        return

    NtClose(
        handle_object(value)
    )


def close_win32_handle(handle):
    if handle is None:
        return

    try:
        value = handle_value(handle)
    except (TypeError, ValueError):
        return

    if value in (
        None,
        0,
        INVALID_HANDLE_VALUE,
    ):
        return

    CloseHandle(
        handle_object(value)
    )


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

    OPEN_EXISTING is the Win32 CreateFileW disposition.
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

    value = handle_value(handle)

    if value == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()

        return (
            None,
            error,
            win_error_text(error),
        )

    return (
        value,
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
        handle_object(
            root_handle
        )
    )

    object_attributes.ObjectName = (
        ctypes.pointer(
            name_u
        )
    )

    object_attributes.Attributes = (
        attributes
    )

    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    io_status = IO_STATUS_BLOCK()

    result_handle = HANDLE()

    status = NtCreateFile(
        ctypes.byref(
            result_handle
        ),

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
        handle_object(handle),

        ctypes.cast(
            buffer,
            ctypes.c_void_p,
        ),

        len(payload),

        ctypes.byref(
            written
        ),

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
            f"{written.value} of "
            f"{len(payload)} bytes",
        )

    if not FlushFileBuffers(
        handle_object(handle)
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


def read_from_open_handle(
    handle,
    max_bytes=1024 * 1024,
):
    """
    Read the complete contents from an already-open HANDLE.

    Used before closing the renamed source HANDLE so the test verifies
    the rename without relying on a second open.
    """

    buffer = ctypes.create_string_buffer(
        max_bytes
    )

    read_count = wintypes.DWORD()

    ok = ReadFile(
        handle_object(handle),

        ctypes.cast(
            buffer,
            ctypes.c_void_p,
        ),

        max_bytes,

        ctypes.byref(
            read_count
        ),

        None,
    )

    if not ok:
        error = ctypes.get_last_error()

        return (
            False,
            None,
            f"ReadFile failed: "
            f"{error}: "
            f"{win_error_text(error)}",
        )

    return (
        True,
        buffer.raw[
            :read_count.value
        ],
        "",
    )


def build_file_rename_information(
    root_handle,
    filename,
    replace_if_exists=True,
):
    """
    Build FILE_RENAME_INFORMATION.

    x64 layout:

        offset  0: ReplaceIfExists BOOLEAN
        offset  8: RootDirectory HANDLE
        offset 16: FileNameLength ULONG
        offset 20: FileName WCHAR[]
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

    buffer[0] = (
        1
        if replace_if_exists
        else 0
    )

    root_value = handle_value(
        root_handle
    )

    root_pointer = ctypes.c_void_p(
        root_value
    )

    ctypes.memmove(
        ctypes.addressof(buffer) + 8,

        ctypes.byref(
            root_pointer
        ),

        ctypes.sizeof(
            root_pointer
        ),
    )

    filename_length_value = (
        ctypes.c_ulong(
            filename_length
        )
    )

    ctypes.memmove(
        ctypes.addressof(buffer) + 16,

        ctypes.byref(
            filename_length_value
        ),

        ctypes.sizeof(
            filename_length_value
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
    info_buffer, info_size = (
        build_file_rename_information(
            root_handle,
            destination_name,
            replace_if_exists,
        )
    )

    io_status = IO_STATUS_BLOCK()

    status = NtSetInformationFile(
        handle_object(
            source_handle
        ),

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
# Case A
# ------------------------------------------------------------------------

def test_normal_replacement(root):
    print("-" * 72)
    print("CASE A - Normal Atomic Replacement")
    print("-" * 72)
    print()

    target = (
        root /
        "target.txt"
    )

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

        print(
            "Creating temporary source with "
            "RootDirectory + OBJ_DONT_REPARSE..."
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
            f"NtCreateFile status: "
            f"{ntstatus_hex(status)}"
        )

        if (
            u32_status(status)
            != STATUS_SUCCESS
        ):
            print(
                "Temporary source creation failed."
            )
            return False

        print(
            "Temporary source HANDLE: PASS"
        )

        ok, message = (
            write_and_flush(
                source_handle,
                "NEW_REPLACEMENT_CONTENT\n",
            )
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

        status, _ = (
            nt_rename_relative(
                source_handle,
                root_handle,
                "target.txt",
                replace_if_exists=True,
            )
        )

        print(
            f"NtSetInformationFile status: "
            f"{ntstatus_hex(status)}"
        )

        if (
            u32_status(status)
            != STATUS_SUCCESS
        ):
            print(
                "Normal replacement failed."
            )
            return False

        print(
            "Relative replacement: PASS"
        )

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

        # ------------------------------------------------------------
        # Verification 1:
        # Read the renamed object through the existing NT HANDLE.
        # ------------------------------------------------------------

        ok, data, message = (
            read_from_open_handle(
                source_handle
            )
        )

        if not ok:
            print(
                message
            )
            return False

        expected = (
            b"NEW_REPLACEMENT_CONTENT\n"
        )

        if data != expected:
            print(
                "FAIL: renamed HANDLE did not "
                "contain expected contents."
            )

            print(
                f"Read bytes: {data!r}"
            )

            return False

        print(
            "Renamed HANDLE content verification: PASS"
        )

        # ------------------------------------------------------------
        # Verification 2:
        # Close the renamed source HANDLE BEFORE
        # ordinary Python re-open.
        # ------------------------------------------------------------

        close_nt_handle(
            source_handle
        )

        source_handle = None

        print(
            "Renamed HANDLE closed before "
            "ordinary reopen: PASS"
        )

        # ------------------------------------------------------------
        # Verification 3:
        # Reopen through ordinary Python I/O.
        # ------------------------------------------------------------

        try:
            contents = read_text(
                target
            )
        except Exception as exc:
            print(
                "FAIL: ordinary Python reopen "
                f"failed: {type(exc).__name__}: {exc}"
            )
            return False

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
            "Destination replacement verification: PASS"
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
# Case B
# ------------------------------------------------------------------------

def test_junction_destination(root):
    print()
    print("-" * 72)
    print("CASE B - Reparse-Point Destination")
    print("-" * 72)
    print()

    target_name = (
        "target_junction"
    )

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

    rc, stdout, stderr = (
        create_junction(
            junction_path,
            outside,
        )
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

        print(
            "Creating temporary source..."
        )

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
            f"NtCreateFile status: "
            f"{ntstatus_hex(status)}"
        )

        if (
            u32_status(status)
            != STATUS_SUCCESS
        ):
            print(
                "Could not create temporary source."
            )
            return None

        ok, message = (
            write_and_flush(
                source_handle,
                "MUST_NOT_REACH_OUTSIDE\n",
            )
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

        status, _ = (
            nt_rename_relative(
                source_handle,
                root_handle,
                target_name,
                replace_if_exists=True,
            )
        )

        print(
            f"NtSetInformationFile status: "
            f"{ntstatus_hex(status)}"
        )

        outside_contents = read_text(
            outside_marker
        )

        outside_still_exists = (
            outside_marker.exists()
        )

        junction_still_exists = (
            junction_path.exists()
        )

        source_path = (
            root /
            "lumina_replace_temp_b.tmp"
        )

        source_still_exists = (
            source_path.exists()
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

        print(
            f"Temporary source name exists: "
            f"{source_still_exists}"
        )

        # ------------------------------------------------------------
        # Security checks.
        # ------------------------------------------------------------

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

        if (
            u32_status(status)
            == STATUS_SUCCESS
        ):
            print()
            print(
                "WARNING:"
            )

            print(
                "NtSetInformationFile reported "
                "STATUS_SUCCESS while the "
                "destination was a directory junction."
            )

            print(
                "The outside target was preserved."
            )

            if not junction_still_exists:
                print(
                    "The original junction entry "
                    "was removed/replaced."
                )
            else:
                print(
                    "The original junction entry "
                    "still exists."
                )

            if not source_still_exists:
                print(
                    "The source temporary name "
                    "was removed."
                )
            else:
                print(
                    "The source temporary name "
                    "still exists."
                )

            print()
            print(
                "This behavior requires a dedicated "
                "follow-up test before it can be "
                "classified as production-safe."
            )

            print(
                "CASE B RESULT: INCONCLUSIVE"
            )

            return None

        print(
            "Destination junction was not "
            "successfully replaced."
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
        "Atomic Replacement Security v4"
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
            prefix=(
                "lumina_ntrename_security_v4_"
            )
        )
    )

    print(
        f"Test root: {root}"
    )

    print()

    case_a = False
    case_b = None

    try:
        case_a = (
            test_normal_replacement(
                root
            )
        )

        case_b = (
            test_junction_destination(
                root
            )
        )

        print()
        print("=" * 72)
        print("OVERALL RESULT")
        print("=" * 72)

        print(
            "Case A - normal replacement: "
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