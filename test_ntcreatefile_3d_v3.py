import ctypes
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


# ========================================================================
# TEST 3D v3
# NtCreateFile Leaf Junction Rejection
#
# Purpose:
#   Verify that OBJ_DONT_REPARSE rejects a reparse point when the
#   reparse point is the FINAL path component.
#
# Reparse type:
#   Directory junction
#
# Why v3 exists:
#   3D v1 could not create a symbolic link because the test environment
#   lacked the required symbolic-link privilege.
#
#   3D v2 successfully created the junction, but its Win32 CreateFileW
#   setup accidentally used the NT FILE_OPEN constant (1). Win32
#   CreateFileW interprets 1 as CREATE_NEW, causing ERROR_FILE_EXISTS.
#
#   v3 fixes that by using the correct Win32 OPEN_EXISTING constant (3)
#   exclusively for the root HANDLE acquisition.
#
# Important:
#   FILE_OPEN = 1 remains correct for NtCreateFile.
#
# Expected:
#   STATUS_REPARSE_POINT_ENCOUNTERED (0xC000050B)
#
# ========================================================================


# ------------------------------------------------------------------------
# NTSTATUS values
# ------------------------------------------------------------------------

STATUS_SUCCESS = 0x00000000
STATUS_REPARSE_POINT_ENCOUNTERED = 0xC000050B


# ------------------------------------------------------------------------
# NtCreateFile access constants
# ------------------------------------------------------------------------

GENERIC_READ = 0x80000000
SYNCHRONIZE = 0x00100000


# ------------------------------------------------------------------------
# File sharing constants
# ------------------------------------------------------------------------

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004


# ------------------------------------------------------------------------
# NtCreateFile create disposition
#
# IMPORTANT:
#   This is the NT value used by NtCreateFile.
#
#   Do NOT use this value for Win32 CreateFileW().
# ------------------------------------------------------------------------

FILE_OPEN = 0x00000001


# ------------------------------------------------------------------------
# NtCreateFile create options
# ------------------------------------------------------------------------

FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020


# ------------------------------------------------------------------------
# OBJECT_ATTRIBUTES flags
# ------------------------------------------------------------------------

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000


# ------------------------------------------------------------------------
# Win32 CreateFileW constants
#
# These are deliberately separate from the NtCreateFile constants above.
# ------------------------------------------------------------------------

OPEN_EXISTING = 3

FILE_LIST_DIRECTORY = 0x0001
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


# ------------------------------------------------------------------------
# HANDLE constants
# ------------------------------------------------------------------------

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ------------------------------------------------------------------------
# Basic Windows types
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
# Native APIs
# ------------------------------------------------------------------------

ntdll = ctypes.WinDLL("ntdll.dll")


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


NtClose = ntdll.NtClose
NtClose.argtypes = [
    HANDLE,
]
NtClose.restype = NTSTATUS


kernel32 = ctypes.WinDLL(
    "kernel32.dll",
    use_last_error=True,
)


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


CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [
    HANDLE,
]
CloseHandle.restype = wintypes.BOOL


# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------

def ntstatus_hex(status):
    """
    Render an NTSTATUS as an unsigned 32-bit hexadecimal value.
    """
    return f"0x{ctypes.c_ulong(status).value:08X}"


def make_unicode_string(text):
    """
    Build a UNICODE_STRING whose backing buffer remains alive for the
    duration of the native call.
    """

    buffer = ctypes.create_unicode_buffer(text)

    value = UNICODE_STRING()

    value.Length = (
        len(text) * ctypes.sizeof(WCHAR)
    )

    value.MaximumLength = (
        value.Length + ctypes.sizeof(WCHAR)
    )

    value.Buffer = ctypes.cast(
        buffer,
        ctypes.POINTER(WCHAR),
    )

    return value, buffer


def close_nt_handle(handle):
    """
    Close an NT handle returned by NtCreateFile.
    """

    if handle is None:
        return

    try:
        value = handle.value
    except AttributeError:
        value = None

    if value in (None, 0, INVALID_HANDLE_VALUE):
        return

    NtClose(handle)


def create_junction(link_path, target_path):
    """
    Create a directory junction using mklink /J.

    This is intentionally used instead of an ordinary symbolic link
    because symbolic-link creation may require SeCreateSymbolicLinkPrivilege
    in the current test environment.
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
    Open the test root directory with Win32 CreateFileW.

    IMPORTANT:
        Win32 CreateFileW requires OPEN_EXISTING (3).

        The NT FILE_OPEN value (1) must NOT be used here.
    """

    desired_access = (
        FILE_LIST_DIRECTORY |
        SYNCHRONIZE
    )

    share_mode = (
        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE
    )

    flags = FILE_FLAG_BACKUP_SEMANTICS

    handle = CreateFileW(
        str(root),
        desired_access,
        share_mode,
        None,
        OPEN_EXISTING,
        flags,
        None,
    )

    if handle == HANDLE(INVALID_HANDLE_VALUE).value:
        error = ctypes.get_last_error()

        return (
            None,
            error,
            ctypes.FormatError(error).strip(),
        )

    return handle, 0, ""


def nt_create_directory_relative(root_handle, name):
    """
    Open a directory relative to root_handle using NtCreateFile.

    The important security property under test is:

        RootDirectory = root_handle
        ObjectName    = relative final component
        OBJ_DONT_REPARSE = enabled

    If the final component is a reparse point, the expected result is:

        STATUS_REPARSE_POINT_ENCOUNTERED
    """

    name_u, name_buffer = make_unicode_string(name)

    object_attributes = OBJECT_ATTRIBUTES()

    object_attributes.Length = ctypes.sizeof(
        OBJECT_ATTRIBUTES
    )

    object_attributes.RootDirectory = root_handle

    object_attributes.ObjectName = ctypes.pointer(
        name_u
    )

    object_attributes.Attributes = (
        OBJ_CASE_INSENSITIVE |
        OBJ_DONT_REPARSE
    )

    object_attributes.SecurityDescriptor = None
    object_attributes.SecurityQualityOfService = None

    io_status = IO_STATUS_BLOCK()

    result_handle = HANDLE()

    status = NtCreateFile(
        ctypes.byref(result_handle),

        # Directory open:
        GENERIC_READ | SYNCHRONIZE,

        ctypes.byref(object_attributes),

        ctypes.byref(io_status),

        None,

        0,

        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE,

        FILE_OPEN,

        FILE_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT,

        None,

        0,
    )

    # Keep the Unicode backing buffer alive through the syscall.
    _ = name_buffer

    return status, result_handle


# ------------------------------------------------------------------------
# Environment information
# ------------------------------------------------------------------------

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
# Main test
# ------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("TEST 3D v3 - NtCreateFile Leaf Junction Rejection")
    print("=" * 72)

    print_environment()

    print("Security condition:")
    print("  OBJ_DONT_REPARSE = ENABLED")
    print("  Reparse point is the FINAL path component")
    print("  Reparse type = directory junction")
    print()

    # --------------------------------------------------------------------
    # Create isolated test tree.
    # --------------------------------------------------------------------

    root = Path(
        tempfile.mkdtemp(
            prefix="lumina_ntcreate_3d_v3_"
        )
    )

    outside = root / "outside"

    leaf_junction = root / "leaf_junction"

    outside.mkdir()

    print(f"Root:      {root}")
    print(f"Target:    {outside}")
    print(f"Junction:  {leaf_junction}")
    print()

    root_handle = None

    try:
        # ---------------------------------------------------------------
        # Create final-component junction.
        # ---------------------------------------------------------------

        print(
            "Creating directory junction with mklink /J..."
        )

        rc, stdout, stderr = create_junction(
            leaf_junction,
            outside,
        )

        if stdout:
            print(
                f"stdout: {stdout}"
            )

        if stderr:
            print(
                f"stderr: {stderr}"
            )

        if (
            rc != 0
            or not leaf_junction.exists()
        ):
            print()
            print(
                "Junction creation was not available."
            )
            print(
                f"return code: {rc}"
            )

            print()
            print("=" * 72)
            print("RESULT: INCONCLUSIVE")
            print("=" * 72)
            print()

            print(
                "The test could not establish the "
                "final-component junction condition."
            )

            return 2

        print(
            "Junction creation: PASS"
        )

        print()

        # ---------------------------------------------------------------
        # Open root using Win32 CreateFileW.
        #
        # IMPORTANT:
        #   OPEN_EXISTING = 3
        #
        # This is deliberately NOT FILE_OPEN = 1.
        # ---------------------------------------------------------------

        print(
            "Opening test root directory HANDLE..."
        )

        root_handle, error, error_text = (
            open_root_directory(root)
        )

        if root_handle is None:
            print(
                f"CreateFileW failed: "
                f"Win32 error {error}: "
                f"{error_text}"
            )

            print()
            print("=" * 72)
            print("RESULT: INCONCLUSIVE")
            print("=" * 72)
            print()

            print(
                "The test did not reach NtCreateFile."
            )

            return 2

        print(
            "Root HANDLE: PASS"
        )

        print()

        # ---------------------------------------------------------------
        # Actual test.
        # ---------------------------------------------------------------

        print(
            "Calling NtCreateFile with:"
        )

        print(
            "  RootDirectory       = root HANDLE"
        )

        print(
            "  ObjectName          = leaf_junction"
        )

        print(
            "  OBJ_DONT_REPARSE    = ENABLED"
        )

        print(
            "  FILE_DIRECTORY_FILE = ENABLED"
        )

        print()

        status, leaf_handle = (
            nt_create_directory_relative(
                root_handle,
                "leaf_junction",
            )
        )

        print(
            f"NTSTATUS: {ntstatus_hex(status)}"
        )

        # ---------------------------------------------------------------
        # Expected security result.
        # ---------------------------------------------------------------

        if (
            ctypes.c_ulong(status).value
            == STATUS_REPARSE_POINT_ENCOUNTERED
        ):
            close_nt_handle(
                leaf_handle
            )

            print()

            print(
                "The final-component junction was rejected."
            )

            print(
                "Rejection status matches "
                "STATUS_REPARSE_POINT_ENCOUNTERED."
            )

            print()
            print("=" * 72)
            print("RESULT: PASS")
            print("=" * 72)
            print()

            print(
                "NtCreateFile + RootDirectory + "
                "OBJ_DONT_REPARSE rejected a "
                "final-component directory junction."
            )

            return 0

        # ---------------------------------------------------------------
        # Security failure.
        # ---------------------------------------------------------------

        if (
            ctypes.c_ulong(status).value
            == STATUS_SUCCESS
        ):
            close_nt_handle(
                leaf_handle
            )

            print()

            print(
                "SECURITY FAILURE:"
            )

            print(
                "NtCreateFile returned STATUS_SUCCESS "
                "for the final-component junction "
                "despite OBJ_DONT_REPARSE."
            )

            print()
            print("=" * 72)
            print("RESULT: SECURITY FAILURE")
            print("=" * 72)
            print()

            return 1

        # ---------------------------------------------------------------
        # Unexpected status.
        # ---------------------------------------------------------------

        close_nt_handle(
            leaf_handle
        )

        print()

        print(
            "NtCreateFile failed with an "
            "unexpected NTSTATUS."
        )

        print(
            "This does not establish the "
            "expected security property."
        )

        print()
        print("=" * 72)
        print("RESULT: INCONCLUSIVE")
        print("=" * 72)
        print()

        return 2

    finally:
        # ---------------------------------------------------------------
        # Close root HANDLE.
        # ---------------------------------------------------------------

        if root_handle is not None:
            CloseHandle(
                root_handle
            )

        # ---------------------------------------------------------------
        # Remove isolated test tree.
        # ---------------------------------------------------------------

        shutil.rmtree(
            root,
            ignore_errors=True,
        )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )