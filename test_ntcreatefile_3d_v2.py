import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path


# ========================================================================
# TEST 3D v2
# NtCreateFile Leaf Junction Rejection
#
# Purpose:
#   Verify that OBJ_DONT_REPARSE rejects a reparse point when the
#   reparse point is the FINAL path component.
#
# Difference from 3D v1:
#   3D v1 tests a file symbolic link, which requires
#   SeCreateSymbolicLinkPrivilege in this environment.
#
#   3D v2 uses a directory junction, which can be created with
#   "mklink /J" without requiring that symbolic-link privilege.
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
# NtCreateFile constants
# ------------------------------------------------------------------------

GENERIC_READ = 0x80000000
SYNCHRONIZE = 0x00100000

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

FILE_OPEN = 0x00000001

FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

OBJ_CASE_INSENSITIVE = 0x00000040
OBJ_DONT_REPARSE = 0x00001000

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ------------------------------------------------------------------------
# NT structures
# ------------------------------------------------------------------------

ULONG = wintypes.ULONG
USHORT = wintypes.USHORT
WCHAR = wintypes.WCHAR
HANDLE = wintypes.HANDLE
NTSTATUS = ctypes.c_long


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
NtClose.argtypes = [HANDLE]
NtClose.restype = NTSTATUS


# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------

def ntstatus_hex(status):
    return f"0x{ctypes.c_ulong(status).value:08X}"


def check_windows():
    version = sys.getwindowsversion()

    print(f"Python: {sys.version}")
    print(f"Pointer size: {ctypes.sizeof(ctypes.c_void_p) * 8}-bit")
    print(
        f"Windows: {version.major}.{version.minor} "
        f"build {version.build}"
    )
    print()


def make_unicode_string(text):
    buffer = ctypes.create_unicode_buffer(text)

    value = UNICODE_STRING()
    value.Length = (len(text) * ctypes.sizeof(WCHAR))
    value.MaximumLength = value.Length + ctypes.sizeof(WCHAR)
    value.Buffer = ctypes.cast(buffer, ctypes.POINTER(WCHAR))

    return value, buffer


def nt_create_directory_relative(root_handle, name):
    """
    Open a directory relative to root_handle using NtCreateFile.

    OBJ_DONT_REPARSE is deliberately applied to the OBJECT_ATTRIBUTES.
    """

    name_u, name_buffer = make_unicode_string(name)

    object_attributes = OBJECT_ATTRIBUTES()
    object_attributes.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    object_attributes.RootDirectory = root_handle
    object_attributes.ObjectName = ctypes.pointer(name_u)
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
        GENERIC_READ | SYNCHRONIZE,
        ctypes.byref(object_attributes),
        ctypes.byref(io_status),
        None,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0,
    )

    # Keep buffer alive through the syscall.
    _ = name_buffer

    return status, result_handle


def close_nt_handle(handle):
    if handle and handle.value not in (None, 0, INVALID_HANDLE_VALUE):
        NtClose(handle)


def create_junction(link_path, target_path):
    """
    Create a directory junction using cmd.exe /c mklink /J.

    Unlike ordinary symbolic-link creation, this does not require
    SeCreateSymbolicLinkPrivilege.
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

    return result.returncode, result.stdout.strip(), result.stderr.strip()


# ------------------------------------------------------------------------
# Main test
# ------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("TEST 3D v2 - NtCreateFile Leaf Junction Rejection")
    print("=" * 72)

    check_windows()

    print("Security condition:")
    print("  OBJ_DONT_REPARSE = ENABLED")
    print("  Reparse point is the FINAL path component")
    print("  Reparse type = directory junction")
    print()

    root = Path(
        tempfile.mkdtemp(prefix="lumina_ntcreate_3d_v2_")
    )

    outside = root / "outside"
    outside.mkdir()

    leaf_junction = root / "leaf_junction"

    print(f"Root:   {root}")
    print(f"Target: {outside}")
    print(f"Junction: {leaf_junction}")
    print()

    try:
        print("Creating directory junction with mklink /J...")

        rc, stdout, stderr = create_junction(
            leaf_junction,
            outside,
        )

        if stdout:
            print(f"stdout: {stdout}")

        if stderr:
            print(f"stderr: {stderr}")

        if rc != 0 or not leaf_junction.exists():
            print()
            print("Junction creation was not available.")
            print(f"return code: {rc}")
            print()
            print("=" * 72)
            print("RESULT: INCONCLUSIVE")
            print("=" * 72)
            print()
            print(
                "The test could not establish the final-component "
                "junction condition."
            )
            return 2

        print("Junction creation: PASS")
        print()

        # Open the root directory using ordinary Win32 CreateFileW.
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

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
        CloseHandle.argtypes = [HANDLE]
        CloseHandle.restype = wintypes.BOOL

        FILE_LIST_DIRECTORY = 0x0001
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

        print("Opening test root directory HANDLE...")

        root_handle = CreateFileW(
            str(root),
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            FILE_OPEN,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )

        if root_handle == HANDLE(INVALID_HANDLE_VALUE).value:
            error = ctypes.get_last_error()

            print(
                f"CreateFileW failed: Win32 error {error}: "
                f"{ctypes.FormatError(error).strip()}"
            )

            print()
            print("=" * 72)
            print("RESULT: INCONCLUSIVE")
            print("=" * 72)

            return 2

        try:
            print("Root HANDLE: PASS")
            print()

            print(
                "Calling NtCreateFile with:"
            )
            print(
                "  RootDirectory = root HANDLE"
            )
            print(
                "  ObjectName    = leaf_junction"
            )
            print(
                "  OBJ_DONT_REPARSE = ENABLED"
            )
            print(
                "  FILE_DIRECTORY_FILE = ENABLED"
            )
            print()

            status, leaf_handle = nt_create_directory_relative(
                root_handle,
                "leaf_junction",
            )

            print(
                f"NTSTATUS: {ntstatus_hex(status)}"
            )

            if status == STATUS_REPARSE_POINT_ENCOUNTERED:
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

                return 0

            if status == STATUS_SUCCESS:
                close_nt_handle(leaf_handle)

                print()
                print(
                    "SECURITY FAILURE: NtCreateFile followed or opened "
                    "the final-component junction despite "
                    "OBJ_DONT_REPARSE."
                )

                print()
                print("=" * 72)
                print("RESULT: SECURITY FAILURE")
                print("=" * 72)

                return 1

            print()
            print(
                "NtCreateFile failed, but with an unexpected NTSTATUS."
            )
            print(
                "This does not establish the expected security property."
            )

            print()
            print("=" * 72)
            print("RESULT: INCONCLUSIVE")
            print("=" * 72)

            return 2

        finally:
            CloseHandle(root_handle)

    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())