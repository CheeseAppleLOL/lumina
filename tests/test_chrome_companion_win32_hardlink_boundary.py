"""Slice 15 Diagnostic: Win32 Hardlink Security & Object-Identity Boundary.

Establishes Windows file-object identity and boundary semantics when private state
pathnames are aliased via hardlinks (CreateHardLinkW), using test-local fallback injection
for missing primitives to preserve production code integrity.
"""
import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path

import pytest

# Step 1: Pre-import primitives and inject test-local fallback before win32_state import
import chrome_companion.win32_primitives as win32_primitives

if not hasattr(win32_primitives, "delete_file_handle"):
    ntdll = ctypes.WinDLL("ntdll")

    class IO_STATUS_BLOCK(ctypes.Structure):
        class _STATUS(ctypes.Union):
            _fields_ = [("Status", wintypes.LONG), ("Pointer", ctypes.c_void_p)]
        _fields_ = [("u", _STATUS), ("Information", ctypes.c_void_p)]

    class FILE_DISPOSITION_INFORMATION(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

    def _test_local_delete_file_handle(handle):
        io_status = IO_STATUS_BLOCK()
        disp = FILE_DISPOSITION_INFORMATION(DeleteFile=True)
        status = ntdll.NtSetInformationFile(
            handle,
            ctypes.byref(io_status),
            ctypes.byref(disp),
            ctypes.sizeof(disp),
            13,  # FileDispositionInformation
        )
        if status != 0:  # STATUS_SUCCESS
            raise OSError(f"NtSetInformationFile failed with status 0x{status:08X}")

    win32_primitives.delete_file_handle = _test_local_delete_file_handle

# Step 2: Safe imports from production modules
from chrome_companion.win32_primitives import (
    BY_HANDLE_FILE_INFORMATION,
    GetFileInformationByHandle,
    close_handle,
    open_file_relative,
    FILE_READ_ATTRIBUTES,
    FILE_OPEN,
    FILE_NON_DIRECTORY_FILE,
    FILE_SYNCHRONOUS_IO_NONALERT,
    STATUS_SUCCESS,
)
from chrome_companion.win32_state import (
    STATE_VERSION,
    open_trusted_dir,
    read_private_json_at,
    write_private_json_at,
    StateError,
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Win32 Constants
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_BEGIN = 0
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

CreateHardLinkW = kernel32.CreateHardLinkW
CreateHardLinkW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
CreateHardLinkW.restype = wintypes.BOOL

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

ReadFile = kernel32.ReadFile
ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
ReadFile.restype = wintypes.BOOL

SetFilePointerEx = kernel32.SetFilePointerEx
SetFilePointerEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int64,
    ctypes.POINTER(ctypes.c_int64),
    wintypes.DWORD,
]
SetFilePointerEx.restype = wintypes.BOOL


def _get_file_info(handle):
    info = BY_HANDLE_FILE_INFORMATION()
    if not GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    identity = (
        int(info.dwVolumeSerialNumber),
        int(info.nFileIndexHigh),
        int(info.nFileIndexLow),
    )
    return {
        "identity": identity,
        "num_links": int(info.nNumberOfLinks),
        "attributes": int(info.dwFileAttributes),
    }


def _read_bytes_from_handle(handle, num_bytes=1024):
    new_pos = ctypes.c_int64()
    if not SetFilePointerEx(handle, 0, ctypes.byref(new_pos), FILE_BEGIN):
        raise ctypes.WinError(ctypes.get_last_error())

    buf = ctypes.create_string_buffer(num_bytes)
    read_bytes = wintypes.DWORD(0)
    res = ReadFile(handle, buf, num_bytes, ctypes.byref(read_bytes), None)
    if not res:
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.raw[: read_bytes.value]


def msvcrt_get_osfhandle(fd: int) -> int:
    import msvcrt
    return msvcrt.get_osfhandle(fd)


# Test 1: Hardlink identity baseline
def test_win32_hardlink_identity_and_link_count_invariants(tmp_path):
    """Verify Win32 handle identity invariants across aliased hardlinks."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "target.txt"
    outside_file.write_text("outside target content", encoding="utf-8")

    private_dir = tmp_path / "private_state"
    private_dir.mkdir()
    link_file = private_dir / "aliased.txt"

    res = CreateHardLinkW(str(link_file), str(outside_file), None)
    if not res:
        err = ctypes.get_last_error()
        pytest.skip(f"CreateHardLinkW failed with Win32 error {err}")

    assert link_file.exists()

    dir_fd = open_trusted_dir(private_dir, create=False)
    try:
        parent_handle = ctypes.c_void_p(msvcrt_get_osfhandle(dir_fd))
        status, h_link = open_file_relative(
            parent_handle,
            "aliased.txt",
            desired_access=FILE_READ_ATTRIBUTES,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        try:
            info_link = _get_file_info(h_link)
        finally:
            close_handle(h_link)
    finally:
        os.close(dir_fd)

    dir_fd_out = open_trusted_dir(outside_dir, create=False)
    try:
        parent_handle_out = ctypes.c_void_p(msvcrt_get_osfhandle(dir_fd_out))
        status, h_target = open_file_relative(
            parent_handle_out,
            "target.txt",
            desired_access=FILE_READ_ATTRIBUTES,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        try:
            info_target = _get_file_info(h_target)
        finally:
            close_handle(h_target)
    finally:
        os.close(dir_fd_out)

    assert info_link["num_links"] >= 2
    assert info_target["num_links"] >= 2
    assert info_link["identity"] == info_target["identity"]


# Test 2: Read through hardlink
def test_state_backend_read_hardlink_boundary(tmp_path):
    """Diagnose read_private_json_at behavior on a hardlinked state file."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "pairing.json"
    valid_payload = {
        "version": STATE_VERSION,
        "instance_id": "a" * 32,
        "extension_origin": "chrome-extension://abcdefghijklmnop",
    }
    outside_file.write_text(json.dumps(valid_payload), encoding="utf-8")

    private_dir = tmp_path / "chrome_companion"
    private_dir.mkdir()
    link_file = private_dir / "pairing.json"

    res = CreateHardLinkW(str(link_file), str(outside_file), None)
    if not res:
        pytest.skip("CreateHardLinkW unavailable")

    fd = open_trusted_dir(private_dir, create=False)
    try:
        data = read_private_json_at(fd, "pairing.json", path=link_file)
        assert data == valid_payload
    finally:
        os.close(fd)


# Test 3: Write decoupling
def test_state_backend_write_hardlink_decoupling(tmp_path):
    """Verify write_private_json_at decouples hardlinks via atomic replacement."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "pairing.json"
    v0_text = json.dumps({"version": STATE_VERSION, "instance_id": "0" * 32, "extension_origin": "chrome-extension://v0"})
    outside_file.write_text(v0_text, encoding="utf-8")

    private_dir = tmp_path / "chrome_companion"
    private_dir.mkdir()
    link_file = private_dir / "pairing.json"

    res = CreateHardLinkW(str(link_file), str(outside_file), None)
    if not res:
        pytest.skip("CreateHardLinkW unavailable")

    dir_fd_out = open_trusted_dir(outside_dir, create=False)
    try:
        parent_handle_out = ctypes.c_void_p(msvcrt_get_osfhandle(dir_fd_out))
        status, h_target = open_file_relative(
            parent_handle_out,
            "pairing.json",
            desired_access=FILE_READ_ATTRIBUTES,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        try:
            original_identity = _get_file_info(h_target)["identity"]
        finally:
            close_handle(h_target)
    finally:
        os.close(dir_fd_out)

    fd = open_trusted_dir(private_dir, create=False)
    try:
        v1_payload = {
            "version": STATE_VERSION,
            "instance_id": "1" * 32,
            "extension_origin": "chrome-extension://v1",
        }
        write_private_json_at(fd, "pairing.json", v1_payload, path=link_file)

        assert outside_file.read_text(encoding="utf-8") == v0_text
        read_back = read_private_json_at(fd, "pairing.json", path=link_file)
        assert read_back == v1_payload

        dir_fd_priv = open_trusted_dir(private_dir, create=False)
        try:
            parent_handle_priv = ctypes.c_void_p(msvcrt_get_osfhandle(dir_fd_priv))
            status, h_priv = open_file_relative(
                parent_handle_priv,
                "pairing.json",
                desired_access=FILE_READ_ATTRIBUTES,
                create_disposition=FILE_OPEN,
                create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            )
            assert status == STATUS_SUCCESS
            try:
                replacement_identity = _get_file_info(h_priv)["identity"]
            finally:
                close_handle(h_priv)
        finally:
            os.close(dir_fd_priv)

        assert replacement_identity != original_identity
    finally:
        os.close(fd)


def _run_open_handle_experiment(tmp_path, share_mode, mode_label):
    """Controlled helper for Test 4A and Test 4B."""
    outside_dir = tmp_path / f"outside_{mode_label}"
    outside_dir.mkdir()
    outside_file = outside_dir / "pairing.json"
    v0_text = json.dumps({"version": STATE_VERSION, "instance_id": "0" * 32, "extension_origin": "chrome-extension://v0"})
    outside_file.write_text(v0_text, encoding="utf-8")

    private_dir = tmp_path / f"chrome_companion_{mode_label}"
    private_dir.mkdir()
    link_file = private_dir / "pairing.json"

    res = CreateHardLinkW(str(link_file), str(outside_file), None)
    if not res:
        pytest.skip("CreateHardLinkW unavailable")

    h_outside = CreateFileW(
        str(outside_file),
        GENERIC_READ,
        share_mode,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h_outside == INVALID_HANDLE_VALUE or h_outside is None:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        info_pre = _get_file_info(h_outside)
        original_identity = info_pre["identity"]
        assert info_pre["num_links"] >= 2
        content_pre = _read_bytes_from_handle(h_outside, 1024).decode("utf-8")
        assert content_pre == v0_text

        v1_payload = {
            "version": STATE_VERSION,
            "instance_id": "1" * 32,
            "extension_origin": "chrome-extension://v1",
        }

        fd = open_trusted_dir(private_dir, create=False)
        write_exception = None
        try:
            write_private_json_at(fd, "pairing.json", v1_payload, path=link_file)
        except Exception as exc:
            write_exception = exc
        finally:
            os.close(fd)

        # Baseline Invariants (Must hold regardless of outcome):
        # 1. Pre-existing handle MUST still point to original identity and read V0
        info_post_handle = _get_file_info(h_outside)
        assert info_post_handle["identity"] == original_identity
        content_post_handle = _read_bytes_from_handle(h_outside, 1024).decode("utf-8")
        assert content_post_handle == v0_text

        # 2. Outside pathname MUST still point to original identity and read V0
        assert outside_file.read_text(encoding="utf-8") == v0_text

        dir_fd_out = open_trusted_dir(outside_dir, create=False)
        try:
            parent_out = ctypes.c_void_p(msvcrt_get_osfhandle(dir_fd_out))
            status_out, h_out_path = open_file_relative(
                parent_out,
                "pairing.json",
                desired_access=FILE_READ_ATTRIBUTES,
                create_disposition=FILE_OPEN,
                create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            )
            assert status_out == STATUS_SUCCESS
            try:
                assert _get_file_info(h_out_path)["identity"] == original_identity
            finally:
                close_handle(h_out_path)
        finally:
            os.close(dir_fd_out)

        # Outcome-specific Invariants
        if write_exception is None:
            # SUCCESS PATH:
            # Private pathname must exist, contain V1, and have a NEW file identity.
            assert link_file.exists()
            fd_priv = open_trusted_dir(private_dir, create=False)
            try:
                data_priv = read_private_json_at(fd_priv, "pairing.json", path=link_file)
                assert data_priv == v1_payload

                parent_priv = ctypes.c_void_p(msvcrt_get_osfhandle(fd_priv))
                status_priv, h_priv_path = open_file_relative(
                    parent_priv,
                    "pairing.json",
                    desired_access=FILE_READ_ATTRIBUTES,
                    create_disposition=FILE_OPEN,
                    create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                )
                assert status_priv == STATUS_SUCCESS
                try:
                    priv_identity = _get_file_info(h_priv_path)["identity"]
                    assert priv_identity != original_identity
                finally:
                    close_handle(h_priv_path)
            finally:
                os.close(fd_priv)
        else:
            # FAILURE PATH:
            # Exception MUST be StateError.
            # Private pathname MUST still exist, contain V0, and resolve to original identity.
            assert isinstance(write_exception, StateError)
            assert link_file.exists()

            fd_priv = open_trusted_dir(private_dir, create=False)
            try:
                data_priv = read_private_json_at(fd_priv, "pairing.json", path=link_file)
                assert data_priv == json.loads(v0_text)

                parent_priv = ctypes.c_void_p(msvcrt_get_osfhandle(fd_priv))
                status_priv, h_priv_path = open_file_relative(
                    parent_priv,
                    "pairing.json",
                    desired_access=FILE_READ_ATTRIBUTES,
                    create_disposition=FILE_OPEN,
                    create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                )
                assert status_priv == STATUS_SUCCESS
                try:
                    priv_identity = _get_file_info(h_priv_path)["identity"]
                    assert priv_identity == original_identity
                finally:
                    close_handle(h_priv_path)
            finally:
                os.close(fd_priv)
    finally:
        CloseHandle(h_outside)


# Test 4A: Open external handle WITH FILE_SHARE_DELETE
def test_state_backend_write_hardlink_with_open_target_handle_share_delete(tmp_path):
    """Test 4A: Controlled hardlink replacement with FILE_SHARE_DELETE enabled."""
    share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    _run_open_handle_experiment(tmp_path, share_mode, "share_delete")


# Test 4B: Open external handle WITHOUT FILE_SHARE_DELETE
def test_state_backend_write_hardlink_with_open_target_handle_no_share_delete(tmp_path):
    """Test 4B: Controlled hardlink replacement with FILE_SHARE_DELETE omitted."""
    share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE
    _run_open_handle_experiment(tmp_path, share_mode, "no_share_delete")