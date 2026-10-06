"""Slice 16A Diagnostic: Deterministic Win32 File Replacement & Handle-Pinning Races (TOCTOU).

Proves that pathname substitutions during state read/write operations via genuine
NT file-object renames never cause in-place object corruption or silent traversal
of attacker-controlled objects, with unconditional handle verification, explicit
status classification, and robust hardlink survivor identity tracking for both write and read races.
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
            13,
        )
        if status != 0:
            raise OSError(f"NtSetInformationFile failed with status 0x{status:08X}")

    win32_primitives.delete_file_handle = _test_local_delete_file_handle

# Step 2: Safe imports from production modules[cite: 1, 2]
import chrome_companion.win32_state as win32_state
from chrome_companion.win32_primitives import (
    BY_HANDLE_FILE_INFORMATION,
    GetFileInformationByHandle,
    close_handle,
    open_file_relative,
    FILE_READ_ATTRIBUTES,
    DELETE,
    SYNCHRONIZE,
    FILE_OPEN,
    FILE_NON_DIRECTORY_FILE,
    FILE_SYNCHRONOUS_IO_NONALERT,
    STATUS_SUCCESS,
    rename_replace_relative,
)
from chrome_companion.win32_state import (
    STATE_VERSION,
    open_trusted_dir,
    read_private_json_at,
    write_private_json_at,
    StateError,
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

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

CreateHardLinkW = kernel32.CreateHardLinkW
CreateHardLinkW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
CreateHardLinkW.restype = wintypes.BOOL


def _get_file_info(handle):
    info = BY_HANDLE_FILE_INFORMATION()
    if not GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return {
        "identity": (int(info.dwVolumeSerialNumber), int(info.nFileIndexHigh), int(info.nFileIndexLow)),
        "num_links": int(info.nNumberOfLinks),
    }


def msvcrt_get_osfhandle(fd: int) -> int:
    import msvcrt
    return msvcrt.get_osfhandle(fd)


def test_win32_write_replacement_race_toctou(tmp_path):
    """Slice 16A-1: Deterministic file replacement race during write_private_json_at.

    Intercepts win32_state.rename_replace_relative, asserts success of the attacker's
    NT file object substitution, unconditionally verifies target file identity matches
    the attacker survivor before production proceeds, and tracks object integrity.
    """
    private_dir = tmp_path / "chrome_companion"
    private_dir.mkdir()
    target_file = private_dir / "pairing.json"

    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    attacker_source_file = attacker_dir / "attacker_source.json"
    attacker_survivor = attacker_dir / "attacker_survivor.json"

    v0_payload = {
        "version": STATE_VERSION,
        "instance_id": "0" * 32,
        "extension_origin": "chrome-extension://v0",
    }
    v1_payload = {
        "version": STATE_VERSION,
        "instance_id": "1" * 32,
        "extension_origin": "chrome-extension://v1",
    }
    attacker_payload = {
        "version": STATE_VERSION,
        "instance_id": "f" * 32,
        "extension_origin": "chrome-extension://attacker",
    }

    v0_text = json.dumps(v0_payload, indent=2, sort_keys=True) + "\n"
    attacker_text = json.dumps(attacker_payload, indent=2, sort_keys=True) + "\n"

    target_file.write_text(v0_text, encoding="utf-8")
    attacker_source_file.write_text(attacker_text, encoding="utf-8")

    # Establish attacker-survivor hardlink to track the attacker object independently
    if not CreateHardLinkW(str(attacker_survivor), str(attacker_source_file), None):
        pytest.skip("CreateHardLinkW unavailable for attacker survivor setup")

    # Capture original attacker object identity and content baseline
    h_att = CreateFileW(
        str(attacker_survivor),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    assert h_att != INVALID_HANDLE_VALUE and h_att is not None
    try:
        original_attacker_identity = _get_file_info(h_att)["identity"]
    finally:
        CloseHandle(h_att)

    assert attacker_survivor.read_text(encoding="utf-8") == attacker_text

    # Patch win32_state.rename_replace_relative directly
    original_state_rename = win32_state.rename_replace_relative
    interception_triggered = []
    attacker_status_captured = []

    def deterministic_intercept_rename(source_handle, destination_directory, name):
        interception_triggered.append(True)
        # Genuine attacker substitution: Open a handle to the attacker source file
        h_attacker = CreateFileW(
            str(attacker_source_file),
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if h_attacker != INVALID_HANDLE_VALUE and h_attacker is not None:
            try:
                # Atomically replace pairing.json with the attacker's file object
                status = rename_replace_relative(h_attacker, destination_directory, name)
                attacker_status_captured.append(status)
            finally:
                CloseHandle(h_attacker)
        
        # Unconditionally verify that target pathname now points to the attacker object
        h_check_sub = CreateFileW(
            str(target_file),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        assert h_check_sub != INVALID_HANDLE_VALUE and h_check_sub is not None
        try:
            sub_identity = _get_file_info(h_check_sub)["identity"]
            assert sub_identity == original_attacker_identity, "Attacker substitution failed to bind target to attacker object"
        finally:
            CloseHandle(h_check_sub)

        # Proceed with the real production rename
        return original_state_rename(source_handle, destination_directory, name)

    win32_state.rename_replace_relative = deterministic_intercept_rename
    try:
        fd = open_trusted_dir(private_dir, create=False)
        try:
            write_private_json_at(fd, "pairing.json", v1_payload, path=target_file)
        except StateError as exc:
            write_error = exc
        else:
            write_error = None
        finally:
            os.close(fd)
    finally:
        win32_state.rename_replace_relative = original_state_rename

    assert len(interception_triggered) == 1
    assert len(attacker_status_captured) == 1
    assert attacker_status_captured[0] == STATUS_SUCCESS, f"Attacker substitution NT status failed: 0x{attacker_status_captured[0]:08X}"

    # Invariant Verification 1: Attacker-survivor object must remain completely pristine and unmutated
    h_surv_check = CreateFileW(
        str(attacker_survivor),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    assert h_surv_check != INVALID_HANDLE_VALUE and h_surv_check is not None
    try:
        survivor_info = _get_file_info(h_surv_check)
        assert survivor_info["identity"] == original_attacker_identity
    finally:
        CloseHandle(h_surv_check)
    assert attacker_survivor.read_text(encoding="utf-8") == attacker_text

    # Invariant Verification 2: Production outcome is either secure success (publishing V1) or safe StateError failure
    if write_error is None:
        final_data = target_file.read_text(encoding="utf-8")
        assert json.loads(final_data) == v1_payload
    else:
        assert isinstance(write_error, StateError)


def test_win32_read_handle_pinning_race(tmp_path):
    """Slice 16A-2: Verify read_private_json_at handle pinning against pathname replacement.

    Proves that once open_file_relative acquires a handle, attempting a pathname replacement
    explicitly classifies the resulting NT status (distinguishing successful replacement from
    Windows sharing access denial), uses a hardlink survivor baseline to verify successful object
    re-binding, and verifies that the active read stream remains securely pinned to the original object.
    """
    private_dir = tmp_path / "chrome_companion"
    private_dir.mkdir()
    target_file = private_dir / "pairing.json"

    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    malicious_source = attacker_dir / "malicious_source.json"
    malicious_survivor = attacker_dir / "malicious_survivor.json"

    v0_payload = {
        "version": STATE_VERSION,
        "instance_id": "0" * 32,
        "extension_origin": "chrome-extension://v0",
    }
    malicious_payload = {
        "version": STATE_VERSION,
        "instance_id": "f" * 32,
        "extension_origin": "chrome-extension://malicious",
    }

    target_file.write_text(json.dumps(v0_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    malicious_source.write_text(json.dumps(malicious_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Establish malicious-survivor hardlink to track the malicious object baseline independently
    if not CreateHardLinkW(str(malicious_survivor), str(malicious_source), None):
        pytest.skip("CreateHardLinkW unavailable for malicious survivor setup")

    # Capture baseline identity of the malicious object via survivor
    h_mal_base = CreateFileW(
        str(malicious_survivor),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    assert h_mal_base != INVALID_HANDLE_VALUE and h_mal_base is not None
    try:
        malicious_identity = _get_file_info(h_mal_base)["identity"]
    finally:
        CloseHandle(h_mal_base)

    # Patch win32_state.open_file_relative directly
    original_state_open = win32_state.open_file_relative
    read_intercept_executed = []
    replacement_statuses = []

    def intercept_open(parent_handle, name, *, desired_access, create_disposition=FILE_OPEN, create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT):
        status, handle = original_state_open(
            parent_handle,
            name,
            desired_access=desired_access,
            create_disposition=create_disposition,
            create_options=create_options,
        )
        if status == STATUS_SUCCESS and name == "pairing.json":
            read_intercept_executed.append(True)
            # Attempt file object substitution while read handle is held
            h_mal = CreateFileW(
                str(malicious_source),
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if h_mal != INVALID_HANDLE_VALUE and h_mal is not None:
                try:
                    rep_status = rename_replace_relative(h_mal, parent_handle, name)
                    replacement_statuses.append(rep_status)
                finally:
                    CloseHandle(h_mal)
        return status, handle

    win32_state.open_file_relative = intercept_open
    try:
        fd = open_trusted_dir(private_dir, create=False)
        try:
            read_data = read_private_json_at(fd, "pairing.json", path=target_file)
        finally:
            os.close(fd)
    finally:
        win32_state.open_file_relative = original_state_open

    assert len(read_intercept_executed) == 1

    # Explicitly classify the result of the replacement attempt:
    if replacement_statuses:
        status_code = replacement_statuses[0]
        if status_code == STATUS_SUCCESS:
            # Finding A: Pathname was successfully replaced while original HANDLE remained open.
            # Verify target identity matches the malicious survivor baseline object.
            h_read_check = CreateFileW(
                str(target_file),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            assert h_read_check != INVALID_HANDLE_VALUE and h_read_check is not None
            try:
                read_check_identity = _get_file_info(h_read_check)["identity"]
                assert read_check_identity == malicious_identity, "Pathname replacement did not bind target to malicious object"
            finally:
                CloseHandle(h_read_check)
        elif status_code == 0xC0000022:  # STATUS_ACCESS_DENIED
            # Finding B: Windows sharing semantics prevented replacement while read HANDLE was open.
            pass
        else:
            pytest.fail(f"Unexpected rename replacement status: 0x{status_code:08X}")

    # Regardless of whether replacement succeeded or was blocked by sharing semantics,
    # the active read result must remain securely pinned to v0_payload.
    assert read_data == v0_payload