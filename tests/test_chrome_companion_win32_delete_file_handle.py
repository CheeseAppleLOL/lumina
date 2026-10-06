import ctypes
from pathlib import Path
import pytest
from chrome_companion.win32_primitives import (
    DELETE, FILE_READ_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
    FILE_SYNCHRONOUS_IO_NONALERT, STATUS_ACCESS_DENIED, STATUS_SUCCESS,
    IO_STATUS_BLOCK, NtSetInformationFile, status_u32,
    close_handle, open_directory_absolute,
    open_file_relative,
)

FILE_DISPOSITION_INFORMATION = 13


class FILE_DISPOSITION_INFORMATION_STRUCT(ctypes.Structure):
    _fields_ = [("DeletePending", ctypes.c_ubyte)]


def delete_file_handle(handle) -> int:
    info = FILE_DISPOSITION_INFORMATION_STRUCT()
    info.DeletePending = 1
    io_status = IO_STATUS_BLOCK()
    status = NtSetInformationFile(
        handle,
        ctypes.byref(io_status),
        ctypes.byref(info),
        ctypes.sizeof(info),
        FILE_DISPOSITION_INFORMATION,
    )
    return status_u32(status)


def _open_file(root, name, access):
    return open_file_relative(
        root, name, desired_access=access, create_disposition=FILE_OPEN,
        create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )

def test_delete_file_handle_deletes_regular_file(tmp_path: Path):
    target = tmp_path / "target.txt"
    target.write_bytes(b"DELETE-ME")
    root = open_directory_absolute(str(tmp_path))
    try:
        status, handle = _open_file(root, target.name, DELETE | FILE_READ_DATA)
        assert status == STATUS_SUCCESS
        assert handle is not None
        try:
            assert delete_file_handle(handle) == STATUS_SUCCESS
        finally:
            close_handle(handle)
        assert not target.exists()
    finally:
        close_handle(root)

def test_delete_file_handle_requires_delete_access(tmp_path: Path):
    target = tmp_path / "protected.txt"
    target.write_bytes(b"KEEP-ME")
    root = open_directory_absolute(str(tmp_path))
    try:
        status, handle = _open_file(root, target.name, FILE_READ_DATA)
        assert status == STATUS_SUCCESS
        assert handle is not None
        try:
            assert delete_file_handle(handle) == STATUS_ACCESS_DENIED
        finally:
            close_handle(handle)
        assert target.read_bytes() == b"KEEP-ME"
    finally:
        close_handle(root)

def test_delete_file_handle_rejects_final_directory_junction(tmp_path: Path):
    outside = tmp_path / "outside"
    root_path = tmp_path / "root"
    outside.mkdir()
    root_path.mkdir()
    protected = outside / "protected.txt"
    protected.write_bytes(b"OUTSIDE")
    junction = root_path / "target.txt"

    import subprocess
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.skip(
            "directory junction creation unavailable: "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )

    root = open_directory_absolute(str(root_path))
    try:
        status, handle = _open_file(root, junction.name, DELETE | FILE_READ_DATA)
        assert not (status == STATUS_SUCCESS and handle is not None)
        if handle is not None:
            close_handle(handle)
        assert protected.read_bytes() == b"OUTSIDE"
    finally:
        close_handle(root)
