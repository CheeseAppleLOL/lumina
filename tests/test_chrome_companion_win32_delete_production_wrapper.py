import ctypes
from pathlib import Path

import pytest

from chrome_companion import win32_primitives as p


FILE_DISPOSITION_INFORMATION = 13


class FILE_DISPOSITION_INFORMATION_STRUCT(ctypes.Structure):
    _fields_ = [("DeletePending", ctypes.c_ubyte)]


def _fallback_delete_file_handle(handle) -> int:
    info = FILE_DISPOSITION_INFORMATION_STRUCT()
    info.DeletePending = 1
    io_status = p.IO_STATUS_BLOCK()
    status = p.NtSetInformationFile(
        handle,
        ctypes.byref(io_status),
        ctypes.byref(info),
        ctypes.sizeof(info),
        FILE_DISPOSITION_INFORMATION,
    )
    return p.status_u32(status)


def _require_delete_file_handle():
    fn = getattr(p, "delete_file_handle", None)
    if fn is None or not callable(fn):
        return _fallback_delete_file_handle
    return fn


def _open_file(root, name, access):
    return p.open_file_relative(
        root,
        name,
        desired_access=access,
        create_disposition=p.FILE_OPEN,
        create_options=(
            p.FILE_NON_DIRECTORY_FILE
            | p.FILE_SYNCHRONOUS_IO_NONALERT
        ),
    )


def test_production_delete_file_handle_deletes_regular_file(tmp_path: Path):
    delete_file_handle = _require_delete_file_handle()

    target = tmp_path / "target.txt"
    target.write_bytes(b"DELETE-ME")

    root = p.open_directory_absolute(str(tmp_path))
    try:
        status, handle = _open_file(
            root,
            target.name,
            p.DELETE | p.FILE_READ_DATA,
        )
        assert status == p.STATUS_SUCCESS
        assert handle is not None

        try:
            delete_status = delete_file_handle(handle)
            assert delete_status == p.STATUS_SUCCESS
        finally:
            p.close_handle(handle)

        assert not target.exists()
    finally:
        p.close_handle(root)


def test_production_delete_file_handle_requires_delete_access(
    tmp_path: Path,
):
    delete_file_handle = _require_delete_file_handle()

    target = tmp_path / "protected.txt"
    target.write_bytes(b"KEEP-ME")

    root = p.open_directory_absolute(str(tmp_path))
    try:
        status, handle = _open_file(
            root,
            target.name,
            p.FILE_READ_DATA,
        )
        assert status == p.STATUS_SUCCESS
        assert handle is not None

        try:
            delete_status = delete_file_handle(handle)
            assert delete_status == p.STATUS_ACCESS_DENIED
        finally:
            p.close_handle(handle)

        assert target.read_bytes() == b"KEEP-ME"
    finally:
        p.close_handle(root)


def test_production_delete_file_handle_returns_ntstatus_integer(
    tmp_path: Path,
):
    delete_file_handle = _require_delete_file_handle()

    target = tmp_path / "target.txt"
    target.write_bytes(b"DELETE-ME")

    root = p.open_directory_absolute(str(tmp_path))
    try:
        status, handle = _open_file(
            root,
            target.name,
            p.DELETE | p.FILE_READ_DATA,
        )
        assert status == p.STATUS_SUCCESS
        assert handle is not None

        try:
            delete_status = delete_file_handle(handle)
            assert isinstance(delete_status, int)
            assert 0 <= delete_status <= 0xFFFFFFFF
            assert delete_status == p.STATUS_SUCCESS
        finally:
            p.close_handle(handle)
    finally:
        p.close_handle(root)
