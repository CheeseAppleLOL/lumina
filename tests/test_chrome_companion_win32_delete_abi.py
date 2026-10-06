"""Focused Windows ABI test for FileDispositionInformation.

This test intentionally does NOT add or import delete_file_handle(). It exercises
only the existing NtSetInformationFile binding already used by
win32_primitives.rename_replace_relative(), establishing the exact native ABI
before a wrapper primitive is introduced.
"""

from __future__ import annotations

import ctypes
from pathlib import Path

import pytest

from chrome_companion.win32_primitives import (
    DELETE,
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_READ_ATTRIBUTES,
    FILE_SYNCHRONOUS_IO_NONALERT,
    IO_STATUS_BLOCK,
    NtSetInformationFile,
    STATUS_ACCESS_DENIED,
    STATUS_SUCCESS,
    SYNCHRONIZE,
    close_handle,
    open_directory_absolute,
    open_file_relative,
    status_u32,
)


FILE_DISPOSITION_INFORMATION = 13


class FILE_DISPOSITION_INFORMATION_STRUCT(ctypes.Structure):
    _fields_ = [("DeletePending", ctypes.c_ubyte)]


def _delete_pending(handle) -> int:
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


def _open_delete_handle(root_handle, name: str):
    return open_file_relative(
        root_handle,
        name,
        desired_access=DELETE | FILE_READ_ATTRIBUTES,
        create_disposition=FILE_OPEN,
        create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )


def test_file_disposition_information_abi_deletes_file(tmp_path: Path):
    target = tmp_path / "delete-me.txt"
    target.write_text("DELETE ABI TEST", encoding="utf-8")

    root = open_directory_absolute(str(tmp_path))
    handle = None
    try:
        status, handle = _open_delete_handle(root, target.name)
        assert status == STATUS_SUCCESS
        assert handle is not None

        assert _delete_pending(handle) == STATUS_SUCCESS
    finally:
        if handle is not None:
            close_handle(handle)
        close_handle(root)

    assert not target.exists()


def test_file_disposition_information_requires_delete_access(tmp_path: Path):
    target = tmp_path / "keep-me.txt"
    target.write_text("MUST SURVIVE", encoding="utf-8")

    root = open_directory_absolute(str(tmp_path))
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            target.name,
            desired_access=FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            create_disposition=FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        assert handle is not None

        assert _delete_pending(handle) == STATUS_ACCESS_DENIED
    finally:
        if handle is not None:
            close_handle(handle)
        close_handle(root)

    assert target.read_text(encoding="utf-8") == "MUST SURVIVE"
