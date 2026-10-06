"""Windows-only tests for chrome_companion.win32_primitives."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows-only Companion primitive tests",
)


if os.name == "nt":
    from chrome_companion import win32_primitives as w32


def test_relative_directory_open_rejects_junction(tmp_path: Path):
    parent = tmp_path / "parent"
    real = parent / "real"
    junction = parent / "junction"
    parent.mkdir()
    real.mkdir()
    (real / "marker.txt").write_text("marker\n", encoding="utf-8")

    result = os.system(
        f'cmd.exe /c mklink /J "{junction}" "{real}" >nul'
    )
    assert result == 0

    parent_handle = w32.open_directory_absolute(str(parent))
    try:
        status, handle = w32.open_directory_relative(
            parent_handle,
            junction.name,
        )
        assert status == w32.STATUS_REPARSE_POINT_ENCOUNTERED
        assert handle is None
    finally:
        w32.close_handle(parent_handle)


def test_relative_directory_open_accepts_real_directory(tmp_path: Path):
    parent = tmp_path / "parent"
    real = parent / "real"
    parent.mkdir()
    real.mkdir()

    parent_handle = w32.open_directory_absolute(str(parent))
    try:
        status, handle = w32.open_directory_relative(
            parent_handle,
            real.name,
        )
        assert status == w32.STATUS_SUCCESS
        assert handle not in (None, 0, w32.INVALID_HANDLE_VALUE)
        w32.close_handle(handle)
    finally:
        w32.close_handle(parent_handle)


def test_relative_write_flush_and_replace(tmp_path: Path):
    parent = tmp_path / "parent"
    parent.mkdir()
    target = parent / "target.txt"
    source = parent / "source.tmp"
    target.write_text("OLD\n", encoding="utf-8")

    parent_handle = w32.open_directory_absolute(str(parent))
    try:
        status, source_handle = w32.open_file_relative(
            parent_handle,
            source.name,
            desired_access=w32.FILE_WRITE_DATA | w32.DELETE,
            create_disposition=w32.FILE_CREATE,
        )
        assert status == w32.STATUS_SUCCESS

        try:
            w32.write_all(source_handle, b"NEW\n")
            w32.flush_file(source_handle)

            status = w32.rename_replace_relative(
                source_handle,
                parent_handle,
                target.name,
            )
            assert status == w32.STATUS_SUCCESS
        finally:
            w32.close_handle(source_handle)
    finally:
        w32.close_handle(parent_handle)

    assert target.read_text(encoding="utf-8") == "NEW\n"
    assert not source.exists()
