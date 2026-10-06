r"""
Slice 3B: Windows destination-boundary enforcement.

Run from the canonical Lumina repository root:

    cd C:\Projects\lumina
    pytest -q tests/test_chrome_companion_win32_destination_boundary.py

No custom environment variables are required.

This slice deliberately treats a destination as exactly one filename
component.  Multi-component relative paths are rejected before the NT
rename operation, preventing traversal through ".." or intermediate
reparse points.  A final-component junction is also tested independently.
"""

from pathlib import Path

import pytest

from chrome_companion.win32_primitives import (
    DELETE,
    FILE_CREATE,
    FILE_READ_DATA,
    FILE_WRITE_DATA,
    STATUS_SUCCESS,
    close_handle,
    flush_file,
    open_directory_absolute,
    open_file_relative,
    rename_replace_relative,
    validate_relative_filename,
    write_all,
)


ORIGINAL = b"ORIGINAL_SOURCE\n"
OLD_DESTINATION = b"OLD_DESTINATION\n"
OUTSIDE_PROTECTED = b"OUTSIDE_PROTECTED\n"


def _open_root(path: Path):
    return open_directory_absolute(str(path))


def _open_source(root, name: str = "source.txt"):
    status, handle = open_file_relative(
        root,
        name,
        desired_access=DELETE | FILE_READ_DATA,
    )
    assert status == STATUS_SUCCESS, f"source open failed: 0x{status:08X}"
    assert handle not in (None, 0), f"invalid source handle: {handle!r}"
    return handle


def _create_file(root, name: str, data: bytes):
    status, handle = open_file_relative(
        root,
        name,
        desired_access=FILE_READ_DATA | FILE_WRITE_DATA,
        create_disposition=FILE_CREATE,
    )
    assert status == STATUS_SUCCESS, f"file create failed: 0x{status:08X}"
    assert handle not in (None, 0), f"invalid file handle: {handle!r}"
    try:
        write_all(handle, data)
        flush_file(handle)
    finally:
        close_handle(handle)


def test_destination_is_exactly_one_filename_component(tmp_path: Path):
    """
    Valid destination replacement works, while path traversal forms are
    rejected before NtSetInformationFile is called.
    """
    root_path = tmp_path / "state"
    root_path.mkdir()

    outside_path = tmp_path / "outside.txt"
    outside_path.write_bytes(OUTSIDE_PROTECTED)

    source_path = root_path / "source.txt"
    destination_path = root_path / "destination.txt"
    source_path.write_bytes(ORIGINAL)
    destination_path.write_bytes(OLD_DESTINATION)

    root = _open_root(root_path)
    source_handle = None

    try:
        source_handle = _open_source(root)

        # These are all path-like or alternate-stream forms, not permitted
        # single state filenames.  Rejection must occur before the NT rename.
        invalid_names = (
            "..\\outside.txt",
            "../outside.txt",
            "nested\\destination.txt",
            "nested/destination.txt",
            "C:\\outside.txt",
            "\\\\server\\share\\outside.txt",
            "destination.txt:stream",
            ".",
            "..",
            "",
        )

        for name in invalid_names:
            with pytest.raises(ValueError):
                rename_replace_relative(source_handle, root, name)

        # Do not reopen the source pathname while the DELETE-capable source
        # HANDLE is still open. Windows can deny a fresh pathname open even
        # though the original HANDLE remains valid. Close only after the
        # boundary checks have completed, then inspect the namespace.
        close_handle(source_handle)
        source_handle = None

        # The invalid attempts must not have changed the namespace.
        assert source_path.exists()
        assert source_path.read_bytes() == ORIGINAL
        assert destination_path.exists()
        assert destination_path.read_bytes() == OLD_DESTINATION
        assert outside_path.read_bytes() == OUTSIDE_PROTECTED

        # Reacquire the original source object by its unchanged pathname.
        source_handle = _open_source(root)

        # A normal single-component destination remains supported.
        status = rename_replace_relative(
            source_handle,
            root,
            "destination.txt",
        )
        assert status == STATUS_SUCCESS, f"valid rename failed: 0x{status:08X}"

    finally:
        if source_handle is not None:
            close_handle(source_handle)
        close_handle(root)

    assert destination_path.read_bytes() == ORIGINAL
    assert not source_path.exists()
    assert outside_path.read_bytes() == OUTSIDE_PROTECTED


def test_final_destination_junction_cannot_be_replaced(tmp_path: Path):
    """
    A single-component destination name may itself be a reparse point.
    The tested NT rename primitive must refuse replacing that junction rather
    than modifying the directory/file reached through it.
    """
    root_path = tmp_path / "state"
    root_path.mkdir()

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    protected_path = outside_dir / "protected.txt"
    protected_path.write_bytes(OUTSIDE_PROTECTED)

    destination_junction = root_path / "destination.txt"
    source_path = root_path / "source.txt"
    source_path.write_bytes(ORIGINAL)

    result = pytest.importorskip("os").system(
        f'cmd.exe /c mklink /J "{destination_junction}" "{outside_dir}" >nul'
    )
    assert result == 0, "mklink /J failed; junction fixture could not be created"

    root = _open_root(root_path)
    source_handle = None

    try:
        source_handle = _open_source(root)

        status = rename_replace_relative(
            source_handle,
            root,
            "destination.txt",
        )

        assert status != STATUS_SUCCESS, (
            "rename unexpectedly replaced a final-component junction"
        )
    finally:
        if source_handle is not None:
            close_handle(source_handle)
        close_handle(root)

    # The junction must still exist and the protected outside object must be
    # unchanged.  The source must also remain because the rename was rejected.
    assert destination_junction.is_dir()
    assert destination_junction.is_junction()
    assert protected_path.read_bytes() == OUTSIDE_PROTECTED
    assert source_path.read_bytes() == ORIGINAL


@pytest.mark.parametrize(
    "name",
    [
        "name with space.txt",
        "unicode-\u03bb.txt",
        "state-01.json",
        "a" * 255,
    ],
)
def test_valid_single_component_names_are_accepted(name: str):
    """The policy permits ordinary single-component Windows filenames."""
    validate_relative_filename(name)
