"""Deterministic Windows secure directory/file acquisition tests."""
from pathlib import Path
import subprocess
import pytest

from chrome_companion.win32_primitives import (
    FILE_READ_DATA,
    FILE_READ_ATTRIBUTES,
    FILE_NON_DIRECTORY_FILE,
    FILE_SYNCHRONOUS_IO_NONALERT,
    FILE_OPEN_REPARSE_POINT,
    STATUS_FILE_IS_A_DIRECTORY,
    STATUS_REPARSE_POINT_ENCOUNTERED,
    STATUS_SUCCESS,
    close_handle,
    open_directory_absolute,
    open_directory_relative,
    open_file_relative,
)


def _junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"junction creation unavailable: {result.stdout} {result.stderr}")


def _open_root(path: Path):
    return open_directory_absolute(str(path))


def _close(handle):
    if handle is not None:
        close_handle(handle)


def test_directory_relative_open_accepts_normal_child(tmp_path: Path):
    root_path = tmp_path / "state"
    child_path = root_path / "child"
    root_path.mkdir()
    child_path.mkdir()

    root = _open_root(root_path)
    child = None
    try:
        status, child = open_directory_relative(root, "child")
        assert status == STATUS_SUCCESS
        assert child is not None
    finally:
        _close(child)
        _close(root)


def test_directory_relative_open_rejects_final_junction(tmp_path: Path):
    root_path = tmp_path / "state"
    outside = tmp_path / "outside"
    junction = root_path / "child"
    root_path.mkdir()
    outside.mkdir()
    _junction(junction, outside)

    root = _open_root(root_path)
    child = None
    try:
        status, child = open_directory_relative(root, "child")
        assert status == STATUS_REPARSE_POINT_ENCOUNTERED
        assert child is None
        assert outside.is_dir()
    finally:
        _close(child)
        _close(root)


def test_directory_relative_open_rejects_intermediate_junction(tmp_path: Path):
    root_path = tmp_path / "state"
    outside = tmp_path / "outside"
    junction = root_path / "redirect"
    root_path.mkdir()
    outside.mkdir()
    (outside / "child").mkdir()
    _junction(junction, outside)

    root = _open_root(root_path)
    child = None
    try:
        status, child = open_directory_relative(root, "redirect\\child")
        assert status == STATUS_REPARSE_POINT_ENCOUNTERED
        assert child is None
        assert (outside / "child").is_dir()
    finally:
        _close(child)
        _close(root)


def test_file_relative_open_accepts_normal_file(tmp_path: Path):
    root_path = tmp_path / "state"
    root_path.mkdir()
    (root_path / "state.bin").write_bytes(b"STATE")

    root = _open_root(root_path)
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            "state.bin",
            desired_access=FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        )
        assert status == STATUS_SUCCESS
        assert handle is not None
    finally:
        _close(handle)
        _close(root)


def test_file_relative_open_final_junction_records_actual_status(tmp_path: Path):
    """Document the observed final-junction status with FILE_NON_DIRECTORY_FILE."""
    root_path = tmp_path / "state"
    outside = tmp_path / "outside"
    junction = root_path / "state.bin"
    root_path.mkdir()
    outside.mkdir()
    (outside / "state.bin").write_bytes(b"OUTSIDE")
    _junction(junction, outside)

    root = _open_root(root_path)
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            "state.bin",
            desired_access=FILE_READ_DATA,
        )
        assert status in (STATUS_REPARSE_POINT_ENCOUNTERED, STATUS_FILE_IS_A_DIRECTORY)
        assert handle is None
        assert (outside / "state.bin").read_bytes() == b"OUTSIDE"
    finally:
        _close(handle)
        _close(root)


def test_file_relative_open_final_junction_without_type_constraint_rejects_reparse(tmp_path: Path):
    """A/B: remove FILE_NON_DIRECTORY_FILE and test OBJ_DONT_REPARSE directly."""
    root_path = tmp_path / "state"
    outside = tmp_path / "outside"
    junction = root_path / "state.bin"
    root_path.mkdir()
    outside.mkdir()
    _junction(junction, outside)

    root = _open_root(root_path)
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            "state.bin",
            desired_access=FILE_READ_ATTRIBUTES,
            create_options=FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_REPARSE_POINT_ENCOUNTERED
        assert handle is None
    finally:
        _close(handle)
        _close(root)


def test_file_relative_open_final_junction_with_open_reparse_point_targets_junction(tmp_path: Path):
    """Control: FILE_OPEN_REPARSE_POINT intentionally opens the reparse object itself."""
    root_path = tmp_path / "state"
    outside = tmp_path / "outside"
    junction = root_path / "state.bin"
    root_path.mkdir()
    outside.mkdir()
    _junction(junction, outside)

    root = _open_root(root_path)
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            "state.bin",
            desired_access=FILE_READ_ATTRIBUTES,
            create_options=FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        assert status == STATUS_SUCCESS
        assert handle is not None
    finally:
        _close(handle)
        _close(root)


def test_file_relative_open_rejects_intermediate_junction(tmp_path: Path):
    root_path = tmp_path / "state"
    outside = tmp_path / "outside"
    junction = root_path / "redirect"
    root_path.mkdir()
    outside.mkdir()
    (outside / "state.bin").write_bytes(b"OUTSIDE")
    _junction(junction, outside)

    root = _open_root(root_path)
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            "redirect\\state.bin",
            desired_access=FILE_READ_DATA,
        )
        assert status == STATUS_REPARSE_POINT_ENCOUNTERED
        assert handle is None
        assert (outside / "state.bin").read_bytes() == b"OUTSIDE"
    finally:
        _close(handle)
        _close(root)


def test_file_relative_open_rejects_directory_as_non_directory_file(tmp_path: Path):
    root_path = tmp_path / "state"
    root_path.mkdir()
    (root_path / "not_a_file").mkdir()

    root = _open_root(root_path)
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            "not_a_file",
            desired_access=FILE_READ_DATA,
            create_options=FILE_NON_DIRECTORY_FILE,
        )
        assert status != STATUS_SUCCESS
        assert handle is None
    finally:
        _close(handle)
        _close(root)


def test_file_relative_open_does_not_create_when_open_requested(tmp_path: Path):
    root_path = tmp_path / "state"
    root_path.mkdir()

    root = _open_root(root_path)
    handle = None
    try:
        status, handle = open_file_relative(
            root,
            "missing.bin",
            desired_access=FILE_READ_DATA,
        )
        assert status != STATUS_SUCCESS
        assert handle is None
        assert not (root_path / "missing.bin").exists()
    finally:
        _close(handle)
        _close(root)
