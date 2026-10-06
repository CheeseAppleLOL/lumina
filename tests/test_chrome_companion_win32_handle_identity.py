r"""
Slice 3A: Windows HANDLE/object identity.

Run from the canonical Lumina repository root:

    cd C:\Projects\lumina
    pytest -q tests/test_chrome_companion_win32_handle_identity.py

The test targets the verified Slice 1 win32_primitives interface:
    open_file_relative(...) -> (NTSTATUS, HANDLE)
    open_directory_absolute(...) -> HANDLE

No custom environment variables are required.
"""

from pathlib import Path

from chrome_companion.win32_primitives import (
    DELETE,
    FILE_CREATE,
    FILE_READ_DATA,
    FILE_WRITE_DATA,
    STATUS_ACCESS_DENIED,
    STATUS_SUCCESS,
    close_handle,
    flush_file,
    open_directory_absolute,
    open_file_relative,
    rename_replace_relative,
    write_all,
)


ORIGINAL = b"ORIGINAL_OBJECT\n"
ATTACKER = b"NEW_OBJECT_AT_OLD_PATH\n"
OLD_DESTINATION = b"OLD_DESTINATION\n"


def _open_root(path: Path):
    return open_directory_absolute(str(path))


def _open_source(root, name: str):
    status, handle = open_file_relative(
        root,
        name,
        desired_access=DELETE | FILE_READ_DATA,
    )
    assert status == STATUS_SUCCESS, (
        f"source open failed for {name!r}: 0x{status:08X}"
    )
    assert handle not in (None, 0), f"source open returned invalid handle: {handle!r}"
    return handle


def _create_file(root, name: str):
    # This handle is used to populate the replacement object, so it must have
    # FILE_WRITE_DATA as well as FILE_READ_DATA.
    status, handle = open_file_relative(
        root,
        name,
        desired_access=FILE_READ_DATA | FILE_WRITE_DATA,
        create_disposition=FILE_CREATE,
    )
    assert status == STATUS_SUCCESS, (
        f"replacement create failed for {name!r}: 0x{status:08X}"
    )
    assert handle not in (None, 0), (
        f"replacement create returned invalid handle: {handle!r}"
    )
    return handle


def _write_fixture(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _read_fixture(path: Path) -> bytes:
    return path.read_bytes()


def test_source_handle_remains_pinned_after_pathname_replacement(tmp_path):
    """
    Prove that rename_replace_relative() operates on the supplied HANDLE's
    object rather than re-resolving the original pathname.

    The intermediate renamed pathname is deliberately not reopened while the
    original DELETE-capable handle remains open. That reopen is not needed for
    the identity proof and can be denied by Windows sharing semantics.

    Proof sequence:
      1. H1 opens the original source object.
      2. H2 opens the same object and renames it to moved.txt.
      3. H2 closes; H1 remains open.
      4. A new source.txt is created and populated with ATTACKER.
      5. H1 directly renames the original object to destination.txt.
      6. H1 closes.
      7. destination.txt contains ORIGINAL while source.txt contains ATTACKER.

    If the final rename resolved source.txt instead of using H1, the original
    content could not arrive at destination.txt while the replacement object
    remained at source.txt.
    """
    root_path = tmp_path / "state"
    root_path.mkdir()

    source_path = root_path / "source.txt"
    moved_path = root_path / "moved.txt"
    destination_path = root_path / "destination.txt"

    _write_fixture(source_path, ORIGINAL)
    _write_fixture(destination_path, OLD_DESTINATION)

    root = _open_root(root_path)
    source_handle = None
    namespace_handle = None
    replacement_handle = None

    try:
        # H1 is the identity-pinned original object.
        source_handle = _open_source(root, "source.txt")

        # H2 independently references the same object and performs the first
        # namespace substitution.
        namespace_handle = _open_source(root, "source.txt")
        status = rename_replace_relative(namespace_handle, root, "moved.txt")
        assert status == STATUS_SUCCESS, (
            f"preparatory rename failed: 0x{status:08X}"
        )

        close_handle(namespace_handle)
        namespace_handle = None

        assert not source_path.exists(), "original source pathname still exists"
        assert moved_path.exists(), "preparatory rename did not create moved.txt"

        # The old pathname is now free. Create a genuinely different object at
        # that pathname while H1 remains open against the original object.
        replacement_handle = _create_file(root, "source.txt")
        try:
            write_all(replacement_handle, ATTACKER)
            flush_file(replacement_handle)
        finally:
            close_handle(replacement_handle)
            replacement_handle = None

        assert source_path.exists(), "replacement source pathname was not created"
        assert _read_fixture(source_path) == ATTACKER

        # Decisive operation: this call receives H1 directly. It must rename the
        # original object, regardless of what source.txt now names.
        status = rename_replace_relative(source_handle, root, "destination.txt")
        assert status == STATUS_SUCCESS, (
            f"H1 rename failed: 0x{status:08X}"
        )

        # Close H1 before reopening destination through the pathname API.
        close_handle(source_handle)
        source_handle = None

        assert not moved_path.exists(), "original moved pathname still exists"
        assert _read_fixture(destination_path) == ORIGINAL
        assert _read_fixture(source_path) == ATTACKER

    finally:
        if replacement_handle is not None:
            close_handle(replacement_handle)
        if namespace_handle is not None:
            close_handle(namespace_handle)
        if source_handle is not None:
            close_handle(source_handle)
        close_handle(root)


def test_rename_requires_delete_access(tmp_path):
    """
    FileRenameInformation requires DELETE access on the source HANDLE.
    """
    root_path = tmp_path / "state"
    root_path.mkdir()

    source_path = root_path / "source.txt"
    destination_path = root_path / "destination.txt"

    _write_fixture(source_path, ORIGINAL)
    _write_fixture(destination_path, OLD_DESTINATION)

    root = _open_root(root_path)
    source_handle = None

    try:
        status, source_handle = open_file_relative(
            root,
            "source.txt",
            desired_access=FILE_READ_DATA,
        )
        assert status == STATUS_SUCCESS, (
            f"source open without DELETE failed unexpectedly: 0x{status:08X}"
        )
        assert source_handle not in (None, 0), (
            f"source open returned invalid handle: {source_handle!r}"
        )

        status = rename_replace_relative(
            source_handle,
            root,
            "destination.txt",
        )
        assert status == STATUS_ACCESS_DENIED, (
            f"rename unexpectedly succeeded or returned another status: "
            f"0x{status:08X}"
        )

        assert source_path.exists()
        assert _read_fixture(source_path) == ORIGINAL
        assert destination_path.exists()
        assert _read_fixture(destination_path) == OLD_DESTINATION

    finally:
        if source_handle is not None:
            close_handle(source_handle)
        close_handle(root)
