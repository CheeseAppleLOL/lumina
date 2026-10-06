"""Windows Slice 5: state-layer hostile-path and integrity tests.

These tests exercise the existing win32_state.py through its public helpers.
They deliberately do not modify chrome_companion/state.py.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows state backend")

from chrome_companion import win32_state as state


EXT_ID = "abcdefghijklmnopabcdefghijklmnop"
ORIGIN = f"chrome-extension://{EXT_ID}/"
INSTANCE = "0123456789abcdef0123456789abcdef"


def _junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"junction creation unavailable: {result.stderr.strip()}")


def _victim(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.json"
    victim.write_text("DO_NOT_TOUCH\n", encoding="utf-8")
    return victim


def test_read_rejects_final_file_junction(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    companion = state.companion_dir(data_dir)
    companion.mkdir(exist_ok=True)
    victim = _victim(tmp_path)

    target = companion / "target.json"
    _junction(target, victim.parent)

    with pytest.raises(state.StateError):
        state.read_private_json(target)

    assert victim.read_text(encoding="utf-8") == "DO_NOT_TOUCH\n"
    assert target.is_dir()


def test_write_rejects_final_directory_junction(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    companion = state.companion_dir(data_dir)
    companion.mkdir(exist_ok=True)
    victim = _victim(tmp_path)

    target = companion / "target.json"
    _junction(target, victim.parent)

    with pytest.raises(state.StateError):
        state.write_private_json(target, {"version": 1, "value": "MUST NOT ESCAPE"})

    assert victim.read_text(encoding="utf-8") == "DO_NOT_TOUCH\n"
    assert target.is_dir()


def test_remove_does_not_follow_final_directory_junction(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    companion = state.companion_dir(data_dir)
    companion.mkdir(exist_ok=True)
    victim = _victim(tmp_path)

    target = companion / "target.json"
    _junction(target, victim.parent)

    fd = state.open_companion_dir(data_dir, create=False)
    try:
        assert state.remove_regular_at(fd, "target.json") is False
    finally:
        os.close(fd)

    assert victim.read_text(encoding="utf-8") == "DO_NOT_TOUCH\n"
    assert target.is_dir()


def test_intermediate_companion_junction_is_rejected(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    real_companion = state.companion_dir(data_dir)
    real_companion.mkdir(exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "install.json").write_text(
        json.dumps({"version": 1, "extension_origin": ORIGIN, "socket_path": "ATTACKER", "installed_at": 1}),
        encoding="utf-8",
    )

    # Replace the companion directory with a junction after the data root is
    # created. open_companion_dir must refuse to traverse it.
    real_companion.rmdir()
    _junction(real_companion, outside)

    with pytest.raises(state.StateError):
        state.open_companion_dir(data_dir, create=False)

    assert (outside / "install.json").read_text(encoding="utf-8").find("ATTACKER") >= 0


def test_existing_directory_cannot_be_replaced_as_state_file(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    companion = state.companion_dir(data_dir)
    companion.mkdir(exist_ok=True)
    victim = _victim(tmp_path)

    target = companion / "state.json"
    target.mkdir()

    with pytest.raises(state.StateError):
        state.write_private_json(target, {"version": 1, "value": "MUST NOT"})

    assert target.is_dir()
    assert victim.read_text(encoding="utf-8") == "DO_NOT_TOUCH\n"


def test_malformed_json_is_rejected(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    companion = state.companion_dir(data_dir)
    companion.mkdir(exist_ok=True)
    target = companion / "install.json"
    target.write_text("{not-json", encoding="utf-8")

    with pytest.raises(state.StateError):
        state.load_install(data_dir)


def test_wrong_state_version_is_rejected(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    companion = state.companion_dir(data_dir)
    companion.mkdir(exist_ok=True)
    target = companion / "install.json"
    target.write_text(
        json.dumps({
            "version": 999,
            "extension_origin": ORIGIN,
            "socket_path": "test",
            "installed_at": 1,
        }),
        encoding="utf-8",
    )

    with pytest.raises(state.StateError):
        state.load_install(data_dir)


def test_atomic_replace_leaves_exact_final_content_and_no_temp_files(tmp_path: Path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    target = data_dir / "state.json"

    state.write_private_json(target, {"version": 1, "value": "first"})
    state.write_private_json(target, {"version": 1, "value": "second"})

    assert state.read_private_json(target)["value"] == "second"
    leftovers = list(target.parent.glob(f".{target.name}.*.tmp"))
    assert leftovers == []
