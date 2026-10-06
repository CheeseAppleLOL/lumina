"""Windows-only Slice 2 state backend verification.

These tests are intentionally separate from the existing POSIX state suite so
Windows security/behavior gates remain permanently identifiable.
"""
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows state backend")

from chrome_companion import state

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


def test_private_state_round_trip_and_atomic_replace(tmp_path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)

    state.write_private_json(data_dir / "sample.json", {"version": 1, "value": "first"})
    assert state.read_private_json(data_dir / "sample.json")["value"] == "first"

    state.write_private_json(data_dir / "sample.json", {"version": 1, "value": "second"})
    assert state.read_private_json(data_dir / "sample.json")["value"] == "second"


def test_companion_install_and_pairing_records(tmp_path):
    data_dir = tmp_path / "data"

    install = state.save_install(
        data_dir,
        extension_id=EXT_ID,
        socket_path=r"\\.\pipe\lumina-companion-test",
    )
    assert install.extension_origin == ORIGIN
    loaded_install = state.load_install(data_dir)
    assert loaded_install == install

    pairing = state.save_pairing(
        data_dir,
        instance_id=INSTANCE,
        extension_origin=ORIGIN,
    )
    assert state.load_pairing(data_dir) == pairing


def test_final_reparse_target_is_rejected(tmp_path):
    data_dir = tmp_path / "data"
    state.ensure_private_dir(data_dir)
    companion = state.companion_dir(data_dir)
    companion.mkdir(exist_ok=True)

    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.json"
    victim.write_text("DO_NOT_TOUCH\n", encoding="utf-8")

    target = companion / "target.json"
    _junction(target, outside)

    with pytest.raises(state.StateError):
        state.write_private_json(target, {"version": 1, "value": "MUST NOT REPLACE JUNCTION"})

    assert victim.read_text(encoding="utf-8") == "DO_NOT_TOUCH\n"
    assert target.is_dir()
