"""Windows Slice 5 API-lineage test.

TEST ONLY: does not import or modify the Windows state backend.
It statically compares names imported from win32_primitives.py by
win32_state.py against names actually defined/exported by the primitive
module.

This is intentionally useful when slice artifacts have been mixed across
revisions: it diagnoses the production-module API mismatch without
changing either module.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    __import__("os").name != "nt",
    reason="Windows state backend",
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _imported_primitive_names(state_path: Path) -> list[str]:
    tree = ast.parse(state_path.read_text(encoding="utf-8"), filename=str(state_path))

    names: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module != "chrome_companion.win32_primitives":
            continue
        for alias in node.names:
            if alias.name != "*":
                names.append(alias.name)

    return names


def _defined_primitive_names(primitives_path: Path) -> set[str]:
    tree = ast.parse(
        primitives_path.read_text(encoding="utf-8"),
        filename=str(primitives_path),
    )

    names: set[str] = set()

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)

    # Names imported into win32_primitives itself are also valid module
    # attributes, so account for normal "from X import NAME" imports.
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])

    return names


def test_win32_state_imports_are_satisfied_by_current_primitives():
    repo = _repo_root()
    state_path = repo / "chrome_companion" / "win32_state.py"
    primitives_path = repo / "chrome_companion" / "win32_primitives.py"

    assert state_path.is_file(), f"Missing {state_path}"
    assert primitives_path.is_file(), f"Missing {primitives_path}"

    imported = _imported_primitive_names(state_path)
    defined = _defined_primitive_names(primitives_path)

    missing = sorted(set(imported) - defined)

    assert not missing, (
        "win32_state.py imports primitive API names that are absent from the "
        f"current win32_primitives.py: {missing}\n\n"
        f"All imported names: {sorted(set(imported))}\n"
        f"Primitive names found: {sorted(defined)}"
    )


def test_delete_file_handle_api_is_present_if_state_uses_it():
    repo = _repo_root()
    state_path = repo / "chrome_companion" / "win32_state.py"
    primitives_path = repo / "chrome_companion" / "win32_primitives.py"

    imported = _imported_primitive_names(state_path)
    if "delete_file_handle" not in imported:
        pytest.skip("Current win32_state.py does not import delete_file_handle")

    defined = _defined_primitive_names(primitives_path)

    assert "delete_file_handle" in defined, (
        "win32_state.py explicitly requires delete_file_handle, but the "
        "current win32_primitives.py does not define/export it."
    )
