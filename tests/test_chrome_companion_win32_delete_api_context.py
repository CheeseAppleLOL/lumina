"""TEST-ONLY diagnostic: establish delete_file_handle caller semantics.

This reads the ACTUAL Windows checkout and does not import or modify production
modules. It prints:
  * the function containing delete_file_handle(handle)
  * surrounding source
  * assignments/opens feeding the `handle` variable
  * try/except/finally structure around the call
  * the POSIX state.py delete/remove analogue when present

Run with:
  pytest -q -s tests/test_chrome_companion_win32_delete_api_context.py
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows backend")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def source(path: Path) -> tuple[str, ast.Module]:
    text = path.read_text(encoding="utf-8")
    return text, ast.parse(text, filename=str(path))


def enclosing_function(tree: ast.Module, target: ast.Call) -> ast.AST | None:
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.lineno <= target.lineno <= getattr(node, "end_lineno", node.lineno):
            if best is None or node.lineno >= best.lineno:
                best = node
    return best


def node_source(lines: list[str], node: ast.AST) -> str:
    start = max(1, node.lineno - 8)
    end = min(len(lines), getattr(node, "end_lineno", node.lineno) + 8)
    return "".join(
        f"{i:4}: {lines[i-1]}"
        for i in range(start, end + 1)
    )


def calls_delete(tree: ast.Module) -> list[ast.Call]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if (
                isinstance(f, ast.Name) and f.id == "delete_file_handle"
            ) or (
                isinstance(f, ast.Attribute)
                and f.attr == "delete_file_handle"
            ):
                out.append(node)
    return out


def references_to_handle(fn: ast.AST) -> list[ast.AST]:
    return [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Name) and n.id == "handle"
    ]


def test_print_delete_call_context():
    path = repo_root() / "chrome_companion" / "win32_state.py"
    assert path.is_file()
    text, tree = source(path)
    lines = text.splitlines(keepends=True)

    calls = calls_delete(tree)
    assert len(calls) == 1, f"Expected exactly one call, found {len(calls)}"

    call = calls[0]
    assert len(call.args) == 1
    assert isinstance(call.args[0], ast.Name)
    assert call.args[0].id == "handle"

    fn = enclosing_function(tree, call)
    assert fn is not None

    print("\n=== ACTUAL DELETE CALL ===")
    print(f"{path}:{call.lineno}:{call.col_offset}")
    print("delete_file_handle(handle)")

    print("\n=== ENCLOSING FUNCTION ===")
    print(f"{fn.name} (lines {fn.lineno}-{fn.end_lineno})")
    print(node_source(lines, fn))

    print("\n=== ALL `handle` REFERENCES IN CALLER ===")
    for n in references_to_handle(fn):
        print(f"line {n.lineno}: {ast.unparse(n)}")

    print("\n=== FULL CALLER SOURCE ===")
    start = fn.lineno
    end = fn.end_lineno
    for i in range(start, end + 1):
        print(f"{i:4}: {lines[i-1]}", end="")

    # Print nearby primitive calls in the same function, which establishes
    # the handle lifecycle without importing production code.
    print("\n=== PRIMITIVE CALLS IN CALLER ===")
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            try:
                rendered = ast.unparse(n)
            except Exception:
                rendered = ast.dump(n, include_attributes=False)
            if any(
                name in rendered
                for name in (
                    "open_",
                    "close_handle",
                    "delete_file_handle",
                    "write_all",
                    "flush_file",
                    "rename_replace_relative",
                )
            ):
                print(f"line {n.lineno}: {rendered}")


def test_print_posix_analogue_if_present():
    win_path = repo_root() / "chrome_companion" / "win32_state.py"
    posix_path = repo_root() / "chrome_companion" / "state.py"

    assert win_path.is_file()

    if not posix_path.is_file():
        print("\n=== POSIX ANALOGUE ===")
        print("chrome_companion/state.py is not present; no comparison available.")
        return

    text, tree = source(posix_path)
    lines = text.splitlines(keepends=True)

    print("\n=== POSIX state.py DELETE/REMOVE REFERENCES ===")
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            rendered = ast.unparse(node)
            if any(
                token in rendered
                for token in ("unlink", "remove", "replace", "delete")
            ):
                print(f"line {node.lineno}: {rendered}")
                found = True

    if not found:
        print("No obvious unlink/remove/replace/delete calls found.")

    # This test is deliberately informational.
    print("\n=== POSIX RELEVANT SOURCE WINDOWS ===")
    for i, line in enumerate(lines, 1):
        lower = line.lower()
        if any(token in lower for token in ("unlink", "remove", "delete")):
            start = max(1, i - 5)
            end = min(len(lines), i + 8)
            for j in range(start, end + 1):
                print(f"{j:4}: {lines[j-1]}", end="")
            print("---")
