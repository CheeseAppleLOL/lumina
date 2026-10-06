"""Diagnostic test for the missing win32_primitives.delete_file_handle API.

TEST ONLY. This does not modify or import the production Windows backend.

It statically inspects the ACTUAL chrome_companion/win32_state.py in the
checkout where this test is run and reports every call to delete_file_handle,
including source location and argument shape.  It also verifies that the
imported symbol is currently missing.

The purpose is to establish the function's real call-site contract before
implementing it.
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


def _load_state_tree() -> tuple[Path, ast.Module]:
    path = _repo_root() / "chrome_companion" / "win32_state.py"
    assert path.is_file(), f"Missing {path}"
    return path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _primitive_imports(tree: ast.Module) -> set[str]:
    result: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if node.module == "chrome_companion.win32_primitives":
                for alias in node.names:
                    if alias.name != "*":
                        result.add(alias.asname or alias.name)
    return result


def _delete_calls(tree: ast.Module) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        if isinstance(func, ast.Name) and func.id == "delete_file_handle":
            calls.append(node)
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "delete_file_handle"
        ):
            calls.append(node)

    return calls


def _expr_shape(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return f"Name({node.id})"
    if isinstance(node, ast.Constant):
        return f"Constant({node.value!r})"
    if isinstance(node, ast.Attribute):
        return f"Attribute({_expr_shape(node.value)}.{node.attr})"
    if isinstance(node, ast.Call):
        return "Call(...)"
    if isinstance(node, ast.Subscript):
        return "Subscript(...)"
    if isinstance(node, ast.UnaryOp):
        return f"UnaryOp({_expr_shape(node.operand)})"
    return type(node).__name__


def test_delete_file_handle_call_contract_from_actual_state_backend():
    path, tree = _load_state_tree()

    imports = _primitive_imports(tree)
    calls = _delete_calls(tree)

    assert "delete_file_handle" in imports, (
        f"{path} no longer imports delete_file_handle; this diagnostic "
        "is no longer applicable."
    )
    assert calls, (
        f"{path} imports delete_file_handle but contains no call to it."
    )

    report: list[str] = [
        f"State backend: {path}",
        f"delete_file_handle call count: {len(calls)}",
        "",
    ]

    for index, call in enumerate(calls, 1):
        args = [_expr_shape(arg) for arg in call.args]
        keywords = [
            f"{kw.arg}={_expr_shape(kw.value)}"
            for kw in call.keywords
        ]
        report.append(
            f"call {index}: line {call.lineno}, column {call.col_offset}"
        )
        report.append(f"  positional args ({len(args)}): {args}")
        report.append(f"  keyword args ({len(keywords)}): {keywords}")

    # This is deliberately informational: the test passes after printing
    # the contract so the user can return the exact result without us
    # modifying production code.
    print("\n" + "\n".join(report))


def test_current_primitives_do_not_define_delete_file_handle():
    primitives_path = _repo_root() / "chrome_companion" / "win32_primitives.py"
    assert primitives_path.is_file(), f"Missing {primitives_path}"

    tree = ast.parse(
        primitives_path.read_text(encoding="utf-8"),
        filename=str(primitives_path),
    )

    defined = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }

    assert "delete_file_handle" not in defined, (
        "delete_file_handle is now present in the current primitives module; "
        "the API-contract diagnosis is no longer needed."
    )
