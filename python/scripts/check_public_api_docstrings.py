#!/usr/bin/env python3
"""S020 checklist E-1 enforcement: every public API must have a docstring.

Walks src/aegis/*.py (excluding _generated/) and checks that every public
function, class, and method (those whose name does not start with '_') has a
docstring. Exits non-zero with a list of violations on failure.

Aegis 米軍規格: skip = fail. A missing docstring is a hard fail.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "aegis"
EXCLUDE_DIRS = {"_generated"}


def is_public(name: str) -> bool:
    return not name.startswith("_")


def walk(
    node: ast.AST, file: Path, violations: list[str], in_function: bool = False
) -> None:
    """Walk AST, checking public defs.

    Skips nested defs inside functions (closures, decorators, wrappers — implementation
    detail, not public API). Class-level methods are still checked.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (
                not in_function
                and is_public(child.name)
                and not ast.get_docstring(child)
            ):
                violations.append(
                    f"{file}:{child.lineno}: {child.name} missing docstring"
                )
            child_in_function = in_function or isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef)
            )
            walk(child, file, violations, child_in_function)


def main() -> int:
    violations: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError as e:
            violations.append(f"{path}: SyntaxError: {e}")
            continue
        walk(tree, path, violations)

    if violations:
        print("E-1 FAIL: public APIs missing docstrings", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("E-1 PASS: all public APIs have docstrings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
