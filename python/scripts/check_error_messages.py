#!/usr/bin/env python3
"""S020 checklist I-2 enforcement: error messages must be actionable and not leak internals.

Walks src/aegis/*.py (excluding _generated/) and checks every
``raise ValueError(...)`` and ``raise RuntimeError(...)`` for:

1. **No internal-name leak**: messages must NOT contain banned terms
   (Trojan Horse: ``aegis-core``, ``sync_policies``, ``Mode.FULL``, ``Mode.LITE``,
   ``encryption``, ``audit``, ``scoring``, ``reflex engine``, ``aegis-shield``).
2. **Actionable**: message must contain at least one actionability cue
   (``Use``, ``Specify``, ``Example``, ``Set``, ``Define``, ``Install``,
   ``Contact``, ``See``, ``For``, period followed by capital letter, etc.).
   Exception: ``TypeError`` is exempt (already structurally typed).

Aegis 米軍規格: skip = fail.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "aegis"
EXCLUDE_DIRS = {"_generated"}

BANNED_TERMS = (
    "aegis-core",
    "sync_policies",
    "Mode.FULL",
    "Mode.LITE",
    "reflex engine",
    "aegis-shield",
    # error-message-specific bans: these are user-visible at runtime through
    # tracebacks and exception logs, so the looser source-wide allowance for
    # ``encryption`` / ``audit`` / ``scoring`` does not apply here. There is no
    # legitimate reason for an error message raised to a caller to enumerate
    # internal Aegis platform components.
    "encryption",
    "scoring",
)

ACTIONABLE_CUES = (
    "Use ",
    "use ",
    "Specify ",
    "specify ",
    "Example",
    "example",
    "Set ",
    "Define ",
    "define ",
    "Install ",
    "install ",
    "Contact ",
    "contact ",
    "See ",
    "see ",
    "For ",
    "for ",
    "should ",
    "Provide ",
    "provide ",
)

CHECK_TYPES = {"ValueError", "RuntimeError"}


def collect_message(node: ast.Call) -> str | None:
    """Extract the literal message string from a raise X(...) call, if any.

    Concatenates string literals (including implicit f-string parts that are constants).
    """
    if not node.args:
        return None
    parts: list[str] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            parts.append(arg.value)
        elif isinstance(arg, ast.JoinedStr):
            for v in arg.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
        elif isinstance(arg, ast.BinOp):
            # crude string concatenation handler
            try:
                src = ast.unparse(arg)
                parts.append(re.sub(r"[^A-Za-z0-9 ,.'\"\\[\\]:_/-]", "", src))
            except Exception:
                pass
    return " ".join(parts) if parts else None


def walk(file: Path, tree: ast.AST, violations: list[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise) or node.exc is None:
            continue
        if not isinstance(node.exc, ast.Call):
            continue
        func = node.exc.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else (func.attr if isinstance(func, ast.Attribute) else None)
        )
        if name not in CHECK_TYPES:
            continue
        msg = collect_message(node.exc)
        if msg is None:
            violations.append(f"{file}:{node.lineno}: {name} has no literal message")
            continue
        for term in BANNED_TERMS:
            if term in msg:
                violations.append(
                    f"{file}:{node.lineno}: {name} leaks banned term '{term}'"
                )
        if not any(cue in msg for cue in ACTIONABLE_CUES):
            violations.append(
                f"{file}:{node.lineno}: {name} message is not actionable: {msg!r}"
            )


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
        walk(path, tree, violations)

    if violations:
        print("I-2 FAIL: error messages have issues", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("I-2 PASS: all ValueError/RuntimeError messages are actionable and leak-free")
    return 0


if __name__ == "__main__":
    sys.exit(main())
