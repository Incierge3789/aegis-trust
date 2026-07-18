"""S024 security sprint — env-surface hygiene guards (Python).

Mechanically enforces four source-level invariants over the SDK's environment
intake, so a future change that widens the secret surface is rejected by CI
rather than shipping silently:

1. Prefix confinement — every environment read in ``src/aegis_trust`` names an
   ``AEGIS_`` variable. The SDK must never read arbitrary host env, which is
   where third-party secrets live (AO-006 secret hygiene). A non-literal key is
   recorded as ``"<dynamic>"`` and fails this check.
2. No bulk / indirect intake — the SDK must not read the whole environment or
   reach it through an alias. ``dict(os.environ)``, ``os.environ.copy()``,
   iteration over ``os.environ``, ``env = os.environ`` and the like are the
   "read arbitrary host env" hole in disguise, so they are rejected outright.
3. Token confinement — ``AEGIS_TOKEN`` is read only in the sanctioned transport
   modules ``{client.py, shield.py}`` (matched by path relative to the package
   root, so a same-named module under a subpackage is not silently sanctioned).
4. Insecure-toggle confinement — ``AEGIS_DEV_INSECURE`` / ``AEGIS_VERIFY_SSL``
   are read only in the TLS-resolution module ``shield.py``. Keeping the
   dev-insecure decision in one module preserves the fail-secure prod-lock
   (AO-001 / AO-005); scattering the toggle would create bypass paths.

The scan is AST-based, so docstring/comment mentions of an env var are not
counted as reads. It resolves import aliases (``import os as _o`` /
``import os.path`` / ``from os import environ as _e``), assignment and annotated
rebinds (``env = os.environ`` / ``o: T = os``), one-hop ``getattr(os,
"environ")``, and both the str and bytes APIs (``environ``/``environb``,
``getenv``/``getenvb``) — closing the bypass classes surfaced across three
rounds of the S024 cross-review (codex + cursor).

Accepted coverage boundary (defense-in-depth, not a complete static analyzer;
none of these appear in the SDK and each is non-idiomatic). Out of scope for a
source-level lint: fully dynamic metaprogramming — ``importlib`` /
``__import__("os")``, ``from os import *``, ``os.__dict__["environ"]`` — and
control-flow-dependent aliasing such as ``o = os if cond else os``. A guard that
runs without executing the code cannot follow these; they are covered by the
layered controls (gitleaks secret scan + human code review + fail-closed
runtime). Recorded as S024 residual handoff (R-S024-1).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[2] / "src" / "aegis_trust"

# Sanctioned module sets, keyed by POSIX path relative to SRC_DIR.
TOKEN_MODULES = {"client.py", "shield.py"}
INSECURE_TOGGLE_MODULES = {"shield.py"}
INSECURE_TOGGLE_VARS = {"AEGIS_DEV_INSECURE", "AEGIS_VERIFY_SSL"}

# Both the str and bytes environment APIs.
ENVIRON_ATTRS = ("environ", "environb")
GETENV_ATTRS = ("getenv", "getenvb")


class _EnvScan:
    """Classify every environment access in one module.

    Produces ``reads`` (env-var names of confined literal reads, plus
    ``"<dynamic>"`` for computed keys) and ``indirect`` (line numbers of
    bulk / aliased environment accesses that bypass a named read).
    """

    def __init__(self, tree: ast.AST) -> None:
        self.os_aliases: set[str] = set()
        self.environ_aliases: set[str] = set()
        self.getenv_aliases: set[str] = set()
        self.reads: list[str] = []
        self.indirect: list[int] = []
        self._confined_ids: set[int] = set()
        self._aliasdef_ids: set[int] = set()

        self._resolve_import_aliases(tree)
        # Assignment aliases may chain (a = os.environ; b = a); iterate to a
        # fixpoint over a few rounds (chains are short in practice).
        for _ in range(4):
            before = (len(self.environ_aliases), len(self.getenv_aliases))
            self._resolve_assignment_aliases(tree)
            if (len(self.environ_aliases), len(self.getenv_aliases)) == before:
                break
        self._classify(tree)

    # -- alias resolution -------------------------------------------------
    def _resolve_import_aliases(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        if a.name == "os":  # ``import os as _o``
                            self.os_aliases.add(a.asname)
                    elif a.name.split(".")[0] == "os":
                        # ``import os`` and ``import os.path`` both bind ``os``.
                        self.os_aliases.add("os")
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                for a in node.names:
                    if a.name in ENVIRON_ATTRS:
                        self.environ_aliases.add(a.asname or a.name)
                    elif a.name in GETENV_ATTRS:
                        self.getenv_aliases.add(a.asname or a.name)

    def _is_os_ref(self, node: ast.AST) -> bool:
        """``os`` reached as a bare name, or via ``getattr(os, 'environ'|...)``."""
        return isinstance(node, ast.Name) and node.id in self.os_aliases

    def _getattr_target(self, node: ast.AST, attrs: tuple[str, ...]) -> bool:
        """Match ``getattr(<os-alias>, '<attr>')`` — a reflective attr access."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and self._is_os_ref(node.args[0])
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in attrs
        )

    def _is_environ_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.environ_aliases
        if self._getattr_target(node, ENVIRON_ATTRS):
            return True
        return (
            isinstance(node, ast.Attribute)
            and node.attr in ENVIRON_ATTRS
            and self._is_os_ref(node.value)
        )

    def _is_getenv_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.getenv_aliases
        if self._getattr_target(node, GETENV_ATTRS):
            return True
        return (
            isinstance(node, ast.Attribute)
            and node.attr in GETENV_ATTRS
            and self._is_os_ref(node.value)
        )

    def _resolve_assignment_aliases(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            # Plain ``a = b`` and annotated ``a: T = b`` rebinds both count.
            if isinstance(node, ast.Assign):
                val = node.value
                targets = [t for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                val = node.value
                targets = [node.target] if isinstance(node.target, ast.Name) else []
            else:
                continue
            if not targets:
                continue
            # Module rebind: ``o = os`` / ``o: Any = os`` widens the os-alias
            # set so ``o.environ.get(...)`` is still seen.
            if isinstance(val, ast.Name) and val.id in self.os_aliases:
                for t in targets:
                    self.os_aliases.add(t.id)
            elif self._is_environ_expr(val):
                self._aliasdef_ids.add(id(val))
                for t in targets:
                    self.environ_aliases.add(t.id)
            elif self._is_getenv_expr(val):
                self._aliasdef_ids.add(id(val))
                for t in targets:
                    self.getenv_aliases.add(t.id)

    # -- classification ---------------------------------------------------
    @staticmethod
    def _literal(node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return "<dynamic>"

    def _classify(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            # environ.get("X") / getenv("X")
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "get"
                    and self._is_environ_expr(func.value)
                ):
                    self._confined_ids.add(id(func.value))
                    self.reads.append(
                        self._literal(node.args[0]) if node.args else "<dynamic>"
                    )
                elif self._is_getenv_expr(func):
                    self._confined_ids.add(id(func))
                    self.reads.append(
                        self._literal(node.args[0]) if node.args else "<dynamic>"
                    )
            # environ["X"]
            elif isinstance(node, ast.Subscript) and self._is_environ_expr(node.value):
                self._confined_ids.add(id(node.value))
                self.reads.append(self._literal(node.slice))

        # Any environ / getenv reference that is neither a confined read
        # receiver nor an alias definition is a bulk / indirect access.
        for node in ast.walk(tree):
            if self._is_environ_expr(node) or self._is_getenv_expr(node):
                if id(node) in self._confined_ids or id(node) in self._aliasdef_ids:
                    continue
                self.indirect.append(getattr(node, "lineno", -1))


def _scan_all() -> dict[str, _EnvScan]:
    assert SRC_DIR.is_dir(), f"source dir not found: {SRC_DIR}"
    out: dict[str, _EnvScan] = {}
    for py in sorted(SRC_DIR.rglob("*.py")):
        scan = _EnvScan(ast.parse(py.read_text(encoding="utf-8"), filename=str(py)))
        if scan.reads or scan.indirect:
            out[py.relative_to(SRC_DIR).as_posix()] = scan
    return out


def test_scan_is_non_vacuous():
    """Guard against a scan that passes by finding nothing."""
    scans = _scan_all()
    total = sum(len(s.reads) for s in scans.values())
    assert total >= 10, f"expected the SDK to read >=10 env vars, found {total}"
    all_names = {n for s in scans.values() for n in s.reads}
    assert "AEGIS_TOKEN" in all_names, "AEGIS_TOKEN read not detected — scan is broken"


def test_all_env_reads_are_aegis_prefixed():
    """Invariant 1: no SDK module reads a non-AEGIS_ (or dynamic) env var."""
    scans = _scan_all()
    offenders = {
        mod: [n for n in s.reads if not n.startswith("AEGIS_")]
        for mod, s in scans.items()
    }
    offenders = {m: n for m, n in offenders.items() if n}
    assert not offenders, f"non-AEGIS_ env reads found: {offenders}"


def test_no_bulk_or_indirect_environ_access():
    """Invariant 2: the SDK never reads the whole environment or aliases it."""
    scans = _scan_all()
    offenders = {mod: s.indirect for mod, s in scans.items() if s.indirect}
    assert not offenders, (
        "bulk / indirect os.environ access (dict()/copy()/iteration/alias) "
        f"bypasses the named-read guard: {offenders}"
    )


def test_token_intake_is_confined():
    """Invariant 3: AEGIS_TOKEN read only in sanctioned transport modules."""
    scans = _scan_all()
    readers = {mod for mod, s in scans.items() if "AEGIS_TOKEN" in s.reads}
    assert readers, "AEGIS_TOKEN reader set is empty — scan is broken"
    stray = readers - TOKEN_MODULES
    assert not stray, f"AEGIS_TOKEN read outside {TOKEN_MODULES}: {stray}"


def test_insecure_toggle_is_confined():
    """Invariant 4: dev-insecure / verify-ssl toggles read only in the TLS module."""
    scans = _scan_all()
    readers = {
        mod for mod, s in scans.items() if INSECURE_TOGGLE_VARS.intersection(s.reads)
    }
    assert readers, "insecure-toggle reader set is empty — scan is broken"
    stray = readers - INSECURE_TOGGLE_MODULES
    assert not stray, (
        f"insecure toggle {INSECURE_TOGGLE_VARS} read outside "
        f"{INSECURE_TOGGLE_MODULES}: {stray}"
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
