"""Conformance runner hygiene — the guard on the guards (Python).

A shared corpus only delivers cross-language identity if both implementations
feed it to code that actually ships. A runner that re-derives the behaviour
inline and checks its own reconstruction is tautological: it proves only that
the primitive it reimplemented is deterministic, it stays green while the
shipped code drifts underneath it, and it reads as coverage in every report.

The Node byte anchor for the canonical idempotency digest was exactly this --
it rebuilt the canonical form and hashed its own reconstruction, never calling
the shipped payloadHash. Green throughout, proving nothing.

Cross-review history (2026-07-19, cursor + agy, both flagged independently):
the first version of this guard checked only that a runner IMPORTED the shipped
symbol. Import is not use. A runner could import the symbol, never call it, and
assert a hard-coded digest -- green, and exactly the tautology the guard exists
to stop. It also banned only static `import hashlib`, which `__import__` and
`importlib.import_module` walk straight past. Both holes are closed below:
the check is now on CALL sites, and dynamic-import machinery is itself banned
inside runners.

What is enforced here:
  1. Every corpus on disk has a registry entry (no unexercised corpus).
  2. Every runner CALLS the shipped symbol, not merely imports it.
  3. No runner can re-derive: crypto primitives and the dynamic-import
     machinery that would smuggle them in are both refused.
  4. Every runner reads the corpus it is registered against.
  5. The declaration file cannot drift: customer_facing is recomputed from
     enforcement, and every attached evidence path must exist.
  6. The scan asserts its own non-vacuity.

Mirror: node/tests/conformanceRunnerHygiene.test.ts.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONFORMANCE = REPO / "conformance"
REGISTRY = CONFORMANCE / "runners.v0.json"
INVARIANTS = CONFORMANCE / "invariants.v0.json"

_REG = json.loads(REGISTRY.read_text())
assert _REG["version"] == 0
CORPORA = _REG["corpora"]
FORBIDDEN = set(_REG["forbidden_imports"]["python"])
DYNAMIC_IMPORT = set(_REG["forbidden_dynamic_import"]["python"])
NOT_CORPORA = set(_REG["not_corpora"])

_INV = json.loads(INVARIANTS.read_text())
INVARIANTS_LIST = _INV["invariants"]

# Criteria 2 and 3 of enforcement_full_criteria need the runner registry and the
# backend matrix respectively (see the tests at the end of this file).
BACKENDS_PATH = CONFORMANCE / "backends.v0.json"
_BACKENDS = json.loads(BACKENDS_PATH.read_text())


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.Module) -> set[tuple[str, str]]:
    """(module, imported-name) pairs. ``from a import b as c`` -> ("a", "b")."""
    out: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                out.add((node.module, alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.add((alias.name, alias.name))
    return out


def _local_name_for(tree: ast.Module, module: str, symbol: str) -> str | None:
    """The local binding a symbol was imported under, honouring ``as`` renames."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            for alias in node.names:
                if alias.name == symbol:
                    return alias.asname or alias.name
    return None


def _called_names(tree: ast.Module) -> set[str]:
    """Identifiers that appear in call position, including attribute calls."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                out.add(func.id)
            elif isinstance(func, ast.Attribute):
                out.add(func.attr)
    return out


def _string_constants(tree: ast.Module) -> set[str]:
    return {
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }


def test_scan_is_non_vacuous() -> None:
    """A guard that scans nothing must fail, not pass."""
    assert CORPORA, "runner registry declares no corpora — the guard is inert"
    assert INVARIANTS_LIST, "invariants declaration is empty — the guard is inert"
    for entry in CORPORA:
        assert "python" in entry["runners"], (
            f"{entry['corpus']}: no Python runner declared"
        )


def test_every_corpus_has_a_registry_entry() -> None:
    """A corpus added without runners would sit unexercised, looking covered."""
    on_disk = {p.name for p in CONFORMANCE.glob("*.json") if p.name not in NOT_CORPORA}
    declared = {e["corpus"] for e in CORPORA}
    missing = on_disk - declared
    assert not missing, (
        f"corpus files with no runner entry in {REGISTRY.name}: {sorted(missing)} — "
        "a corpus nobody runs is not conformance, it is decoration"
    )
    stale = declared - on_disk
    assert not stale, f"registry names corpora that do not exist: {sorted(stale)}"


def test_not_corpora_entries_are_justified() -> None:
    """`not_corpora` is an escape hatch; every use of it must be declared.

    Cross-review (cursor): without this, a contributor drops an awkward corpus
    into `not_corpora` and it silently stops needing runners.
    """
    reasons = _REG["not_corpora_reasons"]
    undocumented = NOT_CORPORA - set(reasons)
    assert not undocumented, (
        f"not_corpora entries with no stated reason: {sorted(undocumented)} — "
        "the exemption list is where a suite goes to quietly die"
    )
    for name, reason in reasons.items():
        assert len(reason) > 20, f"{name}: reason is too thin to audit ({reason!r})"


@pytest.mark.parametrize("entry", CORPORA, ids=[e["corpus"] for e in CORPORA])
def test_runner_file_exists(entry: dict) -> None:
    """Both languages' runner paths are checked here, not just Python's.

    Cross-review (agy): if each language only validated its own paths, deleting
    the Python runner would leave Node CI green and vice versa.
    """
    for lang in ("python", "node"):
        path = REPO / entry["runners"][lang]["path"]
        assert path.is_file(), f"{entry['corpus']}: {lang} runner missing at {path}"


@pytest.mark.parametrize("entry", CORPORA, ids=[e["corpus"] for e in CORPORA])
def test_runner_calls_the_shipped_symbol(entry: dict) -> None:
    """Import is not use. The runner must CALL the shipped symbol.

    Cross-review (cursor + agy, independently): a runner could import the symbol
    to satisfy an import-only check, never call it, and assert a hard-coded
    expectation. Green, and precisely the tautology this guard exists to stop.
    """
    spec = entry["runners"]["python"]
    path = REPO / spec["path"]
    tree = _tree(path)
    module = spec["must_import"]["module"]
    symbol = spec["must_import"]["symbol"]

    local = _local_name_for(tree, module, symbol)
    assert local is not None, (
        f"{entry['corpus']}: {spec['path']} does not import {symbol} from {module}"
    )
    assert local in _called_names(tree), (
        f"{entry['corpus']}: {spec['path']} imports {symbol} but never calls it. "
        "A runner that does not invoke the shipped symbol is verifying its own "
        "reconstruction, whatever it imports."
    )


@pytest.mark.parametrize("entry", CORPORA, ids=[e["corpus"] for e in CORPORA])
def test_runner_reads_the_corpus_it_is_registered_against(entry: dict) -> None:
    """Registry and runner must name the same corpus.

    Cross-review (cursor): otherwise a runner can read some other fixture and
    still satisfy every import check, so the registry's claim about what is
    exercised becomes decorative.
    """
    spec = entry["runners"]["python"]
    path = REPO / spec["path"]
    # Substring, not equality: a runner may name the corpus inside a path
    # literal rather than as a bare filename.
    named = [s for s in _string_constants(_tree(path)) if entry["corpus"] in s]
    assert named, (
        f"{entry['corpus']}: {spec['path']} never names it. The registry claims "
        "this runner exercises that corpus; nothing checked that claim."
    )


@pytest.mark.parametrize("entry", CORPORA, ids=[e["corpus"] for e in CORPORA])
def test_runner_cannot_re_derive_the_behaviour(entry: dict) -> None:
    """Deny the primitives a runner would need to rebuild what it verifies.

    Cross-review (cursor + agy): banning only static `import hashlib` is walked
    past by `__import__("hashlib")` and `importlib.import_module(...)`, so the
    dynamic-import machinery is refused inside runners too.

    Honest residual, unchanged: a contributor can still hand-roll SHA-256 in
    pure Python, or vendor a third-party digest library. This raises the cost
    and removes the accidental path; it does not make re-derivation impossible.
    Nor would it have caught the ORIGINAL Node anchor, which lived outside the
    registry entirely. What it closes is the recurrence path for registered
    runners. Banning crypto across every test file was considered and rejected:
    it would reject the SHA-3 known-answer vectors, whose whole purpose is to
    compute a digest independently.
    """
    spec = entry["runners"]["python"]
    path = REPO / spec["path"]
    tree = _tree(path)

    modules = {m for m, _ in _imports(tree)}
    offenders = sorted(modules & FORBIDDEN)
    assert not offenders, (
        f"{entry['corpus']}: {spec['path']} imports {offenders}. A conformance "
        "runner with crypto primitives can re-derive the behaviour it is meant "
        "to verify, which is how a test goes green while proving nothing."
    )

    # Callee names AND imported symbol names. Cross-review round 2 (cursor, P1):
    # checking call sites alone is walked past by renaming the machinery on the
    # way in — `from importlib import import_module as im; im("hashlib")` calls
    # `im`, which is in no ban list. The static-import rename hole was closed in
    # round 1; this is the same hole on the dynamic side.
    imported_names = {name for _, name in _imports(tree)}
    dynamic = sorted((_called_names(tree) | imported_names) & DYNAMIC_IMPORT)
    assert not dynamic, (
        f"{entry['corpus']}: {spec['path']} uses {dynamic}. Dynamic import is "
        "how a banned primitive gets in without appearing in the import list — "
        "including under an alias."
    )


# ── the declaration file itself must not drift ──────────────────


def test_customer_facing_is_derived_not_hand_set() -> None:
    """invariants.v0.json declares customer_facing 'machine-checked'. Be the machine.

    Cross-review (cursor + agy, both P1): the declaration asserted this property
    and nothing in the repository enforced it, so `customer_facing: true` could
    be hand-edited onto an unenforced invariant and reach a customer. Declaring
    a guarantee while shipping no mechanism for it is the same failure this
    whole suite exists to remove -- it was simply one level further up.
    """
    for inv in INVARIANTS_LIST:
        applicable = [v for v in inv["enforcement"].values() if v != "not_applicable"]
        expected = bool(applicable) and all(v == "full" for v in applicable)
        assert inv["customer_facing"] == expected, (
            f"{inv['id']}: customer_facing={inv['customer_facing']} but enforcement="
            f"{inv['enforcement']} derives {expected}. customer_facing is derived, "
            "never hand-set — an invariant reaches a customer only once the machine "
            "that keeps it exists."
        )


def test_enforcement_values_are_from_the_declared_vocabulary() -> None:
    allowed = set(_INV["enforcement_values"])
    for inv in INVARIANTS_LIST:
        for side, value in inv["enforcement"].items():
            assert value in allowed, (
                f"{inv['id']}.{side}: unknown enforcement {value!r}"
            )


def test_not_applicable_sides_are_justified() -> None:
    """`not_applicable` removes a side from the customer_facing calculation."""
    for inv in INVARIANTS_LIST:
        for side, value in inv["enforcement"].items():
            if value == "not_applicable":
                reason = inv.get("not_applicable_reason", {}).get(side)
                assert reason, (
                    f"{inv['id']}.{side}: not_applicable with no justification. "
                    "An unjustified exemption is how a suite stops meaning anything."
                )


def test_attached_evidence_paths_exist() -> None:
    """Evidence must point at files that exist, or the map rots silently."""
    for inv in INVARIANTS_LIST:
        for item in inv["evidence"]:
            target = REPO / item["file"]
            assert target.is_file(), (
                f"{inv['id']}: evidence names {item['file']}, which does not exist"
            )


def _registered_runner_paths() -> set[str]:
    """Every runner path declared in runners.v0.json, both languages."""
    return {
        runner["path"] for corpus in CORPORA for runner in corpus["runners"].values()
    }


def test_full_enforcement_requires_evidence() -> None:
    """Criterion 1 of enforcement_full_criteria, mechanised."""
    for inv in INVARIANTS_LIST:
        if any(v == "full" for v in inv["enforcement"].values()):
            assert inv["evidence"], (
                f"{inv['id']}: enforcement claims 'full' with no attached evidence"
            )


def test_evidence_registered_flag_is_not_self_declared() -> None:
    """`registered: true` must agree with runners.v0.json, not assert itself.

    The flag is written by hand in invariants.v0.json. Criterion 2 says evidence
    must be "registered where that is machine-checked", and nothing checked the
    claim against the registry — so an entry could declare itself registered and
    the matrix would render it as machine-verified evidence. Cross-review (codex
    + cursor, 2026-07-29) flagged the criterion-2 gap; this closes the half of it
    that is checkable on any entry, not just `full` ones.
    """
    registered = _registered_runner_paths()
    for inv in INVARIANTS_LIST:
        for ev in inv.get("evidence", []):
            if ev.get("registered"):
                assert ev["file"] in registered, (
                    f"{inv['id']}: evidence {ev['file']} claims registered=true "
                    f"but is not a runner in runners.v0.json. The flag is a "
                    f"claim about machine-checking; it cannot be its own proof."
                )


def test_full_enforcement_requires_registered_evidence() -> None:
    """Criterion 2 of enforcement_full_criteria, mechanised.

    The declaration says all three criteria must hold for `full`, and `full` is
    what `customer_facing` derives from — so a criterion that is written but not
    enforced becomes a loose promise in a sales conversation. Only criterion 1
    was mechanised. This is criterion 2: every attached test must reach shipped
    code through a registered runner.
    """
    registered = _registered_runner_paths()
    for inv in INVARIANTS_LIST:
        if not any(v == "full" for v in inv["enforcement"].values()):
            continue
        for ev in inv["evidence"]:
            assert ev["file"] in registered, (
                f"{inv['id']}: enforcement claims 'full', but evidence "
                f"{ev['file']} is not registered in runners.v0.json. Criterion 2 "
                f"requires evidence to reach the shipped code through a "
                f"machine-checked runner — an unregistered test may be checking "
                f"its own reconstruction, which is exactly how the canonical "
                f"digest anchor stayed green while testing nothing."
            )


def test_full_enforcement_requires_complete_backend_coverage() -> None:
    """Criterion 3 of enforcement_full_criteria, mechanised.

    "Passes in all configurations": an invariant cannot be `full` while any
    surface in the backend registry still reports `none` or `partial` for it.
    Without this, `full` means "some backend passes", and `customer_facing`
    would promise a guarantee the product only partly delivers.
    """
    coverage = _BACKENDS["coverage"]
    for inv in INVARIANTS_LIST:
        if not any(v == "full" for v in inv["enforcement"].values()):
            continue
        weak = [
            f"{surface}={cells[inv['id']]['state']}"
            for surface, cells in coverage.items()
            if inv["id"] in cells and cells[inv["id"]]["state"] != "full"
        ]
        assert not weak, (
            f"{inv['id']}: enforcement claims 'full' but the backend registry "
            f"still reports non-full cells: {', '.join(sorted(weak))}. "
            f"Criterion 3 requires every configuration to pass."
        )


def test_the_full_criteria_gates_are_not_vacuous() -> None:
    """The three criteria above are only meaningful if they can fail.

    Nothing in the tree is `full` today (by design — the registry is
    incomplete), so the three tests above pass by iterating over an empty set.
    A test that is green because it examined nothing is the failure mode this
    whole file exists to stop, so exercise the predicates directly on a
    synthetic invariant that violates each criterion.
    """
    registered = _registered_runner_paths()
    assert registered, "runners.v0.json declares no runners — registry unreadable"

    unregistered = "python/tests/definitely_not_a_registered_runner.py"
    assert unregistered not in registered

    # Criterion 2 predicate must reject an unregistered evidence file.
    fake = {
        "id": "INV-FAKE",
        "enforcement": {"sdk": "full"},
        "evidence": [{"file": unregistered, "registered": True}],
    }
    assert any(v == "full" for v in fake["enforcement"].values())
    assert fake["evidence"][0]["file"] not in registered

    # Criterion 3 predicate must reject a non-full backend cell.
    cells = {"INV-FAKE": {"state": "partial"}}
    weak = [k for k, c in cells.items() if c["state"] != "full"]
    assert weak, "criterion-3 predicate failed to flag a partial cell"
