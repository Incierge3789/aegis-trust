"""Backend registry gate — a surface cannot be added without declaring it (Python).

invariants.v0.json says what must HOLD. backends.v0.json says what it must hold
FOR. This guard binds the second to reality: it parses the SDK's own source and
refuses any extension point that is not registered.

This is the backend form of the pattern already proven in test_contract_gate.py,
which AST-parses client.py for HTTP path literals and asserts each exists in the
committed openapi.json -- you cannot add a surface without declaring it. Nothing
equivalent existed for adapters, modes, or decision sources, which is precisely
the condition where a new adapter appears and nobody decides what it must
satisfy. By the time there are enough of them for the question to feel urgent,
declaring an invariant means discovering that some existing configuration
violates it.

Enforced here:
  1. Extraction matches source -- every backend exported by the SDK has a
     registry entry, and every registry entry names something that exists.
  2. The product is complete -- every (backend x invariant) cell resolves to a
     declared state, so a new backend cannot be registered without a recorded
     decision for all seven invariants, including an honest 'none'.
  3. Asymmetry is declared, not discovered -- a backend present in one SDK and
     absent in the other must say why. Undeclared asymmetry is how two SDKs stop
     being the same product without anyone noticing.

The guard earned its place while being written: the modes surface had been
registered with two members because the Mode enum was assumed to have two. It
has three. AUTO now has its own row.

Mirror: node/tests/backendRegistry.test.ts.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONFORMANCE = REPO / "conformance"
REGISTRY = CONFORMANCE / "backends.v0.json"

_REG = json.loads(REGISTRY.read_text())
assert _REG["version"] == 0
SURFACES = _REG["surfaces"]
COVERAGE = _REG["coverage"]
INVARIANT_IDS = _REG["invariant_ids"]
CELL_STATES = set(_REG["cell_states"])


def _module(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _dunder_all(tree: ast.Module) -> set[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "__all__":
                    return {
                        e.value
                        for e in node.value.elts  # type: ignore[attr-defined]
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    }
    return set()


def _enum_members(tree: ast.Module, class_name: str) -> set[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                t.id
                for stmt in node.body
                if isinstance(stmt, ast.Assign)
                for t in stmt.targets
                if isinstance(t, ast.Name)
            }
    return set()


def _extract(surface: dict) -> set[str]:
    """The symbols this surface actually exports, read off the source AST."""
    spec = surface["extraction"]["python"]
    tree = _module(REPO / spec["file"])
    if spec["symbol_source"] == "__all__" or spec["symbol_source"] == "named exports":
        return _dunder_all(tree)
    if spec["symbol_source"] == "Mode enum members":
        return _enum_members(tree, "Mode")
    raise AssertionError(f"unknown symbol_source {spec['symbol_source']!r}")


def _registered(surface: dict) -> set[str]:
    return {b["python"] for b in surface["backends"] if b["python"] is not None}


def test_registry_is_non_vacuous() -> None:
    """A gate that enumerates nothing must fail, not pass."""
    assert SURFACES, "no surfaces registered — the gate is inert"
    assert COVERAGE, "no coverage matrix — the gate is inert"
    assert len(INVARIANT_IDS) >= 7, "invariant id list looks truncated"
    for s in SURFACES:
        assert s["backends"], f"{s['id']}: surface with no backends"
        assert _extract(s), (
            f"{s['id']}: extraction found nothing — the parser is broken"
        )


def _excluded(surface: dict) -> dict[str, str]:
    return surface.get("classification_excluded", {}).get("python", {})


@pytest.mark.parametrize("surface", SURFACES, ids=[s["id"] for s in SURFACES])
def test_every_export_is_classified(surface: dict) -> None:
    """The whole point: a surface cannot grow without someone deciding.

    Not merely "registered" — CLASSIFIED. Every exported symbol is either a
    backend (with a row in `coverage` deciding all seven invariants) or an
    explicit exclusion with a stated reason. A new export is neither until
    somebody chooses, so this fails and the choice has to be made.
    """
    unclassified = _extract(surface) - _registered(surface) - set(_excluded(surface))
    assert not unclassified, (
        f"{surface['id']}: exported but unclassified: {sorted(unclassified)}. "
        "Register each as a backend (deciding all seven invariants for it) or "
        "exclude it with a reason. An undeclared export is one nobody decided "
        "the invariants for."
    )


@pytest.mark.parametrize("surface", SURFACES, ids=[s["id"] for s in SURFACES])
def test_exclusions_are_justified(surface: dict) -> None:
    """An exemption list with no reasons is where a gate goes to quietly die.

    Same rule as not_corpora_reasons in runners.v0.json: the cheapest way to
    defeat this gate is to move an inconvenient backend into the exclusion list,
    so an exclusion has to argue for itself.
    """
    for name, reason in _excluded(surface).items():
        assert reason and len(reason) > 30, (
            f"{surface['id']}/{name}: exclusion reason is too thin to audit ({reason!r})"
        )


@pytest.mark.parametrize("surface", SURFACES, ids=[s["id"] for s in SURFACES])
def test_exclusions_still_exist(surface: dict) -> None:
    """Stale exclusions hide the fact that a real export went away."""
    stale = set(_excluded(surface)) - _extract(surface)
    assert not stale, (
        f"{surface['id']}: excluded symbols no longer exported: {sorted(stale)}"
    )


@pytest.mark.parametrize("surface", SURFACES, ids=[s["id"] for s in SURFACES])
def test_no_registered_backend_missing_from_source(surface: dict) -> None:
    """The registry must not name things that no longer exist."""
    stale = _registered(surface) - _extract(surface)
    assert not stale, (
        f"{surface['id']}: registered but absent from source: {sorted(stale)}"
    )


@pytest.mark.parametrize("surface", SURFACES, ids=[s["id"] for s in SURFACES])
def test_cross_language_asymmetry_is_declared(surface: dict) -> None:
    """A backend in one SDK and not the other must say why.

    Undeclared asymmetry is how two SDKs stop being the same product without
    anyone noticing. See INV-7, where exactly that had already happened.
    """
    for b in surface["backends"]:
        if b["python"] is None or b.get("node") is None:
            assert b.get("asymmetry_reason"), (
                f"{surface['id']}/{b['id']}: present in one SDK only, with no "
                "asymmetry_reason. Declare it or make it symmetric."
            )


def test_invariant_ids_match_the_declaration() -> None:
    """The product must be over the REAL invariant set, not a private copy.

    Cross-review round 2 (cursor, P1): `backends.invariant_ids` was an
    independent list. Deleting an entry from it deleted every cell obligation
    for that invariant, and adding INV-8 to invariants.v0.json would leave the
    matrix silently unaware of it. A product taken over a copy of the axis is
    not the product.
    """
    declared = [
        i["id"]
        for i in json.loads((CONFORMANCE / "invariants.v0.json").read_text())[
            "invariants"
        ]
    ]
    assert INVARIANT_IDS == declared, (
        "backends.v0.json invariant_ids has drifted from invariants.v0.json:\n"
        f"  registry:    {INVARIANT_IDS}\n  declaration: {declared}"
    )


def test_every_backend_has_a_coverage_row() -> None:
    declared = {b["id"] for s in SURFACES for b in s["backends"]}
    missing = declared - set(COVERAGE)
    assert not missing, f"backends with no coverage row: {sorted(missing)}"
    stale = set(COVERAGE) - declared
    assert not stale, f"coverage rows for unknown backends: {sorted(stale)}"


def test_the_product_is_complete() -> None:
    """Every (backend x invariant) cell is declared. This is the 直積.

    A new backend cannot be registered without a decision recorded for all
    seven invariants. 'none' is a valid decision; silence is not.
    """
    for backend, row in COVERAGE.items():
        missing = set(INVARIANT_IDS) - set(row)
        assert not missing, f"{backend}: undeclared invariants {sorted(missing)}"
        for inv_id, cell in row.items():
            assert cell["state"] in CELL_STATES, (
                f"{backend}/{inv_id}: unknown state {cell['state']!r}"
            )
            if cell["state"] != "none":
                assert cell.get("note"), (
                    f"{backend}/{inv_id}: claims {cell['state']} with no note. "
                    "A coverage claim without a stated basis is how a matrix "
                    "becomes decorative."
                )


def test_no_cell_claims_full_yet() -> None:
    """Guards the honesty of the matrix against optimistic editing.

    'full' requires the three enforcement_full_criteria in invariants.v0.json,
    and criterion 3 (holds across all configurations) cannot be met while any
    cell in that backend's row is below full. If this test ever needs deleting,
    that deletion should be a visible, argued act rather than a quiet edit.
    """
    claimed = [
        f"{b}/{i}"
        for b, row in COVERAGE.items()
        for i, c in row.items()
        if c["state"] == "full"
    ]
    assert not claimed, (
        f"cells claiming 'full': {claimed}. Verify against enforcement_full_criteria "
        "and remove this test deliberately, with the evidence, if the claim is real."
    )
