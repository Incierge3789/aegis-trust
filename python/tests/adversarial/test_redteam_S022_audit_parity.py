"""S022 A11/T-950: `_diff_keys` / `_collect_removed` audit parity.

Attack surface: shield.py:710-725 `_collect_removed` walks only
``isinstance(original, dict)`` and ``isinstance(original, list)``. After
R1 container generalization (deque / set / frozenset / generator / etc.
fail-closed dropped), the audit trail diff must ALSO walk those
containers or the audit record will under-report removed fields — an
attacker who notices the gap gains a "quiet removal" channel.

Plan Review R4: promote this from Tier 2 → Tier 1. Audit parity is
release-blocking given the red-team objective.

This runs against Lite mode by default (AEGIS_MODE=lite). Full-mode
audit POST-body parity is T-952 (separate file).
"""

from __future__ import annotations

from collections import deque

from aegis_trust import shield
from aegis_trust.shield import _diff_keys


def test_diff_keys_reports_removed_ssn_from_list():
    """Baseline: list path audits correctly (regression of S021 fix)."""
    original = {"users": [{"name": "T", "ssn": "x"}]}
    filtered = {"users": [{"name": "T"}]}
    removed = _diff_keys(original, filtered)
    assert any("ssn" in r for r in removed), f"S021 regression: {removed!r}"


def test_diff_keys_reports_removed_from_tuple():
    """A11/R4: tuple path audit must report removed fields.

    Pre-R4: tuple at line 721 `isinstance(original[k], list)` miss.
    Post-R4: container generalization covers tuple.
    """
    original = {"users": ({"name": "T", "ssn": "x"},)}
    filtered = {"users": ({"name": "T"},)}
    removed = _diff_keys(original, filtered)
    # Audit trail MUST record ssn removal even through tuple container
    assert any("ssn" in r for r in removed), (
        f"A11/R4: tuple audit under-reports: {removed!r}"
    )


def test_diff_keys_reports_removed_from_deque():
    """A11/R4: deque path audit — post-R4 must report."""
    original = {"users": deque([{"name": "T", "ssn": "x"}])}
    filtered = {"users": deque([{"name": "T"}])}
    removed = _diff_keys(original, filtered)
    assert any("ssn" in r for r in removed), (
        f"A11/R4: deque audit under-reports: {removed!r}"
    )


def test_diff_keys_reports_removed_through_generator():
    """S022 Review CR-1: single-pass iterable (generator) must be frozen
    at shield entry so audit diff can re-read the structure and report
    removed fields. Pre-fix, filtering consumed the generator and the
    diff re-iterated an exhausted iterator → 0 removals reported.
    """

    def _gen():
        yield {"name": "T", "ssn": "x"}

    @shield(purpose="support", scope=["users.name"])
    def get():
        return {"users": _gen()}

    # Run the shielded function so audit writes go through the shield
    # entry path (where the freeze happens).
    result = get()
    # Filter produced the correct dict …
    assert result == {"users": [{"name": "T"}]}

    # … AND the module-level audit hook captured "users.ssn" as removed.
    # Validate indirectly by re-running _diff_keys with the same freeze
    # applied (mirrors what _shield_lite does internally).
    from aegis_trust.shield import _freeze_single_pass

    original = _freeze_single_pass({"users": _gen()})
    filtered = {"users": [{"name": "T"}]}
    removed = _diff_keys(original, filtered)
    assert any("ssn" in r for r in removed), (
        f"CR-1: generator-backed audit under-reports: {removed!r}"
    )


def test_collect_removed_handles_fail_closed_drop():
    """A11/R4: when a key is dropped entirely (fail-closed), the audit
    must record the key-level removal, not silently under-report."""
    original = {"users": [{"name": "T", "ssn": "x"}], "other": "kept"}
    filtered = {"other": "kept"}  # users dropped fail-closed
    removed = _diff_keys(original, filtered)
    assert any("users" in r for r in removed), (
        f"A11/R4: key-drop not in audit: {removed!r}"
    )
