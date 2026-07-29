"""INV-4 — the same input yields the same decision across versions (Python runner).

The other corpora establish that the two SDKs agree with EACH OTHER at one point
in time. Neither says anything about whether this release agrees with the last
one. The customer's question is not "do your two SDKs match" but "will the answer
I got last month still be the answer next month", and that is a different
property. Attaching filter_parity to INV-4 was refused for exactly this reason.

WHAT THIS PROVES TODAY: nothing. The golden values were recorded from the current
build, so replaying them against the current build is circular. The property
becomes real at the first release after 0.9.3 that replays this file unchanged.
Saying so is more important than the file: a snapshot that gets regenerated
whenever it fails looks like cross-version evidence while being a mirror.

WHEN A REPLAY FAILS, the first assumption is that the IMPLEMENTATION regressed --
not that the snapshot is stale. Regenerating the file to make CI green is the
failure mode this exists to prevent.

Mirror: node/tests/goldenDecisions.test.ts (same file, shipped Node functions).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_trust import wrap
from aegis_trust.doctor import ActionPlan, LocalPolicy, check

REPO = Path(__file__).resolve().parents[2]
GOLDEN = REPO / "conformance" / "golden_decisions.v0.json"

_DOC = json.loads(GOLDEN.read_text())
assert _DOC["version"] == 0
ENTRIES = _DOC["entries"]
WRAP_ENTRIES = [e for e in ENTRIES if e["surface"] == "wrap"]
DOCTOR_ENTRIES = [e for e in ENTRIES if e["surface"] == "doctor.check"]


def test_snapshot_is_non_vacuous() -> None:
    """A golden file with nothing in it passes every replay."""
    assert len(ENTRIES) >= 10, (
        f"only {len(ENTRIES)} entries — the snapshot is too thin to mean anything"
    )
    assert WRAP_ENTRIES, "no wrap entries"
    assert DOCTOR_ENTRIES, "no doctor entries"
    assert _DOC["recorded_against"], (
        "no version recorded — the snapshot is not bound to a release"
    )


def test_every_entry_declares_the_version_it_entered_at() -> None:
    """Without `since`, a replay failure cannot be attributed to a release."""
    for e in ENTRIES:
        assert e.get("since"), f"{e['id']}: no `since` version"


@pytest.mark.parametrize("entry", WRAP_ENTRIES, ids=[e["id"] for e in WRAP_ENTRIES])
def test_wrap_decision_is_unchanged(entry: dict) -> None:
    """Replay a recorded wrap() decision against the shipped implementation."""
    spec = entry["input"]
    result = wrap(
        spec["data"],
        purpose=spec["purpose"],
        scope=spec.get("scope"),
        deny_fields=spec.get("deny_fields"),
    )
    assert result.data == entry["expected"]["data"], (
        f"{entry['id']}: the decision changed since {entry['since']}.\n"
        f"  recorded: {entry['expected']['data']}\n  now:      {result.data}\n"
        "Assume the implementation regressed before assuming the snapshot is stale. "
        "If the change is intended, add a breaking_changes entry naming the version "
        "and the reason — do not regenerate this file to make CI green."
    )
    assert sorted(result.filtered_keys) == entry["expected"]["filtered_keys"], (
        f"{entry['id']}: filtered_keys changed since {entry['since']}"
    )


@pytest.mark.parametrize("entry", DOCTOR_ENTRIES, ids=[e["id"] for e in DOCTOR_ENTRIES])
def test_doctor_decision_is_unchanged(entry: dict) -> None:
    """Replay a recorded boundary decision against the shipped implementation."""
    spec = entry["input"]
    policy = LocalPolicy(**spec["policy"]) if spec.get("policy") else None
    decision = check(ActionPlan(**spec["plan"]), policy)
    got = {
        "outcome": decision.outcome.value,
        "allowed_data": sorted(decision.allowed_data),
        "blocked_data": sorted(decision.blocked_data),
        "reason_codes": sorted(decision.reason_codes),
        "receipt_required": decision.receipt_required,
    }
    assert got == entry["expected"], (
        f"{entry['id']}: the boundary decision changed since {entry['since']}.\n"
        f"  recorded: {entry['expected']}\n  now:      {got}\n"
        "A changed boundary decision is a changed product promise. If intended, "
        "record it in breaking_changes with the version and the reason."
    )


def test_breaking_changes_are_documented() -> None:
    """Every recorded break must name a version and a reason.

    The list is empty today. It is checked anyway, so the first entry cannot be
    added as a bare marker to silence a failing replay.
    """
    for bc in _DOC["breaking_changes"]:
        assert bc.get("version"), f"breaking change with no version: {bc}"
        assert bc.get("entry_id"), f"breaking change with no entry_id: {bc}"
        assert len(bc.get("reason", "")) > 30, (
            f"{bc.get('entry_id')}: reason too thin to audit — a breaking change to "
            "a boundary decision needs an argument, not a note"
        )
        assert any(e["id"] == bc["entry_id"] for e in ENTRIES), (
            f"{bc['entry_id']}: breaking change references an entry that does not exist"
        )


def test_honesty_marker_is_present() -> None:
    """The file must keep saying that it proves nothing until a later release replays it.

    If this ever gets quietly dropped, the snapshot starts reading as
    cross-version evidence a year before it is one.
    """
    assert _DOC.get("proves_cross_version_from"), (
        "the snapshot no longer states when it starts being evidence"
    )
    assert "NOTHING" in _DOC["$comment"], (
        "the 'proves nothing today' statement was removed from the snapshot's own comment"
    )
