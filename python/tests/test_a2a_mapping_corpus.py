"""Cross-SDK A2A decision→TaskState mapping conformance — Python runner.

Executes the shared corpus (``conformance/a2a_mapping.v0.json``) through the
Python SDK's shipped ``map_decision_to_a2a``. The Node SDK runs the SAME corpus
(``node/tests/a2aMappingCorpus.test.ts``) through its shipped
``mapDecisionToA2A``. Two implementations agreeing with each other proves
nothing if both are wrong; both agreeing with one normative corpus is the claim
worth making.

The corpus also declares ``legal_pairs``, so "a legal pair is missing from the
corpus" is itself detectable — a corpus that quietly omitted
``BLOCKED/internal_failure`` would otherwise let a wrong mapping for that pair
ship while every vector stayed green.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_trust.a2a.mapping import (
    LEGAL_OUTCOME_REASON_PAIRS,
    A2AMappingError,
    map_decision_to_a2a,
    validate_outcome_reason,
)

CORPUS = Path(__file__).resolve().parents[2] / "conformance" / "a2a_mapping.v0.json"

_DATA = json.loads(CORPUS.read_text())

OUTCOMES = (
    "PROTECTED",
    "ACCESS_REDUCED",
    "CHECK_REQUIRED",
    "APPROVAL_REQUIRED",
    "BLOCKED",
)
REASONS = (
    "minimum_disclosure",
    "policy_denied",
    "approval_required",
    "check_required",
    "invalid_scope",
    "internal_failure",
)


def test_corpus_version_is_pinned() -> None:
    assert _DATA["version"] == "v0"


@pytest.mark.parametrize("entry", _DATA["entries"], ids=lambda e: e["id"])
def test_positive_vector(entry: dict) -> None:
    result = map_decision_to_a2a(entry["decision"])
    assert (
        result.task_state_recommendation == entry["expect"]["task_state_recommendation"]
    )
    assert result.halts_task == entry["expect"]["halts_task"]
    # Exact equality both ways: an extra substate field is a leak, a missing one
    # is a dropped signal.
    assert dict(result.substate) == entry["expect"]["substate"]


@pytest.mark.parametrize("entry", _DATA["negative_entries"], ids=lambda e: e["id"])
def test_negative_vector(entry: dict) -> None:
    with pytest.raises(A2AMappingError) as excinfo:
        map_decision_to_a2a(entry["decision"])
    err = excinfo.value
    assert err.code == entry["expect_error"]
    # Machine-parseable error contract: agents route on code and need a
    # remediation, not a free-text guess.
    assert err.remediation
    assert entry["expect_error"] in err.docs_url


def test_corpus_covers_every_declared_legal_pair() -> None:
    covered = {
        f"{e['decision'].get('outcome')} {e['decision'].get('reason_code')}"
        for e in _DATA["entries"]
    }
    declared = {f"{o} {r}" for o, r in _DATA["legal_pairs"]}
    assert declared - covered == set()


def test_corpus_legal_pairs_match_the_shipped_mapping() -> None:
    from_corpus = {f"{o} {r}" for o, r in _DATA["legal_pairs"]}
    from_code = {f"{o} {r}" for o, r in LEGAL_OUTCOME_REASON_PAIRS}
    assert from_corpus == from_code


def test_every_illegal_pair_is_refused() -> None:
    legal = {f"{o} {r}" for o, r in LEGAL_OUTCOME_REASON_PAIRS}
    checked = 0
    for outcome in OUTCOMES:
        for reason in REASONS:
            if f"{outcome} {reason}" in legal:
                continue
            checked += 1
            with pytest.raises(A2AMappingError):
                validate_outcome_reason(outcome, reason)
    # 5x6 = 30 combinations, 7 legal → 23 must be refused. If this count drifts,
    # the legal set changed and the mapping table must be re-derived from the
    # decision engine, not patched here.
    assert checked == 23
