"""Cross-SDK A2A reducer conformance — Python runner.

Executes ``conformance/a2a_reducer.v0.json`` through the SHIPPED reducer and
authorization-request builder. The Node SDK runs the same corpus through its
shipped equivalents. Obligations are compared as (correlation_id, generation,
state) sets; rejected events as ordered (index, code) lists.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aegis_trust.a2a.extension import assert_no_enforcement_claim
from aegis_trust.a2a.privacy import validate_decision_substate
from aegis_trust.a2a.reducer import (
    A2AReducerError,
    build_authorization_request,
    build_obligation_status_update,
    reduce_task_state,
)

CORPUS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "conformance" / "a2a_reducer.v0.json"
    ).read_text(encoding="utf-8")
)


def _run_trace(vector: dict[str, Any]):
    return reduce_task_state(
        task_id=vector["task_id"],
        context_id=vector["context_id"],
        events=vector["events"],
        prior_state=vector.get("prior_state"),
        prior_obligations=vector.get("prior_obligations", ()),
        prior_unresolved_halt=vector.get("prior_unresolved_halt"),
    )


def _obligation_view(obligations) -> list[tuple[str, int, str]]:
    return sorted(
        (o["key"]["correlation_id"], o["key"]["generation"], o["state"])
        for o in obligations
    )


def test_corpus_version_pinned() -> None:
    assert CORPUS["version"] == "v0"


@pytest.mark.parametrize("vector", CORPUS["traces"], ids=lambda v: v["id"])
def test_trace(vector: dict[str, Any]) -> None:
    result = _run_trace(vector)
    assert result.task_state == vector["expect"]["task_state"], vector["why"]
    assert _obligation_view(result.obligations) == sorted(
        (o["correlation_id"], o["generation"], o["state"])
        for o in vector["expect"]["obligations"]
    ), vector["why"]
    assert [(r.index, r.code) for r in result.rejected_events] == [
        (r["index"], r["code"]) for r in vector["expect"]["rejected"]
    ], vector["why"]
    if "unresolved_halt" in vector["expect"]:
        assert result.unresolved_halt == vector["expect"]["unresolved_halt"], vector[
            "why"
        ]


def test_commuting_permutation_pairs_reduce_identically() -> None:
    pairs = [v for v in CORPUS["traces"] if "permutation_of" in v]
    assert pairs, "corpus must contain at least one permutation pair"
    by_id = {v["id"]: v for v in CORPUS["traces"]}
    for vector in pairs:
        original = by_id[vector["permutation_of"]]
        a = _run_trace(original)
        b = _run_trace(vector)
        assert b.task_state == a.task_state
        assert _obligation_view(b.obligations) == _obligation_view(a.obligations)
        assert b.rejected_events == a.rejected_events


@pytest.mark.parametrize("vector", CORPUS["input_errors"], ids=lambda v: v["id"])
def test_input_error(vector: dict[str, Any]) -> None:
    inp = vector["input"]
    with pytest.raises(A2AReducerError) as excinfo:
        reduce_task_state(
            task_id=inp.get("task_id", ""),
            context_id=inp.get("context_id", ""),
            events=inp.get("events", ()),
            prior_state=inp.get("prior_state"),
            prior_obligations=inp.get("prior_obligations", ()),
        )
    assert excinfo.value.code == vector["expect_error"], vector["why"]


@pytest.mark.parametrize(
    "vector", CORPUS["authorization_request"], ids=lambda v: v["id"]
)
def test_authorization_request(vector: dict[str, Any]) -> None:
    if "expect_error" in vector:
        with pytest.raises(A2AReducerError) as excinfo:
            build_authorization_request(
                key=vector["key"],
                approver_role=vector["approver_role"],
                approver_roles=vector["approver_roles"],
            )
        assert excinfo.value.code == vector["expect_error"], vector["why"]
        return
    request = build_authorization_request(
        key=vector["key"],
        approver_role=vector["approver_role"],
        approver_roles=vector["approver_roles"],
    )
    expected = vector["expect"]
    assert request.task_state == expected["task_state"]
    assert dict(request.substate) == expected["substate"]
    for fragment in expected["message_contains"]:
        assert fragment in request.status_message, vector["why"]
    # Producer-side capability material (server nonce, request digest) must
    # never reach the client-visible surface: the nonce is what makes a
    # pre-played credential unable to name the obligation.
    client_visible = request.status_message + json.dumps(dict(request.substate))
    for secret in expected.get("message_and_substate_omit", ()):
        assert secret not in client_visible, vector["why"]
    # The builder's output satisfies the same law as everyone else's: honesty
    # guard over the message, privacy validator over the substate.
    assert_no_enforcement_claim(
        request.status_message, f"authorization_request:{vector['id']}"
    )
    validate_decision_substate(
        request.substate, approver_roles=vector["approver_roles"]
    )


@pytest.mark.parametrize(
    "vector", CORPUS["obligation_status_update"], ids=lambda v: v["id"]
)
def test_obligation_status_update(vector: dict[str, Any]) -> None:
    if "expect_error" in vector:
        with pytest.raises(A2AReducerError) as excinfo:
            build_obligation_status_update(vector["key"], vector["status"])
        assert excinfo.value.code == vector["expect_error"], vector["why"]
        return
    substate = build_obligation_status_update(vector["key"], vector["status"])
    expected = vector["expect"]
    assert substate == expected["substate"], vector["why"]
    # Wire-visible closure must not leak producer-side capability material,
    # and must pass the same validator every substate passes.
    serialized = json.dumps(substate)
    for secret in expected["omit"]:
        assert secret not in serialized, vector["why"]
    validate_decision_substate(substate)
