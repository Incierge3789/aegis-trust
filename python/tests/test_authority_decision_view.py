"""AI-native ``decision`` reader — behaviour beyond the shared corpus.

The corpus (test_authority_decision_view_corpus.py) pins shape acceptance and
refusal. This file pins how the reader sits in the client: it reads the
``decision`` member of a real ``tool_call`` / ``stream_open`` body, the view
is decoupled from the input, and the flat ``check_boundary`` view is NOT
where these members live (so nothing there pretends to carry them).
"""

from __future__ import annotations

import copy
import dataclasses
import json

import httpx
import pytest

from aegis_trust.client import (
    AUTHORITY_OUTCOMES,
    AegisClient,
    AuthorityDecisionView,
    BoundaryDecisionView,
    parse_authority_decision,
)

CORPUS_PATH = "conformance/authority_decision_view.v0.json"


def _full_decision() -> dict:
    from pathlib import Path

    corpus = json.loads(
        (Path(__file__).resolve().parents[2] / CORPUS_PATH).read_text(encoding="utf-8")
    )
    return copy.deepcopy(corpus["valid"][0]["decision"])


def _client_with_transport(handler) -> AegisClient:
    c = AegisClient(base_url="https://localhost:8443/api/v1", verify_ssl=False)
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    return c


def test_reads_the_decision_member_of_a_tool_call_body() -> None:
    decision = _full_decision()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": decision, "enforcement": None})

    body = _client_with_transport(handler).tool_call(
        "query_business_data", "customer_data", "acme"
    )
    view = parse_authority_decision(body["decision"])
    assert view.fragment_tags == ("pii:contact", "sensitive:Finance")
    assert [p.boundary for p in view.parts] == ["purpose", "data"]
    assert view.decision_id == "hashchain:0000042"
    assert view.ledgered is True
    # The existing floor (tool_allowed) and the reader agree on the gate bits.
    assert view.outcome in AegisClient.PASSING_OUTCOMES


def test_reads_the_decision_member_of_a_stream_open_body() -> None:
    decision = _full_decision()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "decision": decision,
                "enforcement": None,
                "stream": {"stream_id": decision["decision_id"], "status": "open"},
            },
        )

    body = _client_with_transport(handler).stream_open({"purpose": "customer_data"})
    view = parse_authority_decision(body["decision"])
    assert view.receipt_event_id == "hashchain:0000043"
    assert view.parts[1].withheld_fields == ("email",)


def test_view_is_decoupled_from_the_input_object() -> None:
    decision = _full_decision()
    view = parse_authority_decision(decision)
    decision["fragment_tags"].append("injected:later")
    decision["parts"][1]["fragment_tags"].clear()
    decision["allowed_fields"].append("email")
    assert view.fragment_tags == ("pii:contact", "sensitive:Finance")
    assert view.parts[1].fragment_tags == ("pii:contact", "sensitive:Finance")
    assert view.allowed_fields == ("name", "company")


def test_view_is_frozen_all_the_way_down() -> None:
    """frozen=True alone is shallow (a list member could still be appended
    to); the sequences are tuples so the view cannot be altered in place."""
    view = parse_authority_decision(_full_decision())
    with pytest.raises(dataclasses.FrozenInstanceError):
        view.ledgered = False  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        view.parts[0].boundary = "x"  # type: ignore[misc]
    assert isinstance(view.fragment_tags, tuple)
    assert isinstance(view.parts, tuple)
    assert isinstance(view.parts[1].fragment_tags, tuple)
    assert not hasattr(view.fragment_tags, "append")


def test_required_members_have_no_defaults() -> None:
    """A view cannot be fabricated by leaving required members out (only the
    post-freeze / by-design-optional members carry a default)."""
    optional = {
        f.name
        for f in dataclasses.fields(AuthorityDecisionView)
        if f.default is not dataclasses.MISSING
        or f.default_factory is not dataclasses.MISSING  # type: ignore[misc]
    }
    assert optional == {"policy_generation", "policy_digest", "replayed"}
    with pytest.raises(TypeError):
        AuthorityDecisionView(outcome="PROTECTED", ledgered=True)  # type: ignore[call-arg]


def test_policy_generation_number_parity() -> None:
    """JSON has one number type: 3.0 is 3; beyond 2**53-1 both SDKs refuse."""
    base = _full_decision()
    assert (
        parse_authority_decision({**base, "policy_generation": 3.0}).policy_generation
        == 3
    )
    for bad in (2**53, float("nan"), float("inf"), 3.5, -1.0, True):
        with pytest.raises(ValueError, match="policy_generation"):
            parse_authority_decision({**base, "policy_generation": bad})


def test_outcome_vocabulary_matches_the_flat_view_and_the_gate() -> None:
    assert AUTHORITY_OUTCOMES == (
        "PROTECTED",
        "ACCESS_REDUCED",
        "CHECK_REQUIRED",
        "APPROVAL_REQUIRED",
        "BLOCKED",
    )
    assert set(AegisClient.PASSING_OUTCOMES) < set(AUTHORITY_OUTCOMES)


def test_rebinding_the_public_vocabulary_cannot_widen_it(monkeypatch) -> None:
    """The reader validates against a private frozenset captured at import,
    so a caller rebinding ``AUTHORITY_OUTCOMES`` gains nothing (Node parity:
    frozen export + private Set)."""
    import aegis_trust.client as client_mod

    monkeypatch.setattr(
        client_mod, "AUTHORITY_OUTCOMES", (*AUTHORITY_OUTCOMES, "UNKNOWN")
    )
    with pytest.raises(ValueError, match="outcome"):
        parse_authority_decision({**_full_decision(), "outcome": "UNKNOWN"})


def test_list_with_a_stateful_iterator_cannot_smuggle_past_validation() -> None:
    """The snapshot that is validated is the snapshot that is returned: a list
    subclass that yields a clean traversal first and a dirty one second must
    not end up in the view (cross-review round 6, codex)."""

    class Shifty(list):  # type: ignore[type-arg]
        def __init__(self) -> None:
            super().__init__(["safe"])
            self._n = 0

        def __iter__(self):  # type: ignore[no-untyped-def]
            self._n += 1
            return iter(["safe"]) if self._n == 1 else iter([42])

    # withheld_fields: not tied to the winner partial by the composition rule
    view = parse_authority_decision({**_full_decision(), "withheld_fields": Shifty()})
    assert view.withheld_fields == ("safe",)


def test_flat_check_boundary_view_does_not_pretend_to_carry_these_members() -> None:
    """The flat /check-boundary wire never sends fragment_tags / parts; the
    SDK must not grow fields for them there (a field the wire never fills is a
    claim without a source). ledgered / decision_id ARE on that wire, under
    their flat names."""
    flat = {f.name for f in dataclasses.fields(BoundaryDecisionView)}
    assert "fragment_tags" not in flat
    assert "parts" not in flat
    assert "evidence_available" in flat  # == the ledgered bit
    assert "evidence" in flat  # carries decision_id
    ai_native = {f.name for f in dataclasses.fields(AuthorityDecisionView)}
    assert {"fragment_tags", "parts", "ledgered", "decision_id"} <= ai_native
