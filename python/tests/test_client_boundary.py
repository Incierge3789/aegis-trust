"""Client tests for the /check-access scope contract fix (CSR-03) and the
Doctor v1 /check-boundary request/response plumbing.
"""

from __future__ import annotations

import json

import httpx
import pytest

from aegis_trust.client import AegisClient


def _client_with_transport(handler) -> AegisClient:
    c = AegisClient(base_url="https://localhost:8443/api/v1", verify_ssl=False)
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    return c


# ── /check-access scope contract (CSR-03 fix) ───────────────


def test_check_access_single_scope_sent_as_string():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    c.check_access("p", ["name"])
    assert captured["body"]["purpose"] == "p"
    # Single string, NOT an array — matches server Option<String>.
    assert captured["body"]["scope"] == "name"


def test_check_access_always_sends_required_tool_name():
    # The gateway's CheckAccessRequest requires a non-Option `tool_name`. Omit
    # it and the body is 422 → every FULL authorize fail-closes, so a FULL gate
    # can never grant against a live gateway (S015 live bug). Pin that the field
    # is always present with the default placeholder.
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    c.check_access("p", ["name"])
    assert captured["body"]["tool_name"] == "shielded_call"


def test_check_access_empty_scope_omits_field():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    c.check_access("p", [])
    assert "scope" not in captured["body"]


def test_authorize_multi_scope_fails_closed():
    # Review finding B: a >1-scope authorize must DENY without even sending a
    # request — dropping to purpose-level could let the single-scope server
    # ALLOW more than the caller asked for (fail-open regression).
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json={"allowed": True})

    c = _client_with_transport(handler)
    assert c.authorize("p", ["name", "issue"]) is False
    # No request was issued at all.
    assert called["n"] == 0


def test_check_access_body_omits_scope_for_multi_scope():
    # The body builder still omits scope for >1 (defensive), but the gate path
    # never reaches it because authorize() denies first.
    body = AegisClient._check_access_body("p", ["name", "issue"])
    assert "scope" not in body
    assert body["purpose"] == "p"


# ── /check-boundary (Doctor v1) ─────────────────────────────


def test_check_boundary_posts_array_scope_and_snake_cases_fields():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": ["name"],
                "withheld_fields": [],
                "reason_code": "minimum_disclosure",
                "reason_label": "Minimum disclosure",
                "evidence_available": True,
                "evidence": None,
            },
        )

    c = _client_with_transport(handler)
    view = c.check_boundary(
        "p",
        ["name", "issue"],
        destination="external_llm",
        agent_id="agent-7",
        environment="prod",
        mode="full",
        schema_version=1,
    )
    assert captured["path"].endswith("/check-boundary")
    body = captured["body"]
    assert body["scope"] == ["name", "issue"]
    assert body["destination"] == "external_llm"
    assert body["agent_id"] == "agent-7"
    assert body["environment"] == "prod"
    assert body["mode"] == "full"
    assert body["schema_version"] == 1
    assert "principal" not in body
    assert view.outcome == "PROTECTED"
    assert view.allowed_fields == ["name"]


def test_check_boundary_raises_on_non_2xx():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="nope")

    c = _client_with_transport(handler)
    with pytest.raises(httpx.HTTPStatusError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_malformed_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"source": "CORE"})  # no outcome

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_partial_body_with_outcome_only():
    # Finding A: a partial-but-valid-JSON body with only outcome present must
    # NOT parse to a trusted view (it would otherwise map PROTECTED -> ALLOW).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"outcome": "PROTECTED"})

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_missing_source():
    # Finding A: source is a required field.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": [],
                "withheld_fields": [],
                "reason_code": "x",
            },
        )

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_missing_reason_code():
    # Finding A: reason_code is a required field.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "allowed_fields": [],
                "withheld_fields": [],
            },
        )

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])


def test_check_boundary_raises_on_missing_allowed_fields():
    # Finding A: allowed_fields is now REQUIRED (no default-to-empty).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "source": "CORE",
                "outcome": "PROTECTED",
                "purpose_label": "p",
                "withheld_fields": [],
                "reason_code": "x",
            },
        )

    c = _client_with_transport(handler)
    with pytest.raises(ValueError):
        c.check_boundary("p", ["name"])
