"""Malformed 200 response fail-secure tests (T-157, S023 Phase 4 Build).

Closes cursor CU4 finding: aegis-core returns HTTP 200 with a body shape
that differs from the OpenAPI contract (schema drift, proxy rewrite, bug).
Without strict validation, KeyError / TypeError propagates through the call
stack unpredictably. AO-002 (ゼロ漏洩) requires a deterministic fail-closed
empty result on any schema violation.
"""

from __future__ import annotations

import httpx
import pytest

from aegis_trust import shield
from aegis_trust.client import AegisClient
from aegis_trust.shield import reset
from aegis_trust.types import IngestEntry


@pytest.fixture(autouse=True)
def _full_env(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "full")
    monkeypatch.setenv("AEGIS_URL", "https://localhost:8443/api/v1")
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")
    yield
    reset()


# ── _parse_ingest_body unit tests ────────────────────────────────────


def test_valid_body_parses():
    resp = AegisClient._parse_ingest_body(
        {
            "success": True,
            "data": {"ingested": 1, "audit_seq_start": 5, "audit_seq_end": 7},
        }
    )
    assert resp.ingested == 1
    assert resp.audit_seq_start == 5
    assert resp.audit_seq_end == 7


@pytest.mark.parametrize(
    "body",
    [
        None,
        "not a dict",
        42,
        [],
        {},
        {"data": None},
        {"data": "not a dict"},
        {"data": {}},
        {"data": {"ingested": "one"}},
        {"data": {"ingested": -1, "audit_seq_start": 1, "audit_seq_end": 1}},
        {"data": {"ingested": 1, "audit_seq_start": -1, "audit_seq_end": 1}},
        {
            "data": {"ingested": 1, "audit_seq_start": 5, "audit_seq_end": 3}
        },  # non-monotonic
        {"data": {"ingested": 1, "audit_seq_start": None, "audit_seq_end": 1}},
    ],
)
def test_malformed_raises_valueerror(body):
    with pytest.raises(ValueError):
        AegisClient._parse_ingest_body(body)


# ── @shield end-to-end ───────────────────────────────────────────────


def _transport_with_body(body):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        if path.endswith("/shield/ingest"):
            return httpx.Response(200, json=body)
        if path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_shield_fails_closed_on_malformed_success():
    """Backend returns HTTP 200 with unexpected shape → @shield returns {}."""
    from aegis_trust.shield import _get_client

    client = _get_client()
    client._httpx = httpx.Client(
        base_url=client._base_url,
        transport=_transport_with_body({"unexpected": "shape"}),
        headers={},
        timeout=httpx.Timeout(10.0),
    )

    @shield(purpose="support", scope=["name"])
    def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = get_record()
    assert result == {}


def test_shield_fails_closed_on_non_monotonic_seq():
    from aegis_trust.shield import _get_client

    client = _get_client()
    client._httpx = httpx.Client(
        base_url=client._base_url,
        transport=_transport_with_body(
            {"data": {"ingested": 1, "audit_seq_start": 10, "audit_seq_end": 5}}
        ),
        headers={},
        timeout=httpx.Timeout(10.0),
    )

    @shield(purpose="support", scope=["name"])
    def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = get_record()
    assert result == {}


def test_ingest_public_api_raises_on_malformed():
    """AegisClient.ingest() should raise ValueError so callers can distinguish
    transport vs schema errors. The @shield wrapper catches all exceptions.
    """
    client = AegisClient()
    client._httpx = httpx.Client(
        base_url=client._base_url,
        transport=_transport_with_body({"wrong": "shape"}),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    with pytest.raises(ValueError):
        client.ingest(
            [
                IngestEntry(
                    function="f",
                    purpose="p",
                    scope=["s"],
                    blocked_fields=[],
                    timestamp="2026-04-14T00:00:00Z",
                )
            ]
        )


# ── S017 H10: partial / zero durable acceptance must fail closed ──────


def test_shield_fails_closed_on_partial_ingest():
    """S017 H10: a contract-valid 200 with `ingested: 0` (gateway durably
    committed ZERO of the entries sent) is a partial acceptance — the audit
    record never landed, so FULL mode must NOT release the filtered data. It
    previously parsed as success (`ingested >= 0`) and released = fail-OPEN.
    """
    from aegis_trust.shield import _get_client

    client = _get_client()
    client._httpx = httpx.Client(
        base_url=client._base_url,
        transport=_transport_with_body(
            {"data": {"ingested": 0, "audit_seq_start": 0, "audit_seq_end": 0}}
        ),
        headers={},
        timeout=httpx.Timeout(10.0),
    )

    @shield(purpose="support", scope=["name"])
    def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    assert get_record() == {}


def test_ingest_public_api_raises_on_partial_acceptance():
    """AegisClient.ingest() raises when fewer entries were durably accepted than
    were sent (audit incomplete), so the FULL gate fails closed."""
    client = AegisClient()
    client._httpx = httpx.Client(
        base_url=client._base_url,
        transport=_transport_with_body(
            {"data": {"ingested": 0, "audit_seq_start": 0, "audit_seq_end": 0}}
        ),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    with pytest.raises(ValueError, match="partial acceptance"):
        client.ingest(
            [
                IngestEntry(
                    function="f",
                    purpose="p",
                    scope=["s"],
                    blocked_fields=[],
                    timestamp="2026-04-14T00:00:00Z",
                )
            ]
        )
