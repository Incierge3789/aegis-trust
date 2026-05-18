"""Per-call audit inclusion proof tests (T-154 + T-140, S023 Phase 4 Build).

Closes consensus finding CS2 from S023 Phase 3 cross-review (codex + cursor):
calling /audit/verify alone does not prove "this SDK call landed in the
chain". The SDK now retains the highest seq returned by /shield/ingest and
verify_inclusion() asserts both chain validity AND that total_entries
covers our high-water mark.

This is the SDK-side AO-004 (監査完全性) per-call non-repudiation gate.
"""

from __future__ import annotations

import httpx
import pytest

from aegis_trust.client import AegisClient
from aegis_trust.shield import reset
from aegis_trust.types import AuditChainStatus, IngestEntry


@pytest.fixture(autouse=True)
def _reset():
    reset()
    yield
    reset()


def _entry(seq: int = 1) -> IngestEntry:
    return IngestEntry(
        function="get_record",
        purpose="support",
        scope=["name"],
        blocked_fields=["ssn"],
        timestamp="2026-04-14T00:00:00Z",
    )


def _client_with(handler) -> AegisClient:
    c = AegisClient(token="dev")
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers=c._auth_headers(),
        timeout=httpx.Timeout(5.0),
    )
    return c


# ── chain status parser ─────────────────────────────────────────────


def test_parse_chain_body_valid():
    status = AegisClient._parse_chain_body({"chain_valid": True, "total_entries": 42})
    assert status == AuditChainStatus(chain_valid=True, total_entries=42)


@pytest.mark.parametrize(
    "body",
    [
        None,
        "x",
        {},
        {"chain_valid": True},
        {"chain_valid": "true", "total_entries": 1},
        {"chain_valid": True, "total_entries": -1},
        {"chain_valid": True, "total_entries": "many"},
    ],
)
def test_parse_chain_body_malformed(body):
    with pytest.raises(ValueError):
        AegisClient._parse_chain_body(body)


# ── ingest seq tracking ─────────────────────────────────────────────


def test_ingest_records_max_seq():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {
                    "ingested": 1,
                    "audit_seq_start": 7,
                    "audit_seq_end": 7,
                },
            },
        )

    c = _client_with(handler)
    assert c._max_audit_seq == 0
    c.ingest([_entry()])
    assert c._max_audit_seq == 7
    c.ingest([_entry()])  # response repeats seq 7 — should not regress
    assert c._max_audit_seq == 7


def test_ingest_advances_max_seq_on_higher_response():
    seq_box = [3]

    def handler(request: httpx.Request) -> httpx.Response:
        seq = seq_box[0]
        seq_box[0] += 5
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {
                    "ingested": 1,
                    "audit_seq_start": seq,
                    "audit_seq_end": seq + 4,
                },
            },
        )

    c = _client_with(handler)
    c.ingest([_entry()])
    assert c._max_audit_seq == 7
    c.ingest([_entry()])
    assert c._max_audit_seq == 12


# ── verify_inclusion ─────────────────────────────────────────────────


def test_verify_inclusion_returns_true_when_chain_covers_seq():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/shield/ingest"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "ingested": 1,
                        "audit_seq_start": 10,
                        "audit_seq_end": 10,
                    },
                },
            )
        if path.endswith("/audit/verify"):
            return httpx.Response(200, json={"chain_valid": True, "total_entries": 12})
        return httpx.Response(404)

    c = _client_with(handler)
    c.ingest([_entry()])
    assert c.verify_inclusion() is True


def test_verify_inclusion_false_when_chain_invalid():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/shield/ingest"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "ingested": 1,
                        "audit_seq_start": 5,
                        "audit_seq_end": 5,
                    },
                },
            )
        if path.endswith("/audit/verify"):
            return httpx.Response(
                200, json={"chain_valid": False, "total_entries": 100}
            )
        return httpx.Response(404)

    c = _client_with(handler)
    c.ingest([_entry()])
    assert c.verify_inclusion() is False


def test_verify_inclusion_false_when_chain_too_short():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/shield/ingest"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "ingested": 1,
                        "audit_seq_start": 50,
                        "audit_seq_end": 50,
                    },
                },
            )
        if path.endswith("/audit/verify"):
            return httpx.Response(200, json={"chain_valid": True, "total_entries": 49})
        return httpx.Response(404)

    c = _client_with(handler)
    c.ingest([_entry()])
    assert c.verify_inclusion() is False


def test_verify_inclusion_false_when_no_seq_seen():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    c = _client_with(handler)
    assert c.verify_inclusion() is False


def test_verify_inclusion_explicit_seq():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/audit/verify"):
            return httpx.Response(200, json={"chain_valid": True, "total_entries": 30})
        return httpx.Response(404)

    c = _client_with(handler)
    assert c.verify_inclusion(seq_end=25) is True
    assert c.verify_inclusion(seq_end=31) is False


def test_verify_inclusion_fails_closed_on_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/audit/verify"):
            return httpx.Response(503)
        return httpx.Response(404)

    c = _client_with(handler)
    c._max_audit_seq = 5
    assert c.verify_inclusion() is False
