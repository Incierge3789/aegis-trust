"""Purpose authorization enforcement tests (T-151, S023 Phase 4 Build).

Verifies @shield calls AegisClient.authorize / aauthorize against the
backend /check-access endpoint before filtering or ingesting. Closes codex
C3 finding: check_access() existed but was never called from the shield
path, degrading AO-003 purpose-driven access to labeling only.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _full_env(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "full")
    monkeypatch.setenv("AEGIS_URL", "https://localhost:8443/api/v1")
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")
    yield
    reset()


def _make_tracking_transport(*, access_status: int = 200):
    """MockTransport that records all requests and uses ``access_status`` for
    /check-access responses.
    """
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append((request.method, path))
        if path.endswith("/check-access"):
            if access_status == 200:
                return httpx.Response(200, json={"allowed": True})
            return httpx.Response(access_status, json={"error": "denied"})
        if path.endswith("/shield/ingest"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "ingested": 1,
                        "audit_seq_start": 1,
                        "audit_seq_end": 1,
                    },
                },
            )
        if path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404)

    return httpx.MockTransport(handler), calls


def _patch_sync_transport(transport: httpx.MockTransport):
    from aegis_trust.shield import _get_client

    client = _get_client()
    client._httpx = httpx.Client(
        base_url=client._base_url,
        transport=transport,
        headers={},
        timeout=httpx.Timeout(10.0),
    )


def _patch_async_transport(monkeypatch, transport: httpx.MockTransport):
    from aegis_trust.client import AegisClient

    real_init = AegisClient.__init__

    def _init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        self._async_httpx = httpx.AsyncClient(
            base_url=self._base_url,
            transport=transport,
            headers={},
            timeout=httpx.Timeout(10.0),
        )

    monkeypatch.setattr(AegisClient, "__init__", _init)


# ── sync path ────────────────────────────────────────────────────────


def test_sync_full_calls_check_access_before_ingest():
    transport, calls = _make_tracking_transport(access_status=200)
    _patch_sync_transport(transport)

    @shield(purpose="support", scope=["name"])
    def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = get_record()
    assert result == {"name": "alice"}
    # /check-access must appear before /shield/ingest
    paths = [p for _, p in calls]
    ca_idx = paths.index("/api/v1/check-access")
    ing_idx = paths.index("/api/v1/shield/ingest")
    assert ca_idx < ing_idx


def test_sync_full_denied_returns_empty_and_skips_ingest():
    transport, calls = _make_tracking_transport(access_status=403)
    _patch_sync_transport(transport)

    @shield(purpose="forbidden", scope=["ssn"])
    def get_record() -> dict:
        return {"ssn": "leaked-if-broken"}

    result = get_record()
    # T-SDK-FULL-GATE-01: fail-closed FULL → wrapped fn never runs → None.
    # (Node parity: wrapped function did not execute, no data shape to mirror.)
    assert result is None
    paths = [p for _, p in calls]
    assert "/api/v1/shield/ingest" not in paths


def test_sync_deny_mode_denied_returns_empty():
    transport, calls = _make_tracking_transport(access_status=403)
    _patch_sync_transport(transport)

    @shield(purpose="forbidden", deny_fields=["ssn"])
    def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = get_record()
    # T-SDK-FULL-GATE-01: fail-closed FULL → wrapped fn never runs → None.
    assert result is None
    paths = [p for _, p in calls]
    assert "/api/v1/shield/ingest" not in paths


def test_sync_full_allow_is_cached():
    """Second call with the same (purpose, scope) should NOT call /check-access again."""
    transport, calls = _make_tracking_transport(access_status=200)
    _patch_sync_transport(transport)

    @shield(purpose="support", scope=["name"])
    def get_record() -> dict:
        return {"name": "alice"}

    get_record()
    get_record()
    ca_count = sum(1 for _, p in calls if p == "/api/v1/check-access")
    assert ca_count == 1


# ── async path ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_full_calls_check_access_before_ingest(monkeypatch):
    transport, calls = _make_tracking_transport(access_status=200)
    _patch_async_transport(monkeypatch, transport)

    @shield(purpose="support", scope=["name"])
    async def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = await get_record()
    assert result == {"name": "alice"}
    paths = [p for _, p in calls]
    ca_idx = paths.index("/api/v1/check-access")
    ing_idx = paths.index("/api/v1/shield/ingest")
    assert ca_idx < ing_idx


@pytest.mark.asyncio
async def test_async_full_denied_returns_empty(monkeypatch):
    transport, calls = _make_tracking_transport(access_status=403)
    _patch_async_transport(monkeypatch, transport)

    @shield(purpose="forbidden", scope=["name"])
    async def get_record() -> dict:
        return {"name": "alice"}

    result = await get_record()
    # T-SDK-FULL-GATE-01: fail-closed FULL → wrapped fn never runs → None.
    assert result is None
    paths = [p for _, p in calls]
    assert "/api/v1/shield/ingest" not in paths


@pytest.mark.asyncio
async def test_async_concurrent_denied_all_empty(monkeypatch):
    transport, calls = _make_tracking_transport(access_status=403)
    _patch_async_transport(monkeypatch, transport)

    @shield(purpose="forbidden", scope=["name"])
    async def get_record(i: int) -> dict:
        return {"name": f"user-{i}"}

    results = await asyncio.gather(get_record(1), get_record(2), get_record(3))
    # T-SDK-FULL-GATE-01: fail-closed FULL → wrapped fn never runs → None.
    assert results == [None, None, None]
    paths = [p for _, p in calls]
    assert "/api/v1/shield/ingest" not in paths
