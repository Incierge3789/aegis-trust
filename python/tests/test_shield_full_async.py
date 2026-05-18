"""Async Full mode tests (T-152, S023 Phase 4 Build).

Verifies the @shield decorator on an async user function uses httpx.AsyncClient
(not sync httpx) when backend is Full mode. This closes codex C4 finding: the
async wrapper previously called _shield_full which blocked the event loop on
sync HTTP I/O, making SLO p95/p99 measurements misleading.
"""

from __future__ import annotations

import asyncio
import time

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


def _async_transport(*, slow_ms: int = 0) -> httpx.AsyncBaseTransport:
    """Mock aegis-core that simulates I/O latency to expose event-loop blocking."""

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if slow_ms:
            await asyncio.sleep(slow_ms / 1000.0)
        if path.endswith("/health"):
            return httpx.Response(200, json={"status": "ok"})
        if path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
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
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _patch_async_client(monkeypatch, transport: httpx.AsyncBaseTransport):
    """Force the module-level client to use our mock AsyncTransport."""
    from aegis_trust.client import AegisClient

    real_init = AegisClient.__init__

    def _init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        # Replace the lazy factory with one that injects our transport
        self._async_httpx = httpx.AsyncClient(
            base_url=self._base_url,
            transport=transport,
            headers={},
            timeout=httpx.Timeout(10.0),
        )

    monkeypatch.setattr(AegisClient, "__init__", _init)


@pytest.mark.asyncio
async def test_async_full_runs_concurrently(monkeypatch):
    """Two @shield async calls with 100ms simulated latency each should finish
    in ~100ms (concurrent on the event loop), not ~200ms (sequential/blocking).
    This proves the async path uses httpx.AsyncClient.
    """
    _patch_async_client(monkeypatch, _async_transport(slow_ms=100))

    @shield(purpose="support", scope=["name"])
    async def get_record(i: int) -> dict:
        return {"name": f"user-{i}", "ssn": "hidden"}

    t0 = time.perf_counter()
    results = await asyncio.gather(get_record(1), get_record(2), get_record(3))
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert all(r == {"name": f"user-{i}"} for i, r in enumerate(results, start=1))
    # Sequential sync httpx would take >= 300ms.
    # Async httpx should finish well under 250ms (100ms + scheduling overhead).
    assert elapsed_ms < 250, (
        f"async Full mode appears to be blocking: {elapsed_ms:.0f}ms for 3 calls "
        f"with 100ms simulated latency each"
    )


@pytest.mark.asyncio
async def test_async_full_filters_and_sends_ingest(monkeypatch):
    seen: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        if path.endswith("/shield/ingest"):
            seen.append(request.read().decode())
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

    _patch_async_client(monkeypatch, httpx.MockTransport(handler))

    @shield(purpose="support", scope=["name"])
    async def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = await get_record()
    assert result == {"name": "alice"}
    assert len(seen) == 1
    assert "ssn" in seen[0]  # blocked_fields recorded


@pytest.mark.asyncio
async def test_async_full_fail_closed_on_ingest_500(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        if path.endswith("/shield/ingest"):
            return httpx.Response(500, json={"error": "internal"})
        return httpx.Response(200, json={"status": "ok"})

    _patch_async_client(monkeypatch, httpx.MockTransport(handler))

    @shield(purpose="support", scope=["name"])
    async def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = await get_record()
    assert result == {}  # fail-closed (dict → {})


@pytest.mark.asyncio
async def test_async_deny_mode_full(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
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
        return httpx.Response(200, json={"status": "ok"})

    _patch_async_client(monkeypatch, httpx.MockTransport(handler))

    @shield(purpose="support", deny_fields=["ssn"])
    async def get_record() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = await get_record()
    assert result == {"name": "alice"}
