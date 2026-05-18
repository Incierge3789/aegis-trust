"""Metrics hook tests (T-143, S023 Phase 4 Build).

Closes cursor CU3 finding: the original plan directly embedded
prometheus_client into the SDK, which would pollute every host process's
global registry. T-143 replaces the direct dependency with a pluggable
`set_metrics_hook()` callback — users wire their preferred metrics system
(prometheus, statsd, datadog, …) in their own code.
"""

from __future__ import annotations

import httpx
import pytest

from aegis_trust.client import AegisClient, set_metrics_hook
from aegis_trust.shield import reset
from aegis_trust.types import IngestEntry


@pytest.fixture(autouse=True)
def _reset():
    reset()
    set_metrics_hook(None)
    yield
    set_metrics_hook(None)
    reset()


def _entry() -> IngestEntry:
    return IngestEntry(
        function="f",
        purpose="p",
        scope=["s"],
        blocked_fields=[],
        timestamp="2026-04-14T00:00:00Z",
    )


def _client_with(handler):
    c = AegisClient(token="dev")
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers=c._auth_headers(),
        timeout=httpx.Timeout(5.0),
    )
    return c


def test_hook_receives_endpoint_and_status_on_ingest():
    captured: list[tuple[str, float, int]] = []
    set_metrics_hook(lambda ep, dur, status: captured.append((ep, dur, status)))

    def handler(request: httpx.Request) -> httpx.Response:
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

    _client_with(handler).ingest([_entry()])
    assert len(captured) == 1
    endpoint, duration, status = captured[0]
    assert endpoint == "shield.ingest"
    assert status == 200
    assert duration >= 0


def test_hook_receives_status_on_check_access():
    captured: list[tuple[str, float, int]] = []
    set_metrics_hook(lambda ep, dur, status: captured.append((ep, dur, status)))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "denied"})

    _client_with(handler).authorize("p", ["s"])
    assert len(captured) == 1
    endpoint, _, status = captured[0]
    assert endpoint == "check-access"
    assert status == 403


def test_hook_receives_status_zero_on_transport_error():
    captured: list[tuple[str, float, int]] = []
    set_metrics_hook(lambda ep, dur, status: captured.append((ep, dur, status)))

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    _client_with(handler).authorize("p", ["s"])
    assert len(captured) == 1
    endpoint, _, status = captured[0]
    assert endpoint == "check-access"
    assert status == 0


def test_hook_exception_is_swallowed():
    def explode(*a, **kw):
        raise RuntimeError("bad metric")

    set_metrics_hook(explode)

    def handler(request: httpx.Request) -> httpx.Response:
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

    # Must not raise — instrumentation failure never breaks the data path.
    _client_with(handler).ingest([_entry()])


def test_no_hook_means_zero_overhead_api_surface():
    """When no hook is registered, the path still runs and returns normally."""

    def handler(request: httpx.Request) -> httpx.Response:
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

    resp = _client_with(handler).ingest([_entry()])
    assert resp.audit_seq_end == 5
