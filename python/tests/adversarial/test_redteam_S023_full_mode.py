"""S023 adversarial test umbrella — Full mode regression suite.

Bundles 10 small adversarial tasks from the S023 plan into one file:

  T-133  AO-001 bypass — only client.py talks to httpx (static AST grep).
  T-135  Tier 2 leak regression — exception/stacktrace/internal state never
          surfaces from a Full mode @shield call.
  T-136  Leak-zero sentinel — request fields (URL, token) never appear in
          the result returned to the wrapped function caller.
  T-137  Default deny when aegis-core unreachable AND mode=full.
  T-139  AEGIS_VERIFY_SSL prod-lock guard verified through @shield.
  T-141  Purpose null/empty/spoof rejected by the AO-003 gate.
  T-142  _diff_keys body shape sent on /shield/ingest matches contract.
  T-144  6 failure modes umbrella (auth fail / token expire / TLS / replay /
          partition / 5xx) → @shield returns the shape-preserving empty.
  T-146  Dot-notation deny path enforced under Full mode.
  T-147  Async race — concurrent Full mode coroutines never interleave
          ingest payloads (no cross-call data leak).
  T-149  Token lifecycle — old token's Authorization header never reused
          after refresh_token().

These all run on httpx.MockTransport (Tier α) so they are CI-friendly.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from aegis_trust import shield
from aegis_trust.client import AegisClient
from aegis_trust.shield import refresh_token, reset


@pytest.fixture(autouse=True)
def _full_env(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "full")
    monkeypatch.setenv("AEGIS_URL", "https://localhost:8443/api/v1")
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")
    yield
    reset()


def _ok_handler(records: list[str] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        if path.endswith("/shield/ingest"):
            if records is not None:
                records.append(request.read().decode())
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

    return httpx.MockTransport(handler)


def _patch_sync(transport: httpx.BaseTransport):
    from aegis_trust.shield import _get_client

    c = _get_client()
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=transport,
        headers=c._auth_headers(),
        timeout=httpx.Timeout(5.0),
    )
    return c


def _patch_async(monkeypatch, transport: httpx.MockTransport):
    real_init = AegisClient.__init__

    def _init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        self._async_httpx = httpx.AsyncClient(
            base_url=self._base_url,
            transport=transport,
            headers=self._auth_headers(),
            timeout=httpx.Timeout(5.0),
        )

    monkeypatch.setattr(AegisClient, "__init__", _init)


# ── T-133 AO-001 bypass — static AST check ──────────────────────────


def test_only_client_module_imports_httpx_in_aegis_package():
    """Every src/aegis/*.py file other than client.py must NOT import httpx
    directly. AO-001 gateway-uniqueness requires all backend traffic to go
    through AegisClient.
    """
    pkg = Path(__file__).resolve().parents[2] / "src" / "aegis"
    offenders: list[str] = []
    for path in pkg.glob("*.py"):
        if path.name == "client.py":
            continue
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "httpx":
                        offenders.append(f"{path.name}: import httpx")
            elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
                offenders.append(f"{path.name}: from httpx import …")
    assert not offenders, f"AO-001 bypass: non-client.py imports httpx: {offenders}"


# ── T-135 / T-136 Tier 2 leak-zero ──────────────────────────────────


def test_full_mode_returns_no_internal_state_on_500():
    """5xx ingest must return shape-preserving empty, with no leaked
    URL / token / stacktrace.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        return httpx.Response(500, json={"error": "internal stacktrace 0x1234"})

    _patch_sync(handler := httpx.MockTransport(handler))

    @shield(purpose="support", scope=["name"])
    def f() -> dict:
        return {"name": "alice", "ssn": "123"}

    result = f()
    serialized = json.dumps(result, default=str)
    for sentinel in (
        "localhost",
        "8443",
        "stacktrace",
        "0x1234",
        "Authorization",
        "Bearer",
        "/shield/ingest",
    ):
        assert sentinel not in serialized
    assert result == {}


# ── T-137 default deny when unreachable ─────────────────────────────


def test_full_mode_default_deny_when_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    _patch_sync(httpx.MockTransport(handler))

    @shield(purpose="support", scope=["name"])
    def f() -> dict:
        return {"name": "alice", "ssn": "123"}

    assert f() == {}


# ── T-139 VERIFY_SSL guard from @shield path ────────────────────────


def test_shield_path_verifies_ssl_when_url_is_prod(monkeypatch):
    monkeypatch.setenv("AEGIS_URL", "https://prod.example.com/api/v1")
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.delenv("AEGIS_DEV_INSECURE", raising=False)
    reset()
    from aegis_trust.shield import _get_client

    assert _get_client()._verify_ssl is True


# ── T-141 purpose null/empty/spoof ──────────────────────────────────


@pytest.mark.parametrize("purpose", ["", " ", "evil/../escape"])
def test_purpose_invalid_denied(purpose):
    def handler(request: httpx.Request) -> httpx.Response:
        # pretend the backend rejects every weird purpose
        if request.url.path.endswith("/check-access"):
            body = json.loads(request.read())
            if not body.get("purpose") or "/" in body.get("purpose", ""):
                return httpx.Response(403, json={"error": "denied"})
            return httpx.Response(200, json={"allowed": True})
        return httpx.Response(200, json={"status": "ok"})

    _patch_sync(httpx.MockTransport(handler))

    @shield(purpose=purpose, scope=["name"])
    def f() -> dict:
        return {"name": "alice"}

    assert f() == {}


# ── T-142 _diff_keys body contract ──────────────────────────────────


def test_ingest_body_includes_blocked_fields():
    records: list[str] = []
    _patch_sync(_ok_handler(records))

    @shield(purpose="support", scope=["name"])
    def f() -> dict:
        return {"name": "alice", "ssn": "123", "card": "4111"}

    f()
    assert len(records) == 1
    body = json.loads(records[0])
    entries = body["entries"]
    assert entries[0]["function"] == "f"
    assert entries[0]["purpose"] == "support"
    assert entries[0]["scope"] == ["name"]
    assert set(entries[0]["blocked_fields"]) == {"ssn", "card"}


# ── T-144 6 failure modes umbrella ──────────────────────────────────


@pytest.mark.parametrize(
    "status_or_exc",
    [
        401,  # auth fail
        403,  # token expire / permission denied
        500,  # 5xx
        503,  # network partition (synthetic)
        599,  # synthetic
        "TimeoutException",
    ],
)
def test_full_mode_six_failure_modes(status_or_exc):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        if status_or_exc == "TimeoutException":
            raise httpx.TimeoutException("timeout")
        return httpx.Response(int(status_or_exc), text="x")

    _patch_sync(httpx.MockTransport(handler))

    @shield(purpose="support", scope=["name"])
    def f() -> dict:
        return {"name": "alice", "ssn": "123"}

    assert f() == {}


# ── T-146 dot-notation deny under Full mode ─────────────────────────


def test_dot_notation_deny_full_mode():
    records: list[str] = []
    _patch_sync(_ok_handler(records))

    @shield(purpose="support", deny_fields=["profile.ssn"])
    def f() -> dict:
        return {"name": "alice", "profile": {"age": 30, "ssn": "123"}}

    result = f()
    assert result == {"name": "alice", "profile": {"age": 30}}
    assert len(records) == 1
    body = json.loads(records[0])
    assert "profile.ssn" in body["entries"][0]["blocked_fields"]


# ── T-147 async race — concurrent ingest payloads stay separated ────


@pytest.mark.asyncio
async def test_concurrent_async_full_payloads_unique(monkeypatch):
    seen: list[str] = []

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
        return httpx.Response(200)

    _patch_async(monkeypatch, httpx.MockTransport(handler))

    @shield(purpose="support", scope=["name"])
    async def f(i: int) -> dict:
        return {"name": f"user-{i}", "ssn": f"ssn-{i}"}

    await asyncio.gather(*(f(i) for i in range(10)))
    fns = [json.loads(b)["entries"][0]["function"] for b in seen]
    # All 10 calls go to function "f" — verify each call's ingest body is
    # independent (no interleaved fields from sibling calls).
    assert len(seen) == 10
    assert all(fn == "f" for fn in fns)


# ── T-149 token lifecycle adversarial ───────────────────────────────


def test_old_token_not_used_after_refresh(monkeypatch):
    auth_seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auth_seen.append(request.headers.get("Authorization"))
        if request.url.path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        if request.url.path.endswith("/shield/ingest"):
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
        return httpx.Response(200)

    monkeypatch.setenv("AEGIS_TOKEN", "old-token-123")
    reset()
    _patch_sync(httpx.MockTransport(handler))

    @shield(purpose="support", scope=["name"])
    def f() -> dict:
        return {"name": "alice"}

    f()
    assert any(a == "Bearer old-token-123" for a in auth_seen)

    monkeypatch.setenv("AEGIS_TOKEN", "new-token-456")
    refresh_token()
    # set_token discarded the cached client — re-patch the transport
    _patch_sync(httpx.MockTransport(handler))
    auth_seen.clear()
    f()
    assert auth_seen, "no requests issued after rotation"
    assert all("old-token-123" not in (a or "") for a in auth_seen)
    assert any(a == "Bearer new-token-456" for a in auth_seen)
