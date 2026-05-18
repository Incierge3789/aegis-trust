"""Tests for @shield decorator — full mode (requires running aegis-core).

These tests verify:
  - Auto mode correctly detects aegis-core
  - Full mode sends audit logs to aegis-core
  - Full mode still filters data correctly (AO-002)
  - Graceful fallback when aegis-core is unavailable

Run with aegis-core running:
    AEGIS_URL=https://localhost:8443/api/v1 pytest tests/test_shield_full.py -v

Skip if aegis-core is not available:
    AEGIS_MODE=lite pytest tests/ -v  (runs only lite tests)
"""

import os

import httpx
import pytest

from aegis_trust import shield
from aegis_trust.client import AegisClient
from aegis_trust.shield import reset, _detect_mode
from aegis_trust.types import Mode

AEGIS_URL = os.environ.get("AEGIS_URL", "https://localhost:8443/api/v1")


def _aegis_core_available() -> bool:
    """Check if aegis-core is reachable."""
    try:
        resp = httpx.get(f"{AEGIS_URL}/health", verify=False, timeout=2.0)
        return resp.status_code == 200
    except Exception:
        return False


def _aegis_core_accepts_unauthed_check_access() -> bool:
    """Return True when /check-access responds without 401.

    S024 live β fixture: the gateway's auth middleware rejects
    unauthenticated POST /check-access (correct per AO-001). Scope
    filtering tests need authorize() == True, which requires either
    AEGIS_APIKEY_AUTH=false on the gateway or a valid AEGIS_TOKEN on
    the client. When neither is set we skip the scope-filter tests and
    still attest the rest of the suite.
    """
    try:
        headers = {}
        if os.environ.get("AEGIS_TOKEN"):
            headers["Authorization"] = f"Bearer {os.environ['AEGIS_TOKEN']}"
        resp = httpx.post(
            f"{AEGIS_URL}/check-access",
            json={"purpose": "probe", "scope": ["x"]},
            headers=headers,
            verify=False,
            timeout=2.0,
        )
        return resp.status_code != 401
    except Exception:
        return False


requires_aegis_core = pytest.mark.skipif(
    not _aegis_core_available(),
    reason="aegis-core not running",
)

requires_authed_check_access = pytest.mark.skipif(
    not (_aegis_core_available() and _aegis_core_accepts_unauthed_check_access()),
    reason=(
        "aegis-core /check-access requires auth; set AEGIS_TOKEN to a "
        "valid gateway token or run the gateway with AEGIS_APIKEY_AUTH=false"
    ),
)


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    """Reset shield state for each test."""
    reset()
    monkeypatch.setenv("AEGIS_URL", AEGIS_URL)
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")  # T-153: dev opt-in
    yield
    reset()


# ── Auto detection ──────────────────────────────────────────


@requires_aegis_core
def test_auto_detects_full_mode(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "auto")
    mode = _detect_mode()
    assert mode == Mode.FULL


def test_auto_detects_lite_when_unavailable(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "auto")
    monkeypatch.setenv("AEGIS_URL", "https://localhost:19999/api/v1")
    mode = _detect_mode()
    assert mode == Mode.LITE


# ── Full mode filtering (AO-002) ────────────────────────────


@requires_authed_check_access
def test_full_mode_filters_dict(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "full")

    @shield(purpose="support", scope=["name", "issue"])
    def get_customer():
        return {
            "name": "Tanaka Taro",
            "email": "tanaka@example.com",
            "card": "4242-****-****-1234",
            "issue": "Login problem",
        }

    result = get_customer()
    assert result == {"name": "Tanaka Taro", "issue": "Login problem"}
    assert "email" not in result
    assert "card" not in result


@requires_authed_check_access
def test_full_mode_filters_list(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "full")

    @shield(purpose="analytics", scope=["id", "status"])
    def list_orders():
        return [
            {"id": 1, "status": "shipped", "address": "Tokyo"},
            {"id": 2, "status": "pending", "address": "Osaka"},
        ]

    result = list_orders()
    assert result == [
        {"id": 1, "status": "shipped"},
        {"id": 2, "status": "pending"},
    ]


# ── Fail-closed against authenticated gateway (AO-003) ──────


@requires_aegis_core
def test_full_mode_unauthed_returns_empty(monkeypatch):
    """When /check-access returns 401 (no dev token wired), full mode
    must fail closed — empty dict, not the raw function return. This
    is the counterpart to test_full_mode_filters_dict: together they
    pin both sides of the AO-003 gate.
    """
    monkeypatch.setenv("AEGIS_MODE", "full")
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)

    @shield(purpose="support_unauthed", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "email": "x@example.com"}

    # If the runner has a token capsule wired, skip — the authed path
    # is covered by the scope-filter tests above.
    if _aegis_core_accepts_unauthed_check_access():
        pytest.skip("gateway accepts unauthed /check-access; covered elsewhere")
    assert get_customer() == {}


# ── Audit log sent (AO-003) ─────────────────────────────────


@requires_authed_check_access
def test_full_mode_sends_audit(monkeypatch):
    """Verify that full mode sends audit log without raising."""
    monkeypatch.setenv("AEGIS_MODE", "full")

    @shield(purpose="audit_test", scope=["name"])
    def get_data():
        return {"name": "Test", "secret": "hidden"}

    # Should not raise — audit log is fire-and-forget
    result = get_data()
    assert result == {"name": "Test"}


# ── Client direct tests ─────────────────────────────────────


@requires_aegis_core
def test_client_is_available():
    client = AegisClient(base_url=AEGIS_URL, verify_ssl=False)
    assert client.is_available() is True


def test_client_not_available_wrong_url():
    client = AegisClient(base_url="https://localhost:19999/api/v1", verify_ssl=False)
    assert client.is_available() is False


@requires_aegis_core
def test_client_log_audit_requires_auth():
    """Verify audit log returns 401 without token (expected)."""
    import httpx

    client = AegisClient(base_url=AEGIS_URL, verify_ssl=False)
    with pytest.raises(httpx.HTTPStatusError, match="401"):
        client.log_audit(
            purpose="test",
            tool_name="shield",
            requester_id="sdk-test",
            decision="allow",
            reason="integration test",
        )


# ── Graceful degradation ────────────────────────────────────


def test_full_mode_fail_closed_when_unavailable(monkeypatch):
    """AO-003: Full mode returns empty result when ingest fails (fail-closed)."""
    monkeypatch.setenv("AEGIS_MODE", "full")
    monkeypatch.setenv("AEGIS_URL", "https://localhost:19999/api/v1")

    @shield(purpose="test", scope=["a"])
    def get_data():
        return {"a": 1, "b": 2}

    # Should not raise — but returns empty dict (fail-closed)
    result = get_data()
    assert result == {}


# ── M3 regression: httpx timeout (S013) ────────────────────────


def test_client_httpx_has_timeout():
    """S013/M3 regression: httpx.Client must have a timeout configured."""
    from aegis_trust.client import AegisClient, _API_TIMEOUT

    client = AegisClient(base_url="https://localhost:19999/api/v1", verify_ssl=False)
    httpx_client = client._get_httpx()
    assert httpx_client.timeout.connect == _API_TIMEOUT
    assert httpx_client.timeout.read == _API_TIMEOUT
