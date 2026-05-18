"""Full mode behavior tests — no private function mocks.

Tests the @shield decorator in Full mode by simulating aegis-core REST API
responses via httpx.MockTransport. This exercises the real code path:
  @shield → _detect_mode → _get_client → AegisClient → httpx → REST API

No mock.patch on private functions (_get_client, _detect_mode, _shield_full).
Python 3.10+ compatible.

Aegis AO compliance:
  AO-002: fail-closed on ingest failure
  AO-003: audit record sent via /shield/ingest
  AO-006: data flow explicit (no env-var magic in tests)
"""

import json
import os

import httpx
import pytest

from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _full_mode_env(monkeypatch):
    """Configure Full mode with a test server URL."""
    reset()
    monkeypatch.setenv("AEGIS_MODE", "full")
    monkeypatch.setenv("AEGIS_URL", "https://test-aegis:8443/api/v1")
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    yield
    reset()


def _make_transport(ingest_response=None, fail=False):
    """Create a MockTransport that simulates aegis-core REST API."""
    if ingest_response is None:
        ingest_response = {
            "success": True,
            "data": {"ingested": 1, "audit_seq_start": 1, "audit_seq_end": 1},
        }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/v1/check-access":
            # T-151: default allow for legacy tests; dedicated T-151 tests
            # override this endpoint explicitly.
            return httpx.Response(200, json={"allowed": True})
        if path == "/api/v1/shield/ingest":
            if fail:
                return httpx.Response(500, json={"error": "internal"})
            return httpx.Response(200, json=ingest_response)
        if path == "/api/v1/shield/policy-sync":
            body = json.loads(request.content)
            names = list(body.get("purposes", {}).keys())
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "synced": len(names),
                        "added": names,
                        "updated": [],
                    },
                },
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _patch_client_transport(transport):
    """Inject a MockTransport into the module-level AegisClient."""
    from aegis_trust.shield import _get_client

    client = _get_client()
    # Replace the httpx.Client with one using our mock transport
    client._httpx = httpx.Client(
        base_url=os.environ["AEGIS_URL"],
        transport=transport,
        timeout=httpx.Timeout(10.0),
    )
    return client


# ── scope (whitelist) + Full mode ─────────────────────────


class TestShieldFullScope:
    """@shield with scope in Full mode sends ingest and filters correctly."""

    def test_scope_filters_and_sends_ingest(self):
        from aegis_trust import shield

        transport = _make_transport()
        _patch_client_transport(transport)

        @shield(purpose="support", scope=["name", "issue"])
        def get_customer(cid: str) -> dict:
            return {
                "name": "Tanaka",
                "email": "t@example.com",
                "card": "4242",
                "issue": "Login problem",
            }

        result = get_customer("C-001")
        assert result == {"name": "Tanaka", "issue": "Login problem"}
        assert "email" not in result
        assert "card" not in result

    def test_scope_nested_dot_path(self):
        from aegis_trust import shield

        transport = _make_transport()
        _patch_client_transport(transport)

        @shield(purpose="analytics", scope=["name", "profile.age"])
        def get_user(uid: str) -> dict:
            return {
                "name": "Sato",
                "profile": {"age": 28, "ssn": "123-45-6789"},
            }

        result = get_user("U-001")
        assert result == {"name": "Sato", "profile": {"age": 28}}

    def test_scope_list_input(self):
        from aegis_trust import shield

        transport = _make_transport()
        _patch_client_transport(transport)

        @shield(purpose="support", scope=["name"])
        def list_customers() -> list:
            return [
                {"name": "A", "email": "a@x.com"},
                {"name": "B", "email": "b@x.com"},
            ]

        result = list_customers()
        assert result == [{"name": "A"}, {"name": "B"}]


# ── deny_fields (blacklist) + Full mode ───────────────────


class TestShieldFullDeny:
    """@shield with deny_fields in Full mode."""

    def test_deny_filters_and_sends_ingest(self):
        from aegis_trust import shield

        transport = _make_transport()
        _patch_client_transport(transport)

        @shield(purpose="billing", deny_fields=["card", "ssn"])
        def get_account(aid: str) -> dict:
            return {"name": "Tanaka", "card": "4242", "ssn": "123", "balance": 100}

        result = get_account("A-001")
        assert result == {"name": "Tanaka", "balance": 100}
        assert "card" not in result
        assert "ssn" not in result

    def test_deny_nested_path(self):
        from aegis_trust import shield

        transport = _make_transport()
        _patch_client_transport(transport)

        @shield(purpose="support", deny_fields=["profile.ssn"])
        def get_user(uid: str) -> dict:
            return {
                "name": "Tanaka",
                "profile": {"ssn": "123-45-6789", "age": 30},
            }

        result = get_user("U-001")
        assert result == {"name": "Tanaka", "profile": {"age": 30}}


# ── AO-002: fail-closed on ingest failure ─────────────────


class TestShieldFullFailClosed:
    """AO-002: when aegis-core is unreachable, shield returns empty."""

    def test_ingest_failure_returns_empty_dict(self):
        from aegis_trust import shield

        transport = _make_transport(fail=True)
        _patch_client_transport(transport)

        @shield(purpose="support", scope=["name"])
        def get_customer(cid: str) -> dict:
            return {"name": "Tanaka", "email": "t@x.com"}

        result = get_customer("C-001")
        assert result == {}

    def test_ingest_failure_returns_empty_list(self):
        from aegis_trust import shield

        transport = _make_transport(fail=True)
        _patch_client_transport(transport)

        @shield(purpose="support", scope=["name"])
        def list_customers() -> list:
            return [{"name": "A", "email": "a@x.com"}]

        result = list_customers()
        assert result == []

    def test_deny_ingest_failure_returns_empty(self):
        from aegis_trust import shield

        transport = _make_transport(fail=True)
        _patch_client_transport(transport)

        @shield(purpose="billing", deny_fields=["card"])
        def get_account(aid: str) -> dict:
            return {"name": "Tanaka", "card": "4242"}

        result = get_account("A-001")
        assert result == {}


# ── sync_policies ─────────────────────────────────────────


class TestSyncPolicies:
    """Policy synchronization API behavior across modes."""

    def test_sync_policies_full_mode(self):
        from aegis_trust.shield import sync_policies
        from aegis_trust.types import PolicySyncEntry

        transport = _make_transport()
        _patch_client_transport(transport)

        # sync_policies currently does not return the response (void function).
        # This test verifies the call completes without raising.
        sync_policies({"support": PolicySyncEntry(scope=["name", "issue"])})

    def test_sync_policies_lite_mode_raises(self, monkeypatch):
        from aegis_trust.shield import sync_policies
        from aegis_trust.types import PolicySyncEntry

        monkeypatch.setenv("AEGIS_MODE", "lite")
        reset()

        with pytest.raises(RuntimeError, match="no enterprise backend is configured"):
            sync_policies({"support": PolicySyncEntry(scope=["name"])})
