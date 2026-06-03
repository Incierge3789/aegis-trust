"""T-504: Full mode REST API boundary attack — verify_ssl forced disable (AO-001).

AI Red Team S018 — adversarial attempts to disable SSL verification
and attack the trust boundary between aegis-trust and aegis-core.
"""

import os

import pytest

from aegis_trust.client import AegisClient
from aegis_trust.shield import _resolve_verify_ssl, reset


@pytest.fixture(autouse=True)
def _clean():
    reset()
    yield
    reset()


# ── Attack 1: AEGIS_VERIFY_SSL=false env var ─────────────────────


def test_verify_ssl_default_is_true():
    """Default verify_ssl must be True — never false."""
    client = AegisClient()
    assert client._verify_ssl is True


def test_verify_ssl_env_false_on_prod_rejected(monkeypatch):
    """T-153 (S023): AEGIS_VERIFY_SSL=false on non-dev host is force-overridden
    to True (fail-secure). Closes the S018 downgrade path.
    """
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.delenv("AEGIS_DEV_INSECURE", raising=False)
    assert _resolve_verify_ssl("https://prod.example.com/api/v1") is True


def test_verify_ssl_env_false_localhost_without_opt_in_rejected(monkeypatch):
    """T-153: localhost + VERIFY_SSL=false WITHOUT AEGIS_DEV_INSECURE=1 is
    still rejected. Dev opt-in must be explicit.
    """
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.delenv("AEGIS_DEV_INSECURE", raising=False)
    assert _resolve_verify_ssl("https://localhost:8443/api/v1") is True


def test_verify_ssl_env_false_with_explicit_opt_in_on_local(monkeypatch):
    """T-153: localhost + AEGIS_DEV_INSECURE=1 → dev opt-in accepted."""
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")
    assert _resolve_verify_ssl("https://localhost:8443/api/v1") is False


def test_verify_ssl_env_empty_defaults_true(monkeypatch):
    """Empty AEGIS_VERIFY_SSL must default to True."""
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "")
    assert _resolve_verify_ssl("https://localhost:8443/api/v1") is True


def test_verify_ssl_env_zero_is_true(monkeypatch):
    """AEGIS_VERIFY_SSL=0 must NOT disable SSL (only 'false' disables)."""
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "0")
    assert _resolve_verify_ssl("https://localhost:8443/api/v1") is True


def test_verify_ssl_env_no_is_true(monkeypatch):
    """AEGIS_VERIFY_SSL=no must NOT disable SSL."""
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "no")
    assert _resolve_verify_ssl("https://localhost:8443/api/v1") is True


# ── Attack 2: Token not leaked in logs ───────────────────────────


def test_token_not_in_repr():
    """AegisClient repr must not contain the token."""
    client = AegisClient(token="super_secret_token_12345")
    repr_str = repr(client)
    assert "super_secret_token_12345" not in repr_str


def test_token_not_in_str():
    """AegisClient str must not contain the token."""
    client = AegisClient(token="super_secret_token_12345")
    str_str = str(client)
    assert "super_secret_token_12345" not in str_str


# ── Attack 3: Base URL manipulation ──────────────────────────────


def test_base_url_default_is_https():
    """Default base URL must use HTTPS, not HTTP."""
    client = AegisClient()
    assert client._base_url.startswith("https://")


def test_base_url_env_override(monkeypatch):
    """AEGIS_URL can override base URL — verify it's stored as-is."""
    monkeypatch.setenv("AEGIS_URL", "http://evil.com/api")
    url = os.environ.get("AEGIS_URL", "https://localhost:8443/api/v1")
    client = AegisClient(base_url=url)
    # This is allowed (developer choice) but the default is safe
    assert client._base_url == "http://evil.com/api"


# ── Attack 4: Timeout values ─────────────────────────────────────


def test_api_timeout_is_reasonable():
    """API timeout must be set (not infinite)."""
    from aegis_trust.client import _API_TIMEOUT, _HEALTH_TIMEOUT

    assert _HEALTH_TIMEOUT > 0
    assert _HEALTH_TIMEOUT <= 5  # Health check should be fast
    assert _API_TIMEOUT > 0
    assert _API_TIMEOUT <= 30  # API calls should have a reasonable bound
