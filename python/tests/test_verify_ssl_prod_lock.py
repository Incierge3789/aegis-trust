"""Fail-secure TLS verify prod-lock tests (T-153, S023 Phase 4 Build).

Enforces AO-001 (Gateway唯一信頼境界) + AO-005 (fail-secure) + 米軍
defense-in-depth: AEGIS_VERIFY_SSL=false is silently overridden to True on
any non-dev host. Dev opt-in requires both a local host AND explicit
AEGIS_DEV_INSECURE=1.
"""

from __future__ import annotations

import logging

import pytest

from aegis_trust.shield import _resolve_verify_ssl, reset


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.delenv("AEGIS_VERIFY_SSL", raising=False)
    monkeypatch.delenv("AEGIS_DEV_INSECURE", raising=False)
    yield
    reset()


def test_default_verify_true():
    assert _resolve_verify_ssl("https://example.com/api/v1") is True


def test_explicit_true_stays_true(monkeypatch):
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "true")
    assert _resolve_verify_ssl("https://anything/api/v1") is True


@pytest.mark.parametrize(
    "url",
    [
        "https://prod.example.com/api/v1",
        "https://api.customer.io/v1",
        "https://203.0.113.10:8443/api/v1",
    ],
)
def test_prod_host_false_is_rejected(monkeypatch, url, caplog):
    """Non-dev host + VERIFY_SSL=false must be overridden to True (fail-secure)."""
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")  # even with opt-in, prod host wins
    with caplog.at_level(logging.WARNING, logger="aegis"):
        assert _resolve_verify_ssl(url) is True
    assert "rejected" in caplog.text.lower()


def test_dev_host_without_opt_in_rejected(monkeypatch, caplog):
    """localhost + VERIFY_SSL=false without AEGIS_DEV_INSECURE=1 → still True."""
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    with caplog.at_level(logging.WARNING, logger="aegis"):
        assert _resolve_verify_ssl("https://localhost:8443/api/v1") is True
    assert "rejected" in caplog.text.lower()


@pytest.mark.parametrize(
    "host", ["localhost", "127.0.0.1", "0.0.0.0", "::1", "dev.local"]
)
def test_dev_host_with_opt_in_allowed(monkeypatch, host, caplog):
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")
    url = (
        f"https://{host}:8443/api/v1"
        if ":" not in host
        else f"https://[{host}]:8443/api/v1"
    )
    with caplog.at_level(logging.WARNING, logger="aegis"):
        assert _resolve_verify_ssl(url) is False
    assert "accepted for dev host" in caplog.text.lower()


def test_opt_in_variant_values(monkeypatch):
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    for val in ("1", "true", "TRUE"):
        monkeypatch.setenv("AEGIS_DEV_INSECURE", val)
        assert _resolve_verify_ssl("https://localhost/api/v1") is False


def test_malformed_url_defaults_to_verify(monkeypatch, caplog):
    """Unparseable URL should still fail-secure (verify=True)."""
    monkeypatch.setenv("AEGIS_VERIFY_SSL", "false")
    monkeypatch.setenv("AEGIS_DEV_INSECURE", "1")
    with caplog.at_level(logging.WARNING, logger="aegis"):
        assert _resolve_verify_ssl("not a url") is True
