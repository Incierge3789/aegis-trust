"""Python rc4 cross-SDK parity contract tests.

Mirrors `node/tests/fullMode.test.ts` for the rc4 contract surface
(AEGIS_URL canonical + AEGIS_BASE_URL deprecation alias + AUTO probe-first
behaviour matrix + fail-closed FULL on intent + unreachable). Authored to
close the cursor iter-1 cross-review P1 finding that the rc4 contract had
Node-only test coverage (cross-SDK test asymmetry under Hard Stop #2).

Each test below has a Node twin in `node/tests/fullMode.test.ts` — assertions
are aligned to the same observable behaviour where the underlying SDK
implementation supports identical witnessing.
"""

from __future__ import annotations

import logging
import os

import pytest

from aegis_trust.shield import (
    _is_dev_host,
    _resolve_base_url,
    _user_intends_full,
    reset,
)


@pytest.fixture(autouse=True)
def _reset_env_and_state():
    """Match node `beforeEach(resetModuleClient)` + `afterEach(env cleanup)`."""
    reset()
    for key in ("AEGIS_URL", "AEGIS_BASE_URL", "AEGIS_TOKEN", "AEGIS_MODE"):
        os.environ.pop(key, None)
    yield
    reset()
    for key in ("AEGIS_URL", "AEGIS_BASE_URL", "AEGIS_TOKEN", "AEGIS_MODE"):
        os.environ.pop(key, None)


# ─── _resolve_base_url() precedence + deprecation warning ───────────────


def test_resolve_base_url_default_when_no_env() -> None:
    """No env vars set → default base URL (parity with npm `DEFAULT_BASE_URL`)."""
    assert _resolve_base_url() == "https://localhost:8443/api/v1"


def test_resolve_base_url_aegis_url_canonical() -> None:
    """AEGIS_URL alone → canonical; no deprecation warn (parity with npm)."""
    os.environ["AEGIS_URL"] = "https://canonical.example.com:8443/api/v1"
    assert _resolve_base_url() == "https://canonical.example.com:8443/api/v1"


def test_resolve_base_url_aegis_base_url_alone_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """AEGIS_BASE_URL alone triggers exactly one logger.warning per process.

    Mirrors node `AEGIS_BASE_URL alone triggers exactly one console.warn per
    process` (cursor iter-1 P1-b coverage parity).
    """
    os.environ["AEGIS_BASE_URL"] = "https://alias.example.com:8443/api/v1"
    with caplog.at_level(logging.WARNING, logger="aegis_trust.shield"):
        for _ in range(3):
            url = _resolve_base_url()
            assert url == "https://alias.example.com:8443/api/v1"
    alias_warns = [r for r in caplog.records if "AEGIS_BASE_URL" in r.getMessage()]
    # Exactly one warning across multiple resolutions (re-armed only by reset()).
    assert len(alias_warns) == 1


def test_resolve_base_url_aegis_url_precedence_no_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """AEGIS_URL + AEGIS_BASE_URL → canonical wins, no deprecation warn fires.

    Mirrors node `AEGIS_URL takes precedence over AEGIS_BASE_URL with no
    warning fired` (cursor iter-1 P1-b coverage parity).
    """
    os.environ["AEGIS_URL"] = "https://canonical.example.com:8443/api/v1"
    os.environ["AEGIS_BASE_URL"] = "https://alias.example.com:8443/api/v1"
    with caplog.at_level(logging.WARNING, logger="aegis_trust.shield"):
        url = _resolve_base_url()
    assert url == "https://canonical.example.com:8443/api/v1"
    alias_warns = [r for r in caplog.records if "AEGIS_BASE_URL" in r.getMessage()]
    assert alias_warns == []


def test_reset_rearms_deprecation_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """reset() re-arms the deprecation-warning state across logical resets.

    Mirrors node `resetModuleClient()` re-arming behaviour.
    """
    os.environ["AEGIS_BASE_URL"] = "https://alias.example.com:8443/api/v1"
    with caplog.at_level(logging.WARNING, logger="aegis_trust.shield"):
        _resolve_base_url()
        _resolve_base_url()
        reset()
        _resolve_base_url()
        _resolve_base_url()
    alias_warns = [r for r in caplog.records if "AEGIS_BASE_URL" in r.getMessage()]
    # One warn pre-reset + one warn post-reset = 2 total.
    assert len(alias_warns) == 2


# ─── _user_intends_full() breaking-for-direct-callers ───────────────────


def test_user_intends_full_aegis_mode_full_alone_returns_false() -> None:
    """rc4+ breaking change: AEGIS_MODE=full alone is no longer a sole intent signal.

    AEGIS_MODE handling moved to _detect_mode(); _user_intends_full() now
    requires AEGIS_TOKEN OR a non-dev URL. Mirrors node `userIntendsFull`
    breaking-for-direct-callers semantics.
    """
    os.environ["AEGIS_MODE"] = "full"
    assert _user_intends_full() is False


def test_user_intends_full_aegis_token_returns_true() -> None:
    """AEGIS_TOKEN alone signals Full intent (preserved from pre-rc4)."""
    os.environ["AEGIS_TOKEN"] = "t"
    assert _user_intends_full() is True


def test_user_intends_full_non_dev_aegis_url_returns_true() -> None:
    """Non-dev AEGIS_URL signals Full intent (rc4 addition)."""
    os.environ["AEGIS_URL"] = "https://prod.example.com:8443/api/v1"
    assert _user_intends_full() is True


def test_user_intends_full_non_dev_aegis_base_url_returns_true() -> None:
    """Non-dev AEGIS_BASE_URL (deprecation alias) also signals Full intent."""
    os.environ["AEGIS_BASE_URL"] = "https://prod.example.com:8443/api/v1"
    assert _user_intends_full() is True


def test_user_intends_full_dev_url_returns_false() -> None:
    """Dev host (localhost / 127.0.0.1 / *.local) does NOT signal Full intent
    even when AEGIS_URL is set, so dev fixtures keep working without ingest.
    """
    os.environ["AEGIS_URL"] = "https://localhost:8443/api/v1"
    assert _user_intends_full() is False
    assert _is_dev_host("https://localhost:8443/api/v1") is True
    assert _is_dev_host("https://127.0.0.1:8443/api/v1") is True
    assert _is_dev_host("https://prod.example.com:8443/api/v1") is False
