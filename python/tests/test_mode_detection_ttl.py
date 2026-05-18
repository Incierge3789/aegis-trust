"""Mode detection TTL + degrade-event tests (T-145 + T-134, S023 Phase 4).

Closes consensus finding CS4 from S023 Phase 3 cross-review: the previous
_detected_mode cache held for the lifetime of the process, so AEGIS_MODE=auto
could not pick up backend state changes (came up, went down). T-145 adds a
60s TTL; T-134 emits a warning when the mode flips so audit readers can
distinguish "always-Lite" from "Full degraded mid-process" (AO-006).
"""

from __future__ import annotations

import logging

import pytest

import sys

from aegis_trust.shield import _detect_mode, reset
from aegis_trust.types import Mode

# aegis/__init__.py rebinds the bare attribute `aegis.shield` to the @shield
# decorator function, so `aegis.shield` no longer refers to the submodule.
# Pull the real module from sys.modules to monkeypatch its private TTL.
shield_mod = sys.modules["aegis_trust.shield"]


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    reset()
    monkeypatch.delenv("AEGIS_MODE", raising=False)
    yield
    reset()


def test_explicit_lite_caches_and_returns(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "lite")
    assert _detect_mode() == Mode.LITE


def test_explicit_full_caches_and_returns(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "full")
    assert _detect_mode() == Mode.FULL


def test_cache_invalidates_after_ttl(monkeypatch):
    """Walk the monotonic clock past TTL — second call re-detects."""
    monkeypatch.setattr(shield_mod, "_DETECT_MODE_TTL_S", 0.001)
    monkeypatch.setenv("AEGIS_MODE", "lite")
    assert _detect_mode() == Mode.LITE

    # Flip env, advance time, expect a new detection
    monkeypatch.setenv("AEGIS_MODE", "full")
    import time as _time

    _time.sleep(0.01)
    assert _detect_mode() == Mode.FULL


def test_mode_flip_emits_warning(monkeypatch, caplog):
    monkeypatch.setattr(shield_mod, "_DETECT_MODE_TTL_S", 0.001)
    monkeypatch.setenv("AEGIS_MODE", "lite")
    _detect_mode()

    monkeypatch.setenv("AEGIS_MODE", "full")
    import time as _time

    _time.sleep(0.01)
    with caplog.at_level(logging.WARNING, logger="aegis"):
        _detect_mode()
    assert "mode changed lite → full" in caplog.text


def test_initial_detection_emits_info(monkeypatch, caplog):
    monkeypatch.setenv("AEGIS_MODE", "lite")
    with caplog.at_level(logging.INFO, logger="aegis"):
        _detect_mode()
    assert "detected mode=lite" in caplog.text


def test_cache_holds_within_ttl(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "lite")
    _detect_mode()
    monkeypatch.setenv("AEGIS_MODE", "full")
    # within TTL — cache wins
    assert _detect_mode() == Mode.LITE
