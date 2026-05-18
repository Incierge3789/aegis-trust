"""Phase 5 review-fix tests for Sprint S023.

Codex P1 — authorize() fail-OPEN regression:
  200 from /check-access without `{"allowed": true}` was previously cached
  as allow. Fix: parse body, deny when missing/false/malformed.

Codex P2 — _collect_removed cycle guard too aggressive:
  Shared `_seen` across the entire walk dropped legitimate aliasing
  entries from blocked_fields. Fix: track only the current recursion path.

Cursor P1 — token rotation race poisoning the cache:
  An in-flight authorize() that started before set_token() could write the
  old principal's allow into the new principal's cache. Fix: token_epoch
  in cache key + epoch_at_request guard in _remember_allow.

Cursor P1 — AO-001 silent Lite degrade in auto mode:
  AEGIS_MODE=auto used to drop to Lite on any unreachable backend, even
  when the user clearly intended Full (set AEGIS_TOKEN or non-default
  AEGIS_URL). Fix: stay in Full + fail-closed.
"""

from __future__ import annotations

import sys

import httpx
import pytest

from aegis_trust.client import AegisClient, set_metrics_hook
from aegis_trust.shield import _detect_mode, _user_intends_full, _collect_removed, reset
from aegis_trust.types import IngestEntry, Mode

shield_mod = sys.modules["aegis_trust.shield"]


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    reset()
    set_metrics_hook(None)
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_MODE", raising=False)
    monkeypatch.delenv("AEGIS_URL", raising=False)
    monkeypatch.delenv("AEGIS_VERIFY_SSL", raising=False)
    monkeypatch.delenv("AEGIS_DEV_INSECURE", raising=False)
    yield
    reset()
    set_metrics_hook(None)


def _client_with(handler):
    c = AegisClient(token="dev")
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers=c._auth_headers(),
        timeout=httpx.Timeout(5.0),
    )
    return c


# ── codex P1 — authorize body validation ────────────────────────────


def test_authorize_200_without_allowed_field_is_denied():
    def handler(request):
        return httpx.Response(200, json={"unexpected": "shape"})

    assert _client_with(handler).authorize("p", ["s"]) is False


def test_authorize_200_with_allowed_false_is_denied():
    def handler(request):
        return httpx.Response(200, json={"allowed": False})

    assert _client_with(handler).authorize("p", ["s"]) is False


def test_authorize_200_with_allowed_string_true_is_denied():
    """Only boolean True passes — string 'true' must not."""

    def handler(request):
        return httpx.Response(200, json={"allowed": "true"})

    assert _client_with(handler).authorize("p", ["s"]) is False


def test_authorize_200_with_allowed_true_is_allowed():
    def handler(request):
        return httpx.Response(200, json={"allowed": True})

    assert _client_with(handler).authorize("p", ["s"]) is True


def test_authorize_200_non_json_body_is_denied():
    def handler(request):
        return httpx.Response(200, text="not json")

    assert _client_with(handler).authorize("p", ["s"]) is False


def test_denied_response_is_not_cached():
    """Deny is never cached — every deny re-probes (was already true; this
    locks the contract along with the body-validation fix).
    """
    calls = [0]

    def handler(request):
        calls[0] += 1
        return httpx.Response(200, json={"allowed": False})

    c = _client_with(handler)
    assert c.authorize("p", ["s"]) is False
    assert c.authorize("p", ["s"]) is False
    assert calls[0] == 2


# ── codex P2 — cycle guard path-local ───────────────────────────────


def test_aliased_subtree_is_diffed_under_both_paths():
    """Two different keys point at the same dict — both removals must end up
    in `removed` (regression: shared `_seen` skipped the second).
    """
    inner = {"a": 1, "b": 2}
    original = {"x": inner, "y": inner}
    filtered = {"x": {"a": 1}, "y": {"a": 1}}
    removed: set[str] = set()
    _collect_removed(original, filtered, "", removed)
    assert "x.b" in removed
    assert "y.b" in removed


def test_self_cycle_still_terminates():
    """Path-local guard must still catch true self-cycles."""
    d = {"a": 1}
    d["self"] = d
    filtered = {"a": 1}
    removed: set[str] = set()
    _collect_removed(d, filtered, "", removed)
    assert "self" in removed


# ── cursor P1 — token rotation race ─────────────────────────────────


def test_cache_key_includes_token_epoch():
    c = AegisClient(token="t1")
    k_before = c._cache_key("p", ["s"])
    c.set_token("t2")
    k_after = c._cache_key("p", ["s"])
    assert k_before != k_after


def test_remember_allow_with_old_epoch_is_noop():
    c = AegisClient(token="t1")
    old_epoch = c._token_epoch
    c.set_token("t2")
    c._remember_allow("p", ["s"], epoch_at_request=old_epoch)
    assert not c._cached_allow("p", ["s"])


# ── cursor P1 — AO-001 explicit Full intent ─────────────────────────


def test_user_intends_full_via_token(monkeypatch):
    monkeypatch.setenv("AEGIS_TOKEN", "x")
    assert _user_intends_full() is True


def test_user_intends_full_via_non_default_url(monkeypatch):
    monkeypatch.setenv("AEGIS_URL", "https://prod.example.com/api/v1")
    assert _user_intends_full() is True


def test_user_intends_full_default_localhost_is_no(monkeypatch):
    monkeypatch.setenv("AEGIS_URL", "https://localhost:8443/api/v1")
    assert _user_intends_full() is False


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost:19999/api/v1",  # different port — still dev
        "https://127.0.0.1/api/v1",
        "https://[::1]:8443/api/v1",
        "https://dev.local/api/v1",
    ],
)
def test_user_intends_full_local_variants_are_dev(monkeypatch, url):
    monkeypatch.setenv("AEGIS_URL", url)
    assert _user_intends_full() is False


def test_auto_with_token_stays_full_when_unreachable(monkeypatch, caplog):
    """Phase 5 fix: auto + AEGIS_TOKEN set + backend down → stay Full,
    fail-closed (do NOT silently degrade to Lite).
    """
    import logging

    monkeypatch.setattr(shield_mod, "_DETECT_MODE_TTL_S", 0.001)
    monkeypatch.setenv("AEGIS_TOKEN", "x")
    monkeypatch.setenv("AEGIS_URL", "https://unreachable.invalid/api/v1")
    # is_available() will fail because the host doesn't resolve

    with caplog.at_level(logging.WARNING, logger="aegis"):
        m = _detect_mode()
    assert m == Mode.FULL
    assert "fail-closed" in caplog.text


def test_auto_no_token_no_url_falls_to_lite_when_unreachable(monkeypatch):
    monkeypatch.setenv("AEGIS_URL", "https://localhost:8443/api/v1")
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)
    # localhost:8443 is the default — no Full intent. Backend is not running.
    m = _detect_mode()
    assert m == Mode.LITE


# ── end-to-end regression: a successful authorize must still pass ────


def test_full_mode_end_to_end_after_fixes():
    def handler(request):
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
                        "audit_seq_start": 1,
                        "audit_seq_end": 1,
                    },
                },
            )
        return httpx.Response(404)

    c = _client_with(handler)
    assert c.authorize("support", ["name"]) is True
    resp = c.ingest(
        [
            IngestEntry(
                function="f",
                purpose="support",
                scope=["name"],
                blocked_fields=["ssn"],
                timestamp="2026-04-14T00:00:00Z",
            )
        ]
    )
    assert resp.audit_seq_end == 1
