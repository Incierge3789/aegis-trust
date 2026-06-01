"""S018 D3 — Python local-history write-failure visibility (P1 path-leak hardened).

When ``AEGIS_HISTORY=1`` but the local history cannot be written (unwritable
path, permission error, disk problem), a developer who turned on local audit
evidence must learn it is NOT being recorded — **without** the diagnostic
echoing the ``AEGIS_HISTORY_PATH`` value (which may embed tenant / user /
secret-bearing path segments) or the raw exception message + traceback (an
``OSError`` message echoes the path). These tests lock:

  1. an init failure on a bad path does NOT break the @shield data path
     (the wrapped call still returns its filtered result),
  2. the diagnostic clearly states evidence is NOT being recorded, framed as a
     local developer diagnostic (not authoritative audit),
  3. the diagnostic fires once, not per-call (spam suppression), and
  4. the path value, exception message, and traceback are NOT leaked.
"""

import logging

import pytest

from aegis_trust import shield
from aegis_trust.history import record_if_enabled, reset_store
from aegis_trust.shield import reset


def _messages(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def _has_traceback(caplog) -> bool:
    return any(r.exc_info is not None or r.exc_text for r in caplog.records)


@pytest.fixture(autouse=True)
def _clean():
    reset_store()
    reset()
    yield
    reset_store()
    reset()


def test_history_init_failure_does_not_break_data_path(caplog, monkeypatch):
    # A path under a regular *file* (not a directory) makes mkdir/connect fail.
    bad_path = "/dev/null/cannot/exist/history.db"
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", bad_path)

    @shield(purpose="support", scope=["name"])
    def get_user():
        return {"name": "Aria", "ssn": "111-22-3333"}

    with caplog.at_level(logging.ERROR, logger="aegis"):
        result = get_user()

    msgs = _messages(caplog)
    # Data path unbroken: filtering still happened and returned normally.
    assert result == {"name": "Aria"}
    # Broken-evidence state is communicated.
    assert "NOT being recorded" in msgs
    # Framed as a local developer diagnostic, not an authoritative audit claim.
    assert "not an authoritative audit" in msgs.lower()
    # The raw path value is NOT leaked.
    assert bad_path not in msgs
    assert "/dev/null/cannot/exist" not in msgs


def test_adversarial_secret_bearing_history_path_does_not_leak(caplog, monkeypatch):
    secret_path = "/srv/tenant_acme_corp/user_alice/sk_live_HISTORYSECRET/history.db"
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", secret_path)

    @shield(purpose="support", scope=["name"])
    def get_user():
        return {"name": "Aria", "ssn": "x"}

    with caplog.at_level(logging.ERROR, logger="aegis"):
        result = get_user()

    msgs = _messages(caplog)
    assert result == {"name": "Aria"}  # fail-closed / data path intact
    assert "NOT being recorded" in msgs
    for needle in (
        secret_path,
        "tenant_acme_corp",
        "user_alice",
        "sk_live_HISTORYSECRET",
        "history.db",  # even the basename is withheld (could itself carry a secret)
    ):
        assert needle not in msgs, f"LEAKED path segment: {needle!r}"
    assert not _has_traceback(caplog)


def test_history_write_failure_warns_once(caplog, monkeypatch):
    bad_path = "/dev/null/cannot/exist/history.db"
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", bad_path)

    @shield(purpose="support", scope=["name"])
    def get_user():
        return {"name": "Aria", "ssn": "x"}

    with caplog.at_level(logging.ERROR, logger="aegis"):
        for _ in range(5):
            assert get_user() == {"name": "Aria"}

    # Spam suppression: the broken-evidence diagnostic is emitted once.
    occurrences = _messages(caplog).count("NOT being recorded")
    assert occurrences == 1, f"expected one warning, got {occurrences}"


def test_record_if_enabled_swallows_store_record_failure(caplog, monkeypatch, tmp_path):
    # Even a write failure *after* a successful store init must not raise out
    # of record_if_enabled, and must surface the broken-evidence state once —
    # without echoing the raw exception message (which can carry a path/secret).
    db = tmp_path / "history.db"
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", str(db))

    from aegis_trust import history as hist

    store = hist._get_store()
    assert store is not None

    def _boom(**kwargs):
        raise OSError("disk full at /srv/tenant_x/sk_live_DISKSECRET")

    monkeypatch.setattr(store, "record", _boom)

    with caplog.at_level(logging.ERROR, logger="aegis"):
        # Must not raise.
        record_if_enabled(
            function="f",
            purpose="p",
            scope=["name"],
            deny_fields=[],
            blocked_fields=[],
            timestamp="2026-06-01T00:00:00+00:00",
            mode="lite",
        )

    msgs = _messages(caplog)
    assert "NOT being recorded" in msgs
    # Raw exception message (and any secret it carries) is withheld.
    assert "disk full" not in msgs
    assert "sk_live_DISKSECRET" not in msgs
    assert "tenant_x" not in msgs
    assert not _has_traceback(caplog)
    # The exception class name IS surfaced (safe identifier).
    assert "OSError" in msgs
