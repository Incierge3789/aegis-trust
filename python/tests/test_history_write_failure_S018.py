"""S018 D3 — Python local-history write-failure visibility parity.

When ``AEGIS_HISTORY=1`` but the local history cannot be written (unwritable
path, permission error, disk problem), a developer who turned on local audit
evidence must learn it is NOT being recorded. Before S018 the Python path
either logged a bare "Failed to record shield history" (no cause, no path) or
— for a first-call store-init failure — let the exception escape and break the
@shield data path entirely. These tests lock:

  1. an init failure on a bad path does NOT break the @shield data path
     (the wrapped call still returns its filtered result),
  2. the diagnostic names the cause and the target path,
  3. the diagnostic fires once, not per-call (spam suppression), and
  4. it is framed as a local developer diagnostic, not authoritative audit.
"""

import logging

import pytest

from aegis_trust import shield
from aegis_trust.history import record_if_enabled, reset_store
from aegis_trust.shield import reset


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

    # Data path unbroken: filtering still happened and returned normally.
    assert result == {"name": "Aria"}
    # Diagnostic names the path and the cause, and the broken-evidence state.
    assert bad_path in caplog.text
    assert "NOT being recorded" in caplog.text
    # Framed as a local developer diagnostic, not an authoritative audit claim.
    assert "not an authoritative audit" in caplog.text.lower()


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
    occurrences = caplog.text.count("NOT being recorded")
    assert occurrences == 1, f"expected one warning, got {occurrences}"


def test_record_if_enabled_swallows_store_record_failure(caplog, monkeypatch, tmp_path):
    # Even a write failure *after* a successful store init must not raise out
    # of record_if_enabled, and must surface the cause once.
    db = tmp_path / "history.db"
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", str(db))

    from aegis_trust import history as hist

    store = hist._get_store()
    assert store is not None

    def _boom(**kwargs):
        raise OSError("disk full")

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

    assert "disk full" in caplog.text
    assert "NOT being recorded" in caplog.text
