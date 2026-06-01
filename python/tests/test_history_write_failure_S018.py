"""S018 D3 — Python local-history write-failure visibility (P1 + P2 hardened).

When ``AEGIS_HISTORY=1`` but the local history cannot be written, the developer
must learn evidence is NOT being recorded — **without** the diagnostic echoing
any application-controlled string:

  P1 — no ``AEGIS_HISTORY_PATH`` value, no raw exception message, no traceback.
  P2 — no exception *class name* either (a dynamically named exception class
       would otherwise leak its name).

Hardened contract — the diagnostic emits ONLY SDK-controlled fixed strings:
``history_write_failed local_evidence_not_recorded=true`` + a fixed remediation
+ the "not an authoritative audit record" disclaimer. The @shield data path is
never broken by a history failure, and the diagnostic fires once.
"""

import logging

import pytest

from aegis_trust import shield
from aegis_trust.history import record_if_enabled, reset_store
from aegis_trust.shield import reset

MARKER = "history_write_failed"


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
    bad_path = "/dev/null/cannot/exist/history.db"
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", bad_path)

    @shield(purpose="support", scope=["name"])
    def get_user():
        return {"name": "Aria", "ssn": "111-22-3333"}

    with caplog.at_level(logging.ERROR, logger="aegis"):
        result = get_user()

    msgs = _messages(caplog)
    assert result == {"name": "Aria"}  # data path unbroken
    assert MARKER in msgs
    assert "local_evidence_not_recorded=true" in msgs
    assert "not an authoritative audit" in msgs.lower()
    # No raw path value.
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
    assert result == {"name": "Aria"}
    assert MARKER in msgs
    for needle in (
        secret_path,
        "tenant_acme_corp",
        "user_alice",
        "sk_live_HISTORYSECRET",
        "history.db",
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

    occurrences = _messages(caplog).count(MARKER)
    assert occurrences == 1, f"expected one warning, got {occurrences}"


def test_record_if_enabled_swallows_store_record_failure(caplog, monkeypatch, tmp_path):
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
        record_if_enabled(  # must not raise
            function="f",
            purpose="p",
            scope=["name"],
            deny_fields=[],
            blocked_fields=[],
            timestamp="2026-06-01T00:00:00+00:00",
            mode="lite",
        )

    msgs = _messages(caplog)
    assert MARKER in msgs
    # Raw exception message + class name + secret all withheld.
    assert "disk full" not in msgs
    assert "sk_live_DISKSECRET" not in msgs
    assert "tenant_x" not in msgs
    assert "OSError" not in msgs  # P2: exception class name withheld
    assert not _has_traceback(caplog)


def test_adversarial_history_exception_class_name_does_not_leak(
    caplog, monkeypatch, tmp_path
):
    """P2-1: a dynamically named history-write exception must not leak its name."""
    db = tmp_path / "history.db"
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", str(db))

    from aegis_trust import history as hist

    store = hist._get_store()
    assert store is not None

    EvilExc = type("customer_ssn_123_45_6789_sk_live_HISTEXC_Error", (OSError,), {})

    def _boom(**kwargs):
        raise EvilExc("boom")

    monkeypatch.setattr(store, "record", _boom)

    with caplog.at_level(logging.ERROR, logger="aegis"):
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
    assert MARKER in msgs  # fixed marker still present
    for needle in ("customer_ssn", "123_45_6789", "123-45-6789", "sk_live_HISTEXC"):
        assert needle not in msgs, (
            f"LEAKED via history exception class name: {needle!r}"
        )
