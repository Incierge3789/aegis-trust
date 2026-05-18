"""Tests for local history store."""

import os
import tempfile

import pytest

from aegis_trust import shield
from aegis_trust.history import HistoryStore, reset_store
from aegis_trust.shield import reset


@pytest.fixture
def tmp_db():
    """Create a temporary database file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    """Reset shield and history state for each test."""
    reset()
    reset_store()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()
    reset_store()


# ── HistoryStore direct tests ────────────────────────────────


def test_store_record_and_retrieve(tmp_db):
    store = HistoryStore(tmp_db)
    store.record(
        function="get_customer",
        purpose="support",
        scope=["name"],
        deny_fields=[],
        blocked_fields=["email", "card"],
        timestamp="2026-04-10T00:00:00Z",
        mode="lite",
    )
    records = store.get_history(limit=10)
    assert len(records) == 1
    assert records[0].function == "get_customer"
    assert records[0].purpose == "support"
    assert records[0].scope == ["name"]
    assert records[0].blocked_fields == ["email", "card"]
    assert records[0].mode == "lite"
    store.close()


def test_store_get_history_purpose_filter(tmp_db):
    store = HistoryStore(tmp_db)
    store.record(
        function="fn1",
        purpose="support",
        scope=["a"],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-04-10T00:00:00Z",
        mode="lite",
    )
    store.record(
        function="fn2",
        purpose="analytics",
        scope=["b"],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-04-10T00:00:01Z",
        mode="lite",
    )
    support = store.get_history(limit=10, purpose="support")
    assert len(support) == 1
    assert support[0].function == "fn1"

    all_records = store.get_history(limit=10)
    assert len(all_records) == 2
    store.close()


def test_store_get_stats(tmp_db):
    store = HistoryStore(tmp_db)
    store.record(
        function="fn1",
        purpose="support",
        scope=["name"],
        deny_fields=[],
        blocked_fields=["email", "card"],
        timestamp="2026-04-10T00:00:00Z",
        mode="lite",
    )
    store.record(
        function="fn2",
        purpose="support",
        scope=["name"],
        deny_fields=[],
        blocked_fields=["email"],
        timestamp="2026-04-10T00:00:01Z",
        mode="lite",
    )
    store.record(
        function="fn3",
        purpose="analytics",
        scope=["id"],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-04-10T00:00:02Z",
        mode="lite",
    )

    stats = store.get_stats()
    assert stats["total_calls"] == 3
    assert stats["total_blocked_fields"] == 3
    assert stats["by_purpose"]["support"]["calls"] == 2
    assert stats["by_purpose"]["support"]["blocked"] == 2
    assert stats["by_purpose"]["analytics"]["calls"] == 1
    assert stats["by_purpose"]["analytics"]["blocked"] == 0
    assert stats["by_field"]["email"] == 2
    assert stats["by_field"]["card"] == 1
    store.close()


def test_store_db_auto_created():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "sub", "history.db")
        store = HistoryStore(db_path)
        assert os.path.exists(db_path)
        store.close()


# ── Integration: @shield + history ───────────────────────────


def test_history_disabled_by_default(monkeypatch, tmp_db):
    """History is off by default — no DB file created at default path."""
    monkeypatch.delenv("AEGIS_HISTORY", raising=False)
    reset_store()

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "email": "t@x.com"}

    get_customer()
    # No store initialized — nothing to check except no error


def test_history_enabled_records_shield_calls(monkeypatch, tmp_db):
    """When AEGIS_HISTORY=1, @shield calls are recorded."""
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", tmp_db)
    reset_store()

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "email": "t@x.com"}

    get_customer()

    store = HistoryStore(tmp_db)
    records = store.get_history(limit=10)
    assert len(records) == 1
    assert records[0].purpose == "support"
    assert records[0].scope == ["name"]
    assert records[0].function == "get_customer"
    assert records[0].blocked_fields == ["email"]
    store.close()
