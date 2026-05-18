"""Tests for aegis CLI."""

import os
import tempfile

import pytest

from aegis_trust.cli import main
from aegis_trust.history import HistoryStore, reset_store
from aegis_trust.shield import reset


@pytest.fixture
def tmp_db():
    """Create a temporary database with sample data."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store = HistoryStore(path)
    store.record(
        function="get_customer",
        purpose="support",
        scope=["name"],
        deny_fields=[],
        blocked_fields=["email", "card"],
        timestamp="2026-04-10T10:00:00Z",
        mode="lite",
    )
    store.record(
        function="list_orders",
        purpose="analytics",
        scope=["id", "status"],
        deny_fields=[],
        blocked_fields=["address"],
        timestamp="2026-04-10T10:01:00Z",
        mode="lite",
    )
    store.record(
        function="get_profile",
        purpose="support",
        scope=[],
        deny_fields=["ssn"],
        blocked_fields=["ssn"],
        timestamp="2026-04-10T10:02:00Z",
        mode="lite",
    )
    store.close()
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    reset()
    reset_store()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()
    reset_store()


# ── aegis history ────────────────────────────────────────────


def test_cli_history(monkeypatch, tmp_db, capsys):
    monkeypatch.setenv("AEGIS_HISTORY_PATH", tmp_db)
    result = main(["history"])
    assert result == 0
    out = capsys.readouterr().out
    assert "get_customer" in out
    assert "list_orders" in out
    assert "3 record(s) shown" in out


def test_cli_history_limit(monkeypatch, tmp_db, capsys):
    monkeypatch.setenv("AEGIS_HISTORY_PATH", tmp_db)
    result = main(["history", "--limit", "1"])
    assert result == 0
    out = capsys.readouterr().out
    assert "1 record(s) shown" in out


def test_cli_history_purpose_filter(monkeypatch, tmp_db, capsys):
    monkeypatch.setenv("AEGIS_HISTORY_PATH", tmp_db)
    result = main(["history", "--purpose", "analytics"])
    assert result == 0
    out = capsys.readouterr().out
    assert "list_orders" in out
    assert "1 record(s) shown" in out


def test_cli_history_no_db(monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_HISTORY_PATH", "/nonexistent/path.db")
    result = main(["history"])
    assert result == 1
    out = capsys.readouterr().out
    assert "No history database" in out


# ── aegis stats ──────────────────────────────────────────────


def test_cli_stats(monkeypatch, tmp_db, capsys):
    monkeypatch.setenv("AEGIS_HISTORY_PATH", tmp_db)
    result = main(["stats"])
    assert result == 0
    out = capsys.readouterr().out
    assert "Total calls: 3" in out
    assert "support" in out
    assert "analytics" in out
    assert "email" in out


def test_cli_stats_no_db(monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_HISTORY_PATH", "/nonexistent/path.db")
    result = main(["stats"])
    assert result == 1


# ── no command ───────────────────────────────────────────────


def test_cli_no_command(capsys):
    result = main([])
    assert result == 0
    out = capsys.readouterr().out
    assert "aegis" in out.lower() or "usage" in out.lower()
