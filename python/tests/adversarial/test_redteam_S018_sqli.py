"""T-507: history.py SQLite injection attempt.

AI Red Team S018 — adversarial attempts to inject SQL via shield parameters.
"""

import os
import tempfile

import pytest

from aegis_trust.history import HistoryStore


@pytest.fixture()
def store():
    """Create a temp SQLite store for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # HistoryStore creates it
    s = HistoryStore(path)
    yield s
    s.close()
    if os.path.exists(path):
        os.unlink(path)


# ── Attack 1: SQL injection via purpose field ────────────────────


def test_sqli_via_purpose(store):
    """Attacker sets purpose to SQL injection payload."""
    malicious_purpose = "'; DROP TABLE shield_history; --"

    store.record(
        function="get_customer",
        purpose=malicious_purpose,
        scope=["name"],
        deny_fields=[],
        blocked_fields=["ssn"],
        timestamp="2026-01-01T00:00:00Z",
        mode="lite",
    )

    # Table must still exist and be queryable
    records = store.get_history(limit=10)
    assert len(records) == 1
    assert records[0].purpose == malicious_purpose

    # Verify table wasn't dropped
    stats = store.get_stats()
    assert stats["total_calls"] == 1


def test_sqli_via_purpose_union_select(store):
    """Attacker tries UNION SELECT to exfiltrate data."""
    malicious = "support' UNION SELECT 1,2,3,4,5,6,7,8 FROM sqlite_master--"

    store.record(
        function="fn",
        purpose=malicious,
        scope=[],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-01-01T00:00:00Z",
        mode="lite",
    )

    records = store.get_history(limit=10, purpose=malicious)
    assert len(records) == 1
    assert records[0].purpose == malicious


# ── Attack 2: SQL injection via function name ────────────────────


def test_sqli_via_function_name(store):
    """Attacker sets function name to SQL injection payload."""
    malicious_fn = "get_customer'; INSERT INTO shield_history VALUES(999,'evil','evil','[]','[]','[]','now','lite');--"

    store.record(
        function=malicious_fn,
        purpose="support",
        scope=["name"],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-01-01T00:00:00Z",
        mode="lite",
    )

    records = store.get_history(limit=100)
    # Only 1 record should exist, not 2
    assert len(records) == 1
    assert records[0].function == malicious_fn


# ── Attack 3: SQL injection via blocked_fields JSON ──────────────


def test_sqli_via_blocked_fields(store):
    """Attacker injects SQL via blocked_fields list values."""
    malicious_fields = ["ssn'; DROP TABLE shield_history;--", "card"]

    store.record(
        function="fn",
        purpose="support",
        scope=["name"],
        deny_fields=[],
        blocked_fields=malicious_fields,
        timestamp="2026-01-01T00:00:00Z",
        mode="lite",
    )

    records = store.get_history(limit=10)
    assert len(records) == 1
    # blocked_fields is JSON-serialized, not interpolated into SQL
    assert records[0].blocked_fields == malicious_fields

    # Table still works
    assert store.get_stats()["total_calls"] == 1


# ── Attack 4: SQL injection via scope list ───────────────────────


def test_sqli_via_scope(store):
    """Attacker injects SQL via scope list values."""
    malicious_scope = ["name", "') ; DELETE FROM shield_history WHERE ('1'='1"]

    store.record(
        function="fn",
        purpose="support",
        scope=malicious_scope,
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-01-01T00:00:00Z",
        mode="lite",
    )

    records = store.get_history(limit=10)
    assert len(records) == 1
    assert records[0].scope == malicious_scope


# ── Attack 5: SQL injection via timestamp ────────────────────────


def test_sqli_via_timestamp(store):
    """Attacker injects SQL via timestamp field."""
    malicious_ts = "2026-01-01'); DELETE FROM shield_history;--"

    store.record(
        function="fn",
        purpose="support",
        scope=[],
        deny_fields=[],
        blocked_fields=[],
        timestamp=malicious_ts,
        mode="lite",
    )

    records = store.get_history(limit=10)
    assert len(records) == 1
    assert records[0].timestamp == malicious_ts


# ── Attack 6: SQL injection via mode field ───────────────────────


def test_sqli_via_mode(store):
    """Attacker injects SQL via mode field."""
    malicious_mode = "lite'; UPDATE shield_history SET purpose='hacked' WHERE '1'='1"

    store.record(
        function="fn",
        purpose="support",
        scope=[],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-01-01T00:00:00Z",
        mode=malicious_mode,
    )

    records = store.get_history(limit=10)
    assert len(records) == 1
    assert records[0].mode == malicious_mode
    # Verify no other records were modified
    assert records[0].purpose == "support"


# ── Attack 7: get_history purpose filter injection ───────────────


def test_sqli_via_get_history_purpose(store):
    """Attacker injects SQL via the purpose parameter of get_history."""
    # First, insert a legitimate record
    store.record(
        function="fn",
        purpose="legit",
        scope=[],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-01-01T00:00:00Z",
        mode="lite",
    )

    # Try to inject via purpose filter
    malicious_purpose = "' OR '1'='1"
    records = store.get_history(limit=10, purpose=malicious_purpose)
    # Should return 0 records (no matching purpose), not all records
    assert len(records) == 0


# ── Attack 8: Null bytes in fields ───────────────────────────────


def test_null_bytes_in_fields(store):
    """Attacker injects null bytes to try truncation attacks."""
    store.record(
        function="fn\x00evil",
        purpose="support\x00DROP TABLE",
        scope=["name\x00ssn"],
        deny_fields=[],
        blocked_fields=[],
        timestamp="2026-01-01T00:00:00Z",
        mode="lite",
    )

    records = store.get_history(limit=10)
    assert len(records) == 1
    # Null bytes are preserved in SQLite TEXT fields
    assert "\x00" in records[0].function or records[0].function == "fn\x00evil"
