"""S017 schema_version contract regression tests (Python SDK).

Locks the schema_version=1 audit-event contract as a *permanent* regression
(sprint_017 oracles H-1..H-7), replacing the one-shot probes used at close
time. Node twin: ``node/tests/schemaVersion.test.ts`` — assertions aligned to
the same observable contract (Python emits snake_case ``schema_version``; Node
emits camelCase ``schemaVersion`` on disk and snake_case on the wire — the
casing asymmetry is intentional, see D-A..D-I).

Coverage map:
- T5/H-6  4 emit paths carry version 1 (here: SQLite local + /shield/ingest wire)
- T3/H-1  signature-drift regression — AEGIS_HISTORY=1 writes a versioned row
- T6/H-3  legacy SQLite db (no schema_version column) migrates, old rows read 1
- T6/H-4  missing version on read normalises to 1 (migration backfill)
- H-2/D-D schema_version excluded from the idempotency _payload_hash (byte parity)
- T4/H-7  AUDIT_SCHEMA_VERSION is single-source in aegis_trust._constants
"""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

from aegis_trust import shield
from aegis_trust._constants import AUDIT_SCHEMA_VERSION
from aegis_trust.client import AegisClient
from aegis_trust.history import HistoryStore, _payload_hash, reset_store
from aegis_trust.shield import reset
from aegis_trust.types import IngestEntry


@pytest.fixture
def tmp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
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


# ── constant value + single source (T4 / H-7) ────────────────


def test_audit_schema_version_value_is_1():
    assert AUDIT_SCHEMA_VERSION == 1


def test_audit_schema_version_is_single_source():
    """Public API + history + client all resolve to the one _constants definition."""
    from aegis_trust import AUDIT_SCHEMA_VERSION as public_const
    from aegis_trust import client as client_mod
    from aegis_trust import history as history_mod

    assert public_const is AUDIT_SCHEMA_VERSION
    assert client_mod.AUDIT_SCHEMA_VERSION is AUDIT_SCHEMA_VERSION
    assert history_mod.AUDIT_SCHEMA_VERSION is AUDIT_SCHEMA_VERSION


# ── emit path 1: SQLite local record (T5) ────────────────────


def test_sqlite_record_stamps_schema_version(tmp_db):
    store = HistoryStore(tmp_db)
    store.record(
        function="getUser",
        purpose="p",
        scope=["a"],
        deny_fields=[],
        blocked_fields=[],
        timestamp="t",
        mode="lite",
    )
    assert store.get_history(limit=1)[0].schema_version == 1
    # Stamped at the storage layer, not just on read-back.
    raw = (
        sqlite3.connect(tmp_db)
        .execute("SELECT schema_version FROM shield_history")
        .fetchone()
    )
    assert raw[0] == 1
    store.close()


def test_sqlite_record_idempotent_stamps_schema_version(tmp_db):
    store = HistoryStore(tmp_db)
    store.record_idempotent(
        function="getUser",
        purpose="p",
        scope=["a"],
        deny_fields=[],
        blocked_fields=[],
        timestamp="t",
        mode="lite",
        idempotency_key="k1",
    )
    assert store.get_history(limit=1)[0].schema_version == 1
    store.close()


# ── emit path 3: /shield/ingest wire payload (T5) ────────────


def test_wire_ingest_payload_stamps_schema_version():
    entry = IngestEntry(
        function="getUser",
        purpose="p",
        scope=["a", "b"],
        blocked_fields=["m", "n"],
        timestamp="t",
        count=1,
        deny_fields=["y", "z"],
    )
    payload = AegisClient._ingest_payload([entry])
    assert payload["entries"][0]["schema_version"] == 1


# ── signature-drift regression (T3 / H-1) ────────────────────


def test_aegis_history_enabled_writes_versioned_row(monkeypatch, tmp_db):
    """AEGIS_HISTORY=1 must actually write a row (rc=0), versioned at 1.

    Guards the silent-failure class: record_if_enabled -> HistoryStore.record
    keyword contract stays stable, so a row is appended (not swallowed by an
    except) and carries schema_version from the single-source constant.
    """
    monkeypatch.setenv("AEGIS_HISTORY", "1")
    monkeypatch.setenv("AEGIS_HISTORY_PATH", tmp_db)
    reset_store()

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "email": "t@x.com"}

    get_customer()

    rows = HistoryStore(tmp_db).get_history(limit=10)
    assert len(rows) == 1
    assert rows[0].function == "get_customer"
    assert rows[0].schema_version == 1


# ── legacy migration + missing-version read (T6 / H-3,H-4) ───


def test_legacy_db_without_schema_version_column_migrates_to_1(tmp_db):
    """A v0.8/v0.9 db with no schema_version column migrates; old rows read 1."""
    conn = sqlite3.connect(tmp_db)
    conn.execute(
        """CREATE TABLE shield_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            function TEXT NOT NULL, purpose TEXT NOT NULL, scope TEXT NOT NULL,
            deny_fields TEXT NOT NULL, blocked_fields TEXT NOT NULL,
            timestamp TEXT NOT NULL, mode TEXT NOT NULL,
            trace_id TEXT, idempotency_key TEXT
        )"""
    )
    conn.execute(
        "INSERT INTO shield_history "
        "(function,purpose,scope,deny_fields,blocked_fields,timestamp,mode) "
        "VALUES ('old','p','[]','[]','[]','t','lite')"
    )
    conn.commit()
    conn.close()

    # Opening via HistoryStore runs the idempotent ADD COLUMN ... DEFAULT 1,
    # which backfills the pre-existing row to 1 (the column is NOT NULL, so no
    # NULL version is ever observable through the migration path).
    rows = HistoryStore(tmp_db).get_history(limit=10)
    assert len(rows) == 1
    assert rows[0].schema_version == 1


# ── idempotency hash invariance / parity (H-2 / D-D) ─────────


def test_payload_hash_excludes_schema_version_byte_parity():
    """Idempotency hash is unchanged by schema_version (cross-lang byte anchor).

    node/tests/schemaVersion.test.ts byte-anchors the same digest over the
    identical canonical form (its "byte-anchors the canonical idempotency
    digest" test), so both SDKs pin this exact value. The hash takes no version
    parameter — adding schema_version must never change it or break py<->node
    parity.
    """
    expected = "4578b3e2eaa20d48e43ab7bd13d0c03b163c8f463b674ce1551a01ba3a4a06e9"
    got = _payload_hash(
        function="getUser",
        purpose="p",
        scope=["a", "b"],
        deny_fields=["y", "z"],
        blocked_fields=["m", "n"],
        mode="lite",
    )
    assert got == expected
