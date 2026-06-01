"""Local history store for @shield invocations.

Records filtering history to SQLite for debugging and local audit.
Enabled via AEGIS_HISTORY=1 environment variable (default: off).

No external dependencies — uses Python stdlib sqlite3.

v0.9.0-rc1 additions (internal-ops/sprint_001):
- ``trace_id`` column for end-to-end trace propagation (links agent reasoning →
  shield call → audit chain via :mod:`aegis.trace` contextvars).
- ``idempotency_key`` column + :meth:`HistoryStore.record_idempotent` method
  (Stripe Idempotency-Key model: same key + same payload = single append; same
  key + different payload = :class:`aegis.errors.AegisAuditError`).

internal-ops/sprint_017 additions:
- ``schema_version`` column — the audit-event shape version, stamped on every
  row from the single-source :data:`aegis_trust._constants.AUDIT_SCHEMA_VERSION`
  (S017 T5). Existing pre-S017 databases are migrated with an idempotent
  ``ALTER TABLE ... ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1`` so
  rows written before this column read back as version 1 (S017 T6 / D-C).
  ``schema_version`` is deliberately NOT part of the idempotency
  :func:`_payload_hash` (S017 D-D) — it is record metadata, not an
  idempotency-significant field, so cross-language hash parity is preserved.
- ``record_if_enabled`` / ``HistoryStore.record`` keep their existing keyword
  signatures: the version is injected inside ``record`` from the constant, so
  no new kwargs are plumbed caller→store. This structurally prevents the
  signature-drift / silent-failure class observed in the quarantined stash
  5dc516b (S017 T3 / D-F).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_trust._constants import AUDIT_SCHEMA_VERSION
from aegis_trust.errors import AegisAuditError, aegis_docs_url

logger = logging.getLogger("aegis")

_store: HistoryStore | None = None
_checked: bool = False
# S018 D3: warn-once latch so a persistently-broken history path does not spam
# the log on every @shield call (parity with Node history.ts `_historyWarned`).
_history_warned: bool = False

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS shield_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function TEXT NOT NULL,
    purpose TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '[]',
    deny_fields TEXT NOT NULL DEFAULT '[]',
    blocked_fields TEXT NOT NULL DEFAULT '[]',
    timestamp TEXT NOT NULL,
    mode TEXT NOT NULL,
    trace_id TEXT,
    idempotency_key TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1
)
"""

# v0.9.0-rc1: ALTER TABLE for existing v0.8.x databases (idempotent).
# internal-ops/sprint_017: schema_version migration (S017 T6 / H-3).
_MIGRATE_ADD_TRACE_ID = "ALTER TABLE shield_history ADD COLUMN trace_id TEXT"
_MIGRATE_ADD_IDEMPOTENCY_KEY = (
    "ALTER TABLE shield_history ADD COLUMN idempotency_key TEXT"
)
_MIGRATE_ADD_SCHEMA_VERSION = (
    "ALTER TABLE shield_history ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1"
)

_INSERT = """
INSERT INTO shield_history (function, purpose, scope, deny_fields, blocked_fields, timestamp, mode, trace_id, idempotency_key, schema_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_BY_IDEMPOTENCY_KEY = """
SELECT function, purpose, scope, deny_fields, blocked_fields, mode
FROM shield_history
WHERE idempotency_key = ?
LIMIT 1
"""

_SELECT_HISTORY = """
SELECT id, function, purpose, scope, deny_fields, blocked_fields, timestamp, mode, schema_version
FROM shield_history
{where}
ORDER BY id DESC
LIMIT ?
"""

_STATS_BY_PURPOSE = """
SELECT purpose, COUNT(*) as calls,
       SUM(CASE WHEN blocked_fields != '[]' THEN 1 ELSE 0 END) as blocked
FROM shield_history
GROUP BY purpose
ORDER BY calls DESC
"""

_STATS_BY_FIELD = """
SELECT blocked_fields FROM shield_history WHERE blocked_fields != '[]'
"""


@dataclass
class HistoryRecord:
    """A single history record."""

    id: int
    function: str
    purpose: str
    scope: list[str]
    deny_fields: list[str]
    blocked_fields: list[str]
    timestamp: str
    mode: str
    trace_id: str | None = None
    idempotency_key: str | None = None
    # S017: audit-event shape version. Rows written before the schema_version
    # column (or read with a NULL) are normalised to 1 (S017 D-C).
    schema_version: int = 1


def _payload_hash(
    *,
    function: str,
    purpose: str,
    scope: list[str],
    deny_fields: list[str],
    blocked_fields: list[str],
    mode: str,
) -> str:
    """Canonical SHA256 over idempotency-significant fields (D-952 P0-2 parity with TS).

    S017 D-D: ``schema_version`` is intentionally excluded — it is record
    metadata, not idempotency-significant, so adding it must not change this
    hash or break the cross-language byte parity with the TS SDK.
    """
    canonical = json.dumps(
        [
            function,
            purpose,
            sorted(scope),
            sorted(deny_fields),
            sorted(blocked_fields),
            mode,
        ],
        sort_keys=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class HistoryStore:
    """SQLite-backed local history store."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_CREATE_TABLE)
        # v0.9.0-rc1 migration: add trace_id + idempotency_key to pre-existing v0.8.x dbs.
        # S017 migration: add schema_version to pre-existing v0.8.x/v0.9.x dbs (existing
        # rows backfill to 1 via the column DEFAULT).
        for ddl in (
            _MIGRATE_ADD_TRACE_ID,
            _MIGRATE_ADD_IDEMPOTENCY_KEY,
            _MIGRATE_ADD_SCHEMA_VERSION,
        ):
            try:
                self._conn.execute(ddl)
            except sqlite3.OperationalError:
                pass  # column already exists
        self._conn.commit()

    def record(
        self,
        *,
        function: str,
        purpose: str,
        scope: list[str],
        deny_fields: list[str],
        blocked_fields: list[str],
        timestamp: str,
        mode: str,
        trace_id: str | None = None,
    ) -> None:
        """Record a single @shield invocation.

        ``schema_version`` is stamped from the single-source constant inside
        this method (S017): callers do not pass it, which keeps the
        caller→store keyword contract stable (no signature drift).
        """
        self._conn.execute(
            _INSERT,
            (
                function,
                purpose,
                json.dumps(scope),
                json.dumps(deny_fields),
                json.dumps(blocked_fields),
                timestamp,
                mode,
                trace_id,
                None,
                AUDIT_SCHEMA_VERSION,
            ),
        )
        self._conn.commit()

    def record_idempotent(
        self,
        *,
        function: str,
        purpose: str,
        scope: list[str],
        deny_fields: list[str],
        blocked_fields: list[str],
        timestamp: str,
        mode: str,
        idempotency_key: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        """Stripe Idempotency-Key semantics for the local audit JSONL.

        Calling :meth:`record_idempotent` with the same ``idempotency_key`` more
        than once (within or across process runs) appends only once. Used by
        agents that retry on partial failure without producing duplicate audit
        records.

        Reusing the key with a divergent payload (different function / purpose /
        scope / deny_fields / blocked_fields / mode) raises
        :class:`AegisAuditError` instead of silently dropping the retry.

        Returns ``{"wrote": True|False, "idempotency_key": <key>}``.
        """
        if not idempotency_key or not isinstance(idempotency_key, str):
            raise AegisAuditError(
                "record_idempotent: idempotency_key must be a non-empty string",
                code="aegis.audit.idempotencyKey.required",
                remediation="Pass a non-empty string as idempotency_key.",
                docs_url=aegis_docs_url("aegis.audit.idempotencyKey.required"),
            )
        new_hash = _payload_hash(
            function=function,
            purpose=purpose,
            scope=scope,
            deny_fields=deny_fields,
            blocked_fields=blocked_fields,
            mode=mode,
        )
        cursor = self._conn.execute(_SELECT_BY_IDEMPOTENCY_KEY, (idempotency_key,))
        existing = cursor.fetchone()
        if existing is not None:
            ex_func, ex_purpose, ex_scope, ex_deny, ex_blocked, ex_mode = existing
            existing_hash = _payload_hash(
                function=ex_func,
                purpose=ex_purpose,
                scope=json.loads(ex_scope),
                deny_fields=json.loads(ex_deny),
                blocked_fields=json.loads(ex_blocked),
                mode=ex_mode,
            )
            if existing_hash != new_hash:
                raise AegisAuditError(
                    f"record_idempotent: idempotency_key '{idempotency_key}' reused with divergent payload",
                    code="aegis.audit.idempotencyKey.payloadDivergence",
                    remediation=(
                        "An idempotency_key was reused with a different payload. Either "
                        "rotate the key for the new payload, or fix the caller so retries "
                        "pass the same args."
                    ),
                    docs_url=aegis_docs_url(
                        "aegis.audit.idempotencyKey.payloadDivergence"
                    ),
                )
            return {"wrote": False, "idempotency_key": idempotency_key}
        # New key — append.
        self._conn.execute(
            _INSERT,
            (
                function,
                purpose,
                json.dumps(scope),
                json.dumps(deny_fields),
                json.dumps(blocked_fields),
                timestamp,
                mode,
                trace_id,
                idempotency_key,
                AUDIT_SCHEMA_VERSION,
            ),
        )
        self._conn.commit()
        return {"wrote": True, "idempotency_key": idempotency_key}

    def get_history(
        self, limit: int = 20, purpose: str | None = None
    ) -> list[HistoryRecord]:
        """Retrieve recent history records."""
        if purpose is not None:
            where = "WHERE purpose = ?"
            params: tuple[Any, ...] = (purpose, limit)
        else:
            where = ""
            params = (limit,)

        cursor = self._conn.execute(_SELECT_HISTORY.format(where=where), params)
        return [
            HistoryRecord(
                id=row[0],
                function=row[1],
                purpose=row[2],
                scope=json.loads(row[3]),
                deny_fields=json.loads(row[4]),
                blocked_fields=json.loads(row[5]),
                timestamp=row[6],
                mode=row[7],
                # S017 D-C: missing / NULL version reads back as 1.
                schema_version=row[8] if row[8] is not None else 1,
            )
            for row in cursor.fetchall()
        ]

    def get_stats(self) -> dict[str, Any]:
        """Aggregate statistics by purpose and blocked field."""
        cursor = self._conn.execute(_STATS_BY_PURPOSE)
        by_purpose = {
            row[0]: {"calls": row[1], "blocked": row[2]} for row in cursor.fetchall()
        }

        cursor = self._conn.execute(_STATS_BY_FIELD)
        field_counts: dict[str, int] = {}
        for (raw,) in cursor.fetchall():
            for field in json.loads(raw):
                field_counts[field] = field_counts.get(field, 0) + 1

        total_calls = sum(p["calls"] for p in by_purpose.values())
        total_blocked = sum(field_counts.values())

        return {
            "total_calls": total_calls,
            "total_blocked_fields": total_blocked,
            "by_purpose": by_purpose,
            "by_field": field_counts,
        }

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()


def _get_store() -> HistoryStore | None:
    """Return the global HistoryStore if AEGIS_HISTORY=1, else None."""
    global _store, _checked
    if _checked:
        return _store
    _checked = True
    if os.environ.get("AEGIS_HISTORY", "").strip() == "1":
        db_path = os.environ.get(
            "AEGIS_HISTORY_PATH",
            str(Path.home() / ".aegis" / "history.db"),
        )
        _store = HistoryStore(db_path)
        logger.info("aegis history enabled — %s", db_path)
    return _store


def record_if_enabled(
    *,
    function: str,
    purpose: str,
    scope: list[str],
    deny_fields: list[str],
    blocked_fields: list[str],
    timestamp: str,
    mode: str,
) -> None:
    """Record a @shield invocation if history is enabled.

    Keeps its original keyword signature: ``schema_version`` is stamped inside
    :meth:`HistoryStore.record`, so no new kwargs cross the caller→store
    boundary (S017 T3 — structurally prevents the silent-failure drift type).

    S018 D3: ``_get_store()`` (which opens the SQLite file, creating parent
    dirs) runs *inside* the try so a first-call init failure on an unwritable
    path no longer escapes and breaks the @shield data path (parity with Node
    history.ts, where getStore() is inside the try). On any failure a
    developer diagnostic is emitted once (not per-call) so a developer who set
    ``AEGIS_HISTORY=1`` to capture local audit evidence learns it is NOT being
    written. This is a local developer diagnostic, not an authoritative-audit
    guarantee.

    S018 P1 hardening: the diagnostic deliberately **withholds** the
    ``AEGIS_HISTORY_PATH`` value (it may embed tenant / user / secret-bearing
    path segments) and the raw exception message + traceback (an ``OSError``
    message echoes the very path). Only the exception *class name* and a fixed
    remediation are surfaced.
    """
    global _history_warned
    try:
        store = _get_store()
        if store is None:
            return
        store.record(
            function=function,
            purpose=purpose,
            scope=scope,
            deny_fields=deny_fields,
            blocked_fields=blocked_fields,
            timestamp=timestamp,
            mode=mode,
        )
    except Exception as exc:
        if not _history_warned:
            _history_warned = True
            logger.error(
                "aegis-trust: AEGIS_HISTORY=1 but the local history could not be "
                "written (%s) — local audit evidence is NOT being recorded. "
                "Check the path/permissions configured via AEGIS_HISTORY_PATH "
                "(its value is withheld here to avoid leaking tenant / user / "
                "secret path segments), or unset AEGIS_HISTORY. (Local developer "
                "diagnostic only — not an authoritative audit record.)",
                type(exc).__name__,
            )


def reset_store() -> None:
    """Reset the global store. For testing only."""
    global _store, _checked, _history_warned
    if _store is not None:
        _store.close()
    _store = None
    _checked = False
    _history_warned = False
