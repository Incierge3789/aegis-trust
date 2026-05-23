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

from aegis_trust.errors import AegisAuditError, aegis_docs_url

logger = logging.getLogger("aegis")

_store: HistoryStore | None = None
_checked: bool = False

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
    idempotency_key TEXT
)
"""

# v0.9.0-rc1: ALTER TABLE for existing v0.8.x databases (idempotent).
_MIGRATE_ADD_TRACE_ID = "ALTER TABLE shield_history ADD COLUMN trace_id TEXT"
_MIGRATE_ADD_IDEMPOTENCY_KEY = (
    "ALTER TABLE shield_history ADD COLUMN idempotency_key TEXT"
)

_INSERT = """
INSERT INTO shield_history (function, purpose, scope, deny_fields, blocked_fields, timestamp, mode, trace_id, idempotency_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_BY_IDEMPOTENCY_KEY = """
SELECT function, purpose, scope, deny_fields, blocked_fields, mode
FROM shield_history
WHERE idempotency_key = ?
LIMIT 1
"""

_SELECT_HISTORY = """
SELECT id, function, purpose, scope, deny_fields, blocked_fields, timestamp, mode
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


def _payload_hash(
    *,
    function: str,
    purpose: str,
    scope: list[str],
    deny_fields: list[str],
    blocked_fields: list[str],
    mode: str,
) -> str:
    """Canonical SHA256 over idempotency-significant fields (D-952 P0-2 parity with TS)."""
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
        for ddl in (_MIGRATE_ADD_TRACE_ID, _MIGRATE_ADD_IDEMPOTENCY_KEY):
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
        """Record a single @shield invocation."""
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
    """Record a @shield invocation if history is enabled."""
    store = _get_store()
    if store is None:
        return
    try:
        store.record(
            function=function,
            purpose=purpose,
            scope=scope,
            deny_fields=deny_fields,
            blocked_fields=blocked_fields,
            timestamp=timestamp,
            mode=mode,
        )
    except Exception:
        logger.error("Failed to record shield history")


def reset_store() -> None:
    """Reset the global store. For testing only."""
    global _store, _checked
    if _store is not None:
        _store.close()
    _store = None
    _checked = False
