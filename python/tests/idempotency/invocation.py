"""Invocation script for productization-ops idempotency_guarantee verifier (Python SDK).

Mirrors node/tests/idempotency/invocation.py contract: the verifier copies this
file to <package-dir>/.productization_idempotency_test.tmp and runs it under
python3 with cwd = the python SDK package directory.

Invariant under test: calling HistoryStore.record_idempotent with the same
idempotency_key across 1 initial + 100 retries must result in exactly one
appended record. The observable state_file (written by this script) must remain
byte-identical across all retries after the initial run.

State_file format: deterministic JSONL snapshot of all audit rows projected to
fields that are invariant under idempotent retry (function, purpose, scope,
deny_fields, blocked_fields, mode, idempotency_key). Timestamp and SQLite row
id are excluded because they would differ across the initial-vs-retry boundary
if the system clock or auto-increment counter advanced. The hash compares only
the idempotent payload, which is what the verifier semantically cares about.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    state_file = os.environ.get("AEGIS_IDEMPOTENCY_STATE_FILE")
    if not state_file:
        print("AEGIS_IDEMPOTENCY_STATE_FILE env var not set", file=sys.stderr)
        return 1

    state_path = Path(state_file)
    db_path = state_path.with_suffix(".sqlite")

    # Allow running from anywhere — caller (verifier) sets cwd to the python
    # SDK package dir, so the freshly-built source is importable from src/.
    sdk_src = Path.cwd() / "src"
    if sdk_src.is_dir():
        sys.path.insert(0, str(sdk_src))

    from aegis_trust.history import HistoryStore

    store = HistoryStore(db_path)
    try:
        store.record_idempotent(
            function="fixedFn",
            purpose="support",
            scope=["name", "email"],
            deny_fields=[],
            blocked_fields=[],
            timestamp="2026-05-25T00:00:00Z",
            mode="LITE",
            idempotency_key="fixed-test-key-001",
        )

        records = store.get_history(limit=1000)
        rows = []
        for r in records:
            rows.append(
                {
                    "function": r.function,
                    "purpose": r.purpose,
                    "scope": sorted(r.scope),
                    "deny_fields": sorted(r.deny_fields),
                    "blocked_fields": sorted(r.blocked_fields),
                    "mode": r.mode,
                }
            )
        rows.sort(key=lambda x: (x["function"], x["purpose"]))

        with open(state_file, "w") as f:
            for row in rows:
                f.write(json.dumps(row, sort_keys=True) + "\n")
    finally:
        store.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
