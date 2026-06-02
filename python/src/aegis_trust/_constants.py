"""Single-source schema/version constants for aegis-trust.

Leaf module (imports nothing from the package) so ``history.py`` / ``client.py``
/ ``__init__.py`` can all reference one canonical ``AUDIT_SCHEMA_VERSION``
without a circular import (S017 T4 / D-A: single-source; the audit-event
on-disk/on-wire shape version lives here, the package SemVer is independent).
"""

from __future__ import annotations

# Schema version for the audit-event shape emitted by HistoryStore (local
# SQLite) AND the /shield/ingest wire payload. Bump when the record shape
# changes (S017 D-B: stays 1 for the initial stamping). Readers treat a
# missing / NULL version as 1 (S017 D-C). NOT included in the idempotency
# _payload_hash (S017 D-D).
AUDIT_SCHEMA_VERSION = 1
