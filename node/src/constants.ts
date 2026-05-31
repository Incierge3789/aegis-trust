// Single-source schema/version constants for aegis-trust (parity with
// python `aegis_trust/_constants.py`). Leaf module — imported by index.ts
// (re-export), history.ts, and client.ts so `AUDIT_SCHEMA_VERSION` has exactly
// one definition (S017 T4 / D-A).
//
// Schema version for the audit-event shape emitted by HistoryStore (local
// JSONL) AND the /shield/ingest wire payload. Bump when the record shape
// changes (S017 D-B: stays 1 for the initial stamping). Readers treat a
// missing version as 1 (S017 D-C). NOT part of the idempotency `_payloadHash`
// (S017 D-D).
export const AUDIT_SCHEMA_VERSION = 1;
