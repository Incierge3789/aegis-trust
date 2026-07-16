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

// Aegis-Api-Version dated header (Stripe-model dated API versioning).
// Clients send `Aegis-Api-Version: <YYYY-MM-DD>`; unset → SDK uses this
// default. Sunset: 18-month notice + 6-month deprecation warning.
// Lives here (leaf module) so client.ts and index.ts share ONE definition —
// client.ts previously hardcoded the date literal a second time, which would
// drift silently on the next version bump.
export const AEGIS_API_VERSION = "2026-05-18";
export const AEGIS_API_VERSION_HEADER = "Aegis-Api-Version";
