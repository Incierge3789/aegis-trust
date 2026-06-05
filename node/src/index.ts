// aegis-trust — TypeScript port of aegis-trust (PyPI).
//
// AI agent data access control. Control what agents can see based on
// declared purpose. Drop-in: one wrapper declares purpose; SDK enforces
// field-level access control.
//
// Quickstart:
//
//     import { shield } from "aegis-trust";
//
//     const safeGetUser = shield({
//       purpose: "show_profile",
//       scope: ["name", "email"],
//     })(async function getUser(id: number) {
//       return await db.users.find(id); // returns { id, name, email, ssn, ... }
//     });
//
//     const u = await safeGetUser(123);
//     // u → { name: "...", email: "..." }
//
// Lite mode: in-process dict filter, zero infrastructure, zero runtime
// deps. Full mode: filter + audit chain via AegisClient (aegis-core).

// Core decorator surface.
export { shield, wrap, syncPolicies, refreshToken, reset } from "./shield.js";

// Machine-parseable error model (v0.9.0-rc1).
export {
  AegisError,
  AegisValidationError,
  AegisConfigError,
  AegisIngestError,
  AegisAuditError,
  AegisHttpError,
  aegisDocsUrl,
  type AegisErrorPayload,
} from "./errors.js";

// Trace context propagation (v0.9.0-rc1).
export {
  type TraceContext,
  withTraceContext,
  getTraceContext,
  newTraceId,
} from "./trace.js";

// Mode enum + types (parity with aegis.types).
export { Mode } from "./types.js";
export type {
  AccessPolicy,
  AuditChainStatus,
  AuditEntry,
  FieldStats,
  FunctionStats,
  IngestEntry,
  IngestResponse,
  PathTree,
  PolicySyncEntry,
  PolicySyncResponse,
  PurposeStats,
  ShieldOptions,
  ShieldResult,
  ShieldStats,
} from "./types.js";

// AegisClient (Full mode HTTP wrapper, parity with aegis.client).
export {
  AegisClient,
  type AegisClientOptions,
  type MetricsHook,
  setMetricsHook,
  getModuleClient,
  detectMode,
  resetModuleClient,
  isDevHost,
  resolveVerifySsl,
  // userIntendsFull is the rc4-level intent heuristic (parity with PyPI
  // `_user_intends_full`). Re-exported in the barrel so the rc4 CHANGELOG
  // Migration recipe ("callers that import userIntendsFull directly from
  // aegis-trust") resolves against the public package surface. Without
  // this re-export, the Migration story is non-functional for npm
  // consumers (codex iter-1 cross-review P1 closure).
  userIntendsFull,
  // Doctor v1 (Core-backed) — boundary check wire types.
  type BoundaryDecisionView,
  type CoreBoundaryOutcome,
  type CoreDecisionEvidence,
  type CheckBoundaryArgs,
} from "./client.js";

// Config (YAML loader, parity with aegis.config).
export {
  loadConfig,
  getPurposePolicy,
  resetConfig,
  type PurposeConfig,
  type PurposeConfigScope,
  type PurposeConfigDeny,
} from "./config.js";

// History (local audit store, parity with aegis.history).
export {
  HistoryStore,
  type HistoryRecord,
  type HistoryStats,
  recordIfEnabled,
  resetStore,
} from "./history.js";

// Vitest plugin (parity with aegis.pytest_plugin).
export {
  useShieldHistory,
  assertShieldBlocked,
  assertShieldPassed,
  type ShieldRecord,
  type ShieldHistoryHandle,
} from "./vitestPlugin.js";

export const VERSION = "0.9.2";

// Schema version for the audit event format emitted by HistoryStore and
// the ingest endpoint payload. Bumped when audit record shape changes.
// API versioning doctrine §2: SemVer for the package, schema_version for
// the on-disk / on-wire audit event shape (independent axis).
export { AUDIT_SCHEMA_VERSION } from "./constants.js";

// Stability level — see docs/VERSIONING.md.
//   "preview"  → v0.x.y-rc* : public API may change between rc tags.
//   "stable"   → v1+        : SemVer breaking change rules apply.
//   "deprecated" → marked for removal in next major.
export const STABILITY_LEVEL: "preview" | "stable" | "deprecated" = "preview";

// Aegis-Api-Version dated header (Stripe-model dated API versioning).
// Date-based public contract version. Clients send `Aegis-Api-Version: <YYYY-MM-DD>`;
// unset → SDK uses this default.
// Sunset: 18-month notice + 6-month deprecation warning.
export const AEGIS_API_VERSION = "2026-05-18";
export const AEGIS_API_VERSION_HEADER = "Aegis-Api-Version";
