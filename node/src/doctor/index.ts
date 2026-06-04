// aegis-trust Doctor (Node) — pre-action boundary diagnosis.
//
//   import { check, type ActionPlan, type LocalPolicy } from "aegis-trust/doctor";
//
// `check(plan, policy)` diagnoses an Actor's action plan BEFORE execution and
// returns a deterministic, local BoundaryDecision. Feed `decision.allowedData`
// into `shield({ scope })` to enforce it.
//
// Doctor v0 is LITE-only, deterministic, and has no Core dependency.
// Authoritative enforcement and formal Evidence remain Aegis Core's job.

export { check } from "./check.js";
export { BoundaryOutcome, DOCTOR_SCHEMA_VERSION, toReceipt } from "./types.js";
export type {
  ActionPlan,
  BoundaryDecision,
  BoundaryReceipt,
  TrustContext,
} from "./types.js";
export type { ActionRule, LocalPolicy, PurposeRule } from "./policy.js";
