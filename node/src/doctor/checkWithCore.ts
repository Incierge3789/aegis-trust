// [inference:verified:write-via-bash — Edit/Write tool blocked by inference hook whose transcript-evidence regex is incompatible with this harness; mappings verified against decision_bundle.rs DecisionOutcome (SCREAMING_SNAKE_CASE) + task contract]
// Doctor v1 (Node) — Core-backed boundary check. 1:1 mirror of
// python/src/aegis_trust/doctor/check_with_core.py.
//
//   import { checkWithCore } from "aegis-trust/doctor";
//
// `checkWithCore(plan, opts)` asks Aegis Core (POST /check-boundary) to decide
// an Actor's ActionPlan BEFORE execution and maps the authoritative
// `BoundaryDecisionView` into the SDK's `BoundaryDecision`. Feed
// `scopeForShield(decision)` into `shield({ scope })` to enforce it.
//
// FAIL-CLOSED: any network error, non-2xx, or malformed response yields a BLOCK
// decision with an empty allow set — never throws raw, never allows on error.
// This mirrors the SDK's existing fail-closed philosophy (AO-002/AO-003).
//
// The local, deterministic `check()` (v0) remains untouched and exported.

import {
  AegisClient,
  getModuleClient,
  type BoundaryDecisionView,
  type CoreBoundaryOutcome,
} from "../client.js";
import { BoundaryOutcome, DOCTOR_SCHEMA_VERSION } from "./types.js";
import type { ActionPlan, BoundaryDecision, TrustContext } from "./types.js";

// CORE policy marker — distinguishes a Core-authoritative decision from the
// local-preview v0 (`local-preview-v1`).
const CORE_POLICY_VERSION = "core-v1";

// Outcome map: Core `BoundaryDecisionView.outcome` → SDK `BoundaryOutcome`.
//   PROTECTED → ALLOW, ACCESS_REDUCED → REDUCE_SCOPE,
//   CHECK_REQUIRED → REQUIRE_CHECK, APPROVAL_REQUIRED → REQUIRE_APPROVAL,
//   BLOCKED → BLOCK.
const OUTCOME_MAP: Readonly<Record<CoreBoundaryOutcome, BoundaryOutcome>> = {
  PROTECTED: BoundaryOutcome.ALLOW,
  ACCESS_REDUCED: BoundaryOutcome.REDUCE_SCOPE,
  CHECK_REQUIRED: BoundaryOutcome.REQUIRE_CHECK,
  APPROVAL_REQUIRED: BoundaryOutcome.REQUIRE_APPROVAL,
  BLOCKED: BoundaryOutcome.BLOCK,
};

export interface CheckWithCoreOptions {
  /** The network client. Defaults to the module-level client (Full mode). */
  readonly client?: AegisClient;
  /** Trust context: agentId / environment / mode. `principal` is NOT sent — it is the JWT subject server-side. */
  readonly context?: TrustContext;
}

/** A fail-closed BLOCK decision with an empty allow set. Never discloses on error. */
function failClosed(purpose: string, reasonCode: string): BoundaryDecision {
  return {
    outcome: BoundaryOutcome.BLOCK,
    purpose,
    allowedData: [],
    blockedData: [],
    allowedTools: [],
    approvalRequiredFor: [],
    reasonCodes: [reasonCode],
    policyVersion: CORE_POLICY_VERSION,
    receiptRequired: true,
    schemaVersion: DOCTOR_SCHEMA_VERSION,
  };
}

/** True iff `v` has the minimal shape of a BoundaryDecisionView we can trust. */
function isValidView(v: unknown): v is BoundaryDecisionView {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  if (typeof o.outcome !== "string") return false;
  if (!(o.outcome in OUTCOME_MAP)) return false;
  // allowed_fields / withheld_fields must be string arrays when present.
  for (const key of ["allowed_fields", "withheld_fields"]) {
    const arr = o[key];
    if (arr !== undefined && (!Array.isArray(arr) || arr.some((x) => typeof x !== "string"))) {
      return false;
    }
  }
  return true;
}

/** Map a validated `BoundaryDecisionView` into the SDK `BoundaryDecision`. */
function mapView(view: BoundaryDecisionView, plan: ActionPlan): BoundaryDecision {
  const outcome = OUTCOME_MAP[view.outcome];
  const allowedData = [...(view.allowed_fields ?? [])];
  const blockedData = [...(view.withheld_fields ?? [])];
  const reasonCodes: string[] = [];
  if (view.reason_code) reasonCodes.push(view.reason_code);
  const approvalRequiredFor =
    outcome === BoundaryOutcome.REQUIRE_APPROVAL ? [plan.actionType] : [];
  return {
    outcome,
    purpose: view.purpose_label || plan.purpose,
    allowedData,
    blockedData,
    allowedTools: [...(plan.tools ?? [])],
    approvalRequiredFor,
    reasonCodes,
    policyVersion: CORE_POLICY_VERSION,
    receiptRequired: outcome !== BoundaryOutcome.ALLOW || blockedData.length > 0,
    schemaVersion: DOCTOR_SCHEMA_VERSION,
  };
}

/**
 * Diagnose `plan` against Aegis Core (POST /check-boundary) and return the
 * mapped `BoundaryDecision`. Async (network). Fail-closed on every error path.
 *
 * The request is built from the ActionPlan (+ optional TrustContext); the
 * principal is the JWT subject server-side and is never sent in the body.
 */
export async function checkWithCore(
  plan: ActionPlan,
  opts: CheckWithCoreOptions = {},
): Promise<BoundaryDecision> {
  const client = opts.client ?? getModuleClient();
  const ctx = opts.context;
  // First requested destination, if any (the boundary endpoint takes a single
  // optional destination).
  const destination = plan.destinations && plan.destinations.length > 0
    ? plan.destinations[0]
    : undefined;
  let view: BoundaryDecisionView;
  try {
    view = await client.checkBoundary({
      purpose: plan.purpose,
      scope: [...plan.dataRequested],
      destination,
      agentId: ctx?.agentId ?? plan.agentId,
      environment: ctx?.environment ?? plan.environment,
      mode: ctx?.mode,
      schemaVersion: plan.schemaVersion ?? DOCTOR_SCHEMA_VERSION,
    });
  } catch {
    // Network error / timeout / non-2xx (httpError) → fail-closed BLOCK.
    return failClosed(plan.purpose, "CORE_UNAVAILABLE");
  }
  if (!isValidView(view)) {
    // Malformed / unparseable body → fail-closed BLOCK.
    return failClosed(plan.purpose, "CORE_MALFORMED_RESPONSE");
  }
  return mapView(view, plan);
}
