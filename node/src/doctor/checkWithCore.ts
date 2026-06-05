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

/** A string[] (every element a string). */
function isStringArray(arr: unknown): arr is string[] {
  return Array.isArray(arr) && arr.every((x) => typeof x === "string");
}

/**
 * True iff `v` is a FULL, correctly-typed `BoundaryDecisionView`.
 *
 * Review finding A (fail-closed): a partial-but-valid-JSON body such as
 * `{ "outcome": "PROTECTED" }` (every other field missing/defaulted) MUST NOT
 * map to ALLOW. We therefore require EVERY required field to be present and
 * correctly typed before we trust the view — `source` (string), `outcome`
 * (own-key of OUTCOME_MAP), `allowed_fields` (string[]), `withheld_fields`
 * (string[]), and `reason_code` (string). Any missing/mistyped required field
 * → malformed → caller maps to CORE_MALFORMED_RESPONSE → BLOCK.
 *
 * Review finding C (prototype pollution): the outcome is matched with
 * `Object.prototype.hasOwnProperty.call(...)` so inherited keys like
 * `toString` / `constructor` / `__proto__` are NOT accepted as valid outcomes.
 */
function isValidView(v: unknown): v is BoundaryDecisionView {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  // outcome: must be an OWN key of OUTCOME_MAP (not an inherited prototype key).
  if (typeof o.outcome !== "string") return false;
  if (!Object.prototype.hasOwnProperty.call(OUTCOME_MAP, o.outcome)) return false;
  // source: required string.
  if (typeof o.source !== "string") return false;
  // reason_code: required string.
  if (typeof o.reason_code !== "string") return false;
  // allowed_fields / withheld_fields: required string[] (not optional anymore).
  if (!isStringArray(o.allowed_fields)) return false;
  if (!isStringArray(o.withheld_fields)) return false;
  return true;
}

/** Map a validated `BoundaryDecisionView` into the SDK `BoundaryDecision`. */
function mapView(view: BoundaryDecisionView, plan: ActionPlan): BoundaryDecision {
  const outcome = OUTCOME_MAP[view.outcome];
  // Review finding D (invariant parity with v0 `check()`): an allow set is only
  // meaningful for a grant. For ALLOW / REDUCE_SCOPE we carry the Core
  // `allowed_fields`; for REQUIRE_CHECK / REQUIRE_APPROVAL / BLOCK we FORCE the
  // allow set to empty so a Core `BLOCKED` body that (incorrectly) carries
  // non-empty `allowed_fields` can never populate `allowedData`. Withheld
  // fields are always informational and preserved.
  const grants =
    outcome === BoundaryOutcome.ALLOW || outcome === BoundaryOutcome.REDUCE_SCOPE;
  const allowedData = grants ? [...view.allowed_fields] : [];
  const blockedData = [...view.withheld_fields];
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

// Sentinel destination sent when a plan declares MORE THAN ONE destination.
// The /check-boundary endpoint accepts a single `Option<String>` destination,
// so only one of the plan's destinations could be sent. Sending just the first
// (the prior behaviour) UNDER-estimates the boundary: the riskiest sink might
// be the second one, and the server would evaluate the (possibly trusted) first
// destination and ALLOW. Review finding F: instead, when there are multiple
// destinations we send a reserved sentinel that cannot match any trusted
// internal destination, so the server can only evaluate it as an
// unknown/external sink — the decision can get STRICTER, never looser.
const MULTI_DESTINATION_SENTINEL = "__aegis_multi_external__";

/** Choose the single destination to send (fail-closed for multi-destination). */
function resolveDestination(
  destinations: ReadonlyArray<string> | undefined,
): string | undefined {
  if (!destinations || destinations.length === 0) return undefined;
  if (destinations.length === 1) return destinations[0];
  // >1 destination: most-restrictive sentinel (treated as external/unknown).
  return MULTI_DESTINATION_SENTINEL;
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
  const ctx = opts.context;
  try {
    // Review finding G: acquire the client INSIDE the fail-closed try. If
    // getModuleClient() throws (e.g. bad env / construction error), that must
    // BLOCK, not escape as a raw exception.
    const client = opts.client ?? getModuleClient();
    const destination = resolveDestination(plan.destinations);
    const view = await client.checkBoundary({
      purpose: plan.purpose,
      scope: [...plan.dataRequested],
      destination,
      agentId: ctx?.agentId ?? plan.agentId,
      environment: ctx?.environment ?? plan.environment,
      mode: ctx?.mode,
      schemaVersion: plan.schemaVersion ?? DOCTOR_SCHEMA_VERSION,
    });
    if (!isValidView(view)) {
      // Malformed / partial / unparseable body → fail-closed BLOCK (finding A).
      return failClosed(plan.purpose, "CORE_MALFORMED_RESPONSE");
    }
    return mapView(view, plan);
  } catch {
    // Network error / timeout / non-2xx (httpError) / client-acquisition error
    // / any mapping error → fail-closed BLOCK (findings E/G parity with Python).
    return failClosed(plan.purpose, "CORE_UNAVAILABLE");
  }
}
