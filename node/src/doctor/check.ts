// Deterministic boundary diagnosis — `check` (Node, v0). 1:1 mirror of
// python/src/aegis_trust/doctor/check.py.
//
// Given an ActionPlan and a LocalPolicy, return a BoundaryDecision. Pure, local,
// deterministic — no network, no LLM, no Core. The decision's `allowedData` is
// meant to be passed straight to `shield({ scope })`.
//
// v0 produces ALLOW / REDUCE_SCOPE / REQUIRE_APPROVAL / BLOCK. REQUIRE_CHECK is
// reserved for a later release.

import type { LocalPolicy } from "./policy.js";
import { BoundaryOutcome, DOCTOR_SCHEMA_VERSION } from "./types.js";
import type { ActionPlan, BoundaryDecision } from "./types.js";

/** Diagnose `plan` against `policy` and return a deterministic decision. */
export function check(plan: ActionPlan, policy: LocalPolicy = {}): BoundaryDecision {
  const requested = [...plan.dataRequested];

  // 1. Hard block: a forbidden field requested at all (e.g. secrets, .env).
  //    Fail-closed — the action does not proceed and no field is allowed.
  const never = policy.neverFields ?? [];
  if (requested.some((f) => never.includes(f))) {
    return {
      outcome: BoundaryOutcome.BLOCK,
      purpose: plan.purpose,
      allowedData: [],
      blockedData: requested,
      allowedTools: [],
      approvalRequiredFor: [],
      reasonCodes: ["FORBIDDEN_FIELD_REQUESTED"],
      policyVersion: "local-preview-v1",
      receiptRequired: true,
      schemaVersion: DOCTOR_SCHEMA_VERSION,
    };
  }

  // 2. Per-purpose allow/deny → the baseline allowed set.
  const rule = policy.purposes?.[plan.purpose];
  let allowed: string[];
  if (rule && rule.allow != null) {
    const allow = rule.allow;
    allowed = requested.filter((f) => allow.includes(f));
  } else if (rule && rule.deny && rule.deny.length > 0) {
    const deny = rule.deny;
    allowed = requested.filter((f) => !deny.includes(f));
  } else {
    allowed = [...requested];
  }

  // 3. Minimum disclosure to external destinations: strip sensitive fields
  //    before anything leaves the trust boundary.
  const sensitive = policy.sensitiveFields ?? [];
  const external = policy.externalDestinations ?? [];
  const goesExternal = (plan.destinations ?? []).some((d) => external.includes(d));
  if (goesExternal && sensitive.length > 0) {
    allowed = allowed.filter((f) => !sensitive.includes(f));
  }

  const blocked = requested.filter((f) => !allowed.includes(f));

  // 4. Approval seam: action-type rules.
  const approvalRequiredFor: string[] = [];
  if (policy.actions?.[plan.actionType]?.requiresApproval) {
    approvalRequiredFor.push(plan.actionType);
  }

  // 5. Reason codes + outcome (priority: approval > reduce > allow).
  const reasonCodes: string[] = [];
  if (blocked.length > 0) reasonCodes.push("DATA_NOT_REQUIRED_FOR_PURPOSE");
  if (goesExternal && requested.some((f) => sensitive.includes(f))) {
    reasonCodes.push("EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE");
  }
  if (approvalRequiredFor.length > 0) reasonCodes.push("ACTION_REQUIRES_HUMAN_APPROVAL");

  const outcome: BoundaryOutcome =
    approvalRequiredFor.length > 0
      ? BoundaryOutcome.REQUIRE_APPROVAL
      : blocked.length > 0
        ? BoundaryOutcome.REDUCE_SCOPE
        : BoundaryOutcome.ALLOW;

  return {
    outcome,
    purpose: plan.purpose,
    allowedData: allowed,
    blockedData: blocked,
    allowedTools: [...(plan.tools ?? [])],
    approvalRequiredFor,
    reasonCodes,
    policyVersion: "local-preview-v1",
    receiptRequired: outcome !== BoundaryOutcome.ALLOW || blocked.length > 0,
    schemaVersion: DOCTOR_SCHEMA_VERSION,
  };
}
