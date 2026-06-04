// Boundary contracts for the Doctor primitive (Node). 1:1 mirror of
// python/src/aegis_trust/doctor/types.py.
//
// These versioned objects are the shared data contract that shield / doctor /
// receipt (and, later, Core) all read and write. `schemaVersion` lets the shape
// evolve without breaking consumers.
//
// Doctor v0 is LITE-only and deterministic: `check(plan, policy)` returns a
// BoundaryDecision whose `allowedData` feeds `shield({ scope })`. No Core
// dependency, no LLM in this path.

export const DOCTOR_SCHEMA_VERSION = 1;

/**
 * Doctor verdict. Maps 1:1 to the aegis-core UI outcome language:
 * ALLOW→PROTECTED, REDUCE_SCOPE→ACCESS_REDUCED, REQUIRE_CHECK→CHECK_REQUIRED,
 * REQUIRE_APPROVAL→APPROVAL_REQUIRED, BLOCK→BLOCKED. `REQUIRE_CHECK` is reserved
 * (not produced by v0).
 */
export const BoundaryOutcome = {
  ALLOW: "ALLOW",
  REDUCE_SCOPE: "REDUCE_SCOPE",
  REQUIRE_CHECK: "REQUIRE_CHECK",
  REQUIRE_APPROVAL: "REQUIRE_APPROVAL",
  BLOCK: "BLOCK",
} as const;
export type BoundaryOutcome = (typeof BoundaryOutcome)[keyof typeof BoundaryOutcome];

/** Who is acting, for what purpose, in which environment. `principal` is unused locally (LITE); Core binds it to an authenticated subject. */
export interface TrustContext {
  readonly agentId: string;
  readonly purpose: string;
  readonly environment?: string;
  readonly mode?: string;
  readonly principal?: string | null;
  readonly schemaVersion?: number;
}

/** What an Actor is about to do — the input to `check`. Declared intent, not the data itself. */
export interface ActionPlan {
  readonly purpose: string;
  readonly actionType: string;
  readonly dataRequested: ReadonlyArray<string>;
  readonly tools?: ReadonlyArray<string>;
  readonly destinations?: ReadonlyArray<string>;
  readonly sideEffects?: ReadonlyArray<string>;
  readonly agentId?: string;
  readonly environment?: string;
  readonly schemaVersion?: number;
}

/** What doctor (local) or Core (authoritative) decided. `allowedData` is the scope to hand to `shield`. */
export interface BoundaryDecision {
  readonly outcome: BoundaryOutcome;
  readonly purpose: string;
  readonly allowedData: ReadonlyArray<string>;
  readonly blockedData: ReadonlyArray<string>;
  readonly allowedTools: ReadonlyArray<string>;
  readonly approvalRequiredFor: ReadonlyArray<string>;
  readonly reasonCodes: ReadonlyArray<string>;
  readonly policyVersion: string;
  readonly receiptRequired: boolean;
  readonly schemaVersion: number;
}

/** A locally-verifiable record of a boundary decision. `evidenceMode` is `local` and `coreVerified` is false until Core issues formal Evidence — LITE must never claim Core's authority. */
export interface BoundaryReceipt {
  readonly receiptId: string;
  readonly outcome: BoundaryOutcome;
  readonly purpose: string;
  readonly allowedData: ReadonlyArray<string>;
  readonly blockedData: ReadonlyArray<string>;
  readonly approvalRequiredFor: ReadonlyArray<string>;
  readonly reasonCodes: ReadonlyArray<string>;
  readonly policyVersion: string;
  readonly enforcementStatus: string;
  readonly evidenceMode: string;
  readonly coreVerified: boolean;
  readonly schemaVersion: number;
}

/**
 * The scope that may be handed to `shield` — enforcement-coupled (parity with
 * Python `BoundaryDecision.scope_for_shield`).
 *
 * `allowedData` is a *diagnostic* field: it is populated even for
 * `REQUIRE_APPROVAL` and `BLOCK` so a caller can show *what would have been
 * allowed*. Passing that diagnostic straight into `shield({ scope })` would let
 * data flow **before** a required human approval, or **after** a hard block —
 * decoupling the decision from enforcement. This accessor returns the scope
 * **only** when the outcome actually permits the action to proceed (`ALLOW` /
 * `REDUCE_SCOPE`); otherwise it returns an empty array, so the safe pattern
 * `shield({ scope: scopeForShield(decision) })` discloses nothing until the
 * gate is cleared. Use this, not `allowedData`, to drive enforcement.
 */
export function scopeForShield(decision: BoundaryDecision): string[] {
  if (
    decision.outcome === BoundaryOutcome.ALLOW
    || decision.outcome === BoundaryOutcome.REDUCE_SCOPE
  ) {
    return [...decision.allowedData];
  }
  return [];
}

/** Build a {@link BoundaryReceipt} from a decision (parity with Python `BoundaryDecision.to_receipt`). */
export function toReceipt(
  decision: BoundaryDecision,
  opts: { readonly receiptId: string; readonly enforcementStatus?: string },
): BoundaryReceipt {
  return {
    receiptId: opts.receiptId,
    outcome: decision.outcome,
    purpose: decision.purpose,
    allowedData: [...decision.allowedData],
    blockedData: [...decision.blockedData],
    approvalRequiredFor: [...decision.approvalRequiredFor],
    reasonCodes: [...decision.reasonCodes],
    policyVersion: decision.policyVersion,
    enforcementStatus: opts.enforcementStatus ?? "PENDING",
    evidenceMode: "local",
    coreVerified: false,
    schemaVersion: DOCTOR_SCHEMA_VERSION,
  };
}
