// A2A extension — Aegis boundary decision → A2A TaskState mapping (v0, prerelease).
//
// WHAT THIS IS. A2A filled transport; the decision and evidence seats in the
// protocol are empty. This module reports an Aegis boundary decision using A2A's
// OWN vocabulary: an existing `TaskState` plus a substate in `metadata`. The A2A
// extension spec forbids adding enum values, so nothing here invents one.
//
// WHAT THIS IS NOT. Carrying this extension does not prove enforcement. An A2A
// extension is a vocabulary the client activates with the `A2A-Extensions`
// header; it is not an admission control. Aegis's enforcement comes from the
// gateway path, not from a header. Anyone can name an extension URI and emit a
// structurally valid `outcome: PROTECTED` — a recipient learns what was
// *reported*, by whoever emitted it, and nothing more.
//
// STATE OWNERSHIP. `taskStateRecommendation === null` means the mapping sets no
// state. PROTECTED and ACCESS_REDUCED do not make a task successful: only the
// task executor knows whether a withheld field was required for the requested
// result, so the mapping never selects a terminal state on its behalf.
//
// FAIL-CLOSED. Unknown outcomes, unknown reason codes, and (outcome, reason_code)
// pairs the decision engine cannot produce are rejected, never guessed. The
// legal pair set is 7, not 5x6, because the engine derives reason_code from the
// outcome (`ReasonCode::derive`) and only BLOCKED branches. Pinned corpus:
// conformance/a2a_mapping.v0.json.
//
// Normative sources, pinned:
//   A2A spec        a2aproject/A2A@0ef1b02 (in-task authorization is §7.6)
//   decision engine aegis-boundary-core@324efd18
//                   engine/aegis-decision/src/decision.rs:118-142

import { AegisError, aegisDocsUrl } from "../errors.js";

/** Decision outcomes the boundary can report. */
export type DecisionOutcome =
  | "PROTECTED"
  | "ACCESS_REDUCED"
  | "CHECK_REQUIRED"
  | "APPROVAL_REQUIRED"
  | "BLOCKED";

/** Reason codes on the check-boundary surface. */
export type ReasonCode =
  | "minimum_disclosure"
  | "policy_denied"
  | "approval_required"
  | "check_required"
  | "invalid_scope"
  | "internal_failure";

/**
 * Who obtains the approval.
 *
 * `"client"` — the boundary is asking its A2A client to fulfil the
 * authorization. A2A §7.6.1 makes `TASK_STATE_AUTH_REQUIRED` a MUST for this,
 * and taking that state also takes its obligations (explain the request in
 * `TaskStatus`, arrange out-of-band credential receipt, accept messages on the
 * task, resume/stream).
 *
 * `"agent"` — the boundary is resolving the approval itself (its own approver,
 * its own channel). §7.6 frames `AUTH_REQUIRED` as *delegating* fulfilment to
 * the client — a fallback path — so an internally-held approval must NOT
 * interrupt the client. The task stays `WORKING`.
 */
export type FulfillmentOwner = "client" | "agent";

/** A2A `TaskState` values this mapping can recommend. Never a new enum value. */
export type TaskStateRecommendation =
  | "TASK_STATE_WORKING"
  | "TASK_STATE_INPUT_REQUIRED"
  | "TASK_STATE_AUTH_REQUIRED"
  | "TASK_STATE_REJECTED"
  | "TASK_STATE_FAILED";

/** Whether the client can repair the request, or the outcome is final. */
export type Disposition = "terminal" | "correctable";

/** A boundary decision, as far as this mapping needs it. */
export interface BoundaryDecisionInput {
  readonly outcome: string;
  readonly reason_code?: string;
  /** Field NAMES only, never payload values. */
  readonly withheld_fields?: readonly string[];
  readonly fulfillment_owner?: string;
}

/**
 * The substate carried in A2A `metadata`.
 *
 * Payload-value-omitting: it carries field *names*, an outcome, and a reason
 * code. That is not the same as carrying no information — a field-name set
 * discloses schema shape, reason codes disclose policy posture, and counts and
 * timings disclose access patterns. Do not describe it as "value-free".
 */
export interface DecisionSubstate {
  readonly outcome: DecisionOutcome;
  readonly reason_code: ReasonCode;
  readonly withheld_fields?: readonly string[];
  readonly fulfillment_owner?: FulfillmentOwner;
  readonly disposition?: Disposition;
}

/** Result of mapping one decision. A recommendation, not a state assignment. */
export interface DecisionMapping {
  /** `null` = the mapping sets no state; the executor decides. */
  readonly taskStateRecommendation: TaskStateRecommendation | null;
  /** Whether this decision stops the task from proceeding as asked. */
  readonly haltsTask: boolean;
  readonly substate: DecisionSubstate;
}

const OUTCOMES: readonly string[] = [
  "PROTECTED",
  "ACCESS_REDUCED",
  "CHECK_REQUIRED",
  "APPROVAL_REQUIRED",
  "BLOCKED",
];

const REASON_CODES: readonly string[] = [
  "minimum_disclosure",
  "policy_denied",
  "approval_required",
  "check_required",
  "invalid_scope",
  "internal_failure",
];

/**
 * The pairs the decision engine can actually produce — 7, not 30.
 *
 * `ReasonCode::derive(outcome, reason_text)` maps PROTECTED and ACCESS_REDUCED
 * to `minimum_disclosure`, APPROVAL_REQUIRED to `approval_required`,
 * CHECK_REQUIRED to `check_required`, and branches only for BLOCKED.
 */
export const LEGAL_OUTCOME_REASON_PAIRS: ReadonlyArray<
  readonly [DecisionOutcome, ReasonCode]
> = [
  ["PROTECTED", "minimum_disclosure"],
  ["ACCESS_REDUCED", "minimum_disclosure"],
  ["CHECK_REQUIRED", "check_required"],
  ["APPROVAL_REQUIRED", "approval_required"],
  ["BLOCKED", "policy_denied"],
  ["BLOCKED", "invalid_scope"],
  ["BLOCKED", "internal_failure"],
];

const LEGAL_PAIR_KEYS: ReadonlySet<string> = new Set(
  LEGAL_OUTCOME_REASON_PAIRS.map(([o, r]) => `${o} ${r}`),
);

/** Error thrown for anything this mapping refuses to guess about. */
export class A2AMappingError extends AegisError {
  constructor(code: string, message: string, remediation: string) {
    super({ code, message, remediation, docs_url: aegisDocsUrl(code) });
    this.name = "A2AMappingError";
  }
}

/**
 * Fail-closed validation of an (outcome, reason_code) pair.
 *
 * Scoped to the check-boundary vocabulary on purpose. Other gateway surfaces
 * emit reason codes outside this enum (`capsule_scope_denied`, for one), so a
 * permissive "anything seen on the wire" allowlist would let a foreign
 * vocabulary drive A2A task state.
 */
export function validateOutcomeReason(
  outcome: string,
  reasonCode: string | undefined,
): { readonly outcome: DecisionOutcome; readonly reason_code: ReasonCode } {
  if (!OUTCOMES.includes(outcome)) {
    throw new A2AMappingError(
      "unknown_outcome",
      `Unknown decision outcome: ${JSON.stringify(outcome)}.`,
      "Do not map unknown outcomes to a TaskState. Upgrade the SDK to a version whose mapping covers this engine, or handle the decision outside the A2A extension.",
    );
  }
  if (reasonCode === undefined || !REASON_CODES.includes(reasonCode)) {
    throw new A2AMappingError(
      "unknown_reason_code",
      `Unknown or missing reason_code: ${JSON.stringify(reasonCode ?? null)}.`,
      "The A2A mapping is scoped to the check-boundary reason vocabulary. Reason codes from other surfaces must not be mapped here.",
    );
  }
  if (!LEGAL_PAIR_KEYS.has(`${outcome} ${reasonCode}`)) {
    throw new A2AMappingError(
      "illegal_outcome_reason_pair",
      `The decision engine cannot produce outcome ${outcome} with reason_code ${reasonCode}.`,
      "Treat this as a malformed or foreign decision, not as a task state. See conformance/a2a_mapping.v0.json for the 7 legal pairs.",
    );
  }
  return { outcome: outcome as DecisionOutcome, reason_code: reasonCode as ReasonCode };
}

/**
 * Map one boundary decision to an A2A `TaskState` recommendation + substate.
 *
 * Deterministic and side-effect free: same input, same output, no I/O.
 */
export function mapDecisionToA2A(decision: BoundaryDecisionInput): DecisionMapping {
  // A non-object decision (null, a scalar, an array) is a malformed input, not
  // a crash site (round-3 codex): TypeScript's type does not survive JSON, so
  // `decision.outcome` on a null would throw a raw TypeError and abort a whole
  // event stream. Coerce to an A2AMappingError, matching the Python mirror.
  if (typeof decision !== "object" || decision === null || Array.isArray(decision)) {
    throw new A2AMappingError(
      "unknown_outcome",
      `Decision must be an object; got ${JSON.stringify(decision ?? null)}.`,
      "Pass a boundary decision object with an outcome and reason_code.",
    );
  }
  const { outcome, reason_code } = validateOutcomeReason(
    decision.outcome,
    decision.reason_code,
  );

  switch (outcome) {
    case "PROTECTED":
      return {
        taskStateRecommendation: null,
        haltsTask: false,
        substate: { outcome, reason_code },
      };

    case "ACCESS_REDUCED": {
      // Validate the SHAPE, not just presence (round-3 codex): a string
      // `withheld_fields` spreads to ["s","s","n"] and would ship as field
      // names. Python already rejects this as `invalid_withheld_fields`;
      // TypeScript must too, or the same wire input diverges by language.
      const wf = decision.withheld_fields;
      if (
        wf !== undefined &&
        (!Array.isArray(wf) || wf.some((f) => typeof f !== "string" || f.length === 0))
      ) {
        throw new A2AMappingError(
          "invalid_withheld_fields",
          "withheld_fields must be a sequence of non-empty field names.",
          "Pass field NAMES only, never payload values, and never a bare string.",
        );
      }
      return {
        taskStateRecommendation: null,
        haltsTask: false,
        substate: {
          outcome,
          reason_code,
          ...(wf === undefined ? {} : { withheld_fields: [...wf] }),
        },
      };
    }

    case "CHECK_REQUIRED":
      // The boundary runs the check. WORKING is the only state that means
      // "still processing, you need do nothing".
      return {
        taskStateRecommendation: "TASK_STATE_WORKING",
        haltsTask: false,
        substate: { outcome, reason_code },
      };

    case "APPROVAL_REQUIRED": {
      const owner = decision.fulfillment_owner;
      if (owner === undefined) {
        throw new A2AMappingError(
          "missing_fulfillment_owner",
          "APPROVAL_REQUIRED needs fulfillment_owner to choose a TaskState.",
          "Set fulfillment_owner to 'client' when asking the A2A client to fulfil the authorization (A2A §7.6.1 → AUTH_REQUIRED), or 'agent' when the boundary resolves it internally (stays WORKING). Guessing either way is a protocol error.",
        );
      }
      if (owner !== "client" && owner !== "agent") {
        throw new A2AMappingError(
          "unknown_fulfillment_owner",
          `Unknown fulfillment_owner: ${JSON.stringify(owner)}.`,
          "Only 'client' and 'agent' are defined.",
        );
      }
      return {
        taskStateRecommendation:
          owner === "client" ? "TASK_STATE_AUTH_REQUIRED" : "TASK_STATE_WORKING",
        haltsTask: owner === "client",
        substate: { outcome, reason_code, fulfillment_owner: owner },
      };
    }

    case "BLOCKED": {
      if (reason_code === "internal_failure") {
        // Fail-secure refusal on an internal error IS an error, and must stay
        // distinguishable from a policy refusal in the audit trail.
        return {
          taskStateRecommendation: "TASK_STATE_FAILED",
          haltsTask: true,
          substate: { outcome, reason_code, disposition: "terminal" },
        };
      }
      if (reason_code === "invalid_scope") {
        // A scope that could not be resolved is a request defect the client can
        // repair. REJECTED is terminal and would foreclose the repair.
        return {
          taskStateRecommendation: "TASK_STATE_INPUT_REQUIRED",
          haltsTask: true,
          substate: { outcome, reason_code, disposition: "correctable" },
        };
      }
      // policy_denied — a decision, not an error, and not repairable.
      return {
        taskStateRecommendation: "TASK_STATE_REJECTED",
        haltsTask: true,
        substate: { outcome, reason_code, disposition: "terminal" },
      };
    }
  }
}
