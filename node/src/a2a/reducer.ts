// A2A task-state reducer — obligation lifecycle + approval credential binding.
//
// "Only a decision that halts the task drives TaskState" is prose. This module
// is the computable form (S027 T-007): a deterministic reducer over (prior
// state, prior obligations, event sequence) with two required properties and
// one deliberate non-property.
//
// REQUIRED: terminal monotonicity. Once a terminal state is reached, no later
// event changes it. Post-terminal events are recorded as rejected, never
// applied.
//
// REQUIRED: causal ordering. A `resolved` / `rejected` / `expired` closure with
// no matching OPEN obligation is REJECTED, never remembered. The tempting
// alternative — keep an early `resolved` as a tombstone so that order does not
// matter — is an attack surface: an approval credential replayed from an
// earlier task would pre-resolve the obligation, the boundary's later genuine
// APPROVAL_REQUIRED would be swallowed, and the destructive action would
// proceed with every "order invariance" property still satisfied.
//
// NON-PROPERTY: order invariance is NOT required across obligation events.
// It holds only for commuting decision events (PROTECTED / ACCESS_REDUCED /
// CHECK_REQUIRED carry no interrupt and may permute freely).
//
// Obligations are identified by the full 7-field tuple (task, context,
// requesting agent, request digest, correlation id, generation, server nonce),
// and a credential must carry a binding that equals the OPEN obligation's tuple
// exactly. This module checks BINDING, not issuer authenticity: authenticating
// who signed a credential requires keys, and keyed verification is Aegis Core
// territory. A keyless (LITE) reducer that claimed issuer authentication would
// be the overclaim this sprint exists to prevent.
//
// The reducer never selects a success state. `TASK_STATE_COMPLETED` is the task
// executor's call after output validation (round 2 / F3); the reducer's most
// permissive output is `TASK_STATE_WORKING`.
//
// Normative sources, pinned:
//   A2A spec  a2aproject/A2A@0ef1b02 — §7.6 (in-task authorization; AUTH_REQUIRED
//             delegates fulfilment to the client), §7.6.1 (producer MUSTs).
//   Mapping   ./mapping.ts (decision → recommendation), which this reducer
//             composes over a whole event sequence.

import { AegisError, aegisDocsUrl } from "../errors.js";
import {
  A2AMappingError,
  mapDecisionToA2A,
  type BoundaryDecisionInput,
  type DecisionSubstate,
  type TaskStateRecommendation,
} from "./mapping.js";
import { assertNoEnforcementClaim } from "./extension.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** All nine A2A `TaskState` values (spec a2a.proto:187-208). */
export type A2ATaskStateValue =
  | "TASK_STATE_UNSPECIFIED"
  | "TASK_STATE_SUBMITTED"
  | "TASK_STATE_WORKING"
  | "TASK_STATE_COMPLETED"
  | "TASK_STATE_FAILED"
  | "TASK_STATE_CANCELED"
  | "TASK_STATE_INPUT_REQUIRED"
  | "TASK_STATE_REJECTED"
  | "TASK_STATE_AUTH_REQUIRED";

/** Spec-declared terminal states. The reducer freezes on any of these. */
export const TERMINAL_TASK_STATES: readonly A2ATaskStateValue[] = [
  "TASK_STATE_COMPLETED",
  "TASK_STATE_FAILED",
  "TASK_STATE_CANCELED",
  "TASK_STATE_REJECTED",
];

/**
 * The identity of one authorization obligation. All seven fields participate
 * in identity, and a credential binds to the whole tuple — a credential minted
 * for another task, another generation, or another server nonce does not match.
 * `server_nonce` is issued by the boundary when it OPENS the obligation, which
 * is what makes a pre-played credential unable to name it.
 */
export interface ObligationKey {
  readonly task_id: string;
  readonly context_id: string;
  readonly requesting_agent: string;
  /** Digest of the halted request — an opaque reference, never the payload. */
  readonly request_digest: string;
  readonly correlation_id: string;
  /** Re-issue counter. A re-issued approval is a NEW obligation (gen+1). */
  readonly generation: number;
  readonly server_nonce: string;
}

/** How an open obligation closed. */
export type ObligationClosure = "resolved" | "rejected" | "expired";

export type ObligationState = "open" | ObligationClosure;

export interface Obligation {
  readonly key: ObligationKey;
  readonly state: ObligationState;
}

/**
 * The object that represents the approved authorization (A2A §7.6 calls this
 * the credential; it arrives out-of-band). The reducer accepts it only when
 * `binding` equals the open obligation's key exactly.
 */
export interface ApprovalCredential {
  readonly binding: ObligationKey;
}

/** A decision made by the boundary, in event form. */
export interface DecisionEvent {
  readonly kind: "decision";
  readonly decision: BoundaryDecisionInput;
  /**
   * Required when the decision is APPROVAL_REQUIRED with fulfilment delegated
   * to the client: the obligation this decision opens.
   */
  readonly obligation?: ObligationKey;
}

/** Closure of a previously opened obligation. */
export interface ObligationEvent {
  readonly kind: "obligation";
  readonly closure: ObligationClosure;
  readonly key: ObligationKey;
  /** Required for `resolved`. Ignored for `rejected` / `expired`. */
  readonly credential?: ApprovalCredential;
}

export type A2ATaskEvent = DecisionEvent | ObligationEvent;

/** An event the reducer refused to apply, and why. The stream continues. */
export interface RejectedEvent {
  readonly index: number;
  readonly code: string;
  readonly message: string;
}

export interface TaskReductionInput {
  readonly task_id: string;
  readonly context_id: string;
  /** Checkpoint state from an earlier reduction. Terminal values freeze. */
  readonly prior_state?: A2ATaskStateValue | null;
  /**
   * Obligations carried from an earlier reduction. Only `open` ones pin the
   * task; closed ones may be carried for audit and behave as closed.
   */
  readonly prior_obligations?: readonly Obligation[];
  /**
   * The unresolved-halt fact from the checkpoint this reduction resumes
   * (round-3 codex). A denied/expired obligation holds the halt until the
   * boundary speaks again; that fact cannot be reconstructed from
   * `(prior_state, prior_obligations)` alone, because a rejected sibling next
   * to an OPEN one looks identical to a task that is merely waiting on the
   * open one. A checkpoint MUST persist `TaskReduction.unresolved_halt` and
   * pass it back here. When omitted, it is reconstructed with the lossy
   * heuristic (AUTH_REQUIRED with no open obligation) for backward
   * compatibility only.
   */
  readonly prior_unresolved_halt?: boolean;
  readonly events: readonly A2ATaskEvent[];
}

/** States the reducer itself can output. Success states are not among them. */
export type ReducedTaskState = TaskStateRecommendation | A2ATaskStateValue;

export interface TaskReduction {
  /** `null` = nothing observed constrains the state; the executor decides. */
  readonly task_state: ReducedTaskState | null;
  readonly obligations: readonly Obligation[];
  readonly rejected_events: readonly RejectedEvent[];
  /** Substates of the applied decision events, in application order. */
  readonly substates: readonly DecisionSubstate[];
  /**
   * Whether a denial/expiry is still holding the halt. Persist this in the
   * checkpoint and pass it back as `prior_unresolved_halt` — see that field.
   */
  readonly unresolved_halt: boolean;
}

/** Input-shape failure (the whole reduction is malformed, not one event). */
export class A2AReducerError extends AegisError {
  constructor(code: string, message: string, remediation: string) {
    super({ code, message, remediation, docs_url: aegisDocsUrl(code) });
    this.name = "A2AReducerError";
  }
}

// ---------------------------------------------------------------------------
// Obligation key helpers
// ---------------------------------------------------------------------------

const KEY_FIELDS = [
  "task_id",
  "context_id",
  "requesting_agent",
  "request_digest",
  "correlation_id",
  "server_nonce",
] as const;

function obligationKeyProblem(key: unknown): string | null {
  if (typeof key !== "object" || key === null || Array.isArray(key)) {
    return "obligation key must be an object";
  }
  const k = key as Record<string, unknown>;
  for (const f of KEY_FIELDS) {
    if (typeof k[f] !== "string" || (k[f] as string).length === 0) {
      return `obligation key field ${f} must be a non-empty string`;
    }
  }
  if (typeof k.generation !== "number" || !Number.isInteger(k.generation) || k.generation < 1) {
    return "obligation key field generation must be an integer >= 1";
  }
  return null;
}

function keyId(key: ObligationKey): string {
  return JSON.stringify([
    key.task_id,
    key.context_id,
    key.requesting_agent,
    key.request_digest,
    key.correlation_id,
    key.generation,
    key.server_nonce,
  ]);
}

/** Exact 7-field equality — the whole binding, or no binding. */
export function obligationKeysEqual(a: ObligationKey, b: ObligationKey): boolean {
  return keyId(a) === keyId(b);
}

// ---------------------------------------------------------------------------
// The reducer
// ---------------------------------------------------------------------------

function isTerminal(state: A2ATaskStateValue | TaskStateRecommendation): boolean {
  return (TERMINAL_TASK_STATES as readonly string[]).includes(state);
}

/**
 * Reduce an event sequence to a task-state recommendation + obligation set.
 *
 * Deterministic and side-effect free. Per-event failures are RECORDED in
 * `rejected_events` and the stream continues — throwing on the first bad event
 * would let an attacker-injected event destroy the genuine ones behind it
 * (the pre-play vector depends on exactly that survival).
 */
export function reduceTaskState(input: TaskReductionInput): TaskReduction {
  if (typeof input.task_id !== "string" || input.task_id.length === 0) {
    throw new A2AReducerError(
      "invalid_reduction_input",
      "task_id must be a non-empty string.",
      "Reduce one task at a time; the task id scopes every obligation check.",
    );
  }
  if (typeof input.context_id !== "string" || input.context_id.length === 0) {
    throw new A2AReducerError(
      "invalid_reduction_input",
      "context_id must be a non-empty string.",
      "Reduce one task at a time; the context id scopes every obligation check.",
    );
  }

  const obligations = new Map<string, Obligation>();
  for (const ob of input.prior_obligations ?? []) {
    const problem = obligationKeyProblem(ob.key);
    if (problem !== null) {
      throw new A2AReducerError(
        "invalid_obligation_key",
        `Prior obligation is malformed: ${problem}.`,
        "Carry obligations exactly as a previous reduction returned them.",
      );
    }
    if (ob.key.task_id !== input.task_id || ob.key.context_id !== input.context_id) {
      throw new A2AReducerError(
        "foreign_task_obligation",
        "Prior obligation belongs to a different task or context.",
        "Obligations never cross tasks. Reduce each task with its own obligations.",
      );
    }
    if (!["open", "resolved", "rejected", "expired"].includes(ob.state)) {
      throw new A2AReducerError(
        "invalid_obligation_key",
        `Prior obligation has unknown state ${JSON.stringify(ob.state)}.`,
        "Only open / resolved / rejected / expired are defined.",
      );
    }
    const id = keyId(ob.key);
    if (obligations.has(id)) {
      throw new A2AReducerError(
        "duplicate_obligation",
        "The same obligation key appears twice in prior_obligations.",
        "An obligation tuple identifies exactly one obligation.",
      );
    }
    obligations.set(id, ob);
  }

  // Frozen terminal state, if any.
  let terminal: A2ATaskStateValue | TaskStateRecommendation | null =
    input.prior_state != null && isTerminal(input.prior_state) ? input.prior_state : null;

  // A rejected/expired obligation holds the halt until the boundary speaks
  // again (a denied approval must not quietly resume the task). The
  // checkpoint carries this fact explicitly; only when it is absent do we fall
  // back to the lossy heuristic (a prior AUTH_REQUIRED with no open obligation
  // carried), which cannot see a denial hidden behind an open sibling.
  let unresolvedHalt =
    input.prior_unresolved_halt ??
    (input.prior_state === "TASK_STATE_AUTH_REQUIRED" &&
      ![...obligations.values()].some((o) => o.state === "open"));

  let inputInterrupt = input.prior_state === "TASK_STATE_INPUT_REQUIRED";
  let working = input.prior_state === "TASK_STATE_WORKING";

  const rejected: RejectedEvent[] = [];
  const substates: DecisionSubstate[] = [];

  const reject = (index: number, code: string, message: string): void => {
    rejected.push({ index, code, message });
  };

  input.events.forEach((event, index) => {
    // A null, scalar, or array "event" is refused like any other bad event —
    // the per-event-refusal rule (the stream continues) applies to shape
    // garbage too, not only to well-typed events with bad content.
    if (typeof event !== "object" || event === null || Array.isArray(event)) {
      reject(index, "unknown_event_kind", "Event must be an object.");
      return;
    }
    if (terminal !== null) {
      reject(
        index,
        "event_after_terminal",
        `Task already reached terminal state ${terminal}; the event is recorded, not applied.`,
      );
      return;
    }

    if (event.kind === "decision") {
      let mapping;
      try {
        mapping = mapDecisionToA2A(event.decision);
      } catch (err) {
        if (err instanceof A2AMappingError) {
          reject(index, err.code, err.message);
          return;
        }
        throw err;
      }

      // Validate BEFORE applying: a decision that cannot open its obligation
      // must not half-apply (no substate, no interrupt clearing).
      if (mapping.taskStateRecommendation === "TASK_STATE_AUTH_REQUIRED") {
        const key = event.obligation;
        if (key === undefined) {
          reject(
            index,
            "missing_obligation_key",
            "APPROVAL_REQUIRED with client fulfilment must carry the obligation it opens.",
          );
          return;
        }
        const problem = obligationKeyProblem(key);
        if (problem !== null) {
          reject(index, "invalid_obligation_key", problem);
          return;
        }
        if (key.task_id !== input.task_id || key.context_id !== input.context_id) {
          reject(
            index,
            "foreign_task_obligation",
            "The obligation names a different task or context.",
          );
          return;
        }
        const id = keyId(key);
        const existing = obligations.get(id);
        if (existing !== undefined && existing.state !== "open") {
          // A closed tuple cannot be re-opened: re-issuing an approval is a
          // NEW obligation (generation + 1), never a resurrected old one.
          reject(
            index,
            "obligation_key_reused",
            `Obligation tuple already closed (${existing.state}); re-issue with generation ${key.generation + 1}.`,
          );
          return;
        }
        obligations.set(id, { key, state: "open" });
      }

      // The boundary spoke: whatever halt was pending is superseded by THIS
      // decision's own effect.
      unresolvedHalt = false;
      inputInterrupt = false;
      substates.push(mapping.substate);

      switch (mapping.taskStateRecommendation) {
        case null:
          break;
        case "TASK_STATE_WORKING":
          working = true;
          break;
        case "TASK_STATE_INPUT_REQUIRED":
          inputInterrupt = true;
          break;
        case "TASK_STATE_AUTH_REQUIRED":
          break; // obligation opened above; the open set pins the state
        case "TASK_STATE_REJECTED":
        case "TASK_STATE_FAILED":
          terminal = mapping.taskStateRecommendation;
          break;
      }
      return;
    }

    // Obligation closure event. The kind and closure vocabularies are checked
    // at RUNTIME: TypeScript's union types do not survive JSON, and treating
    // "everything that is not a decision" as a closure would let a forged
    // `kind: "status"` event walk straight into the resolution path.
    if ((event as { kind?: unknown }).kind !== "obligation") {
      reject(
        index,
        "unknown_event_kind",
        `Unknown event kind ${JSON.stringify((event as { kind?: unknown }).kind ?? null)}.`,
      );
      return;
    }
    if (!["resolved", "rejected", "expired"].includes(event.closure)) {
      reject(
        index,
        "invalid_field_value",
        `Unknown closure ${JSON.stringify(event.closure ?? null)}.`,
      );
      return;
    }
    const problem = obligationKeyProblem(event.key);
    if (problem !== null) {
      reject(index, "invalid_obligation_key", problem);
      return;
    }
    if (event.key.task_id !== input.task_id || event.key.context_id !== input.context_id) {
      reject(
        index,
        "foreign_task_obligation",
        "The closure names an obligation of a different task or context.",
      );
      return;
    }
    const id = keyId(event.key);
    const existing = obligations.get(id);
    if (existing === undefined || existing.state !== "open") {
      // The causal rule. No tombstones: an early `resolved` is rejected here,
      // so a later genuine APPROVAL_REQUIRED opens untouched.
      reject(
        index,
        "no_matching_open_obligation",
        "No open obligation matches this closure; it is rejected, not remembered.",
      );
      return;
    }
    if (event.closure === "resolved") {
      if (event.credential === undefined) {
        reject(
          index,
          "credential_required",
          "Resolving an authorization obligation requires the credential (A2A §7.6: the object that represents the approved authorization).",
        );
        return;
      }
      const credProblem = obligationKeyProblem(event.credential.binding);
      if (credProblem !== null || !obligationKeysEqual(event.credential.binding, existing.key)) {
        reject(
          index,
          "credential_binding_mismatch",
          "The credential is not bound to this obligation's full tuple (task, context, agent, digest, correlation, generation, nonce).",
        );
        return;
      }
      obligations.set(id, { key: existing.key, state: "resolved" });
      const stillOpen = [...obligations.values()].some((o) => o.state === "open");
      if (!stillOpen && !unresolvedHalt) {
        // §7.6.1 resume duty: the interrupt is over, the task is processing
        // again. WORKING — never a success state; that call is the executor's.
        working = true;
      }
      return;
    }
    // rejected / expired: the obligation closes, the halt does NOT lift. A
    // denied or lapsed approval is not permission to proceed; the boundary's
    // follow-up decision (or a re-issued generation) moves the task.
    obligations.set(id, { key: existing.key, state: event.closure });
    unresolvedHalt = true;
  });

  const anyOpen = [...obligations.values()].some((o) => o.state === "open");

  let task_state: ReducedTaskState | null;
  if (terminal !== null) {
    task_state = terminal;
  } else if (anyOpen || unresolvedHalt) {
    task_state = "TASK_STATE_AUTH_REQUIRED";
  } else if (inputInterrupt) {
    task_state = "TASK_STATE_INPUT_REQUIRED";
  } else if (working) {
    task_state = "TASK_STATE_WORKING";
  } else {
    task_state = null;
  }

  return {
    task_state,
    obligations: [...obligations.values()],
    rejected_events: rejected,
    substates,
    unresolved_halt: unresolvedHalt,
  };
}

// ---------------------------------------------------------------------------
// §7.6.1 authorization request builder (T-016)
// ---------------------------------------------------------------------------

/**
 * What a producer must emit when it takes the AUTH_REQUIRED row. Field-by-field
 * discharge of the A2A §7.6.1 MUSTs:
 *
 *   MUST use a Task ............... this surface is per-task by construction
 *   MUST transition state ......... `task_state` below
 *   explain the request ........... `status_message` (fixed template, role
 *                                   label + correlation only — no payload)
 *   out-of-band credential ........ `substate.credential_receipt`
 *   accept messages on the task ... `substate.accepts_task_messages`
 *   resume / stream ............... `substate.resume_on` + the reducer's
 *                                   resolved → WORKING transition
 */
export interface AuthorizationRequest {
  readonly task_state: "TASK_STATE_AUTH_REQUIRED";
  readonly status_message: string;
  readonly substate: Readonly<Record<string, unknown>>;
}

export interface AuthorizationRequestInput {
  readonly key: ObligationKey;
  /** Role label of the approver (e.g. "data-owner"). Never a person's name. */
  readonly approver_role: string;
  /** The role labels the caller's own policy defines — the provenance set. */
  readonly approver_roles: readonly string[];
}

/**
 * Build the AUTH_REQUIRED transition content. The message is a fixed template
 * over the role label and correlation fields: nothing free-form reaches it, so
 * nothing payload-shaped can leak through it — and it is still passed through
 * the honesty guard, because templates drift.
 */
export function buildAuthorizationRequest(input: AuthorizationRequestInput): AuthorizationRequest {
  const problem = obligationKeyProblem(input.key);
  if (problem !== null) {
    throw new A2AReducerError(
      "invalid_obligation_key",
      `Cannot request authorization: ${problem}.`,
      "Open the obligation with a fully-specified 7-field tuple.",
    );
  }
  if (!input.approver_roles.includes(input.approver_role)) {
    throw new A2AReducerError(
      "approver_not_declared_role",
      `Approver ${JSON.stringify(input.approver_role)} is not one of the declared role labels.`,
      "The approver field carries a role label from the caller's own policy, never a person's name. Declare the role set and pick from it.",
    );
  }
  // The client never constructs the credential's 7-field binding — it cannot:
  // the server nonce is producer-side capability material and is deliberately
  // absent from this message and from the substate. The client obtains the
  // approval out of band; the BOUNDARY synthesizes the bound credential from
  // the received approval and matches it to the open obligation. The client's
  // only correlates are correlation_id and generation.
  const status_message =
    `Authorization is required before this task can proceed: approval by ` +
    `${input.approver_role} is awaited, and fulfilling it is delegated to you, ` +
    `the client. Obtain the approval out of band; the boundary will bind the ` +
    `received approval to this request and match it by correlation_id ` +
    `${input.key.correlation_id}, generation ${input.key.generation}. You may ` +
    `negotiate, correct, or reject this request by sending messages on this ` +
    `task. The task resumes after the bound credential is matched to this ` +
    `request. No payload values are included in this request.`;
  assertNoEnforcementClaim(status_message, "authorization request status message");
  return {
    task_state: "TASK_STATE_AUTH_REQUIRED",
    status_message,
    substate: {
      outcome: "APPROVAL_REQUIRED",
      reason_code: "approval_required",
      fulfillment_owner: "client",
      approver: input.approver_role,
      correlation_id: input.key.correlation_id,
      generation: input.key.generation,
      obligation_status: "open",
      credential_receipt: "out_of_band",
      accepts_task_messages: true,
      resume_on: "credential_resolution",
    },
  };
}

/**
 * The supported closure-emission path (round-2 critique, both vendors): after
 * an obligation closes, the producer MUST make the closure wire-visible so a
 * poller can tell a still-actionable `AUTH_REQUIRED` from one that is waiting
 * on the boundary. This builds that update substate — place it with
 * `placeDecisionMetadata` like any other. The obligation key's secret parts
 * (server nonce, request digest) never appear in it.
 */
export function buildObligationStatusUpdate(
  key: ObligationKey,
  status: ObligationState,
): Readonly<Record<string, unknown>> {
  const problem = obligationKeyProblem(key);
  if (problem !== null) {
    throw new A2AReducerError(
      "invalid_obligation_key",
      `Cannot report obligation status: ${problem}.`,
      "Report status for the obligation exactly as it was opened.",
    );
  }
  if (!["open", "resolved", "rejected", "expired"].includes(status)) {
    throw new A2AReducerError(
      "invalid_field_value",
      `Unknown obligation status ${JSON.stringify(status)}.`,
      "Only open / resolved / rejected / expired are defined.",
    );
  }
  return {
    outcome: "APPROVAL_REQUIRED",
    reason_code: "approval_required",
    fulfillment_owner: "client",
    correlation_id: key.correlation_id,
    generation: key.generation,
    obligation_status: status,
  };
}
