// A2A metadata privacy — provenance-aware, per-field validation (S027 T-019).
//
// THE THREAT MODEL, IN ONE PARAGRAPH. The substate is payload-value-omitting,
// not information-free. A field-NAME set discloses schema shape (which fields
// exist is itself data about the record). Reason codes disclose policy posture
// (a counterparty watching codes learns what this deployment blocks). Counts
// and timestamps disclose access frequency and cadence. And any field that
// accepts free text is a covert channel for actual payload values. The
// mitigations are structural, not promissory: every field is validated against
// a declared PROVENANCE (where its value is allowed to come from), every value
// with a fixed legal form is checked against that form exactly, and every key
// not on the allowlist is rejected — minimization enforced, not requested.
//
// WHY CHARACTER-SHAPE CHECKING DIED. The previous gate (`isValueFreeLabel`,
// `[A-Za-z0-9._:-]{1,128}`) checks what a value LOOKS like. `alice` looks
// exactly like a field name. `role:approver` and a customer's login are the
// same regex language. Shape cannot tell schema vocabulary from payload — only
// provenance can: the caller declares the field-name set its own schema
// defines and the role labels its own policy defines, and membership in a
// declared set is the test. No declaration, no field — fail-closed.
//
// Recipient limitation (who may READ a substate that validates) is the
// activation-binding surface (./activation.ts). This module is about what a
// substate may CONTAIN.

import { AegisError, aegisDocsUrl } from "../errors.js";
import {
  validateOutcomeReason,
  type DecisionOutcome,
  type ReasonCode,
} from "./mapping.js";

/** Validation failure — names the field and the rule, never guesses. */
export class A2APrivacyError extends AegisError {
  constructor(code: string, message: string, remediation: string) {
    super({ code, message, remediation, docs_url: aegisDocsUrl(code) });
    this.name = "A2APrivacyError";
  }
}

/**
 * The fixed reason phrases, pinned verbatim from the decision engine
 * (aegis-boundary-core@324efd18, engine/aegis-decision/src/decision.rs,
 * `ReasonCode::human_label`). `reason_label` must equal the phrase for its
 * `reason_code` EXACTLY: the label is the enum speaking, and any deviation is
 * either drift or smuggled free text — both rejected.
 */
export const REASON_LABELS: Readonly<Record<ReasonCode, string>> = {
  minimum_disclosure: "Only the fields required for this purpose were released.",
  policy_denied: "Access was refused by purpose policy.",
  approval_required: "Access is held pending approval.",
  check_required: "Access requires an additional check before it can proceed.",
  invalid_scope: "The requested scope could not be resolved.",
  internal_failure: "Access was refused (fail-secure).",
};

/**
 * Where values are allowed to come from. Absent declarations fail closed: a
 * substate carrying `withheld_fields` with no declared field-name set cannot
 * have its provenance attested and is rejected, not waved through.
 */
export interface ProvenanceDeclaration {
  /** Field names the caller's OWN schema defines (never taken from the wire). */
  readonly declared_field_names?: readonly string[];
  /** Approver role labels the caller's OWN policy defines. */
  readonly approver_roles?: readonly string[];
}

/** Opaque-identifier grammar for correlation ids — shape check ONLY, and only
 * for fields whose values are self-generated identifiers, never vocabulary. */
const OPAQUE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

const OUTCOME_OF_FIELD: Readonly<Record<string, DecisionOutcome | "any">> = {
  version: "any",
  outcome: "any",
  reason_code: "any",
  reason_label: "any",
  withheld_fields: "ACCESS_REDUCED",
  disposition: "BLOCKED",
  fulfillment_owner: "APPROVAL_REQUIRED",
  approver: "APPROVAL_REQUIRED",
  correlation_id: "APPROVAL_REQUIRED",
  generation: "APPROVAL_REQUIRED",
  obligation_status: "APPROVAL_REQUIRED",
  credential_receipt: "APPROVAL_REQUIRED",
  accepts_task_messages: "APPROVAL_REQUIRED",
  resume_on: "APPROVAL_REQUIRED",
};

function fail(code: string, message: string, remediation: string): never {
  throw new A2APrivacyError(code, message, remediation);
}

/**
 * Validate one decision substate (or the versioned envelope carrying it),
 * per-field, against declared provenance. Returns the substate on success so
 * consumers can use the validated value, not the raw wire value.
 *
 * Fail-closed on: unknown keys (minimization is enforced by rejection, not by
 * hoping producers are frugal), undeclared provenance, fixed-form deviations,
 * and fields present under an outcome they do not belong to.
 */
export function validateDecisionSubstate(
  substate: unknown,
  provenance: ProvenanceDeclaration,
): Readonly<Record<string, unknown>> {
  if (typeof substate !== "object" || substate === null || Array.isArray(substate)) {
    fail(
      "substate_not_an_object",
      "The decision substate must be a JSON object.",
      "Emit the substate produced by the mapping; do not hand-build wire shapes.",
    );
  }
  const s = substate as Record<string, unknown>;

  for (const k of Object.keys(s)) {
    if (!(k in OUTCOME_OF_FIELD)) {
      fail(
        "undeclared_metadata_field",
        `Field ${JSON.stringify(k)} is not part of the v0 substate vocabulary.`,
        "Minimization is enforced: only allowlisted fields may ride in the substate. New fields require a new dated corpus version, with their disclosure reviewed.",
      );
    }
  }

  const { outcome, reason_code } = validateOutcomeReason(
    typeof s.outcome === "string" ? s.outcome : String(s.outcome ?? ""),
    typeof s.reason_code === "string" ? s.reason_code : undefined,
  );

  for (const k of Object.keys(s)) {
    const scope = OUTCOME_OF_FIELD[k];
    if (scope !== "any" && scope !== outcome) {
      fail(
        "field_not_applicable",
        `Field ${JSON.stringify(k)} does not belong on a ${outcome} substate.`,
        `${JSON.stringify(k)} is defined only for ${scope}. A field riding outside its outcome is either drift or a covert channel.`,
      );
    }
  }

  if (s.version !== undefined && s.version !== "v0") {
    fail(
      "invalid_field_value",
      `Unknown substate version ${JSON.stringify(s.version)}.`,
      "This validator understands v0. Reject unknown versions rather than guessing their vocabulary.",
    );
  }

  if (s.reason_label !== undefined) {
    if (s.reason_label !== REASON_LABELS[reason_code]) {
      fail(
        "reason_label_not_fixed_phrase",
        `reason_label must be the fixed phrase for ${reason_code}.`,
        `The only legal value is ${JSON.stringify(REASON_LABELS[reason_code])}. Anything else is either enum drift or free text smuggled into a fixed-phrase field.`,
      );
    }
  }

  if (s.withheld_fields !== undefined) {
    if (
      !Array.isArray(s.withheld_fields) ||
      s.withheld_fields.some((f) => typeof f !== "string" || f.length === 0)
    ) {
      fail(
        "invalid_field_value",
        "withheld_fields must be an array of non-empty strings.",
        "Field NAMES only — and names must be validated against declared provenance.",
      );
    }
    const declared = provenance.declared_field_names;
    if (declared === undefined || declared.length === 0) {
      fail(
        "withheld_field_provenance_unknown",
        "withheld_fields present but no field-name set was declared.",
        "Declare the field names your own schema defines. Without a declaration the validator cannot tell a field name from a payload value, so it refuses.",
      );
    }
    for (const f of s.withheld_fields as string[]) {
      if (!declared.includes(f)) {
        fail(
          "withheld_field_provenance_unknown",
          `withheld_fields entry ${JSON.stringify(f)} is not a declared field name.`,
          "Character shape cannot distinguish a schema field from a person's name or a payload value; declared-set membership can. Only declared names pass.",
        );
      }
    }
  }

  if (s.disposition !== undefined) {
    const legal = reason_code === "invalid_scope" ? "correctable" : "terminal";
    if (s.disposition !== legal) {
      fail(
        "invalid_field_value",
        `disposition for ${reason_code} must be ${JSON.stringify(legal)}.`,
        "Disposition is derived from the reason code, never asserted independently.",
      );
    }
  }

  if (s.fulfillment_owner !== undefined && s.fulfillment_owner !== "client" && s.fulfillment_owner !== "agent") {
    fail(
      "invalid_field_value",
      `Unknown fulfillment_owner ${JSON.stringify(s.fulfillment_owner)}.`,
      "Only 'client' and 'agent' are defined.",
    );
  }

  if (s.approver !== undefined) {
    const roles = provenance.approver_roles;
    if (roles === undefined || roles.length === 0 || typeof s.approver !== "string" || !roles.includes(s.approver)) {
      fail(
        "approver_not_declared_role",
        `approver ${JSON.stringify(s.approver)} is not one of the declared role labels.`,
        "The approver field carries a role label from the caller's own policy, never a person's name. Declare the role set and validate membership.",
      );
    }
  }

  if (s.correlation_id !== undefined && (typeof s.correlation_id !== "string" || !OPAQUE_ID.test(s.correlation_id))) {
    fail(
      "invalid_field_value",
      "correlation_id must match the opaque-identifier grammar.",
      "Correlation ids are self-generated opaque tokens (1-128 chars of [A-Za-z0-9._:-]).",
    );
  }

  if (s.generation !== undefined && (typeof s.generation !== "number" || !Number.isInteger(s.generation) || s.generation < 1)) {
    fail(
      "invalid_field_value",
      "generation must be an integer >= 1.",
      "Generation counts obligation re-issues, starting at 1.",
    );
  }

  if (s.obligation_status !== undefined && !["open", "resolved", "rejected", "expired"].includes(s.obligation_status as string)) {
    fail(
      "invalid_field_value",
      `Unknown obligation_status ${JSON.stringify(s.obligation_status)}.`,
      "Only open / resolved / rejected / expired are defined.",
    );
  }

  if (s.credential_receipt !== undefined && s.credential_receipt !== "out_of_band") {
    fail(
      "invalid_field_value",
      "credential_receipt has exactly one legal value: 'out_of_band'.",
      "A2A §7.6.1: the credential arrives out of band. A field that could say anything else would be describing a different protocol.",
    );
  }

  if (s.accepts_task_messages !== undefined && s.accepts_task_messages !== true) {
    fail(
      "invalid_field_value",
      "accepts_task_messages, when present, must be true.",
      "Accepting messages on the task is a §7.6.1 obligation of taking AUTH_REQUIRED, not an option to advertise away.",
    );
  }

  if (s.resume_on !== undefined && s.resume_on !== "credential_resolution") {
    fail(
      "invalid_field_value",
      "resume_on has exactly one legal value: 'credential_resolution'.",
      "The resume trigger is defined by the obligation lifecycle, not asserted per message.",
    );
  }

  return s;
}
