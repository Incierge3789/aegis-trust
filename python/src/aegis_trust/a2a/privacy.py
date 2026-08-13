"""A2A metadata privacy — provenance-aware, per-field validation (S027 T-019).

THE THREAT MODEL, IN ONE PARAGRAPH. The substate is payload-value-omitting, not
information-free. A field-NAME set discloses schema shape (which fields exist
is itself data about the record). Reason codes disclose policy posture (a
counterparty watching codes learns what this deployment blocks). Counts and
timestamps disclose access frequency and cadence. And any field that accepts
free text is a covert channel for actual payload values. The mitigations are
structural, not promissory: every field is validated against a declared
PROVENANCE (where its value is allowed to come from), every value with a fixed
legal form is checked against that form exactly, and every key not on the
allowlist is rejected — minimization enforced, not requested.

WHY CHARACTER-SHAPE CHECKING DIED. The previous gate (``is_value_free_label``,
``[A-Za-z0-9._:-]{1,128}``) checks what a value LOOKS like. ``alice`` looks
exactly like a field name. ``role:approver`` and a customer's login are the
same regex language. Shape cannot tell schema vocabulary from payload — only
provenance can: the caller declares the field-name set its own schema defines
and the role labels its own policy defines, and membership in a declared set is
the test. No declaration, no field — fail-closed.

Recipient limitation (who may READ a substate that validates) is the
activation-binding surface (:mod:`aegis_trust.a2a.activation`). This module is
about what a substate may CONTAIN.

Mirror of the TypeScript ``src/a2a/privacy.ts``.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from aegis_trust.errors import AegisError, aegis_docs_url
from aegis_trust.a2a.mapping import validate_outcome_reason

__all__ = [
    "REASON_LABELS",
    "_is_integral_generation",
    "A2APrivacyError",
    "validate_decision_substate",
]


class A2APrivacyError(AegisError):
    """Validation failure — names the field and the rule, never guesses."""

    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(
            message,
            code=code,
            remediation=remediation,
            docs_url=aegis_docs_url(code),
        )


#: The fixed reason phrases, pinned verbatim from the decision engine
#: (``aegis-boundary-core@324efd18``, ``engine/aegis-decision/src/decision.rs``,
#: ``ReasonCode::human_label``). ``reason_label`` must equal the phrase for its
#: ``reason_code`` EXACTLY: the label is the enum speaking, and any deviation is
#: either drift or smuggled free text — both rejected.
REASON_LABELS: Mapping[str, str] = {
    "minimum_disclosure": "Only the fields required for this purpose were released.",
    "policy_denied": "Access was refused by purpose policy.",
    "approval_required": "Access is held pending approval.",
    "check_required": "Access requires an additional check before it can proceed.",
    "invalid_scope": "The requested scope could not be resolved.",
    "internal_failure": "Access was refused (fail-secure).",
}

#: Opaque-identifier grammar for correlation ids — shape check ONLY, and only
#: for fields whose values are self-generated identifiers, never vocabulary.
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

_OUTCOME_OF_FIELD: Mapping[str, str] = {
    "version": "any",
    "outcome": "any",
    "reason_code": "any",
    "reason_label": "any",
    "withheld_fields": "ACCESS_REDUCED",
    "disposition": "BLOCKED",
    "fulfillment_owner": "APPROVAL_REQUIRED",
    "approver": "APPROVAL_REQUIRED",
    "correlation_id": "APPROVAL_REQUIRED",
    "generation": "APPROVAL_REQUIRED",
    "obligation_status": "APPROVAL_REQUIRED",
    "credential_receipt": "APPROVAL_REQUIRED",
    "accepts_task_messages": "APPROVAL_REQUIRED",
    "resume_on": "APPROVAL_REQUIRED",
}


def _is_integral_generation(gen: Any) -> bool:
    """Cross-language generation check matching JS ``Number.isInteger`` (round-3
    parity fix): accept an int or an integral float (JSON ``1.0`` parses to a
    JS number ``1`` and to a Python ``float``; both must agree), reject bool,
    non-numeric, non-integral, and < 1. Without this, the same wire bytes
    ``{"generation": 1.0}`` were accepted by Node and rejected by Python.
    """
    if isinstance(gen, bool):
        return False
    if isinstance(gen, int):
        return gen >= 1
    if isinstance(gen, float):
        return gen.is_integer() and gen >= 1
    return False


def _fail(code: str, message: str, remediation: str) -> None:
    raise A2APrivacyError(code, message, remediation)


def validate_decision_substate(
    substate: Any,
    *,
    declared_field_names: Sequence[str] | None = None,
    approver_roles: Sequence[str] | None = None,
) -> Mapping[str, Any]:
    """Validate one decision substate per-field against declared provenance.

    Accepts the substate or the versioned envelope carrying it. Returns the
    substate on success so consumers can use the validated value, not the raw
    wire value.

    Fail-closed on: unknown keys (minimization is enforced by rejection, not by
    hoping producers are frugal), undeclared provenance, fixed-form deviations,
    and fields present under an outcome they do not belong to.
    """
    if not isinstance(substate, Mapping):
        _fail(
            "substate_not_an_object",
            "The decision substate must be a JSON object.",
            "Emit the substate produced by the mapping; do not hand-build wire shapes.",
        )
    assert isinstance(substate, Mapping)

    for k in substate:
        if k not in _OUTCOME_OF_FIELD:
            _fail(
                "undeclared_metadata_field",
                f"Field {k!r} is not part of the v0 substate vocabulary.",
                "Minimization is enforced: only allowlisted fields may ride in "
                "the substate. New fields require a new dated corpus version, "
                "with their disclosure reviewed.",
            )

    outcome, reason_code = validate_outcome_reason(
        substate.get("outcome"), substate.get("reason_code")
    )

    for k in substate:
        scope = _OUTCOME_OF_FIELD[k]
        if scope not in ("any", outcome):
            _fail(
                "field_not_applicable",
                f"Field {k!r} does not belong on a {outcome} substate.",
                f"{k!r} is defined only for {scope}. A field riding outside its "
                "outcome is either drift or a covert channel.",
            )

    if "version" in substate and substate["version"] != "v0":
        _fail(
            "invalid_field_value",
            f"Unknown substate version {substate['version']!r}.",
            "This validator understands v0. Reject unknown versions rather than "
            "guessing their vocabulary.",
        )

    if (
        "reason_label" in substate
        and substate["reason_label"] != REASON_LABELS[reason_code]
    ):
        _fail(
            "reason_label_not_fixed_phrase",
            f"reason_label must be the fixed phrase for {reason_code}.",
            f"The only legal value is {REASON_LABELS[reason_code]!r}. Anything "
            "else is either enum drift or free text smuggled into a "
            "fixed-phrase field.",
        )

    if "withheld_fields" in substate:
        wf = substate["withheld_fields"]
        if (
            not isinstance(wf, Sequence)
            or isinstance(wf, (str, bytes))
            or any(not isinstance(f, str) or not f for f in wf)
        ):
            _fail(
                "invalid_field_value",
                "withheld_fields must be an array of non-empty strings.",
                "Field NAMES only — and names must be validated against declared provenance.",
            )
        if not declared_field_names:
            _fail(
                "withheld_field_provenance_unknown",
                "withheld_fields present but no field-name set was declared.",
                "Declare the field names your own schema defines. Without a "
                "declaration the validator cannot tell a field name from a "
                "payload value, so it refuses.",
            )
        assert declared_field_names is not None
        for f in wf:
            if f not in declared_field_names:
                _fail(
                    "withheld_field_provenance_unknown",
                    f"withheld_fields entry {f!r} is not a declared field name.",
                    "Character shape cannot distinguish a schema field from a "
                    "person's name or a payload value; declared-set membership "
                    "can. Only declared names pass.",
                )

    if "disposition" in substate:
        legal = "correctable" if reason_code == "invalid_scope" else "terminal"
        if substate["disposition"] != legal:
            _fail(
                "invalid_field_value",
                f"disposition for {reason_code} must be {legal!r}.",
                "Disposition is derived from the reason code, never asserted independently.",
            )

    if "fulfillment_owner" in substate and substate["fulfillment_owner"] not in (
        "client",
        "agent",
    ):
        _fail(
            "invalid_field_value",
            f"Unknown fulfillment_owner {substate['fulfillment_owner']!r}.",
            "Only 'client' and 'agent' are defined.",
        )

    if "approver" in substate:
        approver = substate["approver"]
        if (
            not approver_roles
            or not isinstance(approver, str)
            or approver not in approver_roles
        ):
            _fail(
                "approver_not_declared_role",
                f"approver {approver!r} is not one of the declared role labels.",
                "The approver field carries a role label from the caller's own "
                "policy, never a person's name. Declare the role set and "
                "validate membership.",
            )

    if "correlation_id" in substate:
        cid = substate["correlation_id"]
        if not isinstance(cid, str) or not _OPAQUE_ID.match(cid):
            _fail(
                "invalid_field_value",
                "correlation_id must match the opaque-identifier grammar.",
                "Correlation ids are self-generated opaque tokens (1-128 chars "
                "of [A-Za-z0-9._:-]).",
            )

    if "generation" in substate:
        gen = substate["generation"]
        if not _is_integral_generation(gen):
            _fail(
                "invalid_field_value",
                "generation must be an integer >= 1.",
                "Generation counts obligation re-issues, starting at 1.",
            )

    if "obligation_status" in substate and substate["obligation_status"] not in (
        "open",
        "resolved",
        "rejected",
        "expired",
    ):
        _fail(
            "invalid_field_value",
            f"Unknown obligation_status {substate['obligation_status']!r}.",
            "Only open / resolved / rejected / expired are defined.",
        )

    if (
        "credential_receipt" in substate
        and substate["credential_receipt"] != "out_of_band"
    ):
        _fail(
            "invalid_field_value",
            "credential_receipt has exactly one legal value: 'out_of_band'.",
            "A2A §7.6.1: the credential arrives out of band. A field that could "
            "say anything else would be describing a different protocol.",
        )

    if (
        "accepts_task_messages" in substate
        and substate["accepts_task_messages"] is not True
    ):
        _fail(
            "invalid_field_value",
            "accepts_task_messages, when present, must be true.",
            "Accepting messages on the task is a §7.6.1 obligation of taking "
            "AUTH_REQUIRED, not an option to advertise away.",
        )

    if "resume_on" in substate and substate["resume_on"] != "credential_resolution":
        _fail(
            "invalid_field_value",
            "resume_on has exactly one legal value: 'credential_resolution'.",
            "The resume trigger is defined by the obligation lifecycle, not "
            "asserted per message.",
        )

    return substate
