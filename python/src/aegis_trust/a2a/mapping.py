"""A2A extension — Aegis boundary decision → A2A TaskState mapping (v0, prerelease).

WHAT THIS IS. A2A filled transport; the decision and evidence seats in the
protocol are empty. This module reports an Aegis boundary decision using A2A's
OWN vocabulary: an existing ``TaskState`` plus a substate in ``metadata``. The
A2A extension spec forbids adding enum values, so nothing here invents one.

WHAT THIS IS NOT. Carrying this extension does not prove enforcement. An A2A
extension is a vocabulary the client activates with the ``A2A-Extensions``
header; it is not an admission control. Aegis's enforcement comes from the
gateway path, not from a header. Anyone can name an extension URI and emit a
structurally valid ``outcome: PROTECTED`` — a recipient learns what was
*reported*, by whoever emitted it, and nothing more.

STATE OWNERSHIP. ``task_state_recommendation is None`` means the mapping sets no
state. PROTECTED and ACCESS_REDUCED do not make a task successful: only the task
executor knows whether a withheld field was required for the requested result,
so the mapping never selects a terminal state on its behalf.

FAIL-CLOSED. Unknown outcomes, unknown reason codes, and (outcome, reason_code)
pairs the decision engine cannot produce are rejected, never guessed. The legal
pair set is 7, not 5x6, because the engine derives reason_code from the outcome
(``ReasonCode::derive``) and only BLOCKED branches. Pinned corpus:
``conformance/a2a_mapping.v0.json``.

Normative sources, pinned:
  A2A spec        ``a2aproject/A2A@0ef1b02`` (in-task authorization is §7.6)
  decision engine ``aegis-boundary-core@324efd18``
                  ``engine/aegis-decision/src/decision.rs:118-142``

Mirror of the TypeScript ``src/a2a/mapping.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from aegis_trust.errors import AegisError, aegis_docs_url

__all__ = [
    "A2AMappingError",
    "DecisionMapping",
    "LEGAL_OUTCOME_REASON_PAIRS",
    "map_decision_to_a2a",
    "validate_outcome_reason",
]


OUTCOMES: tuple[str, ...] = (
    "PROTECTED",
    "ACCESS_REDUCED",
    "CHECK_REQUIRED",
    "APPROVAL_REQUIRED",
    "BLOCKED",
)

REASON_CODES: tuple[str, ...] = (
    "minimum_disclosure",
    "policy_denied",
    "approval_required",
    "check_required",
    "invalid_scope",
    "internal_failure",
)

#: The pairs the decision engine can actually produce — 7, not 30.
#:
#: ``ReasonCode::derive(outcome, reason_text)`` maps PROTECTED and
#: ACCESS_REDUCED to ``minimum_disclosure``, APPROVAL_REQUIRED to
#: ``approval_required``, CHECK_REQUIRED to ``check_required``, and branches
#: only for BLOCKED.
LEGAL_OUTCOME_REASON_PAIRS: tuple[tuple[str, str], ...] = (
    ("PROTECTED", "minimum_disclosure"),
    ("ACCESS_REDUCED", "minimum_disclosure"),
    ("CHECK_REQUIRED", "check_required"),
    ("APPROVAL_REQUIRED", "approval_required"),
    ("BLOCKED", "policy_denied"),
    ("BLOCKED", "invalid_scope"),
    ("BLOCKED", "internal_failure"),
)

_LEGAL_PAIR_KEYS = frozenset(f"{o} {r}" for o, r in LEGAL_OUTCOME_REASON_PAIRS)


class A2AMappingError(AegisError):
    """Raised for anything this mapping refuses to guess about."""

    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(
            message,
            code=code,
            remediation=remediation,
            docs_url=aegis_docs_url(code),
        )


@dataclass(frozen=True)
class DecisionMapping:
    """Result of mapping one decision. A recommendation, not a state assignment."""

    #: ``None`` = the mapping sets no state; the executor decides.
    task_state_recommendation: str | None
    #: Whether this decision stops the task from proceeding as asked.
    halts_task: bool
    #: Payload-value-omitting substate for A2A ``metadata``.
    #:
    #: It carries field *names*, an outcome, and a reason code. That is not the
    #: same as carrying no information — a field-name set discloses schema
    #: shape, reason codes disclose policy posture, and counts and timings
    #: disclose access patterns. Do not describe it as "value-free".
    substate: Mapping[str, Any] = field(default_factory=dict)


def validate_outcome_reason(outcome: Any, reason_code: Any) -> tuple[str, str]:
    """Fail-closed validation of an ``(outcome, reason_code)`` pair.

    Scoped to the check-boundary vocabulary on purpose. Other gateway surfaces
    emit reason codes outside this enum (``capsule_scope_denied``, for one), so
    a permissive "anything seen on the wire" allowlist would let a foreign
    vocabulary drive A2A task state.
    """
    if outcome not in OUTCOMES:
        raise A2AMappingError(
            "unknown_outcome",
            f"Unknown decision outcome: {outcome!r}.",
            "Do not map unknown outcomes to a TaskState. Upgrade the SDK to a "
            "version whose mapping covers this engine, or handle the decision "
            "outside the A2A extension.",
        )
    if reason_code not in REASON_CODES:
        raise A2AMappingError(
            "unknown_reason_code",
            f"Unknown or missing reason_code: {reason_code!r}.",
            "The A2A mapping is scoped to the check-boundary reason vocabulary. "
            "Reason codes from other surfaces must not be mapped here.",
        )
    if f"{outcome} {reason_code}" not in _LEGAL_PAIR_KEYS:
        raise A2AMappingError(
            "illegal_outcome_reason_pair",
            f"The decision engine cannot produce outcome {outcome} with "
            f"reason_code {reason_code}.",
            "Treat this as a malformed or foreign decision, not as a task "
            "state. See conformance/a2a_mapping.v0.json for the 7 legal pairs.",
        )
    return outcome, reason_code


def map_decision_to_a2a(decision: Mapping[str, Any]) -> DecisionMapping:
    """Map one boundary decision to an A2A ``TaskState`` recommendation + substate.

    Deterministic and side-effect free: same input, same output, no I/O.
    """
    # A non-mapping decision (None, a scalar, a list) is a malformed input, not
    # a crash site (round-3 codex): ``decision.get`` on a str/None would raise
    # AttributeError and abort a whole event stream. Coerce to A2AMappingError,
    # matching the TypeScript mirror.
    if not isinstance(decision, Mapping):
        raise A2AMappingError(
            "unknown_outcome",
            f"Decision must be an object; got {decision!r}.",
            "Pass a boundary decision object with an outcome and reason_code.",
        )
    outcome, reason_code = validate_outcome_reason(
        decision.get("outcome"), decision.get("reason_code")
    )

    if outcome == "PROTECTED":
        return DecisionMapping(
            task_state_recommendation=None,
            halts_task=False,
            substate={"outcome": outcome, "reason_code": reason_code},
        )

    if outcome == "ACCESS_REDUCED":
        substate: dict[str, Any] = {"outcome": outcome, "reason_code": reason_code}
        withheld = decision.get("withheld_fields")
        if withheld is not None:
            if (
                isinstance(withheld, (str, bytes))
                or not isinstance(withheld, Sequence)
                or any(not isinstance(f, str) or not f for f in withheld)
            ):
                raise A2AMappingError(
                    "invalid_withheld_fields",
                    "withheld_fields must be a sequence of non-empty field names.",
                    "Pass field NAMES only, never payload values, and never a bare string.",
                )
            substate["withheld_fields"] = list(withheld)
        return DecisionMapping(
            task_state_recommendation=None, halts_task=False, substate=substate
        )

    if outcome == "CHECK_REQUIRED":
        # The boundary runs the check. WORKING is the only state that means
        # "still processing, you need do nothing".
        return DecisionMapping(
            task_state_recommendation="TASK_STATE_WORKING",
            halts_task=False,
            substate={"outcome": outcome, "reason_code": reason_code},
        )

    if outcome == "APPROVAL_REQUIRED":
        owner = decision.get("fulfillment_owner")
        if owner is None:
            raise A2AMappingError(
                "missing_fulfillment_owner",
                "APPROVAL_REQUIRED needs fulfillment_owner to choose a TaskState.",
                "Set fulfillment_owner to 'client' when asking the A2A client to "
                "fulfil the authorization (A2A §7.6.1 → AUTH_REQUIRED), or 'agent' "
                "when the boundary resolves it internally (stays WORKING). "
                "Guessing either way is a protocol error.",
            )
        if owner not in ("client", "agent"):
            raise A2AMappingError(
                "unknown_fulfillment_owner",
                f"Unknown fulfillment_owner: {owner!r}.",
                "Only 'client' and 'agent' are defined.",
            )
        return DecisionMapping(
            task_state_recommendation=(
                "TASK_STATE_AUTH_REQUIRED"
                if owner == "client"
                else "TASK_STATE_WORKING"
            ),
            halts_task=owner == "client",
            substate={
                "outcome": outcome,
                "reason_code": reason_code,
                "fulfillment_owner": owner,
            },
        )

    # BLOCKED
    if reason_code == "internal_failure":
        # Fail-secure refusal on an internal error IS an error, and must stay
        # distinguishable from a policy refusal in the audit trail.
        return DecisionMapping(
            task_state_recommendation="TASK_STATE_FAILED",
            halts_task=True,
            substate={
                "outcome": outcome,
                "reason_code": reason_code,
                "disposition": "terminal",
            },
        )
    if reason_code == "invalid_scope":
        # A scope that could not be resolved is a request defect the client can
        # repair. REJECTED is terminal and would foreclose the repair.
        return DecisionMapping(
            task_state_recommendation="TASK_STATE_INPUT_REQUIRED",
            halts_task=True,
            substate={
                "outcome": outcome,
                "reason_code": reason_code,
                "disposition": "correctable",
            },
        )
    # policy_denied — a decision, not an error, and not repairable.
    return DecisionMapping(
        task_state_recommendation="TASK_STATE_REJECTED",
        halts_task=True,
        substate={
            "outcome": outcome,
            "reason_code": reason_code,
            "disposition": "terminal",
        },
    )
