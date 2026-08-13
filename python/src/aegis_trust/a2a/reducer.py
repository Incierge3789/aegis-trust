"""A2A task-state reducer — obligation lifecycle + approval credential binding.

"Only a decision that halts the task drives TaskState" is prose. This module is
the computable form (S027 T-007): a deterministic reducer over (prior state,
prior obligations, event sequence) with two required properties and one
deliberate non-property.

REQUIRED: terminal monotonicity. Once a terminal state is reached, no later
event changes it. Post-terminal events are recorded as rejected, never applied.

REQUIRED: causal ordering. A ``resolved`` / ``rejected`` / ``expired`` closure
with no matching OPEN obligation is REJECTED, never remembered. The tempting
alternative — keep an early ``resolved`` as a tombstone so that order does not
matter — is an attack surface: an approval credential replayed from an earlier
task would pre-resolve the obligation, the boundary's later genuine
APPROVAL_REQUIRED would be swallowed, and the destructive action would proceed
with every "order invariance" property still satisfied.

NON-PROPERTY: order invariance is NOT required across obligation events. It
holds only for commuting decision events (PROTECTED / ACCESS_REDUCED /
CHECK_REQUIRED carry no interrupt and may permute freely).

Obligations are identified by the full 7-field tuple (task, context, requesting
agent, request digest, correlation id, generation, server nonce), and a
credential must carry a binding that equals the OPEN obligation's tuple
exactly. This module checks BINDING, not issuer authenticity: authenticating
who signed a credential requires keys, and keyed verification is Aegis Core
territory. A keyless (LITE) reducer that claimed issuer authentication would be
the overclaim this sprint exists to prevent.

The reducer never selects a success state. ``TASK_STATE_COMPLETED`` is the task
executor's call after output validation (round 2 / F3); the reducer's most
permissive output is ``TASK_STATE_WORKING``.

Normative sources, pinned:
    A2A spec  ``a2aproject/A2A@0ef1b02`` — §7.6 (in-task authorization;
              AUTH_REQUIRED delegates fulfilment to the client), §7.6.1
              (producer MUSTs).
    Mapping   :mod:`aegis_trust.a2a.mapping`, which this reducer composes over
              a whole event sequence.

Mirror of the TypeScript ``src/a2a/reducer.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from aegis_trust.errors import AegisError, aegis_docs_url
from aegis_trust.a2a.extension import assert_no_enforcement_claim
from aegis_trust.a2a.mapping import A2AMappingError, map_decision_to_a2a
from aegis_trust.a2a.privacy import _is_integral_generation

__all__ = [
    "TERMINAL_TASK_STATES",
    "A2AReducerError",
    "AuthorizationRequest",
    "RejectedEvent",
    "TaskReduction",
    "build_authorization_request",
    "obligation_keys_equal",
    "reduce_task_state",
]

#: Spec-declared terminal states. The reducer freezes on any of these.
TERMINAL_TASK_STATES: tuple[str, ...] = (
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_REJECTED",
)

_KEY_STRING_FIELDS = (
    "task_id",
    "context_id",
    "requesting_agent",
    "request_digest",
    "correlation_id",
    "server_nonce",
)

_OBLIGATION_STATES = ("open", "resolved", "rejected", "expired")
_CLOSURES = ("resolved", "rejected", "expired")


class A2AReducerError(AegisError):
    """Input-shape failure (the whole reduction is malformed, not one event)."""

    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(
            message,
            code=code,
            remediation=remediation,
            docs_url=aegis_docs_url(code),
        )


@dataclass(frozen=True)
class RejectedEvent:
    """An event the reducer refused to apply, and why. The stream continues."""

    index: int
    code: str
    message: str


@dataclass(frozen=True)
class TaskReduction:
    """Reduction result: recommendation + obligations + the refusal record."""

    #: ``None`` = nothing observed constrains the state; the executor decides.
    task_state: str | None
    #: Obligations after the reduction, as ``{"key": {...}, "state": ...}``.
    obligations: tuple[dict[str, Any], ...]
    rejected_events: tuple[RejectedEvent, ...]
    #: Substates of the applied decision events, in application order.
    substates: tuple[Mapping[str, Any], ...]
    #: Whether a denial/expiry is still holding the halt. Persist this in the
    #: checkpoint and pass it back as ``prior_unresolved_halt`` (round-3 codex):
    #: a rejected sibling next to an OPEN one cannot be reconstructed from
    #: ``(prior_state, prior_obligations)`` alone.
    unresolved_halt: bool = False


def _obligation_key_problem(key: Any) -> str | None:
    if not isinstance(key, Mapping):
        return "obligation key must be an object"
    for f in _KEY_STRING_FIELDS:
        v = key.get(f)
        if not isinstance(v, str) or not v:
            return f"obligation key field {f} must be a non-empty string"
    gen = key.get("generation")
    if not _is_integral_generation(gen):
        return "obligation key field generation must be an integer >= 1"
    return None


def _key_id(key: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        key["task_id"],
        key["context_id"],
        key["requesting_agent"],
        key["request_digest"],
        key["correlation_id"],
        key["generation"],
        key["server_nonce"],
    )


def obligation_keys_equal(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Exact 7-field equality — the whole binding, or no binding."""
    return _key_id(a) == _key_id(b)


def reduce_task_state(
    *,
    task_id: str,
    context_id: str,
    events: Sequence[Mapping[str, Any]],
    prior_state: str | None = None,
    prior_obligations: Sequence[Mapping[str, Any]] = (),
    prior_unresolved_halt: bool | None = None,
) -> TaskReduction:
    """Reduce an event sequence to a task-state recommendation + obligations.

    Deterministic and side-effect free. Per-event failures are RECORDED in
    ``rejected_events`` and the stream continues — raising on the first bad
    event would let an attacker-injected event destroy the genuine ones behind
    it (the pre-play vector depends on exactly that survival).
    """
    if not isinstance(task_id, str) or not task_id:
        raise A2AReducerError(
            "invalid_reduction_input",
            "task_id must be a non-empty string.",
            "Reduce one task at a time; the task id scopes every obligation check.",
        )
    if not isinstance(context_id, str) or not context_id:
        raise A2AReducerError(
            "invalid_reduction_input",
            "context_id must be a non-empty string.",
            "Reduce one task at a time; the context id scopes every obligation check.",
        )

    obligations: dict[tuple[Any, ...], dict[str, Any]] = {}
    for ob in prior_obligations:
        key = ob.get("key")
        problem = _obligation_key_problem(key)
        if problem is not None:
            raise A2AReducerError(
                "invalid_obligation_key",
                f"Prior obligation is malformed: {problem}.",
                "Carry obligations exactly as a previous reduction returned them.",
            )
        assert isinstance(key, Mapping)
        if key["task_id"] != task_id or key["context_id"] != context_id:
            raise A2AReducerError(
                "foreign_task_obligation",
                "Prior obligation belongs to a different task or context.",
                "Obligations never cross tasks. Reduce each task with its own obligations.",
            )
        state = ob.get("state")
        if state not in _OBLIGATION_STATES:
            raise A2AReducerError(
                "invalid_obligation_key",
                f"Prior obligation has unknown state {state!r}.",
                "Only open / resolved / rejected / expired are defined.",
            )
        kid = _key_id(key)
        if kid in obligations:
            raise A2AReducerError(
                "duplicate_obligation",
                "The same obligation key appears twice in prior_obligations.",
                "An obligation tuple identifies exactly one obligation.",
            )
        obligations[kid] = {"key": dict(key), "state": state}

    terminal: str | None = (
        prior_state
        if prior_state is not None and prior_state in TERMINAL_TASK_STATES
        else None
    )

    # A rejected/expired obligation holds the halt until the boundary speaks
    # again (a denied approval must not quietly resume the task). The
    # checkpoint carries this fact explicitly; only when it is absent do we
    # fall back to the lossy heuristic (a prior AUTH_REQUIRED with no open
    # obligation carried), which cannot see a denial hidden behind an open
    # sibling.
    if prior_unresolved_halt is not None:
        unresolved_halt = prior_unresolved_halt
    else:
        unresolved_halt = prior_state == "TASK_STATE_AUTH_REQUIRED" and not any(
            o["state"] == "open" for o in obligations.values()
        )
    input_interrupt = prior_state == "TASK_STATE_INPUT_REQUIRED"
    working = prior_state == "TASK_STATE_WORKING"

    rejected: list[RejectedEvent] = []
    substates: list[Mapping[str, Any]] = []

    def reject(index: int, code: str, message: str) -> None:
        rejected.append(RejectedEvent(index=index, code=code, message=message))

    for index, event in enumerate(events):
        # A None, scalar, or list "event" is refused like any other bad event —
        # the per-event-refusal rule (the stream continues) applies to shape
        # garbage too, not only to well-typed events with bad content.
        if not isinstance(event, Mapping):
            reject(index, "unknown_event_kind", "Event must be an object.")
            continue
        if terminal is not None:
            reject(
                index,
                "event_after_terminal",
                f"Task already reached terminal state {terminal}; the event is recorded, not applied.",
            )
            continue

        kind = event.get("kind")
        if kind == "decision":
            try:
                # Pass the raw decision (not ``or {}``): a scalar or list
                # decision must reach the non-mapping guard, not be masked into
                # an empty dict (round-3 codex, cross-language parity).
                decision = event["decision"] if "decision" in event else {}
                mapping = map_decision_to_a2a(decision)
            except A2AMappingError as err:
                reject(index, err.code, str(err))
                continue

            # Validate BEFORE applying: a decision that cannot open its
            # obligation must not half-apply (no substate, no interrupt
            # clearing).
            if mapping.task_state_recommendation == "TASK_STATE_AUTH_REQUIRED":
                key = event.get("obligation")
                if key is None:
                    reject(
                        index,
                        "missing_obligation_key",
                        "APPROVAL_REQUIRED with client fulfilment must carry the obligation it opens.",
                    )
                    continue
                problem = _obligation_key_problem(key)
                if problem is not None:
                    reject(index, "invalid_obligation_key", problem)
                    continue
                if key["task_id"] != task_id or key["context_id"] != context_id:
                    reject(
                        index,
                        "foreign_task_obligation",
                        "The obligation names a different task or context.",
                    )
                    continue
                kid = _key_id(key)
                existing = obligations.get(kid)
                if existing is not None and existing["state"] != "open":
                    # A closed tuple cannot be re-opened: re-issuing an
                    # approval is a NEW obligation (generation + 1), never a
                    # resurrected old one.
                    reject(
                        index,
                        "obligation_key_reused",
                        f"Obligation tuple already closed ({existing['state']}); "
                        f"re-issue with generation {key['generation'] + 1}.",
                    )
                    continue
                obligations[kid] = {"key": dict(key), "state": "open"}

            # The boundary spoke: whatever halt was pending is superseded by
            # THIS decision's own effect.
            unresolved_halt = False
            input_interrupt = False
            substates.append(mapping.substate)

            rec = mapping.task_state_recommendation
            if rec == "TASK_STATE_WORKING":
                working = True
            elif rec == "TASK_STATE_INPUT_REQUIRED":
                input_interrupt = True
            elif rec in ("TASK_STATE_REJECTED", "TASK_STATE_FAILED"):
                terminal = rec
            continue

        if kind != "obligation":
            reject(index, "unknown_event_kind", f"Unknown event kind {kind!r}.")
            continue

        closure = event.get("closure")
        if closure not in _CLOSURES:
            reject(index, "invalid_field_value", f"Unknown closure {closure!r}.")
            continue
        key = event.get("key")
        problem = _obligation_key_problem(key)
        if problem is not None:
            reject(index, "invalid_obligation_key", problem)
            continue
        assert isinstance(key, Mapping)
        if key["task_id"] != task_id or key["context_id"] != context_id:
            reject(
                index,
                "foreign_task_obligation",
                "The closure names an obligation of a different task or context.",
            )
            continue
        kid = _key_id(key)
        existing = obligations.get(kid)
        if existing is None or existing["state"] != "open":
            # The causal rule. No tombstones: an early ``resolved`` is
            # rejected here, so a later genuine APPROVAL_REQUIRED opens
            # untouched.
            reject(
                index,
                "no_matching_open_obligation",
                "No open obligation matches this closure; it is rejected, not remembered.",
            )
            continue
        if closure == "resolved":
            credential = event.get("credential")
            if credential is None:
                reject(
                    index,
                    "credential_required",
                    "Resolving an authorization obligation requires the credential "
                    "(A2A §7.6: the object that represents the approved authorization).",
                )
                continue
            binding = (
                credential.get("binding") if isinstance(credential, Mapping) else None
            )
            if (
                _obligation_key_problem(binding) is not None
                or not obligation_keys_equal(binding, existing["key"])  # type: ignore[arg-type]
            ):
                reject(
                    index,
                    "credential_binding_mismatch",
                    "The credential is not bound to this obligation's full tuple "
                    "(task, context, agent, digest, correlation, generation, nonce).",
                )
                continue
            obligations[kid] = {"key": existing["key"], "state": "resolved"}
            still_open = any(o["state"] == "open" for o in obligations.values())
            if not still_open and not unresolved_halt:
                # §7.6.1 resume duty: the interrupt is over, the task is
                # processing again. WORKING — never a success state; that call
                # is the executor's.
                working = True
            continue
        # rejected / expired: the obligation closes, the halt does NOT lift. A
        # denied or lapsed approval is not permission to proceed; the
        # boundary's follow-up decision (or a re-issued generation) moves the
        # task.
        obligations[kid] = {"key": existing["key"], "state": closure}
        unresolved_halt = True

    any_open = any(o["state"] == "open" for o in obligations.values())

    if terminal is not None:
        task_state: str | None = terminal
    elif any_open or unresolved_halt:
        task_state = "TASK_STATE_AUTH_REQUIRED"
    elif input_interrupt:
        task_state = "TASK_STATE_INPUT_REQUIRED"
    elif working:
        task_state = "TASK_STATE_WORKING"
    else:
        task_state = None

    return TaskReduction(
        task_state=task_state,
        obligations=tuple(obligations.values()),
        rejected_events=tuple(rejected),
        substates=tuple(substates),
        unresolved_halt=unresolved_halt,
    )


# ---------------------------------------------------------------------------
# §7.6.1 authorization request builder (T-016)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationRequest:
    """What a producer must emit when it takes the AUTH_REQUIRED row.

    Field-by-field discharge of the A2A §7.6.1 MUSTs:

    - MUST use a Task: this surface is per-task by construction.
    - MUST transition state: :attr:`task_state`.
    - Explain the request: :attr:`status_message` (fixed template, role label +
      correlation only — no payload).
    - Out-of-band credential: ``substate["credential_receipt"]``.
    - Accept messages on the task: ``substate["accepts_task_messages"]``.
    - Resume / stream: ``substate["resume_on"]`` + the reducer's
      resolved → WORKING transition.
    """

    task_state: str
    status_message: str
    substate: Mapping[str, Any]


def build_authorization_request(
    *,
    key: Mapping[str, Any],
    approver_role: str,
    approver_roles: Sequence[str],
) -> AuthorizationRequest:
    """Build the AUTH_REQUIRED transition content.

    The message is a fixed template over the role label and correlation
    fields: nothing free-form reaches it, so nothing payload-shaped can leak
    through it — and it is still passed through the honesty guard, because
    templates drift.
    """
    problem = _obligation_key_problem(key)
    if problem is not None:
        raise A2AReducerError(
            "invalid_obligation_key",
            f"Cannot request authorization: {problem}.",
            "Open the obligation with a fully-specified 7-field tuple.",
        )
    if approver_role not in approver_roles:
        raise A2AReducerError(
            "approver_not_declared_role",
            f"Approver {approver_role!r} is not one of the declared role labels.",
            "The approver field carries a role label from the caller's own "
            "policy, never a person's name. Declare the role set and pick from it.",
        )
    # The client never constructs the credential's 7-field binding — it
    # cannot: the server nonce is producer-side capability material and is
    # deliberately absent from this message and from the substate. The client
    # obtains the approval out of band; the BOUNDARY synthesizes the bound
    # credential from the received approval and matches it to the open
    # obligation. The client's only correlates are correlation_id and
    # generation.
    status_message = (
        "Authorization is required before this task can proceed: approval by "
        f"{approver_role} is awaited, and fulfilling it is delegated to you, "
        "the client. Obtain the approval out of band; the boundary will bind "
        "the received approval to this request and match it by correlation_id "
        f"{key['correlation_id']}, generation {key['generation']}. You may "
        "negotiate, correct, or reject this request by sending messages on "
        "this task. The task resumes after the bound credential is matched "
        "to this request. No payload values are included in this request."
    )
    assert_no_enforcement_claim(status_message, "authorization request status message")
    return AuthorizationRequest(
        task_state="TASK_STATE_AUTH_REQUIRED",
        status_message=status_message,
        substate={
            "outcome": "APPROVAL_REQUIRED",
            "reason_code": "approval_required",
            "fulfillment_owner": "client",
            "approver": approver_role,
            "correlation_id": key["correlation_id"],
            "generation": key["generation"],
            "obligation_status": "open",
            "credential_receipt": "out_of_band",
            "accepts_task_messages": True,
            "resume_on": "credential_resolution",
        },
    )


def build_obligation_status_update(
    key: Mapping[str, Any],
    status: str,
) -> dict[str, Any]:
    """The supported closure-emission path (round-2 critique, both vendors).

    After an obligation closes, the producer MUST make the closure
    wire-visible so a poller can tell a still-actionable ``AUTH_REQUIRED``
    from one that is waiting on the boundary. This builds that update
    substate — place it with :func:`place_decision_metadata` like any other.
    The obligation key's secret parts (server nonce, request digest) never
    appear in it.
    """
    problem = _obligation_key_problem(key)
    if problem is not None:
        raise A2AReducerError(
            "invalid_obligation_key",
            f"Cannot report obligation status: {problem}.",
            "Report status for the obligation exactly as it was opened.",
        )
    if status not in _OBLIGATION_STATES:
        raise A2AReducerError(
            "invalid_field_value",
            f"Unknown obligation status {status!r}.",
            "Only open / resolved / rejected / expired are defined.",
        )
    return {
        "outcome": "APPROVAL_REQUIRED",
        "reason_code": "approval_required",
        "fulfillment_owner": "client",
        "correlation_id": key["correlation_id"],
        "generation": key["generation"],
        "obligation_status": status,
    }
