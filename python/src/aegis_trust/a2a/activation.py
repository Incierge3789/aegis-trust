"""A2A extension activation binding — who may READ what was written
(S027 T-022).

Negotiation (:mod:`aegis_trust.a2a.extension`) answers "did the requester opt
in, on this request". That is not the same question as "may the principal
receiving THIS delivery see the decision metadata". A task outlives its
originating request: a second principal can GetTask it, a subscriber can
stream it, a webhook can push it to a party that never sent an
``A2A-Extensions`` header in its life. If activation is a property of the
request, every one of those paths leaks the substate to principals who never
opted in.

So activation is bound as STATE: (principal, task, extension URI, version,
delivery channel). A binding on one channel does not cover another — opting in
on the request/response path says nothing about wanting the substate pushed to
a webhook endpoint.

THE REVERSE PROBLEM. Stripping the metadata for non-activated readers cannot
simply delete the key: a reader entitled to know that governance reporting
EXISTS would then see a task indistinguishable from one that was never
reported on at all — and "Aegis reporting is present on this task" silently
degrades to "there is no Aegis reporting". The filter therefore replaces the
value with a WITHHELD marker that carries zero decision content (no outcome,
no reason, no field names): existence is disclosed, content is not. Where no
report exists, no marker is invented — absence stays absence.

Mirror of the TypeScript ``src/a2a/activation.ts``.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from aegis_trust.errors import AegisError, aegis_docs_url
from aegis_trust.a2a.extension import (
    AEGIS_A2A_EXTENSION_URI_V0,
    AEGIS_A2A_EXTENSION_VERSION,
    NegotiationResult,
)

__all__ = [
    "DELIVERY_CHANNELS",
    "WITHHELD_STATUS",
    "A2AActivationError",
    "bind_activation",
    "bind_activation_from_negotiation",
    "filter_decision_metadata_for_delivery",
    "is_activated_for",
]


class A2AActivationError(AegisError):
    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(
            message,
            code=code,
            remediation=remediation,
            docs_url=aegis_docs_url(code),
        )


#: Delivery paths a task's metadata can reach a principal through.
DELIVERY_CHANNELS: tuple[str, ...] = (
    "request_response",
    "get_task",
    "subscribe",
    "webhook",
)

#: ``status`` value of the withheld marker.
WITHHELD_STATUS = "withheld_not_activated"


def _validate_binding(binding: Mapping[str, Any]) -> None:
    principal = binding.get("principal")
    if not isinstance(principal, str) or not principal:
        raise A2AActivationError(
            "invalid_activation_binding",
            "Activation binding needs a non-empty principal.",
            "Bind activation to the authenticated principal identity, not to a request.",
        )
    task_id = binding.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise A2AActivationError(
            "invalid_activation_binding",
            "Activation binding needs a non-empty task_id.",
            "Activation is per task; a blanket opt-in would leak future tasks.",
        )
    if binding.get("uri") != AEGIS_A2A_EXTENSION_URI_V0:
        raise A2AActivationError(
            "unknown_extension_uri",
            f"This surface manages activation for {AEGIS_A2A_EXTENSION_URI_V0} only.",
            "Bind other extensions in their own registries; a shared bag of "
            "URIs is how a near-miss identifier inherits someone else's opt-in.",
        )
    if binding.get("version") != AEGIS_A2A_EXTENSION_VERSION:
        raise A2AActivationError(
            "unsupported_extension_version",
            f"Unknown extension version {binding.get('version')!r}.",
            "Activation is per dated version; an opt-in to v0 must not "
            "silently cover a future vocabulary.",
        )
    if binding.get("channel") not in DELIVERY_CHANNELS:
        raise A2AActivationError(
            "unknown_delivery_channel",
            f"Unknown delivery channel {binding.get('channel')!r}.",
            "Only request_response, get_task, subscribe and webhook are defined.",
        )


def _same_binding(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    return all(
        a.get(f) == b.get(f)
        for f in ("principal", "task_id", "uri", "version", "channel")
    )


def bind_activation(
    bindings: Sequence[Mapping[str, Any]],
    binding: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Record one activation. Pure: returns a new list. Idempotent: re-binding
    an identical tuple does not duplicate it."""
    _validate_binding(binding)
    out = [dict(b) for b in bindings]
    if not any(_same_binding(b, binding) for b in bindings):
        out.append(dict(binding))
    return out


def _is_well_formed_binding(b: Mapping[str, Any]) -> bool:
    """Well-formedness without raising — used to IGNORE poisoned records at
    the read boundary. ``bind_activation`` refuses to create a malformed
    binding, but bindings restored from persistence (JSON, a database row, an
    attacker who can write either) never went through it. A malformed record
    must count as no activation at all, not as whatever its raw strings happen
    to match."""
    if not isinstance(b, Mapping):
        return False
    principal = b.get("principal")
    task_id = b.get("task_id")
    return (
        isinstance(principal, str)
        and bool(principal)
        and isinstance(task_id, str)
        and bool(task_id)
        and b.get("uri") == AEGIS_A2A_EXTENSION_URI_V0
        and b.get("version") == AEGIS_A2A_EXTENSION_VERSION
        and b.get("channel") in DELIVERY_CHANNELS
    )


def _is_well_formed_query(principal: Any, task_id: Any, channel: Any) -> bool:
    return (
        isinstance(principal, str)
        and bool(principal)
        and isinstance(task_id, str)
        and bool(task_id)
        and channel in DELIVERY_CHANNELS
    )


def bind_activation_from_negotiation(
    bindings: Sequence[Mapping[str, Any]],
    *,
    principal: str,
    task_id: str,
    channel: str,
    negotiation: NegotiationResult,
) -> list[dict[str, Any]]:
    """Record an activation FROM a successful negotiation (round-3 codex,
    preferred over hand-constructing a binding). The provenance of a binding is
    the request in which this principal opted in: passing the
    ``NegotiationResult`` ties the binding to an actual activation rather than
    to a caller's say-so. Refuses to bind when the negotiation did not activate
    the extension."""
    if not negotiation.activated:
        raise A2AActivationError(
            "activation_not_negotiated",
            "Refusing to bind activation: the negotiation did not activate "
            "this extension.",
            "Only bind a principal that actually opted in. A binding invented "
            "without a negotiation is exactly the confused-deputy this guards "
            "against.",
        )
    return bind_activation(
        bindings,
        {
            "principal": principal,
            "task_id": task_id,
            "uri": AEGIS_A2A_EXTENSION_URI_V0,
            "version": AEGIS_A2A_EXTENSION_VERSION,
            "channel": channel,
        },
    )


def is_activated_for(
    bindings: Sequence[Mapping[str, Any]],
    *,
    principal: str,
    task_id: str,
    channel: str,
) -> bool:
    """Whether this exact (principal, task, channel) holds a v0 activation.

    Validates BOTH sides at the read boundary: a malformed query (unknown
    channel, empty principal) and a malformed stored binding each count as
    "not activated". Matching raw strings would let a poisoned persistence
    record ``{"channel": "email"}`` meet a same-shaped query and release the
    substate on a channel this module has never heard of.
    """
    if not _is_well_formed_query(principal, task_id, channel):
        return False
    return any(
        _is_well_formed_binding(b)
        and b.get("principal") == principal
        and b.get("task_id") == task_id
        and b.get("channel") == channel
        for b in bindings
    )


def filter_decision_metadata_for_delivery(
    metadata: Mapping[str, Any] | None,
    bindings: Sequence[Mapping[str, Any]],
    *,
    principal: str,
    task_id: str,
    channel: str,
) -> dict[str, Any]:
    """Filter a task's metadata for one delivery.

    - No extension key present → returned unchanged. No marker is invented: a
      task that was never reported on must stay distinguishable from one whose
      report is being withheld.
    - Key present, delivery is activated → returned unchanged.
    - Key present, delivery is NOT activated → the value is replaced with the
      withheld marker. Existence disclosed, content not.

    Pure: the caller's mapping is never mutated.
    """
    source = dict(metadata or {})
    if AEGIS_A2A_EXTENSION_URI_V0 not in source:
        return source
    if is_activated_for(
        bindings, principal=principal, task_id=task_id, channel=channel
    ):
        return source
    source[AEGIS_A2A_EXTENSION_URI_V0] = {
        "version": AEGIS_A2A_EXTENSION_VERSION,
        "status": WITHHELD_STATUS,
        "reason": "extension_not_activated_for_principal_on_channel",
    }
    return source
