"""A2A verification status — derived by the consumer, never asserted by the
producer (S027 T-020).

THE RULE. On the wire, every field is the counterparty's self-report. A
``coreVerified: true`` or ``enforcementStatus: "ENFORCED"`` arriving in A2A
metadata is not a fact about enforcement — it is a string the sender chose.
Inside this SDK those fields are produced under discipline, but the wire does
not carry the discipline, only the bytes. A consumer that displays a producer's
positive trust assertion next to its own derived "unverified" has built a UI
where the attacker's field wins.

So this surface has exactly one authoritative verification value: the one the
CONSUMER derives here, from checks it ran itself. Positive producer-asserted
trust fields are rejected outright — not ignored, not deprioritized, rejected —
so the "derived says unverified, embedded field says verified" state is
unrepresentable.

WHAT A KEYLESS CONSUMER CAN DERIVE. The LITE SDK can check structure: the
substate validates against its vocabulary and provenance, and a receipt's
internal structure recomputes. It CANNOT authenticate the issuer — keyed
verification is Aegis Core territory. ``issuer_authenticated`` is therefore not
a member of the status vocabulary: a value this module cannot prove is a value
this module cannot emit.

Mirror of the TypeScript ``src/a2a/verification.ts``.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Sequence

from aegis_trust.errors import AegisError, aegis_docs_url
from aegis_trust.a2a.privacy import A2APrivacyError, validate_decision_substate

__all__ = [
    "CARRIER_IMPERSONATION_KEYS",
    "PRODUCER_TRUST_ASSERTION_KEYS",
    "A2AVerificationError",
    "DerivedVerification",
    "assert_no_producer_trust_assertions_scoped",
    "assert_no_producer_trust_assertions",
    "derive_verification_status",
]


class A2AVerificationError(AegisError):
    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(
            message,
            code=code,
            remediation=remediation,
            docs_url=aegis_docs_url(code),
        )


#: Key names that assert trust on the producer's behalf. Matching first
#: applies Unicode NFKC (so full-width letters fold to ASCII), lower-cases,
#: then strips EVERY character outside ``[a-z0-9]`` — ``coreVerified``,
#: ``core_verified``, ``CORE-VERIFIED``, ``core.Verified``, and a
#: zero-width-space ``core\u200bVerified`` are all the same claim. Stripping
#: only ``_``/``-`` was bypassable by exactly the separators nobody listed.
PRODUCER_TRUST_ASSERTION_KEYS: tuple[str, ...] = (
    "coreverified",
    "enforcementstatus",
    "evidencemode",
    "issuerauthenticated",
    "verificationstatus",
    "verified",
    "attested",
    "authenticated",
    "trusted",
    "trustlevel",
    "enforcementverified",
    "enforced",
    "assurancelevel",
)


def _normalize_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", k).lower())


#: The subset of trust-assertion keys that specifically impersonate THIS
#: extension's consumer-derived verification output. Used for scanning the
#: integrator's OWN sibling metadata: their generic ``authenticated`` /
#: ``verified`` / ``trusted`` fields are their business (round-3 codex: a
#: top-level ``authenticated: false`` from an auth system is not an Aegis
#: authority claim), but a sibling naming our output — ``coreVerified``,
#: ``enforcementStatus``, ``enforced`` — must not be couriered as if we
#: produced it. Our OWN emitted value is still held to the full list.
CARRIER_IMPERSONATION_KEYS: tuple[str, ...] = (
    "coreverified",
    "enforcementstatus",
    "evidencemode",
    "issuerauthenticated",
    "verificationstatus",
    "enforcementverified",
    "assurancelevel",
    "trustlevel",
    "enforced",
)


def _is_namespace_key(k: str) -> bool:
    """A key that names another extension's namespace: a URI or URN. Values
    under such keys are that extension's own vocabulary and are left opaque."""
    return "://" in k or k.lower().startswith("urn:")


def assert_no_producer_trust_assertions_scoped(payload: Any, where: str) -> None:
    """Reject a producer trust-assertion KEY anywhere in a carrier EXCEPT
    inside another extension's namespace-keyed bag.

    Round-3 fix: checking only the top-level keys (round 2) left a depth-1
    courier hole — ``{"notes": {"coreVerified": true}}`` rode through, because
    ``notes`` is not a URI so its contents were never a "foreign bag", yet the
    top-level scan never looked inside it. This walks the whole carrier but
    stops at any value whose KEY is a namespace (``://`` or ``urn:``): those
    belong to other extensions (and to us — our own value was already
    deep-scanned before the merge), and policing their vocabularies is what
    broke co-installed extensions in round 2. Everything else is the
    integrator's own space, where a machine-readable authority claim must not
    ride alongside our decision metadata through this helper.
    """

    def walk(node: Any, path: str) -> None:
        if isinstance(node, (list, tuple)):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")
            return
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            if isinstance(k, str) and _normalize_key(k) in CARRIER_IMPERSONATION_KEYS:
                raise A2AVerificationError(
                    "producer_trust_assertion",
                    f"{where} carries a field impersonating Aegis verification "
                    f"output ({k!r}) at {path}.{k}.",
                    "This extension's verification is derived by the consumer; "
                    "a sibling field naming that output is a self-report and is "
                    "rejected. Rename it, or move it under your own extension's "
                    "URI-keyed metadata. (Generic fields like 'authenticated' "
                    "and other extensions' URI-keyed bags are left untouched.)",
                )
            if isinstance(k, str) and _is_namespace_key(k):
                continue
            walk(v, f"{path}.{k}")

    walk(payload, "$")


def assert_no_producer_trust_assertions(payload: Any, where: str) -> None:
    """Reject any payload carrying a producer-asserted trust field, at any
    nesting depth. Runs on the CONSUMER side before derivation (so an embedded
    claim can never coexist with a derived status) and on the PRODUCER side
    before emission (so this SDK cannot be the producer that emits one).
    """

    def walk(node: Any, path: str) -> None:
        if isinstance(node, (list, tuple)):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")
            return
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            if (
                isinstance(k, str)
                and _normalize_key(k) in PRODUCER_TRUST_ASSERTION_KEYS
            ):
                raise A2AVerificationError(
                    "producer_trust_assertion",
                    f"{where} carries producer-asserted trust field {k!r} at {path}.",
                    "Verification status is derived by the consumer from checks "
                    "it ran itself; a producer field asserting it is a "
                    "self-report and is rejected. Remove the field. If the "
                    "underlying value matters, ship the evidence it summarizes "
                    "and let the consumer derive.",
                )
            walk(v, f"{path}.{k}")

    walk(payload, "$")


_LIMITS: tuple[str, ...] = (
    "does_not_establish_issuer_identity",
    "does_not_establish_enforcement",
    "keyed_chain_verification_is_core_territory",
)


@dataclass(frozen=True)
class DerivedVerification:
    """The one authoritative verification value, with its basis and ceiling.

    ``status`` is deliberately capped at ``structure_verified``: issuer
    authentication needs keys, keys are Core territory, and a status this
    module cannot prove is a status it cannot emit.
    """

    status: str  # "unverified" | "structure_verified"
    #: The checks this consumer actually ran, machine-readable.
    basis: tuple[str, ...]
    #: What this status does NOT establish — fixed strings, always present.
    limits: tuple[str, ...] = _LIMITS


def derive_verification_status(
    *,
    substate: Any,
    declared_field_names: Sequence[str] | None = None,
    approver_roles: Sequence[str] | None = None,
    receipt_structure: str = "absent",
) -> DerivedVerification:
    """Derive the one authoritative verification value from evidence the
    consumer gathered itself.

    ``receipt_structure`` is the result of the LITE structural receipt
    verification, if a receipt rode along and the consumer ran it
    (``verify_session_receipt_structure`` / ``session_dag_root`` are the
    existing keyless checks): ``"verified"``, ``"failed"``, or ``"absent"``.

    Raises ``producer_trust_assertion`` if the payload smuggles a producer
    claim — rejection, not reconciliation.
    """
    assert_no_producer_trust_assertions(substate, "verification evidence substate")

    if receipt_structure not in ("verified", "failed", "absent"):
        raise A2AVerificationError(
            "invalid_field_value",
            f"Unknown receipt_structure {receipt_structure!r}.",
            "Pass 'verified', 'failed', or 'absent' from your own run of the "
            "LITE structural verifier.",
        )

    basis: list[str] = []
    try:
        validate_decision_substate(
            substate,
            declared_field_names=declared_field_names,
            approver_roles=approver_roles,
        )
        basis.append("substate_schema_and_provenance")
    except A2APrivacyError as err:
        return DerivedVerification(
            status="unverified",
            basis=(f"substate_invalid:{err.code}",),
        )

    if receipt_structure == "failed":
        return DerivedVerification(
            status="unverified",
            basis=(*basis, "receipt_structure_failed"),
        )
    if receipt_structure == "verified":
        basis.append("receipt_structure_recomputed")
    return DerivedVerification(status="structure_verified", basis=tuple(basis))
