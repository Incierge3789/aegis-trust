"""A2A extension — declaration, activation negotiation, and metadata placement.

The mapping (:mod:`aegis_trust.a2a.mapping`) decides WHAT to report. This module
decides WHERE it goes on the wire and WHETHER the client asked for it at all.

THREE THINGS THIS DELIBERATELY DOES NOT DO.

1. It does not claim enforcement. An A2A extension is a vocabulary the client
   activates with the ``A2A-Extensions`` header. Activation is not admission
   control, and ``required: true`` in an AgentCard is a notice about request
   construction, not a gate. Aegis's enforcement lives in the gateway path.
   :func:`assert_no_enforcement_claim` is the machine check for that boundary.
2. It does not ship a real URI. The v0 identifier is a placeholder and is
   machine-detectably so — registering an identifier is an ownership act, and
   this sprint does not perform it. :func:`is_placeholder_extension_uri` exists
   so a release cannot carry one by accident.
3. It does not decide who may READ what it wrote. Negotiation here is per
   request; binding activation to a principal, task, and delivery channel — so
   a second principal reading the same task cannot harvest the metadata — is
   :mod:`aegis_trust.a2a.activation`, and deliveries must pass through its
   filter.

Normative source, pinned: ``a2aproject/A2A@0ef1b02``, §4.6 (extensions), §14.2.2
(the ``A2A-Extensions`` header). Metadata placement follows the spec's own
example: ``metadata`` is keyed BY the extension URI (§4.6.1, §4.6.2).

Mirror of the TypeScript ``src/a2a/extension.ts``.
"""

from __future__ import annotations

import re
import unicodedata

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from aegis_trust.errors import AegisError, aegis_docs_url
from aegis_trust.a2a.privacy import validate_decision_substate
from aegis_trust.a2a.verification import (
    assert_no_producer_trust_assertions,
    assert_no_producer_trust_assertions_scoped,
)

__all__ = [
    "A2A_EXTENSIONS_HEADER",
    "AEGIS_A2A_EXTENSION_URI_V0",
    "AEGIS_A2A_EXTENSION_VERSION",
    "A2AExtensionError",
    "NegotiationResult",
    "assert_no_enforcement_claim",
    "build_agent_card_extension",
    "is_placeholder_extension_uri",
    "negotiate_extensions",
    "place_decision_metadata",
]

#: The header a client uses to opt in. Spec §14.2.2.
A2A_EXTENSIONS_HEADER = "A2A-Extensions"

#: v0 extension identifier — a PLACEHOLDER, not a registered URI.
#:
#: The ``x-aegis-placeholder`` authority is deliberately not resolvable and
#: deliberately not a domain anyone could mistake for a published one. Choosing
#: the real identifier is an ownership decision (it becomes the public name of
#: this vocabulary), and it is not made here.
AEGIS_A2A_EXTENSION_URI_V0 = "urn:x-aegis-placeholder:a2a:boundary-decision:v0"

#: Dated version of the substate shape carried under the extension key.
AEGIS_A2A_EXTENSION_VERSION = "v0"

_PLACEHOLDER_MARKERS = ("x-aegis-placeholder", "urn:x-")


def is_placeholder_extension_uri(uri: str) -> bool:
    """True while the extension identifier is still a placeholder."""
    lowered = uri.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


class A2AExtensionError(AegisError):
    """Raised when the extension surface is asked to do something dishonest."""

    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(
            message,
            code=code,
            remediation=remediation,
            docs_url=aegis_docs_url(code),
        )


# ---------------------------------------------------------------------------
# Honesty guard
# ---------------------------------------------------------------------------

# Subject words: the thing a claim could be made ABOUT.
_CLAIM_SUBJECTS = (
    "aegis",
    "extension",
    "boundary",
    "receipt",
    "decision",
    "policy",
    "access",
)

# Assurance words: what a reader would take as "this was enforced / proven".
# A banned-substring list over whole phrases is escapable by paraphrase, which is
# why this matches a SUBJECT near an ASSURANCE word instead of fixed sentences.
_ASSURANCE_WORDS = (
    "enforced",
    "enforcement",
    "guaranteed",
    "guarantees",
    "assurance",
    "assured",
    "proven",
    "proves",
    "verified",
    "certified",
    "protected by",
    "secured by",
    "compliant",
    "in effect",
    "upholds",
    "gated",
    "blocks",
    "prevents",
)
# "establishes" was dropped after round 3 (codex FP: "the policy establishes
# the document format"); cursor's "establishes that access was gated" is still
# caught via "gated". "blocks"/"prevents" added for "Aegis blocks access".
# "confirms" and "coverage" were dropped earlier: as standalone words
# they fire on honest compliance prose ("SOC 2 report confirms coverage of
# access-control reviews"). The round-1 vector they were added for ("confirms
# Aegis coverage is in effect") is still caught by "in effect" near a subject.

# Phrases that are honest precisely because they negate. Without this, the
# disclaimer sentence would trip the guard that exists to enforce it.
#
# Scope (round-1 critique fix): a negation exempts an assurance term only when
# it appears BEFORE the term, within _NEGATION_WINDOW characters, in the SAME
# sentence segment. The previous rule — any negation anywhere in a +/-60
# window — was defeated by appending an unrelated negation after the claim
# ("Aegis assurance active (readers remain unverified)") and by borrowing one
# from the previous clause ("The extension is not decorative; policy
# enforcement is verified"). "unverified" is a status word, not a negation of
# a claim, and is deliberately absent.
_NEGATIONS = (
    "does not",
    "doesn't",
    "not enforcement",
    "never",
    "no guarantee",
    "cannot",
    "can't",
    "not proof",
    "is not",
)

#: Bare "value-free" is banned on this surface — see the mapping doc §7.
_BANNED_TERMS = ("value-free", "value free")

_WINDOW = 60
_NEGATION_WINDOW = 35
# Clause boundaries, comma included (round-2 codex): "Aegis does not log,
# policy enforced." must not let the first clause's negation launder the
# second clause's claim. A negation and the assurance it negates share a
# clause; anything across punctuation is borrowing.
_SENTENCE_BOUNDARY = ".;!?,"


def _escape_re(w: str) -> str:
    return re.escape(w)


# Word-boundaried matching (round-3): substring matching let "access" fire
# inside "inaccessible". \b matches whole words and multi-word phrases.
_ASSURANCE_RE = re.compile(
    r"\b(?:" + "|".join(_escape_re(w) for w in _ASSURANCE_WORDS) + r")\b"
)
_SUBJECT_RE = re.compile(
    r"\b(?:" + "|".join(_escape_re(w) for w in _CLAIM_SUBJECTS) + r")\b"
)


def _segment_start(text: str, at: int) -> int:
    """Start index of the sentence segment containing ``at``."""
    for i in range(at - 1, -1, -1):
        if text[i] in _SENTENCE_BOUNDARY:
            return i + 1
    return 0


def assert_no_enforcement_claim(text: str, where: str) -> None:
    """Reject text that reads as "this extension proves enforcement".

    Deliberately conservative about what counts as a claim and deliberately
    explicit about what counts as a negation, because the failure mode this
    guards against is a paraphrase nobody put on a banned list.
    """
    lowered = unicodedata.normalize("NFKC", text).lower()

    for term in _BANNED_TERMS:
        if term in lowered:
            raise A2AExtensionError(
                "banned_claim_term",
                f'{where} uses "{term}", which overstates what is carried.',
                'Say "payload-value-omitting", or state the property in full: '
                "field names are carried, payload values are not.",
            )

    for match in _ASSURANCE_RE.finditer(lowered):
        at = match.start()
        assurance = match.group(0)
        window = lowered[max(0, at - _WINDOW) : at + len(assurance) + _WINDOW]
        if not _SUBJECT_RE.search(window):
            continue
        # A negation only exempts when it precedes the assurance term closely,
        # inside the same sentence segment.
        negation_from = max(_segment_start(lowered, at), at - _NEGATION_WINDOW)
        negation_window = lowered[negation_from : at + len(assurance)]
        if any(negation in negation_window for negation in _NEGATIONS):
            continue
        raise A2AExtensionError(
            "enforcement_claim_detected",
            f'{where} reads as an enforcement claim near "{assurance}".',
            "Carrying this extension shows what was reported, by whoever "
            "emitted it. State that, or negate the claim explicitly.",
        )


# ---------------------------------------------------------------------------
# AgentCard declaration
# ---------------------------------------------------------------------------


def build_agent_card_extension() -> dict[str, Any]:
    """Build the AgentCard declaration for this extension.

    ``required`` is fixed to ``False`` and is not a parameter. Marking an
    extension required tells clients how to build requests; it does not make a
    counterparty honour anything, and a "required" security-flavoured extension
    invites exactly the misreading this surface must avoid.
    """
    description = (
        "Reports Aegis boundary decisions using existing A2A TaskState values "
        "plus a substate in metadata. It is a reporting vocabulary: activating "
        "it does not enforce anything and is not proof that anything was "
        "enforced. Field names are carried; payload values are not. "
        "PRERELEASE: the identifier is a placeholder and is not registered."
    )
    assert_no_enforcement_claim(description, "AgentCard extension description")
    return {
        "uri": AEGIS_A2A_EXTENSION_URI_V0,
        "description": description,
        "required": False,
        "params": {
            "version": AEGIS_A2A_EXTENSION_VERSION,
            "status": "prerelease",
            "identifier_is_placeholder": True,
        },
    }


# ---------------------------------------------------------------------------
# Activation negotiation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NegotiationResult:
    """Outcome of reading the request ``A2A-Extensions`` header."""

    #: Whether this extension was requested and can be honoured.
    activated: bool
    #: Every URI the client asked for, in request order, de-duplicated.
    requested: tuple[str, ...]
    #: Machine-readable reason when ``activated`` is False.
    reason: str | None = None
    #: What to echo in the response header. Empty when nothing was activated —
    #: never a silent partial answer.
    echo: tuple[str, ...] = ()


def negotiate_extensions(header_value: str | Sequence[str] | None) -> NegotiationResult:
    """Parse the request ``A2A-Extensions`` header and decide activation.

    Extensions are inactive by default, so "the client did not ask" is a normal
    outcome, not an error — but it is a NAMED outcome. A caller must be able to
    tell "no decision metadata because the client did not opt in" from "no
    decision metadata because there was nothing to report"; those look identical
    on the wire otherwise.
    """
    if header_value is None:
        raw = ""
    elif isinstance(header_value, str):
        raw = header_value
    else:
        raw = ",".join(header_value)

    requested: list[str] = []
    for part in raw.split(","):
        uri = part.strip()
        if uri and uri not in requested:
            requested.append(uri)

    if AEGIS_A2A_EXTENSION_URI_V0 not in requested:
        return NegotiationResult(
            activated=False, requested=tuple(requested), reason="not_requested", echo=()
        )
    return NegotiationResult(
        activated=True,
        requested=tuple(requested),
        echo=(AEGIS_A2A_EXTENSION_URI_V0,),
    )


# ---------------------------------------------------------------------------
# Metadata placement
# ---------------------------------------------------------------------------


def _assert_honest_runtime_strings(payload: Any, where: str) -> None:
    """Apply the honesty guard to every string VALUE in a runtime payload.

    The guard was born checking docs and descriptions; H-003's runtime mutant
    (``verification_message: "Policy enforcement verified"``) rides in a value,
    so emission walks the payload and holds values to the same standard.
    """
    if isinstance(payload, str):
        assert_no_enforcement_claim(payload, where)
        return
    if isinstance(payload, (list, tuple)):
        for i, item in enumerate(payload):
            _assert_honest_runtime_strings(item, f"{where}[{i}]")
        return
    if isinstance(payload, Mapping):
        for k, v in payload.items():
            _assert_honest_runtime_strings(v, f"{where}.{k}")


def place_decision_metadata(
    metadata: Mapping[str, Any] | None,
    substate: Mapping[str, Any],
    negotiation: NegotiationResult,
    *,
    declared_field_names: Sequence[str] | None = None,
    approver_roles: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Place a decision substate under the extension's own metadata key.

    Spec §4.6.1/§4.6.2: ``metadata`` is keyed by the extension URI. Returns a new
    dict; the caller's metadata is not mutated.

    Raises when the extension was not activated. Writing extension metadata a
    client never opted into is the quiet version of the disclosure problem —
    fail-closed instead.

    Also refuses to EMIT dishonesty, in four layers (the emission path IS the
    enforcement point for T-019/T-020 on the producer side — a validator only
    consumers run is an optional helper, not a defense):

    1. A substate carrying a producer-asserted trust field is rejected with the
       specific code.
    2. The final versioned value is validated per-field against declared
       provenance — ``withheld_fields: ["alice"]`` and undeclared keys die
       HERE, before the wire, not merely at a well-behaved consumer.
    3. The merged carrier's TOP-LEVEL KEYS are checked, so a root sibling
       ``coreVerified: true`` in the caller's own metadata is refused — this
       SDK will not courier a machine-readable authority claim. Other
       extensions' URI-keyed bags are opaque: their vocabularies are theirs.
    4. Every string value in OUR emitted value is held to the honesty guard.
    """
    if not negotiation.activated:
        raise A2AExtensionError(
            "extension_not_activated",
            "Refusing to write Aegis decision metadata for a client that did "
            "not activate the extension.",
            f'Activate it by sending "{A2A_EXTENSIONS_HEADER}: '
            f'{AEGIS_A2A_EXTENSION_URI_V0}", or report the decision outside the '
            "A2A extension.",
        )
    assert_no_producer_trust_assertions(dict(substate), "decision substate")
    value: dict[str, Any] = {
        "version": AEGIS_A2A_EXTENSION_VERSION,
        **dict(substate),
    }
    validate_decision_substate(
        value,
        declared_field_names=declared_field_names,
        approver_roles=approver_roles,
    )
    merged: dict[str, Any] = dict(metadata or {})
    merged[AEGIS_A2A_EXTENSION_URI_V0] = value
    # Carrier scan, namespace-scoped (round-2 + round-3 critique): trust
    # assertion KEYS are refused anywhere in the carrier EXCEPT inside another
    # extension's namespace-keyed bag. Round 2 stopped co-installed extensions
    # from breaking (their URI bags are opaque); round 3 closed the depth-1
    # courier hole this left (``{"notes": {"coreVerified": true}}``). The
    # honesty string walk stays on OUR value only — the integrator's own prose
    # is the integrator's own claim.
    assert_no_producer_trust_assertions_scoped(merged, "decision metadata carrier")
    _assert_honest_runtime_strings(value, "decision metadata value")
    return merged
