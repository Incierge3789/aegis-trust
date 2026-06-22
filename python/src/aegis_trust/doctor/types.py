"""Boundary contracts for the Doctor primitive (Python).

These four versioned objects are the shared data contract that shield / doctor /
receipt (and, later, Core) all read and write. They carry ``schema_version`` so
the on-disk / on-wire shape can evolve without breaking consumers. The Node SDK
mirrors these names and semantics 1:1.

Doctor v0 is LITE-only and deterministic: ``doctor.check(plan, policy)`` returns
a :class:`BoundaryDecision` whose ``allowed_data`` feeds ``shield(scope=...)``.
There is no Core dependency and no LLM in this path.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

DOCTOR_SCHEMA_VERSION = 1


class BoundaryOutcome(str, Enum):
    """Doctor verdict. Maps 1:1 to the Core UI outcome language (see the
    aegis-core trust-signal contract): ALLOW→PROTECTED, REDUCE_SCOPE→
    ACCESS_REDUCED, REQUIRE_CHECK→CHECK_REQUIRED, REQUIRE_APPROVAL→
    APPROVAL_REQUIRED, BLOCK→BLOCKED. ``REQUIRE_CHECK`` is reserved (not produced
    by v0)."""

    ALLOW = "ALLOW"
    REDUCE_SCOPE = "REDUCE_SCOPE"
    REQUIRE_CHECK = "REQUIRE_CHECK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class TrustContext:
    """Who is acting, for what purpose, in which environment. ``principal`` is
    unused locally (LITE); Core binds it to an authenticated subject."""

    agent_id: str
    purpose: str
    environment: str = "local"
    mode: str = "lite"
    principal: str | None = None
    schema_version: int = DOCTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class ActionPlan:
    """What an Actor is about to do — the input to ``doctor.check``. The data is
    *declared intent*, not the data itself; doctor diagnoses the plan, it does
    not read records."""

    purpose: str
    action_type: str
    data_requested: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    side_effects: list[str] = field(default_factory=list)
    agent_id: str = "unknown"
    environment: str = "local"
    schema_version: int = DOCTOR_SCHEMA_VERSION


@dataclass(frozen=True)
class BoundaryDecision:
    """What doctor (local) or Core (authoritative) decided. ``allowed_data`` is
    the scope to hand to ``shield``."""

    outcome: BoundaryOutcome
    purpose: str
    allowed_data: list[str] = field(default_factory=list)
    blocked_data: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    approval_required_for: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    policy_version: str = "local-preview-v1"
    receipt_required: bool = False
    schema_version: int = DOCTOR_SCHEMA_VERSION

    def scope_for_shield(self) -> list[str]:
        """The scope that may be handed to ``shield`` — enforcement-coupled.

        ``allowed_data`` is a *diagnostic* field: it is populated even for
        :attr:`BoundaryOutcome.REQUIRE_APPROVAL` and
        :attr:`BoundaryOutcome.BLOCK` so a caller can show *what would have been
        allowed*. Passing that diagnostic straight into ``shield(scope=...)``
        would let data flow **before** a required human approval, or **after** a
        hard block — the decision and the enforcement become decoupled.

        This accessor returns the scope **only** when the outcome actually
        permits the action to proceed (``ALLOW`` / ``REDUCE_SCOPE``). For
        ``REQUIRE_APPROVAL`` / ``REQUIRE_CHECK`` / ``BLOCK`` it returns an empty
        list, so the safe path — ``shield(scope=decision.scope_for_shield())`` —
        discloses nothing until the gate is cleared. Use this, not
        ``allowed_data``, to drive enforcement.
        """
        if self.outcome in (BoundaryOutcome.ALLOW, BoundaryOutcome.REDUCE_SCOPE):
            return list(self.allowed_data)
        return []

    def to_receipt(
        self,
        *,
        receipt_id: str,
        enforcement_status: str = "PENDING",
    ) -> BoundaryReceipt:
        return BoundaryReceipt(
            receipt_id=receipt_id,
            outcome=self.outcome,
            purpose=self.purpose,
            allowed_data=list(self.allowed_data),
            blocked_data=list(self.blocked_data),
            approval_required_for=list(self.approval_required_for),
            reason_codes=list(self.reason_codes),
            policy_version=self.policy_version,
            enforcement_status=enforcement_status,
        )


@dataclass(frozen=True)
class CoreEvidenceLink:
    # Verifiable linkage to Aegis Core Evidence (present iff core_verified).
    # Parity with Node CoreEvidenceLink; makes the receipt CHECKABLE.
    decision_id: str
    enforced_by: str
    integrity_checkable_at: str
    recorded_at: str


@dataclass(frozen=True)
class BoundaryReceipt:
    """A locally-verifiable record of a boundary decision. ``evidence_mode`` is
    ``local`` and ``core_verified`` is False until Core issues formal Evidence —
    LITE must never claim Core's authority."""

    receipt_id: str
    outcome: BoundaryOutcome
    purpose: str
    allowed_data: list[str] = field(default_factory=list)
    blocked_data: list[str] = field(default_factory=list)
    approval_required_for: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    policy_version: str = "local-preview-v1"
    enforcement_status: str = "PENDING"
    evidence_mode: str = "local"
    core_verified: bool = False
    core_evidence: "CoreEvidenceLink | None" = None
    schema_version: int = DOCTOR_SCHEMA_VERSION


def to_core_verified_receipt(decision, evidence, *, receipt_id, enforcement_status="PENDING"):
    # Core-VERIFIED receipt (parity with Node toCoreVerifiedReceipt, §7 pin).
    # core_verified=True means Core ISSUED Evidence, CHECKABLE at
    # integrity_checkable_at — NOT a proof the SDK performed; consumers MUST verify
    # there before trusting the flag (the linkage is the minimum needed FOR
    # verification). Low-level primitive: TRUSTS that `evidence` is the real Core
    # Evidence from a BoundaryDecisionView. The fabrication-resistant source is
    # check_with_core_receipt (evidence only from a real /check-boundary response);
    # prefer it. Fail-closed: missing/partial -> LITE-local (core_verified=False).
    lite = decision.to_receipt(receipt_id=receipt_id, enforcement_status=enforcement_status)

    def _get(obj, key):
        # Accept the SDK's CoreDecisionEvidence dataclass AND the raw snake_case
        # wire dict (codex P2: the FULL path returns the dataclass, not a dict).
        if obj is None:
            return None
        if isinstance(obj, dict):
            return obj.get(key)
        return getattr(obj, key, None)

    did = _get(evidence, "decision_id")
    integ = _get(evidence, "integrity_checkable_at")
    # Non-empty AFTER strip (cursor P2: whitespace-only is not a real id / URL).
    if not (isinstance(did, str) and did.strip() and isinstance(integ, str) and integ.strip()):
        return lite
    eb = _get(evidence, "enforced_by")
    ra = _get(evidence, "recorded_at")
    return replace(
        lite,
        evidence_mode="core",
        core_verified=True,
        core_evidence=CoreEvidenceLink(
            decision_id=did,
            enforced_by=eb if isinstance(eb, str) else "",
            integrity_checkable_at=integ,
            recorded_at=ra if isinstance(ra, str) else "",
        ),
    )
