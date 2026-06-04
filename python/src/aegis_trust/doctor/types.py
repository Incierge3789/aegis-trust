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

from dataclasses import dataclass, field
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
    schema_version: int = DOCTOR_SCHEMA_VERSION
