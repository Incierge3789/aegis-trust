"""aegis-trust Doctor (Python) — pre-action boundary diagnosis.

    from aegis_trust.doctor import check, ActionPlan, LocalPolicy

``check(plan, policy)`` diagnoses an Actor's action plan BEFORE execution and
returns a deterministic, local :class:`BoundaryDecision`. Feed
``decision.allowed_data`` into ``shield(scope=...)`` to enforce it.

Doctor v0 is LITE-only, deterministic, and has no Core dependency. Authoritative
enforcement and formal Evidence remain Aegis Core's responsibility.
"""

from aegis_trust.doctor.check import check
from aegis_trust.doctor.policy import ActionRule, LocalPolicy, PurposeRule
from aegis_trust.doctor.types import (
    DOCTOR_SCHEMA_VERSION,
    ActionPlan,
    BoundaryDecision,
    BoundaryOutcome,
    BoundaryReceipt,
    TrustContext,
)

__all__ = [
    "check",
    "ActionPlan",
    "BoundaryDecision",
    "BoundaryOutcome",
    "BoundaryReceipt",
    "TrustContext",
    "LocalPolicy",
    "PurposeRule",
    "ActionRule",
    "DOCTOR_SCHEMA_VERSION",
]
