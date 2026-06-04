"""Deterministic boundary diagnosis — ``doctor.check`` (Python, v0).

Given an :class:`ActionPlan` and a :class:`LocalPolicy`, return a
:class:`BoundaryDecision`. Pure, local, deterministic — no network, no LLM, no
Core. The decision's ``allowed_data`` is meant to be passed straight to
``shield(scope=...)``.

v0 produces ALLOW / REDUCE_SCOPE / REQUIRE_APPROVAL / BLOCK. REQUIRE_CHECK is
reserved for a later release.
"""

from __future__ import annotations

from aegis_trust.doctor.policy import LocalPolicy
from aegis_trust.doctor.types import ActionPlan, BoundaryDecision, BoundaryOutcome


def check(plan: ActionPlan, policy: LocalPolicy | None = None) -> BoundaryDecision:
    """Diagnose ``plan`` against ``policy`` and return a deterministic decision."""
    policy = policy or LocalPolicy()
    requested = list(plan.data_requested)

    # 1. Hard block: a forbidden field requested at all (e.g. secrets, .env).
    #    Fail-closed — the action does not proceed and no field is allowed.
    hard = [f for f in requested if f in policy.never_fields]
    if hard:
        return BoundaryDecision(
            outcome=BoundaryOutcome.BLOCK,
            purpose=plan.purpose,
            allowed_data=[],
            blocked_data=requested,
            allowed_tools=[],
            reason_codes=["FORBIDDEN_FIELD_REQUESTED"],
            receipt_required=True,
        )

    # 2. Per-purpose allow/deny → the baseline allowed set.
    rule = policy.purposes.get(plan.purpose)
    if rule is not None and rule.allow is not None:
        allowed = [f for f in requested if f in rule.allow]
    elif rule is not None and rule.deny:
        allowed = [f for f in requested if f not in rule.deny]
    else:
        allowed = list(requested)

    # 3. Minimum disclosure to external destinations: strip sensitive fields
    #    before anything leaves the trust boundary.
    goes_external = any(d in policy.external_destinations for d in plan.destinations)
    if goes_external and policy.sensitive_fields:
        allowed = [f for f in allowed if f not in policy.sensitive_fields]

    blocked = [f for f in requested if f not in allowed]

    # 4. Approval seam: action-type rules.
    approval_required_for: list[str] = []
    act_rule = policy.actions.get(plan.action_type)
    if act_rule is not None and act_rule.requires_approval:
        approval_required_for.append(plan.action_type)

    # 5. Reason codes + outcome (priority: approval > reduce > allow).
    reason_codes: list[str] = []
    if blocked:
        reason_codes.append("DATA_NOT_REQUIRED_FOR_PURPOSE")
    if goes_external and any(f in policy.sensitive_fields for f in requested):
        reason_codes.append("EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE")
    if approval_required_for:
        reason_codes.append("ACTION_REQUIRES_HUMAN_APPROVAL")

    if approval_required_for:
        outcome = BoundaryOutcome.REQUIRE_APPROVAL
    elif blocked:
        outcome = BoundaryOutcome.REDUCE_SCOPE
    else:
        outcome = BoundaryOutcome.ALLOW

    return BoundaryDecision(
        outcome=outcome,
        purpose=plan.purpose,
        allowed_data=allowed,
        blocked_data=blocked,
        allowed_tools=list(plan.tools),
        approval_required_for=approval_required_for,
        reason_codes=reason_codes,
        receipt_required=(outcome is not BoundaryOutcome.ALLOW) or bool(blocked),
    )
