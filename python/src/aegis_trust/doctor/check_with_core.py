"""Doctor v1 (Python) — Core-backed boundary check.

1:1 mirror of node/src/doctor/checkWithCore.ts.

    from aegis_trust.doctor import check_with_core

``check_with_core(plan, ...)`` asks Aegis Core (POST ``/check-boundary``) to
decide an Actor's :class:`ActionPlan` BEFORE execution and maps the
authoritative ``BoundaryDecisionView`` into the SDK's :class:`BoundaryDecision`.
Feed ``decision.scope_for_shield()`` into ``shield(scope=...)`` to enforce it.

FAIL-CLOSED: any network error, non-2xx, or malformed response yields a BLOCK
decision with an empty allow set — never raises raw, never allows on error. This
mirrors the SDK's existing fail-closed philosophy (AO-002/AO-003).

The local, deterministic :func:`aegis_trust.doctor.check` (v0) remains untouched
and exported.
"""

from __future__ import annotations

import logging

from aegis_trust.client import AegisClient, BoundaryDecisionView
from aegis_trust.doctor.types import (
    DOCTOR_SCHEMA_VERSION,
    ActionPlan,
    BoundaryDecision,
    BoundaryOutcome,
    TrustContext,
)

logger = logging.getLogger("aegis")

# CORE policy marker — distinguishes a Core-authoritative decision from the
# local-preview v0 (``local-preview-v1``).
_CORE_POLICY_VERSION = "core-v1"

# Outcome map: Core ``BoundaryDecisionView.outcome`` -> SDK ``BoundaryOutcome``.
#   PROTECTED -> ALLOW, ACCESS_REDUCED -> REDUCE_SCOPE,
#   CHECK_REQUIRED -> REQUIRE_CHECK, APPROVAL_REQUIRED -> REQUIRE_APPROVAL,
#   BLOCKED -> BLOCK.
_OUTCOME_MAP: dict[str, BoundaryOutcome] = {
    "PROTECTED": BoundaryOutcome.ALLOW,
    "ACCESS_REDUCED": BoundaryOutcome.REDUCE_SCOPE,
    "CHECK_REQUIRED": BoundaryOutcome.REQUIRE_CHECK,
    "APPROVAL_REQUIRED": BoundaryOutcome.REQUIRE_APPROVAL,
    "BLOCKED": BoundaryOutcome.BLOCK,
}


def _fail_closed(purpose: str, reason_code: str) -> BoundaryDecision:
    """A fail-closed BLOCK decision with an empty allow set. Never discloses."""
    return BoundaryDecision(
        outcome=BoundaryOutcome.BLOCK,
        purpose=purpose,
        allowed_data=[],
        blocked_data=[],
        allowed_tools=[],
        approval_required_for=[],
        reason_codes=[reason_code],
        policy_version=_CORE_POLICY_VERSION,
        receipt_required=True,
        schema_version=DOCTOR_SCHEMA_VERSION,
    )


def _map_view(view: BoundaryDecisionView, plan: ActionPlan) -> BoundaryDecision:
    """Map a validated ``BoundaryDecisionView`` into a :class:`BoundaryDecision`."""
    outcome = _OUTCOME_MAP[view.outcome]
    allowed_data = list(view.allowed_fields)
    blocked_data = list(view.withheld_fields)
    reason_codes = [view.reason_code] if view.reason_code else []
    approval_required_for = (
        [plan.action_type] if outcome is BoundaryOutcome.REQUIRE_APPROVAL else []
    )
    return BoundaryDecision(
        outcome=outcome,
        purpose=view.purpose_label or plan.purpose,
        allowed_data=allowed_data,
        blocked_data=blocked_data,
        allowed_tools=list(plan.tools),
        approval_required_for=approval_required_for,
        reason_codes=reason_codes,
        policy_version=_CORE_POLICY_VERSION,
        receipt_required=outcome is not BoundaryOutcome.ALLOW or bool(blocked_data),
        schema_version=DOCTOR_SCHEMA_VERSION,
    )


async def check_with_core(
    plan: ActionPlan,
    *,
    client: AegisClient | None = None,
    context: TrustContext | None = None,
) -> BoundaryDecision:
    """Diagnose ``plan`` against Aegis Core (POST ``/check-boundary``).

    Async (network). Fail-closed on every error path. The request is built from
    the :class:`ActionPlan` (+ optional :class:`TrustContext`); the principal is
    the JWT subject server-side and is never sent in the body.

    Args:
        plan: the Actor's declared action plan.
        client: the network client. Defaults to the shield module-level client.
        context: trust context (agent_id / environment / mode). ``principal`` is
            NOT sent.
    """
    if client is None:
        from aegis_trust.shield import _get_client

        client = _get_client()

    destination = plan.destinations[0] if plan.destinations else None
    agent_id = context.agent_id if context is not None else plan.agent_id
    environment = context.environment if context is not None else plan.environment
    mode = context.mode if context is not None else None

    try:
        view = await client.acheck_boundary(
            plan.purpose,
            list(plan.data_requested),
            destination=destination,
            agent_id=agent_id,
            environment=environment,
            mode=mode,
            schema_version=plan.schema_version or DOCTOR_SCHEMA_VERSION,
        )
    except ValueError:
        # Malformed / unparseable body (_parse_boundary_view raises ValueError)
        # -> fail-closed BLOCK. Distinct reason code for Node/Python parity.
        logger.warning("check_with_core: malformed Core response, fail-closed")
        return _fail_closed(plan.purpose, "CORE_MALFORMED_RESPONSE")
    except Exception:
        # Network error / timeout / non-2xx (raise_for_status) -> fail-closed.
        logger.warning("check_with_core: Core unavailable, fail-closed")
        return _fail_closed(plan.purpose, "CORE_UNAVAILABLE")

    if view.outcome not in _OUTCOME_MAP:
        # Unknown outcome string -> fail-closed BLOCK.
        logger.warning("check_with_core: unknown Core outcome, fail-closed")
        return _fail_closed(plan.purpose, "CORE_MALFORMED_RESPONSE")

    return _map_view(view, plan)
