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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # FULL/gateway-mode types only. Importing AegisClient at runtime pulls the
    # optional gateway dependencies (httpx, attrs) into the import graph; the
    # real client is obtained lazily via ``shield._get_client()`` inside
    # ``check_with_core()`` below, so a LITE-only install
    # (``from aegis_trust.doctor import check``) carries no runtime dependency
    # and importing the public ``aegis_trust.doctor`` package never touches httpx.
    from aegis_trust.client import AegisClient, BoundaryDecisionView
from aegis_trust.doctor.types import to_core_verified_receipt  # noqa: F401 (receipt bridge)
from aegis_trust.doctor.types import (
    DOCTOR_SCHEMA_VERSION,
    ActionPlan,
    BoundaryDecision,
    BoundaryReceipt,
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
    # Review finding D (invariant parity with v0 ``check()``): an allow set is
    # only meaningful for a grant. For ALLOW / REDUCE_SCOPE we carry the Core
    # ``allowed_fields``; for REQUIRE_CHECK / REQUIRE_APPROVAL / BLOCK we FORCE
    # the allow set to empty so a Core ``BLOCKED`` body that (incorrectly)
    # carries non-empty ``allowed_fields`` can never populate ``allowed_data``.
    grants = outcome in (BoundaryOutcome.ALLOW, BoundaryOutcome.REDUCE_SCOPE)
    allowed_data = list(view.allowed_fields) if grants else []
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


# Sentinel destination sent when a plan declares MORE THAN ONE destination.
# The /check-boundary endpoint accepts a single ``Option<String>`` destination,
# so only one of the plan's destinations could be sent. Sending just the first
# (the prior behaviour) UNDER-estimates the boundary: the riskiest sink might be
# the second one, and the server would evaluate the (possibly trusted) first
# destination and ALLOW. Review finding F: instead, when there are multiple
# destinations we send a reserved sentinel that cannot match any trusted
# internal destination, so the server can only evaluate it as an
# unknown/external sink — the decision can get STRICTER, never looser.
_MULTI_DESTINATION_SENTINEL = "__aegis_multi_external__"


def _resolve_destination(destinations: list[str]) -> str | None:
    """Choose the single destination to send (fail-closed for multi-dest)."""
    if not destinations:
        return None
    if len(destinations) == 1:
        return destinations[0]
    # >1 destination: most-restrictive sentinel (treated as external/unknown).
    return _MULTI_DESTINATION_SENTINEL


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
    try:
        if client is None:
            from aegis_trust.shield import _get_client

            client = _get_client()

        destination = _resolve_destination(plan.destinations)
        # ``agent_id`` is an IDENTITY claim the gateway constant-time compares to
        # the authenticated JWT subject (mismatch -> 403 -> fail-closed BLOCK). It
        # must come ONLY from an explicit TrustContext, never from the ActionPlan's
        # local-diagnostic ``agent_id``/``environment`` (whose defaults
        # ``"unknown"``/``"local"`` would mismatch every real subject and make
        # Doctor v1 always BLOCK). Omitted when no context -> the gateway uses the
        # JWT subject alone. (Found by the live SDK<->gateway e2e; Node parity.)
        agent_id = context.agent_id if context is not None else None
        environment = context.environment if context is not None else None
        mode = context.mode if context is not None else None

        view = await client.acheck_boundary(
            plan.purpose,
            list(plan.data_requested),
            destination=destination,
            agent_id=agent_id,
            environment=environment,
            mode=mode,
            schema_version=plan.schema_version or DOCTOR_SCHEMA_VERSION,
        )
        if view.outcome not in _OUTCOME_MAP:
            # Unknown outcome string -> fail-closed BLOCK.
            logger.warning("check_with_core: unknown Core outcome, fail-closed")
            return _fail_closed(plan.purpose, "CORE_MALFORMED_RESPONSE")

        # Review finding E: the mapping is INSIDE the fail-closed try so a
        # malformed plan (e.g. plan.tools is None) raises here and BLOCKs,
        # rather than escaping as a raw exception.
        return _map_view(view, plan)
    except ValueError:
        # Malformed / partial / unparseable body (_parse_boundary_view raises
        # ValueError) -> fail-closed BLOCK. Distinct reason code for parity.
        logger.warning("check_with_core: malformed Core response, fail-closed")
        return _fail_closed(plan.purpose, "CORE_MALFORMED_RESPONSE")
    except Exception:
        # Network error / timeout / non-2xx (raise_for_status), client
        # acquisition error, or mapping error -> fail-closed BLOCK.
        logger.warning("check_with_core: Core unavailable, fail-closed")
        return _fail_closed(plan.purpose, "CORE_UNAVAILABLE")


async def check_with_core_receipt(
    plan: ActionPlan,
    *,
    receipt_id: str,
    enforcement_status: str = "PENDING",
    client: "AegisClient | None" = None,
    context: "TrustContext | None" = None,
) -> "tuple[BoundaryDecision, BoundaryReceipt]":
    """Core round-trip -> (decision, Core-verified receipt) from the REAL Core
    Evidence on the response (never caller-supplied). Safe path: core_verified
    only from an actual /check-boundary response (parity with Node
    checkWithCoreReceipt, closes §7 review P1). Fail-closed: error/malformed ->
    BLOCK decision + LITE-local receipt."""
    try:
        if client is None:
            from aegis_trust.shield import _get_client

            client = _get_client()
        destination = _resolve_destination(plan.destinations)
        agent_id = context.agent_id if context is not None else None
        environment = context.environment if context is not None else None
        mode = context.mode if context is not None else None
        view = await client.acheck_boundary(
            plan.purpose,
            list(plan.data_requested),
            destination=destination,
            agent_id=agent_id,
            environment=environment,
            mode=mode,
            schema_version=plan.schema_version or DOCTOR_SCHEMA_VERSION,
        )
        if view.outcome not in _OUTCOME_MAP:
            d = _fail_closed(plan.purpose, "CORE_MALFORMED_RESPONSE")
            return d, d.to_receipt(
                receipt_id=receipt_id, enforcement_status=enforcement_status
            )
        decision = _map_view(view, plan)
        receipt = to_core_verified_receipt(
            decision,
            getattr(view, "evidence", None),
            receipt_id=receipt_id,
            enforcement_status=enforcement_status,
        )
        return decision, receipt
    except ValueError:
        d = _fail_closed(plan.purpose, "CORE_MALFORMED_RESPONSE")
        return d, d.to_receipt(
            receipt_id=receipt_id, enforcement_status=enforcement_status
        )
    except Exception:
        d = _fail_closed(plan.purpose, "CORE_UNAVAILABLE")
        return d, d.to_receipt(
            receipt_id=receipt_id, enforcement_status=enforcement_status
        )
