"""Tests for the Doctor primitive Core-backed entry point (check_with_core), v1.

Mirrors node/tests/doctorCore.test.ts 1:1: the five outcome mappings, the
fail-closed paths (network error / non-2xx / malformed body -> BLOCK with empty
allowed_data), scope_for_shield coupling, and request shaping.
"""

from __future__ import annotations

import httpx
import pytest

from aegis_trust.client import BoundaryDecisionView
from aegis_trust.doctor import ActionPlan, BoundaryOutcome, check_with_core
from aegis_trust.doctor.types import TrustContext


def _plan(**kw) -> ActionPlan:
    base = dict(
        purpose="customer_support",
        action_type="generate_draft",
        data_requested=["name", "issue", "email"],
        destinations=["internal_reply"],
    )
    base.update(kw)
    return ActionPlan(**base)


def _view(**overrides) -> BoundaryDecisionView:
    base = dict(
        source="CORE",
        outcome="PROTECTED",
        purpose_label="customer_support",
        allowed_fields=["name", "issue"],
        withheld_fields=[],
        reason_code="minimum_disclosure",
        reason_label="Minimum disclosure",
        evidence_available=True,
        evidence=None,
    )
    base.update(overrides)
    return BoundaryDecisionView(**base)


class _FakeClient:
    """Stands in for AegisClient — only acheck_boundary is exercised."""

    def __init__(self, impl):
        self._impl = impl
        self.last_kwargs: dict | None = None

    async def acheck_boundary(self, purpose, scope, **kwargs):
        self.last_kwargs = {"purpose": purpose, "scope": scope, **kwargs}
        return await self._impl(purpose, scope, **kwargs)


def _client_returning(view: BoundaryDecisionView) -> _FakeClient:
    async def impl(purpose, scope, **kw):
        return view

    return _FakeClient(impl)


# ── outcome mapping ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_protected_maps_to_allow():
    client = _client_returning(
        _view(outcome="PROTECTED", allowed_fields=["name", "issue"], withheld_fields=[])
    )
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.ALLOW
    assert d.allowed_data == ["name", "issue"]
    assert d.policy_version == "core-v1"
    assert "minimum_disclosure" in d.reason_codes


@pytest.mark.asyncio
async def test_access_reduced_maps_to_reduce_scope():
    client = _client_returning(
        _view(
            outcome="ACCESS_REDUCED", allowed_fields=["name"], withheld_fields=["email"]
        )
    )
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.REDUCE_SCOPE
    assert d.allowed_data == ["name"]
    assert d.blocked_data == ["email"]


@pytest.mark.asyncio
async def test_check_required_maps_to_require_check():
    client = _client_returning(_view(outcome="CHECK_REQUIRED"))
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.REQUIRE_CHECK


@pytest.mark.asyncio
async def test_approval_required_maps_and_carries_action_type():
    client = _client_returning(_view(outcome="APPROVAL_REQUIRED"))
    d = await check_with_core(_plan(action_type="send"), client=client)
    assert d.outcome is BoundaryOutcome.REQUIRE_APPROVAL
    assert d.approval_required_for == ["send"]


@pytest.mark.asyncio
async def test_blocked_maps_to_block():
    client = _client_returning(
        _view(outcome="BLOCKED", allowed_fields=[], withheld_fields=["ssn"])
    )
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert d.allowed_data == []


# ── fail-closed ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_network_error_fails_closed():
    async def impl(purpose, scope, **kw):
        raise httpx.ConnectError("refused")

    client = _FakeClient(impl)
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert d.allowed_data == []
    assert "CORE_UNAVAILABLE" in d.reason_codes


@pytest.mark.asyncio
async def test_non_2xx_fails_closed():
    # The real client raises HTTPStatusError via raise_for_status on non-2xx.
    async def impl(purpose, scope, **kw):
        raise httpx.HTTPStatusError(
            "503",
            request=httpx.Request("POST", "http://x"),
            response=httpx.Response(503),
        )

    client = _FakeClient(impl)
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert d.allowed_data == []
    assert "CORE_UNAVAILABLE" in d.reason_codes


@pytest.mark.asyncio
async def test_malformed_body_fails_closed():
    # The real client's _parse_boundary_view raises ValueError on a bad shape.
    async def impl(purpose, scope, **kw):
        raise ValueError("check-boundary: 'outcome' missing or not a str")

    client = _FakeClient(impl)
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert d.allowed_data == []
    assert "CORE_MALFORMED_RESPONSE" in d.reason_codes


@pytest.mark.asyncio
async def test_unknown_outcome_fails_closed():
    client = _client_returning(_view(outcome="MAYBE"))
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert "CORE_MALFORMED_RESPONSE" in d.reason_codes


@pytest.mark.asyncio
async def test_prototype_pollution_outcome_fails_closed():
    # Finding C: an inherited-style attribute string like "toString" is not a
    # member of _OUTCOME_MAP (dict membership is own-key in Python) -> BLOCK.
    client = _client_returning(_view(outcome="toString"))
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert "CORE_MALFORMED_RESPONSE" in d.reason_codes


@pytest.mark.asyncio
async def test_blocked_with_allowed_fields_clears_allow_set():
    # Finding D: a BLOCKED view that (incorrectly) carries allowed_fields must
    # not populate allowed_data.
    client = _client_returning(
        _view(
            outcome="BLOCKED", allowed_fields=["name", "ssn"], withheld_fields=["ssn"]
        )
    )
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert d.allowed_data == []
    assert d.scope_for_shield() == []


@pytest.mark.asyncio
async def test_check_required_with_allowed_fields_clears_allow_set():
    # Finding D: REQUIRE_CHECK / REQUIRE_APPROVAL also clear the allow set.
    client = _client_returning(_view(outcome="CHECK_REQUIRED", allowed_fields=["name"]))
    d = await check_with_core(_plan(), client=client)
    assert d.outcome is BoundaryOutcome.REQUIRE_CHECK
    assert d.allowed_data == []


@pytest.mark.asyncio
async def test_mapping_error_fails_closed():
    # Finding E: a malformed plan (tools is None -> list(None) raises) must
    # BLOCK because the mapping is inside the fail-closed try.
    client = _client_returning(_view())
    bad_plan = _plan()
    object.__setattr__(bad_plan, "tools", None)
    d = await check_with_core(bad_plan, client=client)
    assert d.outcome is BoundaryOutcome.BLOCK
    assert "CORE_UNAVAILABLE" in d.reason_codes


# ── destination fail-closed (finding F) ─────────────────────


@pytest.mark.asyncio
async def test_single_destination_sent_as_is():
    client = _client_returning(_view())
    await check_with_core(_plan(destinations=["internal_reply"]), client=client)
    assert client.last_kwargs is not None
    assert client.last_kwargs["destination"] == "internal_reply"


@pytest.mark.asyncio
async def test_multi_destination_uses_restrictive_sentinel():
    client = _client_returning(_view())
    await check_with_core(
        _plan(destinations=["internal_reply", "external_llm"]), client=client
    )
    assert client.last_kwargs is not None
    # Never the first (possibly-trusted) destination — a restrictive sentinel.
    assert client.last_kwargs["destination"] == "__aegis_multi_external__"
    assert client.last_kwargs["destination"] != "internal_reply"


# ── scope_for_shield coupling ───────────────────────────────


@pytest.mark.asyncio
async def test_scope_for_shield_allow():
    client = _client_returning(
        _view(outcome="PROTECTED", allowed_fields=["name", "issue"], withheld_fields=[])
    )
    d = await check_with_core(_plan(), client=client)
    assert d.scope_for_shield() == ["name", "issue"]


@pytest.mark.asyncio
async def test_scope_for_shield_reduce_scope():
    client = _client_returning(
        _view(
            outcome="ACCESS_REDUCED", allowed_fields=["name"], withheld_fields=["email"]
        )
    )
    d = await check_with_core(_plan(), client=client)
    assert d.scope_for_shield() == ["name"]


@pytest.mark.asyncio
async def test_scope_for_shield_block_yields_nothing():
    client = _client_returning(_view(outcome="BLOCKED", allowed_fields=[]))
    d = await check_with_core(_plan(), client=client)
    assert d.scope_for_shield() == []


# ── request shaping ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_request_shaping_no_principal():
    client = _client_returning(_view())
    await check_with_core(
        _plan(
            data_requested=["name", "issue"],
            destinations=["external_llm"],
            agent_id="agent-7",
        ),
        client=client,
        context=TrustContext(
            agent_id="agent-7", purpose="customer_support", mode="full"
        ),
    )
    kw = client.last_kwargs
    assert kw is not None
    assert kw["scope"] == ["name", "issue"]
    assert kw["destination"] == "external_llm"
    assert kw["agent_id"] == "agent-7"
    assert kw["mode"] == "full"
    assert "principal" not in kw
