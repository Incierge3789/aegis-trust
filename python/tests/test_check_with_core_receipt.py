from types import SimpleNamespace

import pytest

from aegis_trust.doctor import check_with_core_receipt
from aegis_trust.doctor.types import ActionPlan, BoundaryOutcome


def _plan():
    return ActionPlan(purpose="draft_reply", action_type="read", data_requested=["name"], destinations=[])


def _view(with_evidence: bool):
    ev = (
        SimpleNamespace(
            decision_id="core-dec-1",
            enforced_by="Aegis Core",
            integrity_checkable_at="https://core/evidence/core-dec-1",
            recorded_at="2026-06-22T00:00:00Z",
        )
        if with_evidence
        else None
    )
    return SimpleNamespace(
        source="CORE",
        outcome="PROTECTED",
        purpose_label="draft_reply",
        allowed_fields=["name"],
        withheld_fields=["email_body"],
        reason_code="ok",
        reason_label="ok",
        evidence_available=with_evidence,
        evidence=ev,
    )


class _StubClient:
    def __init__(self, view_or_raise):
        self._v = view_or_raise

    async def acheck_boundary(self, *a, **k):
        if self._v == "raise":
            raise RuntimeError("network")
        return self._v


@pytest.mark.asyncio
async def test_verified_from_real_core_evidence():
    decision, receipt = await check_with_core_receipt(
        _plan(), receipt_id="rc1", client=_StubClient(_view(True))
    )
    assert receipt.core_verified is True
    assert receipt.core_evidence.decision_id == "core-dec-1"


@pytest.mark.asyncio
async def test_fail_closed_no_evidence():
    _decision, receipt = await check_with_core_receipt(
        _plan(), receipt_id="rc2", client=_StubClient(_view(False))
    )
    assert receipt.core_verified is False
    assert receipt.core_evidence is None


@pytest.mark.asyncio
async def test_fail_closed_network_error():
    decision, receipt = await check_with_core_receipt(
        _plan(), receipt_id="rc3", client=_StubClient("raise")
    )
    assert decision.outcome == BoundaryOutcome.BLOCK
    assert receipt.core_verified is False
