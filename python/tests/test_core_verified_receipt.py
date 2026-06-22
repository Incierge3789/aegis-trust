from aegis_trust.doctor.types import (
    BoundaryDecision,
    BoundaryOutcome,
    to_core_verified_receipt,
)


def _decision():
    return BoundaryDecision(
        outcome=BoundaryOutcome.ALLOW,
        purpose="draft_reply",
        allowed_data=["name"],
        blocked_data=["email_body"],
    )


GOOD = {
    "decision_id": "dec-123",
    "enforced_by": "Aegis Core",
    "integrity_checkable_at": "https://core/evidence/dec-123",
    "recorded_at": "2026-06-22T00:00:00Z",
}


def test_verified_with_real_core_evidence():
    r = to_core_verified_receipt(_decision(), GOOD, receipt_id="r1")
    assert r.core_verified is True
    assert r.evidence_mode == "core"
    assert r.core_evidence.decision_id == "dec-123"
    assert r.core_evidence.integrity_checkable_at == "https://core/evidence/dec-123"


def test_fail_closed_no_evidence():
    r = to_core_verified_receipt(_decision(), None, receipt_id="r2")
    assert r.core_verified is False
    assert r.evidence_mode == "local"
    assert r.core_evidence is None


def test_fail_closed_missing_decision_id():
    r = to_core_verified_receipt(
        _decision(), {**GOOD, "decision_id": ""}, receipt_id="r3"
    )
    assert r.core_verified is False
    assert r.core_evidence is None


def test_fail_closed_missing_integrity_url():
    bad = {k: v for k, v in GOOD.items() if k != "integrity_checkable_at"}
    r = to_core_verified_receipt(_decision(), bad, receipt_id="r4")
    assert r.core_verified is False
    assert r.core_evidence is None


def test_lite_to_receipt_unchanged():
    r = _decision().to_receipt(receipt_id="r5")
    assert r.core_verified is False
    assert r.core_evidence is None
    assert r.evidence_mode == "local"


class _EvidenceObj:
    # Mirrors the SDK's CoreDecisionEvidence dataclass (attribute-shaped, not dict).
    def __init__(self):
        self.decision_id = "dec-9"
        self.enforced_by = "Aegis Core"
        self.integrity_checkable_at = "https://core/evidence/dec-9"
        self.recorded_at = "2026-06-22T00:00:00Z"


def test_verified_with_sdk_evidence_dataclass_not_dict():
    # codex P2: the FULL path passes the dataclass, not a dict.
    r = to_core_verified_receipt(_decision(), _EvidenceObj(), receipt_id="r6")
    assert r.core_verified is True
    assert r.core_evidence.decision_id == "dec-9"


def test_fail_closed_whitespace_only():
    bad = {**GOOD, "decision_id": "   ", "integrity_checkable_at": "   "}
    r = to_core_verified_receipt(_decision(), bad, receipt_id="r7")
    assert r.core_verified is False
    assert r.core_evidence is None
