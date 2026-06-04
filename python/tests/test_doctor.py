"""Tests for the Doctor primitive (aegis_trust.doctor), v0."""

import pytest

from aegis_trust import shield
from aegis_trust.doctor import (
    DOCTOR_SCHEMA_VERSION,
    ActionPlan,
    ActionRule,
    BoundaryOutcome,
    BoundaryReceipt,
    LocalPolicy,
    PurposeRule,
    check,
)
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


POLICY = LocalPolicy(
    purposes={"customer_support": PurposeRule(allow=["name", "issue"])},
    sensitive_fields=["email", "card_number"],
    never_fields=["password", "ssn", ".env"],
    external_destinations=["external_llm"],
    actions={"send": ActionRule(requires_approval=True)},
)


def _plan(**kw) -> ActionPlan:
    base = dict(
        purpose="customer_support",
        action_type="generate_draft",
        data_requested=["name", "issue"],
        destinations=["internal_reply"],
    )
    base.update(kw)
    return ActionPlan(**base)


class TestDoctor:
    def test_allow_when_request_matches_purpose(self):
        d = check(_plan(data_requested=["name", "issue"]), POLICY)
        assert d.outcome is BoundaryOutcome.ALLOW
        assert d.allowed_data == ["name", "issue"]
        assert d.blocked_data == []

    def test_reduce_scope_drops_unneeded_fields(self):
        d = check(
            _plan(data_requested=["name", "issue", "email", "card_number"]), POLICY
        )
        assert d.outcome is BoundaryOutcome.REDUCE_SCOPE
        assert d.allowed_data == ["name", "issue"]
        assert set(d.blocked_data) == {"email", "card_number"}
        assert "DATA_NOT_REQUIRED_FOR_PURPOSE" in d.reason_codes

    def test_external_destination_strips_sensitive_even_without_purpose_rule(self):
        # purpose with no allow rule; sensitive fields still stripped for external
        d = check(
            ActionPlan(
                purpose="unlisted",
                action_type="generate_draft",
                data_requested=["name", "email", "card_number"],
                destinations=["external_llm"],
            ),
            POLICY,
        )
        assert d.outcome is BoundaryOutcome.REDUCE_SCOPE
        assert d.allowed_data == ["name"]
        assert set(d.blocked_data) == {"email", "card_number"}
        assert "EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE" in d.reason_codes

    def test_require_approval_for_send_action(self):
        d = check(_plan(action_type="send", data_requested=["name", "issue"]), POLICY)
        assert d.outcome is BoundaryOutcome.REQUIRE_APPROVAL
        assert d.approval_required_for == ["send"]
        assert "ACTION_REQUIRES_HUMAN_APPROVAL" in d.reason_codes

    def test_block_when_forbidden_field_requested(self):
        d = check(_plan(data_requested=["name", "password"]), POLICY)
        assert d.outcome is BoundaryOutcome.BLOCK
        assert d.allowed_data == []  # fail-closed: nothing allowed
        assert "FORBIDDEN_FIELD_REQUESTED" in d.reason_codes

    def test_decision_feeds_shield_end_to_end(self):
        plan = _plan(
            data_requested=["name", "issue", "email", "card_number"],
            destinations=["external_llm"],
        )
        decision = check(plan, POLICY)

        @shield(purpose=plan.purpose, scope=decision.allowed_data)
        def get_customer():
            return {
                "name": "Tanaka",
                "issue": "Login",
                "email": "t@example.com",
                "card_number": "4242",
            }

        out = get_customer()
        assert out == {"name": "Tanaka", "issue": "Login"}
        assert "email" not in out and "card_number" not in out

    def test_empty_policy_is_permissive_but_deterministic(self):
        # No policy → no rules → ALLOW everything requested (caller opted out).
        d = check(_plan(data_requested=["name", "issue", "email"]))
        assert d.outcome is BoundaryOutcome.ALLOW
        assert d.allowed_data == ["name", "issue", "email"]

    def test_contracts_carry_schema_version(self):
        d = check(_plan(), POLICY)
        assert d.schema_version == DOCTOR_SCHEMA_VERSION
        r = d.to_receipt(receipt_id="br_001")
        assert isinstance(r, BoundaryReceipt)
        assert r.schema_version == DOCTOR_SCHEMA_VERSION
        assert r.evidence_mode == "local" and r.core_verified is False

    def test_reduce_then_approval_priority(self):
        # send action with over-broad data: approval takes precedence as the outcome,
        # but blocked_data still records what would be reduced.
        d = check(
            _plan(action_type="send", data_requested=["name", "issue", "email"]), POLICY
        )
        assert d.outcome is BoundaryOutcome.REQUIRE_APPROVAL
        assert "email" in d.blocked_data
