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
        # purpose with no allow rule; sensitive fields still stripped for external.
        # strict_unknown_purpose=False opts into the permissive-unknown path so
        # this exercises the sensitive-strip seam (see the strict variant below).
        permissive = LocalPolicy(
            purposes={"customer_support": PurposeRule(allow=["name", "issue"])},
            sensitive_fields=["email", "card_number"],
            never_fields=["password", "ssn", ".env"],
            external_destinations=["external_llm"],
            actions={"send": ActionRule(requires_approval=True)},
            strict_unknown_purpose=False,
        )
        d = check(
            ActionPlan(
                purpose="unlisted",
                action_type="generate_draft",
                data_requested=["name", "email", "card_number"],
                destinations=["external_llm"],
            ),
            permissive,
        )
        assert d.outcome is BoundaryOutcome.REDUCE_SCOPE
        assert d.allowed_data == ["name"]
        assert set(d.blocked_data) == {"email", "card_number"}
        assert "EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE" in d.reason_codes

    def test_unknown_purpose_fails_closed_by_default(self):
        # Trust-boundary hardening: an unknown purpose against a non-empty policy
        # must NOT allow everything requested (the attacker cannot disable the
        # whitelist by inventing a purpose string).
        d = check(
            _plan(purpose="support_v2", data_requested=["name", "ssn_alias", "card"]),
            POLICY,
        )
        assert d.allowed_data == []
        assert d.outcome is BoundaryOutcome.REDUCE_SCOPE

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


class TestTrustBoundaryHardening:
    """Regression suite for the doctor→shield fail-open class (S-redteam).

    Each case is a confirmed bypass that must now fail closed end-to-end:
    feed the decision's enforcement-coupled scope into shield and assert the
    forbidden value never surfaces.
    """

    def _emit(self, scope, record):
        @shield(purpose="p", scope=scope)
        def get():
            return record

        return get()

    def test_f1_dotnotation_does_not_escape_never_block(self):
        d = check(
            ActionPlan(purpose="p", action_type="read", data_requested=["profile.ssn"]),
            LocalPolicy(never_fields=["ssn"]),
        )
        assert d.outcome is BoundaryOutcome.BLOCK
        assert d.scope_for_shield() == []

    def test_f2_bare_parent_does_not_leak_child_secret(self):
        # Doctor allows the bare parent name it cannot introspect, but shield
        # now drops a bare leaf over a nested mapping fail-closed.
        assert self._emit(["config"], {"config": {"api_key": "SECRET"}}) == {}

    def test_f3_unknown_destination_treated_external(self):
        d = check(
            ActionPlan(
                purpose="p",
                action_type="send",
                data_requested=["ssn"],
                destinations=["evilcorp"],
            ),
            LocalPolicy(
                sensitive_fields=["ssn"], external_destinations=["external_llm"]
            ),
        )
        assert d.scope_for_shield() == []

    def test_f7_deny_blacklist_path_aware(self):
        d = check(
            ActionPlan(purpose="p", action_type="read", data_requested=["profile.ssn"]),
            LocalPolicy(purposes={"p": PurposeRule(deny=["ssn"])}),
        )
        assert d.scope_for_shield() == []

    def test_f9_casing_cannot_dodge_never(self):
        d = check(
            ActionPlan(purpose="p", action_type="read", data_requested=["SSN"]),
            LocalPolicy(never_fields=["ssn"]),
        )
        assert d.outcome is BoundaryOutcome.BLOCK

    def test_a1_parent_in_never_blocks_child_request(self):
        d = check(
            ActionPlan(
                purpose="p", action_type="read", data_requested=["config.api_key"]
            ),
            LocalPolicy(never_fields=["config"]),
        )
        assert d.outcome is BoundaryOutcome.BLOCK

    def test_a2_approval_decision_yields_no_enforceable_scope(self):
        d = check(
            ActionPlan(
                purpose="p",
                action_type="send",
                data_requested=["ssn", "name"],
            ),
            LocalPolicy(actions={"send": ActionRule(requires_approval=True)}),
        )
        assert d.outcome is BoundaryOutcome.REQUIRE_APPROVAL
        # Diagnostic still populated, but the enforcement-coupled scope is empty:
        # nothing flows before the human approval is cleared.
        assert d.allowed_data == ["ssn", "name"]
        assert d.scope_for_shield() == []
        assert self._emit(d.scope_for_shield(), {"ssn": "S", "name": "n"}) == {}

    def test_f12_malformed_path_fails_closed_at_gate(self):
        d = check(
            ActionPlan(purpose="p", action_type="read", data_requested=["a..b"]),
            LocalPolicy(),
        )
        assert d.outcome is BoundaryOutcome.BLOCK
        assert "MALFORMED_FIELD_PATH" in d.reason_codes

    def test_cx2_nfkc_folds_fullwidth_onto_ascii_guard(self):
        # codex cross-review: NFC left full-width 'ＳＳＮ' distinct from 'ssn'.
        d = check(
            ActionPlan(purpose="p", action_type="read", data_requested=["ＳＳＮ"]),
            LocalPolicy(never_fields=["ssn"]),
        )
        assert d.outcome is BoundaryOutcome.BLOCK

    def test_cx3_prototype_chain_purpose_cannot_dodge_guard(self):
        # Parity with the Node fix: a dunder purpose must not be treated as a
        # known rule-less purpose. (Python's dict.get is immune by construction;
        # this locks the behaviour as a cross-SDK contract.)
        for purpose in ("__proto__", "__class__", "constructor"):
            d = check(
                ActionPlan(
                    purpose=purpose,
                    action_type="read",
                    data_requested=["name", "ssn", "card"],
                ),
                LocalPolicy(purposes={"support": PurposeRule(allow=["name"])}),
            )
            assert d.scope_for_shield() == []
