"""aegis-trust Doctor — diagnose an agent's action BEFORE it runs, then enforce.

Setup:
    pip install aegis-trust

Run:
    python examples/doctor_example.py

What it shows:
    A support agent intends to pull a customer record and draft a reply with an
    external LLM. doctor.check() diagnoses the plan against a local policy and
    returns a BoundaryDecision: drop email/card_number (not needed for the
    purpose, and sensitive for an external destination). That decision feeds
    shield() directly, so the agent only ever receives the reduced record.
    No LLM, no network, no Aegis Core — fully local and deterministic.
"""

from aegis_trust import shield
from aegis_trust.doctor import ActionPlan, ActionRule, LocalPolicy, PurposeRule, check

policy = LocalPolicy(
    purposes={"customer_support": PurposeRule(allow=["name", "issue"])},
    sensitive_fields=["email", "card_number"],
    never_fields=["password", "ssn"],
    external_destinations=["external_llm"],
    actions={"send": ActionRule(requires_approval=True)},
)

plan = ActionPlan(
    agent_id="support_agent",
    purpose="customer_support",
    action_type="generate_draft",
    data_requested=["name", "issue", "email", "card_number"],
    tools=["crm.read", "llm.generate"],
    destinations=["external_llm"],
)

decision = check(plan, policy)

print("Doctor decision:", decision.outcome.value)
print("  allowed:", decision.allowed_data)
print("  blocked before the agent runs:", decision.blocked_data)
print("  reasons:", decision.reason_codes)


# Enforce the decision: shield filters the real fetch to the allowed scope.
@shield(purpose=plan.purpose, scope=decision.allowed_data)
def get_customer() -> dict[str, str]:
    return {
        "name": "Tanaka Taro",
        "issue": "Login problem",
        "email": "tanaka@example.com",
        "card_number": "4242-****-****-1234",
    }


print("Agent receives:", get_customer())
# -> {'name': 'Tanaka Taro', 'issue': 'Login problem'} — email/card_number never reach the model.
