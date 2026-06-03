"""CrewAI (Python) + aegis-trust — per-agent scope on shared data.

Setup:
    pip install aegis-trust crewai

Run:
    OPENAI_API_KEY=... python examples/crewai_example.py

What it shows:
    Two agents — Support and Billing — sharing one customer record. Each agent
    has a different shield purpose, so the same underlying data produces a
    different view per agent. Cross-context leakage (Support seeing card
    numbers, Billing seeing escalation notes) is structurally prevented.

    The shield is at the data layer, not the framework — so this pattern works
    identically with LangGraph, AutoGen, or any agent that accepts a tool.
"""
from aegis_trust.adapters import shielded_tool, to_crewai_tool

CUSTOMERS = {
    "C-1001": {
        "name": "Tanaka Taro",
        "email": "tanaka@example.com",
        "ssn": "123-45-6789",
        "credit_card": "4242-****-****-1234",
        "plan": "enterprise",
        "balance_due": 1250.0,
        "billing_address": "1-2-3 Shibuya, Tokyo",
        "issue": "Cannot reset password",
        "internal_notes": "Tier 2 escalation",
    }
}

support_lookup = shielded_tool(
    name="customer_lookup_support",
    description="Look up a customer for support work.",
    purpose="customer_support",
    scope=["name", "plan", "issue"],
    handler=lambda customer_id: CUSTOMERS.get(customer_id, {}),
)
billing_lookup = shielded_tool(
    name="customer_lookup_billing",
    description="Look up a customer for billing work.",
    purpose="billing",
    scope=["name", "plan", "balance_due", "billing_address"],
    handler=lambda customer_id: CUSTOMERS.get(customer_id, {}),
)


def main() -> None:
    try:
        from crewai.tools import BaseTool
    except ImportError:
        print("This example can wire real CrewAI tools with:")
        print("    pip install crewai\n")
        print("=== Full record (what the data source returns) ===")
        print(CUSTOMERS["C-1001"])
        print("\n=== What the Support agent sees ===")
        print(support_lookup.run(customer_id="C-1001"))
        print("\n=== What the Billing agent sees ===")
        print(billing_lookup.run(customer_id="C-1001"))
        print("\nNeither agent saw ssn, credit_card, email, or internal_notes.")
        return

    support_tool = to_crewai_tool(BaseTool, support_lookup)
    billing_tool = to_crewai_tool(BaseTool, billing_lookup)
    # Hand support_tool / billing_tool to their respective crewai Agents.
    print("Support tool:", support_tool.name, "->", support_tool.run(customer_id="C-1001"))
    print("Billing tool:", billing_tool.name, "->", billing_tool.run(customer_id="C-1001"))


if __name__ == "__main__":
    main()
