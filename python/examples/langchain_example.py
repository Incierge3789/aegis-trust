"""LangChain (Python) + aegis-trust — filter PII before the LLM sees it.

Setup:
    pip install aegis-trust langchain-core langchain-openai

Run:
    OPENAI_API_KEY=... python examples/langchain_example.py

What it shows:
    A customer-lookup tool handles a support ticket. Without the shield the LLM
    sees the full customer record — email, SSN, credit card, everything. With
    the dedicated adapter (`shielded_tool` + `to_langchain_tool`) the tool
    returns only the support-scoped fields. SSN and card never reach the model
    context, the model logs, or the provider's training pipeline.
"""
from aegis_trust.adapters import shielded_tool, to_langchain_tool

CUSTOMERS = {
    "C-1001": {
        "name": "Tanaka Taro",
        "email": "tanaka@example.com",
        "phone": "+81-90-1234-5678",
        "ssn": "123-45-6789",
        "credit_card": "4242-****-****-1234",
        "plan": "enterprise",
        "last_login": "2026-05-15T08:23:00Z",
        "issue": "Cannot reset password",
        "internal_notes": "Tier 2 escalation",
    }
}

# One shielded_tool(...) declaration is the whole integration.
customer_lookup = shielded_tool(
    name="customer_lookup",
    description="Look up a customer record by ID for support purposes.",
    purpose="customer_support",
    scope=["name", "plan", "last_login", "issue"],
    handler=lambda customer_id: CUSTOMERS.get(customer_id, {}),
)


def main() -> None:
    try:
        from langchain_core.tools import StructuredTool
    except ImportError:
        print("This example can run a real LangChain tool with:")
        print("    pip install langchain-core langchain-openai\n")
        print("=== Raw record (what the tool would normally return) ===")
        print(CUSTOMERS["C-1001"])
        print("\n=== shield-filtered record (what the agent actually sees) ===")
        print(customer_lookup.run(customer_id="C-1001"))
        print("\nThe LLM never sees email, ssn, credit_card, phone, or internal_notes.")
        return

    lc_tool = to_langchain_tool(StructuredTool.from_function, customer_lookup)
    # Hand `lc_tool` to your agent / AgentExecutor. Invoked directly here:
    print(lc_tool.invoke({"customer_id": "C-1001"}))
    print("\nThe agent never saw email, ssn, credit_card, or internal_notes.")


if __name__ == "__main__":
    main()
