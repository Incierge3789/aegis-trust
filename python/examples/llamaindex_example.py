"""LlamaIndex (Python) + aegis-trust — filter PII before the LLM sees it.

Setup:
    pip install aegis-trust llama-index-core

Run:
    python examples/llamaindex_example.py

What it shows:
    A customer-lookup tool handles a support ticket. Without the shield the LLM
    sees the full customer record — email, SSN, credit card, everything. With
    the dedicated adapter (`shielded_tool` + `to_llamaindex_tool`) the tool
    returns only the support-scoped fields. SSN and card never reach the model
    context, the model logs, or the provider's training pipeline.
"""

from aegis_trust.adapters import shielded_tool, to_llamaindex_tool

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
        from llama_index.core.tools import FunctionTool
    except ImportError:
        print("This example can run a real LlamaIndex tool with:")
        print("    pip install llama-index-core\n")
        print("=== Raw record (what the tool would normally return) ===")
        print(CUSTOMERS["C-1001"])
        print("\n=== shield-filtered record (what the agent actually sees) ===")
        print(customer_lookup.run(customer_id="C-1001"))
        print("\nThe LLM never sees email, ssn, credit_card, phone, or internal_notes.")
        return

    li_tool = to_llamaindex_tool(FunctionTool.from_defaults, customer_lookup)
    # Hand `li_tool` to your agent (e.g. FunctionAgent / ReActAgent). Called directly here:
    print(li_tool.call(customer_id="C-1001"))
    print("\nThe agent never saw email, ssn, credit_card, or internal_notes.")


if __name__ == "__main__":
    main()
