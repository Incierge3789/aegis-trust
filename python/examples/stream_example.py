"""Streaming + aegis-trust — filter each record at its boundary as it arrives.

Setup:
    pip install aegis-trust

Run:
    python examples/stream_example.py

What it shows:
    A data accessor that yields customer records ONE AT A TIME (a DB cursor, a
    paginated fetch, or an upstream LLM emitting one JSON object per step).
    ``shielded_stream_tool()`` filters each WHOLE record the moment it is
    complete — without buffering the entire result first, which is the
    limitation ``shielded_tool()`` has. ssn / credit_card / internal_notes never
    leave the boundary; the consumer only ever sees the support-scoped view.

    No framework is required — streaming is a pure local (LITE) filter. Mode
    note: streaming supports LITE only. Passing ``mode="full"`` raises
    ``aegis.shield.stream.full_unsupported`` (the FULL /check-access gate cannot
    run per-record without leaking how many rows matched). Use
    ``shielded_tool()`` for the FULL gate.
"""

import asyncio

from aegis_trust.adapters import shielded_stream_tool

# ── Simulated paginated data source (each row carries PII) ─

ROWS = [
    {
        "name": "Tanaka Taro",
        "email": "tanaka@example.com",
        "ssn": "123-45-6789",
        "credit_card": "4242-****-****-1234",
        "plan": "enterprise",
        "issue": "Cannot reset password",
        "internal_notes": "Tier 2 escalation — billing dispute pending",
    },
    {
        "name": "Suzuki Hanako",
        "email": "suzuki@example.com",
        "ssn": "987-65-4321",
        "credit_card": "4111-****-****-5678",
        "plan": "pro",
        "issue": "Billing question on last invoice",
        "internal_notes": "VIP — handle within 2h",
    },
]


def customer_cursor(q: str):
    """Yield one record at a time (the shape streaming is built for)."""
    for row in ROWS:
        # (a real cursor would fetch the next page here)
        if q == "open" or q in row["issue"].lower():
            yield row


# ── The shielded streaming tool ───────────────────────────

customer_rows = shielded_stream_tool(
    name="customer_rows",
    description="Stream customer records for a support session.",
    purpose="customer_support",
    scope=["name", "plan", "issue"],
    handler=customer_cursor,
)


async def main() -> None:
    print("=== Raw rows (what the cursor yields) ===")
    for row in ROWS:
        print(row)

    print("\n=== Shield-filtered stream (what the consumer sees, one at a time) ===")
    async for rec in customer_rows.stream("open"):
        # rec is {name, plan, issue} only — filtered the moment the record was whole.
        print(rec)

    print(
        "\nEach record was filtered at its boundary as it arrived — no full-result "
        "buffering. ssn, credit_card, email, and internal_notes never left the shield."
    )


if __name__ == "__main__":
    asyncio.run(main())
