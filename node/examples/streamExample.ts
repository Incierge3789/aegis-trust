// Streaming + aegis-trust — filter each record at its boundary as it arrives.
//
// Setup:
//   npm install aegis-trust
//
// Run:
//   npx tsx examples/streamExample.ts
//
// What it shows:
//   A data accessor that yields customer records ONE AT A TIME (a DB cursor, a
//   paginated fetch, or an upstream LLM emitting one JSON object per step).
//   `shieldedStreamTool()` filters each WHOLE record the moment it is complete —
//   without buffering the entire result first, which is the limitation
//   `shieldedTool()` has. ssn / credit_card / internal_notes never leave the
//   boundary; the consumer only ever sees the support-scoped view.
//
// No framework is required — streaming is a pure local (LITE) filter. Mode note:
//   streaming supports LITE only. Passing `mode: "full"` throws
//   `aegis.shield.stream.full_unsupported` (the FULL /check-access gate cannot
//   run per-record without leaking how many rows matched). Use shieldedTool()
//   for the FULL gate.

import { shieldedStreamTool } from "../src/adapters/index.js";

// ── Simulated paginated data source (each row carries PII) ─

const ROWS: Record<string, unknown>[] = [
  {
    name: "Tanaka Taro",
    email: "tanaka@example.com",
    ssn: "123-45-6789",
    credit_card: "4242-****-****-1234",
    plan: "enterprise",
    issue: "Cannot reset password",
    internal_notes: "Tier 2 escalation — billing dispute pending",
  },
  {
    name: "Suzuki Hanako",
    email: "suzuki@example.com",
    ssn: "987-65-4321",
    credit_card: "4111-****-****-5678",
    plan: "pro",
    issue: "Billing question on last invoice",
    internal_notes: "VIP — handle within 2h",
  },
];

// A cursor that yields one record at a time (the shape streaming is built for).
async function* customerCursor({ q }: { q: string }): AsyncGenerator<Record<string, unknown>> {
  for (const row of ROWS) {
    // (a real cursor would await the next page here)
    if (q === "open" || (row.issue as string).toLowerCase().includes(q)) {
      yield row;
    }
  }
}

// ── The shielded streaming tool ───────────────────────────

const customerRows = shieldedStreamTool<{ q: string }>({
  name: "customer_rows",
  description: "Stream customer records for a support session.",
  purpose: "customer_support",
  scope: ["name", "plan", "issue"],
  handler: customerCursor,
});

async function main() {
  console.log("=== Raw rows (what the cursor yields) ===");
  for (const row of ROWS) console.log(row);

  console.log("\n=== Shield-filtered stream (what the consumer sees, one at a time) ===");
  for await (const rec of customerRows.stream({ q: "open" })) {
    // rec is { name, plan, issue } only — filtered the moment the record was whole.
    console.log(rec);
  }

  console.log(
    "\nEach record was filtered at its boundary as it arrived — no full-result "
      + "buffering. ssn, credit_card, email, and internal_notes never left the "
      + "shield.",
  );
}

main();
