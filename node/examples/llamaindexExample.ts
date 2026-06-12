// LlamaIndex.TS + aegis-trust — filter PII before the LLM sees it.
//
// Setup:
//   npm install aegis-trust llamaindex
//
// Run:
//   OPENAI_API_KEY=... npx tsx examples/llamaindexExample.ts
//
// What it shows:
//   A LlamaIndex tool handles a support ticket. Without the shield, the LLM
//   sees the full customer record — email, SSN, credit card, everything. With
//   the dedicated LlamaIndex adapter (`shieldedTool` + `toLlamaIndexTool`), the
//   tool returns only what the declared purpose (customer_support) is allowed
//   to see. SSN and card never reach the model context, the model logs, or the
//   provider's training pipeline.

import { shieldedTool, toLlamaIndexTool } from "../src/adapters/index.js";

// ── Simulated customer database ───────────────────────────

const CUSTOMERS: Record<string, Record<string, unknown>> = {
  "C-1001": {
    name: "Tanaka Taro",
    email: "tanaka@example.com",
    phone: "+81-90-1234-5678",
    ssn: "123-45-6789",
    credit_card: "4242-****-****-1234",
    plan: "enterprise",
    last_login: "2026-05-15T08:23:00Z",
    issue: "Cannot reset password",
    internal_notes: "Tier 2 escalation — billing dispute pending",
  },
};

// ── The tool the agent will call ──────────────────────────
//
// One shieldedTool(...) declaration is the entire integration. It refuses to
// return anything outside the support scope, and toLlamaIndexTool() binds it to
// a native LlamaIndex FunctionTool (the `FunctionTool.from` factory is injected
// so this package takes no dependency on LlamaIndex).

const customerLookup = shieldedTool<{ customer_id: string }>({
  name: "customer_lookup",
  description: "Look up a customer record by ID for support purposes.",
  purpose: "customer_support",
  scope: ["name", "plan", "last_login", "issue"],
  handler: async ({ customer_id }) => CUSTOMERS[customer_id] ?? {},
});

// ── LlamaIndex wiring (or fallback if not installed) ─────

async function main() {
  let llamaindexAvailable = false;
  try {
    await import("llamaindex");
    llamaindexAvailable = true;
  } catch {
    // not installed
  }

  if (!llamaindexAvailable) {
    await runWithoutLlamaIndex();
    return;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const llamaindex: any = await import("llamaindex");
  const { FunctionTool } = llamaindex;

  // The adapter binds the shielded tool to a native LlamaIndex FunctionTool.
  // shield filtering + JSON serialization are baked in — the agent only ever
  // sees the support-scoped fields. Hand `lookupTool` to a FunctionAgent /
  // ReActAgent; invoked directly here to show the filtered output.
  const lookupTool = toLlamaIndexTool(FunctionTool.from, customerLookup);
  const out = await lookupTool.call({ customer_id: "C-1001" });
  console.log("\n=== Tool output (what the agent sees) ===");
  console.log(out);
  console.log(
    "\nNote: the agent never saw email, ssn, credit_card, or internal_notes.\n"
      + "Those were filtered out by shield(...) before the tool returned.",
  );
}

async function runWithoutLlamaIndex() {
  console.log("This example can run a real LlamaIndex tool with:");
  console.log("    npm install llamaindex\n");
  console.log("=== Raw record (what the tool would normally return) ===");
  console.log(CUSTOMERS["C-1001"]);
  console.log("\n=== shield-filtered record (what the agent actually sees) ===");
  console.log(await customerLookup.run({ customer_id: "C-1001" }));
  console.log(
    "\nThe LLM never sees email, ssn, credit_card, phone, or internal_notes.",
  );
}

main();
