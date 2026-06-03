// Vercel AI SDK + aegis-trust — filter PII before the LLM sees it.
//
// Setup:
//   npm install aegis-trust ai @ai-sdk/openai zod
//
// Run:
//   OPENAI_API_KEY=... npx tsx examples/vercelAiExample.ts
//
// What it shows:
//   A Vercel AI SDK tool call (`generateText` with a `customer_lookup` tool)
//   handles a support ticket. Without the shield, the tool would hand the LLM
//   the full customer record — email, SSN, credit card, everything. With the
//   dedicated adapter (`shieldedTool` + `toVercelTool`), the tool's execute()
//   returns only the support-scoped fields. SSN and card never reach the model
//   context, the model logs, or the provider's training pipeline.
//
// Note on AI SDK versions: the tool schema key is `inputSchema` on AI SDK v5+
// (the adapter default) and `parameters` on v4 and earlier — pass
// `toVercelTool(tool, { schemaKey: "parameters" })` for v4.

import { shieldedTool, toVercelTool } from "../src/adapters/index.js";

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

// ── The shielded tool ─────────────────────────────────────
//
// One shieldedTool(...) declaration is the whole integration; toVercelTool()
// produces the AI SDK tool object. The `schema` is passed through to the SDK
// untouched (aegis-trust never inspects tool arguments).

async function buildTool() {
  let zodAvailable = false;
  try {
    await import("zod");
    zodAvailable = true;
  } catch {
    // zod not installed — fall back to a bare schema object below.
  }

  let schema: unknown = { type: "object", properties: { customer_id: { type: "string" } } };
  if (zodAvailable) {
    const { z } = await import("zod");
    schema = z.object({ customer_id: z.string() });
  }

  return shieldedTool<{ customer_id: string }>({
    name: "customer_lookup",
    description: "Look up a customer record by ID for support purposes.",
    purpose: "customer_support",
    scope: ["name", "plan", "last_login", "issue"],
    schema,
    handler: async ({ customer_id }) => CUSTOMERS[customer_id] ?? {},
  });
}

// ── Vercel AI SDK wiring (or fallback if not installed) ───

async function main() {
  const customerLookup = await buildTool();

  let aiAvailable = false;
  try {
    await import("ai");
    await import("@ai-sdk/openai");
    aiAvailable = true;
  } catch {
    // not installed
  }

  if (!aiAvailable) {
    await runWithoutAiSdk(customerLookup);
    return;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ai: any = await import("ai");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const openaiMod: any = await import("@ai-sdk/openai");
  const openai = openaiMod.openai ?? openaiMod.default;

  const result = await ai.generateText({
    model: openai("gpt-4o-mini"),
    tools: {
      // toVercelTool bakes in shield filtering; execute() returns the
      // support-scoped view of the record only.
      customer_lookup: toVercelTool(customerLookup),
    },
    maxSteps: 3,
    prompt: "Customer C-1001 needs help. Look them up and summarize their issue.",
  });

  console.log("\n=== Agent answer ===");
  console.log(result.text);
  console.log(
    "\nNote: the model never saw email, ssn, credit_card, phone, or internal_notes.\n"
      + "Those were filtered out by the shield before the tool returned.",
  );
}

async function runWithoutAiSdk(customerLookup: Awaited<ReturnType<typeof buildTool>>) {
  console.log("This example can run a real Vercel AI SDK tool call with:");
  console.log("    npm install ai @ai-sdk/openai zod\n");
  console.log("=== Raw record (what the tool would normally return) ===");
  console.log(CUSTOMERS["C-1001"]);
  console.log("\n=== shield-filtered record (what the model actually sees) ===");
  const tool = toVercelTool(customerLookup);
  console.log(await tool.execute({ customer_id: "C-1001" }));
  console.log(
    "\nThe model never sees email, ssn, credit_card, phone, or internal_notes.",
  );
}

main();
