// LangChain.js + aegis-trust — filter PII before the LLM sees it.
//
// Setup:
//   npm install aegis-trust langchain @langchain/openai @langchain/core
//
// Run:
//   OPENAI_API_KEY=... npx tsx examples/langchainExample.ts
//
// What it shows:
//   A LangChain agent calls a customer-lookup tool to handle a support
//   ticket. Without the shield, the LLM sees the full customer record —
//   email, SSN, credit card, everything. With the dedicated LangChain
//   adapter (`shieldedTool` + `toLangChainTool`), the tool returns only what
//   the declared purpose (customer_support) is allowed to see. SSN and card
//   never reach the model context, the model logs, or the provider's
//   training pipeline.

import { shieldedTool, toLangChainTool } from "../src/adapters/index.js";

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
// return anything outside the support scope, and toLangChainTool() binds it to
// a native LangChain StructuredTool (the `tool` factory is injected so this
// package takes no dependency on LangChain).

const customerLookup = shieldedTool<{ customer_id: string }>({
  name: "customer_lookup",
  description: "Look up a customer record by ID for support purposes.",
  purpose: "customer_support",
  scope: ["name", "plan", "last_login", "issue"],
  handler: async ({ customer_id }) => CUSTOMERS[customer_id] ?? {},
});

// ── LangChain wiring (or fallback if not installed) ─────

async function main() {
  let langchainAvailable = false;
  try {
    await import("@langchain/openai");
    await import("@langchain/core/tools");
    langchainAvailable = true;
  } catch {
    // not installed
  }

  if (!langchainAvailable) {
    await runWithoutLangchain();
    return;
  }

  const { ChatOpenAI } = await import("@langchain/openai");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tools: any = await import("@langchain/core/tools");
  const { tool } = tools;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const langchain: any = await import("langchain/agents");

  // The adapter binds the shielded tool to a native LangChain StructuredTool.
  // shield filtering + JSON serialization are baked in — the agent only ever
  // sees the support-scoped fields.
  const lookupTool = toLangChainTool(tool, customerLookup);

  const llm = new ChatOpenAI({ model: "gpt-4o-mini", temperature: 0 });
  const agent = await langchain.createToolCallingAgent({
    llm,
    tools: [lookupTool],
    prompt: [
      ["system", "You are a customer support agent. Use tools to help."],
      ["human", "{input}"],
      ["placeholder", "{agent_scratchpad}"],
    ],
  });
  const executor = new langchain.AgentExecutor({
    agent,
    tools: [lookupTool],
    verbose: true,
  });
  const result = await executor.invoke({
    input: "Customer C-1001 needs help. Look them up and summarize.",
  });
  console.log("\n=== Agent answer ===");
  console.log(result.output);
  console.log(
    "\nNote: the agent never saw email, ssn, credit_card, or internal_notes.\n"
      + "Those were filtered out by shield(...) before the tool returned.",
  );
}

async function runWithoutLangchain() {
  console.log("This example can run a real LangChain agent with:");
  console.log("    npm install langchain @langchain/openai @langchain/core\n");
  console.log("=== Raw record (what the tool would normally return) ===");
  console.log(CUSTOMERS["C-1001"]);
  console.log("\n=== shield-filtered record (what the agent actually sees) ===");
  console.log(await customerLookup.run({ customer_id: "C-1001" }));
  console.log(
    "\nThe LLM never sees email, ssn, credit_card, phone, or internal_notes.",
  );
}

main();
