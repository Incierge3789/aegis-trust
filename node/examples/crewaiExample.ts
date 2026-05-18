// CrewAI (Node port) + aegis-trust — per-agent scope on shared data.
//
// Setup:
//   npm install aegis-trust crewai
//
// Run:
//   OPENAI_API_KEY=... npx tsx examples/crewaiExample.ts
//
// What it shows:
//   Two agents — Support and Billing — sharing one customer record. Each
//   agent has a different shield(...) purpose, so the same underlying data
//   produces a different view per agent. Cross-context leakage (Support
//   agent seeing card numbers, Billing agent seeing internal escalation
//   notes) is structurally prevented.
//
// The shield is at the data layer, not the framework — so this pattern
// works identically with LangGraph, AutoGen, swarm, or any multi-agent
// framework.

import { shield } from "../src/index.js";

const CUSTOMERS: Record<string, Record<string, unknown>> = {
  "C-1001": {
    name: "Tanaka Taro",
    email: "tanaka@example.com",
    phone: "+81-90-1234-5678",
    ssn: "123-45-6789",
    credit_card: "4242-****-****-1234",
    plan: "enterprise",
    balance_due: 1250.0,
    billing_address: "1-2-3 Shibuya, Tokyo",
    last_login: "2026-05-15T08:23:00Z",
    issue: "Cannot reset password",
    internal_notes: "Tier 2 escalation — billing dispute pending",
  },
};

// ── Two scoped tools backed by the same data source ──────

const getCustomerForSupport = shield({
  purpose: "customer_support",
  scope: ["name", "plan", "last_login", "issue"],
})(async (customerId: string) => CUSTOMERS[customerId] ?? {});

const getCustomerForBilling = shield({
  purpose: "billing",
  scope: ["name", "plan", "balance_due", "billing_address"],
})(async (customerId: string) => CUSTOMERS[customerId] ?? {});

// ── CrewAI wiring (or fallback if not installed) ─────────

async function main() {
  let crewAvailable = false;
  try {
    await import("crewai");
    crewAvailable = true;
  } catch {
    // not installed
  }

  if (!crewAvailable) {
    await runWithoutCrew();
    return;
  }

  // crewai is a community Node port (`crewai` on npm). API surface differs
  // slightly from the Python original. The pattern below uses the
  // documented Crew/Agent/Task primitives. If they have moved, adjust to
  // match the installed version's API — the shield(...) integration is
  // independent of any specific framework version.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const crew: any = await import("crewai");

  const supportAgent = new crew.Agent({
    role: "Customer Support Specialist",
    goal: "Resolve customer issues using only support-scoped data",
    backstory: "A senior support engineer with limited data access.",
    tools: [
      {
        name: "customer_lookup_support",
        description: "Look up a customer for support work.",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        run: async (args: any) => getCustomerForSupport(args.customer_id),
      },
    ],
  });

  const billingAgent = new crew.Agent({
    role: "Billing Analyst",
    goal: "Review billing status using only billing-scoped data",
    backstory: "A billing specialist with limited data access.",
    tools: [
      {
        name: "customer_lookup_billing",
        description: "Look up a customer for billing work.",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        run: async (args: any) => getCustomerForBilling(args.customer_id),
      },
    ],
  });

  const supportTask = new crew.Task({
    description: "Look up customer C-1001 and summarize their issue.",
    expectedOutput: "A 1-sentence summary of the customer's issue.",
    agent: supportAgent,
  });

  const billingTask = new crew.Task({
    description: "Look up customer C-1001 and report their balance due.",
    expectedOutput: "A 1-sentence statement of the balance due.",
    agent: billingAgent,
  });

  const c = new crew.Crew({
    agents: [supportAgent, billingAgent],
    tasks: [supportTask, billingTask],
  });
  const result = await c.kickoff();
  console.log("\n=== Crew result ===");
  console.log(result);
  console.log(
    "\nNote: support saw only {name, plan, last_login, issue};\n"
      + "billing saw only {name, plan, balance_due, billing_address}.\n"
      + "Neither saw ssn, credit_card, phone, email, or internal_notes.",
  );
}

async function runWithoutCrew() {
  console.log("This example can run a real CrewAI crew with:");
  console.log("    npm install crewai\n");
  console.log("=== Full record (what the data source returns) ===");
  console.log(CUSTOMERS["C-1001"]);

  console.log("\n=== What the Support agent sees ===");
  console.log(await getCustomerForSupport("C-1001"));

  console.log("\n=== What the Billing agent sees ===");
  console.log(await getCustomerForBilling("C-1001"));
}

main();
