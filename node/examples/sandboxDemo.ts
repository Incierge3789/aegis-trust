// aegis-trust sandbox — dummy data + agent request + audit log.
//
// Run:
//   npx tsx examples/sandboxDemo.ts
//
//   or (after install):
//   npx aegis sandbox
//
// Shows the entire value of aegis-trust in 10 seconds without any setup.

import { appendFileSync } from "node:fs";
import { resolve } from "node:path";

import { shield } from "../src/index.js";

const DUMMY_USER: Record<string, unknown> = {
  user_id: "u_123",
  name: "Aria Sato",
  email: "aria@example.com",
  phone: "+81-80-1111-2222",
  ssn: "234-56-7890",
  credit_card: "5555-****-****-4242",
  plan: "pro",
  last_login: "2026-05-15T08:23:00Z",
  internal_notes: "VIP, do not contact about renewals",
};

const getUser = shield({
  purpose: "customer_support",
  scope: ["user_id", "plan", "last_login"],
})((_userId: string) => DUMMY_USER);

function auditPath(): string {
  return process.env.AEGIS_SANDBOX_AUDIT
    ?? resolve(process.cwd(), "aegis-sandbox-audit.jsonl");
}

function emitAudit(allowed: Record<string, unknown>, blocked: string[]): string {
  const path = auditPath();
  const entry = {
    timestamp: new Date().toISOString(),
    agent: "support_agent",
    purpose: "customer_support",
    requested_id: "u_123",
    allowed_fields: Object.keys(allowed).sort(),
    blocked_fields: blocked,
    decision: "filtered",
    reason: "fields outside declared scope",
  };
  appendFileSync(path, JSON.stringify(entry) + "\n");
  return path;
}

export function run(): number {
  console.log("Aegis sandbox demo");
  console.log("─".repeat(60));
  console.log();
  console.log("1. Source record (what the database / API would return):");
  for (const k of Object.keys(DUMMY_USER).sort()) {
    console.log(`     ${k}: ${DUMMY_USER[k]}`);
  }
  console.log();
  console.log("2. Agent request:");
  console.log('     getUser("u_123")   under purpose="customer_support"');
  console.log();

  const result = getUser("u_123") as Record<string, unknown>;
  const blocked = Object.keys(DUMMY_USER)
    .filter((k) => !(k in result))
    .sort();
  const path = emitAudit(result, blocked);

  console.log("3. Aegis decision:");
  console.log("     ┌────────────────────────────────────────────────────────┐");
  console.log("     │ Agent:        support_agent");
  console.log("     │ Purpose:      customer_support");
  console.log(`     │ Requested:    ${Object.keys(DUMMY_USER).sort().join(", ")}`);
  console.log(`     │ ✓ Allowed:    ${Object.keys(result).sort().join(", ")}`);
  console.log(`     │ ✗ Blocked:    ${blocked.join(", ")}`);
  console.log("     │ Decision:     filtered");
  console.log(`     │ Audit:        ${path}`);
  console.log("     └────────────────────────────────────────────────────────┘");
  console.log();
  console.log("4. What the agent actually sees:");
  console.log(`     ${JSON.stringify(result, null, 2).split("\n").join("\n     ")}`);
  console.log();
  console.log("5. Use in your own code:");
  console.log("     import { shield } from \"aegis-trust\";");
  console.log("     const fn = shield({ purpose: \"your_purpose\", scope: [\"a\", \"b\"] })(yourTool);");
  console.log();
  console.log(`To delete sandbox artifacts:  rm ${path}`);
  return 0;
}

run();
