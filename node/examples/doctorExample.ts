// aegis-trust Doctor — diagnose an agent's action BEFORE it runs, then enforce.
//
// Setup:
//   npm install aegis-trust
//
// Run:
//   npx tsx examples/doctorExample.ts
//
// What it shows:
//   A support agent intends to pull a customer record and draft a reply with an
//   external LLM. doctor.check() diagnoses the plan against a local policy and
//   returns a BoundaryDecision: drop email/card_number (not needed for the
//   purpose, and sensitive for an external destination). That decision feeds
//   shield() directly, so the agent only ever receives the reduced record.
//   No LLM, no network, no Aegis Core — fully local and deterministic.

import { shield } from "aegis-trust";
import { check, type ActionPlan, type LocalPolicy } from "aegis-trust/doctor";

const policy: LocalPolicy = {
  purposes: { customer_support: { allow: ["name", "issue"] } },
  sensitiveFields: ["email", "card_number"],
  neverFields: ["password", "ssn"],
  externalDestinations: ["external_llm"],
  actions: { send: { requiresApproval: true } },
};

const plan: ActionPlan = {
  agentId: "support_agent",
  purpose: "customer_support",
  actionType: "generate_draft",
  dataRequested: ["name", "issue", "email", "card_number"],
  tools: ["crm.read", "llm.generate"],
  destinations: ["external_llm"],
};

const decision = check(plan, policy);

console.log("Doctor decision:", decision.outcome);
console.log("  allowed:", decision.allowedData);
console.log("  blocked before the agent runs:", decision.blockedData);
console.log("  reasons:", decision.reasonCodes);

// Enforce the decision: shield filters the real fetch to the allowed scope.
const getCustomer = shield({ purpose: plan.purpose, scope: [...decision.allowedData] })(() => ({
  name: "Tanaka Taro",
  issue: "Login problem",
  email: "tanaka@example.com",
  card_number: "4242-****-****-1234",
}));

const result = await getCustomer();
console.log("Agent receives:", result);
// → { name: 'Tanaka Taro', issue: 'Login problem' } — email/card_number never reach the model.
