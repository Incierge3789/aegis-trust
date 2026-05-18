// Same data, different purposes — each agent sees only what it needs.

import { shield } from "../src/index.js";

const CUSTOMERS: Record<string, Record<string, unknown>> = {
  "C-001": {
    name: "Alice Johnson",
    email: "alice@example.com",
    phone: "+1-555-0100",
    ssn: "123-45-6789",
    plan: "enterprise",
    balance: 2500.0,
    internal_score: 95,
  },
};

const getForSupport = shield({
  purpose: "support",
  scope: ["name", "email", "phone"],
})((customerId: string) => CUSTOMERS[customerId]);

const getForBilling = shield({
  purpose: "billing",
  scope: ["name", "plan", "balance"],
})((customerId: string) => CUSTOMERS[customerId]);

const getForAnalytics = shield({
  purpose: "analytics",
  denyFields: ["ssn", "internal_score"],
})((customerId: string) => CUSTOMERS[customerId]);

const cid = "C-001";

console.log("Support agent sees:");
console.log(getForSupport(cid));

console.log("\nBilling agent sees:");
console.log(getForBilling(cid));

console.log("\nAnalytics agent sees:");
console.log(getForAnalytics(cid));
