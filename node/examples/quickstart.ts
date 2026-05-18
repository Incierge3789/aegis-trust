// aegis-trust — Quickstart Example
//
// npm install aegis-trust
// npx tsx examples/quickstart.ts

import { shield } from "../src/index.js";

// Before: agent sees everything
function getCustomerUnsafe(_id: number) {
  return {
    name: "Tanaka Taro",
    email: "tanaka@example.com",
    card: "4242-****-****-1234",
    issue: "Login problem",
  };
}

// After: agent sees only what it needs
const getCustomer = shield({
  purpose: "customer_support",
  scope: ["name", "issue"],
})((_id: number) => ({
  name: "Tanaka Taro",
  email: "tanaka@example.com",
  card: "4242-****-****-1234",
  issue: "Login problem",
}));

console.log("=== Without shield ===");
console.log(getCustomerUnsafe(1));

console.log("\n=== With shield ===");
console.log(getCustomer(1));
// → { name: "Tanaka Taro", issue: "Login problem" }
// email and card are never exposed to the agent
