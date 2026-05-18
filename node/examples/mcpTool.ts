// aegis-trust + MCP — Model Context Protocol tool with data access control.
//
// Install:
//   npm install aegis-trust @modelcontextprotocol/sdk
//
// Run:
//   npx tsx examples/mcpTool.ts

import { shield } from "../src/index.js";

// Simulated database
const CUSTOMERS: Record<string, Record<string, unknown>> = {
  "C-001": {
    name: "Tanaka Taro",
    email: "tanaka@example.com",
    card: "4242-****-****-1234",
    ssn: "123-45-6789",
    issue: "Login problem",
    plan: "enterprise",
  },
};

// Wrap any data-fetching function before registering it as an MCP tool.
// shield(...) returns a function with the same signature; you can pass it
// to your MCP server's tool registry directly.

const getCustomer = shield({
  purpose: "customer_support",
  scope: ["name", "issue"],
})(async (customerId: string) => CUSTOMERS[customerId] ?? {});

const getCustomerBilling = shield({
  purpose: "billing",
  denyFields: ["ssn", "card"],
})(async (customerId: string) => CUSTOMERS[customerId] ?? {});

// Pseudo-MCP integration — replace with your MCP server's tool registration.
//
// import { Server } from "@modelcontextprotocol/sdk/server";
// const server = new Server({ name: "customer-service", version: "1.0.0" }, {});
// server.setRequestHandler("tools/call", async (req) => {
//   if (req.params.name === "get_customer") {
//     return await getCustomer(req.params.arguments.customer_id);
//   }
//   if (req.params.name === "get_customer_billing") {
//     return await getCustomerBilling(req.params.arguments.customer_id);
//   }
// });

async function demo() {
  console.log("=== customer_support (scope) ===");
  console.log(await getCustomer("C-001"));
  // → { name: "Tanaka Taro", issue: "Login problem" }

  console.log("\n=== billing (denyFields) ===");
  console.log(await getCustomerBilling("C-001"));
  // → { name: "Tanaka Taro", email: ..., issue: ..., plan: ... }
  //    (ssn and card removed)
}

demo();
