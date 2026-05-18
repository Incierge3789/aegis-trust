// Async function with shield(...) — works seamlessly with async functions.

import { shield } from "../src/index.js";

const getTicket = shield({
  purpose: "support",
  scope: ["name", "issue", "status"],
})(async (_ticketId: string) => {
  // In production this would be an async DB call.
  await new Promise((r) => setTimeout(r, 10));
  return {
    name: "Alice Johnson",
    issue: "Login not working",
    status: "open",
    ssn: "123-45-6789",
    internal_notes: "Escalate to tier 2",
  };
});

async function main() {
  const result = await getTicket("T-001");
  console.log("Agent sees:", result);
  // → { name: "Alice Johnson", issue: "Login not working", status: "open" }
  // ssn and internal_notes are filtered out
}

main();
