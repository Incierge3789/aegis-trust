// Minimal MCP callable proof runner — agent → shield → audit, end-to-end.
//
// Demonstrates the four-link chain that the v0.9.0-rc1 productization gate
// is designed to verify:
//   1. Agent reasoning step opens a trace context (`withTraceContext`).
//   2. The agent calls an MCP tool, which is `shield()`-wrapped.
//   3. shield filters the data per declared purpose + scope.
//   4. The local audit JSONL records the call with the matching `trace_id`.
//
// Run (from sdk/node-trust):
//   npm run build
//   AEGIS_HISTORY=1 AEGIS_HISTORY_PATH=/tmp/aegis-mcp-e2e.jsonl \
//     node tests/mcp/run_end_to_end.mjs
//
// The companion `examples/mcpEndToEnd.ts` is the documentation-form file
// (imports from the published package name). This runner imports from
// `../../dist/index.js` so it executes without a transpile step and is
// used to materialise the audit JSONL for the trace_propagation verifier.

import { mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  newTraceId,
  resetStore,
  shield,
  withTraceContext,
} from "../../dist/index.js";

process.env.AEGIS_HISTORY = "1";
if (!process.env.AEGIS_HISTORY_PATH) {
  // Fresh dir per run: a fixed default path accumulates records across runs
  // and the trace_id match below would fail on the second local invocation.
  const dir = mkdtempSync(join(tmpdir(), "aegis-mcp-e2e-"));
  process.env.AEGIS_HISTORY_PATH = join(dir, "audit.jsonl");
}

resetStore();

const CUSTOMERS = {
  "C-001": {
    name: "Tanaka Taro",
    email: "tanaka@example.com",
    card: "4242-****-****-1234",
    ssn: "123-45-6789",
    issue: "Login problem",
    plan: "enterprise",
    last_login: "2026-05-16T09:00:00Z",
  },
};

async function db_fetch(customerId) {
  return CUSTOMERS[customerId] ?? {};
}

const supportTool = shield({
  purpose: "customer_support",
  scope: ["name", "issue", "plan"],
})(db_fetch);
const billingTool = shield({
  purpose: "billing",
  denyFields: ["ssn", "card"],
})(db_fetch);
const opsTool = shield({
  purpose: "ops_review",
  scope: ["name", "last_login", "plan"],
})(db_fetch);
const auditTool = shield({
  purpose: "audit_export",
  scope: ["name"],
})(db_fetch);

async function agentSession() {
  const traceId = newTraceId();
  console.log(`agent: starting reasoning session traceId=${traceId}`);

  await withTraceContext({ traceId }, async () => {
    console.log("[support] →", await supportTool("C-001"));
    console.log("[billing] →", await billingTool("C-001"));
    console.log("[ops]     →", await opsTool("C-001"));
    console.log("[audit]   →", await auditTool("C-001"));
  });

  console.log(`agent: closed traceId=${traceId}`);
  console.log(`audit jsonl: ${process.env.AEGIS_HISTORY_PATH}`);

  const raw = readFileSync(process.env.AEGIS_HISTORY_PATH, "utf8");
  const records = raw
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));
  const matched = records.filter((r) => r.trace_id === traceId);
  console.log(`verify: ${matched.length}/${records.length} records carry traceId=${traceId}`);
  if (matched.length !== records.length || records.length < 4) {
    console.error(`FAIL: expected 4+ matching records, got ${matched.length}/${records.length}`);
    process.exit(1);
  }
  console.log("PASS: agent → shield → audit chain verified end-to-end via trace_id.");
}

agentSession().catch((err) => {
  console.error("agent session failed:", err);
  process.exit(1);
});
