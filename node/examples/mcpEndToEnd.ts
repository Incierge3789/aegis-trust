// Minimal MCP callable proof — agent → shield → audit, end-to-end.
//
// Demonstrates the four-link chain that the v0.9.0-rc1 productization gate
// is designed to verify:
//   1. Agent reasoning step opens a trace context (`withTraceContext`).
//   2. The agent calls an MCP tool, which is `shield()`-wrapped.
//   3. shield filters the data per declared purpose + scope.
//   4. The local audit JSONL records the call with the matching `trace_id`.
//
// Run:
//   AEGIS_HISTORY=1 \
//   AEGIS_HISTORY_PATH=/tmp/aegis-mcp-e2e.jsonl \
//   npx tsx examples/mcpEndToEnd.ts
//
// Then inspect the audit chain:
//   cat /tmp/aegis-mcp-e2e.jsonl
//   # → 4 events, all sharing one trace_id, one per shield-wrapped tool call.

import { mkdtempSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

import {
  newTraceId,
  resetStore,
  shield,
  withTraceContext,
} from "../src/index.js";

// Default to a temp path so this example is hermetic; override with
// AEGIS_HISTORY_PATH for shared inspection.
process.env.AEGIS_HISTORY = "1";
if (!process.env.AEGIS_HISTORY_PATH) {
  // Fresh dir per run: a fixed path accumulates records across runs and the
  // trace_id verification below would fail on a second invocation.
  const dir = mkdtempSync(join(tmpdir(), "aegis-mcp-e2e-"));
  process.env.AEGIS_HISTORY_PATH = join(dir, "audit.jsonl");
}

// Reset in case a prior run is still cached in this process.
resetStore();

// ── 1. Pretend backend ────────────────────────────────────────────────
const CUSTOMERS: Record<string, Record<string, unknown>> = {
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

async function db_fetch(customerId: string): Promise<Record<string, unknown>> {
  return CUSTOMERS[customerId] ?? {};
}

// ── 2. MCP tools — shield-wrapped before tool registration ────────────
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

// ── 3. Agent runs four tool calls under a single trace ────────────────

async function agentSession(): Promise<void> {
  const traceId = newTraceId();
  console.log(`agent: starting reasoning session traceId=${traceId}`);

  await withTraceContext({ traceId }, async () => {
    console.log("\n[support] →", await supportTool("C-001"));
    console.log("[billing] →", await billingTool("C-001"));
    console.log("[ops]     →", await opsTool("C-001"));
    console.log("[audit]   →", await auditTool("C-001"));
  });

  console.log(`\nagent: closed traceId=${traceId}`);
  console.log(`audit jsonl: ${process.env.AEGIS_HISTORY_PATH}`);

  // ── 4. Verify trace_id propagated to every record ───────────────────
  const raw = readFileSync(process.env.AEGIS_HISTORY_PATH!, "utf8");
  const records = raw
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as { trace_id?: string; function: string; purpose: string });

  const matched = records.filter((r) => r.trace_id === traceId);
  console.log(`\nverify: ${matched.length}/${records.length} records carry traceId=${traceId}`);
  if (matched.length !== records.length || records.length < 4) {
    console.error(
      `FAIL: expected 4+ records all with traceId=${traceId}, got ${matched.length}/${records.length}`,
    );
    process.exit(1);
  }
  console.log("PASS: agent → shield → audit chain verified end-to-end via trace_id.");
}

agentSession().catch((err) => {
  console.error("agent session failed:", err);
  process.exit(1);
});

// Avoid unused-import lint when readers paste this fragment.
void dirname;
