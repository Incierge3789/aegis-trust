// Dev-agent workflow MCP callable-proof runner — agent → shield → audit,
// end-to-end, for the First Protected Workflow reference policy
// (examples/devAgentWorkflow.ts; policy literals mirrored here and pinned
// against drift by tests/devAgentWorkflow.test.ts reading this source).
//
// Verifies the chain the DP walkthrough will show:
//   1. The agent opens a trace context (`withTraceContext`).
//   2. It calls the two shield()-wrapped dev-agent tools.
//   3. LITE filters per policy (scope dot-notation / denyFields dot-notation).
//   4. The local audit JSONL records each call with the matching trace_id and
//      the exact blocked field NAMES — and never the field VALUES.
//      (Value-absence is a REGRESSION PIN: record() serializes labels and key
//      paths only; the future channel to guard is values-as-keys flowing into
//      blockedFields.)
//
// Run (from node/):
//   npm run build
//   node tests/mcp/run_dev_agent_workflow.mjs

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { newTraceId, resetStore, shield, withTraceContext } from "../../dist/index.js";

// Deterministic LITE-local run even if the operator shell has AEGIS_TOKEN etc.
process.env.AEGIS_MODE = "lite";
process.env.AEGIS_HISTORY = "1";
process.env.AEGIS_HISTORY_PATH = join(
  mkdtempSync(join(tmpdir(), "aegis-devagent-e2e-")),
  "audit.jsonl",
);

resetStore();

// ── Fixtures (same shape and sentinels as examples/devAgentWorkflow.ts) ─────

const SERVICE_CONFIG = {
  service: "billing-api",
  version: "2.31.0",
  endpoints: ["/v1/charge", "/v1/refund", "/v1/invoice"],
  spec_url: "https://specs.internal/billing-api/openapi.yaml",
  api_key: "sk-live-EXAMPLE-aaaabbbbccccdddd",
  deploy_token: "ghp-EXAMPLE-deploytoken12345",
  db: {
    engine: "postgres",
    host: "db.internal.example",
    connection_string: "postgres://svc:EXAMPLE-dbpass@db.internal.example/billing",
  },
};

const RECENT_LOGS = {
  service: "billing-api",
  window: "15m",
  error_count: 2,
  sanitized_lines: ["12:01:02 WARN retry charge attempt=2", "12:03:14 ERROR invoice render timeout"],
  raw_lines: [
    "12:01:02 WARN retry charge attempt=2 customer_email=tanaka@example.com",
    "12:03:14 ERROR invoice render timeout card=4111-1111-1111-1111",
  ],
  client_ips: ["203.0.113.10", "203.0.113.22"],
  context: { host: "prod-worker-3", auth_token: "Bearer-EXAMPLE-authtoken9876" },
};

const SENTINELS = [
  "sk-live-EXAMPLE-aaaabbbbccccdddd",
  "ghp-EXAMPLE-deploytoken12345",
  "EXAMPLE-dbpass",
  "Bearer-EXAMPLE-authtoken9876",
  "tanaka@example.com",
];

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

// (a) positive control — the raw fixtures really contain the sentinels;
// without this, every absence check below would be vacuous.
const rawText = JSON.stringify({ SERVICE_CONFIG, RECENT_LOGS });
for (const s of SENTINELS) {
  if (!rawText.includes(s)) fail(`positive control: sentinel missing from raw fixture: ${s}`);
}

// ── The two shielded dev-agent tools (named fns → function field in audit) ──

const getServiceConfig = shield({
  purpose: "dev_agent_spec_access",
  scope: ["service", "version", "endpoints", "spec_url", "db.engine", "db.host"],
})(async function getServiceConfig(_serviceId) {
  return { ...SERVICE_CONFIG, db: { ...SERVICE_CONFIG.db } };
});

const getRecentLogs = shield({
  purpose: "dev_agent_log_triage",
  denyFields: ["raw_lines", "client_ips", "context.auth_token"],
})(async function getRecentLogs(_serviceId) {
  return { ...RECENT_LOGS, context: { ...RECENT_LOGS.context } };
});

const EXPECTED_BLOCKED = {
  dev_agent_spec_access: ["api_key", "db.connection_string", "deploy_token"],
  dev_agent_log_triage: ["client_ips", "context.auth_token", "raw_lines"],
};

async function agentSession() {
  const traceId = newTraceId();
  console.log(`agent: starting dev-agent session traceId=${traceId}`);

  await withTraceContext({ traceId }, async () => {
    console.log("[spec]  →", JSON.stringify(await getServiceConfig("billing-api")));
    console.log("[logs]  →", JSON.stringify(await getRecentLogs("billing-api")));
  });

  console.log(`audit jsonl: ${process.env.AEGIS_HISTORY_PATH}`);
  const raw = readFileSync(process.env.AEGIS_HISTORY_PATH, "utf8");
  const records = raw.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));

  // (b) trace propagation — exactly this run's 2 records, all carrying traceId.
  const matched = records.filter((r) => r.trace_id === traceId);
  if (records.length !== 2 || matched.length !== 2) {
    fail(`expected exactly 2 records for this run with trace_id=${traceId}, got ${matched.length}/${records.length}`);
  }

  // (c) per-record exact blocked-field sets, keyed by purpose. This is the
  // non-tautological core: denyFields/scope are policy echoes; blockedFields
  // is what enforcement actually removed.
  for (const [purpose, expected] of Object.entries(EXPECTED_BLOCKED)) {
    const rec = records.find((r) => r.purpose === purpose);
    if (!rec) fail(`no audit record for purpose=${purpose}`);
    const got = [...rec.blockedFields].sort();
    if (JSON.stringify(got) !== JSON.stringify(expected)) {
      fail(`blockedFields mismatch for ${purpose}: got ${JSON.stringify(got)}, expected ${JSON.stringify(expected)}`);
    }
  }

  // (d) regression pin: the audit text contains field NAMES, never VALUES.
  for (const s of SENTINELS) {
    if (raw.includes(s)) fail(`audit JSONL leaked a sentinel value: ${s}`);
  }

  console.log("verify: 2/2 records carry the trace_id; blockedFields exact-match both tools; 0 sentinel values in audit.");
  console.log("PASS: dev-agent → shield → audit chain verified end-to-end.");
}

agentSession().catch((err) => {
  console.error("dev-agent session failed:", err);
  process.exit(1);
});
