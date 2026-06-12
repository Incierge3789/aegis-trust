// Dev-agent workflow — the First Protected Workflow reference implementation.
//
// A development agent (coding agent / MCP-tool-using agent) calls tools that
// return STRUCTURED records: service config, deployment metadata, recent logs.
// aegis-trust LITE filters each tool's return value in-process before the
// agent sees it: specification/metadata fields pass, credential-bearing
// fields and production-log fields never reach the agent.
//
// NON-CLAIM (read before adapting): the LITE filter is field-structural.
// It filters STRUCTURED records (objects/fields, incl. dot-notation paths).
// A tool that returns raw unstructured text — the bytes of an .env file, a
// raw log stream — cannot be protected this way; returning structured
// records is part of the workflow design, not an optional detail. See
// docs/productization/LITE_CLAIMS.md for the full claim ceiling (LITE
// results are in-process filtering, not audit evidence).
//
// Install:
//   npm install aegis-trust
//
// Run (from node/ in this repo):
//   npx tsx examples/devAgentWorkflow.ts

import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { shield, wrap } from "../src/index.js";

// ── Simulated infrastructure the dev-agent's tools read from ───────────────

const SERVICE_CONFIG: Record<string, unknown> = {
  service: "billing-api",
  version: "2.31.0",
  endpoints: ["/v1/charge", "/v1/refund", "/v1/invoice"], // string array: leaf-scopeable
  spec_url: "https://specs.internal/billing-api/openapi.yaml",
  api_key: "sk-live-EXAMPLE-aaaabbbbccccdddd", // credential — must never reach the agent
  deploy_token: "ghp-EXAMPLE-deploytoken12345", // credential — must never reach the agent
  db: {
    engine: "postgres",
    host: "db.internal.example",
    connection_string: "postgres://svc:EXAMPLE-dbpass@db.internal.example/billing", // credential
  },
};

const RECENT_LOGS: Record<string, unknown> = {
  service: "billing-api",
  window: "15m",
  error_count: 2,
  sanitized_lines: [
    "12:01:02 WARN retry charge attempt=2",
    "12:03:14 ERROR invoice render timeout",
  ],
  raw_lines: [
    "12:01:02 WARN retry charge attempt=2 customer_email=tanaka@example.com",
    "12:03:14 ERROR invoice render timeout card=4111-1111-1111-1111",
  ], // production log lines — must never reach the agent
  client_ips: ["203.0.113.10", "203.0.113.22"], // production data — must never reach the agent
  context: {
    host: "prod-worker-3",
    auth_token: "Bearer-EXAMPLE-authtoken9876", // credential nested in allowed subtree
  },
};

// ── The two shielded tools (one per LITE mechanism, both load-bearing) ──────
//
// Tool 1 — allow-list (scope, incl. dot-notation): spec/metadata fields pass,
// everything else (api_key, deploy_token, db.connection_string) falls away.
// db.host / db.engine stay alive via dot-notation scope, which is what keeps
// the nested allow path honest (the db subtree is NOT simply dropped).

export const getServiceConfig = shield({
  purpose: "dev_agent_spec_access",
  scope: ["service", "version", "endpoints", "spec_url", "db.engine", "db.host"],
})(async (_serviceId: string) => ({ ...SERVICE_CONFIG, db: { ...(SERVICE_CONFIG.db as object) } }));

// Tool 2 — deny-list (denyFields, incl. dot-notation): sanitized log fields
// pass; production-log fields and the nested credential are removed while the
// rest of the context subtree (context.host) survives.

export const getRecentLogs = shield({
  purpose: "dev_agent_log_triage",
  denyFields: ["raw_lines", "client_ips", "context.auth_token"],
})(async (_serviceId: string) => ({ ...RECENT_LOGS, context: { ...(RECENT_LOGS.context as object) } }));

// Raw fixtures exported for the behavioral test's positive control: the test
// proves the credentials exist BEFORE filtering and are absent AFTER.
export const RAW_SERVICE_CONFIG = SERVICE_CONFIG;
export const RAW_RECENT_LOGS = RECENT_LOGS;

// ── Observe what was filtered (wrap(): in-process result, NOT evidence) ─────

export function observeConfigFiltering() {
  return wrap(SERVICE_CONFIG, {
    purpose: "dev_agent_spec_access",
    scope: ["service", "version", "endpoints", "spec_url", "db.engine", "db.host"],
  });
}

// Pseudo-MCP integration — replace with your MCP server's tool registration.
//
// import { Server } from "@modelcontextprotocol/sdk/server";
// const server = new Server({ name: "dev-agent-tools", version: "1.0.0" }, {});
// server.setRequestHandler("tools/call", async (req) => {
//   if (req.params.name === "get_service_config") {
//     return await getServiceConfig(req.params.arguments.service_id);
//   }
//   if (req.params.name === "get_recent_logs") {
//     return await getRecentLogs(req.params.arguments.service_id);
//   }
// });

async function demo() {
  console.log("=== dev_agent_spec_access (scope, dot-notation allow) ===");
  console.log(JSON.stringify(await getServiceConfig("billing-api"), null, 2));
  // → service/version/endpoints/spec_url + db.engine/db.host
  //   (api_key, deploy_token, db.connection_string never reach the agent)

  console.log("\n=== dev_agent_log_triage (denyFields, dot-notation deny) ===");
  console.log(JSON.stringify(await getRecentLogs("billing-api"), null, 2));
  // → service/window/error_count/sanitized_lines + context.host
  //   (raw_lines, client_ips, context.auth_token removed)

  const res = observeConfigFiltering();
  console.log("\nfilteredKeys:", JSON.stringify(res.filteredKeys));
  // → ["api_key", "deploy_token", "db.connection_string"] — deep diff with
  //   dot paths: db survives via dot-notation scope, the credential inside it
  //   is reported by its full path.
}

// Run the demo only when executed directly (`npx tsx examples/devAgentWorkflow.ts`),
// not when imported by the test suite. realpath BOTH sides: on darwin, /tmp
// resolves to /private/tmp and a one-sided compare mismatches.
const directRun = (() => {
  try {
    const argv1 = process.argv[1];
    if (!argv1) return false;
    const self = realpathSync(fileURLToPath(import.meta.url));
    return realpathSync(argv1) === self;
  } catch {
    return false;
  }
})();
if (directRun) {
  demo().catch((e) => {
    console.error(e);
    process.exitCode = 1;
  });
}
