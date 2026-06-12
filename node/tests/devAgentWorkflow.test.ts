// Behavioral pin for the First Protected Workflow reference implementation
// (examples/devAgentWorkflow.ts). Each block maps 1:1 to a row of the
// candidate policy table (deploy/s010/first_protected_workflow_candidate.md §2):
//   row 1  allow: spec/metadata fields            → scope allow-list
//   row 2  withhold: credential-bearing fields    → scope omission + dot-notation paths
//   row 3  allow/withhold: log fields             → denyFields incl. dot-notation deny
//   row 4  unstructured content                   → NON-CLAIM (documented, not tested)
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  RAW_RECENT_LOGS,
  RAW_SERVICE_CONFIG,
  getRecentLogs,
  getServiceConfig,
  observeConfigFiltering,
} from "../examples/devAgentWorkflow.js";

describe("dev-agent workflow — Tool 1: scope allow-list (dot-notation allow)", () => {
  it("positive control: the raw fixture really contains every credential", () => {
    // Without this, every absence assertion below would pass vacuously.
    expect(RAW_SERVICE_CONFIG).toHaveProperty("api_key");
    expect(RAW_SERVICE_CONFIG).toHaveProperty("deploy_token");
    expect(RAW_SERVICE_CONFIG).toHaveProperty(["db", "connection_string"]);
  });

  it("allows spec/metadata fields (D1 row 1)", async () => {
    const cfg = (await getServiceConfig("billing-api")) as Record<string, unknown>;
    expect(cfg.service).toBe("billing-api");
    expect(cfg.version).toBe("2.31.0");
    expect(cfg.endpoints).toEqual(["/v1/charge", "/v1/refund", "/v1/invoice"]);
    expect(cfg.spec_url).toMatch(/^https:/);
  });

  it("dot-notation scope keeps the allowed nested fields alive (deny is not vacuous)", async () => {
    const cfg = (await getServiceConfig("billing-api")) as Record<string, unknown>;
    const db = cfg.db as Record<string, unknown>;
    expect(db).toBeDefined();
    expect(db.engine).toBe("postgres");
    expect(db.host).toBe("db.internal.example");
  });

  it("withholds credential-bearing fields, incl. the nested one (D1 row 2)", async () => {
    const cfg = (await getServiceConfig("billing-api")) as Record<string, unknown>;
    expect(cfg).not.toHaveProperty("api_key");
    expect(cfg).not.toHaveProperty("deploy_token");
    expect(cfg.db as Record<string, unknown>).not.toHaveProperty("connection_string");
    // Letter-bearing sentinels (a digits-only sentinel can collide with
    // timestamp digits — S010 CI flake lesson):
    const s = JSON.stringify(cfg);
    expect(s).not.toContain("sk-live-EXAMPLE");
    expect(s).not.toContain("ghp-EXAMPLE");
    expect(s).not.toContain("EXAMPLE-dbpass");
  });

  it("wrap() reports the exact withheld paths (deep, dot-notation)", () => {
    const res = observeConfigFiltering();
    expect([...res.filteredKeys].sort()).toEqual(
      ["api_key", "db.connection_string", "deploy_token"].sort(),
    );
    expect(JSON.stringify(res.data)).not.toContain("EXAMPLE-dbpass");
  });
});

describe("dev-agent workflow — Tool 2: denyFields (dot-notation deny)", () => {
  it("positive control: the raw fixture really contains the production data", () => {
    expect(RAW_RECENT_LOGS).toHaveProperty("raw_lines");
    expect(RAW_RECENT_LOGS).toHaveProperty("client_ips");
    expect(RAW_RECENT_LOGS).toHaveProperty(["context", "auth_token"]);
  });

  it("allows sanitized-log fields (D1 row 3 allow side)", async () => {
    const logs = (await getRecentLogs("billing-api")) as Record<string, unknown>;
    expect(logs.service).toBe("billing-api");
    expect(logs.window).toBe("15m");
    expect(logs.error_count).toBe(2);
    expect(Array.isArray(logs.sanitized_lines)).toBe(true);
    expect((logs.sanitized_lines as string[]).length).toBe(2);
  });

  it("dot-notation deny removes the nested credential while its subtree survives", async () => {
    const logs = (await getRecentLogs("billing-api")) as Record<string, unknown>;
    const context = logs.context as Record<string, unknown>;
    expect(context).toBeDefined();
    expect(context.host).toBe("prod-worker-3"); // survivor proves deny is surgical, not subtree-drop
    expect(context).not.toHaveProperty("auth_token");
  });

  it("withholds production-log fields (D1 row 3 withhold side)", async () => {
    const logs = (await getRecentLogs("billing-api")) as Record<string, unknown>;
    expect(logs).not.toHaveProperty("raw_lines");
    expect(logs).not.toHaveProperty("client_ips");
    const s = JSON.stringify(logs);
    expect(s).not.toContain("tanaka@example.com");
    expect(s).not.toContain("Bearer-EXAMPLE-authtoken");
    expect(s).not.toContain("203.0.113.10");
  });
});

describe("dev-agent workflow — policy drift pin (example ↔ e2e runner)", () => {
  it("the MCP e2e runner mirrors the example's policy literals verbatim", () => {
    // tests/mcp/run_dev_agent_workflow.mjs redeclares the policy (it imports
    // dist, not the example). If the example policy changes and the runner is
    // left stale, this fails loudly instead of the runner silently passing
    // with an outdated policy.
    const src = readFileSync(new URL("./mcp/run_dev_agent_workflow.mjs", import.meta.url), "utf8");
    expect(src).toContain('scope: ["service", "version", "endpoints", "spec_url", "db.engine", "db.host"]');
    expect(src).toContain('denyFields: ["raw_lines", "client_ips", "context.auth_token"]');
    expect(src).toContain('"api_key", "db.connection_string", "deploy_token"');
    expect(src).toContain('"client_ips", "context.auth_token", "raw_lines"');
  });
});

describe("dev-agent workflow — example hygiene", () => {
  it("exports are importable (import-safe smoke; direct-run guard verified manually via tsx)", () => {
    expect(typeof getServiceConfig).toBe("function");
    expect(typeof getRecentLogs).toBe("function");
  });
});
