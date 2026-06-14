// shield-proxy end-to-end tests (Node) — mirror of python/tests/test_mcp_proxy.py.
// Real subprocess, real stdio framing: a fake MCP server returns an over-broad
// record; the proxy must deliver only the policy scope to the host (for both
// tools/call AND resources/read), block unknown tools without forwarding, and
// emit schema-valid canonical v0 audit events. Same spec as the Python proxy
// test => cross-SDK parity for the enforcement point.
//
// Requests are written in one batch and all responses collected after the proxy
// exits (matched by JSON-RPC id), robust across test-runner stdio scheduling.

import { describe, expect, it } from "vitest";
import Ajv2020 from "ajv/dist/2020.js";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const PROXY = fileURLToPath(new URL("../dist/mcpProxy.js", import.meta.url));
const EVENT_SCHEMA = JSON.parse(
  readFileSync(new URL("../../schemas/v0/aegis-audit-event.v0.schema.json", import.meta.url), "utf8"),
);

const FAKE_SERVER = `
import { createInterface } from "node:readline";
const RECORD = { name: "ACME", company: "ACME Inc", email: "ceo@acme.test", ssn: "123-45-6789" };
const seen = [];
createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  if (!("id" in msg)) return;
  let result;
  if (msg.method === "tools/call") {
    seen.push(msg.params.name);
    result = { structuredContent: RECORD,
      content: [{ type: "text", text: JSON.stringify(RECORD) }, { type: "text", text: "plain note" }] };
  } else if (msg.method === "resources/read") {
    result = { contents: [{ uri: msg.params.uri, text: JSON.stringify(RECORD) }] };
  } else if (msg.method === "tools/seen") {
    result = { calls: seen };
  } else {
    result = { ok: true };
  }
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\\n");
});
`;

const POLICY = {
  policy_schema_version: 0,
  policy_id: "proxy-test-policy",
  purposes: { customer_data: { scope: ["name", "company"] } },
  tools: {
    query_business_data: "customer_data",
    "tools/seen": "customer_data",
    "resources/read": "customer_data",
  },
  defaults: { unknown_tool: "block" },
};

const REQUESTS = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
  { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "query_business_data", arguments: {} } },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "exfiltrate_everything", arguments: {} } },
  { jsonrpc: "2.0", id: 4, method: "tools/seen", params: { name: "tools/seen" } },
  { jsonrpc: "2.0", id: 5, method: "resources/read", params: { uri: "file://customer/acme" } },
];

function runProxy(): Promise<{ byId: Map<number, Record<string, unknown>>; events: Array<Record<string, unknown>> }> {
  const dir = mkdtempSync(join(tmpdir(), "aegis-proxy-"));
  const serverPath = join(dir, "server.mjs");
  const policyPath = join(dir, "policy.json");
  const auditPath = join(dir, "events.jsonl");
  writeFileSync(serverPath, FAKE_SERVER);
  writeFileSync(policyPath, JSON.stringify(POLICY));

  const proc = spawn(
    process.execPath,
    [PROXY, "--policy", policyPath, "--agent-id", "cursor-test", "--audit-path", auditPath,
      "--", process.execPath, serverPath],
    { stdio: ["pipe", "pipe", "inherit"] },
  );

  let out = "";
  proc.stdout.on("data", (d) => (out += d.toString()));
  proc.stdin.write(REQUESTS.map((r) => JSON.stringify(r)).join("\n") + "\n");
  proc.stdin.end();

  return new Promise((resolve) => {
    proc.on("exit", () => {
      const byId = new Map<number, Record<string, unknown>>();
      for (const line of out.split("\n")) {
        if (!line.trim()) continue;
        const m = JSON.parse(line) as Record<string, unknown>;
        byId.set(m.id as number, m);
      }
      const events = readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
      resolve({ byId, events });
    });
  });
}

describe("shield-proxy (Node) — MCP enforcement point", () => {
  it("minimizes mapped tool + resource results and blocks an unknown tool", { timeout: 20000 }, async () => {
    const { byId, events } = await runProxy();

    // non-gated traffic passes through untouched
    expect((byId.get(1)!.result as Record<string, unknown>)).toEqual({ ok: true });

    // mapped tool: result minimized to scope in structuredContent AND JSON text
    const result = byId.get(2)!.result as Record<string, unknown>;
    expect(result.structuredContent).toEqual({ name: "ACME", company: "ACME Inc" });
    const content = result.content as Array<{ text: string }>;
    expect(JSON.parse(content[0].text)).toEqual({ name: "ACME", company: "ACME Inc" });
    expect(content[1].text).toBe("plain note"); // v0 limit: free text passthrough

    // unknown tool: blocked AND never forwarded to the server
    const br = byId.get(3)!.result as { isError: boolean; content: Array<{ text: string }> };
    expect(br.isError).toBe(true);
    expect(br.content[0].text).toContain("unknown_tool");

    // the server never saw the blocked tool
    expect(JSON.stringify(byId.get(4)!.result)).not.toContain("exfiltrate_everything");

    // resources/read is a sibling data path on the same boundary — also minimized
    const res = byId.get(5)!.result as { contents: Array<{ text: string }> };
    expect(JSON.parse(res.contents[0].text)).toEqual({ name: "ACME", company: "ACME Inc" });

    // canonical audit: allow (mapped calls) + deny (unknown tool), every event
    // carries the enforcement point, AND every event is schema-valid v0.
    const summary = events.map((e) => [e.enforcement_point, e.decision]);
    expect(summary).toContainEqual(["mcp_proxy", "allow"]);
    expect(summary).toContainEqual(["mcp_proxy", "deny"]);
    expect(events.every((e) => e.enforcement_point === "mcp_proxy")).toBe(true);

    const validate = new Ajv2020({ strict: false }).compile(EVENT_SCHEMA);
    for (const e of events) {
      expect(validate(e), JSON.stringify(validate.errors)).toBe(true);
    }
  });
});
