// canonical.ts load + validation tests — parity with python/tests/test_canonical.py.
// A policy the Python loader rejects must also be rejected by the Node loader
// (fail-closed), and a valid policy must resolve + minimize identically.

import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringify as yamlStringify } from "yaml";

import { loadCanonicalPolicy } from "../src/canonical.js";

function write(policy: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "aegis-canon-"));
  const p = join(dir, "policy.json");
  writeFileSync(p, JSON.stringify(policy));
  return p;
}

const GOOD = {
  policy_schema_version: 0,
  policy_id: "p",
  purposes: {
    customer_data: { scope: ["name", "company"] },
    billing: { deny_fields: ["ssn"], destinations: { allow: ["webhook:slack"] }, max_level: "financial", legal_basis: "contract", retention_days: 30 },
  },
  tools: { query: "customer_data" },
  roles: { sales: { allow_purposes: ["customer_data"] } },
  defaults: { unknown_tool: "block" },
};

describe("canonical.ts — load + validation parity", () => {
  it("loads a valid policy and resolves + minimizes", () => {
    const pol = loadCanonicalPolicy(write(GOOD));
    expect(pol.purposeForTool("query")?.name).toBe("customer_data");
    expect(pol.purposeForTool("unmapped")).toBeNull();
    const { filtered, removed } = pol.filterPayload(pol.purposes.customer_data, {
      name: "ACME", company: "ACME Inc", ssn: "x",
    });
    expect(filtered).toEqual({ name: "ACME", company: "ACME Inc" });
    expect(removed).toEqual(["ssn"]);
    // role + destination layers
    expect(pol.roleAllows("sales", "customer_data")).toBe(true);
    expect(pol.roleAllows("sales", "billing")).toBe(false);
    expect(pol.destinationAllowed(pol.purposes.billing, "webhook:slack")).toBe(true);
    expect(pol.destinationAllowed(pol.purposes.billing, "llm:openai")).toBe(false);
    expect(pol.destinationAllowed(pol.purposes.customer_data, "anything")).toBe(false); // no block => deny
  });

  it("loads a YAML policy (parity with python pyyaml extra)", () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-canon-yaml-"));
    const p = join(dir, "policy.yaml");
    writeFileSync(p, yamlStringify(GOOD));
    const pol = loadCanonicalPolicy(p);
    expect(pol.purposeForTool("query")?.name).toBe("customer_data");
  });

  const REJECTED: Array<[string, unknown]> = [
    ["unsupported version", { ...GOOD, policy_schema_version: 1 }],
    ["empty purposes", { ...GOOD, purposes: {} }],
    ["scope+deny conflict", { ...GOOD, purposes: { x: { scope: ["a"], deny_fields: ["b"] } }, tools: {} }],
    ["neither scope nor deny", { ...GOOD, purposes: { x: {} }, tools: {} }],
    ["empty deny_fields", { ...GOOD, purposes: { x: { deny_fields: [] } }, tools: {} }],
    ["bad field path", { ...GOOD, purposes: { x: { scope: ["a..b"] } }, tools: {} }],
    ["tool -> unknown purpose", { ...GOOD, tools: { query: "nope" } }],
    ["invalid max_level", { ...GOOD, purposes: { x: { scope: ["a"], max_level: "ultra" } }, tools: {} }],
    ["invalid legal_basis", { ...GOOD, purposes: { x: { scope: ["a"], legal_basis: "vibes" } }, tools: {} }],
    ["retention_days < 1", { ...GOOD, purposes: { x: { scope: ["a"], retention_days: 0 } }, tools: {} }],
    ["destinations allow+deny", { ...GOOD, purposes: { x: { scope: ["a"], destinations: { allow: ["i"], deny: ["j"] } } }, tools: {} }],
    ["destinations deny empty", { ...GOOD, purposes: { x: { scope: ["a"], destinations: { deny: [] } } }, tools: {} }],
    ["roles allow+deny", { ...GOOD, roles: { r: { allow_purposes: ["customer_data"], deny_purposes: ["billing"] } } }],
    ["defaults not block", { ...GOOD, defaults: { unknown_tool: "passthrough" } }],
  ];

  it.each(REJECTED)("rejects fail-closed: %s", (_label, policy) => {
    expect(() => loadCanonicalPolicy(write(policy))).toThrow();
  });
});
