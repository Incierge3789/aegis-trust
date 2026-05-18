import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { getPurposePolicy, loadConfig, resetConfig } from "../src/index.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "aegis-trust-"));
  resetConfig();
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
  resetConfig();
  delete process.env.AEGIS_CONFIG;
});

function writeYaml(name: string, src: string): string {
  const p = join(tmp, name);
  writeFileSync(p, src, "utf8");
  return p;
}

describe("loadConfig", () => {
  it("loads valid YAML with scope purpose", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  support:
    scope: ["name", "issue"]
`,
    );
    process.env.AEGIS_CONFIG = p;
    const cfg = await loadConfig();
    expect(cfg.purposes).toBeDefined();
  });

  it("loads valid YAML with deny_fields purpose", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  ops:
    deny_fields: ["ssn", "card.cvc"]
`,
    );
    process.env.AEGIS_CONFIG = p;
    const cfg = await loadConfig();
    const policy = (cfg.purposes as Record<string, Record<string, unknown>>).ops;
    expect(policy.deny_fields).toEqual(["ssn", "card.cvc"]);
  });

  it("rejects scope+deny_fields combo", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  bad:
    scope: ["a"]
    deny_fields: ["b"]
`,
    );
    process.env.AEGIS_CONFIG = p;
    await expect(loadConfig()).rejects.toThrow(/mutually exclusive/);
  });

  it("rejects missing scope and deny", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  bad: {}
`,
    );
    process.env.AEGIS_CONFIG = p;
    await expect(loadConfig()).rejects.toThrow(/required/);
  });

  it("rejects invalid field path", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  bad:
    scope: ["1foo"]
`,
    );
    process.env.AEGIS_CONFIG = p;
    await expect(loadConfig()).rejects.toThrow(/Invalid field path/);
  });

  it("rejects empty deny_fields", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  bad:
    deny_fields: []
`,
    );
    process.env.AEGIS_CONFIG = p;
    await expect(loadConfig()).rejects.toThrow(/empty/);
  });

  it("rejects non-mapping top level", async () => {
    const p = writeYaml("aegis.yaml", `- 1\n- 2\n`);
    process.env.AEGIS_CONFIG = p;
    await expect(loadConfig()).rejects.toThrow(/mapping/);
  });

  it("AEGIS_CONFIG pointing to missing file → not found", async () => {
    process.env.AEGIS_CONFIG = join(tmp, "nonexistent.yaml");
    await expect(loadConfig()).rejects.toThrow(/No aegis config/);
  });
});

describe("getPurposePolicy", () => {
  it("returns scope policy", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  support:
    scope: ["name"]
`,
    );
    process.env.AEGIS_CONFIG = p;
    const policy = await getPurposePolicy("support");
    expect(policy).toEqual({ scope: ["name"] });
  });

  it("returns deny policy", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  ops:
    deny_fields: ["ssn"]
`,
    );
    process.env.AEGIS_CONFIG = p;
    const policy = await getPurposePolicy("ops");
    expect(policy).toEqual({ denyFields: ["ssn"] });
  });

  it("returns null when purpose missing", async () => {
    const p = writeYaml(
      "aegis.yaml",
      `purposes:
  support:
    scope: ["name"]
`,
    );
    process.env.AEGIS_CONFIG = p;
    expect(await getPurposePolicy("nonexistent")).toBeNull();
  });

  it("returns null when config not findable", async () => {
    process.env.AEGIS_CONFIG = join(tmp, "missing.yaml");
    expect(await getPurposePolicy("any")).toBeNull();
  });
});
