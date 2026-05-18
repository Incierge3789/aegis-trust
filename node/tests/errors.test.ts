import { describe, expect, it } from "vitest";

import {
  AegisAuditError,
  AegisConfigError,
  AegisError,
  AegisHttpError,
  AegisIngestError,
  AegisValidationError,
  aegisDocsUrl,
  loadConfig,
  resetConfig,
  shield,
} from "../src/index.js";

describe("AegisError model", () => {
  it("carries code + remediation + docs_url on the base class", () => {
    const e = new AegisError({
      code: "test.example",
      remediation: "Fix it.",
      docs_url: aegisDocsUrl("test.example"),
      message: "boom",
    });
    expect(e.code).toBe("test.example");
    expect(e.remediation).toBe("Fix it.");
    expect(e.docs_url).toBe("https://aegis-trust.dev/errors/test.example");
    expect(e.message).toBe("boom");
    expect(e.toJSON()).toEqual({
      name: "AegisError",
      message: "boom",
      code: "test.example",
      remediation: "Fix it.",
      docs_url: "https://aegis-trust.dev/errors/test.example",
    });
  });

  it("derived classes inherit fields and set name", () => {
    const v = new AegisValidationError({
      code: "v",
      remediation: "r",
      docs_url: "d",
      message: "m",
    });
    expect(v.name).toBe("AegisValidationError");
    expect(v).toBeInstanceOf(AegisError);
    expect(v.code).toBe("v");
    expect(v.remediation).toBe("r");
    expect(v.docs_url).toBe("d");
  });

  it("AegisHttpError carries status", () => {
    const e = new AegisHttpError({
      code: "http.500",
      remediation: "Retry.",
      docs_url: aegisDocsUrl("http.500"),
      message: "server error",
      status: 500,
    });
    expect(e.status).toBe(500);
    expect(e.name).toBe("AegisHttpError");
  });

  it("aegisDocsUrl builds canonical URL", () => {
    expect(aegisDocsUrl("aegis.shield.purpose.required")).toBe(
      "https://aegis-trust.dev/errors/aegis.shield.purpose.required",
    );
  });
});

describe("shield throws AegisValidationError on empty purpose", () => {
  it("propagates code + remediation + docs_url", () => {
    try {
      shield({ purpose: "" });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AegisValidationError);
      const v = e as AegisValidationError;
      expect(v.code).toBe("aegis.shield.purpose.required");
      expect(v.remediation).toContain("non-empty");
      expect(v.docs_url).toBe(
        "https://aegis-trust.dev/errors/aegis.shield.purpose.required",
      );
    }
  });
});

describe("loadConfig throws AegisConfigError on missing file", () => {
  it("propagates code + remediation + docs_url", async () => {
    resetConfig();
    const prev = process.env.AEGIS_CONFIG;
    process.env.AEGIS_CONFIG = "/tmp/__nonexistent_aegis_config_for_test__.yaml";
    try {
      await loadConfig();
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AegisConfigError);
      const c = e as AegisConfigError;
      expect(c.code).toBe("aegis.config.fileNotFound");
      expect(c.docs_url).toContain("aegis.config.fileNotFound");
    } finally {
      if (prev === undefined) delete process.env.AEGIS_CONFIG;
      else process.env.AEGIS_CONFIG = prev;
      resetConfig();
    }
  });
});

describe("AegisIngestError / AegisAuditError construction parity", () => {
  it("constructs and exposes the three required fields", () => {
    const i = new AegisIngestError({
      code: "i",
      remediation: "r",
      docs_url: "d",
      message: "m",
    });
    const a = new AegisAuditError({
      code: "a",
      remediation: "r",
      docs_url: "d",
      message: "m",
    });
    expect(i.code).toBe("i");
    expect(a.code).toBe("a");
    expect(i).toBeInstanceOf(AegisError);
    expect(a).toBeInstanceOf(AegisError);
  });
});
