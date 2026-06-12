import { afterEach, describe, expect, it } from "vitest";

import { _setTestHook } from "../src/shield.js";
import { AegisValidationError, Mode } from "../src/index.js";
import {
  shieldedTool,
  toCrewaiTool,
  toLangChainTool,
  toLlamaIndexTool,
  toVercelTool,
  type ShieldedTool,
} from "../src/adapters/index.js";

afterEach(() => {
  _setTestHook(null);
});

const RECORD = {
  name: "Tanaka Taro",
  email: "tanaka@example.com",
  ssn: "123-45-6789",
  credit_card: "4242-****-****-1234",
  issue: "Cannot reset password",
};

const SCOPED = { name: "Tanaka Taro", issue: "Cannot reset password" };

function lookup(): ShieldedTool<{ id: string }> {
  return shieldedTool<{ id: string }>({
    name: "customer_lookup",
    description: "Look up a customer record by id for support.",
    purpose: "customer_support",
    scope: ["name", "issue"],
    mode: Mode.LITE,
    handler: async () => RECORD,
  });
}

describe("shieldedTool (core)", () => {
  it("run() returns only the scoped fields", async () => {
    expect(await lookup().run({ id: "C-1001" })).toEqual(SCOPED);
  });

  it("call() serializes the filtered record to JSON, never the blocked fields", async () => {
    const s = await lookup().call({ id: "C-1001" });
    expect(JSON.parse(s)).toEqual(SCOPED);
    expect(s).not.toContain("ssn");
    expect(s).not.toContain("123-45-6789");
    expect(s).not.toContain("credit_card");
    expect(s).not.toContain("email");
  });

  it("passes the tool-call argument through to the handler", async () => {
    let seen: unknown;
    const t = shieldedTool<{ id: string }>({
      name: "t",
      description: "d",
      purpose: "p",
      scope: ["name"],
      mode: Mode.LITE,
      handler: async (args) => {
        seen = args;
        return RECORD;
      },
    });
    await t.run({ id: "C-42" });
    expect(seen).toEqual({ id: "C-42" });
  });

  it("honours a custom serializer", async () => {
    const t = shieldedTool({
      name: "t",
      description: "d",
      purpose: "p",
      scope: ["name"],
      mode: Mode.LITE,
      handler: async () => RECORD,
      serialize: (v) => `<<${JSON.stringify(v)}>>`,
    });
    expect(await t.call({})).toBe('<<{"name":"Tanaka Taro"}>>');
  });

  it("defers minimum-disclosure enforcement to shield() (throws with no scope/deny)", () => {
    expect(() =>
      shieldedTool({
        name: "t",
        description: "d",
        purpose: "p",
        handler: async () => RECORD,
      }),
    ).toThrow(AegisValidationError);
  });

  it("fail-closed: a throwing handler yields a safe empty, never the error's data", async () => {
    const t = shieldedTool({
      name: "t",
      description: "d",
      purpose: "p",
      scope: ["name"],
      mode: Mode.LITE,
      handler: async () => {
        throw new Error("db blew up — ssn=123-45-6789");
      },
    });
    expect(await t.run({})).toBe("");
    expect(await t.call({})).not.toContain("123-45-6789");
  });
});

describe("shieldedTool — audit identity & mode coverage", () => {
  it("records the tool name (not 'anonymous') in the audit hook", async () => {
    const seen: string[] = [];
    _setTestHook((r) => seen.push(r.function));
    await lookup().run({ id: "C-1001" });
    expect(seen).toContain("customer_lookup");
    expect(seen).not.toContain("anonymous");
  });

  it("supports a denyFields-only spec (blacklist) and records the tool name", async () => {
    const seen: string[] = [];
    _setTestHook((r) => seen.push(r.function));
    const t = shieldedTool<{ id: string }>({
      name: "customer_lookup_deny",
      description: "Look up a customer, stripping sensitive fields.",
      purpose: "customer_support",
      denyFields: ["ssn", "credit_card", "email"],
      mode: Mode.LITE,
      handler: async () => RECORD,
    });
    expect(await t.run({ id: "C-1001" })).toEqual({
      name: "Tanaka Taro",
      issue: "Cannot reset password",
    });
    expect(seen).toContain("customer_lookup_deny");
  });

  it("AUTO mode (default, no token) resolves to the LITE path and still filters", async () => {
    // No AEGIS_TOKEN in the test env → detectMode() returns 'lite' with no
    // network probe, exercising the forced-async runGatedAsync → LITE branch.
    const t = shieldedTool<{ id: string }>({
      name: "auto_lookup",
      description: "d",
      purpose: "p",
      scope: ["name", "issue"],
      handler: async () => RECORD,
    });
    expect(await t.run({ id: "C-1001" })).toEqual(SCOPED);
  });

  it("fail-closed: a serializer that throws yields '' rather than propagating", async () => {
    const t = shieldedTool({
      name: "bad_serializer",
      description: "d",
      purpose: "p",
      scope: ["name"],
      mode: Mode.LITE,
      handler: async () => RECORD,
      serialize: () => {
        throw new Error("serializer blew up with ssn=123-45-6789");
      },
    });
    expect(await t.call({})).toBe("");
  });
});

describe("toLangChainTool", () => {
  it("calls the injected factory with name/description/schema and a string-returning func", async () => {
    const schema = { type: "object", properties: { id: { type: "string" } } };
    const t = shieldedTool<{ id: string }>({
      name: "customer_lookup",
      description: "Look up a customer.",
      purpose: "customer_support",
      scope: ["name", "issue"],
      mode: Mode.LITE,
      schema,
      handler: async () => RECORD,
    });

    let captured: { func: (i: unknown) => Promise<string> | string; config: Record<string, unknown> } | undefined;
    const fakeFactory = (
      func: (i: unknown) => Promise<string> | string,
      config: { name: string; description: string; schema?: unknown },
    ) => {
      captured = { func, config };
      return { __isLangChainTool: true };
    };

    const lc = toLangChainTool(fakeFactory, t);
    expect(lc).toEqual({ __isLangChainTool: true });
    expect(captured!.config).toEqual({
      name: "customer_lookup",
      description: "Look up a customer.",
      schema,
    });

    const out = await captured!.func({ id: "C-1001" });
    expect(typeof out).toBe("string");
    expect(JSON.parse(out as string)).toEqual(SCOPED);
  });

  it("omits the schema key when the tool has no schema", () => {
    let cfg: Record<string, unknown> | undefined;
    toLangChainTool((_f, config) => {
      cfg = config;
      return null;
    }, lookup());
    expect(cfg).toEqual({ name: "customer_lookup", description: "Look up a customer record by id for support." });
    expect("schema" in cfg!).toBe(false);
  });
});

describe("toLlamaIndexTool", () => {
  it("calls the injected factory with name/description/parameters and a string-returning fn", async () => {
    const schema = { type: "object", properties: { id: { type: "string" } } };
    const t = shieldedTool<{ id: string }>({
      name: "customer_lookup",
      description: "Look up a customer.",
      purpose: "customer_support",
      scope: ["name", "issue"],
      mode: Mode.LITE,
      schema,
      handler: async () => RECORD,
    });

    let captured: { fn: (i: unknown) => Promise<string> | string; config: Record<string, unknown> } | undefined;
    const fakeFactory = (
      fn: (i: unknown) => Promise<string> | string,
      config: { name: string; description: string; parameters?: unknown },
    ) => {
      captured = { fn, config };
      return { __isLlamaIndexTool: true };
    };

    const li = toLlamaIndexTool(fakeFactory, t);
    expect(li).toEqual({ __isLlamaIndexTool: true });
    // LlamaIndex names the schema param `parameters` (not LangChain's `schema`).
    expect(captured!.config).toEqual({
      name: "customer_lookup",
      description: "Look up a customer.",
      parameters: schema,
    });

    const out = await captured!.fn({ id: "C-1001" });
    expect(typeof out).toBe("string");
    expect(JSON.parse(out as string)).toEqual(SCOPED);
  });

  it("omits the parameters key when the tool has no schema", () => {
    let cfg: Record<string, unknown> | undefined;
    toLlamaIndexTool((_f, config) => {
      cfg = config;
      return null;
    }, lookup());
    expect(cfg).toEqual({ name: "customer_lookup", description: "Look up a customer record by id for support." });
    expect("parameters" in cfg!).toBe(false);
  });
});

describe("toVercelTool", () => {
  it("defaults the schema key to inputSchema (AI SDK v5+) and execute returns the filtered object", async () => {
    const schema = { __zod: "object" };
    const t = shieldedTool<{ id: string }>({
      name: "customer_lookup",
      description: "Look up a customer.",
      purpose: "customer_support",
      scope: ["name", "issue"],
      mode: Mode.LITE,
      schema,
      handler: async () => RECORD,
    });
    const v = toVercelTool(t);
    expect(v.inputSchema).toBe(schema);
    expect(v.parameters).toBeUndefined();
    expect(v.description).toBe("Look up a customer.");
    expect(await v.execute({ id: "C-1001" })).toEqual(SCOPED);
  });

  it("honours a custom schemaKey for AI SDK v4 and earlier", () => {
    const schema = { __zod: "object" };
    const t = shieldedTool({
      name: "t",
      description: "d",
      purpose: "p",
      scope: ["name"],
      mode: Mode.LITE,
      schema,
      handler: async () => RECORD,
    });
    const v = toVercelTool(t, { schemaKey: "parameters" });
    expect(v.parameters).toBe(schema);
    expect(v.inputSchema).toBeUndefined();
  });
});

describe("toCrewaiTool", () => {
  it("exposes { name, description, run } and run() returns the filtered object", async () => {
    const c = toCrewaiTool(lookup());
    expect(c.name).toBe("customer_lookup");
    expect(c.description).toBe("Look up a customer record by id for support.");
    expect(await c.run({ id: "C-1001" })).toEqual(SCOPED);
  });
});
