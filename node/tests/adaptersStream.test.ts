import { afterEach, describe, expect, it } from "vitest";

import { _setTestHook } from "../src/shield.js";
import { resetModuleClient } from "../src/client.js";
import { AegisValidationError, Mode } from "../src/index.js";
import {
  shieldedStreamTool,
  type ShieldedStreamTool,
  type ShieldedStreamToolSpec,
} from "../src/adapters/index.js";

afterEach(() => {
  _setTestHook(null);
});

const RECORDS = [
  { name: "Tanaka Taro", email: "tanaka@example.com", ssn: "123-45-6789", issue: "Login" },
  { name: "Sato Hanako", email: "sato@example.com", ssn: "987-65-4321", issue: "Billing" },
  { name: "Suzuki Ken", email: "suzuki@example.com", ssn: "555-55-5555", issue: "Refund" },
];

const SCOPED = [
  { name: "Tanaka Taro", issue: "Login" },
  { name: "Sato Hanako", issue: "Billing" },
  { name: "Suzuki Ken", issue: "Refund" },
];

function streamTool(
  handler: ShieldedStreamToolSpec<{ q: string }>["handler"],
): ShieldedStreamTool<{ q: string }> {
  return shieldedStreamTool<{ q: string }>({
    name: "customer_rows",
    description: "Stream customer records for a support session.",
    purpose: "customer_support",
    scope: ["name", "issue"],
    mode: Mode.LITE,
    handler,
  });
}

async function collect(it: AsyncIterable<unknown>): Promise<unknown[]> {
  const out: unknown[] = [];
  for await (const r of it) out.push(r);
  return out;
}

describe("shieldedStreamTool", () => {
  it("filters each record from an async generator to the declared scope", async () => {
    const tool = streamTool(async function* () {
      for (const r of RECORDS) yield r;
    });
    expect(await collect(tool.stream({ q: "open" }))).toEqual(SCOPED);
  });

  it("filters records from a plain sync iterable too", async () => {
    const tool = streamTool(() => RECORDS[Symbol.iterator]());
    expect(await collect(tool.stream({ q: "open" }))).toEqual(SCOPED);
  });

  it("never emits blocked fields in any record", async () => {
    const tool = streamTool(async function* () {
      for (const r of RECORDS) yield r;
    });
    const serialized = JSON.stringify(await collect(tool.stream({ q: "open" })));
    expect(serialized).not.toContain("ssn");
    expect(serialized).not.toContain("123-45-6789");
    expect(serialized).not.toContain("email");
    expect(serialized).not.toContain("@example.com");
  });

  it("fails closed to an EMPTY stream when the handler throws before producing", async () => {
    const tool = streamTool(() => {
      throw new Error("upstream down — must not surface, may carry data");
    });
    expect(await collect(tool.stream({ q: "open" }))).toEqual([]);
  });

  it("fails closed mid-stream: stops cleanly, keeps already-filtered records, leaks nothing", async () => {
    const tool = streamTool(async function* () {
      yield RECORDS[0];
      yield RECORDS[1];
      throw new Error("cursor exploded with raw row in the message");
    });
    const got = await collect(tool.stream({ q: "open" }));
    // The two records produced before the throw stand — filtered.
    expect(got).toEqual([SCOPED[0], SCOPED[1]]);
    // And nothing from the failure leaked.
    expect(JSON.stringify(got)).not.toContain("ssn");
  });

  it("does not re-throw when the underlying iterator throws (framework sees no exception)", async () => {
    const tool = streamTool(async function* () {
      yield RECORDS[0];
      throw new Error("boom");
    });
    await expect(collect(tool.stream({ q: "open" }))).resolves.toBeDefined();
  });

  it("yields an empty stream when the handler yields nothing", async () => {
    const tool = streamTool(async function* () {
      // produce no records
    });
    expect(await collect(tool.stream({ q: "open" }))).toEqual([]);
  });

  it("throws aegis.shield.spec.required synchronously when neither scope nor denyFields is set", () => {
    expect(() =>
      shieldedStreamTool({
        name: "bad",
        description: "missing scope and denyFields",
        purpose: "customer_support",
        handler: async function* () {
          yield RECORDS[0];
        },
      }),
    ).toThrow(AegisValidationError);
  });

  it("supports denyFields (blacklist) per record", async () => {
    const tool = shieldedStreamTool<{ q: string }>({
      name: "customer_rows_deny",
      description: "Stream rows with sensitive fields stripped.",
      purpose: "customer_support",
      denyFields: ["ssn", "email"],
      mode: Mode.LITE,
      handler: async function* () {
        yield RECORDS[0];
      },
    });
    const [rec] = (await collect(tool.stream({ q: "open" }))) as Array<Record<string, unknown>>;
    expect(rec).toEqual({ name: "Tanaka Taro", issue: "Login" });
    expect(rec).not.toHaveProperty("ssn");
    expect(rec).not.toHaveProperty("email");
  });

  it("throws aegis.shield.stream.full_unsupported when mode FULL is requested explicitly", () => {
    expect(() =>
      shieldedStreamTool({
        name: "full_stream",
        description: "FULL is not supported for streaming yet",
        purpose: "customer_support",
        scope: ["name", "issue"],
        mode: Mode.FULL,
        handler: async function* () {
          yield RECORDS[0];
        },
      }),
    ).toThrow(AegisValidationError);
  });

  it("throws aegis.shield.mode.invalid for a mistyped mode (no silent LITE downgrade)", () => {
    for (const bad of ["FULL", "Lite", "fulll", "AUTO"]) {
      expect(() =>
        shieldedStreamTool({
          name: "bad_mode",
          description: "mistyped mode must fail closed, not downgrade to LITE",
          purpose: "customer_support",
          scope: ["name", "issue"],
          mode: bad as unknown as Mode,
          handler: async function* () {
            yield RECORDS[0];
          },
        }),
      ).toThrow(AegisValidationError);
    }
  });

  it("refuses fail-closed (empty stream, handler NOT called) when AUTO resolves to FULL", async () => {
    const prev = process.env.AEGIS_MODE;
    process.env.AEGIS_MODE = "full"; // explicit FULL intent → detectMode() === "full"
    resetModuleClient(); // clear the 60s detect-mode TTL cache so env takes effect
    try {
      let called = false;
      const tool = shieldedStreamTool<{ q: string }>({
        name: "auto_full_stream",
        description: "AUTO that resolves to FULL must refuse, not downgrade",
        purpose: "customer_support",
        scope: ["name", "issue"],
        // no mode → AUTO; AEGIS_MODE=full makes detectMode() resolve to FULL
        handler: async function* () {
          called = true; // must never run: the gate cannot be honored
          yield RECORDS[0];
        },
      });
      const got = await collect(tool.stream({ q: "open" }));
      expect(got).toEqual([]); // empty stream — no cardinality leak
      expect(called).toBe(false); // accessor never executed — no side effects
    } finally {
      if (prev === undefined) delete process.env.AEGIS_MODE;
      else process.env.AEGIS_MODE = prev;
      resetModuleClient();
    }
  });

  it("records the tool name (not 'anonymous') in the shield audit hook", async () => {
    const names: string[] = [];
    _setTestHook((call) => {
      names.push(call.function);
    });
    const tool = streamTool(async function* () {
      for (const r of RECORDS) yield r;
    });
    await collect(tool.stream({ q: "open" }));
    expect(names.length).toBeGreaterThan(0);
    expect(names.every((n) => n === "customer_rows")).toBe(true);
  });
});
