import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AegisClient,
  isDevHost,
  resetModuleClient,
  resolveVerifySsl,
  setMetricsHook,
} from "../src/index.js";

const origFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = origFetch;
  setMetricsHook(null);
  resetModuleClient();
});

function mockFetch(impl: typeof fetch): void {
  globalThis.fetch = impl as unknown as typeof fetch;
}

describe("isDevHost", () => {
  it("recognises localhost variants", () => {
    expect(isDevHost("http://localhost:8443")).toBe(true);
    expect(isDevHost("https://127.0.0.1")).toBe(true);
    expect(isDevHost("http://my.local")).toBe(true);
  });
  it("flags non-dev hosts", () => {
    expect(isDevHost("https://api.aegis.example.com")).toBe(false);
  });
});

describe("resolveVerifySsl prod-lock", () => {
  it("forces TLS verify on for prod host even if requested false", () => {
    expect(resolveVerifySsl("https://api.example.com", false)).toBe(true);
  });
  it("allows TLS off on dev host only with AEGIS_DEV_INSECURE=1", () => {
    process.env.AEGIS_DEV_INSECURE = "1";
    expect(resolveVerifySsl("http://localhost:8443", false)).toBe(false);
    delete process.env.AEGIS_DEV_INSECURE;
    expect(resolveVerifySsl("http://localhost:8443", false)).toBe(true);
  });
});

describe("AegisClient.isAvailable", () => {
  it("returns true on 200", async () => {
    mockFetch(async () => new Response("ok", { status: 200 }));
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.isAvailable()).toBe(true);
  });
  it("returns false on transport error", async () => {
    mockFetch(async () => {
      throw new Error("ECONNREFUSED");
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.isAvailable()).toBe(false);
  });
});

describe("authorize (AO-003 fail-closed)", () => {
  it("allows when 200 { allowed: true }", async () => {
    mockFetch(async () => new Response(JSON.stringify({ allowed: true }), { status: 200 }));
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.authorize("p", ["name"])).toBe(true);
  });
  it("denies when 200 { allowed: false }", async () => {
    mockFetch(async () => new Response(JSON.stringify({ allowed: false }), { status: 200 }));
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.authorize("p", ["name"])).toBe(false);
  });
  it("fail-closed on 200 without allowed field", async () => {
    mockFetch(async () => new Response(JSON.stringify({}), { status: 200 }));
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.authorize("p", ["name"])).toBe(false);
  });
  it("fail-closed on transport error", async () => {
    mockFetch(async () => {
      throw new Error("net");
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.authorize("p", ["name"])).toBe(false);
  });
  it("denies on 403", async () => {
    mockFetch(async () => new Response("forbidden", { status: 403 }));
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.authorize("p", ["name"])).toBe(false);
  });
  it("caches allow decisions", async () => {
    let calls = 0;
    mockFetch(async () => {
      calls++;
      return new Response(JSON.stringify({ allowed: true }), { status: 200 });
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    await c.authorize("p", ["name"]);
    await c.authorize("p", ["name"]);
    expect(calls).toBe(1);
  });
  it("does not cache deny decisions", async () => {
    let calls = 0;
    mockFetch(async () => {
      calls++;
      return new Response(JSON.stringify({ allowed: false }), { status: 200 });
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    await c.authorize("p", ["name"]);
    await c.authorize("p", ["name"]);
    expect(calls).toBe(2);
  });
});

describe("ingest", () => {
  it("posts payload and parses response", async () => {
    const captured: { url: string; body: string }[] = [];
    mockFetch(async (input, init) => {
      captured.push({
        url: String(input),
        body: String(init?.body),
      });
      return new Response(
        JSON.stringify({
          data: { ingested: 1, audit_seq_start: 10, audit_seq_end: 10 },
        }),
        { status: 200 },
      );
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    const out = await c.ingest([
      {
        function: "getUser",
        purpose: "p",
        scope: ["name"],
        blockedFields: ["ssn"],
        timestamp: "2026-01-01T00:00:00Z",
        count: 1,
        denyFields: [],
      },
    ]);
    expect(out).toEqual({ ingested: 1, auditSeqStart: 10, auditSeqEnd: 10 });
    expect(captured[0]!.url).toContain("/shield/ingest");
    const sent = JSON.parse(captured[0]!.body);
    expect(sent.entries[0].blocked_fields).toEqual(["ssn"]);
  });
  it("rejects malformed body shapes", async () => {
    mockFetch(async () => new Response(JSON.stringify({ bogus: 1 }), { status: 200 }));
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    await expect(
      c.ingest([
        {
          function: "f",
          purpose: "p",
          scope: [],
          blockedFields: [],
          timestamp: "t",
          count: 1,
          denyFields: [],
        },
      ]),
    ).rejects.toThrow(/data/);
  });
  it("rejects non-monotonic seq", async () => {
    mockFetch(async () =>
      new Response(
        JSON.stringify({
          data: { ingested: 1, audit_seq_start: 10, audit_seq_end: 5 },
        }),
        { status: 200 },
      ),
    );
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    await expect(
      c.ingest([
        {
          function: "f",
          purpose: "p",
          scope: [],
          blockedFields: [],
          timestamp: "t",
          count: 1,
          denyFields: [],
        },
      ]),
    ).rejects.toThrow(/non-monotonic|invalid/);
  });
});

describe("verifyAuditChain + verifyInclusion", () => {
  it("verifyAuditChain parses body", async () => {
    mockFetch(async () =>
      new Response(
        JSON.stringify({ chain_valid: true, total_entries: 42 }),
        { status: 200 },
      ),
    );
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    const s = await c.verifyAuditChain();
    expect(s).toEqual({ chainValid: true, totalEntries: 42 });
  });

  it("verifyInclusion fails when no ingests have happened", async () => {
    mockFetch(async () =>
      new Response(JSON.stringify({ chain_valid: true, total_entries: 1 }), { status: 200 }),
    );
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    expect(await c.verifyInclusion()).toBe(false);
  });

  it("verifyInclusion succeeds when chain covers ingested seq", async () => {
    let route: "ingest" | "verify" = "ingest";
    mockFetch(async () => {
      if (route === "ingest") {
        route = "verify";
        return new Response(
          JSON.stringify({
            data: { ingested: 1, audit_seq_start: 5, audit_seq_end: 5 },
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({ chain_valid: true, total_entries: 5 }),
        { status: 200 },
      );
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    await c.ingest([
      {
        function: "f",
        purpose: "p",
        scope: [],
        blockedFields: ["x"],
        timestamp: "t",
        count: 1,
        denyFields: [],
      },
    ]);
    expect(await c.verifyInclusion()).toBe(true);
  });
});

describe("policySync", () => {
  it("posts purposes payload", async () => {
    const captured: { body: string }[] = [];
    mockFetch(async (_input, init) => {
      captured.push({ body: String(init?.body) });
      return new Response(
        JSON.stringify({ data: { synced: 2, added: ["a"], updated: ["b"] } }),
        { status: 200 },
      );
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    const out = await c.policySync({
      support: { scope: ["name"], denyFields: [] },
      ssn_only: { scope: [], denyFields: ["ssn"] },
    });
    expect(out.synced).toBe(2);
    const sent = JSON.parse(captured[0]!.body);
    expect(sent.purposes.ssn_only.deny_fields).toEqual(["ssn"]);
  });
});

describe("getStats", () => {
  it("parses stats body", async () => {
    mockFetch(async () =>
      new Response(
        JSON.stringify({
          data: {
            period: { from: "a", to: "b" },
            total_calls: 5,
            total_blocked_fields: 2,
            by_purpose: { p: { calls: 5, blocked: 2 } },
            by_field: { ssn: { blocked_count: 2 } },
            by_function: { f: { calls: 5, purposes: ["p"] } },
          },
        }),
        { status: 200 },
      ),
    );
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    const s = await c.getStats();
    expect(s.totalCalls).toBe(5);
    expect(s.byField.ssn?.blockedCount).toBe(2);
  });
});

describe("setToken rotation", () => {
  it("clears access cache and updates auth header", async () => {
    let lastAuth: string | null = null;
    mockFetch(async (_input, init) => {
      lastAuth = (init?.headers as Record<string, string>)?.Authorization ?? null;
      return new Response(JSON.stringify({ allowed: true }), { status: 200 });
    });
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1", token: "old" });
    await c.authorize("p", ["x"]);
    expect(lastAuth).toBe("Bearer old");
    c.setToken("new");
    // Cache cleared → re-fetch required.
    await c.authorize("p", ["x"]);
    expect(lastAuth).toBe("Bearer new");
  });
});

describe("metrics hook", () => {
  it("fires after every request", async () => {
    const events: { endpoint: string; status: number }[] = [];
    setMetricsHook((endpoint, _ms, status) => events.push({ endpoint, status }));
    mockFetch(async () => new Response(JSON.stringify({ allowed: true }), { status: 200 }));
    const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
    await c.authorize("p", []);
    expect(events).toEqual([{ endpoint: "check-access", status: 200 }]);
  });
});
