// AI-native v1 client methods (tool-call / capability / stream) — wire-floor
// tests against the frozen boundary contract (AI_NATIVE_V1_CONTRACT.md).
// House pattern (client.test.ts): override globalThis.fetch, restore afterEach.

import { afterEach, describe, expect, it } from "vitest";

import { AegisClient } from "../src/client.js";
import { AegisValidationError } from "../src/errors.js";

const origFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = origFetch;
});

function mockFetch(impl: (url: string, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) =>
    impl(String(input), init)) as unknown as typeof fetch;
}

function client(): AegisClient {
  return new AegisClient({ baseUrl: "https://localhost:8443/api/v1", token: "t" });
}

const DECISION_OK = { outcome: "PROTECTED", ledgered: true, decision_id: "d-1" };

describe("toolCall", () => {
  it("posts the wire body and parses the decision", async () => {
    let captured: { url?: string; body?: unknown } = {};
    mockFetch(async (url, init) => {
      captured = { url, body: JSON.parse(String(init?.body)) };
      return new Response(JSON.stringify({ decision: DECISION_OK, enforcement: null }), {
        status: 200,
      });
    });
    const out = await client().toolCall({
      tool: "query_business_data",
      purpose: "customer_data",
      owner: "acme",
      fields: ["name"],
      sessionId: "s-1",
      destination: "llm:anthropic",
    });
    expect(captured.url).toContain("/tool-call");
    expect(captured.body).toEqual({
      tool: "query_business_data",
      purpose: "customer_data",
      owner: "acme",
      fields: ["name"],
      session_id: "s-1",
      destination: "llm:anthropic",
    });
    expect(out.decision.outcome).toBe("PROTECTED");
  });

  it("attaches capability only when given", async () => {
    let body: Record<string, unknown> = {};
    mockFetch(async (_url, init) => {
      body = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ decision: DECISION_OK, enforcement: null }), {
        status: 200,
      });
    });
    await client().toolCall({ tool: "t", purpose: "p", owner: "o" });
    expect("capability" in body).toBe(false);
    await client().toolCall({ tool: "t", purpose: "p", owner: "o", capability: "tok" });
    expect(body.capability).toBe("tok");
  });

  it("throws AegisValidationError on a malformed decision", async () => {
    mockFetch(async () =>
      new Response(JSON.stringify({ decision: { outcome: "PROTECTED" } }), { status: 200 }));
    await expect(client().toolCall({ tool: "t", purpose: "p", owner: "o" }))
      .rejects.toBeInstanceOf(AegisValidationError);
  });
});

describe("toolAllowed (fail-closed gate)", () => {
  it("denies on transport error, non-200, BLOCKED, and unledgered", async () => {
    mockFetch(async () => { throw new Error("down"); });
    expect(await client().toolAllowed({ tool: "t", purpose: "p", owner: "o" })).toBe(false);

    mockFetch(async () => new Response("{}", { status: 503 }));
    expect(await client().toolAllowed({ tool: "t", purpose: "p", owner: "o" })).toBe(false);

    mockFetch(async () =>
      new Response(JSON.stringify({ decision: { outcome: "BLOCKED", ledgered: true } }),
        { status: 200 }));
    expect(await client().toolAllowed({ tool: "t", purpose: "p", owner: "o" })).toBe(false);

    mockFetch(async () =>
      new Response(JSON.stringify({ decision: { outcome: "PROTECTED", ledgered: false } }),
        { status: 200 }));
    expect(await client().toolAllowed({ tool: "t", purpose: "p", owner: "o" })).toBe(false);
  });

  it("allows a ledgered passing decision", async () => {
    mockFetch(async () =>
      new Response(JSON.stringify({ decision: DECISION_OK, enforcement: null }),
        { status: 200 }));
    expect(await client().toolAllowed({ tool: "t", purpose: "p", owner: "o" })).toBe(true);
  });
});

const GRANT_OK = {
  capability: "tok-abc",
  id: "c1d2",
  exp: 1_900_000_000,
  depth: 1,
  root_delegator: "root-agent",
};

describe("capabilityMint / capabilityRevoke", () => {
  it("posts wire keys and parses the grant", async () => {
    let body: Record<string, unknown> = {};
    mockFetch(async (_url, init) => {
      body = JSON.parse(String(init?.body));
      return new Response(JSON.stringify(GRANT_OK), { status: 200 });
    });
    const grant = await client().capabilityMint({
      forAgent: "sub-agent",
      purposes: ["customer_data"],
      scope: ["name"],
      tools: ["t1"],
      ttlSecs: 600,
      parentCapability: "parent-tok",
    });
    expect(body).toEqual({
      for_agent: "sub-agent",
      purposes: ["customer_data"],
      scope: ["name"],
      tools: ["t1"],
      ttl_secs: 600,
      parent_capability: "parent-tok",
    });
    expect(grant).toEqual(GRANT_OK);
  });

  it.each(["capability", "id", "exp", "depth", "root_delegator"])(
    "rejects a grant missing %s",
    async (missing) => {
      const bad: Record<string, unknown> = { ...GRANT_OK };
      delete bad[missing];
      mockFetch(async () => new Response(JSON.stringify(bad), { status: 200 }));
      await expect(client().capabilityMint({ forAgent: "a", purposes: ["p"] }))
        .rejects.toBeInstanceOf(AegisValidationError);
    },
  );

  it("revokes by token and by id", async () => {
    let body: Record<string, unknown> = {};
    mockFetch(async (_url, init) => {
      body = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ ok: true, revoked: "c1d2" }), { status: 200 });
    });
    expect(await client().capabilityRevoke({ capability: "tok" })).toBe("c1d2");
    expect(body).toEqual({ capability: "tok" });
    expect(await client().capabilityRevoke({ capabilityId: "c1d2" })).toBe("c1d2");
    expect(body).toEqual({ capability_id: "c1d2" });
  });

  it("rejects a revoke without ok:true", async () => {
    mockFetch(async () => new Response(JSON.stringify({ ok: false }), { status: 200 }));
    await expect(client().capabilityRevoke({ capability: "tok" }))
      .rejects.toBeInstanceOf(AegisValidationError);
  });
});

describe("stream open/heartbeat/close", () => {
  it("wraps the envelope and parses the stream grant", async () => {
    let body: Record<string, unknown> = {};
    mockFetch(async (_url, init) => {
      body = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({
        decision: DECISION_OK,
        enforcement: null,
        stream: { stream_id: "s-9", status: "open" },
      }), { status: 200 });
    });
    const env = { schema_version: "1.0", purpose: "p" };
    const out = await client().streamOpen(env);
    expect(body).toEqual({ envelope: env });
    expect(out.stream?.stream_id).toBe("s-9");
  });

  it("passes through a null stream on BLOCKED", async () => {
    mockFetch(async () => new Response(JSON.stringify({
      decision: { outcome: "BLOCKED", ledgered: true },
      enforcement: null,
      stream: null,
    }), { status: 200 }));
    expect((await client().streamOpen({ purpose: "p" })).stream).toBeNull();
  });

  it.each([
    [{ status: "ok" }, { status: "ok", reason: null }],
    [{ status: "revoked", reason: "duress_active" },
      { status: "revoked", reason: "duress_active" }],
    [{ status: "closed" }, { status: "closed", reason: null }],
  ])("heartbeat parses %j", async (wire, expected) => {
    mockFetch(async () => new Response(JSON.stringify(wire), { status: 200 }));
    expect(await client().streamHeartbeat("s-9")).toEqual(expected);
  });

  it("heartbeat rejects a missing status", async () => {
    mockFetch(async () => new Response("{}", { status: 200 }));
    await expect(client().streamHeartbeat("s-9"))
      .rejects.toBeInstanceOf(AegisValidationError);
  });

  it("close returns true on ok and rejects otherwise", async () => {
    mockFetch(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    expect(await client().streamClose("s-9")).toBe(true);
    mockFetch(async () => new Response("{}", { status: 200 }));
    await expect(client().streamClose("s-9")).rejects.toBeInstanceOf(AegisValidationError);
  });
});
