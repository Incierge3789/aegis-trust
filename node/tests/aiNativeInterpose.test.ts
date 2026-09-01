// AI-native Layer 2 interposition — guardTool / delegate / streamSession.
//
// The wire floor (aiNative.test.ts) proves the client speaks the frozen
// contract; THIS file proves the boundary sits IN the call path: forgetting
// is impossible, deny/error → null (the shield convention), a failed
// delegation mint denies the whole window, and a revoked stream stops the
// agent. House pattern: override globalThis.fetch, restore afterEach.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  currentCapability,
  delegate,
  guardTool,
  streamSession,
} from "../src/aiNative.js";
import { AegisClient } from "../src/client.js";
import {
  AegisStreamDeniedError,
  AegisStreamRevokedError,
  AegisValidationError,
} from "../src/errors.js";

const origFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = origFetch;
  vi.restoreAllMocks();
});

beforeEach(() => {
  // Owner resolution must be deterministic — clear ambient identity env.
  delete process.env.AEGIS_OWNER;
  delete process.env.AEGIS_AGENT_ID;
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

const DECISION_OK = { outcome: "PROTECTED", ledgered: true, decision_id: "d-1" };
const DECISION_BLOCKED = { outcome: "BLOCKED", ledgered: true, decision_id: "d-2" };
const GRANT = {
  capability: "cap-token-1",
  id: "a".repeat(32),
  exp: 4102444800,
  depth: 1,
  root_delegator: "root-sub",
};

function client(): AegisClient {
  return new AegisClient({ baseUrl: "https://localhost:8443/api/v1", token: "t" });
}

type Route = ((body: Record<string, unknown>) => Response) | Response | (() => Response);

/** Record calls and route by path suffix (Python _recording_handler parity). */
function mockRoutes(routes: Record<string, Route>): Array<{ path: string; body: Record<string, unknown> }> {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const path = new URL(url).pathname;
    calls.push({ path, body });
    for (const [suffix, resp] of Object.entries(routes)) {
      if (path.endsWith(suffix)) {
        return typeof resp === "function" ? resp(body) : resp.clone();
      }
    }
    return new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
  return calls;
}

const toolOk = () =>
  new Response(JSON.stringify({ decision: DECISION_OK, enforcement: null }), { status: 200 });
const toolBlocked = () =>
  new Response(JSON.stringify({ decision: DECISION_BLOCKED, enforcement: null }), { status: 200 });
const streamOpenOk = () =>
  new Response(
    JSON.stringify({
      decision: DECISION_OK,
      enforcement: null,
      stream: { stream_id: "st-1", status: "open" },
    }),
    { status: 200 },
  );

// ── guardTool ────────────────────────────────────────────────────────

describe("guardTool", () => {
  it("allow: runs fn and sends the wire body", async () => {
    const calls = mockRoutes({ "/tool-call": toolOk });
    const query = guardTool({
      purpose: "customer_data",
      owner: "acme",
      fields: ["name"],
      sessionId: "s-1",
      destination: "llm:anthropic",
      client: client(),
    })(function queryBusinessData(q: string) {
      return { rows: [q] };
    });
    expect(await query("x")).toEqual({ rows: ["x"] });
    expect(calls[0].path).toContain("/tool-call");
    expect(calls[0].body).toEqual({
      tool: "queryBusinessData", // defaults to the function name
      purpose: "customer_data",
      owner: "acme",
      fields: ["name"],
      session_id: "s-1",
      destination: "llm:anthropic",
    });
  });

  it("deny: never invokes fn, resolves null", async () => {
    const calls = mockRoutes({ "/tool-call": toolBlocked });
    let ran = 0;
    const tool = guardTool({ purpose: "p", owner: "o", client: client() })(() => {
      ran += 1;
      return "secret";
    });
    expect(await tool()).toBeNull();
    expect(ran).toBe(0);
    expect(calls.length).toBe(1); // the gate WAS consulted
  });

  it("fail-closed on transport error and unledgered decision", async () => {
    globalThis.fetch = (async () => {
      throw new Error("down");
    }) as unknown as typeof fetch;
    const t1 = guardTool({ purpose: "p", owner: "o", client: client() })(() => "x");
    expect(await t1()).toBeNull();

    mockRoutes({
      "/tool-call": () =>
        new Response(JSON.stringify({ decision: { outcome: "PROTECTED", ledgered: false } }), {
          status: 200,
        }),
    });
    const t2 = guardTool({ purpose: "p", owner: "o", client: client() })(() => "x");
    expect(await t2()).toBeNull();
  });

  it("owner unresolvable: denies locally without a gateway call", async () => {
    const calls = mockRoutes({ "/tool-call": toolOk });
    const tool = guardTool({ purpose: "p", client: client() })(() => "x");
    expect(await tool()).toBeNull();
    expect(calls.length).toBe(0);
  });

  it("owner from AEGIS_OWNER env", async () => {
    process.env.AEGIS_OWNER = "env-owner";
    const calls = mockRoutes({ "/tool-call": toolOk });
    const tool = guardTool({ purpose: "p", client: client() })(() => "x");
    expect(await tool()).toBe("x");
    expect(calls[0].body.owner).toBe("env-owner");
  });

  it("fn throw after grant resolves null (withheld)", async () => {
    mockRoutes({ "/tool-call": toolOk });
    const tool = guardTool({ purpose: "p", owner: "o", client: client() })(() => {
      throw new Error("ssn=123-45-6789"); // must be withheld
    });
    expect(await tool()).toBeNull();
  });

  it("construction-time validation", () => {
    expect(() => guardTool({ purpose: "" })).toThrow(AegisValidationError);
    expect(() => guardTool({ purpose: "p", tool: "" })).toThrow(AegisValidationError);
    expect(() =>
      guardTool({ purpose: "p", fields: "name" as unknown as string[] }),
    ).toThrow(AegisValidationError);   // coded envelope (aegis.guard_tool.fields.invalid), no bare TypeError
  });
});

// ── delegate ─────────────────────────────────────────────────────────

describe("delegate", () => {
  it("mints, attaches to guarded calls, revokes on exit", async () => {
    const calls = mockRoutes({
      "/capability/mint": () => new Response(JSON.stringify(GRANT), { status: 200 }),
      "/capability/revoke": () =>
        new Response(JSON.stringify({ ok: true, revoked: GRANT.id }), { status: 200 }),
      "/tool-call": toolOk,
    });
    const c = client();

    expect(currentCapability()).toBeNull();
    await delegate({ forAgent: "researcher", purposes: ["customer_data"], client: c }, async (grant) => {
      expect(grant?.capability).toBe("cap-token-1");
      expect(currentCapability()).toBe("cap-token-1");
      const tool = guardTool({ purpose: "customer_data", owner: "acme", client: c })(() => "ok");
      expect(await tool()).toBe("ok");
    });
    expect(currentCapability()).toBeNull();

    expect(calls[0].path).toContain("/capability/mint");
    expect(calls[0].body.for_agent).toBe("researcher");
    expect(calls[0].body).not.toHaveProperty("parent_capability"); // root mint
    const toolCall = calls.find((c2) => c2.path.endsWith("/tool-call"));
    expect(toolCall?.body.capability).toBe("cap-token-1"); // auto-attached
    expect(calls[calls.length - 1].path).toContain("/capability/revoke");
    expect(calls[calls.length - 1].body).toEqual({ capability: "cap-token-1" });
  });

  it("nested narrowing carries the parent capability", async () => {
    const child = { ...GRANT, capability: "cap-token-2", depth: 2 };
    let mints = 0;
    const calls = mockRoutes({
      "/capability/mint": () => {
        mints += 1;
        return new Response(JSON.stringify(mints === 1 ? GRANT : child), { status: 200 });
      },
      "/capability/revoke": () =>
        new Response(JSON.stringify({ ok: true, revoked: "x".repeat(32) }), { status: 200 }),
    });
    const c = client();
    await delegate({ forAgent: "outer", purposes: ["p1"], client: c }, async () => {
      await delegate({ forAgent: "inner", purposes: ["p1"], client: c }, async (inner) => {
        expect(inner).not.toBeNull();
        expect(currentCapability()).toBe("cap-token-2");
      });
      expect(currentCapability()).toBe("cap-token-1");
    });
    const mintBodies = calls.filter((c2) => c2.path.endsWith("/capability/mint"));
    expect(mintBodies[0].body).not.toHaveProperty("parent_capability");
    expect(mintBodies[1].body.parent_capability).toBe("cap-token-1");
  });

  it("mint failure denies the whole window (locally)", async () => {
    const calls = mockRoutes({
      "/capability/mint": () => new Response(JSON.stringify({ error: "widening" }), { status: 422 }),
      "/tool-call": toolOk,
    });
    const c = client();
    await delegate({ forAgent: "child", purposes: ["p"], client: c }, async (grant) => {
      expect(grant).toBeNull();
      expect(currentCapability()).toBeNull(); // denied, not a token
      const tool = guardTool({ purpose: "p", owner: "o", client: c })(() => "x");
      expect(await tool()).toBeNull(); // denied LOCALLY
      // a nested window inside a denied window stays denied (no mint call)
      await delegate({ forAgent: "grandchild", purposes: ["p"], client: c }, async (inner) => {
        expect(inner).toBeNull();
      });
    });
    // only the failed mint reached the wire — no tool-call, no second mint
    expect(calls.map((c2) => c2.path.split("/").pop())).toEqual(["mint"]);
  });

  it("revokeOnExit=false skips revoke; revoke failure is swallowed", async () => {
    const calls = mockRoutes({
      "/capability/mint": () => new Response(JSON.stringify(GRANT), { status: 200 }),
      "/capability/revoke": () => new Response("{}", { status: 503 }),
    });
    const c = client();
    await delegate({ forAgent: "a", purposes: ["p"], revokeOnExit: false, client: c }, () => {});
    expect(calls.filter((c2) => c2.path.endsWith("/capability/revoke")).length).toBe(0);

    // revoke failure must not reject the delegate() promise
    await delegate({ forAgent: "a", purposes: ["p"], client: c }, () => {});
    expect(calls[calls.length - 1].path).toContain("/capability/revoke");
  });

  it("validation", async () => {
    await expect(delegate({ forAgent: "", purposes: ["p"] }, () => {})).rejects.toThrow(
      AegisValidationError,
    );
    await expect(delegate({ forAgent: "a", purposes: [] }, () => {})).rejects.toThrow(
      AegisValidationError,
    );
  });
});

// ── streamSession ────────────────────────────────────────────────────

function streamRoutes(
  heartbeats: Array<Record<string, unknown> | Error>,
): Record<string, Route> {
  const seq = [...heartbeats];
  return {
    "/stream/open": streamOpenOk,
    "/stream/heartbeat": () => {
      const payload = seq.length > 1 ? seq.shift()! : seq[0];
      if (payload instanceof Error) throw payload;
      return new Response(JSON.stringify(payload), { status: 200 });
    },
    "/stream/close": () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
  };
}

describe("streamSession", () => {
  it("normal lifecycle: opens, runs fn, closes witnessed", async () => {
    const calls = mockRoutes(streamRoutes([{ status: "ok" }]));
    const out = await streamSession(
      { envelope: "e" },
      async (s) => {
        expect(s.streamId).toBe("st-1");
        expect(s.decision.outcome).toBe("PROTECTED");
        expect(s.revoked).toBe(false);
        return 42;
      },
      { heartbeatIntervalMs: 20, client: client() },
    );
    expect(out).toBe(42);
    expect(calls[calls.length - 1].path).toContain("/stream/close");
    expect(calls[calls.length - 1].body).toEqual({ stream_id: "st-1" });
  });

  it("open denied: fn never runs", async () => {
    mockRoutes({
      "/stream/open": () =>
        new Response(
          JSON.stringify({ decision: DECISION_BLOCKED, enforcement: null, stream: null }),
          { status: 200 },
        ),
    });
    const fn = vi.fn();
    await expect(
      streamSession({ e: 1 }, fn, { client: client() }),
    ).rejects.toMatchObject({ code: "aegis.stream.denied" });
    expect(fn).not.toHaveBeenCalled();
  });

  it("open transport error: fail-closed denied", async () => {
    globalThis.fetch = (async () => {
      throw new Error("down");
    }) as unknown as typeof fetch;
    const fn = vi.fn();
    await expect(
      streamSession({ e: 1 }, fn, { client: client() }),
    ).rejects.toMatchObject({ code: "aegis.stream.open_failed" });
    expect(fn).not.toHaveBeenCalled();
  });

  it("revocation interrupts the in-flight agent: signal aborts, promise rejects, callback fires", async () => {
    mockRoutes(streamRoutes([{ status: "ok" }, { status: "revoked", reason: "duress_active" }]));
    const seen: string[] = [];
    let aborted = false;
    await expect(
      streamSession(
        { e: 1 },
        (s) =>
          new Promise<never>((_, reject) => {
            s.signal.addEventListener("abort", () => {
              aborted = true;
              reject(new Error("aborted"));
            });
          }),
        { heartbeatIntervalMs: 10, onRevoke: (r) => seen.push(r), client: client() },
      ),
    ).rejects.toMatchObject({ reason: "duress_active" });
    expect(seen).toEqual(["duress_active"]);
    expect(aborted).toBe(true);
  });

  it("revocation wins even when fn never observes the signal", async () => {
    mockRoutes(streamRoutes([{ status: "revoked", reason: "legal_hold" }]));
    await expect(
      streamSession(
        { e: 1 },
        () => new Promise<never>(() => {}), // agent that never yields
        { heartbeatIntervalMs: 10, client: client() },
      ),
    ).rejects.toBeInstanceOf(AegisStreamRevokedError);
  });

  it("heartbeat outage counts as revocation (gateway_unavailable)", async () => {
    mockRoutes(streamRoutes([new Error("down")]));
    await expect(
      streamSession({ e: 1 }, () => new Promise<never>(() => {}), {
        heartbeatIntervalMs: 10,
        maxHeartbeatFailures: 3,
        client: client(),
      }),
    ).rejects.toMatchObject({ reason: "gateway_unavailable" });
  });

  it("denied delegation window refuses locally (no /stream/open)", async () => {
    const calls = mockRoutes({
      "/capability/mint": () => new Response("{}", { status: 403 }),
    });
    const c = client();
    const fn = vi.fn();
    await delegate({ forAgent: "a", purposes: ["p"], client: c }, async () => {
      await expect(
        streamSession({ e: 1 }, fn, { client: c }),
      ).rejects.toMatchObject({ code: "aegis.stream.delegation_denied" });
    });
    expect(fn).not.toHaveBeenCalled();
    expect(calls.filter((c2) => c2.path.endsWith("/stream/open")).length).toBe(0);
  });

  it("attaches the delegation capability to the open envelope", async () => {
    const routes = streamRoutes([{ status: "ok" }]);
    routes["/capability/mint"] = () => new Response(JSON.stringify(GRANT), { status: 200 });
    routes["/capability/revoke"] = () =>
      new Response(JSON.stringify({ ok: true, revoked: GRANT.id }), { status: 200 });
    const calls = mockRoutes(routes);
    const c = client();
    await delegate({ forAgent: "a", purposes: ["p"], client: c }, async () => {
      await streamSession({ principal: {} }, () => "done", {
        heartbeatIntervalMs: 1000,
        client: c,
      });
    });
    const open = calls.find((c2) => c2.path.endsWith("/stream/open"));
    const envelope = open?.body.envelope as Record<string, unknown>;
    expect((envelope.delegation as Record<string, unknown>).capability).toBe("cap-token-1");
  });

  it("fn's own error (no revocation) closes the stream and propagates", async () => {
    const calls = mockRoutes(streamRoutes([{ status: "ok" }]));
    await expect(
      streamSession(
        { e: 1 },
        () => {
          throw new Error("agent bug");
        },
        { heartbeatIntervalMs: 1000, client: client() },
      ),
    ).rejects.toThrow("agent bug");
    expect(calls[calls.length - 1].path).toContain("/stream/close");
  });

  it("validation", async () => {
    await expect(streamSession({}, () => {})).rejects.toThrow(AegisValidationError);
    await expect(
      streamSession({ e: 1 }, () => {}, { heartbeatIntervalMs: 0 }),
    ).rejects.toMatchObject({ code: "aegis.stream.interval.invalid" });
  });
});
