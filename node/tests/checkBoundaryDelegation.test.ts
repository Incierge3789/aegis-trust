// checkBoundary × A-1 delegation — the token reaches the wire without the
// caller carrying it.
//
// The point of this file is the FORGETTING case. A `capability` parameter the
// developer must remember to pass is fail-open by omission: the call is
// decided at full width while the enclosing delegate() window believes its
// narrowing applied. So the load-bearing assertions here are the ones nobody
// wrote a parameter for — inside a window, the body carries the token.
//
// House pattern: override globalThis.fetch, restore afterEach.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AegisClient, getModuleClient, resetModuleClient } from "../src/client.js";
import { AegisHttpError, AegisValidationError } from "../src/errors.js";
import { delegate } from "../src/aiNative.js";

const origFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = origFetch;
  vi.restoreAllMocks();
});

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

const GRANT = {
  capability: "cap-token-1",
  id: "a".repeat(32),
  exp: 4102444800,
  depth: 1,
  root_delegator: "root-sub",
};

const VIEW = {
  source: "CORE",
  outcome: "PROTECTED",
  purpose_label: "customer_support",
  allowed_fields: ["name"],
  withheld_fields: [],
  reason_code: "minimum_disclosure",
  reason_label: "Minimum disclosure",
  evidence_available: false,
};

function client(): AegisClient {
  return new AegisClient({ baseUrl: "https://localhost:8443/api/v1", token: "t" });
}

/** Record calls and route by path suffix (mirrors aiNativeInterpose.test.ts). */
function mockRoutes(
  routes: Record<string, () => Response>,
): Array<{ path: string; body: Record<string, unknown> }> {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const path = new URL(url).pathname;
    calls.push({ path, body });
    for (const [suffix, resp] of Object.entries(routes)) {
      if (path.endsWith(suffix)) return resp();
    }
    return new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
  return calls;
}

const boundaryOk = () => new Response(JSON.stringify(VIEW), { status: 200 });
const mintOk = () => new Response(JSON.stringify(GRANT), { status: 200 });
const revokeOk = () =>
  new Response(JSON.stringify({ ok: true, revoked: GRANT.id }), { status: 200 });

function boundaryBody(
  calls: Array<{ path: string; body: Record<string, unknown> }>,
): Record<string, unknown> {
  const call = calls.find((c) => c.path.endsWith("/check-boundary"));
  expect(call, "expected a /check-boundary call").toBeDefined();
  return call!.body;
}

describe("checkBoundary — automatic delegation attachment", () => {
  it("attaches the enclosing delegate() token with NO caller change", async () => {
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/capability/revoke": revokeOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      // The call site is byte-identical to pre-A-1 code: no capability arg.
      await c.checkBoundary({ purpose: "customer_support", scope: ["name"] });
    });
    expect(boundaryBody(calls).capability).toBe("cap-token-1");
  });

  it("sends NO capability outside a delegation window", async () => {
    const calls = mockRoutes({ "/check-boundary": boundaryOk });
    await client().checkBoundary({ purpose: "customer_support", scope: ["name"] });
    // Byte-identical to prior SDKs: the key is absent, not present-and-null.
    expect(boundaryBody(calls)).not.toHaveProperty("capability");
  });

  it("an explicit capability wins over the ambient window", async () => {
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/capability/revoke": revokeOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      await c.checkBoundary({
        purpose: "customer_support",
        scope: ["name"],
        capability: "cap-explicit",
      });
    });
    expect(boundaryBody(calls).capability).toBe("cap-explicit");
  });

  it("explicit null opts out of the attachment for one call", async () => {
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/capability/revoke": revokeOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      await c.checkBoundary({ purpose: "customer_support", scope: ["name"], capability: null });
    });
    expect(boundaryBody(calls)).not.toHaveProperty("capability");
  });

  it("a denied window refuses LOCALLY — it never asks at full width", async () => {
    const calls = mockRoutes({
      "/capability/mint": () => new Response(JSON.stringify({ error: "widening" }), { status: 422 }),
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "child", purposes: ["p"], client: c }, async (grant) => {
      expect(grant).toBeNull();
      const err = await c
        .checkBoundary({ purpose: "customer_support", scope: ["name"] })
        .then(() => null)
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AegisValidationError);
      expect((err as AegisValidationError).code).toBe("aegis.boundary.delegationDenied");
    });
    // The mint failed, so there is no token to narrow with. Asking anyway
    // would answer at the PARENT's full width, and Doctor hands that answer's
    // allowed_fields to the agent as authorization (checkWithCore mapView →
    // BoundaryDecision.allowedData). So the request must not leave the
    // process at all: only the failed mint reached the wire.
    expect(calls.map((c2) => c2.path.split("/").pop())).toEqual(["mint"]);
  });

  // The refusal above was scoped to "argument unset", which left the explicit
  // opt-out as a one-keystroke way past it. `capability: null` and `""` carry
  // no token, so inside a denied window they are the widening being denied,
  // not a legitimate opt-out. Cross-review (codex + cursor, 2026-07-29) found
  // this hole adjacent to the one the previous round closed; both models also
  // noted the test gap — opt-out was only ever exercised after a SUCCESSFUL
  // mint, denial only with unset or an explicit string, never the combination.
  for (const [label, cap] of [
    ["null", null],
    ["empty string", ""],
  ] as const) {
    it(`a denied window refuses even with an explicit ${label} opt-out`, async () => {
      const calls = mockRoutes({
        "/capability/mint": () =>
          new Response(JSON.stringify({ error: "widening" }), { status: 422 }),
        "/check-boundary": boundaryOk,
      });
      const c = client();
      await delegate({ forAgent: "child", purposes: ["p"], client: c }, async (grant) => {
        expect(grant).toBeNull();
        const err = await c
          .checkBoundary({ purpose: "customer_support", scope: ["name"], capability: cap })
          .then(() => null)
          .catch((e: unknown) => e);
        expect(err).toBeInstanceOf(AegisValidationError);
        expect((err as AegisValidationError).code).toBe("aegis.boundary.delegationDenied");
      });
      // Same oracle as the unset case: nothing but the failed mint may reach
      // the wire. If /check-boundary appears here, the opt-out asked at the
      // parent's full width.
      expect(calls.map((c2) => c2.path.split("/").pop())).toEqual(["mint"]);
    });
  }

  it("an explicit null opt-out is still honoured in a GRANTED window", async () => {
    // The fix must not turn opt-out into a no-op. Outside denial, `null` still
    // means "ask this one question without attaching the ambient token".
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "child", purposes: ["p"], client: c }, async (grant) => {
      expect(grant).not.toBeNull();
      await c.checkBoundary({ purpose: "customer_support", scope: ["name"], capability: null });
    });
    const boundary = calls.find((c2) => c2.path.endsWith("/check-boundary"));
    expect(boundary).toBeDefined();
    expect(boundary?.body).not.toHaveProperty("capability");
  });

  it("delegate WITHOUT an explicit client still mints and attaches", async () => {
    // Python twin. There the origin was first read off the `client` ARGUMENT,
    // which is None on the module-client path — AttributeError, swallowed by
    // the mint block's except, every default window silently DENIED. Node
    // resolves the client before writing the store so it was never exposed,
    // but the pin belongs on both sides: this is the path every quickstart
    // uses, and it had no test in either SDK (cross-review, cursor 2026-07-29).
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/check-boundary": boundaryOk,
    });
    const prevUrl = process.env.AEGIS_BASE_URL;
    process.env.AEGIS_BASE_URL = "https://localhost:8443/api/v1";
    resetModuleClient();
    try {
      const c = getModuleClient();
      await delegate({ forAgent: "child", purposes: ["p"] }, async (grant) => {
        expect(grant, "default-client window was denied").not.toBeNull();
        await c.checkBoundary({ purpose: "customer_support", scope: ["name"] });
      });
    } finally {
      if (prevUrl === undefined) delete process.env.AEGIS_BASE_URL;
      else process.env.AEGIS_BASE_URL = prevUrl;
      resetModuleClient();
    }
    const boundary = calls.find((c2) => c2.path.endsWith("/check-boundary"));
    expect(boundary?.body).toHaveProperty("capability");
  });

  it("the ambient token does NOT attach to a DIFFERENT client in the window", async () => {
    // The store used to hold a bare bearer string, so any client constructed
    // inside the window picked it up — including one pointed at a different
    // base URL. That ships a capability minted for one boundary to another.
    // Found by cross-review (codex, 2026-07-29, severity high) on the merged
    // change; the store now carries the minting origin and the send path
    // refuses a mismatch locally.
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/check-boundary": boundaryOk,
    });
    const minting = client();
    const other = new AegisClient({ baseUrl: "https://other.invalid/api/v1", verifySsl: false });
    await delegate({ forAgent: "child", purposes: ["p"], client: minting }, async (grant) => {
      expect(grant).not.toBeNull();
      await other.checkBoundary({ purpose: "customer_support", scope: ["name"] });
    });
    const boundary = calls.find((c) => c.path.endsWith("/check-boundary"));
    expect(boundary).toBeDefined();
    expect(boundary?.body).not.toHaveProperty("capability");
  });

  it("the ambient token DOES attach to the minting client", async () => {
    // Non-vacuity for the test above: if binding were simply always-refuse,
    // the negative test would pass while auto-attach was dead.
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "child", purposes: ["p"], client: c }, async () => {
      await c.checkBoundary({ purpose: "customer_support", scope: ["name"] });
    });
    const boundary = calls.find((c2) => c2.path.endsWith("/check-boundary"));
    expect(boundary?.body).toHaveProperty("capability");
  });

  it("an EXPLICIT capability still works inside a denied window", async () => {
    // The refusal is about the ambient path (nothing to attach). A caller
    // carrying a token across a process boundary by hand is not guessing.
    const calls = mockRoutes({
      "/capability/mint": () => new Response(JSON.stringify({ error: "widening" }), { status: 422 }),
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "child", purposes: ["p"], client: c }, async () => {
      await c.checkBoundary({
        purpose: "customer_support",
        scope: ["name"],
        capability: "cap-carried",
      });
    });
    expect(boundaryBody(calls).capability).toBe("cap-carried");
  });
});

describe("checkBoundary — async boundaries", () => {
  it("captures the token at CALL time, not at await time", async () => {
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/capability/revoke": revokeOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    let pending: Promise<unknown> | null = null;
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      // Started inside the window, settled after it closes. The async prefix
      // of checkBoundary runs synchronously here, so the token is captured
      // before the AsyncLocalStorage scope unwinds.
      pending = c.checkBoundary({ purpose: "customer_support", scope: ["name"] });
    });
    await pending;
    expect(boundaryBody(calls).capability).toBe("cap-token-1");
  });

  it("concurrent windows do not cross-contaminate", async () => {
    let mints = 0;
    const calls = mockRoutes({
      "/capability/mint": () => {
        mints += 1;
        return new Response(
          JSON.stringify({ ...GRANT, capability: `cap-${mints}` }),
          { status: 200 },
        );
      },
      "/capability/revoke": revokeOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    const run = (purpose: string) =>
      delegate({ forAgent: purpose, purposes: [purpose], client: c }, async () => {
        await new Promise((r) => setTimeout(r, 5)); // interleave the two windows
        await c.checkBoundary({ purpose, scope: ["name"] });
      });
    await Promise.all([run("alpha"), run("beta")]);

    // Each window's boundary call must carry ITS OWN token. A shared mutable
    // store would give both the last-minted one.
    const boundaryCalls = calls.filter((x) => x.path.endsWith("/check-boundary"));
    expect(boundaryCalls).toHaveLength(2);
    const pairs = boundaryCalls.map((x) => [x.body.purpose, x.body.capability]);
    const mintOrder = calls
      .filter((x) => x.path.endsWith("/capability/mint"))
      .map((x) => x.body.for_agent);
    for (const [purpose, capability] of pairs) {
      expect(capability).toBe(`cap-${mintOrder.indexOf(purpose as string) + 1}`);
    }
  });

  it("the token does not leak to a call made after the window closed", async () => {
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/capability/revoke": revokeOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      await c.checkBoundary({ purpose: "inside", scope: ["name"] });
    });
    await c.checkBoundary({ purpose: "outside", scope: ["name"] });

    const boundaryCalls = calls.filter((x) => x.path.endsWith("/check-boundary"));
    expect(boundaryCalls[0].body.capability).toBe("cap-token-1");
    expect(boundaryCalls[1].body).not.toHaveProperty("capability");
  });
});

describe("checkBoundary — wire shape (flat face, not the envelope dialect)", () => {
  it("never nests the token under `delegation` (the plane 422s that shape)", async () => {
    const calls = mockRoutes({
      "/capability/mint": mintOk,
      "/capability/revoke": revokeOk,
      "/check-boundary": boundaryOk,
    });
    const c = client();
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      await c.checkBoundary({ purpose: "customer_support", scope: ["name"] });
    });
    const body = boundaryBody(calls);
    // aegis-decide-plane compat.rs decide_flat refuses a nested `delegation`
    // outright, precisely so a wrong-shape token is never dropped silently
    // and answered at full width. Sending the flat key is the contract.
    expect(body).not.toHaveProperty("delegation");
    expect(body.capability).toBe("cap-token-1");
  });
});

describe("checkBoundary — 501 delegation refusal is named, not generic", () => {
  const refuse = () =>
    new Response(JSON.stringify({ error: "this surface does not evaluate delegated capabilities" }), {
      status: 501,
    });

  it("maps a 501-with-capability to aegis.boundary.delegationUnsupported", async () => {
    mockRoutes({ "/capability/mint": mintOk, "/capability/revoke": revokeOk, "/check-boundary": refuse });
    const c = client();
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      const err = await c
        .checkBoundary({ purpose: "customer_support", scope: ["name"] })
        .then(() => null)
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AegisHttpError);
      expect((err as AegisHttpError).code).toBe("aegis.boundary.delegationUnsupported");
      expect((err as AegisHttpError).status).toBe(501);
      // The remediation must name the DEPLOYMENT — an operator reading
      // "retry if 5xx" would wait out a condition that never clears.
      expect((err as AegisHttpError).remediation).toContain("decide-plane");
    });
  });

  it("still throws (fail-closed) — a refusal is never a soft allow", async () => {
    mockRoutes({ "/capability/mint": mintOk, "/capability/revoke": revokeOk, "/check-boundary": refuse });
    const c = client();
    await delegate({ forAgent: "researcher", purposes: ["customer_support"], client: c }, async () => {
      await expect(c.checkBoundary({ purpose: "customer_support", scope: ["name"] })).rejects.toThrow();
    });
  });

  it("a 501 WITHOUT a capability stays the generic non-2xx envelope", async () => {
    mockRoutes({ "/check-boundary": refuse });
    const err = await client()
      .checkBoundary({ purpose: "customer_support", scope: ["name"] })
      .then(() => null)
      .catch((e: unknown) => e);
    expect((err as AegisHttpError).code).toBe("aegis.http.nonOk");
  });
});
