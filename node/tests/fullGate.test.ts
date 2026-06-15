// fullGate.test.ts — T-SDK-FULL-GATE-01 acceptance tests.
//
// Verifies that shield() FULL mode performs a real pre-call /check-access
// authorization before the protected function runs, and fails closed on
// every non-grant path. Tests 1-8 are the corrective-PR directive set;
// tests 9-11 verify the gate runs BEFORE fn execution (Codex cross-review
// P1) — a denied / unreachable authorization must prevent the protected
// function's side effects, not merely discard its result.

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { AegisValidationError, Mode, resetModuleClient, shield } from "../src/index.js";

const origFetch = globalThis.fetch;

beforeEach(() => {
  resetModuleClient();
});
afterEach(() => {
  globalThis.fetch = origFetch;
  resetModuleClient();
  delete process.env.AEGIS_TOKEN;
  delete process.env.AEGIS_MODE;
  delete process.env.AEGIS_BASE_URL;
});

/** Configurable fetch mock. `checkAccess` controls the /check-access reply. */
function mkFetch(opts: {
  checkAccess?: { status: number; body?: unknown } | "throw";
  health?: number;
}): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const impl: typeof fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith("/health")) {
      return new Response("ok", { status: opts.health ?? 200 });
    }
    if (url.includes("/check-access")) {
      if (opts.checkAccess === "throw") throw new Error("network down");
      const ca = opts.checkAccess ?? { status: 200, body: { allowed: true } };
      return new Response(
        ca.body !== undefined ? JSON.stringify(ca.body) : "",
        { status: ca.status },
      );
    }
    if (url.includes("/shield/ingest")) {
      return new Response(
        JSON.stringify({ data: { ingested: 1, audit_seq_start: 1, audit_seq_end: 1 } }),
        { status: 200 },
      );
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { fetch: impl, calls };
}

function fullEnv(): void {
  process.env.AEGIS_TOKEN = "test-token";
  process.env.AEGIS_BASE_URL = "https://localhost:8443/api/v1";
}

// 1 ──────────────────────────────────────────────────────────
it("FULL calls /check-access before returning data", async () => {
  const m = mkFetch({ checkAccess: { status: 200, body: { allowed: true } } });
  globalThis.fetch = m.fetch;
  fullEnv();

  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => ({ name: "A", ssn: "X" }),
  );
  const out = await getUser(1);

  // /check-access was invoked, and the resolved value is the filtered result —
  // the await on authorize necessarily completed before the return.
  expect(m.calls.some((u) => u.includes("/check-access"))).toBe(true);
  expect(out).toEqual({ name: "A" });
});

// 2 ──────────────────────────────────────────────────────────
it("FULL deny (200 allowed:false) returns the safe empty value", async () => {
  const m = mkFetch({ checkAccess: { status: 200, body: { allowed: false } } });
  globalThis.fetch = m.fetch;
  fullEnv();

  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => ({ name: "A", ssn: "X" }),
  );
  const out = await getUser(1);

  // The gate denies BEFORE the protected function runs — there is no
  // return shape to mirror, so the safe value is a bare null. Never the
  // raw data.
  expect(out).toBeNull();
});

// 3 ──────────────────────────────────────────────────────────
it("FULL gateway-unreachable fails closed (returns empty)", async () => {
  const m = mkFetch({ checkAccess: "throw" });
  globalThis.fetch = m.fetch;
  fullEnv();

  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => ({ name: "A", ssn: "X" }),
  );
  const out = await getUser(1);

  expect(out).toBeNull(); // network error → fail-closed, fn never ran
});

// 4 ──────────────────────────────────────────────────────────
it("FULL core 503 (audit-fail-closed) returns empty", async () => {
  const m = mkFetch({ checkAccess: { status: 503 } });
  globalThis.fetch = m.fetch;
  fullEnv();

  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => ({ name: "A", ssn: "X" }),
  );
  const out = await getUser(1);

  expect(out).toBeNull(); // CSR-02 503 → fail-closed, fn never ran
});

// 5 ──────────────────────────────────────────────────────────
it("LITE remains local filter only — never calls the gateway", async () => {
  const m = mkFetch({});
  globalThis.fetch = m.fetch;
  fullEnv(); // token IS set — LITE must still not call out

  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.LITE })(
    async (_: unknown) => ({ name: "A", ssn: "X" }),
  );
  const out = await getUser(1);

  expect(m.calls).toHaveLength(0); // zero network calls
  expect(out).toEqual({ name: "A" }); // local filter still applied
});

// 6 ──────────────────────────────────────────────────────────
describe("AUTO routes explicitly", () => {
  it("AUTO + token + reachable → FULL (calls /check-access)", async () => {
    const m = mkFetch({ checkAccess: { status: 200, body: { allowed: true } } });
    globalThis.fetch = m.fetch;
    fullEnv();

    const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.AUTO })(
      async (_: unknown) => ({ name: "A", ssn: "X" }),
    );
    const out = await getUser(1);

    expect(m.calls.some((u) => u.includes("/check-access"))).toBe(true);
    expect(out).toEqual({ name: "A" });
  });

  it("AUTO + no token → LITE (never calls the gateway)", async () => {
    const m = mkFetch({});
    globalThis.fetch = m.fetch;
    // no AEGIS_TOKEN

    const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.AUTO })(
      async (_: unknown) => ({ name: "A", ssn: "X" }),
    );
    const out = await getUser(1);

    expect(m.calls.some((u) => u.includes("/check-access"))).toBe(false);
    expect(out).toEqual({ name: "A" });
  });
});

// 7 ──────────────────────────────────────────────────────────
it("sync function + explicit Mode.FULL throws AegisValidationError", () => {
  fullEnv();
  const getUserSync = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    (_: unknown) => ({ name: "A", ssn: "X" }), // synchronous
  );
  let thrown: unknown;
  try {
    getUserSync(1);
  } catch (e) {
    thrown = e;
  }
  expect(thrown).toBeInstanceOf(AegisValidationError);
  expect((thrown as AegisValidationError).code).toBe(
    "aegis.shield.mode.sync_full_unsupported",
  );
});

// 8 ──────────────────────────────────────────────────────────
it("internal filter error returns the safe empty value, not an exception", async () => {
  const m = mkFetch({});
  globalThis.fetch = m.fetch;

  // An object whose property getter throws — exercises the freeze/filter
  // fail-closed try/catch.
  const evil: Record<string, unknown> = {};
  Object.defineProperty(evil, "name", {
    enumerable: true,
    get() {
      throw new Error("boom");
    },
  });

  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.LITE })(
    async (_: unknown) => evil,
  );

  let out: unknown;
  let threw = false;
  try {
    out = await getUser(1);
  } catch {
    threw = true;
  }
  expect(threw).toBe(false); // no exception bubbles to the caller
  expect(out).toEqual({}); // safe empty, never the raw evil object
});

// 9 ──────────────────────────────────────────────────────────
it("FULL deny does NOT invoke the protected function (no side effects)", async () => {
  // The trust gate must run BEFORE the protected function. A denied
  // authorization must prevent the function — and its side effects /
  // DB reads — from executing at all, not merely discard the result.
  const m = mkFetch({ checkAccess: { status: 200, body: { allowed: false } } });
  globalThis.fetch = m.fetch;
  fullEnv();

  let calls = 0;
  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => {
      calls += 1; // side effect — must NOT happen when authorization is denied
      return { name: "A", ssn: "X" };
    },
  );
  const out = await getUser(1);

  expect(calls).toBe(0); // gate denied → protected function never ran
  expect(out).toBeNull();
});

// 10 ─────────────────────────────────────────────────────────
it("FULL unreachable does NOT invoke the protected function", async () => {
  // Same invariant on the fail-closed path: a network error must keep the
  // protected function from running, not run it and drop the output.
  const m = mkFetch({ checkAccess: "throw" });
  globalThis.fetch = m.fetch;
  fullEnv();

  let calls = 0;
  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => {
      calls += 1;
      return { name: "A", ssn: "X" };
    },
  );
  const out = await getUser(1);

  expect(calls).toBe(0); // gateway unreachable → protected function never ran
  expect(out).toBeNull();
});

// 11 ─────────────────────────────────────────────────────────
it("FULL grant invokes the protected function exactly once", async () => {
  const m = mkFetch({ checkAccess: { status: 200, body: { allowed: true } } });
  globalThis.fetch = m.fetch;
  fullEnv();

  let calls = 0;
  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => {
      calls += 1;
      return { name: "A", ssn: "X" };
    },
  );
  const out = await getUser(1);

  expect(calls).toBe(1); // authorized → function ran once, after the gate
  expect(out).toEqual({ name: "A" });
});

// S017 H10 ─────────────────────────────────────────────────────
it("FULL fails closed when ingest reports partial acceptance (ingested<sent)", async () => {
  // Contract-valid 200, but the gateway durably committed ZERO of the entries
  // sent: the audit record never landed. FULL is audit-before-release, so the
  // filtered data must NOT be released. Previously `ingested >= 0` parsed as
  // success and the data was released = fail-OPEN on audit completeness.
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/health")) return new Response("ok", { status: 200 });
    if (url.includes("/check-access")) {
      return new Response(JSON.stringify({ allowed: true }), { status: 200 });
    }
    if (url.includes("/shield/ingest")) {
      return new Response(
        JSON.stringify({ data: { ingested: 0, audit_seq_start: 0, audit_seq_end: 0 } }),
        { status: 200 },
      );
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  fullEnv();

  const getUser = shield({ purpose: "support", scope: ["name"], mode: Mode.FULL })(
    async (_: unknown) => ({ name: "A", ssn: "X" }),
  );
  const out = await getUser(1);

  // Audit incomplete → data withheld → type-shaped empty mirroring the dict.
  expect(out).toEqual({});
});
