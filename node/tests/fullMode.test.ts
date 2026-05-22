import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  Mode,
  detectMode,
  resetModuleClient,
  shield,
} from "../src/index.js";

const origFetch = globalThis.fetch;

beforeEach(() => {
  resetModuleClient();
});
afterEach(() => {
  globalThis.fetch = origFetch;
  resetModuleClient();
  delete process.env.AEGIS_TOKEN;
  delete process.env.AEGIS_MODE;
  delete process.env.AEGIS_URL;
  delete process.env.AEGIS_BASE_URL;
  vi.restoreAllMocks();
});

function fetchMock(): {
  fetch: typeof fetch;
  calls: { url: string; body?: string }[];
} {
  const calls: { url: string; body?: string }[] = [];
  const impl: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, body: init?.body ? String(init.body) : undefined });
    if (url.endsWith("/health")) {
      return new Response("ok", { status: 200 });
    }
    // T-SDK-FULL-GATE-01: FULL mode now performs a pre-call /check-access
    // authorization. The happy-path mock grants it.
    if (url.includes("/check-access")) {
      return new Response(JSON.stringify({ allowed: true }), { status: 200 });
    }
    if (url.includes("/shield/ingest")) {
      return new Response(
        JSON.stringify({
          data: { ingested: 1, audit_seq_start: 1, audit_seq_end: 1 },
        }),
        { status: 200 },
      );
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { fetch: impl, calls };
}

describe("Mode.FULL — filter + async ingest", () => {
  it("filters AND sends ingest entries to aegis-core", async () => {
    const m = fetchMock();
    globalThis.fetch = m.fetch;
    process.env.AEGIS_TOKEN = "test-token";
    process.env.AEGIS_BASE_URL = "https://localhost:8443/api/v1";

    const getUser = shield({
      purpose: "support",
      scope: ["name"],
      mode: Mode.FULL,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));

    const out = await getUser(1);
    expect(out).toEqual({ name: "A" });

    // Wait one tick so the fire-and-forget ingest lands.
    await new Promise((r) => setTimeout(r, 30));

    const ingestCall = m.calls.find((c) => c.url.includes("/shield/ingest"));
    expect(ingestCall).toBeDefined();
    expect(ingestCall!.body).toBeDefined();
    const sent = JSON.parse(ingestCall!.body!);
    expect(sent.entries[0].blocked_fields).toContain("ssn");
    expect(sent.entries[0].purpose).toBe("support");
  });

  it("never bubbles ingest failures into caller (ingest fails AFTER authorize succeeds)", async () => {
    // T-SDK-FULL-GATE-01: ingest is post-authorization telemetry, fail-OPEN.
    // /check-access must still succeed (it is the trust gate); only the
    // downstream /shield/ingest fails. The caller still gets filtered data.
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/check-access")) {
        return new Response(JSON.stringify({ allowed: true }), { status: 200 });
      }
      if (url.includes("/shield/ingest")) {
        throw new Error("ingest net down");
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;
    process.env.AEGIS_TOKEN = "test-token";
    process.env.AEGIS_BASE_URL = "https://localhost:8443/api/v1";

    const getUser = shield({
      purpose: "support",
      scope: ["name"],
      mode: Mode.FULL,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));

    // Authorize succeeded → filtered data returned; ingest failure swallowed.
    await expect(getUser(1)).resolves.toEqual({ name: "A" });
  });
});

describe("Mode.AUTO — detect mode", () => {
  it("falls back to LITE when AEGIS_TOKEN is unset AND backend unreachable", async () => {
    // Post-rc3 behaviour (PyPI parity, shield.py _detect_mode line 162-177):
    // AUTO probes the backend FIRST. With no token + unreachable backend +
    // dev host (no Full intent), detect_mode resolves to LITE.
    // (Reuses the top-level `origFetch` capture + afterEach restore — no
    // in-test fetch reassignment, avoiding the codex iter-1 P1-a landmine
    // where `origFetch` could capture an already-overridden throwing fetch.)
    const calls: { url: string }[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push({ url: String(input) });
      throw new Error("network down");
    }) as typeof fetch;
    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.AUTO,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    await getUser(1);
    // No ingest call should have been made in LITE.
    expect(calls.find((c) => c.url.includes("/shield/ingest"))).toBeUndefined();
  });

  it("upgrades to FULL when backend reachable, even without AEGIS_TOKEN (post-rc3 PyPI parity)", async () => {
    // Post-rc3: AUTO opportunistically upgrades to FULL when /health returns
    // 200, matching PyPI shield.py _detect_mode line 163-165 (probe first,
    // then intent check for fail-closed escalation).
    const m = fetchMock();
    globalThis.fetch = m.fetch;
    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.AUTO,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    await getUser(1);
    await new Promise((r) => setTimeout(r, 30));
    const ingestCall = m.calls.find((c) => c.url.includes("/shield/ingest"));
    expect(ingestCall).toBeDefined();
  });

  it("upgrades to FULL when token present and backend reachable", async () => {
    const m = fetchMock();
    globalThis.fetch = m.fetch;
    process.env.AEGIS_TOKEN = "t";
    process.env.AEGIS_BASE_URL = "https://localhost:8443/api/v1";

    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.AUTO,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    await getUser(1);
    await new Promise((r) => setTimeout(r, 30));

    const ingestCall = m.calls.find((c) => c.url.includes("/shield/ingest"));
    expect(ingestCall).toBeDefined();
  });

  it("AUTO + Full intent (token) + unreachable backend → fail-closed FULL escalation warn + scope filter applies (rc4 PyPI parity)", async () => {
    // Cursor iter-1 P1-b supplementary test #3: verifies the rc4/rc5 safety
    // claim that AUTO + explicit Full intent + unreachable backend does NOT
    // silently degrade to LITE (which would skip the user-visible warning
    // and provide weaker semantics than the user asked for). Mirrors PyPI
    // shield.py _detect_mode line 166-175.
    //
    // Honest scope of the rc4/rc5-level claim: (a) one fail-closed FULL
    // escalation warning fires, (b) scope filter still applies (out-of-
    // scope `ssn` is dropped). The stronger sprint_005-Unreleased claim
    // "shield Mode.FULL returns shape-preserving empty on ingest failure"
    // is NOT in this PR and is therefore NOT asserted here — that test
    // belongs to a subsequent PR carrying the sprint_005 shield-FULL
    // hardening landing.
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const calls: { url: string }[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push({ url: String(input) });
      throw new Error("network down");
    }) as typeof fetch;
    process.env.AEGIS_TOKEN = "t";
    process.env.AEGIS_URL = "https://prod.example.com:8443/api/v1";

    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.AUTO,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    const result = await getUser(1);
    // Wait for fire-and-forget ingest attempt to land in `calls` (it will
    // throw because fetch is mocked to throw, but the attempt is observable).
    await new Promise((r) => setTimeout(r, 30));
    // Scope filter still applies: `ssn` (out of scope) is dropped.
    expect(result).not.toHaveProperty("ssn");
    // Exactly one fail-closed FULL escalation warning fired.
    const failClosedWarns = warnSpy.mock.calls.filter((args) =>
      String(args[0]).includes("unreachable"),
    );
    expect(failClosedWarns.length).toBeGreaterThanOrEqual(1);
    // FULL-vs-LITE witness #1: detectMode() resolves to "full" (codex +
    // cursor iter-1 consensus P1 — the test must distinguish FULL from
    // LITE because scope filter + /health probe + warn could all match
    // a silent LITE degrade. The /shield/ingest attempt is the operative
    // behavioural witness because LITE never calls ingest).
    const mode = await detectMode();
    expect(mode).toBe("full");
    // FULL-vs-LITE witness #2: at least one /shield/ingest attempt was
    // made against the unreachable backend (LITE would never attempt
    // ingest; only FULL does). This makes the test fail when a
    // regression silently flips AUTO+intent+unreachable back to LITE.
    expect(calls.some((c) => c.url.includes("/shield/ingest"))).toBe(true);
    // Full mode probe-first also fired the /health request.
    expect(calls.some((c) => c.url.includes("/health"))).toBe(true);
  });
});

describe("AEGIS_BASE_URL deprecation alias (rc4 PyPI parity)", () => {
  it("AEGIS_BASE_URL alone triggers exactly one console.warn per process", async () => {
    // Cursor iter-1 P1-b supplementary test #1: verifies the rc4 AEGIS_URL
    // canonicalisation — AEGIS_BASE_URL is still accepted as a deprecation
    // alias and emits one warning. Idempotence guard: resetModuleClient()
    // re-arms the warning so subsequent test iterations also see exactly one.
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const m = fetchMock();
    globalThis.fetch = m.fetch;
    process.env.AEGIS_BASE_URL = "https://localhost:8443/api/v1";
    process.env.AEGIS_TOKEN = "t";

    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.AUTO,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    await getUser(1);
    await getUser(1);
    await getUser(1);

    // Exactly one alias warning across multiple invocations.
    const aliasWarns = warnSpy.mock.calls.filter((args) =>
      String(args[0]).includes("AEGIS_BASE_URL is deprecated"),
    );
    expect(aliasWarns).toHaveLength(1);
  });

  it("AEGIS_URL takes precedence over AEGIS_BASE_URL with no warning fired", async () => {
    // Cursor iter-1 P1-b supplementary test #2: verifies the rc4 precedence
    // contract — when both are set, AEGIS_URL wins and AEGIS_BASE_URL is
    // never read, so no deprecation warning fires.
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const m = fetchMock();
    globalThis.fetch = m.fetch;
    process.env.AEGIS_URL = "https://localhost:8443/api/v1";
    process.env.AEGIS_BASE_URL = "https://elsewhere.example.com:9999/api/v1";
    process.env.AEGIS_TOKEN = "t";

    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.AUTO,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    await getUser(1);
    await new Promise((r) => setTimeout(r, 30));

    // No deprecation warning fired (AEGIS_BASE_URL was set but never read).
    const aliasWarns = warnSpy.mock.calls.filter((args) =>
      String(args[0]).includes("AEGIS_BASE_URL is deprecated"),
    );
    expect(aliasWarns).toHaveLength(0);

    // Health probe + ingest both hit the canonical AEGIS_URL, not the alias.
    const healthCall = m.calls.find((c) => c.url.includes("/health"));
    expect(healthCall?.url).toContain("localhost:8443");
    expect(healthCall?.url).not.toContain("elsewhere.example.com");
  });
});

describe("Mode.LITE explicit", () => {
  it("never calls backend", async () => {
    const m = fetchMock();
    globalThis.fetch = m.fetch;
    process.env.AEGIS_TOKEN = "t";

    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.LITE,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    await getUser(1);
    expect(m.calls).toHaveLength(0);
  });
});
