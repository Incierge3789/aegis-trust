import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  Mode,
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
  delete process.env.AEGIS_BASE_URL;
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
  it("falls back to LITE when AEGIS_TOKEN is unset", async () => {
    const m = fetchMock();
    globalThis.fetch = m.fetch;
    const getUser = shield({
      purpose: "p",
      scope: ["name"],
      mode: Mode.AUTO,
    })(async (_: unknown) => ({ name: "A", ssn: "X" }));
    await getUser(1);
    // No ingest call should have been made in LITE.
    expect(m.calls.find((c) => c.url.includes("/shield/ingest"))).toBeUndefined();
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
