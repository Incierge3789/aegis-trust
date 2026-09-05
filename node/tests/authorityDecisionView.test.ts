// AI-native `decision` reader — behaviour beyond the shared corpus.
//
// The corpus runner pins shape acceptance and refusal. This file pins how the
// reader sits in the client: it reads the `decision` member of a real
// toolCall / streamOpen body, the view is decoupled from the input, and the
// flat checkBoundary view is NOT where these members live.

import { afterEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  AegisClient,
  AUTHORITY_OUTCOMES,
  parseAuthorityDecision,
  type BoundaryDecisionView,
} from "../src/index.js";

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

function fullDecision(): Record<string, unknown> {
  const corpus = JSON.parse(
    readFileSync(
      new URL("../../conformance/authority_decision_view.v0.json", import.meta.url),
      "utf8",
    ),
  ) as { valid: Array<{ decision: Record<string, unknown> }> };
  return JSON.parse(JSON.stringify(corpus.valid[0].decision)) as Record<string, unknown>;
}

describe("parseAuthorityDecision in the client", () => {
  it("reads the decision member of a toolCall body", async () => {
    const decision = fullDecision();
    mockFetch(async () =>
      new Response(JSON.stringify({ decision, enforcement: null }), { status: 200 }),
    );
    const body = await client().toolCall({
      tool: "query_business_data",
      purpose: "customer_data",
      owner: "acme",
    });
    const view = parseAuthorityDecision(body.decision);
    expect([...view.fragment_tags]).toEqual(["pii:contact", "sensitive:Finance"]);
    expect(view.parts.map((p) => p.boundary)).toEqual(["purpose", "data"]);
    expect(view.decision_id).toBe("hashchain:0000042");
    expect(view.ledgered).toBe(true);
    expect(AegisClient.PASSING_OUTCOMES).toContain(view.outcome);
  });

  it("reads the decision member of a streamOpen body", async () => {
    const decision = fullDecision();
    mockFetch(async () =>
      new Response(
        JSON.stringify({
          decision,
          enforcement: null,
          stream: { stream_id: decision.decision_id, status: "open" },
        }),
        { status: 200 },
      ),
    );
    const body = await client().streamOpen({ purpose: "customer_data" });
    const view = parseAuthorityDecision(body.decision);
    expect(view.receipt_event_id).toBe("hashchain:0000043");
    expect([...view.parts[1].withheld_fields]).toEqual(["email"]);
  });

  it("is decoupled from the input object", () => {
    const decision = fullDecision();
    const view = parseAuthorityDecision(decision);
    (decision.fragment_tags as string[]).push("injected:later");
    ((decision.parts as Array<Record<string, unknown>>)[1].fragment_tags as string[]).length = 0;
    (decision.allowed_fields as string[]).push("email");
    expect([...view.fragment_tags]).toEqual(["pii:contact", "sensitive:Finance"]);
    expect([...view.parts[1].fragment_tags]).toEqual(["pii:contact", "sensitive:Finance"]);
    expect([...view.allowed_fields]).toEqual(["name", "company"]);
  });

  it("is deep-frozen (readonly is only a compile-time promise)", () => {
    const view = parseAuthorityDecision(fullDecision());
    expect(Object.isFrozen(view)).toBe(true);
    expect(Object.isFrozen(view.fragment_tags)).toBe(true);
    expect(Object.isFrozen(view.parts)).toBe(true);
    expect(Object.isFrozen(view.parts[1])).toBe(true);
    expect(Object.isFrozen(view.parts[1].fragment_tags)).toBe(true);
    expect(() => (view.fragment_tags as string[]).push("injected:later")).toThrow();
  });

  it("validates outcomes against a private copy, so the export cannot widen the vocabulary", () => {
    expect(Object.isFrozen(AUTHORITY_OUTCOMES)).toBe(true);
    expect(() => (AUTHORITY_OUTCOMES as string[]).push("UNKNOWN")).toThrow();
    const decision = { ...fullDecision(), outcome: "UNKNOWN" };
    expect(() => parseAuthorityDecision(decision)).toThrow(/'outcome' missing or unknown/);
  });

  it("policy_generation: 3.0 is 3, unsafe integers are refused", () => {
    const base = fullDecision();
    expect(parseAuthorityDecision({ ...base, policy_generation: 3.0 }).policy_generation).toBe(3);
    for (const bad of [2 ** 53, Number.NaN, Number.POSITIVE_INFINITY, 3.5, -1, true]) {
      expect(() => parseAuthorityDecision({ ...base, policy_generation: bad })).toThrow(
        /policy_generation/,
      );
    }
  });

  it("refuses sparse arrays (holes are not strings, not partials)", () => {
    const base = fullDecision();
    // `every()` skips holes; the reader must not.
    expect(() =>
      parseAuthorityDecision({ ...base, allowed_fields: new Array(1) }),
    ).toThrow(/'allowed_fields' missing or not a list of strings/);
    expect(() =>
      parseAuthorityDecision({ ...base, fragment_tags: new Array(1) }),
    ).toThrow(/'fragment_tags' missing or not a list of strings/);
    expect(() => parseAuthorityDecision({ ...base, parts: new Array(1) })).toThrow(
      /'parts\[0\]' is not an object/,
    );
  });

  it("does not read array holes from a polluted Array.prototype", () => {
    const base = fullDecision();
    const proto = Array.prototype as unknown as Record<number, unknown>;
    proto[0] = "pii:inherited";
    try {
      expect(() =>
        parseAuthorityDecision({ ...base, fragment_tags: new Array(1) }),
      ).toThrow(/'fragment_tags' missing or not a list of strings/);
      expect(() => parseAuthorityDecision({ ...base, parts: new Array(1) })).toThrow(
        /'parts\[0\]' is not an object/,
      );
    } finally {
      delete proto[0];
    }
  });

  it("does not read outcome / ledgered from the prototype chain", () => {
    const decision = fullDecision();
    delete decision.ledgered;
    const polluted = Object.create({ ledgered: true }) as Record<string, unknown>;
    Object.assign(polluted, decision);
    expect(() => parseAuthorityDecision(polluted)).toThrow(/'ledgered' missing/);
  });

  it("shares the outcome vocabulary with the gate", () => {
    expect([...AUTHORITY_OUTCOMES]).toEqual([
      "PROTECTED",
      "ACCESS_REDUCED",
      "CHECK_REQUIRED",
      "APPROVAL_REQUIRED",
      "BLOCKED",
    ]);
    for (const o of AegisClient.PASSING_OUTCOMES) expect(AUTHORITY_OUTCOMES).toContain(o);
  });

  it("the flat checkBoundary view does not pretend to carry these members", () => {
    // Compile-time pin: BoundaryDecisionView has no fragment_tags / parts key.
    // (The flat wire never sends them; a field the wire never fills would be a
    // claim without a source.) ledgered / decision_id ARE there under their
    // flat names.
    type FlatKeys = keyof BoundaryDecisionView;
    const notFlat: Exclude<"fragment_tags" | "parts", FlatKeys>[] = ["fragment_tags", "parts"];
    const flat: FlatKeys[] = ["evidence_available", "evidence"];
    expect(notFlat.length + flat.length).toBe(4);
  });
});
