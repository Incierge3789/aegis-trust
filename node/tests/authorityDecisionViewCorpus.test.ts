// Cross-SDK AI-native `decision` reader conformance — Node runner.
//
// Executes conformance/authority_decision_view.v0.json through the SHIPPED
// parseAuthorityDecision. The Python SDK runs the same corpus. Every invalid
// vector pins the refusal code AND a message fragment, so both SDKs name the
// same member in the same words.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { parseAuthorityDecision, type AuthorityDecisionView } from "../src/client.js";
import { AegisValidationError } from "../src/errors.js";

const corpus = JSON.parse(
  readFileSync(
    new URL("../../conformance/authority_decision_view.v0.json", import.meta.url),
    "utf8",
  ),
) as {
  version: string;
  error_code: string;
  valid: Array<{ id: string; decision: unknown; expect: Record<string, unknown>; why: string }>;
  invalid: Array<{
    id: string;
    decision: unknown;
    expect_error: string;
    expect_detail: string;
    why: string;
  }>;
};

function project(view: AuthorityDecisionView, expect: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(expect)) {
    if (key === "parts_boundaries") out[key] = view.parts.map((p) => p.boundary);
    else if (key === "parts_1_fragment_tags") out[key] = [...view.parts[1].fragment_tags];
    else out[key] = (view as unknown as Record<string, unknown>)[key];
  }
  return out;
}

describe("authority decision view corpus (shared with the Python SDK)", () => {
  it("pins the corpus version", () => {
    expect(corpus.version).toBe("v0");
    expect(corpus.valid.length).toBeGreaterThan(0);
    expect(corpus.invalid.length).toBeGreaterThan(0);
  });

  for (const v of corpus.valid) {
    it(`valid ${v.id} — ${v.why}`, () => {
      const view = parseAuthorityDecision(v.decision);
      expect(project(view, v.expect)).toEqual(v.expect);
    });
  }

  for (const v of corpus.invalid) {
    it(`invalid ${v.id} — ${v.why}`, () => {
      let thrown: unknown;
      try {
        parseAuthorityDecision(v.decision);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(AegisValidationError);
      const e = thrown as AegisValidationError;
      expect(e.code).toBe(v.expect_error);
      expect(e.code).toBe(corpus.error_code);
      expect(e.message).toContain(v.expect_detail);
    });
  }
});
