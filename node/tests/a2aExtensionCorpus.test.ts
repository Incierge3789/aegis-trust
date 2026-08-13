// Cross-SDK A2A extension surface conformance — Node runner.
//
// Executes conformance/a2a_extension.v0.json through the SHIPPED negotiation,
// honesty guard, placeholder guard, and metadata placement. The Python SDK runs
// the same corpus through its shipped equivalents.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  A2AExtensionError,
  AEGIS_A2A_EXTENSION_URI_V0,
  assertNoEnforcementClaim,
  buildAgentCardExtension,
  isPlaceholderExtensionUri,
  negotiateExtensions,
  placeDecisionMetadata,
} from "../src/a2a/extension.js";
import { AegisError } from "../src/errors.js";

const corpus = JSON.parse(
  readFileSync(new URL("../../conformance/a2a_extension.v0.json", import.meta.url), "utf8"),
) as {
  version: string;
  extension_uri: string;
  negotiation: Array<{
    id: string;
    header: string | null;
    expect: {
      activated: boolean;
      reason?: string;
      requested: string[];
      echo: string[];
    };
    why: string;
  }>;
  honesty: Array<{
    id: string;
    text: string;
    expect_rejected: boolean;
    expect_code?: string;
    why: string;
  }>;
  placeholder: Array<{ id: string; uri: string; expect_placeholder: boolean; why: string }>;
  metadata_placement: Array<{
    id: string;
    activated: boolean;
    existing_metadata: Record<string, unknown>;
    substate: Record<string, unknown>;
    provenance?: { declared_field_names?: string[]; approver_roles?: string[] };
    expect_key?: string;
    expect_value?: Record<string, unknown>;
    expect_preserves?: Record<string, unknown>;
    expect_error?: string;
    why: string;
  }>;
};

describe("a2a extension corpus (shared with the Python SDK)", () => {
  it("pins the corpus version and the identifier under test", () => {
    expect(corpus.version).toBe("v0");
    expect(corpus.extension_uri).toBe(AEGIS_A2A_EXTENSION_URI_V0);
  });

  for (const v of corpus.negotiation) {
    it(`negotiates ${v.id} — ${v.why}`, () => {
      const result = negotiateExtensions(v.header);
      expect(result.activated).toBe(v.expect.activated);
      expect([...result.requested]).toEqual(v.expect.requested);
      expect([...result.echo]).toEqual(v.expect.echo);
      if (v.expect.reason === undefined) {
        expect(result.reason).toBeUndefined();
      } else {
        expect(result.reason).toBe(v.expect.reason);
      }
    });
  }

  for (const v of corpus.honesty) {
    it(`honesty guard: ${v.id} — ${v.why}`, () => {
      if (!v.expect_rejected) {
        expect(() => assertNoEnforcementClaim(v.text, "corpus")).not.toThrow();
        return;
      }
      let thrown: unknown;
      try {
        assertNoEnforcementClaim(v.text, "corpus");
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(A2AExtensionError);
      expect((thrown as A2AExtensionError).code).toBe(v.expect_code);
    });
  }

  for (const v of corpus.placeholder) {
    it(`placeholder guard: ${v.id} — ${v.why}`, () => {
      expect(isPlaceholderExtensionUri(v.uri)).toBe(v.expect_placeholder);
    });
  }

  for (const v of corpus.metadata_placement) {
    it(`metadata placement: ${v.id} — ${v.why}`, () => {
      const negotiation = negotiateExtensions(
        v.activated ? AEGIS_A2A_EXTENSION_URI_V0 : null,
      );
      if (v.expect_error !== undefined) {
        let thrown: unknown;
        try {
          placeDecisionMetadata(v.existing_metadata, v.substate as never, negotiation, v.provenance);
        } catch (err) {
          thrown = err;
        }
        // Emission-side refusals cross module boundaries (activation and
        // honesty errors are A2AExtensionError, producer-assertion errors are
        // A2AVerificationError, provenance errors are A2APrivacyError) — all
        // are AegisError with a pinned stable code.
        expect(thrown).toBeInstanceOf(AegisError);
        expect((thrown as AegisError).code).toBe(v.expect_error);
        return;
      }
      const out = placeDecisionMetadata(v.existing_metadata, v.substate as never, negotiation, v.provenance);
      // The COMPLETE output is pinned, not just the named keys — a mutant that
      // smuggles an extra sibling into the result would otherwise stay green
      // (round-1 codex, the corpus/battery survivor).
      expect(out).toEqual({
        ...v.existing_metadata,
        [v.expect_key as string]: v.expect_value,
      });
      // The caller's object is not mutated.
      expect(Object.keys(v.existing_metadata)).not.toContain(v.expect_key);
    });
  }

  // ---- the shipped AgentCard declaration itself --------------------------

  it("declares the extension without claiming enforcement", () => {
    const decl = buildAgentCardExtension();
    expect(decl.uri).toBe(AEGIS_A2A_EXTENSION_URI_V0);
    // Never `required: true` — that is a request-construction notice, not a
    // gate, and a "required" security-flavoured extension invites the exact
    // misreading this surface must avoid.
    expect(decl.required).toBe(false);
    expect(decl.params?.identifier_is_placeholder).toBe(true);
    expect(() =>
      assertNoEnforcementClaim(JSON.stringify(decl), "AgentCard declaration"),
    ).not.toThrow();
  });

  it("keeps the shipped identifier detectable as a placeholder", () => {
    // If this ever goes green with a real URI, registration happened — which is
    // an ownership decision, not a code change.
    expect(isPlaceholderExtensionUri(AEGIS_A2A_EXTENSION_URI_V0)).toBe(true);
  });
});
