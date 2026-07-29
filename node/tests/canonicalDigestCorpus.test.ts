// Cross-SDK canonical idempotency-digest conformance — Node runner.
//
// Executes the shared corpus (conformance/canonical_digest.v0.json) through the
// Node SDK's SHIPPED _payloadHash. The Python SDK runs the SAME corpus
// (python/tests/test_canonical_digest_corpus.py) through its shipped
// _payload_hash. One corpus read by both is what makes the byte parity real;
// the expected digests previously lived as duplicated string literals in the two
// suites, where an edit to one side left the other green.
//
// This runner replaces the former "byte-anchors the canonical idempotency
// digest" test in schemaVersion.test.ts, which re-derived the canonical form
// inline and hashed its own reconstruction — proving only that SHA-256 is
// deterministic, and staying green if the shipped hash drifted underneath it.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { _payloadHash } from "../src/history.js";

interface Case {
  id: string;
  doc: string;
  input: {
    function: string;
    purpose: string;
    scope: string[];
    denyFields: string[];
    blockedFields: string[];
    mode: string;
  };
  expected_digest: string;
}

const corpus = JSON.parse(
  readFileSync(
    new URL("../../conformance/canonical_digest.v0.json", import.meta.url),
    "utf8",
  ),
) as { version: number; algorithm: string; cases: Case[] };

describe("cross-SDK canonical idempotency digest corpus", () => {
  it("corpus is present and versioned", () => {
    expect(corpus.version).toBe(0);
    expect(corpus.algorithm).toBe("sha256");
    expect(corpus.cases.length).toBeGreaterThan(0);
  });

  for (const c of corpus.cases) {
    it(`digest: ${c.id}`, () => {
      expect(_payloadHash(c.input)).toBe(c.expected_digest);
    });
  }

  it("schema_version is not an input to the digest", () => {
    // Stamping record metadata must not move the hash — the corpus inputs carry
    // no schema_version, and the shipped signature must have no place to accept
    // one. Guards the S017 D-D decision structurally rather than by convention.
    const anchor = corpus.cases.find((c) => c.id === "anchor-sorted-input");
    expect(anchor).toBeDefined();
    const withExtra = { ...anchor!.input, schemaVersion: 99 } as never;
    expect(_payloadHash(withExtra)).toBe(anchor!.expected_digest);
  });
});
