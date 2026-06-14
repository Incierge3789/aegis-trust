// Cross-SDK LITE filtering conformance — Node runner.
//
// Executes the shared corpus (conformance/filter_parity.v0.json) through the
// Node SDK's public wrap() and asserts each vector's data + removed-key SET.
// The Python SDK runs the SAME corpus (python/tests/test_filter_parity_corpus.py).
// Both passing on one corpus is the drift-proof guarantee that the two SDKs
// filter identically — a divergence here is a cross-SDK security-parity bug.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import { wrap } from "../src/index.js";

interface Case {
  id: string;
  purpose: string;
  scope?: string[];
  deny_fields?: string[];
  input: unknown;
  expected_data: unknown;
  expected_filtered_keys: string[];
}

const corpus = JSON.parse(
  readFileSync(
    new URL("../../conformance/filter_parity.v0.json", import.meta.url),
    "utf8",
  ),
) as { version: number; cases: Case[] };

describe("cross-SDK LITE filter parity corpus", () => {
  it("corpus is present and versioned", () => {
    expect(corpus.version).toBe(0);
    expect(corpus.cases.length).toBeGreaterThan(0);
  });

  for (const c of corpus.cases) {
    it(`parity: ${c.id}`, () => {
      const opts: { purpose: string; scope?: string[]; denyFields?: string[] } = {
        purpose: c.purpose,
      };
      if (c.scope !== undefined) opts.scope = c.scope;
      if (c.deny_fields !== undefined) opts.denyFields = c.deny_fields;

      const res = wrap(c.input, opts);
      expect(res.data).toEqual(c.expected_data);
      // Order-independent: both SDKs must report the same SET of removed paths.
      expect([...res.filteredKeys].sort()).toEqual(
        [...c.expected_filtered_keys].sort(),
      );
    });
  }
});
