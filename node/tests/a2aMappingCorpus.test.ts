// Cross-SDK A2A decision→TaskState mapping conformance — Node runner.
//
// Executes the shared corpus (conformance/a2a_mapping.v0.json) through the Node
// SDK's SHIPPED mapDecisionToA2A. The Python SDK runs the SAME corpus
// (python/tests/test_a2a_mapping_corpus.py) through its shipped
// map_decision_to_a2a. Two implementations agreeing with each other proves
// nothing if both are wrong; both agreeing with one normative corpus is the
// claim worth making.
//
// The corpus also declares `legal_pairs`, so "a legal pair is missing from the
// corpus" is itself detectable — a corpus that quietly omits
// BLOCKED/internal_failure would otherwise let a wrong mapping for that pair
// ship while every vector stayed green.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  A2AMappingError,
  LEGAL_OUTCOME_REASON_PAIRS,
  mapDecisionToA2A,
  validateOutcomeReason,
} from "../src/a2a/mapping.js";

interface Entry {
  id: string;
  decision: Record<string, unknown>;
  expect: {
    task_state_recommendation: string | null;
    halts_task: boolean;
    substate: Record<string, unknown>;
  };
  why: string;
}

interface NegativeEntry {
  id: string;
  decision: Record<string, unknown>;
  expect_error: string;
  why: string;
}

const corpus = JSON.parse(
  readFileSync(new URL("../../conformance/a2a_mapping.v0.json", import.meta.url), "utf8"),
) as {
  version: string;
  legal_pairs: Array<[string, string]>;
  entries: Entry[];
  negative_entries: NegativeEntry[];
};

describe("a2a mapping corpus (shared with the Python SDK)", () => {
  it("pins the corpus version", () => {
    expect(corpus.version).toBe("v0");
  });

  for (const entry of corpus.entries) {
    it(`maps ${entry.id} — ${entry.why}`, () => {
      const result = mapDecisionToA2A(entry.decision as never);
      expect(result.taskStateRecommendation).toBe(entry.expect.task_state_recommendation);
      expect(result.haltsTask).toBe(entry.expect.halts_task);
      // Deep equality both ways: an extra field on the substate is a leak, a
      // missing one is a dropped signal.
      expect(result.substate).toEqual(entry.expect.substate);
    });
  }

  for (const entry of corpus.negative_entries) {
    it(`rejects ${entry.id} — ${entry.why}`, () => {
      let thrown: unknown;
      try {
        mapDecisionToA2A(entry.decision as never);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(A2AMappingError);
      expect((thrown as A2AMappingError).code).toBe(entry.expect_error);
      // Machine-parseable error contract: agents route on code and need a
      // remediation, not a free-text guess.
      expect((thrown as A2AMappingError).remediation.length).toBeGreaterThan(0);
      expect((thrown as A2AMappingError).docs_url).toContain(entry.expect_error);
    });
  }

  // ---- non-vacuity of the corpus itself -----------------------------------

  it("covers every legal pair declared by the corpus", () => {
    const covered = new Set(
      corpus.entries.map((e) => `${e.decision.outcome} ${e.decision.reason_code}`),
    );
    const declared = corpus.legal_pairs.map(([o, r]) => `${o} ${r}`);
    expect([...declared].filter((p) => !covered.has(p))).toEqual([]);
  });

  it("declares exactly the legal pairs the shipped mapping accepts", () => {
    const fromCorpus = new Set(corpus.legal_pairs.map(([o, r]) => `${o} ${r}`));
    const fromCode = new Set(LEGAL_OUTCOME_REASON_PAIRS.map(([o, r]) => `${o} ${r}`));
    expect([...fromCorpus].sort()).toEqual([...fromCode].sort());
  });

  it("rejects every pair outside the legal set", () => {
    const outcomes = ["PROTECTED", "ACCESS_REDUCED", "CHECK_REQUIRED", "APPROVAL_REQUIRED", "BLOCKED"];
    const reasons = [
      "minimum_disclosure",
      "policy_denied",
      "approval_required",
      "check_required",
      "invalid_scope",
      "internal_failure",
    ];
    const legal = new Set(LEGAL_OUTCOME_REASON_PAIRS.map(([o, r]) => `${o} ${r}`));
    let checked = 0;
    for (const outcome of outcomes) {
      for (const reason of reasons) {
        if (legal.has(`${outcome} ${reason}`)) continue;
        checked += 1;
        expect(() => validateOutcomeReason(outcome, reason)).toThrowError(A2AMappingError);
      }
    }
    // 5x6 = 30 combinations, 7 legal → 23 must be refused. If this count drifts,
    // the legal set changed and the mapping table must be re-derived from the
    // decision engine, not patched here.
    expect(checked).toBe(23);
  });
});
