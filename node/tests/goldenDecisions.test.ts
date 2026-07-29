/**
 * INV-4 — the same input yields the same decision across versions (Node runner).
 *
 * Reads the SAME golden file as the Python runner, so a decision that drifts in
 * one SDK and not the other fails here as well as there. That is deliberate:
 * cross-version stability and cross-language identity are different properties,
 * and this file is where they meet — a release is only stable if BOTH SDKs still
 * produce what was recorded.
 *
 * WHAT THIS PROVES TODAY: nothing. The values were recorded from the current
 * build, so replaying them against the current build is circular. It becomes
 * evidence at the first release after 0.9.3 that replays this file unchanged.
 *
 * WHEN A REPLAY FAILS, assume the implementation regressed before assuming the
 * snapshot is stale. Regenerating the file to make CI green is the failure mode
 * it exists to prevent.
 *
 * Mirror: python/tests/test_golden_decisions.py.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { wrap } from "../src/index.js";

interface WrapEntry {
  id: string;
  surface: "wrap";
  since: string;
  input: { data: unknown; purpose: string; scope?: string[]; deny_fields?: string[] };
  expected: { data: unknown; filtered_keys: string[] };
}

const golden = JSON.parse(
  readFileSync(
    new URL("../../conformance/golden_decisions.v0.json", import.meta.url),
    "utf8",
  ),
) as {
  version: number;
  recorded_against: string;
  proves_cross_version_from: string;
  entries: Array<WrapEntry | { surface: string; id: string; since: string }>;
  breaking_changes: Array<{ version?: string; entry_id?: string; reason?: string }>;
};

const wrapEntries = golden.entries.filter(
  (e): e is WrapEntry => e.surface === "wrap",
);

describe("INV-4 golden decisions — cross-version replay", () => {
  it("snapshot is non-vacuous", () => {
    expect(golden.version).toBe(0);
    expect(golden.entries.length).toBeGreaterThanOrEqual(10);
    expect(wrapEntries.length).toBeGreaterThan(0);
    expect(golden.recorded_against, "not bound to a release").toBeTruthy();
  });

  it("keeps saying it proves nothing yet", () => {
    // If this marker is quietly dropped, the snapshot starts reading as
    // cross-version evidence a year before it is one.
    expect(golden.proves_cross_version_from).toBeTruthy();
  });

  for (const entry of wrapEntries) {
    it(`${entry.id}: decision unchanged since ${entry.since}`, () => {
      const opts: { purpose: string; scope?: string[]; denyFields?: string[] } = {
        purpose: entry.input.purpose,
      };
      if (entry.input.scope !== undefined) opts.scope = entry.input.scope;
      if (entry.input.deny_fields !== undefined) opts.denyFields = entry.input.deny_fields;

      const result = wrap(entry.input.data, opts);
      expect(
        result.data,
        `${entry.id}: the decision changed since ${entry.since}. Assume the ` +
          "implementation regressed before assuming the snapshot is stale; if the " +
          "change is intended, add a breaking_changes entry rather than regenerating.",
      ).toEqual(entry.expected.data);
      expect([...result.filteredKeys].sort()).toEqual(entry.expected.filtered_keys);
    });
  }

  it("breaking changes are documented", () => {
    // Empty today. Checked anyway, so the first entry cannot be added as a bare
    // marker to silence a failing replay.
    for (const bc of golden.breaking_changes) {
      expect(bc.version, "breaking change with no version").toBeTruthy();
      expect(bc.entry_id, "breaking change with no entry_id").toBeTruthy();
      expect((bc.reason ?? "").length, `${bc.entry_id}: reason too thin to audit`).toBeGreaterThan(30);
      expect(
        golden.entries.some((e) => e.id === bc.entry_id),
        `${bc.entry_id}: references an entry that does not exist`,
      ).toBe(true);
    }
  });
});
