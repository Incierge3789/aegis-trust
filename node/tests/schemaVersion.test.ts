import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  AegisClient,
  AUDIT_SCHEMA_VERSION,
  HistoryStore,
  recordIfEnabled,
  resetStore,
} from "../src/index.js";

// S017 schema_version contract regression (Node SDK). Python twin:
// python/tests/test_schema_version.py. Node convention: JSONL records carry
// camelCase `schemaVersion`; the /shield/ingest wire payload carries snake_case
// `schema_version`. That casing asymmetry is intentional (D-A..D-I).

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "aegis-schemaver-"));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
  resetStore();
  delete process.env.AEGIS_HISTORY;
  delete process.env.AEGIS_HISTORY_PATH;
});

describe("AUDIT_SCHEMA_VERSION (T4 / H-7)", () => {
  it("is the single-source constant value 1", () => {
    expect(AUDIT_SCHEMA_VERSION).toBe(1);
  });
});

describe("emit path 2: JSONL local record (T5)", () => {
  it("stamps schemaVersion on a written record", () => {
    const s = new HistoryStore(join(tmp, "history.jsonl"));
    s.record({
      function: "getUser",
      purpose: "p",
      scope: ["a"],
      denyFields: [],
      blockedFields: [],
      timestamp: "t",
      mode: "lite",
    });
    expect(s.getHistory()[0]!.schemaVersion).toBe(1);
  });
});

describe("emit path 4: /shield/ingest wire payload (T5)", () => {
  it("stamps snake_case schema_version on each wire entry", () => {
    // ingestPayload is a private static; access via cast for a unit assertion
    // without widening the public API.
    const payload = (
      AegisClient as unknown as {
        ingestPayload(
          entries: ReadonlyArray<Record<string, unknown>>,
        ): { entries: Array<Record<string, unknown>> };
      }
    ).ingestPayload([
      {
        function: "getUser",
        purpose: "p",
        scope: ["a", "b"],
        denyFields: ["y", "z"],
        blockedFields: ["m", "n"],
        timestamp: "t",
        count: 1,
        mode: "lite",
      },
    ]);
    expect(payload.entries[0]!.schema_version).toBe(1);
  });
});

describe("signature-drift regression (T3 / H-1)", () => {
  it("AEGIS_HISTORY=1 writes a versioned row (not swallowed)", () => {
    process.env.AEGIS_HISTORY = "1";
    process.env.AEGIS_HISTORY_PATH = join(tmp, "history.jsonl");
    resetStore();
    recordIfEnabled({
      function: "getUser",
      purpose: "support",
      scope: ["name"],
      denyFields: [],
      blockedFields: ["email"],
      timestamp: "t",
      mode: "lite",
    });
    const rows = new HistoryStore(join(tmp, "history.jsonl")).getHistory();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.schemaVersion).toBe(1);
  });
});

describe("missing-version read compatibility (T6 / H-4)", () => {
  it("a legacy JSONL line without schemaVersion reads back as 1", () => {
    const path = join(tmp, "history.jsonl");
    // Pre-S017 record shape: no schemaVersion field.
    writeFileSync(
      path,
      JSON.stringify({
        id: 1,
        function: "old",
        purpose: "p",
        scope: [],
        denyFields: [],
        blockedFields: [],
        timestamp: "t",
        mode: "lite",
      }) + "\n",
    );
    const rows = new HistoryStore(path).getHistory();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.schemaVersion).toBe(1);
  });
});

describe("idempotency hash invariance (H-2 / D-D)", () => {
  it("recordIdempotent dedupes regardless of schema_version stamping", () => {
    // schema_version is metadata, excluded from the payload hash. The same
    // key + payload must still collapse to one record across retries.
    const s = new HistoryStore(join(tmp, "history.jsonl"));
    const args = {
      function: "getUser",
      purpose: "p",
      scope: ["a", "b"],
      denyFields: ["y", "z"],
      blockedFields: ["m", "n"],
      timestamp: "t",
      mode: "lite",
    };
    s.recordIdempotent(args, "k1");
    s.recordIdempotent(args, "k1");
    const rows = s.getHistory();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.schemaVersion).toBe(1);
  });

  // The byte anchor for the canonical digest lives in the shared corpus
  // (conformance/canonical_digest.v0.json), exercised by both SDKs against their
  // shipped hash functions — see canonicalDigestCorpus.test.ts. The test that
  // stood here re-derived the canonical form inline and hashed its own
  // reconstruction, so it asserted only that SHA-256 is deterministic and would
  // have stayed green if the shipped payloadHash drifted. It is superseded, not
  // dropped: the corpus covers that exact input as `anchor-sorted-input`, plus
  // six further vectors, and now reaches the real function.
});
