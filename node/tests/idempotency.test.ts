import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { AegisAuditError, HistoryStore } from "../src/index.js";

describe("HistoryStore.recordIdempotent — Stripe Idempotency-Key model", () => {
  let workdir: string;
  let dbPath: string;

  beforeEach(() => {
    workdir = mkdtempSync(join(tmpdir(), "aegis-idem-"));
    dbPath = join(workdir, "audit.jsonl");
  });

  afterEach(() => {
    rmSync(workdir, { recursive: true, force: true });
  });

  function payload() {
    return {
      function: "fetchCustomer",
      purpose: "support",
      scope: ["name", "email"],
      denyFields: [],
      blockedFields: ["ssn"],
      timestamp: "2026-05-17T00:00:00.000Z",
      mode: "lite",
    };
  }

  it("appends exactly once across 100 retries with the same key (same process)", () => {
    const store = new HistoryStore(dbPath);
    const KEY = "agent.retry.001";
    const results = [];
    for (let i = 0; i < 100; i++) {
      results.push(store.recordIdempotent(payload(), KEY));
    }
    expect(results.filter((r) => r.wrote).length).toBe(1);
    expect(results.filter((r) => !r.wrote).length).toBe(99);
    const lines = readFileSync(dbPath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    const rec = JSON.parse(lines[0]) as { idempotencyKey: string };
    expect(rec.idempotencyKey).toBe(KEY);
  });

  it("dedupes across separate HistoryStore instances (cross-process simulation)", () => {
    const KEY = "agent.retry.cross-process";
    const a = new HistoryStore(dbPath);
    const r1 = a.recordIdempotent(payload(), KEY);
    expect(r1.wrote).toBe(true);

    // Simulate a process restart by constructing a fresh HistoryStore that
    // re-seeds its key cache from the existing JSONL.
    const b = new HistoryStore(dbPath);
    const r2 = b.recordIdempotent(payload(), KEY);
    expect(r2.wrote).toBe(false);

    const lines = readFileSync(dbPath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
  });

  it("allows distinct keys (different agent retry chains independent)", () => {
    const store = new HistoryStore(dbPath);
    store.recordIdempotent(payload(), "k1");
    store.recordIdempotent(payload(), "k2");
    store.recordIdempotent(payload(), "k1"); // dedup
    store.recordIdempotent(payload(), "k3");

    const lines = readFileSync(dbPath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3);
  });

  // Round 3 P0-2: divergent-payload retry must surface as AegisAuditError
  // rather than silently drop. Stripe-style semantics for audit correctness.
  it("throws AegisAuditError when same key is reused with a divergent payload", () => {
    const store = new HistoryStore(dbPath);
    store.recordIdempotent(payload(), "agent.retry.001");
    expect(() =>
      store.recordIdempotent(
        { ...payload(), purpose: "billing" }, // divergent
        "agent.retry.001",
      ),
    ).toThrow(AegisAuditError);
  });

  it("ignores cosmetic fields (timestamp, trace_id) when comparing payload hashes", () => {
    const store = new HistoryStore(dbPath);
    store.recordIdempotent({ ...payload(), trace_id: "t1" }, "agent.retry.002");
    // Different timestamp / trace_id but same purpose+scope+denyFields+blockedFields+function+mode.
    expect(() =>
      store.recordIdempotent(
        {
          ...payload(),
          timestamp: "2026-05-18T00:00:00.000Z",
          trace_id: "t2",
        },
        "agent.retry.002",
      ),
    ).not.toThrow();
  });

  it("rejects empty idempotencyKey", () => {
    const store = new HistoryStore(dbPath);
    expect(() => store.recordIdempotent(payload(), "")).toThrow(AegisAuditError);
  });
});
