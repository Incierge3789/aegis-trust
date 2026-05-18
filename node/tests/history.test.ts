import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { HistoryStore, recordIfEnabled, resetStore } from "../src/index.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "aegis-history-"));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
  resetStore();
  delete process.env.AEGIS_HISTORY;
  delete process.env.AEGIS_HISTORY_PATH;
});

describe("HistoryStore", () => {
  it("records and retrieves entries", () => {
    const s = new HistoryStore(join(tmp, "history.jsonl"));
    s.record({
      function: "getUser",
      purpose: "support",
      scope: ["name"],
      denyFields: [],
      blockedFields: ["ssn"],
      timestamp: "2026-01-01T00:00:00Z",
      mode: "lite",
    });
    const records = s.getHistory();
    expect(records).toHaveLength(1);
    expect(records[0]!.function).toBe("getUser");
    expect(records[0]!.blockedFields).toEqual(["ssn"]);
  });

  it("orders by ID desc and respects limit", () => {
    const s = new HistoryStore(join(tmp, "history.jsonl"));
    for (let i = 0; i < 5; i++) {
      s.record({
        function: `f${i}`,
        purpose: "p",
        scope: [],
        denyFields: [],
        blockedFields: [],
        timestamp: "t",
        mode: "lite",
      });
    }
    const out = s.getHistory({ limit: 3 });
    expect(out).toHaveLength(3);
    expect(out[0]!.id).toBe(5);
    expect(out[1]!.id).toBe(4);
    expect(out[2]!.id).toBe(3);
  });

  it("filters by purpose", () => {
    const s = new HistoryStore(join(tmp, "history.jsonl"));
    s.record({
      function: "a",
      purpose: "p1",
      scope: [],
      denyFields: [],
      blockedFields: [],
      timestamp: "t",
      mode: "lite",
    });
    s.record({
      function: "b",
      purpose: "p2",
      scope: [],
      denyFields: [],
      blockedFields: [],
      timestamp: "t",
      mode: "lite",
    });
    const out = s.getHistory({ purpose: "p2" });
    expect(out).toHaveLength(1);
    expect(out[0]!.function).toBe("b");
  });

  it("aggregates stats", () => {
    const s = new HistoryStore(join(tmp, "history.jsonl"));
    s.record({
      function: "f",
      purpose: "p",
      scope: [],
      denyFields: [],
      blockedFields: ["ssn"],
      timestamp: "t",
      mode: "lite",
    });
    s.record({
      function: "f",
      purpose: "p",
      scope: [],
      denyFields: [],
      blockedFields: ["ssn", "card"],
      timestamp: "t",
      mode: "lite",
    });
    const stats = s.getStats();
    expect(stats.totalCalls).toBe(2);
    expect(stats.byPurpose.p?.calls).toBe(2);
    expect(stats.byPurpose.p?.blocked).toBe(2);
    expect(stats.byField.ssn).toBe(2);
    expect(stats.byField.card).toBe(1);
    expect(stats.totalBlockedFields).toBe(3);
  });

  it("survives restart (file persists)", () => {
    const path = join(tmp, "history.jsonl");
    const s1 = new HistoryStore(path);
    s1.record({
      function: "f",
      purpose: "p",
      scope: [],
      denyFields: [],
      blockedFields: [],
      timestamp: "t",
      mode: "lite",
    });
    const s2 = new HistoryStore(path);
    s2.record({
      function: "g",
      purpose: "p",
      scope: [],
      denyFields: [],
      blockedFields: [],
      timestamp: "t",
      mode: "lite",
    });
    const out = s2.getHistory();
    expect(out).toHaveLength(2);
    expect(out[0]!.id).toBe(2); // increments from existing
  });
});

describe("recordIfEnabled", () => {
  it("no-ops when AEGIS_HISTORY is unset", () => {
    process.env.AEGIS_HISTORY_PATH = join(tmp, "history.jsonl");
    recordIfEnabled({
      function: "f",
      purpose: "p",
      scope: [],
      denyFields: [],
      blockedFields: [],
      timestamp: "t",
      mode: "lite",
    });
    // No file should be created.
    expect(() => new HistoryStore(join(tmp, "history.jsonl")).getHistory())
      .not.toThrow();
  });

  it("records when AEGIS_HISTORY=1", () => {
    process.env.AEGIS_HISTORY = "1";
    process.env.AEGIS_HISTORY_PATH = join(tmp, "history.jsonl");
    resetStore();
    recordIfEnabled({
      function: "f",
      purpose: "p",
      scope: [],
      denyFields: [],
      blockedFields: ["x"],
      timestamp: "t",
      mode: "lite",
    });
    const s = new HistoryStore(join(tmp, "history.jsonl"));
    expect(s.getHistory()).toHaveLength(1);
  });
});
