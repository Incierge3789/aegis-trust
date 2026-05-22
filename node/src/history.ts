// Local history store for @shield invocations.
//
// TS port of aegis.history (Python). Python uses stdlib sqlite3; Node's
// stdlib has no SQLite, so this port uses an append-only JSONL file
// (~/.aegis/history.jsonl by default). Public API surface is identical:
//
//   class HistoryStore { record(...), getHistory({limit, purpose}), getStats() }
//   function recordIfEnabled(...) / resetStore()
//
// Activation: env AEGIS_HISTORY=1 (mirror Python).

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

import { aegisDocsUrl, AegisAuditError } from "./errors.js";

export interface HistoryRecord {
  readonly id: number;
  readonly function: string;
  readonly purpose: string;
  readonly scope: ReadonlyArray<string>;
  readonly denyFields: ReadonlyArray<string>;
  readonly blockedFields: ReadonlyArray<string>;
  readonly timestamp: string;
  readonly mode: string;
  readonly idempotencyKey?: string;
  readonly trace_id?: string;
  // T-SDK-FULL-GATE-01: FULL-mode /check-access outcome. `decision` is
  // "allow" | "deny" | "fail_closed"; `reason` is the AuthzReason enum
  // ("allowed" | "denied" | "core_503" | "http_error" | "unreachable" |
  // "internal_error"). Present only for FULL-mode records.
  readonly decision?: string;
  readonly reason?: string;
}

export interface HistoryStats {
  readonly totalCalls: number;
  readonly totalBlockedFields: number;
  readonly byPurpose: Readonly<Record<string, { calls: number; blocked: number }>>;
  readonly byField: Readonly<Record<string, number>>;
}

// Cross-review round 3 P0-2: canonical hash of an idempotent record's payload.
// Used to detect when the same idempotencyKey is reused with a different
// payload — Stripe-style semantics surface this as an error rather than
// silently discarding the divergent retry.
function payloadHash(args: {
  function: string;
  purpose: string;
  scope: ReadonlyArray<string>;
  denyFields: ReadonlyArray<string>;
  blockedFields: ReadonlyArray<string>;
  mode: string;
}): string {
  const canonical = JSON.stringify([
    args.function,
    args.purpose,
    [...args.scope].sort(),
    [...args.denyFields].sort(),
    [...args.blockedFields].sort(),
    args.mode,
  ]);
  return createHash("sha256").update(canonical).digest("hex");
}

export class HistoryStore {
  private _dbPath: string;
  private _nextId: number;
  private _seenKeys: Map<string, string> | null = null;

  constructor(dbPath: string) {
    this._dbPath = dbPath;
    mkdirSync(dirname(this._dbPath), { recursive: true });
    // Seed next-id by counting existing lines (linear scan, fine for local).
    this._nextId = this.countExisting() + 1;
  }

  get path(): string {
    return this._dbPath;
  }

  private countExisting(): number {
    if (!existsSync(this._dbPath)) return 0;
    const raw = readFileSync(this._dbPath, "utf8");
    if (raw.length === 0) return 0;
    let n = 0;
    for (const ch of raw) if (ch === "\n") n++;
    if (raw[raw.length - 1] !== "\n") n++;
    return n;
  }

  record(args: {
    function: string;
    purpose: string;
    scope: ReadonlyArray<string>;
    denyFields: ReadonlyArray<string>;
    blockedFields: ReadonlyArray<string>;
    timestamp: string;
    mode: string;
    trace_id?: string;
    decision?: string;
    reason?: string;
  }): void {
    const rec: HistoryRecord = {
      id: this._nextId++,
      function: args.function,
      purpose: args.purpose,
      scope: args.scope,
      denyFields: args.denyFields,
      blockedFields: args.blockedFields,
      timestamp: args.timestamp,
      mode: args.mode,
      ...(args.trace_id !== undefined ? { trace_id: args.trace_id } : {}),
      ...(args.decision !== undefined ? { decision: args.decision } : {}),
      ...(args.reason !== undefined ? { reason: args.reason } : {}),
    };
    appendFileSync(this._dbPath, JSON.stringify(rec) + "\n", "utf8");
  }

  // Stripe Idempotency-Key semantics translated to the local history store.
  // Calling recordIdempotent() with the same `idempotencyKey` more than once
  // (within or across process runs) appends only once. Used by agents that
  // retry on partial failure without producing duplicate audit records.
  //
  // Key cache is seeded lazily from the on-disk JSONL on first call, so a
  // restarted process still dedupes against keys written by prior runs.
  //
  // Concurrency: dedup is best-effort. Within one process the check + append
  // is atomic because Node is single-threaded. Across processes writing the
  // same JSONL concurrently, two callers can both miss the key cache and
  // both append — the SDK does not file-lock the JSONL. Production-grade
  // cross-process dedup is sprint_002 hardening (D-952 family).
  recordIdempotent(
    args: {
      function: string;
      purpose: string;
      scope: ReadonlyArray<string>;
      denyFields: ReadonlyArray<string>;
      blockedFields: ReadonlyArray<string>;
      timestamp: string;
      mode: string;
      trace_id?: string;
    },
    idempotencyKey: string,
  ): { wrote: boolean; idempotencyKey: string } {
    if (!idempotencyKey || typeof idempotencyKey !== "string") {
      throw new AegisAuditError({
        code: "aegis.audit.idempotencyKey.required",
        remediation: "Pass a non-empty string as idempotencyKey.",
        docs_url: aegisDocsUrl("aegis.audit.idempotencyKey.required"),
        message: "recordIdempotent: idempotencyKey must be a non-empty string",
      });
    }
    if (this._seenKeys === null) {
      this._seenKeys = new Map();
      for (const r of this.readAll()) {
        if (r.idempotencyKey) {
          this._seenKeys.set(r.idempotencyKey, payloadHash(r));
        }
      }
    }
    const newHash = payloadHash(args);
    const existing = this._seenKeys.get(idempotencyKey);
    if (existing !== undefined) {
      if (existing !== newHash) {
        // Cross-review round 3 P0-2: divergent payload retry must surface,
        // not silently drop. Stripe's Idempotency-Key returns the original
        // response on duplicate; here we audit the divergence instead.
        throw new AegisAuditError({
          code: "aegis.audit.idempotencyKey.payloadDivergence",
          remediation:
            "An idempotencyKey was reused with a different payload. Either rotate the key for the new payload, or fix the caller so retries pass the same args.",
          docs_url: aegisDocsUrl("aegis.audit.idempotencyKey.payloadDivergence"),
          message: `recordIdempotent: idempotencyKey '${idempotencyKey}' reused with divergent payload`,
        });
      }
      return { wrote: false, idempotencyKey };
    }
    const rec: HistoryRecord = {
      id: this._nextId++,
      function: args.function,
      purpose: args.purpose,
      scope: args.scope,
      denyFields: args.denyFields,
      blockedFields: args.blockedFields,
      timestamp: args.timestamp,
      mode: args.mode,
      idempotencyKey,
      ...(args.trace_id !== undefined ? { trace_id: args.trace_id } : {}),
    };
    appendFileSync(this._dbPath, JSON.stringify(rec) + "\n", "utf8");
    this._seenKeys.set(idempotencyKey, newHash);
    return { wrote: true, idempotencyKey };
  }

  private readAll(): HistoryRecord[] {
    if (!existsSync(this._dbPath)) return [];
    const raw = readFileSync(this._dbPath, "utf8");
    if (raw.length === 0) return [];
    const out: HistoryRecord[] = [];
    for (const line of raw.split("\n")) {
      if (line.length === 0) continue;
      try {
        out.push(JSON.parse(line) as HistoryRecord);
      } catch {
        // Skip malformed line.
      }
    }
    return out;
  }

  getHistory(
    opts: { limit?: number; purpose?: string } = {},
  ): HistoryRecord[] {
    const limit = opts.limit ?? 20;
    const all = this.readAll();
    let filtered = all;
    if (opts.purpose !== undefined) {
      filtered = all.filter((r) => r.purpose === opts.purpose);
    }
    filtered.sort((a, b) => b.id - a.id);
    return filtered.slice(0, limit);
  }

  getStats(): HistoryStats {
    const all = this.readAll();
    const byPurpose: Record<string, { calls: number; blocked: number }> = {};
    const byField: Record<string, number> = {};
    for (const r of all) {
      const p = byPurpose[r.purpose] ?? { calls: 0, blocked: 0 };
      p.calls += 1;
      if (r.blockedFields.length > 0) p.blocked += 1;
      byPurpose[r.purpose] = p;
      for (const f of r.blockedFields) {
        byField[f] = (byField[f] ?? 0) + 1;
      }
    }
    let totalCalls = 0;
    for (const v of Object.values(byPurpose)) totalCalls += v.calls;
    let totalBlocked = 0;
    for (const v of Object.values(byField)) totalBlocked += v;
    return {
      totalCalls,
      totalBlockedFields: totalBlocked,
      byPurpose,
      byField,
    };
  }

  close(): void {
    // No persistent FD held (append open/close each record). No-op for parity.
  }
}

let _store: HistoryStore | null = null;
let _checked: boolean = false;

function getStore(): HistoryStore | null {
  if (_checked) return _store;
  _checked = true;
  if ((process.env.AEGIS_HISTORY ?? "").trim() === "1") {
    const dbPath = process.env.AEGIS_HISTORY_PATH
      ?? join(homedir(), ".aegis", "history.jsonl");
    _store = new HistoryStore(dbPath);
  }
  return _store;
}

export function recordIfEnabled(args: {
  function: string;
  purpose: string;
  scope: ReadonlyArray<string>;
  denyFields: ReadonlyArray<string>;
  blockedFields: ReadonlyArray<string>;
  timestamp: string;
  mode: string;
  trace_id?: string;
  decision?: string;
  reason?: string;
}): void {
  try {
    // getStore() is inside the try: first-call initialisation opens the
    // history file (mkdir + line-count scan), which can throw on an
    // unwritable / unreadable path. Local history is best-effort telemetry
    // — neither initialisation nor write failure may break the data path
    // (it would otherwise turn a FULL-deny "return null" into a throw).
    const store = getStore();
    if (!store) return;
    store.record(args);
  } catch {
    // Logging failure must not break the data path.
  }
}

export function resetStore(): void {
  if (_store) _store.close();
  _store = null;
  _checked = false;
}
