// AegisClient — TS port of aegis.client (Python).
//
// Thin facade over the aegis-core REST API. Used by Mode.FULL of the shield
// wrapper, and directly when callers want backend access from non-decorator
// code paths.
//
// Endpoints:
//   GET    /health
//   POST   /check-access
//   POST   /audit-log
//   POST   /shield/ingest
//   GET    /audit/verify
//   POST   /shield/policy-sync
//   GET    /shield/stats
//   GET    /shield/report

import {
  aegisDocsUrl,
  AegisAuditError,
  AegisHttpError,
  AegisIngestError,
} from "./errors.js";
import { AUDIT_SCHEMA_VERSION } from "./constants.js";
import type {
  AuditChainStatus,
  FieldStats,
  FunctionStats,
  IngestEntry,
  IngestResponse,
  PolicySyncEntry,
  PolicySyncResponse,
  PurposeStats,
  ShieldStats,
} from "./types.js";

function httpError(endpoint: string, status: number): AegisHttpError {
  return new AegisHttpError({
    code: "aegis.http.nonOk",
    remediation: "Inspect server logs; verify endpoint + token; retry if 5xx.",
    docs_url: aegisDocsUrl("aegis.http.nonOk"),
    message: `${endpoint} HTTP ${status}`,
    status,
  });
}

function ingestError(detail: string): AegisIngestError {
  return new AegisIngestError({
    code: "aegis.ingest.responseShape",
    remediation: "Server returned a malformed shield/ingest response. Check aegis-core version.",
    docs_url: aegisDocsUrl("aegis.ingest.responseShape"),
    message: `ingest: ${detail}`,
  });
}

function auditError(detail: string): AegisAuditError {
  return new AegisAuditError({
    code: "aegis.audit.responseShape",
    remediation: "Server returned a malformed audit/verify response. Check aegis-core version.",
    docs_url: aegisDocsUrl("aegis.audit.responseShape"),
    message: `verify: ${detail}`,
  });
}

const DEFAULT_BASE_URL = "https://localhost:8443/api/v1";
const HEALTH_TIMEOUT_MS = 2_000;
const API_TIMEOUT_MS = 10_000;
const ACCESS_CACHE_TTL_MS = 30_000;

export interface AegisClientOptions {
  readonly baseUrl?: string;
  readonly token?: string;
  readonly verifySsl?: boolean;
}

export type MetricsHook = (
  endpoint: string,
  durationMs: number,
  status: number,
) => void;

let _metricsHook: MetricsHook | null = null;

export function setMetricsHook(hook: MetricsHook | null): void {
  _metricsHook = hook;
}

function emitMetric(endpoint: string, startedMs: number, status: number): void {
  const hook = _metricsHook;
  if (!hook) return;
  try {
    hook(endpoint, performance.now() - startedMs, status);
  } catch {
    // Instrumentation must never break the data path.
  }
}

// In Node 18+, global fetch exists. For TLS verify override we'd need
// undici Agent; in Node, env NODE_TLS_REJECT_UNAUTHORIZED=0 is the user
// escape hatch. We honor `verifySsl: false` by setting that env when the
// client constructs — but only if the host is local (mirror Python prod-lock).

const DEV_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
]);

export function isDevHost(urlOrHost: string): boolean {
  try {
    const u = new URL(urlOrHost);
    const host = (u.hostname || urlOrHost).toLowerCase();
    return DEV_HOSTS.has(host) || host.endsWith(".local");
  } catch {
    const host = urlOrHost.toLowerCase();
    return DEV_HOSTS.has(host) || host.endsWith(".local");
  }
}

export function resolveVerifySsl(
  baseUrl: string,
  requested: boolean,
): boolean {
  // Production (non-dev host): TLS verify is forced ON. AEGIS_VERIFY_SSL=false
  // is ignored unless AEGIS_DEV_INSECURE=1 AND host is dev.
  if (requested) return true;
  if (!isDevHost(baseUrl)) {
    return true;
  }
  if (process.env.AEGIS_DEV_INSECURE === "1") {
    return false;
  }
  return true;
}

// ── check-boundary (Doctor v1, Core-backed) ────────────────
// Wire shape of the gateway's BoundaryDecisionView (POST /check-boundary).
// `outcome` is the SCREAMING_SNAKE_CASE DecisionOutcome enum
// (decision_bundle.rs); `reason_code` is snake_case. Field names are surfaced
// (never values).
export type CoreBoundaryOutcome =
  | "PROTECTED"
  | "ACCESS_REDUCED"
  | "CHECK_REQUIRED"
  | "APPROVAL_REQUIRED"
  | "BLOCKED";

export interface CoreDecisionEvidence {
  readonly decision_id: string;
  readonly policy: string;
  readonly enforced_by: string;
  readonly integrity_checkable_at: string;
  readonly recorded_at: string;
}

export interface BoundaryDecisionView {
  readonly source: string; // "CORE"
  readonly outcome: CoreBoundaryOutcome;
  readonly purpose_label: string;
  readonly allowed_fields: ReadonlyArray<string>;
  readonly withheld_fields: ReadonlyArray<string>;
  readonly reason_code: string;
  readonly reason_label: string;
  readonly evidence_available: boolean;
  readonly evidence: CoreDecisionEvidence | null;
}

// Request to POST /check-boundary. `purpose` + `scope` are required; the rest
// are optional. The authenticated principal is the JWT subject server-side and
// is NEVER sent in the body.
export interface CheckBoundaryArgs {
  readonly purpose: string;
  readonly scope: ReadonlyArray<string>;
  readonly destination?: string;
  readonly agentId?: string;
  readonly environment?: string;
  readonly mode?: string;
  readonly schemaVersion?: number;
}

// T-SDK-FULL-GATE-01: reason a /check-access authorization did not grant.
// Lets shield() FULL record a local diagnostic without widening the boolean
// `authorize()` public contract.
export type AuthzReason =
  | "allowed" // granted
  | "denied" // HTTP 200 + allowed:false — gateway policy denied
  | "core_503" // aegis-core audit-fail-closed (CSR-02)
  | "http_error" // 403 identity_mismatch / other non-200 / unparseable body
  | "unreachable" // network error / timeout — gateway not reached
  | "multi_scope_unsupported"; // >1 scope vs single-scope server (fail-closed, finding B)

export interface AuthzResult {
  readonly allowed: boolean;
  readonly reason: AuthzReason;
}

export class AegisClient {
  private _baseUrl: string;
  private _token: string;
  private _verifySsl: boolean;
  private _accessCache: Map<string, number> = new Map();
  private _tokenEpoch: number = 0;
  private _maxAuditSeq: number = 0;

  constructor(options: AegisClientOptions = {}) {
    this._baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    this._token = options.token ?? "";
    this._verifySsl = resolveVerifySsl(this._baseUrl, options.verifySsl ?? true);
  }

  get baseUrl(): string {
    return this._baseUrl;
  }

  get maxAuditSeq(): number {
    return this._maxAuditSeq;
  }

  private authHeaders(): Record<string, string> {
    // Always attach the Aegis-Api-Version dated header.
    const headers: Record<string, string> = {
      "Aegis-Api-Version": "2026-05-18",
    };
    if (this._token) {
      headers["Authorization"] = `Bearer ${this._token}`;
    }
    return headers;
  }

  private async req(
    method: "GET" | "POST",
    path: string,
    options: {
      body?: unknown;
      timeoutMs?: number;
      params?: Record<string, string>;
    } = {},
  ): Promise<Response> {
    const timeout = options.timeoutMs ?? API_TIMEOUT_MS;
    let url = this._baseUrl + path;
    if (options.params && Object.keys(options.params).length > 0) {
      const qs = new URLSearchParams(options.params).toString();
      url += `?${qs}`;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    const headers: Record<string, string> = {
      ...this.authHeaders(),
    };
    let body: string | undefined;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    // verifySsl=false escape only honored when caller is on dev host AND
    // process env says insecure dev is intended. Handled at construction.
    // Node fetch respects NODE_TLS_REJECT_UNAUTHORIZED globally; we don't
    // toggle it per-request to avoid race conditions.
    try {
      const resp = await fetch(url, {
        method,
        headers,
        body,
        signal: ctrl.signal,
      });
      return resp;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── health ────────────────────────────────────────────
  async isAvailable(): Promise<boolean> {
    try {
      const resp = await this.req("GET", "/health", {
        timeoutMs: HEALTH_TIMEOUT_MS,
      });
      return resp.status === 200;
    } catch {
      return false;
    }
  }

  // ── check-access ──────────────────────────────────────
  private cacheKey(purpose: string, scope: ReadonlyArray<string>): string {
    const sorted = [...scope].sort().join("|");
    return `${this._tokenEpoch}::${purpose}::${sorted}`;
  }

  private cachedAllow(purpose: string, scope: ReadonlyArray<string>): boolean {
    const v = this._accessCache.get(this.cacheKey(purpose, scope));
    return v !== undefined && Date.now() < v;
  }

  private rememberAllow(
    purpose: string,
    scope: ReadonlyArray<string>,
    epochAtRequest: number,
  ): void {
    if (epochAtRequest !== this._tokenEpoch) return;
    this._accessCache.set(
      this.cacheKey(purpose, scope),
      Date.now() + ACCESS_CACHE_TTL_MS,
    );
  }

  private static checkAccessAllowed(body: unknown): boolean {
    if (
      body
      && typeof body === "object"
      && typeof (body as { allowed?: unknown }).allowed === "boolean"
    ) {
      return (body as { allowed: boolean }).allowed;
    }
    return false;
  }

  // Contract fix (CSR-03): the gateway's `/check-access` `scope` field is a
  // single `Option<String>` advisory scope identifier (aegis_gateway
  // rest.rs:296), NOT an array. Sending a JSON array deserializes as a type
  // error server-side (non-200 -> fail-closed), so the prior `{ purpose, scope }`
  // array body silently broke every scope-bearing /check-access call. The
  // authoritative gate is the JWT subject + purpose; `scope` is advisory
  // minimum-disclosure metadata where `None` means "purpose-level access only".
  // This helper emits what the endpoint expects without changing authorize()'s
  // grant/deny contract:
  //   - 0 scopes  -> omit `scope` (None / purpose-level)
  //   - 1 scope   -> send the single string
  //   - >1 scopes -> see authorizeDetailed(): the caller FAILS CLOSED before a
  //                 request is even built (this body builder is never invoked
  //                 with >1 scope on the gate path).
  // Review finding B (fail-closed regression fix): a >1-scope check must NOT
  // silently drop to purpose-level. Earlier, sending the array produced a
  // server type error (non-2xx -> deny); the scope->Option<String> fix changed
  // ">1 scope" into "omit scope", which made the server evaluate at
  // purpose-level and could ALLOW where the caller asked for a stricter,
  // narrower scope. That is a fail-open regression. We therefore DENY a
  // multi-scope check in authorizeDetailed() rather than send a purpose-level
  // request the single-scope server would evaluate more permissively than asked.
  // NOTE: /check-boundary correctly uses `scope: string[]` and does NOT route
  // through here.
  private static checkAccessBody(
    purpose: string,
    scope: ReadonlyArray<string>,
  ): Record<string, unknown> {
    const body: Record<string, unknown> = { purpose };
    if (scope.length === 1) {
      body.scope = scope[0];
    }
    return body;
  }

  async checkAccess(
    purpose: string,
    scope: ReadonlyArray<string>,
  ): Promise<{ allowed: boolean } & Record<string, unknown>> {
    const resp = await this.req("POST", "/check-access", {
      body: AegisClient.checkAccessBody(purpose, scope),
    });
    if (!resp.ok) throw httpError("check-access", resp.status);
    return (await resp.json()) as { allowed: boolean };
  }

  // ── check-boundary (Doctor v1) ────────────────────────
  // POST /check-boundary, reusing the SAME auth header / base-url / timeout /
  // req() + httpError plumbing as checkAccess. Non-2xx throws httpError so the
  // Doctor v1 entry point maps it to a fail-closed BLOCK. `scope` is a string[]
  // here (the boundary endpoint's contract), unlike /check-access. The JWT
  // subject is the authoritative principal server-side — agentId is advisory
  // and the principal is never sent.
  async checkBoundary(args: CheckBoundaryArgs): Promise<BoundaryDecisionView> {
    const body: Record<string, unknown> = {
      purpose: args.purpose,
      scope: [...args.scope],
    };
    if (args.destination !== undefined) body.destination = args.destination;
    if (args.agentId !== undefined) body.agent_id = args.agentId;
    if (args.environment !== undefined) body.environment = args.environment;
    if (args.mode !== undefined) body.mode = args.mode;
    if (args.schemaVersion !== undefined) body.schema_version = args.schemaVersion;
    const resp = await this.req("POST", "/check-boundary", { body });
    if (!resp.ok) throw httpError("check-boundary", resp.status);
    return (await resp.json()) as BoundaryDecisionView;
  }

  // AO-003 gate: fail-closed authorize. The detailed variant returns the
  // failure reason so callers (shield() FULL) can record a local diagnostic.
  // T-SDK-FULL-GATE-01: additive — the boolean `authorize()` contract below
  // is unchanged; existing direct callers are unaffected.
  async authorizeDetailed(
    purpose: string,
    scope: ReadonlyArray<string>,
  ): Promise<AuthzResult> {
    // Review finding B: the gateway's /check-access scope is a single
    // Option<String>. A >1-scope request cannot be expressed faithfully, and
    // dropping to purpose-level would let the server ALLOW more than the caller
    // asked for. Fail closed BEFORE any request — deny, never grant
    // purpose-level. (0-scope purpose-level and 1-scope single-string are
    // unchanged.) /check-boundary is the right path for multi-field scope.
    if (scope.length > 1) {
      return { allowed: false, reason: "multi_scope_unsupported" };
    }
    if (this.cachedAllow(purpose, scope)) {
      return { allowed: true, reason: "allowed" };
    }
    const epochAtRequest = this._tokenEpoch;
    const t0 = performance.now();
    let resp: Response;
    try {
      resp = await this.req("POST", "/check-access", {
        body: AegisClient.checkAccessBody(purpose, scope),
      });
    } catch {
      emitMetric("check-access", t0, 0);
      return { allowed: false, reason: "unreachable" };
    }
    emitMetric("check-access", t0, resp.status);
    if (resp.status === 200) {
      let body: unknown;
      try {
        body = await resp.json();
      } catch {
        return { allowed: false, reason: "http_error" };
      }
      if (AegisClient.checkAccessAllowed(body)) {
        this.rememberAllow(purpose, scope, epochAtRequest);
        return { allowed: true, reason: "allowed" };
      }
      return { allowed: false, reason: "denied" };
    }
    // CSR-02: aegis-core returns 503 when a /check-access decision cannot be
    // written to the audit log (audit-fail-closed).
    if (resp.status === 503) {
      return { allowed: false, reason: "core_503" };
    }
    // 403 identity_mismatch / RBAC deny / unknown_scope / invalid_capsule_id,
    // and any other non-200.
    return { allowed: false, reason: "http_error" };
  }

  // Boolean AO-003 gate — unchanged public contract. Delegates to
  // authorizeDetailed(); existing direct callers see identical behaviour.
  async authorize(
    purpose: string,
    scope: ReadonlyArray<string>,
  ): Promise<boolean> {
    return (await this.authorizeDetailed(purpose, scope)).allowed;
  }

  // ── audit-log ─────────────────────────────────────────
  async logAudit(args: {
    purpose: string;
    toolName: string;
    requesterId: string;
    decision: string;
    sessionId?: string;
    reason?: string;
    bytesReturned?: number;
  }): Promise<void> {
    const payload: Record<string, unknown> = {
      purpose: args.purpose,
      tool_name: args.toolName,
      requester_id: args.requesterId,
      decision: args.decision,
    };
    if (args.sessionId !== undefined) payload.session_id = args.sessionId;
    if (args.reason !== undefined) payload.reason = args.reason;
    if (args.bytesReturned !== undefined) payload.bytes_returned = args.bytesReturned;
    const resp = await this.req("POST", "/audit-log", { body: payload });
    if (!resp.ok) throw httpError("audit-log", resp.status);
  }

  // ── shield/ingest ─────────────────────────────────────
  private static ingestPayload(entries: ReadonlyArray<IngestEntry>): unknown {
    return {
      entries: entries.map((e) => ({
        function: e.function,
        purpose: e.purpose,
        scope: [...e.scope],
        blocked_fields: [...e.blockedFields],
        timestamp: e.timestamp,
        count: e.count,
        deny_fields: [...e.denyFields],
        schema_version: AUDIT_SCHEMA_VERSION,
        // Cross-review round 3 P0-4: trace_id propagation to gateway.
        ...(e.trace_id !== undefined ? { trace_id: e.trace_id } : {}),
      })),
    };
  }

  private static parseIngestBody(body: unknown): IngestResponse {
    if (!body || typeof body !== "object") {
      throw ingestError("body is not a dict");
    }
    const data = (body as { data?: unknown }).data;
    if (!data || typeof data !== "object") {
      throw ingestError("body['data'] missing or not a dict");
    }
    const d = data as {
      ingested?: unknown;
      audit_seq_start?: unknown;
      audit_seq_end?: unknown;
    };
    if (typeof d.ingested !== "number" || d.ingested < 0) {
      throw ingestError("'ingested' invalid");
    }
    if (typeof d.audit_seq_start !== "number" || d.audit_seq_start < 0) {
      throw ingestError("'audit_seq_start' invalid");
    }
    if (
      typeof d.audit_seq_end !== "number"
      || d.audit_seq_end < d.audit_seq_start
    ) {
      throw ingestError("'audit_seq_end' invalid or non-monotonic");
    }
    return {
      ingested: d.ingested,
      auditSeqStart: d.audit_seq_start,
      auditSeqEnd: d.audit_seq_end,
    };
  }

  private recordSeq(parsed: IngestResponse): IngestResponse {
    if (parsed.auditSeqEnd > this._maxAuditSeq) {
      this._maxAuditSeq = parsed.auditSeqEnd;
    }
    return parsed;
  }

  async ingest(entries: ReadonlyArray<IngestEntry>): Promise<IngestResponse> {
    const t0 = performance.now();
    const resp = await this.req("POST", "/shield/ingest", {
      body: AegisClient.ingestPayload(entries),
    });
    emitMetric("shield.ingest", t0, resp.status);
    if (!resp.ok) throw httpError("shield/ingest", resp.status);
    return this.recordSeq(AegisClient.parseIngestBody(await resp.json()));
  }

  // ── audit/verify ──────────────────────────────────────
  private static parseChainBody(body: unknown): AuditChainStatus {
    if (!body || typeof body !== "object") {
      throw auditError("body is not a dict");
    }
    const b = body as { chain_valid?: unknown; total_entries?: unknown };
    if (typeof b.chain_valid !== "boolean") {
      throw auditError("'chain_valid' must be bool");
    }
    if (typeof b.total_entries !== "number" || b.total_entries < 0) {
      throw auditError("'total_entries' invalid");
    }
    return { chainValid: b.chain_valid, totalEntries: b.total_entries };
  }

  async verifyAuditChain(): Promise<AuditChainStatus> {
    const resp = await this.req("GET", "/audit/verify");
    if (!resp.ok) throw httpError("audit/verify", resp.status);
    return AegisClient.parseChainBody(await resp.json());
  }

  async verifyInclusion(opts: { seqEnd?: number } = {}): Promise<boolean> {
    const target = opts.seqEnd ?? this._maxAuditSeq;
    if (target <= 0) return false;
    let status: AuditChainStatus;
    try {
      status = await this.verifyAuditChain();
    } catch {
      return false;
    }
    return status.chainValid && status.totalEntries >= target;
  }

  // ── policy-sync ───────────────────────────────────────
  async policySync(
    purposes: Readonly<Record<string, PolicySyncEntry>>,
  ): Promise<PolicySyncResponse> {
    const payload = {
      purposes: Object.fromEntries(
        Object.entries(purposes).map(([k, v]) => [
          k,
          { scope: [...v.scope], deny_fields: [...v.denyFields] },
        ]),
      ),
    };
    const resp = await this.req("POST", "/shield/policy-sync", { body: payload });
    if (!resp.ok) throw httpError("shield/policy-sync", resp.status);
    const json = (await resp.json()) as { data?: unknown };
    const d = (json.data as {
      synced?: number;
      added?: string[];
      updated?: string[];
    }) ?? {};
    return {
      synced: d.synced ?? 0,
      added: d.added ?? [],
      updated: d.updated ?? [],
    };
  }

  // ── shield/stats ──────────────────────────────────────
  async getStats(
    opts: {
      fromTime?: string;
      toTime?: string;
      purpose?: string;
    } = {},
  ): Promise<ShieldStats> {
    const params: Record<string, string> = {};
    if (opts.fromTime) params.from = opts.fromTime;
    if (opts.toTime) params.to = opts.toTime;
    if (opts.purpose) params.purpose = opts.purpose;
    const resp = await this.req("GET", "/shield/stats", { params });
    if (!resp.ok) throw httpError("shield/stats", resp.status);
    const json = (await resp.json()) as { data?: unknown };
    const d = json.data as {
      period: { from: string; to: string };
      total_calls: number;
      total_blocked_fields: number;
      by_purpose?: Record<string, { calls: number; blocked: number }>;
      by_field?: Record<string, { blocked_count: number }>;
      by_function?: Record<string, { calls: number; purposes?: string[] }>;
    };
    const byPurpose: Record<string, PurposeStats> = {};
    for (const [k, v] of Object.entries(d.by_purpose ?? {})) {
      byPurpose[k] = { calls: v.calls, blocked: v.blocked };
    }
    const byField: Record<string, FieldStats> = {};
    for (const [k, v] of Object.entries(d.by_field ?? {})) {
      byField[k] = { blockedCount: v.blocked_count };
    }
    const byFunction: Record<string, FunctionStats> = {};
    for (const [k, v] of Object.entries(d.by_function ?? {})) {
      byFunction[k] = { calls: v.calls, purposes: v.purposes ?? [] };
    }
    return {
      periodFrom: d.period.from,
      periodTo: d.period.to,
      totalCalls: d.total_calls,
      totalBlockedFields: d.total_blocked_fields,
      byPurpose,
      byField,
      byFunction,
    };
  }

  // ── shield/report ─────────────────────────────────────
  async getReport(
    opts: { format?: "json" | "pdf" } = {},
  ): Promise<Record<string, unknown> | Uint8Array> {
    const fmt = opts.format ?? "json";
    const params: Record<string, string> = fmt === "pdf" ? { format: "pdf" } : {};
    const resp = await this.req("GET", "/shield/report", { params });
    if (!resp.ok) throw httpError("shield/report", resp.status);
    if (fmt === "pdf") {
      const buf = await resp.arrayBuffer();
      return new Uint8Array(buf);
    }
    const json = (await resp.json()) as { data?: unknown };
    return (json.data as Record<string, unknown>) ?? {};
  }

  // ── token rotation ────────────────────────────────────
  setToken(newToken: string): void {
    this._token = newToken;
    this._tokenEpoch += 1;
    this._accessCache.clear();
  }

  // ── teardown ──────────────────────────────────────────
  // fetch has no persistent socket pool in user code; nothing to close.
  async close(): Promise<void> {
    this._accessCache.clear();
  }
}

// ── Module-level lazy client (mirrors Python _get_client) ──

let _moduleClient: AegisClient | null = null;
let _detectedMode: "lite" | "full" | null = null;
let _detectedModeTs = 0;
let _baseUrlAliasWarned = false;

// Mode detection cache TTL — parity with PyPI shield.py `_DETECT_MODE_TTL_S = 60.0`.
// AEGIS_MODE=auto re-probes the backend every `_DETECT_MODE_TTL_MS` ms so
// process state stays in sync with reality without per-call probes. Without
// this, a stuck `lite` detection survives gateway recovery, and a stuck
// fail-closed `full` keeps warning even after the backend is healthy.
const _DETECT_MODE_TTL_MS = 60_000;

// Canonical env var resolution. AEGIS_URL is canonical (parity with PyPI
// aegis-trust shield.py:119). AEGIS_BASE_URL is a deprecated alias kept
// for v0.8.x → v0.9.x backward compatibility — emits one warning per
// process, removed in v1.0.0 per docs/VERSIONING.md deprecation policy.
function resolveBaseUrl(): string {
  const aegisUrl = process.env.AEGIS_URL?.trim();
  if (aegisUrl) return aegisUrl;
  const aegisBaseUrl = process.env.AEGIS_BASE_URL?.trim();
  if (aegisBaseUrl) {
    if (!_baseUrlAliasWarned) {
      _baseUrlAliasWarned = true;
      console.warn(
        "aegis-trust: AEGIS_BASE_URL is deprecated — use AEGIS_URL "
          + "(parity with PyPI aegis-trust). AEGIS_BASE_URL will be removed in v1.0.0.",
      );
    }
    return aegisBaseUrl;
  }
  return DEFAULT_BASE_URL;
}

export function getModuleClient(): AegisClient {
  if (_moduleClient === null) {
    const baseUrl = resolveBaseUrl();
    const token = process.env.AEGIS_TOKEN || "";
    const verifyEnv = process.env.AEGIS_VERIFY_SSL;
    const verifySsl = verifyEnv === "false" || verifyEnv === "0" ? false : true;
    _moduleClient = new AegisClient({ baseUrl, token, verifySsl });
  }
  return _moduleClient;
}

// "User expects Full mode" heuristic, parity with PyPI shield.py
// _user_intends_full (line 165-181). Returns true when:
//   - AEGIS_TOKEN is set, OR
//   - AEGIS_URL / AEGIS_BASE_URL points at a non-dev host.
// (NOTE: explicit `AEGIS_MODE=full` is NOT a Full-intent signal here —
// it is handled in its own branch by `detectMode()` before the AUTO
// probe, mirroring PyPI's `_detect_mode` line 160-161.)
// When true, detectMode refuses to silently degrade to Lite on a
// transient backend outage — AO-001 Gateway-uniqueness outranks
// availability.
export function userIntendsFull(): boolean {
  if (process.env.AEGIS_TOKEN?.trim()) return true;
  const url = (process.env.AEGIS_URL || process.env.AEGIS_BASE_URL || "").trim();
  return !!url && !isDevHost(url);
}

export async function detectMode(): Promise<"lite" | "full"> {
  // TTL cache — parity with PyPI shield.py `_DETECT_MODE_TTL_S = 60.0`.
  // Without this, a transient backend outage causes a permanently-stuck
  // "lite" (or fail-closed Full warn) for the process lifetime.
  const nowMs = Date.now();
  if (_detectedMode !== null && nowMs - _detectedModeTs < _DETECT_MODE_TTL_MS) {
    return _detectedMode;
  }

  const envMode = process.env.AEGIS_MODE?.toLowerCase();
  if (envMode === "lite") {
    _detectedMode = "lite";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  if (envMode === "full") {
    // Explicit Full: never silently degrade. Calls fail-closed at the
    // gateway until the backend recovers. Parity with PyPI shield.py
    // _detect_mode line 160-161.
    _detectedMode = "full";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  // AUTO branch — intent-first per the README AUTO behaviour matrix:
  //   - no Full intent (no AEGIS_TOKEN, no non-dev URL) → LITE (no probe)
  //   - Full intent + reachable backend                 → FULL
  //   - Full intent + unreachable backend               → fail-closed FULL + warn
  // The intent check runs BEFORE the /health probe so a dev environment
  // without credentials does not opportunistically call the gateway —
  // this matches the documented matrix exactly. Earlier rc4-rc5 builds
  // probed first and upgraded to Full whenever the gateway was reachable
  // regardless of intent; that behaviour contradicted the matrix line
  // "auto + no Full intent → Lite" and is corrected here. Mirrors PyPI
  // shield.py _detect_mode intent-first variant.
  if (!userIntendsFull()) {
    _detectedMode = "lite";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  const client = getModuleClient();
  const available = await client.isAvailable();
  if (available) {
    _detectedMode = "full";
    _detectedModeTs = nowMs;
    return _detectedMode;
  }
  // AUTO + explicit Full intent + unreachable: fail-closed Full.
  // Silent Lite degrade would leak data the user asked the gateway to
  // filter.
  _detectedMode = "full";
  _detectedModeTs = nowMs;
  console.warn(
    "aegis-trust: AEGIS_MODE=auto with explicit URL/TOKEN but backend "
      + "unreachable — staying in Full mode (fail-closed). All shield() "
      + "calls will deny until the gateway recovers.",
  );
  return _detectedMode;
}

export function resetModuleClient(): void {
  _moduleClient = null;
  _detectedMode = null;
  _detectedModeTs = 0;
  _baseUrlAliasWarned = false;
}
