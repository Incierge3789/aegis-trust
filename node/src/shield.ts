import {
  AegisClient,
  detectMode,
  getModuleClient,
} from "./client.js";
import { aegisDocsUrl, AegisValidationError } from "./errors.js";
import {
  denyFilterDict,
  diffKeys,
  emptyFor,
  filterDict,
  freezeSinglePass,
  isPlainObject,
  toFilterable,
} from "./filter.js";
import { recordIfEnabled } from "./history.js";
import { parsePaths } from "./paths.js";
import { getTraceContext } from "./trace.js";
import {
  Mode,
  type IngestEntry,
  type ShieldOptions,
  type ShieldResult,
} from "./types.js";

// Module-level test hook — set by vitestPlugin to capture shield calls.
type ShieldCallHook = (record: {
  function: string;
  purpose: string;
  scope: ReadonlyArray<string>;
  denyFields: ReadonlyArray<string>;
  blockedFields: ReadonlyArray<string>;
  timestamp: string;
  mode: string;
}) => void;

let _testHook: ShieldCallHook | null = null;
export function _setTestHook(hook: ShieldCallHook | null): void {
  _testHook = hook;
}

// ── shield() ──────────────────────────────────────────────
//
// HOF returning a wrapped function. Sync and async are both supported:
// the wrapper detects a returned Promise and routes accordingly.
//
//   const safe = shield({ purpose: "lookup", scope: ["name", "email"] })(getUser);
//   const out = safe(123);                        // sync ok
//   const out = await safe(123);                  // async ok
//
// Modes:
//   - LITE: in-process filter only
//   - FULL: filter + ingest to aegis-core via AegisClient (async-only)
//   - AUTO: detect — full if AEGIS_TOKEN set and backend reachable, else lite

export function shield(options: ShieldOptions) {
  const purpose = options.purpose;
  const scope = options.scope ?? [];
  const denyFields = options.denyFields ?? [];
  const requestedMode = options.mode ?? Mode.AUTO;

  if (!purpose || typeof purpose !== "string") {
    throw new AegisValidationError({
      code: "aegis.shield.purpose.required",
      remediation: "Pass a non-empty string to `purpose` (e.g. \"customer_support\").",
      docs_url: aegisDocsUrl("aegis.shield.purpose.required"),
      message: "shield: purpose must be a non-empty string",
    });
  }

  const scopeTree = parsePaths(scope);
  const denyTree = parsePaths(denyFields, { broaderWins: true });

  return function wrap<F extends (...args: unknown[]) => unknown>(fn: F): F {
    const fnName = fn.name || "anonymous";
    const wrapped = function (this: unknown, ...args: unknown[]) {
      const out = fn.apply(this, args);
      if (isPromise(out)) {
        return (out as Promise<unknown>).then(async (resolved) => {
          const mode = await resolveMode(requestedMode);
          if (mode === Mode.FULL) {
            return applyAndAuditFull(
              resolved,
              scope,
              denyFields,
              scopeTree,
              denyTree,
              purpose,
              fnName,
            );
          }
          return applyAndAuditLite(
            resolved,
            scope,
            denyFields,
            scopeTree,
            denyTree,
            purpose,
            fnName,
          );
        });
      }
      // Sync path: Mode.FULL performs an awaited /check-access authorization,
      // which a synchronous function cannot do. T-SDK-FULL-GATE-01: rather
      // than silently mislabel a sync call as "full" (it would run LITE
      // semantics with no trust gate), refuse it with a clear error. Sync +
      // AUTO degrades to LITE (cannot await detection) — documented in README.
      if (requestedMode === Mode.FULL) {
        throw new AegisValidationError({
          code: "aegis.shield.mode.sync_full_unsupported",
          remediation:
            "Mode.FULL performs an awaited /check-access authorization. Wrap an async function for FULL, or use Mode.LITE for synchronous functions.",
          docs_url: aegisDocsUrl("aegis.shield.mode.sync_full_unsupported"),
          message: "shield: Mode.FULL requires an async wrapped function",
        });
      }
      return applyAndAuditLite(
        out,
        scope,
        denyFields,
        scopeTree,
        denyTree,
        purpose,
        fnName,
      );
    };
    Object.defineProperty(wrapped, "name", { value: fnName });
    return wrapped as F;
  };
}

async function resolveMode(requested: Mode): Promise<Mode> {
  if (requested === Mode.LITE) return Mode.LITE;
  if (requested === Mode.FULL) return Mode.FULL;
  // AUTO
  const detected = await detectMode();
  return detected === "full" ? Mode.FULL : Mode.LITE;
}

// Shared audit emission: synchronous test hook + local JSONL history
// (AEGIS_HISTORY=1). `decision` / `reason` are populated for FULL-mode
// records so a FULL authorization outcome is locally diagnosable.
function emitAudit(
  fnName: string,
  purpose: string,
  scope: ReadonlyArray<string>,
  denyFields: ReadonlyArray<string>,
  blockedFields: ReadonlyArray<string>,
  timestamp: string,
  modeStr: string,
  traceId: string | undefined,
  decision?: string,
  reason?: string,
): void {
  if (_testHook) {
    _testHook({
      function: fnName,
      purpose,
      scope,
      denyFields,
      blockedFields,
      timestamp,
      mode: modeStr,
    });
  }
  recordIfEnabled({
    function: fnName,
    purpose,
    scope,
    denyFields,
    blockedFields,
    timestamp,
    mode: modeStr,
    ...(traceId !== undefined ? { trace_id: traceId } : {}),
    ...(decision !== undefined ? { decision } : {}),
    ...(reason !== undefined ? { reason } : {}),
  });
}

// LITE path — in-process filter only, no network. Synchronous.
// T-SDK-FULL-GATE-01: an internal filter error is fail-closed — the caller
// receives a type-shaped safe empty value, never the raw unfiltered data
// and never a propagated exception.
function applyAndAuditLite(
  data: unknown,
  scope: ReadonlyArray<string>,
  denyFields: ReadonlyArray<string>,
  scopeTree: ReturnType<typeof parsePaths>,
  denyTree: ReturnType<typeof parsePaths>,
  purpose: string,
  fnName: string,
): unknown {
  const traceId = getTraceContext()?.traceId;
  try {
    const original = freezeSinglePass(data);
    const filtered = runFilter(original, scope, denyFields, scopeTree, denyTree);
    const blockedFields = diffKeys(original, filtered);
    emitAudit(
      fnName,
      purpose,
      scope,
      denyFields,
      blockedFields,
      new Date().toISOString(),
      "lite",
      traceId,
    );
    return filtered;
  } catch {
    // Internal error anywhere in freeze/filter → fail-closed safe empty.
    // emptyFor inspects only the input's broad shape (no deep read), so it
    // is safe even when `data` carries a throwing getter.
    emitAudit(
      fnName,
      purpose,
      scope,
      denyFields,
      [],
      new Date().toISOString(),
      "lite",
      traceId,
      "fail_closed",
      "internal_error",
    );
    return emptyFor(data);
  }
}

// FULL path — performs a pre-call /check-access authorization BEFORE the
// filter runs, and returns protected data only if authorization is granted.
// The authorization call is the trust gate. Audit ingest is post-
// authorization telemetry (fire-and-forget, fail-open) — never the gate.
async function applyAndAuditFull(
  data: unknown,
  scope: ReadonlyArray<string>,
  denyFields: ReadonlyArray<string>,
  scopeTree: ReturnType<typeof parsePaths>,
  denyTree: ReturnType<typeof parsePaths>,
  purpose: string,
  fnName: string,
): Promise<unknown> {
  const client = getModuleClient();
  const traceId = getTraceContext()?.traceId;

  // The trust gate. authorizeDetailed() is fail-closed — deny / 403 / 503 /
  // gateway-unreachable / network error all yield allowed:false. FULL mode
  // must NOT return protected data unless this call grants.
  let authz: { allowed: boolean; reason: string };
  try {
    authz = await client.authorizeDetailed(purpose, scope);
  } catch {
    // Defensive: authorizeDetailed is itself fail-closed and should not
    // throw — but an unexpected throw must never leak data.
    authz = { allowed: false, reason: "http_error" };
  }

  if (!authz.allowed) {
    const decision = authz.reason === "denied" ? "deny" : "fail_closed";
    emitAudit(
      fnName,
      purpose,
      scope,
      denyFields,
      [],
      new Date().toISOString(),
      "full",
      traceId,
      decision,
      authz.reason,
    );
    // Local diagnostic — distinguishes denied vs unreachable vs core_503
    // (T-SDK-FULL-GATE-01 addition). Carries no caller data: `purpose` and
    // `function` are developer-declared labels, not record fields.
    console.warn(
      `aegis-trust: FULL authorization not granted — mode=full `
      + `decision=${decision} reason=${authz.reason} `
      + `purpose=${purpose} function=${fnName}`,
    );
    return emptyFor(data);
  }

  // Authorized. Freeze + filter; an internal error anywhere here is
  // fail-closed → safe empty (emptyFor inspects only the input's broad
  // shape, safe even with a throwing getter on `data`).
  try {
    const original = freezeSinglePass(data);
    const filtered = runFilter(original, scope, denyFields, scopeTree, denyTree);
    const blockedFields = diffKeys(original, filtered);
    const timestamp = new Date().toISOString();
    emitAudit(
      fnName,
      purpose,
      scope,
      denyFields,
      blockedFields,
      timestamp,
      "full",
      traceId,
      "allow",
      "allowed",
    );

    // Post-authorization telemetry. Fire-and-forget; ingest failure is
    // fail-OPEN — it is NOT the trust gate (the gate is authorizeDetailed()
    // above, which already succeeded).
    if (blockedFields.length > 0) {
      const entry: IngestEntry = {
        function: fnName,
        purpose,
        scope,
        blockedFields,
        timestamp,
        count: 1,
        denyFields,
        ...(traceId !== undefined ? { trace_id: traceId } : {}),
      };
      void ingestSafe(client, [entry]);
    }
    return filtered;
  } catch {
    emitAudit(
      fnName,
      purpose,
      scope,
      denyFields,
      [],
      new Date().toISOString(),
      "full",
      traceId,
      "fail_closed",
      "internal_error",
    );
    return emptyFor(data);
  }
}

async function ingestSafe(
  client: AegisClient,
  entries: IngestEntry[],
): Promise<void> {
  try {
    await client.ingest(entries);
  } catch {
    // Telemetry failure swallowed — never break the data path.
  }
}

function runFilter(
  data: unknown,
  scope: ReadonlyArray<string>,
  denyFields: ReadonlyArray<string>,
  scopeTree: ReturnType<typeof parsePaths>,
  denyTree: ReturnType<typeof parsePaths>,
): unknown {
  const normalized = toFilterable(data);

  let filtered: unknown = normalized;
  if (scope.length > 0) {
    if (isPlainObject(normalized)) {
      filtered = filterDict(normalized, scopeTree, defaultWarn);
    } else if (Array.isArray(normalized)) {
      filtered = normalized.map((item) => {
        const it = toFilterable(item);
        return isPlainObject(it) ? filterDict(it, scopeTree, defaultWarn) : it;
      });
    } else {
      // Non-dict/non-list with scope: fail-closed empty.
      filtered = "";
    }
  }

  if (denyFields.length > 0) {
    if (isPlainObject(filtered)) {
      filtered = denyFilterDict(filtered, denyTree, defaultWarn);
    } else if (Array.isArray(filtered)) {
      filtered = filtered.map((item) => {
        const it = toFilterable(item);
        return isPlainObject(it) ? denyFilterDict(it, denyTree, defaultWarn) : it;
      });
    }
  }

  return filtered;
}

function isPromise(x: unknown): boolean {
  return (
    !!x
    && (typeof x === "object" || typeof x === "function")
    && typeof (x as { then?: unknown }).then === "function"
  );
}

function defaultWarn(msg: string): void {
  console.warn(msg);
}

// ── wrap() — direct value filter (returns ShieldResult) ───

export function wrap<T>(value: T, options: ShieldOptions): ShieldResult<T> {
  const purpose = options.purpose;
  const scope = options.scope ?? [];
  const denyFields = options.denyFields ?? [];
  if (!purpose || typeof purpose !== "string") {
    throw new AegisValidationError({
      code: "aegis.wrap.purpose.required",
      remediation: "Pass a non-empty string to `purpose` (e.g. \"customer_support\").",
      docs_url: aegisDocsUrl("aegis.wrap.purpose.required"),
      message: "wrap: purpose must be a non-empty string",
    });
  }
  const scopeTree = parsePaths(scope);
  const denyTree = parsePaths(denyFields, { broaderWins: true });
  const original = freezeSinglePass(value);
  const filtered = runFilter(value, scope, denyFields, scopeTree, denyTree) as T;
  return {
    data: filtered,
    mode: Mode.LITE,
    purpose,
    scope,
    filteredKeys: diffKeys(original, filtered),
  };
}

// ── Admin functions (mirror Python sync_policies / reset / refresh_token) ──

export async function syncPolicies(
  policies: Readonly<Record<string, { scope: ReadonlyArray<string>; denyFields: ReadonlyArray<string> }>>,
): Promise<void> {
  const client = getModuleClient();
  const entries: Record<string, { scope: ReadonlyArray<string>; denyFields: ReadonlyArray<string> }> = {};
  for (const [name, p] of Object.entries(policies)) {
    entries[name] = { scope: p.scope, denyFields: p.denyFields };
  }
  await client.policySync(entries);
}

export function refreshToken(newToken: string): void {
  const client = getModuleClient();
  client.setToken(newToken);
}

export function reset(): void {
  // Clear the test hook. Module client / history are reset via their
  // own helpers (resetModuleClient / resetStore) to avoid coupling.
  _testHook = null;
}
