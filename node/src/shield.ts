import {
  AegisClient,
  detectMode,
  getModuleClient,
} from "./client.js";
import { aegisDocsUrl, AegisValidationError } from "./errors.js";
import {
  denyFilterDict,
  diffKeys,
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
          return applyAndAudit(
            resolved,
            scope,
            denyFields,
            scopeTree,
            denyTree,
            purpose,
            fnName,
            mode,
          );
        });
      }
      // Sync path: cannot await detection. If FULL requested, run in LITE
      // semantics for filtering, then schedule async ingest.
      const syncMode = requestedMode === Mode.FULL ? Mode.FULL : Mode.LITE;
      return applyAndAudit(
        out,
        scope,
        denyFields,
        scopeTree,
        denyTree,
        purpose,
        fnName,
        syncMode,
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

function applyAndAudit(
  data: unknown,
  scope: ReadonlyArray<string>,
  denyFields: ReadonlyArray<string>,
  scopeTree: ReturnType<typeof parsePaths>,
  denyTree: ReturnType<typeof parsePaths>,
  purpose: string,
  fnName: string,
  mode: Mode,
): unknown {
  const original = freezeSinglePass(data);
  const filtered = runFilter(original, scope, denyFields, scopeTree, denyTree);

  const blockedFields = diffKeys(original, filtered);
  const timestamp = new Date().toISOString();
  const modeStr = mode === Mode.FULL ? "full" : "lite";
  const traceId = getTraceContext()?.traceId;

  // Test hook — synchronous side effect for assertions.
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

  // Local audit (AEGIS_HISTORY=1). trace_id linked from AsyncLocalStorage
  // so a single agent reasoning step → all shield calls within it share
  // one trace, end-to-end.
  recordIfEnabled({
    function: fnName,
    purpose,
    scope,
    denyFields,
    blockedFields,
    timestamp,
    mode: modeStr,
    ...(traceId !== undefined ? { trace_id: traceId } : {}),
  });

  // Full mode: best-effort async ingest. Fire-and-forget; ingest failure
  // never bubbles into caller (AO-002 fail-closed on filter, fail-open
  // on telemetry).
  if (mode === Mode.FULL && blockedFields.length > 0) {
    const client = getModuleClient();
    const entry: IngestEntry = {
      function: fnName,
      purpose,
      scope,
      blockedFields,
      timestamp,
      count: 1,
      denyFields,
      // Cross-review round 3 P0-4: thread trace_id onto the ingest payload
      // so the gateway audit chain is linked to the same trace as the local
      // JSONL — end-to-end correlation for both LITE and FULL.
      ...(traceId !== undefined ? { trace_id: traceId } : {}),
    };
    void ingestSafe(client, [entry]);
  }

  return filtered;
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
