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
//   - FULL: pre-call /check-access trust gate, THEN filter + ingest. The
//           gate runs before the wrapped function — a denied / unreachable /
//           503 authorization never invokes it. FULL requires an `async`
//           function (it has no pre-execution await point otherwise).
//   - AUTO: detect — FULL if AEGIS_TOKEN set and backend reachable, else LITE

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

  // Minimum disclosure (parity with Python shield.py:761-774). An empty spec
  // — neither scope (whitelist) nor denyFields (blacklist) — would return the
  // wrapped function's data entirely unfiltered, leaking every field. Refuse
  // it loudly rather than fail open. S015 P0-1 / H5 / H9.
  // (Python additionally falls back to an aegis.yaml purpose policy here; that
  // lookup is async in Node and cannot run in this sync factory — Node
  // requires an explicit call-site spec instead. Safe-direction divergence,
  // tracked as a follow-up, not a leak.)
  if (scope.length === 0 && denyFields.length === 0) {
    throw new AegisValidationError({
      code: "aegis.shield.spec.required",
      remediation:
        "Pass either `scope` (whitelist, e.g. scope: [\"name\", \"email\"]) or `denyFields` (blacklist, e.g. denyFields: [\"ssn\"]). An empty spec returns all data unfiltered.",
      docs_url: aegisDocsUrl("aegis.shield.spec.required"),
      message: "shield: either scope or denyFields is required (minimum disclosure)",
    });
  }

  const scopeTree = parsePaths(scope);
  const denyTree = parsePaths(denyFields, { broaderWins: true });

  return function wrap<F extends (...args: unknown[]) => unknown>(fn: F): F {
    const fnName = fn.name || "anonymous";

    // FULL / AUTO on an async function: the /check-access trust gate (and,
    // for AUTO, mode detection) runs BEFORE the protected function executes.
    // A denied / unreachable / 503 authorization returns without ever
    // invoking `fn` — the gate prevents side effects, it does not merely
    // discard their result.
    async function runGatedAsync(thisArg: unknown, args: unknown[]): Promise<unknown> {
      const mode = await resolveMode(requestedMode);
      if (mode === Mode.LITE) {
        // AUTO degraded to LITE (no token / backend unreachable). LITE has
        // no trust gate, so running the function here is correct.
        let out: unknown;
        try {
          out = await fn.apply(thisArg, args);
        } catch (err) {
          return failClosedOnThrow(purpose, scope, denyFields, fnName, "lite", err);
        }
        return applyAndAuditLite(out, scope, denyFields, scopeTree, denyTree, purpose, fnName);
      }
      return gateAndRunFull(
        fn as (...a: unknown[]) => unknown,
        thisArg,
        args,
        scope,
        denyFields,
        scopeTree,
        denyTree,
        purpose,
        fnName,
      );
    }

    const wrapped = function (this: unknown, ...args: unknown[]) {
      // ── LITE ──────────────────────────────────────────────
      // No trust gate, no mode detection. Call the function directly and
      // preserve its sync-or-async return shape.
      if (requestedMode === Mode.LITE) {
        let out: unknown;
        try {
          out = fn.apply(this, args);
        } catch (err) {
          return failClosedOnThrow(purpose, scope, denyFields, fnName, "lite", err);
        }
        if (isPromise(out)) {
          return (out as Promise<unknown>).then(
            (resolved) =>
              applyAndAuditLite(resolved, scope, denyFields, scopeTree, denyTree, purpose, fnName),
            (err) => failClosedOnThrow(purpose, scope, denyFields, fnName, "lite", err),
          );
        }
        return applyAndAuditLite(out, scope, denyFields, scopeTree, denyTree, purpose, fnName);
      }

      // ── explicit FULL on a non-async function ─────────────
      // FULL gates execution behind an awaited /check-access authorization.
      // A function not declared `async` gives the wrapper no pre-execution
      // await point, so it cannot be gated before its side effects run.
      // Refuse it loudly rather than silently run un-gated LITE semantics
      // under a "full" label. T-SDK-FULL-GATE-01.
      if (requestedMode === Mode.FULL && !isAsyncFn(fn)) {
        throw new AegisValidationError({
          code: "aegis.shield.mode.sync_full_unsupported",
          remediation:
            "Mode.FULL gates execution behind an awaited /check-access authorization. Declare the wrapped function `async` for FULL, or use Mode.LITE for synchronous functions.",
          docs_url: aegisDocsUrl("aegis.shield.mode.sync_full_unsupported"),
          message: "shield: Mode.FULL requires an async wrapped function",
        });
      }

      // ── AUTO on a non-async function ──────────────────────
      // AUTO can only reach FULL when there is a pre-execution await point.
      // A non-async function degrades to LITE — preserve the sync return.
      if (requestedMode === Mode.AUTO && !isAsyncFn(fn)) {
        let out: unknown;
        try {
          out = fn.apply(this, args);
        } catch (err) {
          return failClosedOnThrow(purpose, scope, denyFields, fnName, "lite", err);
        }
        if (isPromise(out)) {
          return (out as Promise<unknown>).then(
            (resolved) =>
              applyAndAuditLite(resolved, scope, denyFields, scopeTree, denyTree, purpose, fnName),
            (err) => failClosedOnThrow(purpose, scope, denyFields, fnName, "lite", err),
          );
        }
        return applyAndAuditLite(out, scope, denyFields, scopeTree, denyTree, purpose, fnName);
      }

      // ── FULL / AUTO on an async function ──────────────────
      // Gate first, run the protected function only on a granted authz.
      return runGatedAsync(this, args);
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

// Fail-closed disposition when the protected function itself throws. Parity
// with Python (shield.py:848 / :876 / :921), which catches the wrapped
// function's exception and returns "" rather than letting it propagate. A
// thrown error can carry PII in its message/stack; re-raising it raw would
// leak that data past the shield. Return a safe empty and record the
// fail-closed outcome. S015 P0-3.
function failClosedOnThrow(
  purpose: string,
  scope: ReadonlyArray<string>,
  denyFields: ReadonlyArray<string>,
  fnName: string,
  modeStr: string,
  err?: unknown,
): unknown {
  // Diagnostic: name the function and the error TYPE so a genuine bug in the
  // wrapped function is debuggable, WITHOUT echoing the error message/stack
  // (which can carry the very PII we are failing closed to contain). S015.
  const errType = err instanceof Error ? err.constructor.name : typeof err;
  console.warn(
    `aegis-trust: wrapped function '${fnName}' threw (${errType}) — failing `
    + `closed (mode=${modeStr}). The error is not propagated; its message is `
    + `withheld to avoid leaking any data it carries.`,
  );
  emitAudit(
    fnName,
    purpose,
    scope,
    denyFields,
    [],
    new Date().toISOString(),
    modeStr,
    getTraceContext()?.traceId,
    "fail_closed",
    "wrapped_fn_error",
  );
  return "";
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
// protected function runs. The protected function is invoked ONLY after
// authorization is granted; a denied / unreachable / 503 outcome returns
// without ever calling it (no side effects). The authorization call is the
// trust gate. Audit ingest is post-authorization telemetry (fire-and-forget,
// fail-open) — never the gate.
async function gateAndRunFull(
  fn: (...a: unknown[]) => unknown,
  thisArg: unknown,
  args: unknown[],
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
  // gateway-unreachable / network error all yield allowed:false. The
  // protected function has NOT run at this point — a non-grant returns
  // before it ever does.
  let authz: { allowed: boolean; reason: string };
  try {
    authz = await client.authorizeDetailed(purpose, scope);
  } catch {
    // Defensive: authorizeDetailed is itself fail-closed and should not
    // throw — but an unexpected throw must never grant access.
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
    // The protected function was NEVER invoked — there is no return shape
    // to mirror, so the fail-closed value is a bare null.
    return emptyFor(undefined);
  }

  // Authorized — only now is the protected function executed. If it throws,
  // fail closed: the exception can carry PII in its message/stack, so we
  // return a safe empty and record the fail-closed outcome rather than let
  // it propagate raw past the shield (parity with Python shield.py:921-929).
  // S015 P0-3.
  let data: unknown;
  try {
    data = await fn.apply(thisArg, args);
  } catch (err) {
    return failClosedOnThrow(purpose, scope, denyFields, fnName, "full", err);
  }

  // Freeze + filter; an internal error anywhere here is fail-closed → a
  // type-shaped safe empty (the function ran, so `data` exists and its
  // broad shape can be mirrored; emptyFor inspects only that shape, safe
  // even with a throwing getter on `data`).
  try {
    const original = freezeSinglePass(data);
    const filtered = runFilter(original, scope, denyFields, scopeTree, denyTree);
    const blockedFields = diffKeys(original, filtered);
    const timestamp = new Date().toISOString();

    // FULL-mode audit ingest is part of the AO-003 audit-completeness
    // contract, NOT best-effort telemetry. Parity with Python
    // (shield.py:1017-1043): EVERY authorized FULL access is ingested
    // (unconditionally, not only when fields were blocked), and the filtered
    // data is released to the caller ONLY after the audit record is durably
    // accepted. The `allow` audit is emitted AFTER a successful ingest — never
    // before — so a withheld (ingest-failed) access is never recorded as
    // allowed. If ingest fails, fail closed → a type-shaped safe empty
    // mirroring the filtered shape, and a single `fail_closed`/`ingest_failed`
    // record. S015 align-audit-ingest (Direction A: Node→Python).
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
    try {
      await client.ingest([entry]);
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
        "ingest_failed",
      );
      return emptyFor(filtered);
    }
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
        // A scalar element carries no named field for the blacklist to act
        // on — fail-closed rather than pass it raw (parity with Python
        // `_deny_filter_result`). S015 P0-2 / H6.
        return isPlainObject(it) ? denyFilterDict(it, denyTree, defaultWarn) : emptyFor(it);
      });
    } else {
      // Non-object, non-array value under a deny spec: there is nothing for
      // the blacklist to remove, so passing it through would leak the raw
      // value. Fail-closed, symmetric with the scope branch above (which
      // sets `filtered = ""` for the same shape). S015 P0-2 / H10.
      filtered = emptyFor(filtered);
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

// True only for functions declared `async`. FULL/AUTO need a pre-execution
// await point to run the /check-access gate before the function executes;
// `async` is the one declaration form that guarantees one. A plain function
// that merely returns a Promise is not gateable before its body runs.
function isAsyncFn(fn: unknown): boolean {
  return (
    typeof fn === "function"
    && (fn as { constructor?: { name?: string } }).constructor?.name === "AsyncFunction"
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
  // Minimum disclosure (parity with shield()/Python). An empty spec would
  // return `value` entirely unfiltered. S015 P0-1 / H5.
  if (scope.length === 0 && denyFields.length === 0) {
    throw new AegisValidationError({
      code: "aegis.wrap.spec.required",
      remediation:
        "Pass either `scope` (whitelist) or `denyFields` (blacklist). An empty spec returns all data unfiltered.",
      docs_url: aegisDocsUrl("aegis.wrap.spec.required"),
      message: "wrap: either scope or denyFields is required (minimum disclosure)",
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
