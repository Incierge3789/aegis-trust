// Trace context propagation for aegis-trust.
//
// `withTraceContext({ traceId }, fn)` sets a Node AsyncLocalStorage trace
// for the duration of `fn` (sync or async). Any `shield()`-wrapped call
// inside reads `getTraceContext()` and emits the `traceId` into the audit
// record, so an agent reasoning step → SDK call → local history JSONL are
// linked end-to-end by a single trace id (OTel-compatible semantics).

import { AsyncLocalStorage } from "node:async_hooks";

import { aegisDocsUrl, AegisValidationError } from "./errors.js";

export interface TraceContext {
  readonly traceId: string;
  readonly parentId?: string;
}

const _traceStorage = new AsyncLocalStorage<TraceContext>();

// Cross-review round 3 P0-6: validate traceId to prevent secrets being
// persisted into the audit JSONL. Allow printable ASCII (id-like only) and
// cap length so a stray Bearer token / API key cannot be passed as a trace.
const TRACE_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

function assertTraceId(traceId: unknown): asserts traceId is string {
  if (typeof traceId !== "string" || !TRACE_ID_RE.test(traceId)) {
    throw new AegisValidationError({
      code: "aegis.trace.traceId.invalid",
      remediation:
        "traceId must be 1-128 chars of [A-Za-z0-9._:-]. Generate one with `newTraceId()`. Never pass secrets (Bearer tokens, API keys) as traceId — the audit JSONL is not a secret store.",
      docs_url: aegisDocsUrl("aegis.trace.traceId.invalid"),
      message: "withTraceContext: traceId must match [A-Za-z0-9._:-]{1,128}",
    });
  }
}

export function getTraceContext(): TraceContext | undefined {
  return _traceStorage.getStore();
}

export function withTraceContext<R>(ctx: TraceContext, fn: () => R): R {
  assertTraceId(ctx.traceId);
  if (ctx.parentId !== undefined) {
    // parentId follows the same shape as traceId.
    if (typeof ctx.parentId !== "string" || !TRACE_ID_RE.test(ctx.parentId)) {
      throw new AegisValidationError({
        code: "aegis.trace.parentId.invalid",
        remediation: "parentId must be 1-128 chars of [A-Za-z0-9._:-] or omitted.",
        docs_url: aegisDocsUrl("aegis.trace.parentId.invalid"),
        message: "withTraceContext: parentId must match [A-Za-z0-9._:-]{1,128}",
      });
    }
  }
  return _traceStorage.run(ctx, fn);
}

// Convenience — generate a unique trace id (UUIDv4-ish) without bringing in
// a dependency. Deterministic-ish via crypto.randomUUID when available.
export function newTraceId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  // Fallback: timestamp + random.
  return `aegis-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
