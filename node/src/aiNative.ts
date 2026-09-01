// AI-native interposition layer (Layer 2) — the §8 product surface.
//
// The wire-floor client methods (toolCall / capabilityMint / streamOpen …)
// are the contract FLOOR, not the product: an SDK where the developer must
// REMEMBER to call toolCall() before each tool use is fail-open by
// forgetting. This module puts the boundary IN the call path (AO-001 —
// errors structurally impossible — applied to the SDK):
//
// - guardTool()  — the FULL-strength sibling of LITE's shield(): the same
//   wrapper developer experience, but every invocation of the wrapped tool
//   is decided by the boundary (POST /tool-call) BEFORE it runs. Deny /
//   outage / error → the tool never runs and the call resolves null (the
//   shield convention: fail closed, never throw).
// - delegate()   — mints a (narrowing) child capability at the sub-agent
//   spawn boundary and attaches it to every guarded call inside the scope
//   via AsyncLocalStorage. Developers never hand-carry tokens (they leak,
//   they log). A failed mint DENIES the whole window — running the child
//   un-narrowed would be a widening.
// - streamSession() — a managed continuous-authz session that owns the
//   background heartbeat and INTERRUPTS the agent (abort signal + rejected
//   session promise + callback) the moment the boundary revokes. A revoked
//   stream must stop the agent, not wait to be polled.
//
// Wire contract: boundary-core docs/AI_NATIVE_V1_CONTRACT.md (frozen
// 2026-07-03, additive-only). Python parity: aegis_trust/ai_native.py —
// error codes are identical across the two SDKs.

import {
  DELEGATION_DENIED,
  type DelegationGrant,
  capabilityStorage,
  currentCapability,
  currentCapabilityFor,
  delegationDenied,
} from "./delegationContext.js";
import { AegisClient, getModuleClient } from "./client.js";
import type { CapabilityGrant } from "./client.js";
import {
  AegisStreamDeniedError,
  AegisStreamRevokedError,
  AegisValidationError,
  aegisDocsUrl,
} from "./errors.js";

// The delegation store lives in delegationContext.ts: client.ts must read it
// too (checkBoundary attaches the token), and this module imports client.ts,
// so keeping the store here would close an import cycle. `currentCapability`
// is re-exported to hold the public API surface unchanged.
export { currentCapability };

/** `owner` param → AEGIS_OWNER → AEGIS_AGENT_ID (the mcp-proxy resolution
 * order). null means unresolvable — the caller denies. */
function resolveOwner(owner?: string): string | null {
  if (owner) return owner;
  return (
    process.env.AEGIS_OWNER?.trim()
    || process.env.AEGIS_AGENT_ID?.trim()
    || null
  );
}

// ── guardTool — per-tool-call interposition ─────────────────────────

export interface GuardToolOptions {
  /** Why the agent invokes this tool (decided by the boundary). */
  readonly purpose: string;
  /** Boundary tool name; defaults to the wrapped function's name. */
  readonly tool?: string;
  /** principal.owner for the gate; defaults to AEGIS_OWNER then
   * AEGIS_AGENT_ID (unresolvable → deny). */
  readonly owner?: string;
  /** Optional declared field set (data_ref.field_set). */
  readonly fields?: ReadonlyArray<string>;
  readonly sessionId?: string;
  /** Optional egress intent (e.g. "llm:anthropic"). */
  readonly destination?: string;
  /** Explicit client (defaults to the module client). */
  readonly client?: AegisClient;
}

/**
 * Wrap a tool function so EVERY invocation is decided at the boundary
 * before it runs — the FULL-strength sibling of LITE's `shield()`.
 *
 * Each call first drives POST /tool-call (fail-closed: transport error,
 * non-200, malformed body, non-passing outcome, or an unledgered decision
 * is a deny). On deny the function is NEVER invoked and the call resolves
 * `null` — the shield convention (nothing to catch, nothing to forget).
 * Arguments never leave the process — refs and labels only.
 *
 * An enclosing `delegate()` scope attaches its capability automatically; a
 * DENIED scope (failed mint) denies locally without a gateway round-trip.
 * If the wrapped function itself throws after the grant, the error is
 * withheld (it can carry the very data the boundary governs) and the call
 * resolves `null`.
 *
 * @example
 * const query = guardTool({ purpose: "customer_data" })(queryBusinessData);
 * const rows = await query("acme");   // null when denied
 */
export function guardTool(options: GuardToolOptions) {
  if (!options.purpose || typeof options.purpose !== "string") {
    throw new AegisValidationError({
      code: "aegis.guard_tool.purpose.required",
      remediation: 'Pass a non-empty string to `purpose`, e.g. "customer_data".',
      docs_url: aegisDocsUrl("aegis.guard_tool.purpose.required"),
      message: "guardTool: purpose must be a non-empty string",
    });
  }
  if (options.tool !== undefined && (typeof options.tool !== "string" || options.tool === "")) {
    throw new AegisValidationError({
      code: "aegis.guard_tool.tool.invalid",
      remediation: "Pass a non-empty `tool` name, or omit it to use the function name.",
      docs_url: aegisDocsUrl("aegis.guard_tool.tool.invalid"),
      message: "guardTool: tool must be a non-empty string when given",
    });
  }
  if (options.fields !== undefined && !Array.isArray(options.fields)) {
    throw new TypeError("fields must be an array of strings");
  }

  return function guard<F extends (...args: never[]) => unknown>(
    fn: F,
  ): (...args: Parameters<F>) => Promise<Awaited<ReturnType<F>> | null> {
    const fnName = fn.name || "anonymous";
    const toolName = options.tool ?? fnName;

    const wrapped = async function (
      this: unknown,
      ...args: Parameters<F>
    ): Promise<Awaited<ReturnType<F>> | null> {
      if (delegationDenied()) {
        console.warn(
          `aegis-trust: guardTool — delegation window is denied; `
          + `'${fnName}' not invoked (fail-closed)`,
        );
        return null;
      }
      const owner = resolveOwner(options.owner);
      if (owner === null) {
        console.warn(
          "aegis-trust: guardTool — no owner resolvable (owner option / "
          + `AEGIS_OWNER / AEGIS_AGENT_ID all unset); '${fnName}' not `
          + "invoked (fail-closed)",
        );
        return null;
      }
      let allowed = false;
      try {
        // Same origin binding as checkBoundary: read the ambient token for THIS
        // client only, so a token minted against one boundary is never sent to
        // another (cross-review, codex 2026-07-29, severity high).
        const gc = options.client ?? getModuleClient();
        allowed = await gc.toolAllowed({
          tool: toolName,
          purpose: options.purpose,
          owner,
          fields: options.fields,
          sessionId: options.sessionId,
          destination: options.destination,
          capability: currentCapabilityFor(gc.baseUrl) ?? undefined,
        });
      } catch {
        // toolAllowed is itself fail-closed and non-throwing; an unexpected
        // throw (e.g. client construction) must never grant access.
        allowed = false;
      }
      if (!allowed) {
        console.warn(
          `aegis-trust: guardTool — tool=${toolName} purpose=${options.purpose} `
          + `denied by /tool-call; '${fnName}' not invoked (fail-closed)`,
        );
        return null;
      }
      try {
        return (await fn.apply(this, args)) as Awaited<ReturnType<F>>;
      } catch {
        console.error(
          `aegis-trust: guardTool — '${fnName}' threw after gate grant; `
          + "resolving null (fail-closed). The error is withheld (it can "
          + "carry governed data).",
        );
        return null;
      }
    };
    Object.defineProperty(wrapped, "name", { value: fnName });
    return wrapped;
  };
}

// ── delegate — automatic capability propagation at spawn boundaries ──

export interface DelegateOptions {
  readonly forAgent: string;
  readonly purposes: ReadonlyArray<string>;
  readonly scope?: ReadonlyArray<string>;
  readonly tools?: ReadonlyArray<string>;
  readonly ttlSecs?: number;
  /** Revoke the minted token when the scope exits (default true) — the
   * delegation window closes with the block, transitively cutting matching
   * open streams. Pass false when the token must outlive the scope (its
   * exp still bounds it). */
  readonly revokeOnExit?: boolean;
  readonly client?: AegisClient;
}

/**
 * Mint a child capability at the sub-agent spawn boundary and attach it to
 * every guarded call inside `fn` (via AsyncLocalStorage — no hand-carried
 * tokens). Nesting narrows: an enclosing delegate() scope's token becomes
 * the parentCapability of the inner mint, so the boundary enforces that a
 * child can only NARROW its parent and revocation stays transitive.
 *
 * Fail-closed: if the mint is refused (widening, depth, revoked ancestor)
 * or unreachable, the window is DENIED — `fn` still runs (receiving null)
 * but every guardTool() call inside resolves null and streamSession()
 * refuses to open, without a gateway round-trip. Running the child WITHOUT
 * the narrowed token would silently widen its authority back to the
 * parent's role; denial is the only safe direction.
 *
 * @example
 * await delegate({ forAgent: "researcher", purposes: ["customer_data"] },
 *   async (grant) => runSubAgent(grant));
 */
export async function delegate<T>(
  options: DelegateOptions,
  fn: (grant: CapabilityGrant | null) => T | Promise<T>,
): Promise<T> {
  if (!options.forAgent || typeof options.forAgent !== "string") {
    throw new AegisValidationError({
      code: "aegis.delegate.for_agent.required",
      remediation: 'Pass the sub-agent identity, e.g. forAgent: "researcher-1".',
      docs_url: aegisDocsUrl("aegis.delegate.for_agent.required"),
      message: "delegate: forAgent must be a non-empty string",
    });
  }
  if (
    !Array.isArray(options.purposes)
    || options.purposes.length === 0
    || !options.purposes.every((p) => typeof p === "string" && p !== "")
  ) {
    throw new AegisValidationError({
      code: "aegis.delegate.purposes.required",
      remediation: 'Enumerate the delegated purposes, e.g. purposes: ["customer_data"].',
      docs_url: aegisDocsUrl("aegis.delegate.purposes.required"),
      message:
        "delegate: purposes must be a non-empty array of strings "
        + "(minimum disclosure — an unbounded delegation is refused)",
    });
  }

  const client = options.client ?? getModuleClient();
  let grant: CapabilityGrant | null = null;
  // The store carries the minting client's origin, not a bare token: a bearer
  // string alone can be picked up by any other client in the window and sent
  // to a different boundary (cross-review, codex 2026-07-29, severity high).
  let store: DelegationGrant | typeof DELEGATION_DENIED;
  if (delegationDenied()) {
    // A nested window inside an already-denied window stays denied —
    // minting from a denied parent would escape the fail-closed state.
    console.warn(
      "aegis-trust: delegate — enclosing delegation window is denied; "
      + `nested window forAgent=${options.forAgent} stays denied (fail-closed)`,
    );
    store = DELEGATION_DENIED;
  } else {
    try {
      grant = await client.capabilityMint({
        forAgent: options.forAgent,
        purposes: options.purposes,
        scope: options.scope,
        tools: options.tools,
        ttlSecs: options.ttlSecs,
        parentCapability: currentCapabilityFor(client.baseUrl) ?? undefined,
      });
      store = { token: grant.capability, origin: client.baseUrl };
    } catch {
      // Mint refused or unreachable. The error detail is withheld (fixed
      // strings only — house diagnostic discipline).
      console.warn(
        `aegis-trust: delegate — capability mint failed forAgent=${options.forAgent}; `
        + "the delegation window is DENIED (fail-closed): guarded calls "
        + "inside resolve null, stream sessions refuse to open",
      );
      store = DELEGATION_DENIED;
    }
  }
  try {
    return await capabilityStorage.run(store, () => fn(grant));
  } finally {
    if (grant !== null && options.revokeOnExit !== false) {
      try {
        await client.capabilityRevoke({ capability: grant.capability });
      } catch {
        console.warn(
          "aegis-trust: delegate — capability revoke on exit failed "
          + "(already expired/revoked, or gateway unreachable); the token's "
          + "exp still bounds it",
        );
      }
    }
  }
}

// ── streamSession — managed continuous authz ────────────────────────

export interface StreamSessionOptions {
  /** Heartbeat revalidation period in ms (default 5000). */
  readonly heartbeatIntervalMs?: number;
  /** Consecutive heartbeat transport failures counted as revocation
   * (`gateway_unavailable`, default 3) — an unverifiable stream is a
   * stopped stream, never a silently-unmonitored one. */
  readonly maxHeartbeatFailures?: number;
  /** Called once with the reason the moment the boundary revokes. */
  readonly onRevoke?: (reason: string) => void;
  readonly client?: AegisClient;
}

export interface StreamSessionHandle {
  readonly streamId: string;
  readonly decision: Record<string, unknown>;
  /** Aborted the moment the boundary revokes — pass to fetch/agent loops. */
  readonly signal: AbortSignal;
  readonly revoked: boolean;
  readonly revokedReason: string | null;
}

/**
 * Run `fn` under a managed continuous-authz session. The session owns the
 * whole lifecycle so the developer cannot get it wrong:
 *
 * - Open: POST /stream/open with the given Common Envelope (an enclosing
 *   delegate() capability is attached automatically). A deny — or a denied
 *   delegation window — throws AegisStreamDeniedError BEFORE `fn` runs.
 * - Heartbeat: background revalidation every heartbeatIntervalMs.
 * - Interrupt: the moment the boundary revokes, `session.signal` aborts,
 *   `onRevoke(reason)` fires, and the streamSession() promise rejects with
 *   AegisStreamRevokedError — the awaiting agent stops NOW, even if `fn`
 *   is still in flight. A revoked session can never look like a clean run.
 * - Close: a normal completion closes the stream (witnessed) best-effort.
 *
 * @example
 * const out = await streamSession(envelope, async (s) => {
 *   return runAgent({ signal: s.signal });
 * });
 */
export async function streamSession<T>(
  envelope: Record<string, unknown>,
  fn: (session: StreamSessionHandle) => T | Promise<T>,
  options: StreamSessionOptions = {},
): Promise<T> {
  if (
    envelope === null
    || typeof envelope !== "object"
    || Array.isArray(envelope)
    || Object.keys(envelope).length === 0
  ) {
    throw new AegisValidationError({
      code: "aegis.stream.envelope.required",
      remediation: "Pass the Common Envelope object used for /v1/decide.",
      docs_url: aegisDocsUrl("aegis.stream.envelope.required"),
      message:
        "streamSession: envelope must be a non-empty object "
        + "(a full Common Envelope — the same body /v1/decide takes)",
    });
  }
  const intervalMs = options.heartbeatIntervalMs ?? 5000;
  if (!(intervalMs > 0)) {
    throw new AegisValidationError({
      code: "aegis.stream.interval.invalid",
      remediation: "Pass a positive heartbeatIntervalMs (default 5000).",
      docs_url: aegisDocsUrl("aegis.stream.interval.invalid"),
      message: "streamSession: heartbeatIntervalMs must be > 0",
    });
  }
  const maxFailures = Math.max(1, options.maxHeartbeatFailures ?? 3);

  if (delegationDenied()) {
    throw new AegisStreamDeniedError({
      code: "aegis.stream.delegation_denied",
      remediation:
        "The delegate() mint failed, so everything inside the window is "
        + "denied. Fix the delegation (narrowing, depth, revoked ancestor) "
        + "or open the session outside the window.",
      docs_url: aegisDocsUrl("aegis.stream.delegation_denied"),
      message:
        "streamSession: the enclosing delegation window is denied — "
        + "the stream is not opened (fail-closed)",
    });
  }

  const client = options.client ?? getModuleClient();

  // Attach an enclosing delegation capability (never hand-carried).
  let body = envelope;
  // Origin-bound: a stream envelope is a send path too, so a token minted
  // against another boundary must not ride on it (cross-review, cursor
  // 2026-07-29). Python twin: ai_native.py _envelope_with_capability.
  const capability = currentCapabilityFor(client.baseUrl);
  if (capability !== null) {
    const delegation = {
      capability,
      ...((envelope.delegation as Record<string, unknown> | undefined) ?? {}),
    };
    body = { ...envelope, delegation };
  }

  let opened;
  try {
    opened = await client.streamOpen(body);
  } catch (err) {
    throw new AegisStreamDeniedError({
      code: "aegis.stream.open_failed",
      remediation:
        "The boundary was unreachable or returned a non-200. The agent "
        + "block did not run. Retry when the gateway recovers.",
      docs_url: aegisDocsUrl("aegis.stream.open_failed"),
      message: "streamSession: /stream/open failed — the session is denied (fail-closed)",
      cause: err,
    });
  }
  if (opened.stream === null || opened.stream === undefined) {
    throw new AegisStreamDeniedError({
      code: "aegis.stream.denied",
      remediation:
        "Gate on the decision: only PROTECTED / ACCESS_REDUCED AND ledgered "
        + "opens a stream. Check purpose/scope/role and any active ceremony "
        + "(duress / legal hold).",
      docs_url: aegisDocsUrl("aegis.stream.denied"),
      message:
        "streamSession: the boundary did not grant a stream "
        + "(denied or unledgered decision)",
    });
  }
  const streamId = opened.stream.stream_id;

  let revokedReason: string | null = null;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let failures = 0;
  const ac = new AbortController();

  let rejectRevoked: (err: AegisStreamRevokedError) => void = () => {};
  const revokedPromise = new Promise<never>((_, reject) => {
    rejectRevoked = reject;
  });

  const revokeNow = (reason: string): void => {
    if (revokedReason !== null) return;
    revokedReason = reason;
    console.warn(
      `aegis-trust: streamSession — stream ${streamId} revoked `
      + `(reason=${reason}); interrupting the agent`,
    );
    if (options.onRevoke) {
      try {
        options.onRevoke(reason);
      } catch {
        console.error(
          "aegis-trust: streamSession — onRevoke callback threw; "
          + "continuing with the interrupt (the revocation still stands)",
        );
      }
    }
    ac.abort(reason);
    rejectRevoked(
      new AegisStreamRevokedError({
        code: "aegis.stream.revoked",
        remediation:
          "Stop the work driven by this session. Re-open a session when "
          + "the revoking condition (duress / legal hold / delegation "
          + "expiry / revocation) is lifted.",
        docs_url: aegisDocsUrl("aegis.stream.revoked"),
        message:
          `streamSession: the boundary revoked the stream (reason=${reason}) `
          + "— the agent was stopped",
        reason,
      }),
    );
  };

  const beat = async (): Promise<void> => {
    if (stopped || revokedReason !== null) return;
    try {
      const status = await client.streamHeartbeat(streamId);
      if (stopped) return;
      failures = 0;
      if (status.status !== "ok") {
        revokeNow(status.reason ?? status.status);
        return;
      }
    } catch {
      if (stopped) return;
      failures += 1;
      if (failures >= maxFailures) {
        revokeNow("gateway_unavailable");
        return;
      }
    }
    timer = setTimeout(beat, intervalMs);
    timer.unref?.();
  };
  timer = setTimeout(beat, intervalMs);
  timer.unref?.();

  const session: StreamSessionHandle = {
    streamId,
    decision: opened.decision,
    signal: ac.signal,
    get revoked() {
      return revokedReason !== null;
    },
    get revokedReason() {
      return revokedReason;
    },
  };

  try {
    // Promise.race attaches handlers to both promises immediately, so a
    // late rejection from an in-flight `fn` after revocation is observed
    // (no unhandledRejection) but the revocation verdict stands.
    const result = await Promise.race([
      Promise.resolve().then(() => fn(session)),
      revokedPromise,
    ]);
    stopped = true;
    if (timer !== null) clearTimeout(timer);
    try {
      await client.streamClose(streamId);
    } catch {
      console.warn(
        "aegis-trust: streamSession — stream close failed (already cut by "
        + "a ceremony / revocation, or gateway unreachable)",
      );
    }
    return result;
  } catch (err) {
    stopped = true;
    if (timer !== null) clearTimeout(timer);
    if (revokedReason !== null) {
      // A revoked session can never look like a clean run — and never
      // masquerades as the block's own error.
      if (err instanceof AegisStreamRevokedError) throw err;
      throw new AegisStreamRevokedError({
        code: "aegis.stream.revoked",
        remediation:
          "Stop the work driven by this session. Re-open a session when "
          + "the revoking condition is lifted.",
        docs_url: aegisDocsUrl("aegis.stream.revoked"),
        message:
          `streamSession: the boundary revoked the stream (reason=${revokedReason}) `
          + "— the agent was stopped",
        reason: revokedReason,
        cause: err,
      });
    }
    // fn's own failure with no revocation: witnessed close, then propagate.
    try {
      await client.streamClose(streamId);
    } catch {
      console.warn(
        "aegis-trust: streamSession — stream close failed (already cut by "
        + "a ceremony / revocation, or gateway unreachable)",
      );
    }
    throw err;
  }
}
