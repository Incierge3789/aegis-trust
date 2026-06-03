// Streaming framework-adapter — shield a data accessor that yields a SEQUENCE
// of records, filtering each record at its boundary as it arrives.
//
// Why record-boundary, not token-boundary: shield()'s trust boundary is
// field-level minimum disclosure, and field filtering needs a COMPLETE object —
// you cannot safely strip `ssn` from a half-parsed record. So the streaming
// unit here is one fully-formed record, not a partial chunk or a token. A
// handler that produces rows/objects incrementally (paginated fetch, DB cursor,
// an upstream LLM emitting one JSON object per step) gets each record filtered
// and re-emitted the moment it is whole — without buffering the entire result
// first, which is exactly the limitation `shieldedTool()` has today.
//
// Mode scope — LITE only (v1). Streaming filters each record LOCALLY as it
// arrives. FULL mode's pre-execution `/check-access` gate cannot be honored on
// a stream: the gate must run BEFORE the data accessor executes (no side
// effects, no result-cardinality leak on deny), and FULL also carries an
// audit-completeness contract (every authorized access ingested before its data
// is released). A per-record gate would run the accessor first and emit one
// placeholder per matching row on deny — leaking how many rows matched and
// breaking the pre-execution guarantee `shieldedTool()` gives. So streaming
// REFUSES FULL fail-closed (empty stream, accessor never called) rather than
// silently downgrade the gate. FULL streaming (open-gate-then-stream + batched
// audit) is a tracked follow-up; for FULL today, use `shieldedTool()`.
//
// Trust contract for the supported (LITE) path: each record passes through the
// SAME shield() as the non-streaming adapter, constructed in LITE mode. There
// is no second filter implementation and no divergence in the fail-closed
// guarantee — LITE is a local, network-free field filter, so per-record cost is
// negligible.

import { detectMode } from "../client.js";
import { aegisDocsUrl, AegisValidationError } from "../errors.js";
import { shield } from "../shield.js";
import { Mode } from "../types.js";

/** Valid `mode` string values — used to reject mistyped modes (a trust boundary). */
const MODE_VALUES = new Set<string>(Object.values(Mode));

/**
 * Declarative spec for a streaming shielded tool. Identical to
 * {@link ShieldedToolSpec} except `handler` returns an (async or sync) iterable
 * of records rather than a single value, and `mode` is LITE-only (see below).
 * Each yielded record is filtered to `scope` / `denyFields` under `purpose`
 * before it leaves.
 */
export interface ShieldedStreamToolSpec<A = unknown> {
  /** Tool name exposed to the model (and used as the framework tool id). */
  readonly name: string;
  /** Natural-language description the model uses to decide when to call. */
  readonly description: string;
  /** Declared access purpose — the audit subject. */
  readonly purpose: string;
  /** Whitelist of fields each record may return. Either this or `denyFields`. */
  readonly scope?: ReadonlyArray<string>;
  /** Blacklist of fields each record must strip. Either this or `scope`. */
  readonly denyFields?: ReadonlyArray<string>;
  /**
   * shield mode. Streaming v1 supports `lite` only (local per-record
   * filtering). `auto` is accepted and is honored only while it resolves to
   * LITE — if AUTO resolves to FULL at run time (token set + backend
   * reachable), `stream()` refuses fail-closed (empty stream) rather than skip
   * the gate. Passing `full` explicitly throws `AegisValidationError`
   * (`aegis.shield.stream.full_unsupported`) at construction. Defaults to AUTO.
   */
  readonly mode?: Mode;
  /**
   * Framework-native argument schema (zod object, JSON Schema, …). Passed
   * through to the binder untouched — aegis-trust never parses, validates, or
   * inspects tool arguments.
   */
  readonly schema?: unknown;
  /**
   * The streaming data accessor. Receives the single structured tool-call
   * argument object and returns an iterable (or async iterable, or a promise
   * of one) of raw records. Each record's fields are filtered by shield(); the
   * arguments are not filtered.
   */
  readonly handler: (
    args: A,
  ) =>
    | AsyncIterable<unknown>
    | Iterable<unknown>
    | Promise<AsyncIterable<unknown> | Iterable<unknown>>;
}

/**
 * Framework-neutral streaming shielded tool. `stream()` returns an async
 * iterable that yields each record already filtered to the declared scope.
 *
 * Fail-closed contract (stream form of shield()'s "empty on error"):
 *  - If the effective mode is FULL (passed explicitly — caught at construction —
 *    or AUTO resolving to FULL at run time), `stream()` yields nothing and the
 *    handler is NEVER called: streaming does not support the FULL gate yet, and
 *    refusing beats silently downgrading it.
 *  - If the handler throws while *starting* the stream, `stream()` yields
 *    nothing — an empty stream, never a rejection.
 *  - If the underlying iterator throws *mid-stream*, iteration stops cleanly at
 *    that point: no further records, no thrown error, and the raw record that
 *    triggered the failure is never emitted. Records already yielded were
 *    filtered and are safe.
 *  - A single record that fails internal filtering resolves (via shield()) to a
 *    type-shaped empty value rather than leaking — consistent with the
 *    non-streaming adapter.
 *
 * As with `shieldedTool()`, a framework therefore observes a (possibly short or
 * empty) stream of safe results, never an exception that could carry withheld
 * data. Detect upstream outages inside the handler if you need retry/notify.
 */
export interface ShieldedStreamTool<A = unknown> {
  readonly name: string;
  readonly description: string;
  readonly schema?: unknown;
  /** Invoke the streaming accessor; yields each record filtered to scope (fail-closed: short/empty stream on error or FULL mode). */
  stream(args: A): AsyncIterable<unknown>;
}

/** Normalize a sync-or-async iterable to an async iterable for uniform `for await`. */
async function* toAsyncIterable(
  src: AsyncIterable<unknown> | Iterable<unknown>,
): AsyncIterable<unknown> {
  if (src != null && typeof (src as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
    yield* src as AsyncIterable<unknown>;
    return;
  }
  yield* src as Iterable<unknown>;
}

/**
 * Build a framework-neutral {@link ShieldedStreamTool} from a
 * {@link ShieldedStreamToolSpec}.
 *
 * Minimum-disclosure validation is deferred to shield(): if neither `scope`
 * nor `denyFields` is set, the underlying shield() construction throws
 * `AegisValidationError` (`aegis.shield.spec.required`) synchronously from here
 * — the streaming adapter, the non-streaming adapter, and the core share one
 * fail-closed contract and one error code. Passing `mode: Mode.FULL` explicitly
 * throws `aegis.shield.stream.full_unsupported` (see the mode note above).
 *
 * @example
 *   const rows = shieldedStreamTool({
 *     name: "customer_rows",
 *     description: "Stream customer records for a support session.",
 *     purpose: "customer_support",
 *     scope: ["name", "issue"],
 *     handler: async function* ({ q }: { q: string }) {
 *       for await (const row of db.cursor(q)) yield row;  // each row may carry ssn/email
 *     },
 *   });
 *   for await (const rec of rows.stream({ q: "open" })) {
 *     // rec is { name, issue } only — filtered as it arrives
 *   }
 */
export function shieldedStreamTool<A = unknown>(
  spec: ShieldedStreamToolSpec<A>,
): ShieldedStreamTool<A> {
  // Mode validation (parity with shield()'s S016 check). `spec.mode` is typed
  // as Mode, but JS/untyped callers can pass any string. A mis-cased / mistyped
  // value ("FULL", "Lite", "fulll") must NOT fall through to the LITE pin — that
  // would silently downgrade a developer who meant FULL into un-gated local
  // filtering. Mode is a trust boundary; refuse an invalid value loudly. The
  // guard below is pinned to LITE, so it never reaches shield()'s own mode
  // check — this is where the check has to happen.
  if (spec.mode !== undefined && !MODE_VALUES.has(spec.mode as string)) {
    throw new AegisValidationError({
      code: "aegis.shield.mode.invalid",
      remediation:
        `Set \`mode\` to one of "lite" | "full" | "auto" (lowercase), or use the Mode enum (e.g. Mode.LITE) to avoid typos. Omit \`mode\` to default to AUTO. Got ${JSON.stringify(spec.mode)}.`,
      docs_url: aegisDocsUrl("aegis.shield.mode.invalid"),
      message: `shieldedStreamTool: invalid mode ${JSON.stringify(spec.mode)} — expected "lite" | "full" | "auto"`,
    });
  }

  // Streaming v1 is LITE-only. Reject an explicit FULL request loudly at
  // construction (parity with shield()'s spec validation) rather than fail
  // closed silently at stream time — a developer who asked for FULL streaming
  // should learn it is unsupported, not get an empty stream.
  if (spec.mode === Mode.FULL) {
    throw new AegisValidationError({
      code: "aegis.shield.stream.full_unsupported",
      remediation:
        'Streaming supports LITE only for now. Use `mode: "lite"` for streaming, '
        + "or `shieldedTool()` (non-streaming) when you need the FULL /check-access gate.",
      docs_url: aegisDocsUrl("aegis.shield.stream.full_unsupported"),
      message: "shieldedStreamTool: FULL mode is not supported for streaming yet",
    });
  }

  // One shield() over an identity record-filter, reused per record, pinned to
  // LITE so it never attempts a per-record /check-access gate. Forced async to
  // keep a uniform await point. Name the filter `spec.name` so shield() records
  // the tool name (not "anonymous") across local history, the test hook,
  // by-function stats — symmetric with shieldedTool().
  const filterRecord = async (...args: unknown[]) => args[0];
  Object.defineProperty(filterRecord, "name", { value: spec.name, configurable: true });

  const guarded = shield({
    purpose: spec.purpose,
    scope: spec.scope ?? [],
    denyFields: spec.denyFields ?? [],
    mode: Mode.LITE,
  })(filterRecord as (...args: unknown[]) => unknown);

  return {
    name: spec.name,
    description: spec.description,
    schema: spec.schema,
    async *stream(args: A): AsyncIterable<unknown> {
      // AUTO can resolve to FULL at run time (token set + backend reachable).
      // Streaming cannot honor the FULL pre-execution gate, so refuse rather
      // than silently skip the authorization the operator configured. The
      // handler is NOT called — no side effects, no cardinality leak.
      if ((spec.mode ?? Mode.AUTO) === Mode.AUTO) {
        let resolved: "lite" | "full";
        try {
          resolved = await detectMode();
        } catch {
          // detectMode is itself best-effort; an undecidable detect means no
          // reachable FULL backend, i.e. LITE. Treat as LITE.
          resolved = "lite";
        }
        if (resolved === "full") {
          console.warn(
            `aegis-trust: streaming tool '${spec.name}' resolves to FULL mode, `
            + "which streaming does not support yet — failing closed to an empty "
            + 'stream (handler not called). Use `mode: "lite"` for streaming, or '
            + "shieldedTool() for the FULL gate.",
          );
          return;
        }
      }

      let src: AsyncIterable<unknown> | Iterable<unknown>;
      try {
        src = await spec.handler(args);
      } catch {
        // Handler threw before producing anything → fail closed to an empty
        // stream. The error is withheld: it could carry the very data the
        // shield is meant to keep from the model.
        return;
      }
      try {
        for await (const record of toAsyncIterable(src)) {
          // shield() (LITE) is itself fail-closed per record: a filter error
          // yields a type-shaped empty value, never the raw record. So this
          // yield is always a safe (filtered or empty) value.
          yield await guarded(record);
        }
      } catch {
        // The underlying iterator threw mid-stream. End iteration here without
        // re-throwing and without emitting the in-flight raw record — an
        // exception (or that record) could leak withheld fields. Records
        // already yielded were filtered and stand.
        return;
      }
    },
  };
}
