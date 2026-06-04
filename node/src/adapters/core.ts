// Framework-adapter core — turn a shielded data accessor into a normalized
// tool descriptor that each agent framework can consume.
//
// Design: shield() is the trust boundary; it filters the RETURN value of a
// data accessor to the declared purpose/scope before that value ever leaves.
// An agent framework's "tool" is just that accessor exposed to the model with
// a name, a description, and an argument schema. `shieldedTool()` bakes the
// shield in once and produces a framework-neutral descriptor; the per-framework
// binders (./langchain, ./vercel, ./crewai) map that descriptor onto each
// framework's native tool shape WITHOUT this package taking a dependency on —
// or pinning a version of — any of them.

import { shield } from "../shield.js";
import { Mode } from "../types.js";

/**
 * Declarative spec for a shielded tool. `handler` is your raw data accessor;
 * shield() filters its return value to `scope` / `denyFields` under the
 * declared `purpose` before it reaches the model.
 */
export interface ShieldedToolSpec<A = unknown> {
  /** Tool name exposed to the model (and used as the framework tool id). */
  readonly name: string;
  /** Natural-language description the model uses to decide when to call. */
  readonly description: string;
  /** Declared access purpose — the audit subject and (FULL mode) the gate key. */
  readonly purpose: string;
  /** Whitelist of fields the tool may return. Either this or `denyFields`. */
  readonly scope?: ReadonlyArray<string>;
  /** Blacklist of fields the tool must strip. Either this or `scope`. */
  readonly denyFields?: ReadonlyArray<string>;
  /** shield mode (`lite` | `full` | `auto`). Defaults to AUTO via shield(). */
  readonly mode?: Mode;
  /**
   * Framework-native argument schema (zod object, JSON Schema, …). Passed
   * through to the binder untouched — aegis-trust never parses, validates, or
   * inspects tool arguments; argument validation stays the framework's job.
   */
  readonly schema?: unknown;
  /**
   * The data accessor. Receives the single structured tool-call argument
   * object the framework passes (`run(args)` / `call(args)` forward exactly one
   * argument) and returns the raw record(s). Its return value is what shield()
   * filters — the arguments are not filtered.
   */
  readonly handler: (args: A) => unknown | Promise<unknown>;
  /**
   * Serialize the filtered value to the string a text-only tool runner
   * expects. Defaults to JSON.stringify. Only used by `call()` / string-based
   * frameworks (e.g. LangChain); object-based runners (Vercel, CrewAI port)
   * use `run()` and serialize themselves.
   */
  readonly serialize?: (filtered: unknown) => string;
}

/**
 * Framework-neutral shielded tool descriptor. Hand it to a binder, or use it
 * directly: `run()` returns the filtered value (for runners that accept a
 * structured return) and `call()` returns it serialized to a string (for
 * runners that require text).
 *
 * Fail-closed contract (inherited from shield()): a handler error, a denied /
 * unreachable FULL-mode gate, or a serializer error resolves to a type-shaped
 * **empty value** (e.g. `""`), never a thrown exception. The promise does not
 * reject. A framework therefore sees an empty tool result, not a failure, and
 * will not auto-retry on a shielded tool error — by design, because an
 * exception can carry the very data the shield is withholding. Detect outages
 * inside the handler (before returning) if you need retry/notify behaviour.
 */
export interface ShieldedTool<A = unknown> {
  readonly name: string;
  readonly description: string;
  readonly schema?: unknown;
  /** Invoke the shielded accessor with the single tool-call argument; resolves to the filtered value (fail-closed empty on error). */
  run(args: A): Promise<unknown>;
  /** Invoke the shielded accessor with the single tool-call argument; resolves to the filtered value serialized to a string (fail-closed `""` on error). */
  call(args: A): Promise<string>;
}

/**
 * Build a framework-neutral {@link ShieldedTool} from a {@link ShieldedToolSpec}.
 *
 * Minimum-disclosure validation is deferred to shield(): if neither `scope`
 * nor `denyFields` is set, the underlying shield() call throws
 * `AegisValidationError` (`aegis.shield.spec.required`) synchronously from
 * here — the adapter and the core share one fail-closed contract and one
 * error code rather than re-implementing the check.
 *
 * @example
 *   const lookup = shieldedTool({
 *     name: "customer_lookup",
 *     description: "Look up a customer record by id for support.",
 *     purpose: "customer_support",
 *     scope: ["name", "issue"],
 *     handler: async ({ id }: { id: string }) => db.fetch(id),
 *   });
 *   await lookup.run({ id: "C-1001" });  // → { name, issue } only
 */
export function shieldedTool<A = unknown>(spec: ShieldedToolSpec<A>): ShieldedTool<A> {
  // The accessor is forced `async` so AUTO/FULL mode has a pre-execution await
  // point for the /check-access gate (shield refuses FULL on a sync function).
  // It is typed `(...args: unknown[]) => unknown` to satisfy shield()'s wrapper
  // signature; the single tool-call argument arrives as args[0].
  const accessor = async (...args: unknown[]) => spec.handler(args[0] as A);
  // Name the accessor `spec.name` so shield() records the tool name (not
  // "anonymous") across local history, the test hook, by-function stats, and
  // FULL-mode audit ingest — otherwise every adapter tool is indistinguishable
  // in the audit trail. shield() reads `fn.name` when it wraps. (cross-review
  // consensus, codex+cursor.)
  Object.defineProperty(accessor, "name", { value: spec.name, configurable: true });

  const guarded = shield({
    purpose: spec.purpose,
    // Pass the spec fields through verbatim (do NOT default to []). shield()
    // distinguishes an explicitly-provided empty scope (valid: discloses
    // nothing) from an absent spec (refused, minimum disclosure). Defaulting to
    // [] here would mask that distinction and defer no validation.
    ...(spec.scope !== undefined ? { scope: spec.scope } : {}),
    ...(spec.denyFields !== undefined ? { denyFields: spec.denyFields } : {}),
    ...(spec.mode !== undefined ? { mode: spec.mode } : {}),
  })(accessor as (...args: unknown[]) => unknown);

  const serialize = spec.serialize ?? ((v: unknown) => JSON.stringify(v));

  return {
    name: spec.name,
    description: spec.description,
    schema: spec.schema,
    async run(args: A): Promise<unknown> {
      return guarded(args);
    },
    async call(args: A): Promise<string> {
      const filtered = await guarded(args);
      try {
        return serialize(filtered);
      } catch {
        // A serializer error must not propagate raw past the shield — the
        // exception could carry the filtered value in its message. Fail closed
        // to an empty string, symmetric with shield()'s handler-throw path.
        // Warn (naming the tool, withholding the error) so the integration bug
        // stays diagnosable without leaking the value the error may carry.
        // (cross-review: agy.)
        console.warn(
          `aegis-trust: tool '${spec.name}' serializer threw — failing closed `
          + `to "". The error is withheld to avoid leaking the value it may carry.`,
        );
        return "";
      }
    },
  };
}
