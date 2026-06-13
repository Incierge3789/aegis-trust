// LlamaIndex.TS binder. Maps a ShieldedTool onto a LlamaIndex FunctionTool.
//
// The LlamaIndex `FunctionTool.from` factory is INJECTED by the caller rather
// than imported here, so aegis-trust takes no dependency on LlamaIndex.TS and
// is immune to its internal version churn — only the public
// `FunctionTool.from(fn, config)` factory signature has to hold.

import type { ShieldedTool } from "./core.js";

/**
 * Minimal structural type of `llamaindex`'s `FunctionTool.from` factory. The
 * wrapped function returns a string (LlamaIndex tool outputs are text the model
 * reads), which is exactly what `ShieldedTool.call()` produces.
 */
export type LlamaIndexToolFactory<R = unknown> = (
  fn: (input: unknown) => Promise<string> | string,
  config: { name: string; description: string; parameters?: unknown },
) => R;

/**
 * Bind a {@link ShieldedTool} to a LlamaIndex.TS FunctionTool.
 *
 * @example
 *   import { FunctionTool } from "llamaindex";
 *   import { shieldedTool, toLlamaIndexTool } from "aegis-trust/adapters";
 *
 *   const lookup = shieldedTool({
 *     name: "customer_lookup",
 *     description: "Look up a customer record by id for support.",
 *     purpose: "customer_support",
 *     scope: ["name", "issue"],
 *     handler: async ({ id }: { id: string }) => db.fetch(id),
 *   });
 *
 *   const liTool = toLlamaIndexTool(FunctionTool.from, lookup);  // hand to an agent
 *
 * @param factory - the framework's `FunctionTool.from` factory (dependency-injected).
 * @param t - the shielded tool descriptor.
 * @returns whatever the injected factory returns (a FunctionTool) — the return
 *   type is inferred from the factory, so typed callers can pass the result
 *   straight to an agent without a cast.
 */
export function toLlamaIndexTool<R>(factory: LlamaIndexToolFactory<R>, t: ShieldedTool): R {
  // LlamaIndex names the schema parameter `parameters` (a zod/JSON schema),
  // unlike LangChain's `schema`.
  return factory((input: unknown) => t.call(input), {
    name: t.name,
    description: t.description,
    ...(t.schema !== undefined ? { parameters: t.schema } : {}),
  });
}
