// LangChain.js binder. Maps a ShieldedTool onto a LangChain StructuredTool.
//
// The LangChain `tool` factory is INJECTED by the caller rather than imported
// here, so aegis-trust takes no dependency on LangChain and is immune to its
// internal version churn — only the public `tool(func, config)` factory
// signature has to hold.

import type { ShieldedTool } from "./core.js";

/**
 * Minimal structural type of `@langchain/core/tools`' `tool` factory. The
 * wrapped function returns a string (LangChain tool outputs are text the model
 * reads), which is exactly what `ShieldedTool.call()` produces.
 */
export type LangChainToolFactory<R = unknown> = (
  func: (input: unknown) => Promise<string> | string,
  config: { name: string; description: string; schema?: unknown },
) => R;

/**
 * Bind a {@link ShieldedTool} to a LangChain.js StructuredTool.
 *
 * @example
 *   import { tool } from "@langchain/core/tools";
 *   import { shieldedTool, toLangChainTool } from "aegis-trust/adapters";
 *
 *   const lookup = shieldedTool({
 *     name: "customer_lookup",
 *     description: "Look up a customer record by id for support.",
 *     purpose: "customer_support",
 *     scope: ["name", "issue"],
 *     handler: async ({ id }: { id: string }) => db.fetch(id),
 *   });
 *
 *   const lcTool = toLangChainTool(tool, lookup);  // hand to AgentExecutor
 *
 * @param factory - the framework's `tool` factory (dependency-injected).
 * @param t - the shielded tool descriptor.
 * @returns whatever the injected `tool` factory returns (a StructuredTool) —
 *   the return type is inferred from the factory, so typed callers can pass the
 *   result straight to `AgentExecutor` without a cast.
 */
export function toLangChainTool<R>(factory: LangChainToolFactory<R>, t: ShieldedTool): R {
  return factory((input: unknown) => t.call(input), {
    name: t.name,
    description: t.description,
    ...(t.schema !== undefined ? { schema: t.schema } : {}),
  });
}
