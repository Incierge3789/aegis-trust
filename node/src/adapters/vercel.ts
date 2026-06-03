// Vercel AI SDK binder. Maps a ShieldedTool onto an AI SDK tool object.
//
// The AI SDK tool is a plain object `{ description, <schemaKey>, execute }`, so
// we construct it directly — no import of `ai` and no version pin. The SDK
// serializes the tool's return value itself, so `execute` returns the filtered
// object from `run()` rather than a JSON string.

import type { ShieldedTool } from "./core.js";

/** A Vercel AI SDK tool object. The schema lives under a version-dependent key. */
export interface VercelTool {
  description: string;
  execute: (args: unknown) => Promise<unknown>;
  [schemaKey: string]: unknown;
}

/**
 * Bind a {@link ShieldedTool} to a Vercel AI SDK tool object.
 *
 * The schema key changed across AI SDK majors: `parameters` (v3 / v4) →
 * `inputSchema` (v5+). Defaults to `inputSchema`; pass
 * `{ schemaKey: "parameters" }` for AI SDK v4 and earlier.
 *
 * @example
 *   import { z } from "zod";
 *   import { shieldedTool, toVercelTool } from "aegis-trust/adapters";
 *
 *   const lookup = shieldedTool({
 *     name: "customer_lookup",
 *     description: "Look up a customer record by id for support.",
 *     purpose: "customer_support",
 *     scope: ["name", "issue"],
 *     schema: z.object({ id: z.string() }),
 *     handler: async ({ id }: { id: string }) => db.fetch(id),
 *   });
 *
 *   const result = await generateText({
 *     model,
 *     tools: { customer_lookup: toVercelTool(lookup) },
 *     prompt: "...",
 *   });
 *
 * @param t - the shielded tool descriptor.
 * @param opts.schemaKey - the object key the schema is placed under (default `"inputSchema"`).
 */
export function toVercelTool(t: ShieldedTool, opts: { schemaKey?: string } = {}): VercelTool {
  const schemaKey = opts.schemaKey ?? "inputSchema";
  const out: VercelTool = {
    description: t.description,
    execute: (args: unknown) => t.run(args),
  };
  if (t.schema !== undefined) {
    out[schemaKey] = t.schema;
  }
  return out;
}
