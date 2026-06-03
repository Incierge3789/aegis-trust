// CrewAI (Node port) binder. Maps a ShieldedTool onto the port's tool shape.
//
// The CrewAI Node port accepts plain `{ name, description, run }` tool objects
// (see node/examples/crewaiExample.ts), so we construct one directly — no
// import of `crewai` and no version pin. The port consumes the tool's return
// value directly, so `run` returns the filtered object from `ShieldedTool.run()`.

import type { ShieldedTool } from "./core.js";

/** A CrewAI (Node port) tool descriptor. */
export interface CrewaiTool {
  name: string;
  description: string;
  run: (args: unknown) => Promise<unknown>;
}

/**
 * Bind a {@link ShieldedTool} to a CrewAI (Node port) tool descriptor.
 *
 * Because the shield lives at the data layer, the same descriptor works for
 * any multi-agent framework that accepts a `{ name, description, run }` tool
 * (LangGraph, AutoGen.js, swarm, …) — give each agent its own purpose/scope
 * and the same record yields a different per-agent view.
 *
 * @example
 *   import { shieldedTool, toCrewaiTool } from "aegis-trust/adapters";
 *
 *   const supportLookup = shieldedTool({
 *     name: "customer_lookup_support",
 *     description: "Look up a customer for support work.",
 *     purpose: "customer_support",
 *     scope: ["name", "issue"],
 *     handler: async ({ id }: { id: string }) => db.fetch(id),
 *   });
 *
 *   const agent = new crew.Agent({ role: "...", tools: [toCrewaiTool(supportLookup)] });
 *
 * @param t - the shielded tool descriptor.
 */
export function toCrewaiTool(t: ShieldedTool): CrewaiTool {
  return {
    name: t.name,
    description: t.description,
    run: (args: unknown) => t.run(args),
  };
}
