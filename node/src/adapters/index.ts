// aegis-trust framework adapters — dedicated binders for agent frameworks.
//
//   import { shieldedTool, toLangChainTool } from "aegis-trust/adapters";
//
// `shieldedTool()` bakes a shield() over a data accessor and produces a
// framework-neutral tool descriptor; each `to<Framework>Tool` binder maps that
// descriptor onto a framework's native tool shape. The binders take no runtime
// dependency on the frameworks (LangChain's factory is injected; Vercel and
// CrewAI tools are plain objects), so they are version-tolerant and need no
// framework installed to import or test.

export { shieldedTool } from "./core.js";
export type { ShieldedTool, ShieldedToolSpec } from "./core.js";

export { shieldedStreamTool } from "./stream.js";
export type { ShieldedStreamTool, ShieldedStreamToolSpec } from "./stream.js";

export { toLangChainTool } from "./langchain.js";
export type { LangChainToolFactory } from "./langchain.js";

export { toVercelTool } from "./vercel.js";
export type { VercelTool } from "./vercel.js";

export { toCrewaiTool } from "./crewai.js";
export type { CrewaiTool } from "./crewai.js";
