#!/usr/bin/env node
// shield-proxy: MCP process-boundary enforcement point (canonical contract v0).
// Faithful port of python/src/aegis_trust/mcp_proxy.py.
//
//     host  <--stdio-->  aegis-mcp-proxy  <--stdio-->  real MCP server
//
// Every tools/call result (plus resources/read, prompts/get) is filtered to the
// policy's scope before the host's model sees it; unmapped tools are blocked
// fail-closed; JSON-RPC batches and non-JSON server stdout are dropped. A
// canonical v0 audit event (enforcement_point=mcp_proxy) is emitted per call.

import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import {
  CanonicalEmitter,
  CanonicalPolicy,
  CanonicalPurpose,
  ENFORCEMENT_MCP_PROXY,
  loadCanonicalPolicy,
} from "./canonical.js";
import { AegisClient, detectMode, getModuleClient } from "./client.js";
import { VERSION } from "./index.js";

const PROXY_RUNTIME = `mcp-proxy/${VERSION}`;

// Data-bearing server->host methods the proxy gates.
const GATED_METHODS = new Set(["tools/call", "resources/read", "prompts/get"]);

// FULL-mode per-call gate (the third PEP grows teeth). LITE keeps today's
// behavior; in FULL the proxy consults the gateway BEFORE forwarding a gated
// call, so a policy deny stops the tool from ever running. Gate kind is
// EXPLICIT (never auto-probed — a silent up/downgrade of the enforcement
// primitive is exactly the drift Aegis refuses):
//   check-access = @shield-parity purpose gate (every live gateway serves it);
//   tool-call    = AI-native per-tool-call gate (AI_NATIVE_V1_CONTRACT.md).
// Faithful mirror of python mcp_proxy.GatewayGate.
export class GatewayGate {
  constructor(
    private client: AegisClient,
    readonly kind: "check-access" | "tool-call",
    private owner: string,
  ) {}

  /** Returns [allowed, reasonCode]. Fail-closed on every error path. */
  async check(tool: string, purpose: CanonicalPurpose): Promise<[boolean, string]> {
    const scope = [...(purpose.scope ?? [])];
    if (this.kind === "tool-call") {
      // toolAllowed() is fail-closed internally (transport / non-200 /
      // malformed / non-passing / unledgered are all a deny).
      const allowed = await this.client.toolAllowed({
        tool,
        purpose: purpose.name,
        owner: this.owner,
        fields: scope,
      });
      return allowed ? [true, ""] : [false, "gateway_denied"];
    }
    // checkAccess (not authorize): authorize() swallows transport errors into
    // false, which would collapse "policy denied" and "gateway down" into one
    // audit reason. Both deny — but they must stay distinguishable.
    try {
      if (scope.length > 0) {
        for (const s of scope) {
          const resp = await this.client.checkAccess(purpose.name, [s]);
          if (resp.allowed !== true) return [false, "gateway_denied"];
        }
        return [true, ""];
      }
      const resp = await this.client.checkAccess(purpose.name, []);
      return resp.allowed === true ? [true, ""] : [false, "gateway_denied"];
    } catch {
      return [false, "gateway_unavailable"];
    }
  }
}

export class ShieldProxy {
  private pending = new Map<unknown, { tool: string; purpose: string }>();

  constructor(
    private policy: CanonicalPolicy,
    private emitter: CanonicalEmitter,
    private agentId: string,
    private sessionId: string | null = null,
    private gate: GatewayGate | null = null,
  ) {}

  private principal(): Record<string, unknown> {
    return { agent_id: this.agentId, session_id: this.sessionId, transport: "mcp" };
  }

  private blockReply(id: unknown, operation: string, reason: string): string {
    return (
      JSON.stringify({
        jsonrpc: "2.0",
        id: id ?? null,
        result: {
          content: [
            {
              type: "text",
              text: `Aegis shield-proxy: '${operation}' blocked (${reason}, fail-closed).`,
            },
          ],
          isError: true,
        },
      }) + "\n"
    );
  }

  // host -> server. Returns { forward, reply }; exactly one is set.
  // Async because the FULL gate awaits the gateway; LITE resolves immediately.
  async handleClientLine(line: string): Promise<{ forward?: string; reply?: string }> {
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      return { forward: line }; // not ours to judge; transport passthrough
    }
    if (Array.isArray(msg)) {
      // JSON-RPC batch: a batched response would bypass result filtering. No
      // batching in current MCP; fail-closed, never forward.
      this.emitter.emit({
        principal: this.principal(),
        purpose: "unknown",
        operation: "<batch>",
        decision: "deny",
        outcome: "blocked",
        reasonCode: "batch_rejected",
        blockedFields: [],
      });
      return { reply: this.blockReply(null, "<batch>", "batch_rejected") };
    }
    if (typeof msg !== "object" || msg === null) return { forward: line };
    const m = msg as Record<string, unknown>;
    const method = m.method as string | undefined;
    if (!method || !GATED_METHODS.has(method)) return { forward: line };

    const params = (m.params as Record<string, unknown>) || {};
    let operation: string;
    let lookup: string;
    let declared: string | undefined;
    if (method === "tools/call") {
      operation = (params.name as string) || "<unknown>";
      lookup = operation;
      const args = params.arguments;
      declared =
        typeof args === "object" && args !== null
          ? ((args as Record<string, unknown>).purpose as string | undefined)
          : undefined;
    } else {
      operation = `${method}:${(params.uri as string) || (params.name as string) || ""}`;
      lookup = method;
      declared = undefined;
    }
    const purpose = this.policy.purposeForTool(lookup, declared);

    if (purpose === null) {
      this.emitter.emit({
        principal: this.principal(),
        purpose: declared || "unknown",
        operation,
        decision: "deny",
        outcome: "blocked",
        reasonCode: "unknown_tool",
        blockedFields: [],
      });
      return { reply: this.blockReply(m.id, operation, "unknown_tool") };
    }
    if (this.gate !== null) {
      const [allowed, reason] = await this.gate.check(operation, purpose);
      if (!allowed) {
        // FULL gate deny: the tool NEVER runs (pre-call, like @shield).
        this.emitter.emit({
          principal: this.principal(),
          purpose: purpose.name,
          operation,
          decision: "deny",
          outcome: "blocked",
          reasonCode: reason,
          blockedFields: [],
        });
        return { reply: this.blockReply(m.id, operation, reason) };
      }
    }
    if (m.id != null) {
      this.pending.set(m.id, { tool: operation, purpose: purpose.name });
    }
    return { forward: line };
  }

  // server -> host. Returns the (possibly minimized) line, or "" to drop.
  handleServerLine(line: string): string {
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      process.stderr.write("aegis-mcp-proxy: dropped non-JSON server stdout line\n");
      return "";
    }
    if (Array.isArray(msg)) {
      process.stderr.write("aegis-mcp-proxy: dropped JSON-RPC batch from server\n");
      return "";
    }
    // Node's readline strips the trailing newline; passthrough writes must
    // re-add it or consecutive responses concatenate and corrupt the stream.
    if (typeof msg !== "object" || msg === null) return line + "\n";
    const m = msg as Record<string, unknown>;
    if (!("id" in m) || !("result" in m)) return line + "\n";
    const call = this.pending.get(m.id);
    if (call === undefined) return line + "\n";
    this.pending.delete(m.id);

    const purpose = this.policy.purposes[call.purpose];
    const result = m.result;
    const blocked: string[] = [];
    if (typeof result === "object" && result !== null && !Array.isArray(result)) {
      const r = result as Record<string, unknown>;
      const sc = r.structuredContent;
      if (typeof sc === "object" && sc !== null) {
        const { filtered, removed } = this.policy.filterPayload(purpose, sc);
        r.structuredContent = filtered;
        blocked.push(...removed);
      }
      for (const key of ["content", "contents", "messages"]) {
        const arr = r[key];
        if (!Array.isArray(arr)) continue;
        for (const item of arr) {
          if (typeof item !== "object" || item === null) continue;
          let holder = item as Record<string, unknown>;
          if (key === "messages" && typeof holder.content === "object" && holder.content !== null) {
            holder = holder.content as Record<string, unknown>;
          }
          const text = holder.text;
          if (typeof text !== "string") continue;
          let payload: unknown;
          try {
            payload = JSON.parse(text);
          } catch {
            continue; // v0 limit: free text passes through
          }
          if (typeof payload === "object" && payload !== null) {
            const { filtered, removed } = this.policy.filterPayload(purpose, payload);
            holder.text = JSON.stringify(filtered);
            blocked.push(...removed);
          }
        }
      }
    }

    const blockedSorted = [...new Set(blocked)].sort();
    this.emitter.emit({
      principal: this.principal(),
      purpose: purpose.name,
      operation: call.tool,
      decision: "allow",
      outcome: blockedSorted.length ? "access_reduced" : "protected",
      reasonCode: blockedSorted.length ? "minimum_disclosure" : null,
      blockedFields: blockedSorted,
      scope: purpose.scope ?? null,
      denyFields: purpose.denyFields ?? null,
    });
    return JSON.stringify(m) + "\n";
  }
}

interface ParsedArgs {
  policy: string;
  agentId: string;
  sessionId: string | null;
  auditPath: string | null;
  gateKind: "check-access" | "tool-call";
  owner: string | null;
  serverCmd: string[];
}

const USAGE = `usage: aegis-mcp-proxy --policy <aegis-policy v0 JSON> [options] -- <server command>

options:
  --policy <path>      aegis-policy v0 document (JSON), required
  --agent-id <id>      advisory principal id of the host agent (env AEGIS_AGENT_ID)
  --session-id <id>    session id stamped on canonical events (env AEGIS_SESSION_ID)
  --audit-path <path>  canonical event JSONL path (env AEGIS_CANONICAL_AUDIT_PATH)
  --gate <kind>        FULL-mode gate primitive: check-access | tool-call (env AEGIS_MCP_GATE)
  --owner <id>         principal.owner for the tool-call gate (env AEGIS_OWNER)
  --help               show this help
`;

// Flags that take a value. Anything else starting with "--" is rejected: the
// old positional parser silently consumed the NEXT flag as an unknown flag's
// value, so one typo could drop e.g. --audit-path without any warning — on
// the component whose whole job is auditable enforcement.
const VALUE_FLAGS = new Set([
  "--policy",
  "--agent-id",
  "--session-id",
  "--audit-path",
  "--gate",
  "--owner",
]);

function parseArgs(argv: string[]): ParsedArgs {
  const sep = argv.indexOf("--");
  const flags = sep === -1 ? argv : argv.slice(0, sep);
  const serverCmd = sep === -1 ? [] : argv.slice(sep + 1);
  const opts: Record<string, string> = {};
  for (let i = 0; i < flags.length; i += 1) {
    const key = flags[i];
    if (!VALUE_FLAGS.has(key)) {
      throw new Error(
        `aegis-mcp-proxy: unknown argument ${key}\n${USAGE}`,
      );
    }
    const value = flags[i + 1];
    if (value === undefined) {
      throw new Error(`aegis-mcp-proxy: ${key} requires a value\n${USAGE}`);
    }
    opts[key.slice(2)] = value;
    i += 1;
  }
  if (!opts.policy) {
    throw new Error("aegis-mcp-proxy: --policy <aegis-policy v0 JSON> is required");
  }
  if (serverCmd.length === 0) {
    throw new Error("aegis-mcp-proxy: a server command after `--` is required");
  }
  const gateKind = opts.gate || process.env.AEGIS_MCP_GATE || "check-access";
  if (gateKind !== "check-access" && gateKind !== "tool-call") {
    throw new Error(`aegis-mcp-proxy: unknown --gate ${gateKind} (check-access | tool-call)`);
  }
  return {
    policy: opts.policy,
    agentId: opts["agent-id"] || process.env.AEGIS_AGENT_ID || "mcp-host",
    sessionId: opts["session-id"] || process.env.AEGIS_SESSION_ID || null,
    auditPath: opts["audit-path"] || null,
    gateKind,
    owner: opts.owner || process.env.AEGIS_OWNER || null,
    serverCmd,
  };
}

export async function main(argv: string[]): Promise<number> {
  const sepIdx = argv.indexOf("--");
  const flagPart = sepIdx === -1 ? argv : argv.slice(0, sepIdx);
  if (flagPart.includes("--help") || flagPart.includes("-h")) {
    process.stdout.write(USAGE);
    return 0;
  }
  const args = parseArgs(argv);
  const policy = loadCanonicalPolicy(args.policy);
  const emitter = new CanonicalEmitter(
    ENFORCEMENT_MCP_PROXY,
    PROXY_RUNTIME,
    args.auditPath,
    policy.policyId,
  );
  // FULL-mode gate: armed only on explicit intent (AEGIS_MODE=full, or
  // AEGIS_MODE=auto resolving FULL via the same detector shield uses).
  // Unset/lite keeps today's LITE-only proxy byte-for-byte.
  let gate: GatewayGate | null = null;
  const modeEnv = (process.env.AEGIS_MODE ?? "").trim().toLowerCase();
  if (modeEnv && modeEnv !== "lite") {
    const resolved = modeEnv === "full" ? "full" : await detectMode();
    if (resolved === "full") {
      gate = new GatewayGate(getModuleClient(), args.gateKind, args.owner ?? args.agentId);
      process.stderr.write(
        `aegis-mcp-proxy: FULL gate armed (${args.gateKind}) — gateway consulted `
          + "before every gated call (deny = tool never runs, fail-closed)\n",
      );
    }
  }
  const proxy = new ShieldProxy(policy, emitter, args.agentId, args.sessionId, gate);

  const server = spawn(args.serverCmd[0], args.serverCmd.slice(1), {
    stdio: ["pipe", "pipe", "inherit"],
  });

  // host stdin -> proxy -> server stdin (or reply straight to host stdout).
  // Lines are handled SERIALLY (promise chain): the async FULL gate must not
  // reorder host traffic or interleave replies.
  const clientRl = createInterface({ input: process.stdin });
  let clientQueue: Promise<void> = Promise.resolve();
  clientRl.on("line", (line) => {
    if (!line.trim()) return;
    clientQueue = clientQueue.then(async () => {
      const { forward, reply } = await proxy.handleClientLine(line);
      if (reply !== undefined) process.stdout.write(reply);
      if (forward !== undefined) server.stdin.write(forward.endsWith("\n") ? forward : forward + "\n");
    });
  });
  clientRl.on("close", () => {
    void clientQueue.then(() => server.stdin.end());
  });

  // server stdout -> proxy -> host stdout
  const serverRl = createInterface({ input: server.stdout });
  serverRl.on("line", (line) => {
    if (!line.trim()) return;
    process.stdout.write(proxy.handleServerLine(line));
  });

  server.on("exit", (code) => process.exit(code ?? 0));
  return 0;
}

// Run when invoked as the bin (aegis-mcp-proxy), not when imported. Robust
// real-path comparison (mirrors cli.ts) so symlinked bin invocations match.
function isMain(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

if (isMain()) {
  main(process.argv.slice(2)).catch((e) => {
    // Python-parity stderr contract: one line, `aegis-mcp-proxy: <message>
    // [<code>]` when the error carries a machine-parseable code — operators
    // grep the documented aegis.canonical.* codes on BOTH SDKs.
    const msg = String((e as Error).message ?? e);
    const prefixed = msg.startsWith("aegis-mcp-proxy:") ? msg : `aegis-mcp-proxy: ${msg}`;
    const code = (e as { code?: unknown }).code;
    const suffix = typeof code === "string" && code.startsWith("aegis.") ? ` [${code}]` : "";
    process.stderr.write(prefixed + suffix + "\n");
    process.exit(2);
  });
}
