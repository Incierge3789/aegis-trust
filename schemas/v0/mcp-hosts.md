# shield-proxy host registration (Claude Code / Cursor / codex / agy)

`pip install aegis-trust` installs the `aegis-mcp-proxy` command (equivalently
`python3 -m aegis_trust.mcp_proxy`). The proxy wraps any MCP server command:
replace the server command with
`aegis-mcp-proxy --policy <policy> --agent-id <host> -- <original command>`.
The host needs no other change; tool results arrive already minimized and every
call lands in the canonical audit stream (`enforcement_point=mcp_proxy`). This
is how an agent on the tool path sees only policy-permitted fields — host
unmodified, fail-closed on unknown tools.

## Claude Code (`.mcp.json` / `claude mcp add`)

```json
{
  "mcpServers": {
    "crm": {
      "command": "aegis-mcp-proxy",
      "args": [
        "--policy", "/etc/aegis/policy.json",
        "--agent-id", "claude-code",
        "--", "node", "/opt/crm/mcp-server.js"
      ]
    }
  }
}
```

CLI equivalent:
`claude mcp add crm -- aegis-mcp-proxy --policy /etc/aegis/policy.json --agent-id claude-code -- node /opt/crm/mcp-server.js`

## Cursor (`.cursor/mcp.json`, same stdio shape)

```json
{
  "mcpServers": {
    "crm": {
      "command": "aegis-mcp-proxy",
      "args": [
        "--policy", "/etc/aegis/policy.json",
        "--agent-id", "cursor",
        "--", "node", "/opt/crm/mcp-server.js"
      ]
    }
  }
}
```

## codex (`~/.codex/config.toml`)

```toml
[mcp_servers.crm]
command = "python3"
args = [
  "-m", "aegis_trust.mcp_proxy",
  "--policy", "/etc/aegis/policy.json",
  "--agent-id", "codex",
  "--", "node", "/opt/crm/mcp-server.js",
]
```

## agy (Antigravity MCP settings, same stdio shape)

```json
{
  "mcpServers": {
    "crm": {
      "command": "python3",
      "args": [
        "-m", "aegis_trust.mcp_proxy",
        "--policy", "/etc/aegis/policy.json",
        "--agent-id", "agy",
        "--", "node", "/opt/crm/mcp-server.js"
      ]
    }
  }
}
```

## Notes

- `--agent-id` is the advisory `principal.agent_id` in audit events; pick one
  value per host so the stream is attributable.
- `--audit-path` (or `AEGIS_CANONICAL_AUDIT_PATH`) sets the event JSONL;
  default `~/.aegis/canonical_events.jsonl`.
- Same policy file works unchanged in the in-process SDK and (projected) in
  the gateway — that is the upgrade path.
- Gated data paths: `tools/call`, `resources/read`, `prompts/get`. The latter
  two need an explicit purpose mapping in the policy's `tools` map (e.g.
  `"resources/read": "internal_docs"`) or they are blocked. Unmapped tools,
  JSON-RPC batches, and non-JSON server stdout are all rejected fail-closed.
- v0 limits: (1) free-text tool output passes through; structured payloads
  (`structuredContent` / JSON text in `content`/`contents`/`messages`) are
  minimized — prefer structured results for sensitive servers. (2) the
  host→server direction (tool arguments, sampling responses) is not yet
  inspected; egress `destinations` policy is enforced by the SDK/gateway
  forms in v0.

## FULL mode on the proxy path (gateway-backed per-call gate)

By default the proxy is LITE: local canonical-policy filtering only, no
network. Setting `AEGIS_MODE=full` (or `auto` with FULL intent — `AEGIS_TOKEN`
or a non-dev `AEGIS_URL`) arms the gateway gate: the proxy consults the
gateway BEFORE forwarding every gated call, so a policy deny means the tool
NEVER runs (side effects prevented, not just output filtered), and a gateway
outage is a deny (`gateway_unavailable`), never a pass-through. Local
filtering still applies on the way back (defense in depth).

The gate primitive is explicit — never auto-probed:

| `--gate` / `AEGIS_MCP_GATE` | primitive | works against |
|---|---|---|
| `check-access` (default) | `@shield`-parity purpose gate (`POST /check-access`) | every live gateway today |
| `tool-call` | AI-native per-tool-call gate (`POST /tool-call`, role-keyed tool whitelist, chain-witnessed decision — `AI_NATIVE_V1_CONTRACT.md`) | boundaries serving the AI-native family |

Extra env/flags: `AEGIS_URL` + `AEGIS_TOKEN` (the gateway), `--owner` /
`AEGIS_OWNER` (principal.owner for the tool-call gate; defaults to
`--agent-id`). Audit reason codes added by the gate: `gateway_denied`,
`gateway_unavailable`.
