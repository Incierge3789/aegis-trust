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
