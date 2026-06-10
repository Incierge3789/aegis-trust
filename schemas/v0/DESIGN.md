# Aegis Canonical Contract v0 — Policy Schema + Audit Event Schema

Status: **draft v0**

## What this is

One policy schema + one audit event schema, shared by every Aegis enforcement
point (PEP). The product line is the *same contract at three enforcement
strengths*:

| Form factor | Boundary | Strength | Target hosts |
|---|---|---|---|
| trust SDK (in-process) | inside the agent process | cooperative / hygiene | any Python/Node agent (embedded) |
| MCP proxy | process boundary, host unmodified | intermediate | Claude Code, codex, agy, Claude Desktop, any MCP-speaking agent |
| core gateway | host/network boundary + key separation | cryptographic enforcement | regulated environments |

A deployment upgrades enforcement strength **without rewriting policy**: the
same policy document drives all three forms, and all three emit the same
audit event shape.

Files:
- `aegis-policy.v0.schema.json` — the policy document contract (what operators write)
- `aegis-audit-event.v0.schema.json` — the audit event contract (what every PEP emits)
- `examples/` — valid sample documents, exercised by the validation tests
- `validate.py` — schema harness (positive examples + invariant-violation negatives)
- `project_gateway_audit.py` — projects gateway audit records into canonical v0 events
- `mcp-hosts.md` — registering the MCP proxy with Claude Code / codex / agy

## Binding requirements for v0

1. `enforcement_point` is REQUIRED on every audit event
   (`sdk | mcp_proxy | gateway`). One audit stream must remain interpretable
   across the enforcement-strength upgrade path.
2. Egress is part of v0, not a later addition. Policy has per-purpose
   `destinations.allow|deny`; audit events with `event_type=egress` must
   carry `destination`.

## Carried invariants

- `scope` XOR `deny_fields` — exactly one per purpose
- `scope: []` valid (releases nothing); `deny_fields: []` invalid ("hiding nothing")
- unknown purpose / destination / tool ⇒ block. v0 offers no permissive default.
- dot-notation field paths (no leading/trailing/double dots)
- `identity_mismatch: true` on a principal forces `decision: deny`
- `allowed_fields` / `blocked_fields` carry field NAMES only, never values;
  `reason_code` is value-free

## Version axes (do not conflate)

| Axis | Current | Owner |
|---|---|---|
| canonical `policy_schema_version` | 0 | this contract |
| canonical `audit_schema_version` | 0 | this contract |
| trust SDK AUDIT_SCHEMA_VERSION | 1 | local SQLite/JSONL + /shield/ingest |
| gateway audit schema | internal | gateway chain |
| Aegis-Api-Version header | 2026-05-18 | wire/API versioning |

Migration stance: products keep their internal audit/record versions; each PEP
ships an *emitter* that projects its native record into a canonical v0 event.
Emitters stamp the canonical version; readers fail-closed
(treat-as-unverifiable) on a higher major version.

## Implementation status

- SDK: `aegis_trust.canonical` — `load_canonical_policy()` (fail-closed
  loader) + `CanonicalEmitter` (JSONL event writer).
- MCP proxy: `aegis_trust.mcp_proxy` — stdio pass-through; gates
  `tools/call`, `resources/read`, `prompts/get`; rejects JSON-RPC batches;
  drops non-JSON server stdout; minimizes structured payloads; emits
  canonical events.
- Gateway: `project_gateway_audit.py` converts gateway audit JSONL into
  canonical v0 events (integrity chain required; free-text reasons never
  copied).
- All of the above are exercised in CI: schema harness, loader/emitter unit
  tests, and end-to-end proxy subprocess tests.

## Known v0 limits (documented, not hidden)

- **SDK evidentiary limit**: in-process events have no `integrity` chain; the
  writer is the agent itself ⇒ tamper-evident only after async export. The
  SDK form provides hygiene / blast-radius reduction, NOT enforcement.
- **roles in SDK/proxy**: advisory unless the deployment can resolve a
  principal's role; only the gateway binds identity cryptographically
  (`auth_sub`).
- **field classification**: `max_level` requires a field classification map;
  SDK/proxy skip it when absent.
- **proxy direction**: the proxy minimizes what enters the host's context
  (server→host). The host→server direction (tool arguments, sampling
  responses) is not yet inspected; `destinations` egress policy is enforced
  by the SDK/gateway forms in v0.
- **free text**: only structured payloads are minimized (`structuredContent`
  / JSON text in `content`/`contents`/`messages`). Route sensitive data
  through structured results.
