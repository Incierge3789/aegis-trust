# aegis-trust

> **Data Trust Layer for AI Agents.** One wrapper above the tool; the model never sees what it doesn't need.

`aegis-trust` is the developer-first primitive for purpose-bound data access by AI agents. One `shield()` wrapper declares **what** an agent may read (`scope`) and **why** it may read it (`purpose`); the SDK enforces field-level minimum disclosure, machine-parseable errors, end-to-end trace propagation, and a tamper-evident audit chain — fail-closed by default.

```typescript
import { shield } from "aegis-trust";

const safeFetch = shield({ purpose: "customer_support", scope: ["name", "issue"] })(db.fetch);
const u = await safeFetch("C-001"); // agent only ever sees { name, issue }
```

Built for TypeScript / Node.js engineers wiring AI agents into enterprise traffic (LangChain.js, CrewAI, Vercel AI SDK, MCP, Mastra). When procurement asks *"will your AI read our customer data?"*, the answer is in the line above.

- **30-second understanding**: `shield({ purpose, scope })(fn)` returns `fn` with the same signature; the return value is filtered to `scope`, blocked fields are audited, and a `trace_id` from `withTraceContext()` is propagated end-to-end.
- **TypeScript port** of the [`aegis-trust`](https://pypi.org/project/aegis-trust/) Python package on PyPI — same semantics, same fail-closed guarantees, same audit chain.
- **Pre-GA**: v0.9.0-rc5 is a **preview** release (`STABILITY_LEVEL = "preview"`). See [`docs/VERSIONING.md`](docs/VERSIONING.md). SLA: none. Production use: at your own risk.

```bash
npm install aegis-trust@rc
```

## 10-Second Sandbox

```bash
npm install aegis-trust
npx aegis sandbox
```

…or with Docker:

```bash
git clone https://github.com/Incierge3789/aegis-trust
cd aegis-trust/node/examples/docker
docker compose -f docker-compose.dev.yml up --build
# In another shell:
curl -s http://localhost:8080/demo/agent-request | jq
# Stop + clean up: docker compose -f docker-compose.dev.yml down -v
```

Output (excerpt):

```
3. Aegis decision:
     ┌────────────────────────────────────────────────────────┐
     │ Agent:        support_agent
     │ Purpose:      customer_support
     │ ✓ Allowed:    last_login, plan, user_id
     │ ✗ Blocked:    credit_card, email, internal_notes, name, phone, ssn
     │ Decision:     filtered
     │ Audit:        ./aegis-sandbox-audit.jsonl
     └────────────────────────────────────────────────────────┘
```

---

## Quickstart

```typescript
import { shield } from "aegis-trust";

const safeGetUser = shield({
  purpose: "show_profile",
  scope: ["name", "email"],
})(async function getUser(id: number) {
  return await db.users.find(id);
  // returns { id, name, email, ssn, dob, address, ... }
});

const u = await safeGetUser(42);
// u → { name: "...", email: "..." }
// id, ssn, dob, address — never reach the agent
```

One wrapper declares purpose; the SDK enforces field-level access control. Zero runtime dependencies in Lite mode.

---

## Agent Framework Examples

### LangChain.js — filter PII out of tool returns

```typescript
import { shield } from "aegis-trust";

const getCustomer = shield({
  purpose: "customer_support",
  scope: ["name", "plan", "issue"],
})(async (id: string) => db.fetch(id));   // db.fetch returns 10+ fields

// Register `getCustomer` as a LangChain tool. The agent — and the model
// context, the model logs, and the provider's training pipeline — only
// ever see { name, plan, issue }.
```

Runnable end-to-end example: [`examples/langchainExample.ts`](examples/langchainExample.ts).

### CrewAI (Node port) — different agents, different scopes, same data

```typescript
const getForSupport = shield({
  purpose: "customer_support",
  scope: ["name", "plan", "issue"],
})(async (id: string) => db.fetch(id));

const getForBilling = shield({
  purpose: "billing",
  scope: ["name", "plan", "balance_due", "billing_address"],
})(async (id: string) => db.fetch(id));
```

Support and Billing agents share one `db.fetch()` but never see each other's fields. Runnable example: [`examples/crewaiExample.ts`](examples/crewaiExample.ts).

### Vercel AI SDK / MCP / Mastra

```typescript
import { tool } from "ai";
import { shield } from "aegis-trust";

const fetchCustomer = shield({
  purpose: "support",
  scope: ["name", "issue"],
})(async (id: string) => db.fetch(id));

export const customerTool = tool({
  description: "Look up a customer by ID",
  execute: async ({ id }: { id: string }) => fetchCustomer(id),
});
```

`shield()` returns a function with the same signature as the original, so it stacks inside any framework's tool registration. Works identically with `@modelcontextprotocol/sdk`, Mastra `createTool`, AutoGen.js, or any framework that calls a JS function.

---

## Why

Modern AI agents request raw records and decide what to use. That's a security boundary problem: the agent sees more than it needs, and what it sees is impossible to audit.

`aegis-trust` inverts the contract — the caller declares **purpose** and **scope** up-front, and the SDK enforces minimum disclosure at return time. Fail-closed by default.

## API surface (parity with PyPI `aegis-trust` 0.8.1)

| TS export | Python equivalent | Purpose |
|---|---|---|
| `shield(options)(fn)` | `@shield(...)` decorator | Core wrapper |
| `wrap(value, options)` | (TS-only convenience) | Filter a single value |
| `Mode.LITE / FULL / AUTO` | `Mode.LITE/FULL/AUTO` | Operating mode |
| `AegisClient` | `aegis.client.AegisClient` | aegis-core HTTP client |
| `loadConfig`, `getPurposePolicy`, `resetConfig` | `aegis.config.*` | YAML policy loader |
| `HistoryStore`, `recordIfEnabled`, `resetStore` | `aegis.history.*` | Local audit log |
| `useShieldHistory`, `assertShieldBlocked`, `assertShieldPassed` | `aegis.pytest_plugin.*` | Test helpers (vitest) |
| `syncPolicies`, `refreshToken`, `reset` | `aegis.shield.*` admin | Admin |
| `setMetricsHook` | `aegis.client.set_metrics_hook` | Instrumentation |
| `aegis` CLI (`aegis history`, `aegis stats`) | `aegis` CLI | Local inspection |

Full type parity: `AccessPolicy`, `AuditEntry`, `ShieldResult`, `IngestEntry/Response`, `AuditChainStatus`, `PolicySyncEntry/Response`, `PurposeStats`, `FieldStats`, `FunctionStats`, `ShieldStats`.

## `shield(options)(fn)`

| Option | Type | Default | Meaning |
|---|---|---|---|
| `purpose` | `string` | (required) | Why this access is being made. Audit-grade. |
| `scope` | `string[]` | `[]` | Allow-list of field paths. Dot notation. `[]` = pass-through. |
| `denyFields` | `string[]` | `[]` | Block-list of field paths. Applied after scope. Broader paths win. |
| `mode` | `Mode` | `Mode.AUTO` | Operating mode (see below). |

### Semantics

```typescript
// Allow-list
shield({ purpose: "p", scope: ["name", "address.city"] })
// keeps name + address.city, drops everything else

// Block-list
shield({ purpose: "p", denyFields: ["ssn", "address.street"] })
// drops ssn + address.street, keeps everything else

// Broader deny wins
shield({ purpose: "p", denyFields: ["profile", "profile.ssn"] })
// → collapses to deny `profile` entirely
```

### Fail-closed on shape mismatch

```typescript
shield({ purpose: "p", scope: ["users"] })   // value: { users: [{ssn:"x"}, ...] }
// → drops `users` entirely. Bare leaf scope over a list-of-records is a
//   silent-pass footgun. Use `scope: ["users.name"]` instead.
```

### Async support

```typescript
shield({ purpose: "lookup", scope: ["name"] })(
  async (id) => fetch(`/users/${id}`).then(r => r.json())
);
// Returned Promise resolves to the filtered value.
```

## Mode policy

| Mode | What it does | Requires |
|---|---|---|
| `LITE` | In-process filter only. Deterministic, no I/O. | nothing |
| `FULL` | Filter + audit chain ingest + central policy sync via aegis-core. | aegis-core running + `AEGIS_TOKEN` |
| `AUTO` | Probe-first detection. See [AUTO behaviour matrix](#auto-behaviour-matrix-rc4) below. | nothing |

### AUTO behaviour matrix (rc4+)

`Mode.AUTO` probes the backend FIRST (parity with PyPI `aegis-trust`, re-probe TTL = 60 s) and consults the Full-intent heuristic only when the probe fails. Behaviour:

- `AEGIS_MODE=lite` → Lite.
- `AEGIS_MODE=full` → Full (calls fail-closed at the gateway until the backend recovers).
- `AEGIS_MODE=auto` + no Full intent (no `AEGIS_TOKEN` AND no non-dev URL) → Lite.
- `AEGIS_MODE=auto` + Full intent + reachable backend → Full (opportunistic upgrade).
- `AEGIS_MODE=auto` + Full intent + **unreachable backend** → **fail-closed Full** + one `console.warn`. Silent LITE degrade is suppressed because it would skip the user-visible warning and provide weaker semantics than the user asked for.

### Full mode env vars

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_URL` | `https://localhost:8443/api/v1` | aegis-core REST endpoint (rc4+ **canonical**; parity with PyPI). |
| `AEGIS_BASE_URL` | — | Deprecation alias for `AEGIS_URL`. Read only when `AEGIS_URL` is unset; emits one `console.warn` per process the first time it is read (re-armed by `resetModuleClient()`). **Removed in v1.0.0.** |
| `AEGIS_TOKEN` | (empty) | Bearer token for auth |
| `AEGIS_VERIFY_SSL` | `true` | TLS verify (prod-locked: ignored unless host is dev) |
| `AEGIS_DEV_INSECURE` | (unset) | Allow TLS verify off, dev hosts only |
| `AEGIS_MODE` | `auto` | Override mode detection (`full` / `lite`) — see matrix above. |
| `AEGIS_HISTORY` | (unset) | `1` to enable local audit log |
| `AEGIS_HISTORY_PATH` | `~/.aegis/history.jsonl` | Local audit file |
| `AEGIS_CONFIG` | (unset) | Override YAML config path |

### FULL mode — gateway trust-boundary guarantees

When `shield()` runs in FULL mode it calls the aegis-core gateway's `/check-access` endpoint before filtering. As of the Core Security Remediation track (CSR 4/4, landed in aegis-core 2026-05-21) that ingress provides four **scoped** guarantees:

1. **Identity binding** — `/check-access` treats the identity established by the gateway's auth middleware as the sole authoritative requester identity (the JWT `sub` for Bearer-JWT auth; the literal `api-key` for API-key auth). A request body that claims a different `requester_id` is denied (HTTP 403) with an `identity_mismatch` audit record.
2. **Ingress denial of unknown inputs** — an unknown `purpose`, an unknown `scope`, or a malformed / path-traversal `capsule_id` is denied (HTTP 403) at the `/check-access` ingress, each with an audit DENY record. (The unknown-purpose denial is RBAC-pathed; unknown-scope and malformed-capsule carry dedicated `policy.*` audit reasons.)
3. **Audit-or-deny** — a `/check-access` decision fails closed if its audit record cannot be written: the gateway returns HTTP 503 rather than a silently-unaudited 200 ALLOW or 403 DENY.
4. **Boot-time config validation** — started with `AEGIS_PROFILE=production`, the gateway fails its own boot (`exit(2)`) on missing critical config keys, disabled security controls, an enabled legacy dashboard socket, or an unparseable / zero `AEGIS_REST_PORT`, instead of degrading silently. `AEGIS_PROFILE` unset or `development` keeps the pre-existing permissive behaviour.

**Scope of these guarantees — read before relying on them:**

- The audit-or-deny guarantee (#3) applies to the `/check-access` endpoint only. It is **not** a gateway-wide audit fail-closed guarantee; other gateway endpoints are not yet swept.
- The `/check-access` scope check (#2) validates `scope` against a known registry. It is **not** purpose × scope field-level minimum-disclosure enforcement; field-level redaction by purpose × scope is not wired.
- `AEGIS_PROFILE=production` validation (#4) is operator opt-in. The gateway is **not** production-ready out of the box; the default profile keeps silent config fallbacks.
- These four guarantees are `/check-access`-scoped and do **not** amount to an all-gateway-operations audit-complete claim.

**Known follow-ups — tracked, not yet shipped:**

- A missing `AEGIS_CAPSULE_ROOT` can still produce a runtime HTTP 500 with no audit record; that 500 path is evaluated after the identity check (#1) but before the unknown-purpose / scope / capsule checks (#2), so it pre-empts guarantee #2.
- Gateway-wide audit-append fail-closed sweep (beyond `/check-access`).
- Debug-log redaction (`RUST_LOG=debug` output hygiene).
- Wiring validated `scope` through to RBAC / Reflex / field-level enforcement.

## YAML config (optional)

```yaml
# aegis.yaml
purposes:
  support:
    scope: ["name", "issue"]
  ops:
    deny_fields: ["ssn", "card.cvc"]
```

```typescript
import { loadConfig, getPurposePolicy } from "aegis-trust";
const policy = await getPurposePolicy("support");
// { scope: ["name", "issue"] }
```

YAML loading requires `npm install yaml` (declared as `optionalDependencies`).

## Local audit log

```bash
AEGIS_HISTORY=1 node my-agent.js
aegis history --limit 50
aegis stats
```

The CLI reads `~/.aegis/history.jsonl` (or `$AEGIS_HISTORY_PATH`) and prints recent invocations + aggregated stats.

## Vitest helpers

```typescript
import { afterEach, beforeEach, describe, it } from "vitest";
import {
  assertShieldBlocked,
  useShieldHistory,
} from "aegis-trust";

describe("my agent", () => {
  const history = useShieldHistory({ beforeEach, afterEach });

  it("hides SSN from support purpose", () => {
    getCustomer(42); // calls a shield-wrapped function
    assertShieldBlocked(history.records(), "ssn");
  });
});
```

## Machine-parseable errors (v0.9.0-rc1+)

Every error thrown from the SDK is an instance of `AegisError` (or a derived class) and carries `code` + `remediation` + `docs_url`:

```typescript
import { AegisValidationError, shield } from "aegis-trust";

try {
  const safeFetch = shield({ purpose: "" })(db.fetch);
} catch (e) {
  if (e instanceof AegisValidationError) {
    console.error(e.code);        // "aegis.shield.purpose.required"
    console.error(e.remediation); // "Pass a non-empty string to `purpose` ..."
    console.error(e.docs_url);    // "https://aegis-trust.dev/errors/aegis.shield.purpose.required"
  }
}
```

Catch `AegisError` at the agent boundary; switch on `code` for retry / fallback / human escalation. The full registry is in [`docs/errors/README.md`](docs/errors/README.md).

## Trace propagation (v0.9.0-rc1+)

`withTraceContext({ traceId }, fn)` opens an `AsyncLocalStorage` trace scope. Every `shield()` call inside the scope emits the `trace_id` into the audit JSONL, so an agent reasoning step → multiple tool calls → audit chain are linked end-to-end by a single id:

```typescript
import { newTraceId, shield, withTraceContext } from "aegis-trust";

const supportTool = shield({ purpose: "support", scope: ["name", "issue"] })(db.fetch);
const billingTool = shield({ purpose: "billing", denyFields: ["ssn", "card"] })(db.fetch);

const traceId = newTraceId();
await withTraceContext({ traceId }, async () => {
  await supportTool("C-001");
  await billingTool("C-001");
  // both records in ~/.aegis/history.jsonl carry trace_id = <traceId>
});
```

Runnable end-to-end example: [`tests/mcp/run_end_to_end.mjs`](tests/mcp/run_end_to_end.mjs).

## Idempotent local audit (v0.9.0-rc1+)

`HistoryStore.recordIdempotent(args, idempotencyKey)` translates the Stripe Idempotency-Key model to the local JSONL store: calling with the same key across retries (within or across process runs) appends exactly once. **`shield()` itself does not use this primitive** — each successful `shield()`-wrapped call still emits one audit record via `record()`, so a retried agent tool call produces multiple audit rows unless the caller wraps the retry in `recordIdempotent()` directly.

```typescript
import { HistoryStore } from "aegis-trust";

const store = new HistoryStore("/tmp/audit.jsonl");
// Agent retry loop — only one record persisted regardless of retries.
for (let i = 0; i < 100; i++) {
  store.recordIdempotent(
    { function: "fetchCustomer", purpose: "support", scope: ["name"], denyFields: [], blockedFields: ["ssn"], timestamp: new Date().toISOString(), mode: "lite" },
    "agent.retry.fetchCustomer.C-001",
  );
}
```

If the same `idempotencyKey` is reused with a divergent payload (different `purpose` / `scope` / `denyFields` / `blockedFields` / `function` / `mode`), `recordIdempotent` throws `AegisAuditError` with code `aegis.audit.idempotencyKey.payloadDivergence` rather than silently dropping the retry. Cross-process concurrent writers to the same JSONL are best-effort (no file lock); production-grade atomicity lands in `sprint_002` hardening.

## AegisClient (direct use)

```typescript
import { AegisClient } from "aegis-trust";

const client = new AegisClient({
  baseUrl: "https://aegis-core.internal:8443/api/v1",
  token: process.env.AEGIS_TOKEN!,
});

if (await client.authorize("show_profile", ["name", "email"])) {
  // proceed
}

const stats = await client.getStats({ purpose: "show_profile" });
const status = await client.verifyAuditChain();
```

Endpoints covered: `/health`, `/check-access`, `/audit-log`, `/shield/ingest`, `/audit/verify`, `/shield/policy-sync`, `/shield/stats`, `/shield/report`.

## License

MIT © Incierge Inc. — contact@aegisagentcontrol.com
