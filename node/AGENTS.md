# Agent Integration Guide — aegis-trust

This guide helps AI agents and agent frameworks integrate with `aegis-trust` for purpose-based data access control in TypeScript / Node.js.

## For Agent Developers

### 1. Install

```bash
npm install aegis-trust
```

For `aegis.yaml` policy file support:

```bash
npm install aegis-trust yaml
```

### 2. Wrap data-fetching functions

```typescript
import { shield } from "aegis-trust";

const getTicket = shield({
  purpose: "customer_support",
  scope: ["name", "issue", "status"],
})((ticketId: string) => db.getTicket(ticketId));
```

The agent calling `getTicket(...)` only sees `name`, `issue`, and `status`. All other fields (SSN, payment info, internal notes) are filtered out.

### 3. Choose your filtering mode

**Whitelist (`scope`)** — specify exactly what the agent can see:

```typescript
shield({ purpose: "support", scope: ["name", "email", "profile.age"] })
```

**Blacklist (`denyFields`)** — specify what to hide:

```typescript
shield({ purpose: "billing", denyFields: ["ssn", "profile.ssn"] })
```

`scope` and `denyFields` are mutually exclusive when set in `aegis.yaml`. Specifying both in YAML raises an error; setting both in code applies scope first, then denyFields.

### 4. Centralize policies in `aegis.yaml`

```yaml
# aegis.yaml
purposes:
  support:
    scope: ["name", "issue", "profile.age"]
  billing:
    deny_fields: ["ssn", "profile.ssn"]
```

```typescript
import { getPurposePolicy, shield } from "aegis-trust";

const policy = await getPurposePolicy("support");
const getCustomer = shield({
  purpose: "support",
  ...(policy ?? {}),
})((id: number) => db.get(id));
```

Requires `npm install yaml`.

## For Framework Authors

### MCP (Model Context Protocol) Integration

```typescript
import { Server } from "@modelcontextprotocol/sdk/server";
import { shield } from "aegis-trust";

const server = new Server({ name: "my-server", version: "1.0.0" }, {});

const getCustomer = shield({
  purpose: "customer_support",
  scope: ["name", "issue"],
})(async function getCustomer(customerId: string) {
  return await db.get(customerId);
});

server.setRequestHandler("tools/call", async (req) => {
  if (req.params.name === "get_customer") {
    return await getCustomer(req.params.arguments.customer_id);
  }
});
```

`shield(...)` works with any framework — it returns a wrapped function with the same signature, so it stacks inside (closer to the function) any framework decorator or registration call.

### Vercel AI SDK Integration

```typescript
import { tool } from "ai";
import { z } from "zod";
import { shield } from "aegis-trust";

const fetchCustomer = shield({
  purpose: "support",
  scope: ["name", "issue"],
})(async (id: string) => db.get(id));

export const customerTool = tool({
  description: "Look up a customer by ID",
  parameters: z.object({ id: z.string() }),
  execute: async ({ id }) => fetchCustomer(id),
});
```

### Express / Fastify / Hono Integration

```typescript
import express from "express";
import { shield } from "aegis-trust";

const app = express();

const getCustomer = shield({
  purpose: "support",
  scope: ["name", "issue"],
})(async (id: string) => db.get(id));

app.get("/customer/:id", async (req, res) => {
  res.json(await getCustomer(req.params.id));
});
```

### Testing with vitest

```typescript
import { afterEach, beforeEach, describe, it } from "vitest";
import {
  assertShieldBlocked,
  assertShieldPassed,
  useShieldHistory,
} from "aegis-trust";

describe("customer agent", () => {
  const history = useShieldHistory({ beforeEach, afterEach });

  it("hides SSN from support purpose", async () => {
    await getCustomer("id-1");   // calls a shield-wrapped function
    assertShieldBlocked(history.records(), "ssn");
    assertShieldPassed(history.records(), "name");
  });
});
```

`useShieldHistory` wires `beforeEach` / `afterEach` to capture every `shield` invocation in the test, isolated per test.

## Error Handling (v0.9.0-rc1+)

Every error from `aegis-trust` is an `AegisError` (or derived class) carrying `code` + `remediation` + `docs_url`. Catch at the boundary; switch on `code` for retry / fallback:

```typescript
import { AegisValidationError, shield } from "aegis-trust";

try {
  const safe = shield({ purpose: agent.purpose, scope: agent.scope })(db.fetch);
  return await safe(id);
} catch (e) {
  if (e instanceof AegisValidationError) {
    agent.log({ code: e.code, remediation: e.remediation, docs_url: e.docs_url });
    // Self-correct using remediation; do not escalate to human.
    return null;
  }
  throw e;
}
```

Code registry: [`docs/errors/README.md`](docs/errors/README.md). The `code` string is part of the public contract (see [`docs/VERSIONING.md`](docs/VERSIONING.md) §7).

## Trace Propagation (v0.9.0-rc1+)

Open a trace scope once per agent reasoning step. Every `shield()` call inside emits the `trace_id` into the audit JSONL:

```typescript
import { newTraceId, withTraceContext } from "aegis-trust";

const traceId = newTraceId();
await withTraceContext({ traceId }, async () => {
  // All shield() calls reached from here share trace_id.
  await supportTool("C-001");
  await billingTool("C-001");
});
```

End-to-end runnable proof: [`tests/mcp/run_end_to_end.mjs`](tests/mcp/run_end_to_end.mjs).

## Idempotency-Key (v0.9.0-rc1+)

For agent retry loops, `HistoryStore.recordIdempotent(args, idempotencyKey)` dedupes via key — within and across process runs. Mirrors Stripe's Idempotency-Key header semantics, applied to the local audit log.

## Design Principles

- **Minimum Disclosure**: agents see only what their purpose requires
- **Purpose-Driven Access**: every data access declares its purpose explicitly
- **Explicit Data Flow**: filter mismatches return empty values rather than leak through messages
- **Fail-closed**: on any shape mismatch (bare leaf scope over list-of-records, scope expects nested but scalar, etc.), drop the key rather than pass through
- **Machine-parseable errors**: every thrown error carries `code` + `remediation` + `docs_url` so agents can retry without human escalation
- **End-to-end trace propagation**: a single `trace_id` links agent reasoning → tool call → audit chain via `AsyncLocalStorage`
- **Idempotent mutation**: `recordIdempotent()` (and Idempotency-Key on `ingest`, sprint_002) — retries are safe by construction

## Contact

- Security: contact@aegisagentcontrol.com
- Sales: contact@aegisagentcontrol.com
