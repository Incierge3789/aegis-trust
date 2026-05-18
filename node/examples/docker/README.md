# aegis-trust — Docker quickstart (Node.js)

The 60-second demo. No host install, no real data, no telemetry.

## Run

```bash
cd examples/docker
docker compose -f docker-compose.dev.yml up --build
```

In another terminal:

```bash
# Agent requests a user record
curl -s http://localhost:8080/demo/agent-request | jq

# See the audit trail
curl -s http://localhost:8080/demo/audit
```

You will see:

```json
{
  "allowed": {
    "user_id": "u_123",
    "plan": "pro",
    "last_login": "2026-05-15T08:23:00Z"
  },
  "blocked": ["credit_card", "email", "internal_notes", "name", "phone", "ssn"],
  "audit": {
    "purpose": "customer_support",
    "decision": "filtered",
    "reason": "fields outside declared scope",
    "path": "/data/audit.jsonl"
  }
}
```

## Stop and clean up

```bash
docker compose -f docker-compose.dev.yml down -v
```

The `-v` flag removes the `aegis-audit` volume so no demo data persists.

## What's inside

| File | What it does |
|---|---|
| `agentServer.ts` | ~80-line HTTP server using `node:http` (zero deps) + `aegis-trust` |
| `Dockerfile` | node:20-alpine + multi-stage build + non-root + healthcheck |
| `docker-compose.dev.yml` | localhost-only port, read-only fs, no new privs, all caps dropped |

## Use this as a template

Copy `agentServer.ts` into your project, replace `DUMMY_USER` and `getUser` with your real data source, and the same Docker / compose config gives you a hardened HTTP demo of your own purpose-bound access policy.
