# aegis-trust LITE — Evaluation Quickstart

A 10-minute path for an external team to evaluate LITE mode end to end:
install, filter, observe the result, wire metering, and know exactly where
LITE stops and FULL begins. Each step references a runnable example that
ships in this repository.

> LITE in one line: *"Filtered locally by aegis-trust LITE. No gateway
> required."* For what that does and does not mean, read
> [`LITE_CLAIMS.md`](./LITE_CLAIMS.md) first.

## 0. Install

```bash
npm install aegis-trust        # Node 18+
# or
pip install aegis-trust        # Python 3.10+
```

(The two packages version-track each other; see
[`LITE_ARTIFACTS_AND_METADATA.md`](./LITE_ARTIFACTS_AND_METADATA.md) §1.)

## 1. Shield a data accessor (embed parity)

Node — from the package README (30-Second Quickstart, `node/README.md`) and
`node/examples/quickstart.ts`:

```ts
import { shield } from "aegis-trust";

const safeGetUser = shield({
  purpose: "show_profile",
  scope: ["name", "email"],
})(async function getUser(id: number) {
  return await db.users.find(id); // returns { id, name, email, ssn, ... }
});

const u = await safeGetUser(123); // → { name, email } — ssn never reaches the agent
```

Python — same contract (`python/examples/`, repo root `README.md`):

```python
from aegis_trust import shield

@shield(purpose="show_profile", scope=["name", "email"])
def get_user(user_id):
    return db.users.find(user_id)
```

The wrapped accessor is what you hand to your agent framework (LangChain,
CrewAI, Vercel AI SDK, MCP — see the adapter examples listed in
[`LITE_ARTIFACTS_AND_METADATA.md`](./LITE_ARTIFACTS_AND_METADATA.md) §4).

## 2. Observe what was filtered

Node offers a direct value filter, `wrap()`, whose result reports which
fields were stripped (`filteredKeys`):

```ts
import { wrap } from "aegis-trust";

const res = wrap(rawUser, { purpose: "show_profile", scope: ["name", "email"] });
// res.data         → { name, email }
// res.filteredKeys → ["id", "ssn", ...]
```

`wrap()`/`ShieldResult` is **Node-only today** (a named parity gap — see
[`LITE_CLAIMS.md`](./LITE_CLAIMS.md) §1). In Python, observe filtering by
comparing the wrapped accessor's output with the raw accessor's output. See
`node/examples/denyFieldsExample.ts` / `dotNotationExample.ts` for deny-path
and nested-path behavior.

Either way this is an **in-process result, not evidence**: in LITE there is
no `decision_id` and no integrity-checkable record (see
[`LITE_CLAIMS.md`](./LITE_CLAIMS.md) §3).

## 3. Wire usage metering

```ts
import { setMetricsHook } from "aegis-trust";
setMetricsHook((endpoint, durationMs, status) => {
  myMetrics.histogram("aegis_call", durationMs, { endpoint, status });
});
```

```python
from aegis_trust.client import set_metrics_hook
set_metrics_hook(lambda endpoint, duration, status: my_metrics.observe(endpoint, duration, status))
```

The SDK never auto-registers a metrics backend; the hook is the integration
point (`python/tests/test_metrics_hook.py` pins this).

**LITE note:** the hook instruments **gateway calls** (`check-access`,
`shield.ingest` — FULL/AUTO mode). Purely LITE-local filtering as in §1–§2
makes no gateway call, so the hook does not fire; it starts reporting once
your calls actually reach the gateway in FULL mode. (Caveat: not every LITE
call site meters as-is after upgrade — e.g. a multi-element `scope` fails
closed in the Node FULL authorization path before any metered request is
issued; see §4 for where the FULL boundary lives.)

## 4. Know the boundary (where LITE stops)

| You want | Mode | What changes |
|---|---|---|
| In-process field filtering, zero infra | LITE (you are here) | — |
| Gateway-authorized filtering + audit ingest (`shield()` keeps returning filtered data — not a receipt object) | FULL (`shield()` path) | Self-host the gateway; `shield()` call sites stay the same |
| Explicit decision receipts (`BoundaryDecisionView`: outcome, allowed/withheld fields, reason, `decision_id`) | FULL (`checkBoundary()` / `check_boundary()` path) | Call `checkBoundary()` where you need the receipt — a separate call, not a `shield()` return value |

AUTO mode selects between the two by configured intent and **fails closed**:
if FULL intent is configured but the gateway is unreachable, calls deny
rather than silently degrading to LITE.

## 5. Verify what you installed

```bash
cd node
npm ci             # install exactly the locked dependency set
npm run parity     # versions: local sources + git tag + registries
npm run build      # required: one test exercises the built bin-shim (dist/cli.js)
npm test           # behavior: vitest suite incl. shield/filter parity cases
```

---

*This quickstart adds no new claims. The claim ceiling and the never-claim
list live in [`LITE_CLAIMS.md`](./LITE_CLAIMS.md); the artifact inventory and
verification commands live in
[`LITE_ARTIFACTS_AND_METADATA.md`](./LITE_ARTIFACTS_AND_METADATA.md).*
