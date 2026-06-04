# aegis-trust

**The trust layer for AI agents.** One decorator declares the purpose; the SDK enforces what data the agent is allowed to see. Local-first AI agent data access control — no infrastructure, no telemetry.

```bash
pip install aegis-trust
```

[![PyPI version](https://img.shields.io/pypi/v/aegis-trust.svg)](https://pypi.org/project/aegis-trust/)
[![Python versions](https://img.shields.io/pypi/pyversions/aegis-trust.svg)](https://pypi.org/project/aegis-trust/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

You declare what each purpose is allowed to see. Everything else is filtered out before the agent gets it.

---

## 30-Second Quickstart

```python
from aegis_trust import shield

@shield(purpose="customer_support", scope=["name", "issue"])
def get_customer(id):
    return {
        "name": "Tanaka Taro",
        "email": "tanaka@example.com",   # hidden
        "card":  "4242-****-****-1234",  # hidden
        "issue": "Login problem",
    }

get_customer(1)
# → {"name": "Tanaka Taro", "issue": "Login problem"}
```

The agent never sees `email` or `card`. No config files. No middleware. One line.

## 5-Minute Verification

```bash
pip install aegis-trust
python -c "from aegis_trust import shield
f = shield(purpose='support', scope=['name'])(lambda: {'name': 'Aria', 'ssn': '123-45-6789'})
print(f())"
# → {'name': 'Aria'}
```

If you see `{'name': 'Aria'}` (no `ssn`), the install works and field-level filtering is active.

---

## Why this exists

LLM-driven agents see whatever a tool returns. A "look up customer" tool that returns 30 fields hands all 30 to the model on every call. PII, payment data, internal notes — all of it ends up in the prompt window, the logs, and (often) the model provider's training pipeline.

`@shield` collapses the answer down to the fields the declared purpose actually needs, before the agent sees the result. The purpose is a contract: the function says what it is *for*, and the SDK enforces what it is allowed to *return*.

- **Whitelist (`scope`)**: the agent sees only the listed fields.
- **Blacklist (`deny_fields`)**: the agent sees everything except the listed fields.
- **Fail-closed**: on any error, return empty. The decorator never leaks unfiltered data, exceptions, or tracebacks.

## Use Cases

### Quickstart (lite mode, no infrastructure)

```python
from aegis_trust import shield

@shield(purpose="support", scope=["name", "issue"])
def get_customer(customer_id: str) -> dict:
    return db.get_customer(customer_id)
```

### FastAPI

`@shield` stacks with any framework decorator. Put `@shield` directly above the function (closest to it):

```python
from fastapi import FastAPI
from aegis_trust import shield

app = FastAPI()

@app.get("/customer/{customer_id}")
@shield(purpose="support", scope=["name", "issue"])
def get_customer(customer_id: str) -> dict:
    return db.get_customer(customer_id)
```

The HTTP response now contains only `name` and `issue`, regardless of what `db.get_customer` returns.

### FastMCP / MCP server tools

```python
from fastmcp import FastMCP
from aegis_trust import shield

mcp = FastMCP("customer-service")

@mcp.tool()
@shield(purpose="customer_support", scope=["name", "issue"])
def get_customer(customer_id: str) -> dict:
    """Look up a customer by ID."""
    return db.get(customer_id)
```

Every MCP tool call now returns only the fields within the declared `scope` for its `purpose` — fields outside the scope are removed before the tool result reaches the agent (LITE-mode field reduction; `purpose` is a declared context label, not a local authorization decision).

### LangChain / CrewAI adapters (`aegis_trust.adapters`)

Dedicated binders for the major agent frameworks. `shielded_tool()` declares a
shielded data accessor once (shield filtering + serialization baked in); each
`to_<framework>_tool` binder maps it onto that framework's native tool shape.
The binders take **no runtime dependency** on the frameworks — the framework
factory / base class is injected — so they are version-tolerant and unit-tested
without any framework installed.

```python
from langchain_core.tools import StructuredTool
from aegis_trust.adapters import shielded_tool, to_langchain_tool

customer_lookup = shielded_tool(
    name="customer_lookup",
    description="Look up a customer record by ID for support purposes.",
    purpose="customer_support",
    scope=["name", "plan", "issue"],
    handler=lambda customer_id: db.get(customer_id),  # returns 10+ fields
)

# The agent — and the model context, logs, and the provider's training
# pipeline — only ever see {name, plan, issue}.
lc_tool = to_langchain_tool(StructuredTool.from_function, customer_lookup)
```

CrewAI — different agents, different scopes, same data source:

```python
from crewai.tools import BaseTool
from aegis_trust.adapters import shielded_tool, to_crewai_tool

support_lookup = shielded_tool(
    name="customer_lookup_support", description="Support lookup.",
    purpose="customer_support", scope=["name", "plan", "issue"],
    handler=lambda customer_id: db.get(customer_id),
)
billing_lookup = shielded_tool(
    name="customer_lookup_billing", description="Billing lookup.",
    purpose="billing", scope=["name", "plan", "balance_due"],
    handler=lambda customer_id: db.get(customer_id),
)

support_agent = Agent(role="...", tools=[to_crewai_tool(BaseTool, support_lookup)])
billing_agent = Agent(role="...", tools=[to_crewai_tool(BaseTool, billing_lookup)])
```

The shield filters the **return value**, not the arguments — validate and
authorize tool-call arguments in the handler. Failures fail closed as an empty
result (`run()` → empty, `call()` → `""`), never a raised exception. Async
handlers use `await tool.arun(...)` / `await tool.acall(...)`. Runnable examples:
[`examples/langchain_example.py`](examples/langchain_example.py),
[`examples/crewai_example.py`](examples/crewai_example.py).

### Streaming — filter each record as it arrives (record-boundary, LITE only)

`shielded_tool()` buffers the whole return value before filtering. When a handler
yields records *incrementally* (DB cursor, paginated fetch, an upstream LLM
emitting one JSON object per step), `shielded_stream_tool()` filters each **whole
record** at its boundary the moment it is complete — no full-result buffering.

```python
from aegis_trust.adapters import shielded_stream_tool

rows = shielded_stream_tool(
    name="customer_rows",
    description="Stream customer records for a support session.",
    purpose="customer_support",
    scope=["name", "issue"],
    handler=lambda q: db.cursor(q),  # yields rows that may carry ssn/email
)

async for rec in rows.stream("open"):
    ...  # rec is {name, issue} only — filtered as it arrives
```

Each record passes through the **same** `shield()` as the non-streaming adapter
(one filter implementation, one fail-closed contract): a handler error, a
mid-stream iterator error, or a per-record filter error yields a short/empty
stream — never a raw record or a raised exception that could carry withheld
fields. **LITE only**: a partial token can't be field-filtered, and the FULL
`/check-access` pre-execution gate can't run per-record without leaking match
cardinality, so `mode="full"` raises `aegis.shield.stream.full_unsupported` (and
AUTO that resolves to FULL refuses fail-closed). Use the non-streaming
`shielded_tool()` when you need the FULL gate. Runnable example:
[`examples/stream_example.py`](examples/stream_example.py); API + contract:
[`src/aegis_trust/adapters/stream.py`](src/aegis_trust/adapters/stream.py); tests:
[`tests/test_adapters_stream.py`](tests/test_adapters_stream.py).

### aegis.yaml (centralized policies)

For multi-purpose deployments, define policies once in `aegis.yaml`:

```yaml
# aegis.yaml
purposes:
  support:
    scope: ["name", "issue", "profile.age"]
  billing:
    deny_fields: ["card", "ssn", "profile.ssn"]
```

```python
from aegis_trust import shield

# scope/deny_fields pulled from aegis.yaml
@shield(purpose="support")
def get_customer(id: int) -> dict:
    return db.get(id)
```

Requires the optional YAML extra:

```bash
pip install aegis-trust[yaml]
```

### async functions

`@shield` works transparently with `async def`:

```python
from aegis_trust import shield

@shield(purpose="support", scope=["name", "issue"])
async def get_customer(customer_id: str) -> dict:
    return await db.get(customer_id)
```

### Supported return types

`@shield` normalizes common Python return shapes to `dict` before filtering, so the
wrapped function can return objects directly:

| Return type                          | How it's handled                                        |
|--------------------------------------|---------------------------------------------------------|
| `dict`                               | filtered directly                                       |
| `list[dict]`                         | each element filtered                                   |
| `None`                               | passes through                                          |
| `@dataclass` instance                | `dataclasses.asdict()` → filtered                       |
| Pydantic v2 `BaseModel`              | `.model_dump()` → filtered                              |
| Pydantic v1 `BaseModel`              | `.dict()` → filtered                                    |
| SQLAlchemy Declarative instance      | `__table__.columns` → filtered                          |
| Anything else (int, str, opaque obj) | empty value (fail-closed)                               |

Pydantic and SQLAlchemy are **detected by duck typing** — neither is a dependency of
`aegis-trust`. If the conversion raises, `@shield` returns empty (fail-closed) and
emits a **minimum-disclosure** developer diagnostic built from **fixed SDK strings
only** — a `conversion_failed` marker and a fixed `stage=<label>` (e.g.
`stage=pydantic_model_dump`). It withholds the exception message, the traceback, the
object's `repr`, and the **type/exception class names** by default — so PII/secrets
carried by the record (or embedded in a dynamically named class) do not reach your
logs. Hybrid objects that look like both (Pydantic v2 `+` SQLAlchemy Declarative, such
as SQLModel) resolve via the Pydantic v2 branch so serializer customization is preserved.

```python
from dataclasses import dataclass
from aegis_trust import shield

@dataclass
class Customer:
    name: str
    ssn: str

@shield(purpose="support", scope=["name"])
def get_customer():
    return Customer(name="Aria", ssn="111-22-3333")

get_customer()
# → {"name": "Aria"}
```

### Filtering inside lists

Dot-notation drills into each element when the value is a list of dicts:

```python
from aegis_trust import shield

@shield(purpose="support", scope=["users.name"])   # filter each element
def list_users() -> dict:
    return {"users": [
        {"name": "Aria", "ssn": "111-22-3333"},
        {"name": "Ben",  "ssn": "444-55-6666"},
    ]}

list_users()
# → {"users": [{"name": "Aria"}, {"name": "Ben"}]}
```

A **bare** `scope=["users"]` over a list-of-dicts is ambiguous — it whitelists the key
but not the inner fields, so the `ssn` values would pass through. `@shield` treats that
as fail-closed: the key is dropped and a warning points at the dot-notation fix.

```python
@shield(purpose="support", scope=["users"])    # fail-closed drop
def list_users():
    return {"users": [{"name": "Aria", "ssn": "111"}]}

list_users()
# → {}            # users dropped, warning logged: use 'users.<field>'
```

Empty lists (`[]`) and lists of primitives (`["red", "blue"]`) are released as-is — no
inner dicts, no leak path, no warning.

The same contract applies to `deny_fields`: use `deny_fields=["users.ssn"]` to remove
`ssn` from each element; a bare `deny_fields=["ssn"]` removes only the top-level `ssn`
key and does not recurse.

### deny_fields (blacklist with dot-notation)

When the safe set is large and the unsafe set is small, blacklist is clearer:

```python
from aegis_trust import shield

@shield(purpose="billing", deny_fields=["ssn", "profile.ssn", "profile.internal_notes"])
def get_customer(id: int) -> dict:
    return db.get(id)
```

`scope` and `deny_fields` are mutually exclusive. Specifying both raises `ValueError`.

---

## API Summary

### `@shield(purpose, scope=None, *, deny_fields=None)`

Decorator that controls data access based on declared purpose.

- `purpose` (`str`): why the agent needs this data (e.g. `"customer_support"`)
- `scope` (`list[str]`): whitelist — fields the agent is allowed to see
- `deny_fields` (`list[str]`): blacklist — fields to hide; everything else passes

Either `scope` or `deny_fields` is required (not both). Both accept dot-notation: `["profile.age"]`.

On any internal error, the decorated function returns an empty value rather than leaking unfiltered data, exceptions, or tracebacks.

### Testing helpers

```python
from aegis_trust.pytest_plugin import assert_shield_blocked, assert_shield_passed

def test_support_agent_cannot_see_ssn(shield_history):
    get_customer("id-1")
    records = shield_history()
    assert_shield_blocked(records, "ssn")
    assert_shield_passed(records, "name")
```

The `shield_history` fixture is auto-registered via the `pytest11` entry point.

### Local history (optional)

Set `AEGIS_HISTORY=1` to record every `@shield` call to a local SQLite store at `~/.aegis/history.db`:

```bash
AEGIS_HISTORY=1 python my_app.py
aegis history       # show recent calls
aegis stats         # aggregate by purpose / blocked field
```

### Mode (LITE / FULL / AUTO)

| Mode | Behaviour | Requires |
|---|---|---|
| `LITE` | In-process filter only. Deterministic, no I/O. | nothing |
| `FULL` | Filter + audit chain ingest + central policy sync via aegis-core. | aegis-core running + `AEGIS_TOKEN` |
| `AUTO` | Intent-first detection (checks Full-intent *before* any probe). See AUTO behaviour matrix below. | nothing |

### AUTO behaviour matrix (rc4+)

`AEGIS_MODE=auto` (the default) is **intent-first**: it checks Full-intent (`AEGIS_TOKEN` set, or a non-dev URL) **before** any network probe. With no Full-intent it resolves to LITE and makes **zero** network calls. Only with Full-intent does it probe the backend (re-probe TTL = 60 s). Behaviour:

- `AEGIS_MODE=lite` → Lite.
- `AEGIS_MODE=full` → Full (calls fail-closed at the gateway until the backend recovers).
- `AEGIS_MODE=auto` + no Full intent (no `AEGIS_TOKEN` AND no non-dev URL) → Lite.
- `AEGIS_MODE=auto` + Full intent + reachable backend → Full (opportunistic upgrade).
- `AEGIS_MODE=auto` + Full intent + **unreachable backend** → **fail-closed Full** + one `logger.warning`. Silent LITE degrade is suppressed because it would skip the user-visible warning and provide weaker semantics than the user asked for.

### Full mode env vars

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_URL` | `https://localhost:8443/api/v1` | aegis-core REST endpoint (rc4+ **canonical**; parity with npm). |
| `AEGIS_BASE_URL` | — | npm-parity deprecation alias for `AEGIS_URL`. Read only when `AEGIS_URL` is unset; emits one `logger.warning` per process the first time it is read (re-armed by `reset()`). **Removed in v1.0.0.** |
| `AEGIS_TOKEN` | (empty) | Bearer token for auth |
| `AEGIS_MODE` | `auto` | Override mode detection (`full` / `lite`) — see matrix above. |
| `AEGIS_HISTORY` | (unset) | `1` to enable local audit log (`~/.aegis/history.db`). |
| `AEGIS_HISTORY_PATH` | `~/.aegis/history.db` | Local audit file. |

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
- **LITE `shield()` and `doctor.check()` are LOCAL, in-process, and bypassable.** They enforce minimum disclosure for an *honest* caller — `doctor.check()` is a deterministic local diagnostic (no network, no LLM, no gateway) and LITE `shield()` filters in-process. An agent that calls neither is constrained by neither; they are developer-ergonomics minimum-disclosure tooling, not a sandbox or a server-enforced boundary. The recent hardening makes the `doctor`→`shield` path **fail closed by construction** (an honest caller cannot accidentally over-disclose), but attacker-resistant enforcement requires FULL mode. **Drive `shield` from `decision.scope_for_shield()`, never `decision.allowed_data` directly** — `allowed_data` is a diagnostic that stays populated for `REQUIRE_APPROVAL` / `BLOCK`, so using it raw would release data before a required approval.

**Known follow-ups — tracked, not yet shipped:**

- A missing `AEGIS_CAPSULE_ROOT` can still produce a runtime HTTP 500 with no audit record; that 500 path is evaluated after the identity check (#1) but before the unknown-purpose / scope / capsule checks (#2), so it pre-empts guarantee #2.
- Gateway-wide audit-append fail-closed sweep (beyond `/check-access`).
- Debug-log redaction (`RUST_LOG=debug` output hygiene).
- Wiring validated `scope` through to RBAC / Reflex / field-level enforcement.
- SDK access-cache TTL: `authorize()` caches an *allow* decision for 30 s (`_ACCESS_CACHE_TTL_S`). Deny decisions are **never** cached (fail-closed). A same-token server-side policy change is invisible to this SDK process for ≤ 30 s after the last allow; a token rotation (`set_token(...)`) invalidates the entire allow-cache immediately by epoch bump. Parity with the TypeScript SDK `ACCESS_CACHE_TTL_MS = 30_000` (same value, same fail-closed deny semantics). A bounded TTL window for allow decisions is the explicit trade-off; operators that require zero allow-staleness should call `set_token()` on policy change.

---

## Migration from `aegis-shield`

If you were using the TestPyPI distribution `aegis-shield` (versions through `0.6.5.1`), migrate to `aegis-trust`:

```bash
pip uninstall aegis-shield
pip install aegis-trust
```

The import path was renamed to match the package: use `from aegis_trust import shield` (v0.9.0-rc2+). The legacy `from aegis import shield` continues to work via a back-compat shim that emits a `DeprecationWarning` and is slated for removal in v2.0.0.

The package was renamed to `aegis-trust` because `aegis-shield` was already registered on PyPI by an unrelated party.

---

## Security and cryptographic posture

`aegis-trust` is fail-closed by design. On any error inside `@shield` (filtering exception, scope mismatch, internal failure), the decorator returns an empty value rather than leaking unfiltered data, exceptions, or tracebacks.

Release artifacts (the Python wheel/sdist and the npm tarball) are signed with **Sigstore cosign** (keyless OIDC) and logged to the public **Sigstore Rekor** transparency log; CycloneDX SBOMs are attached to each GitHub Release. Verify with `cosign verify-blob` against the assets on the GitHub Release (see the root README supply-chain section). The local SDK audit log is append-only and is **not** itself hash-chained or tamper-evident — server-side audit integrity (`chain_valid`) is a property of the aegis-core gateway in FULL mode.

Vulnerability reports: `contact@aegisagentcontrol.com`. See `SECURITY.md` for the full policy.

## Beyond local filtering

`aegis-trust` is a local-first, open-source SDK (LITE mode by default). For production deployments that need a managed gateway with enforced, server-side policy, email `contact@aegisagentcontrol.com`.

## License

MIT. See `LICENSE`.
