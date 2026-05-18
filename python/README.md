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

Every MCP tool call now respects purpose-based access control.

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
`aegis-trust`. If the conversion raises, `@shield` returns empty. Hybrid objects that
look like both (Pydantic v2 `+` SQLAlchemy Declarative, such as SQLModel) resolve via
the Pydantic v2 branch so serializer customization is preserved.

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

Release evidence is anchored to the Bitcoin blockchain via OpenTimestamps (OTS) for tamper-evident chronology. As of v0.6.4, attestation hashes use SHA-3-512 (NIST FIPS 202) as a pre-PQC bridging measure. OTS is not a post-quantum cryptography substitute; full PQC migration is on the roadmap.

Vulnerability reports: `contact@aegisagentcontrol.com`. See `SECURITY.md` for the full policy.

## Beyond local filtering

`aegis-trust` is the open-source entry point to a broader trust platform. For production deployments with enterprise controls and platform-managed policy orchestration, email `contact@aegisagentcontrol.com`.

## License

MIT. See `LICENSE`.
