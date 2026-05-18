# Agent Integration Guide — aegis-trust

This guide helps AI agents and agent frameworks integrate with `aegis-trust`
for purpose-based data access control.

## For Agent Developers

### 1. Install

```bash
pip install aegis-trust
```

For `aegis.yaml` policy file support:

```bash
pip install aegis-trust[yaml]
```

### 2. Wrap data-fetching functions

```python
from aegis_trust import shield

@shield(purpose="customer_support", scope=["name", "issue", "status"])
def get_ticket(ticket_id: str) -> dict:
    return db.get_ticket(ticket_id)
```

The agent calling `get_ticket()` only sees `name`, `issue`, and `status`.
All other fields (SSN, payment info, internal notes) are filtered out.

### 3. Choose your filtering mode

**Whitelist (`scope`)** — specify exactly what the agent can see:

```python
@shield(purpose="support", scope=["name", "email", "profile.age"])
```

**Blacklist (`deny_fields`)** — specify what to hide:

```python
@shield(purpose="billing", deny_fields=["ssn", "profile.ssn"])
```

`scope` and `deny_fields` are mutually exclusive. Specifying both raises `ValueError`.

### 4. Centralize policies in `aegis.yaml`

```yaml
# aegis.yaml
purposes:
  support:
    scope: ["name", "issue", "profile.age"]
  billing:
    deny_fields: ["ssn", "profile.ssn"]
```

```python
# No scope/deny_fields needed — pulled from aegis.yaml
@shield(purpose="support")
def get_customer(id: int) -> dict:
    return db.get(id)
```

Requires `pip install aegis-trust[yaml]`.

## For Framework Authors

### MCP / FastMCP Integration

```python
from fastmcp import FastMCP
from aegis_trust import shield

mcp = FastMCP("my-server")

@mcp.tool()
@shield(purpose="support", scope=["name", "issue"])
def get_customer(customer_id: str) -> dict:
    return db.get(customer_id)
```

`@shield` works with any decorator. Stack it inside (closer to the function) any
framework decorator that wraps it.

### FastAPI Integration

```python
from fastapi import FastAPI
from aegis_trust import shield

app = FastAPI()

@app.get("/customer/{customer_id}")
@shield(purpose="support", scope=["name", "issue"])
def get_customer(customer_id: str) -> dict:
    return db.get(customer_id)
```

### Testing with pytest

```python
from aegis_trust.pytest_plugin import assert_shield_blocked, assert_shield_passed

def test_support_agent_cannot_see_ssn(shield_history):
    get_customer("id-1")
    records = shield_history()
    assert_shield_blocked(records, "ssn")
    assert_shield_passed(records, "name")
```

The `shield_history` fixture is auto-registered via the `pytest11` entry point.

## Design Principles

- **Minimum Disclosure**: agents see only what their purpose requires
- **Purpose-Driven Access**: every data access declares its purpose explicitly
- **Explicit Data Flow**: errors return empty values rather than leak through messages
- **Fail-closed**: on any error, return empty — never leak data, exceptions, or tracebacks

## Contact

- Security: contact@aegisagentcontrol.com
- Sales: contact@aegisagentcontrol.com
