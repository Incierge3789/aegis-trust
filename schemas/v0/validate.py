#!/usr/bin/env python3
"""Validation harness for the canonical contract v0.

Positive: every examples/*.json validates against its schema.
Negative: mutations that violate carried invariants must FAIL validation
(deny_fields=[], egress without destination, identity_mismatch with allow,
missing enforcement_point, unknown top-level key).

Usage: python3 validate.py  (exit 0 = all pass, exit 1 = any failure)
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("FATAL: pip install jsonschema", file=sys.stderr)
    sys.exit(2)

HERE = Path(__file__).resolve().parent
POLICY_SCHEMA = json.loads((HERE / "aegis-policy.v0.schema.json").read_text())
EVENT_SCHEMA = json.loads((HERE / "aegis-audit-event.v0.schema.json").read_text())
IDENTITY_SCHEMA = json.loads((HERE / "aegis-identity.v0.schema.json").read_text())

failures: list[str] = []


def schema_for(example_name: str) -> dict:
    """Route an example file to its contract by filename prefix."""
    if example_name.startswith("policy."):
        return POLICY_SCHEMA
    if example_name.startswith("identity."):
        return IDENTITY_SCHEMA
    return EVENT_SCHEMA


def check(name: str, schema: dict, doc: dict, expect_valid: bool) -> None:
    validator = jsonschema.Draft202012Validator(schema)
    errors = list(validator.iter_errors(doc))
    ok = (not errors) == expect_valid
    status = "PASS" if ok else "FAIL"
    detail = "" if not errors else f" ({errors[0].message[:100]})"
    print(f"[{status}] {name}: valid={not errors} expected_valid={expect_valid}{detail}")
    if not ok:
        failures.append(name)


# --- positive: all examples validate ---
for path in sorted((HERE / "examples").glob("*.json")):
    doc = json.loads(path.read_text())
    check(f"example:{path.name}", schema_for(path.name), doc, expect_valid=True)

policy = json.loads((HERE / "examples" / "policy.sales-agent.example.json").read_text())
event = json.loads((HERE / "examples" / "event.sdk-access.example.json").read_text())
egress = json.loads((HERE / "examples" / "event.mcp-proxy-egress-deny.example.json").read_text())
mismatch = json.loads((HERE / "examples" / "event.gateway-identity-mismatch.example.json").read_text())
identity = json.loads((HERE / "examples" / "identity.static-key.example.json").read_text())
identity_core = json.loads((HERE / "examples" / "identity.core-issued.example.json").read_text())

# --- negative: policy invariants ---
bad = copy.deepcopy(policy)
bad["purposes"]["billing"]["deny_fields"] = []
check("policy:deny_fields-empty-invalid", POLICY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(policy)
bad["purposes"]["billing"]["scope"] = ["name"]  # scope AND deny_fields
check("policy:scope-xor-deny_fields", POLICY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(policy)
del bad["purposes"]["read_only"]["scope"]  # neither scope nor deny_fields
check("policy:purpose-must-have-rule", POLICY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(policy)
bad["purposes"]["customer_data"]["destinations"] = {"allow": ["llm:anthropic"], "deny": ["llm:openai"]}
check("policy:destinations-allow-xor-deny", POLICY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(policy)
bad["defaults"]["unknown_purpose"] = "passthrough"
check("policy:no-permissive-default", POLICY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(policy)
bad["purposes"]["customer_data"]["scope"] = ["profile..ssn"]
check("policy:field-path-syntax", POLICY_SCHEMA, bad, expect_valid=False)

ok2 = copy.deepcopy(policy)
ok2["purposes"]["read_only"]["scope"] = []
check("policy:empty-scope-valid", POLICY_SCHEMA, ok2, expect_valid=True)

# --- negative: audit event invariants ---
bad = copy.deepcopy(event)
del bad["enforcement_point"]
check("event:enforcement_point-required", EVENT_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(egress)
del bad["destination"]
check("event:egress-requires-destination", EVENT_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(mismatch)
bad["decision"] = "allow"
check("event:identity_mismatch-forces-deny", EVENT_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(event)
del bad["principal"]["agent_id"]  # neither agent_id nor auth_sub
check("event:principal-needs-id", EVENT_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(event)
bad["audit_schema_version"] = 1
check("event:version-pinned-v0", EVENT_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(event)
bad["bytes_returned"] = 123  # product-local field must not leak into canonical
check("event:no-unknown-fields", EVENT_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(mismatch)
bad["integrity"]["prev_hash"] = "nothex"
check("event:integrity-hash-format", EVENT_SCHEMA, bad, expect_valid=False)

# --- negative: principal identity invariants ---
bad = copy.deepcopy(identity)
bad["assurance"] = "core_issued"  # core_issued without auth_sub/issuer/not_after
check("identity:core_issued-requires-binding", IDENTITY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(identity)
bad["auth_sub"] = "smuggled"  # static_key must carry no authoritative subject
check("identity:static_key-carries-no-subject", IDENTITY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(identity_core)
del bad["not_after"]  # half-bound identity (auth_sub/issuer without expiry)
check("identity:no-half-bound-identity", IDENTITY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(identity)
bad["identity_schema_version"] = 1
check("identity:version-pinned-v0", IDENTITY_SCHEMA, bad, expect_valid=False)

bad = copy.deepcopy(identity)
bad["api_key"] = "sk-secret"  # secrets / product-local fields must never appear
check("identity:no-unknown-fields", IDENTITY_SCHEMA, bad, expect_valid=False)

print()
if failures:
    print(f"RESULT: {len(failures)} failure(s): {failures}")
    sys.exit(1)
print("RESULT: all checks passed")
