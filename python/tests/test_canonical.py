"""Canonical contract v0 — loader/emitter tests.

Cross-checks against the schema truth source in schemas/v0/ when jsonschema
is available (v0 requirement: contract tested, not asserted).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_trust.canonical import (
    CANONICAL_AUDIT_SCHEMA_VERSION,
    CanonicalEmitter,
    ENFORCEMENT_MCP_PROXY,
    ENFORCEMENT_SDK,
    load_canonical_policy,
)
from aegis_trust.errors import AegisConfigError

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = REPO_ROOT / "schemas" / "v0"

POLICY_DOC = {
    "policy_schema_version": 0,
    "policy_id": "test-policy",
    "purposes": {
        "customer_data": {
            "scope": ["name", "company"],
            "destinations": {"allow": ["llm:anthropic"]},
        },
        "billing": {
            "deny_fields": ["ssn", "credit_card"],
            "destinations": {"deny": ["webhook:slack"]},
        },
        "locked": {"scope": []},
    },
    "tools": {"query_business_data": "customer_data", "send_invoice": "billing"},
    "roles": {"sales_agent": {"allow_purposes": ["customer_data"]}},
    "defaults": {
        "unknown_purpose": "block",
        "unknown_destination": "block",
        "unknown_tool": "block",
    },
}


@pytest.fixture()
def policy_path(tmp_path: Path) -> Path:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(POLICY_DOC))
    return p


def test_example_policy_in_schemas_dir_loads() -> None:
    example = SCHEMA_DIR / "examples" / "policy.sales-agent.example.json"
    policy = load_canonical_policy(example)
    assert policy.policy_id == "acme-sales-agent-v0"
    assert policy.purpose_for_tool("query_business_data") is not None


def test_load_and_resolve_tool(policy_path: Path) -> None:
    policy = load_canonical_policy(policy_path)
    purpose = policy.purpose_for_tool("query_business_data")
    assert purpose is not None and purpose.name == "customer_data"
    assert policy.purpose_for_tool("unmapped_tool") is None  # caller must block
    declared = policy.purpose_for_tool("unmapped_tool", declared_purpose="billing")
    assert declared is not None and declared.name == "billing"


def test_filter_scope_and_deny(policy_path: Path) -> None:
    policy = load_canonical_policy(policy_path)
    data = {"name": "ACME", "company": "ACME Inc", "email": "x@acme.test", "ssn": "123"}
    filtered, blocked = policy.filter_payload(policy.purposes["customer_data"], data)
    assert filtered == {"name": "ACME", "company": "ACME Inc"}
    assert sorted(blocked) == ["email", "ssn"]
    filtered, blocked = policy.filter_payload(policy.purposes["billing"], data)
    assert "ssn" not in filtered and "credit_card" not in filtered
    assert filtered["name"] == "ACME"


def test_destination_fail_closed(policy_path: Path) -> None:
    policy = load_canonical_policy(policy_path)
    cd = policy.purposes["customer_data"]
    assert cd.destination_allowed("llm:anthropic") is True
    assert cd.destination_allowed("llm:openai") is False
    billing = policy.purposes["billing"]
    assert billing.destination_allowed("webhook:slack") is False
    assert billing.destination_allowed("llm:anthropic") is True
    # no destinations block at all => no egress (fail-closed)
    assert policy.purposes["locked"].destination_allowed("llm:anthropic") is False


def test_role_layer(policy_path: Path) -> None:
    policy = load_canonical_policy(policy_path)
    assert policy.role_allows("sales_agent", "customer_data") is True
    assert policy.role_allows("sales_agent", "billing") is False
    assert (
        policy.role_allows("unknown_role", "billing") is True
    )  # advisory outside gateway


@pytest.mark.parametrize(
    "mutate, code",
    [
        (
            lambda d: d["purposes"]["billing"].update(scope=["a"]),
            "aegis.canonical.purpose.scopeDenyConflict",
        ),
        (
            lambda d: d["purposes"]["billing"].update(deny_fields=[]),
            "aegis.canonical.denyFields.empty",
        ),
        (lambda d: d["purposes"].update(bad={}), "aegis.canonical.purpose.empty"),
        (
            lambda d: d.update(policy_schema_version=1),
            "aegis.canonical.version.unsupported",
        ),
        (
            lambda d: d["tools"].update(x="nonexistent_purpose"),
            "aegis.canonical.tools.unknownPurpose",
        ),
        (
            lambda d: d["defaults"].update(unknown_purpose="allow"),
            "aegis.canonical.defaults.notBlock",
        ),
        (
            lambda d: d["purposes"]["customer_data"]["destinations"].update(deny=["x"]),
            "aegis.canonical.destinations.allowDenyConflict",
        ),
    ],
)
def test_invalid_documents_fail_closed(tmp_path: Path, mutate, code: str) -> None:
    doc = json.loads(json.dumps(POLICY_DOC))
    mutate(doc)
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(AegisConfigError) as exc_info:
        load_canonical_policy(p)
    assert exc_info.value.code == code


def test_emitter_writes_schema_valid_event(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    emitter = CanonicalEmitter(
        ENFORCEMENT_SDK, "trust-sdk-python/test", path=out, policy_id="test-policy"
    )
    event = emitter.emit(
        principal={"agent_id": "test-agent", "transport": "cli"},
        purpose="customer_data",
        operation="query_business_data",
        decision="allow",
        blocked_fields=["email"],
        scope=["name", "company"],
        outcome="access_reduced",
        reason_code="minimum_disclosure",
        mode="lite",
    )
    assert event is not None
    on_disk = json.loads(out.read_text().strip())
    assert on_disk["audit_schema_version"] == CANONICAL_AUDIT_SCHEMA_VERSION
    assert on_disk["enforcement_point"] == "sdk"

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMA_DIR / "aegis-audit-event.v0.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(on_disk)


def test_emitter_invariants() -> None:
    emitter = CanonicalEmitter(
        ENFORCEMENT_MCP_PROXY, "mcp-proxy/test", path="/dev/null"
    )
    with pytest.raises(ValueError, match="destination"):
        emitter.build_event(
            principal={"agent_id": "a"},
            purpose="p",
            operation="o",
            decision="deny",
            blocked_fields=[],
            event_type="egress",
        )
    with pytest.raises(ValueError, match="agent_id or auth_sub"):
        emitter.build_event(
            principal={"role": "x"},
            purpose="p",
            operation="o",
            decision="allow",
            blocked_fields=[],
        )
    with pytest.raises(ValueError, match="enforcement_point"):
        CanonicalEmitter("inline", "x/1")
