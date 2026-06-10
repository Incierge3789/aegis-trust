"""shield-proxy end-to-end tests: real subprocess, real stdio framing.

A fake MCP server returns an over-broad customer record; the proxy must
deliver only the policy's scope to the "host" (this test), block unknown
tools without forwarding them, and emit schema-valid canonical v0 events.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = REPO_ROOT / "schemas" / "v0"

FAKE_SERVER = """
import json, sys
seen_calls = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    record = {"name": "ACME", "company": "ACME Inc",
              "email": "ceo@acme.test", "ssn": "123-45-6789"}
    if msg.get("method") == "tools/call":
        seen_calls.append(msg["params"]["name"])
        result = {"structuredContent": record,
                  "content": [{"type": "text", "text": json.dumps(record)},
                              {"type": "text", "text": "plain note"}]}
    elif msg.get("method") == "resources/read":
        seen_calls.append("resources/read")
        result = {"contents": [{"uri": msg["params"]["uri"],
                                "text": json.dumps(record)}]}
    elif msg.get("method") == "tools/seen":
        result = {"calls": seen_calls}
    elif msg.get("method") == "leak/banner":
        sys.stdout.write("RAW BANNER ssn=123-45-6789\\n")
        sys.stdout.flush()
        result = {"ok": True}
    else:
        result = {"ok": True}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\\n")
    sys.stdout.flush()
"""

POLICY = {
    "policy_schema_version": 0,
    "policy_id": "proxy-test-policy",
    "purposes": {"customer_data": {"scope": ["name", "company"]}},
    "tools": {
        "query_business_data": "customer_data",
        "tools/seen": "customer_data",
        "resources/read": "customer_data",
    },
    "defaults": {"unknown_tool": "block"},
}


@pytest.fixture()
def proxy(tmp_path: Path):
    server_py = tmp_path / "fake_server.py"
    server_py.write_text(FAKE_SERVER)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(POLICY))
    audit_path = tmp_path / "events.jsonl"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegis_trust.mcp_proxy",
            "--policy",
            str(policy_path),
            "--agent-id",
            "claude-code-test",
            "--audit-path",
            str(audit_path),
            "--",
            sys.executable,
            str(server_py),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    yield proc, audit_path
    proc.stdin.close()
    proc.wait(timeout=10)


def rpc(proc: subprocess.Popen, msg: dict) -> dict:
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def test_proxy_filters_known_tool_and_blocks_unknown(proxy) -> None:
    proc, audit_path = proxy

    # non-tools/call traffic passes through untouched
    init = rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"] == {"ok": True}

    # mapped tool: result minimized to scope in BOTH structuredContent and JSON text
    resp = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "query_business_data", "arguments": {}},
        },
    )
    structured = resp["result"]["structuredContent"]
    assert structured == {"name": "ACME", "company": "ACME Inc"}
    text_payload = json.loads(resp["result"]["content"][0]["text"])
    assert set(text_payload) == {"name", "company"}
    assert (
        resp["result"]["content"][1]["text"] == "plain note"
    )  # v0 limit: free text passthrough

    # unknown tool: blocked AND never forwarded to the server
    blocked = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "exfiltrate_everything", "arguments": {}},
        },
    )
    assert blocked["result"]["isError"] is True
    assert "unknown_tool" in blocked["result"]["content"][0]["text"]

    seen = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/seen",
            "params": {"name": "tools/seen"},
        },
    )
    assert "exfiltrate_everything" not in json.dumps(seen)

    # canonical events: schema-valid, enforcement_point=mcp_proxy
    lines = [json.loads(raw) for raw in audit_path.read_text().splitlines()]
    assert len(lines) >= 2
    allow_events = [
        e
        for e in lines
        if e["decision"] == "allow" and e["operation"] == "query_business_data"
    ]
    deny_events = [e for e in lines if e["decision"] == "deny"]
    assert allow_events and deny_events
    assert allow_events[0]["enforcement_point"] == "mcp_proxy"
    assert allow_events[0]["outcome"] == "access_reduced"
    assert sorted(allow_events[0]["blocked_fields"]) == ["email", "ssn"]
    assert allow_events[0]["principal"]["agent_id"] == "claude-code-test"
    assert deny_events[0]["reason_code"] == "unknown_tool"

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMA_DIR / "aegis-audit-event.v0.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    for event in lines:
        validator.validate(event)


def test_proxy_gates_sibling_paths_and_rejects_protocol_abuse(proxy) -> None:
    proc, audit_path = proxy

    # resources/read is a data path on the same boundary: mapped => filtered
    resp = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "resources/read",
            "params": {"uri": "crm://customers/1"},
        },
    )
    payload = json.loads(resp["result"]["contents"][0]["text"])
    assert set(payload) == {"name", "company"}

    # prompts/get is NOT mapped in the policy => blocked, never forwarded
    blocked = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "prompts/get",
            "params": {"name": "system-prompt"},
        },
    )
    assert blocked["result"]["isError"] is True
    assert "unknown_tool" in blocked["result"]["content"][0]["text"]

    # JSON-RPC batch => rejected outright (would bypass per-id filtering)
    batch_reply = rpc(
        proc,
        [
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "query_business_data", "arguments": {}},
            }
        ],
    )
    assert batch_reply["result"]["isError"] is True
    assert "batch_rejected" in batch_reply["result"]["content"][0]["text"]

    # non-JSON server stdout (raw banner with secrets) is dropped, not relayed
    banner_resp = rpc(
        proc, {"jsonrpc": "2.0", "id": 13, "method": "leak/banner", "params": {}}
    )
    assert banner_resp == {"jsonrpc": "2.0", "id": 13, "result": {"ok": True}}

    # nothing blocked/batched ever reached the server
    seen = rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/seen",
            "params": {"name": "tools/seen"},
        },
    )
    seen_text = (
        json.loads(seen["result"]["content"][0]["text"])
        if "content" in seen["result"]
        else seen["result"]
    )
    seen_dump = json.dumps(seen_text)
    assert "prompts/get" not in seen_dump
    assert (
        seen_dump.count("query_business_data") == 0
    )  # the batched call was never forwarded

    # all emitted events remain schema-valid
    jsonschema = pytest.importorskip("jsonschema")
    SCHEMA = json.loads((SCHEMA_DIR / "aegis-audit-event.v0.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for raw in audit_path.read_text().splitlines():
        validator.validate(json.loads(raw))


def test_proxy_refuses_malformed_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps({"policy_schema_version": 0, "purposes": {"p": {"deny_fields": []}}})
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "aegis_trust.mcp_proxy",
            "--policy",
            str(bad),
            "--",
            "true",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0  # fail-closed at startup, server never proxied
