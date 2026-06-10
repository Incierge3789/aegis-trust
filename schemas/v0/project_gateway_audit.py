#!/usr/bin/env python3
"""Project gateway AuditRecord v8 JSON into canonical audit event v0.

The gateway keeps its internal chain-hashed AuditRecord untouched (it is the
AO-003 truth source); this projection produces the cross-product wire shape so
one reader can consume sdk / mcp_proxy / gateway streams together.

Usage:
    python3 project_gateway_audit.py < gateway_records.jsonl > canonical.jsonl
    python3 project_gateway_audit.py --selftest

Mapping notes (see DESIGN.md table):
- principal.auth_sub <- auth_sub (authoritative); fallback agent_id <- session_id
- claimed_requester_id -> principal.claimed_id (advisory, forensics only)
- claimed_tenant_id -> principal.tenant_id (advisory; gateway-internal access
  control uses the JWT tenant, which is not in the record)
- reason (free text, may embed values) is NOT copied; only the value-free
  literal "identity_mismatch" is promoted to reason_code (AO-002).
- product-local fields (bytes_returned, task_id, step, actor, trust engine,
  excluded_unmappable_count, pdf_source) are intentionally dropped.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

CANONICAL_AUDIT_SCHEMA_VERSION = 0
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ProjectionError(ValueError):
    pass


def project_record(rec: dict[str, Any], runtime: str = "gateway/1.0") -> dict[str, Any]:
    """Convert one gateway AuditRecord (v1..v8 JSON) to a canonical v0 event.

    Raises ProjectionError (fail-closed: skip-and-count, never emit a guess)
    when required material is missing or inconsistent.
    """
    timestamp = rec.get("timestamp")
    purpose = rec.get("purpose")
    decision_raw = str(rec.get("decision", "")).lower()
    if not timestamp or not purpose or decision_raw not in ("allow", "deny"):
        raise ProjectionError("missing timestamp/purpose or unmappable decision")

    principal: dict[str, Any] = {}
    if rec.get("auth_sub"):
        principal["auth_sub"] = rec["auth_sub"]
    if rec.get("session_id"):
        principal["session_id"] = rec["session_id"]
        if "auth_sub" not in principal:
            principal["agent_id"] = rec["session_id"]
    if not principal.get("auth_sub") and not principal.get("agent_id"):
        raise ProjectionError("no principal identity (auth_sub/session_id both absent)")
    if rec.get("claimed_requester_id"):
        principal["claimed_id"] = rec["claimed_requester_id"]
    if rec.get("identity_mismatch") is not None:
        principal["identity_mismatch"] = bool(rec["identity_mismatch"])
    if rec.get("role"):
        principal["role"] = rec["role"]
    if rec.get("claimed_tenant_id"):
        principal["tenant_id"] = rec["claimed_tenant_id"]
    if rec.get("protocol"):
        principal["transport"] = rec["protocol"]

    if principal.get("identity_mismatch") and decision_raw != "deny":
        raise ProjectionError("identity_mismatch=true with decision!=deny violates the v7 invariant")

    event: dict[str, Any] = {
        "audit_schema_version": CANONICAL_AUDIT_SCHEMA_VERSION,
        "timestamp": timestamp,
        "enforcement_point": "gateway",
        "enforcement_runtime": runtime,
        "event_type": rec.get("event_type") or "access",
        "principal": principal,
        "purpose": purpose,
        "operation": rec.get("query") or "unknown",
        "decision": decision_raw,
        "blocked_fields": [],
        "outcome": "protected" if decision_raw == "allow" else "blocked",
    }
    if event["event_type"] == "egress":
        if not rec.get("destination"):
            raise ProjectionError("egress record without destination (v0 requirement)")
        event["destination"] = rec["destination"]
    elif rec.get("destination"):
        event["destination"] = rec["destination"]

    if isinstance(rec.get("scope"), list):
        event["scope"] = [str(s) for s in rec["scope"]]
    reason = str(rec.get("reason", ""))
    if "identity_mismatch" in reason:
        event["reason_code"] = "identity_mismatch"
    if rec.get("correlation_id"):
        event["correlation_id"] = rec["correlation_id"]
    if rec.get("trace_id"):
        event["trace_id"] = rec["trace_id"]
    for key in ("subject_id_hash", "region", "jurisdiction"):
        if rec.get(key):
            event[key] = rec[key]

    seq = rec.get("seq")
    prev_hash = rec.get("prev_hash", "")
    curr_hash = rec.get("curr_hash", "")
    if isinstance(seq, int) and _HEX64.match(str(prev_hash)) and _HEX64.match(str(curr_hash)):
        event["integrity"] = {"seq": seq, "prev_hash": prev_hash, "curr_hash": curr_hash}
    else:
        raise ProjectionError("gateway record without a valid integrity chain (seq/prev_hash/curr_hash)")
    return event


def _selftest() -> int:
    import copy
    from pathlib import Path

    try:
        import jsonschema
    except ImportError:
        print("FATAL: pip install jsonschema", file=sys.stderr)
        return 2

    schema = json.loads((Path(__file__).resolve().parent / "aegis-audit-event.v0.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    failures: list[str] = []

    def check(name: str, fn) -> None:
        try:
            fn()
            print(f"[PASS] {name}")
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] {name}: {exc}")
            failures.append(name)

    base_v8 = {
        "seq": 18421,
        "timestamp": "2026-06-10T03:15:30Z",
        "correlation_id": "req-0007",
        "session_id": "sess-1",
        "purpose": "customer_contact",
        "scope": ["name", "email"],
        "query": "/api/v1/check-access",
        "role": "viewer",
        "bytes_returned": 512,
        "decision": "allow",
        "reason": "",
        "event_type": "access",
        "protocol": "rest",
        "auth_sub": "agent:sales-02",
        "schema_version": 8,
        "prev_hash": "a" * 64,
        "curr_hash": "b" * 64,
        "trace_id": "req-0007",
    }

    def t_allow():
        ev = project_record(base_v8)
        validator.validate(ev)
        assert ev["enforcement_point"] == "gateway" and ev["integrity"]["seq"] == 18421
        assert "bytes_returned" not in ev  # product-local fields dropped

    def t_identity_mismatch():
        rec = copy.deepcopy(base_v8)
        rec.update(decision="DENY", reason="identity_mismatch: claimed != auth",
                   claimed_requester_id="agent:sales-99", identity_mismatch=True)
        ev = project_record(rec)
        validator.validate(ev)
        assert ev["decision"] == "deny" and ev["reason_code"] == "identity_mismatch"
        assert ev["principal"]["claimed_id"] == "agent:sales-99"
        assert "claimed != auth" not in json.dumps(ev)  # free-text reason never copied (AO-002)

    def t_egress():
        rec = copy.deepcopy(base_v8)
        rec.update(event_type="egress", destination="llm:anthropic")
        ev = project_record(rec)
        validator.validate(ev)
        assert ev["destination"] == "llm:anthropic"

    def t_egress_without_destination_rejected():
        rec = copy.deepcopy(base_v8)
        rec["event_type"] = "egress"
        rec.pop("destination", None)
        try:
            project_record(rec)
        except ProjectionError:
            return
        raise AssertionError("egress without destination must be rejected")

    def t_mismatch_with_allow_rejected():
        rec = copy.deepcopy(base_v8)
        rec.update(identity_mismatch=True, decision="allow")
        try:
            project_record(rec)
        except ProjectionError:
            return
        raise AssertionError("identity_mismatch with allow must be rejected")

    def t_broken_chain_rejected():
        rec = copy.deepcopy(base_v8)
        rec["curr_hash"] = "nothex"
        try:
            project_record(rec)
        except ProjectionError:
            return
        raise AssertionError("invalid chain hash must be rejected")

    check("project:v8-allow", t_allow)
    check("project:v7-identity-mismatch", t_identity_mismatch)
    check("project:v2-egress", t_egress)
    check("project:egress-needs-destination", t_egress_without_destination_rejected)
    check("project:mismatch-forces-deny", t_mismatch_with_allow_rejected)
    check("project:chain-required", t_broken_chain_rejected)

    print()
    if failures:
        print(f"RESULT: {len(failures)} failure(s): {failures}")
        return 1
    print("RESULT: all projection checks passed")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return _selftest()
    ok = skipped = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            sys.stdout.write(json.dumps(project_record(json.loads(line)), ensure_ascii=False) + "\n")
            ok += 1
        except (ValueError, ProjectionError) as exc:
            skipped += 1
            print(f"skip: {exc}", file=sys.stderr)
    print(f"projected={ok} skipped={skipped}", file=sys.stderr)
    return 0 if skipped == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
