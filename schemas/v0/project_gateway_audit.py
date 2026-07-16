#!/usr/bin/env python3
"""Project gateway AuditRecord v8 JSON into canonical audit event v0.

The gateway keeps its internal chain-hashed AuditRecord untouched (it is the
AO-003 truth source); this projection produces the cross-product wire shape so
one reader can consume sdk / mcp_proxy / gateway streams together.

Two source shapes are recognized:
1. the monolith gateway AuditRecord (v1..v8 JSON) — original mapping, unchanged;
2. the plane-NATIVE union-ledger receipt (kind="receipt", actor/decision in the
   plane vocabulary) — added 2026-07-05.

Usage:
    python3 project_gateway_audit.py < gateway_records.jsonl > canonical.jsonl
    python3 project_gateway_audit.py --selftest

Mapping notes, monolith shape (see DESIGN.md table):
- principal.auth_sub <- auth_sub (authoritative); fallback agent_id <- session_id
- claimed_requester_id -> principal.claimed_id (advisory, forensics only)
- claimed_tenant_id -> principal.tenant_id (advisory; gateway-internal access
  control uses the JWT tenant, which is not in the record)
- reason (free text, may embed values) is NOT copied; only the value-free
  literal "identity_mismatch" is promoted to reason_code (AO-002).
- product-local fields (bytes_returned, task_id, step, actor, trust engine,
  excluded_unmappable_count, pdf_source) are intentionally dropped.

Mapping notes, plane-NATIVE union-ledger shape:
- detected by kind == "receipt", or by actor + a decision in the native
  vocabulary (BLOCKED / PROTECTED / ACCESS_REDUCED / CHECK_REQUIRED /
  APPROVAL_REQUIRED).
- decision: BLOCKED -> deny; PROTECTED -> allow (outcome=protected);
  ACCESS_REDUCED -> allow (outcome=access_reduced);
  CHECK_REQUIRED -> deny (outcome=check_required);
  APPROVAL_REQUIRED -> deny (outcome=approval_required) — the full five-state
  DecisionOutcome vocabulary (union_ledger.schema.json), mapped per the v0
  outcome contract ("deny maps to blocked|check_required|approval_required":
  a pending check/approval has not granted anything yet, so the binary
  decision is deny until a later PROTECTED/ACCESS_REDUCED receipt lands).
  Any other native decision raises ProjectionError (fail-closed
  skip-and-count, never guessed).
- principal.agent_id <- actor (the plane's actor is the JWT-verified
  requester); principal.role <- role when present.
- enforcement_point stays "gateway" (v0 enum has no "plane" member);
  enforcement_runtime = "plane/1.0" is the stream discriminator.
- reason_code is copied ONLY when it is one of the known value-free literals
  (_NATIVE_REASON_CODES, the schema's ReasonCode vocabulary); anything else is
  dropped, never copied (AO-002).
- integrity: curr_hash/prev_hash arrive as "sha256:<64hex>"; the prefix is
  stripped so the v0 integrity block's ^[0-9a-f]{64}$ pattern holds.
  decision_id -> top-level event_id verbatim (the v0 integrity block is
  closed to extra keys; event_id is the schema's unique-identifier slot).
- records WITHOUT a purpose (heartbeat / boot / lifecycle entries) raise
  ProjectionError — correct fail-closed behavior: they are not authorization
  decisions and must not be guessed into one.
- product-local fields (kind, fragment_tags, hmac_keyed) are dropped.
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


# Plane-NATIVE decision vocabulary -> (v0 decision, v0 outcome).
# All five DecisionOutcome states are mapped; the pending states project to
# deny because nothing has been granted yet (v0 outcome contract).
# Anything else (LIST, lifecycle markers, future verbs) fail-closes.
_NATIVE_DECISION_MAP = {
    "BLOCKED": ("deny", "blocked"),
    "PROTECTED": ("allow", "protected"),
    "ACCESS_REDUCED": ("allow", "access_reduced"),
    "CHECK_REQUIRED": ("deny", "check_required"),
    "APPROVAL_REQUIRED": ("deny", "approval_required"),
}

# Value-free reason_code literals (the v0 schema's ReasonCode vocabulary).
# Only these are ever copied from a native record (AO-002).
_NATIVE_REASON_CODES = frozenset({
    "minimum_disclosure",
    "policy_denied",
    "approval_required",
    "check_required",
    "invalid_scope",
    "destination_denied",
    "identity_mismatch",
    "internal_failure",
})


def _is_native(rec: dict[str, Any]) -> bool:
    """True for plane-NATIVE union-ledger records, False for monolith records."""
    if rec.get("kind") == "receipt":
        return True
    return bool(rec.get("actor")) and str(rec.get("decision", "")) in _NATIVE_DECISION_MAP


def _chain_hex(value: Any) -> str:
    """Strip the native ledger's sha256: prefix; the v0 block wants raw hex."""
    s = str(value or "")
    return s[len("sha256:"):] if s.startswith("sha256:") else s


def _project_native(rec: dict[str, Any], runtime: str = "plane/1.0") -> dict[str, Any]:
    """Convert one plane-NATIVE union-ledger receipt to a canonical v0 event.

    Raises ProjectionError (fail-closed: skip-and-count, never emit a guess)
    when required material is missing or the decision is outside the mapped
    vocabulary. Purpose-less records (heartbeat/boot) skip by design.
    """
    timestamp = rec.get("timestamp")
    purpose = rec.get("purpose")
    if not timestamp or not purpose:
        raise ProjectionError(
            "native record missing timestamp/purpose (heartbeat/boot entries skip fail-closed)")
    decision_native = str(rec.get("decision", ""))
    if decision_native not in _NATIVE_DECISION_MAP:
        raise ProjectionError("unmappable native decision (fail-closed, never guessed)")
    decision, outcome = _NATIVE_DECISION_MAP[decision_native]

    actor = rec.get("actor")
    if not actor:
        raise ProjectionError("native record without actor (no principal identity)")
    principal: dict[str, Any] = {"agent_id": str(actor)}
    if rec.get("role"):
        principal["role"] = rec["role"]

    event: dict[str, Any] = {
        "audit_schema_version": CANONICAL_AUDIT_SCHEMA_VERSION,
        "timestamp": timestamp,
        "enforcement_point": "gateway",
        "enforcement_runtime": runtime,
        "event_type": rec.get("event_type") or "access",
        "principal": principal,
        "purpose": purpose,
        "operation": rec.get("query") or "unknown",
        "decision": decision,
        "blocked_fields": [],
        "outcome": outcome,
    }
    if event["event_type"] == "egress":
        if not rec.get("destination"):
            raise ProjectionError("egress record without destination (v0 requirement)")
        event["destination"] = rec["destination"]

    if isinstance(rec.get("scope"), list):
        event["scope"] = [str(s) for s in rec["scope"]]
    if rec.get("reason_code") in _NATIVE_REASON_CODES:
        event["reason_code"] = rec["reason_code"]
    if rec.get("correlation_id"):
        event["correlation_id"] = rec["correlation_id"]
    if rec.get("decision_id"):
        event["event_id"] = str(rec["decision_id"])

    seq = rec.get("seq")
    prev_hash = _chain_hex(rec.get("prev_hash"))
    curr_hash = _chain_hex(rec.get("curr_hash"))
    if isinstance(seq, int) and _HEX64.match(prev_hash) and _HEX64.match(curr_hash):
        event["integrity"] = {"seq": seq, "prev_hash": prev_hash, "curr_hash": curr_hash}
    else:
        raise ProjectionError(
            "native record without a valid integrity chain (seq/prev_hash/curr_hash)")
    return event


def project_record(rec: dict[str, Any], runtime: str = "gateway/1.0") -> dict[str, Any]:
    """Convert one gateway AuditRecord (v1..v8 JSON) or plane-NATIVE
    union-ledger receipt to a canonical v0 event.

    Raises ProjectionError (fail-closed: skip-and-count, never emit a guess)
    when required material is missing or inconsistent.
    """
    if _is_native(rec):
        return _project_native(rec)
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

    # --- plane-NATIVE union-ledger receipts (REAL records from the live GCS
    # union ledger, 2026-07-05; chain hashes expanded to full length — the
    # source excerpts truncated them) ---
    native_blocked = {
        "actor": "test0", "correlation_id": "cb-test0",
        "curr_hash": "sha256:" + "b3d5" + "0" * 60,
        "decision": "BLOCKED", "decision_id": "sha256:" + "9882" + "1" * 60,
        "event_type": "access", "fragment_tags": [], "hmac_keyed": True,
        "kind": "receipt", "prev_hash": "sha256:" + "9882" + "1" * 60,
        "purpose": "customer_data", "reason_code": "policy_denied",
        "role": "viewer", "scope": ["name_only"], "seq": 158,
        "timestamp": "2026-07-05T02:09:46.246828201Z",
    }
    native_protected = {
        "actor": "test0", "correlation_id": "cb-test0",
        "curr_hash": "sha256:" + "2669" + "2" * 60,
        "decision": "PROTECTED", "decision_id": "sha256:" + "b9dc" + "3" * 60,
        "event_type": "access", "fragment_tags": [], "hmac_keyed": True,
        "kind": "receipt", "prev_hash": "sha256:" + "b9dc" + "3" * 60,
        "purpose": "qa:employee_knowledge_qa", "reason_code": "minimum_disclosure",
        "role": "viewer", "scope": ["nemotek_ai_ops"], "seq": 160,
        "timestamp": "2026-07-05T02:09:46.932481235Z",
    }

    def t_native_blocked():
        ev = project_record(copy.deepcopy(native_blocked))
        validator.validate(ev)
        assert ev["decision"] == "deny" and ev["outcome"] == "blocked"
        assert ev["principal"] == {"agent_id": "test0", "role": "viewer"}
        assert ev["enforcement_point"] == "gateway"
        assert ev["enforcement_runtime"] == "plane/1.0"
        assert ev["reason_code"] == "policy_denied"
        assert ev["event_id"] == native_blocked["decision_id"]
        assert ev["integrity"] == {"seq": 158,
                                   "prev_hash": "9882" + "1" * 60,
                                   "curr_hash": "b3d5" + "0" * 60}
        assert "kind" not in ev and "hmac_keyed" not in ev and "fragment_tags" not in ev

    def t_native_protected():
        ev = project_record(copy.deepcopy(native_protected))
        validator.validate(ev)
        assert ev["decision"] == "allow" and ev["outcome"] == "protected"
        assert ev["purpose"] == "qa:employee_knowledge_qa"
        assert ev["scope"] == ["nemotek_ai_ops"]
        assert ev["reason_code"] == "minimum_disclosure"
        assert ev["enforcement_runtime"] == "plane/1.0"

    def t_native_no_purpose_skips():
        rec = copy.deepcopy(native_blocked)
        rec.pop("purpose")  # heartbeat/boot-style entry: no purpose
        try:
            project_record(rec)
        except ProjectionError:
            return
        raise AssertionError("purpose-less native record must be skipped (fail-closed)")

    def t_native_unknown_decision_rejected():
        rec = copy.deepcopy(native_blocked)
        rec["decision"] = "ESCALATED"
        try:
            project_record(rec)
        except ProjectionError:
            return
        raise AssertionError("unknown native decision must be rejected, never guessed")

    def t_native_freetext_reason_dropped():
        rec = copy.deepcopy(native_protected)
        rec["reason_code"] = "denied because salary=9M"  # never copy free text (AO-002)
        ev = project_record(rec)
        validator.validate(ev)
        assert "reason_code" not in ev
        assert "salary" not in json.dumps(ev)

    def t_native_check_required():
        rec = copy.deepcopy(native_blocked)
        rec.update(decision="CHECK_REQUIRED", reason_code="check_required")
        ev = project_record(rec)
        validator.validate(ev)
        assert ev["decision"] == "deny" and ev["outcome"] == "check_required"
        assert ev["reason_code"] == "check_required"

    def t_native_approval_required():
        rec = copy.deepcopy(native_blocked)
        rec.update(decision="APPROVAL_REQUIRED", reason_code="approval_required")
        ev = project_record(rec)
        validator.validate(ev)
        assert ev["decision"] == "deny" and ev["outcome"] == "approval_required"
        assert ev["reason_code"] == "approval_required"

    def t_native_pending_detected_without_kind():
        # CHECK_REQUIRED/APPROVAL_REQUIRED must trip _is_native even when the
        # record lacks kind="receipt" (actor + native vocabulary suffices).
        rec = copy.deepcopy(native_blocked)
        rec.pop("kind")
        rec["decision"] = "APPROVAL_REQUIRED"
        ev = project_record(rec)
        validator.validate(ev)
        assert ev["decision"] == "deny" and ev["outcome"] == "approval_required"

    check("project:v8-allow", t_allow)
    check("project:v7-identity-mismatch", t_identity_mismatch)
    check("project:v2-egress", t_egress)
    check("project:egress-needs-destination", t_egress_without_destination_rejected)
    check("project:mismatch-forces-deny", t_mismatch_with_allow_rejected)
    check("project:chain-required", t_broken_chain_rejected)
    check("project:native-blocked-deny", t_native_blocked)
    check("project:native-protected-allow", t_native_protected)
    check("project:native-no-purpose-skips", t_native_no_purpose_skips)
    check("project:native-unknown-decision-rejected", t_native_unknown_decision_rejected)
    check("project:native-freetext-reason-dropped", t_native_freetext_reason_dropped)
    check("project:native-check-required-deny", t_native_check_required)
    check("project:native-approval-required-deny", t_native_approval_required)
    check("project:native-pending-detected-without-kind", t_native_pending_detected_without_kind)

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
