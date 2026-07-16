"""Canonical contract v0: policy document loader + audit event emitter.

Implements the cross-PEP contract drafted in ``schemas/v0/`` (one policy
document, one audit event shape, three enforcement points):

- ``load_canonical_policy()`` reads an *aegis-policy v0* document (JSON or
  YAML) — the one policy file shared by the in-process SDK, the MCP proxy,
  and the core gateway.
- ``CanonicalEmitter`` writes *aegis-audit-event v0* records (JSONL), the
  one audit shape every enforcement point emits.

Doctrine carried from aegis.yaml loading (config.py): scope XOR deny_fields,
empty deny_fields invalid, dot-path syntax validation, fail-closed on any
structural doubt. New v0 dimensions: per-purpose ``destinations`` and the
required ``enforcement_point`` on every event.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis_trust.errors import (
    AegisConfigError,
    AegisConfigFileNotFoundError,
    aegis_docs_url,
)
from aegis_trust.shield import (
    _diff_keys,
    _filter_result,
    _freeze_single_pass,
    _parse_paths,
    _to_filterable,
    _validate_field_path,
)

CANONICAL_POLICY_SCHEMA_VERSION = 0
CANONICAL_AUDIT_SCHEMA_VERSION = 0

ENFORCEMENT_SDK = "sdk"
ENFORCEMENT_MCP_PROXY = "mcp_proxy"
ENFORCEMENT_GATEWAY = "gateway"
_ENFORCEMENT_POINTS = frozenset(
    {ENFORCEMENT_SDK, ENFORCEMENT_MCP_PROXY, ENFORCEMENT_GATEWAY}
)

_MAX_LEVELS = frozenset(
    {"public", "operational", "pii", "financial", "confidential", "critical"}
)
_LEGAL_BASES = frozenset(
    {
        "consent",
        "contract",
        "legal_obligation",
        "vital_interests",
        "public_task",
        "legitimate_interests",
    }
)


def _err(message: str, code: str) -> AegisConfigError:
    return AegisConfigError(
        message,
        code=code,
        remediation="Fix the canonical policy document; see schemas/v0/aegis-policy.v0.schema.json.",
        docs_url=aegis_docs_url(code),
    )


@dataclass(frozen=True)
class CanonicalPurpose:
    """One purpose rule from an aegis-policy v0 document."""

    name: str
    scope: list[str] | None
    deny_fields: list[str] | None
    destinations_allow: list[str] | None
    destinations_deny: list[str] | None
    max_level: str | None = None
    legal_basis: str | None = None
    retention_days: int | None = None

    def destination_allowed(self, destination: str) -> bool:
        """Egress check (v0 requirement). Fail-closed: a purpose with no
        ``destinations`` block permits no egress at all."""
        if self.destinations_allow is not None:
            return destination in self.destinations_allow
        if self.destinations_deny is not None:
            return destination not in self.destinations_deny
        return False


@dataclass(frozen=True)
class CanonicalPolicy:
    """Parsed aegis-policy v0 document."""

    policy_id: str | None
    purposes: dict[str, CanonicalPurpose]
    tools: dict[str, str] = field(default_factory=dict)
    roles: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    def purpose_for_tool(
        self, tool_name: str, declared_purpose: str | None = None
    ) -> CanonicalPurpose | None:
        """Resolve the purpose for a tool call. Explicit declaration wins
        (explicit declaration takes precedence). Returns None when neither
        resolves to a known purpose — callers MUST block (unknown_tool=block)."""
        name = declared_purpose or self.tools.get(tool_name)
        if name is None:
            return None
        return self.purposes.get(name)

    def role_allows(self, role: str, purpose: str) -> bool:
        """Role layer (advisory outside the gateway). Unknown role: allowed
        only because role enforcement is the gateway's authoritative job;
        the purpose/tool layer above is always enforced."""
        rule = self.roles.get(role)
        if rule is None:
            return True
        allow = rule.get("allow_purposes")
        if allow is not None:
            return purpose in allow
        deny = rule.get("deny_purposes")
        if deny is not None:
            return purpose not in deny
        return True

    def filter_payload(
        self, purpose: CanonicalPurpose, data: Any
    ) -> tuple[Any, list[str]]:
        """Apply the purpose's field rule. Returns (filtered, blocked_fields).
        Fail-closed: any filtering error returns ('', original-shape unknown)."""
        try:
            normalized = _freeze_single_pass(_to_filterable(data))
            if purpose.scope is not None:
                tree = _parse_paths(purpose.scope)
                filtered = _filter_result(normalized, tree)
            else:
                # deny mode: re-use scope filtering complement via shield's
                # deny tree (broader paths win).
                from aegis_trust.shield import _deny_filter_result

                tree = _parse_paths(purpose.deny_fields or [], broader_wins=True)
                filtered = _deny_filter_result(normalized, tree)
            removed = _diff_keys(normalized, filtered)
            return filtered, removed
        except Exception:
            return "", ["<fail_closed>"]


def _parse_destinations(
    name: str, raw: Any
) -> tuple[list[str] | None, list[str] | None]:
    if raw is None:
        return None, None
    if not isinstance(raw, dict):
        raise _err(
            f"Purpose '{name}': destinations must be a mapping",
            "aegis.canonical.destinations.notMapping",
        )
    allow = raw.get("allow")
    deny = raw.get("deny")
    if (allow is None) == (deny is None):
        raise _err(
            f"Purpose '{name}': destinations requires exactly one of allow/deny",
            "aegis.canonical.destinations.allowDenyConflict",
        )
    for key, values in (("allow", allow), ("deny", deny)):
        if values is None:
            continue
        if not isinstance(values, list) or any(
            not isinstance(v, str) or not v for v in values
        ):
            raise _err(
                f"Purpose '{name}': destinations.{key} must be a list of non-empty strings",
                "aegis.canonical.destinations.notList",
            )
    if deny is not None and len(deny) == 0:
        raise _err(
            f"Purpose '{name}': destinations.deny must not be empty (denying nothing)",
            "aegis.canonical.destinations.denyEmpty",
        )
    return allow, deny


def _parse_purpose(name: str, raw: Any) -> CanonicalPurpose:
    if not isinstance(raw, dict):
        raise _err(
            f"Purpose '{name}' must be a mapping", "aegis.canonical.purpose.notMapping"
        )
    has_scope = "scope" in raw
    has_deny = "deny_fields" in raw
    if has_scope and has_deny:
        raise _err(
            f"Purpose '{name}': scope and deny_fields are mutually exclusive",
            "aegis.canonical.purpose.scopeDenyConflict",
        )
    if not has_scope and not has_deny:
        raise _err(
            f"Purpose '{name}': either scope or deny_fields is required",
            "aegis.canonical.purpose.empty",
        )
    for key in ("scope", "deny_fields"):
        fields = raw.get(key)
        if fields is None:
            continue
        if not isinstance(fields, list) or any(not isinstance(f, str) for f in fields):
            raise _err(
                f"Purpose '{name}': {key} must be a list of strings",
                "aegis.canonical.fields.notList",
            )
        for f in fields:
            _validate_field_path(
                f, error_cls=AegisConfigError, code="aegis.canonical.fieldPath.invalid"
            )
    if has_deny and len(raw["deny_fields"]) == 0:
        raise _err(
            f"Purpose '{name}': deny_fields must not be empty (hiding nothing)",
            "aegis.canonical.denyFields.empty",
        )
    max_level = raw.get("max_level")
    if max_level is not None and max_level not in _MAX_LEVELS:
        raise _err(
            f"Purpose '{name}': invalid max_level '{max_level}'",
            "aegis.canonical.maxLevel.invalid",
        )
    legal_basis = raw.get("legal_basis")
    if legal_basis is not None and legal_basis not in _LEGAL_BASES:
        raise _err(
            f"Purpose '{name}': invalid legal_basis '{legal_basis}'",
            "aegis.canonical.legalBasis.invalid",
        )
    retention_days = raw.get("retention_days")
    if retention_days is not None and (
        not isinstance(retention_days, int) or retention_days < 1
    ):
        raise _err(
            f"Purpose '{name}': retention_days must be a positive integer",
            "aegis.canonical.retentionDays.invalid",
        )
    allow, deny = _parse_destinations(name, raw.get("destinations"))
    return CanonicalPurpose(
        name=name,
        scope=list(raw["scope"]) if has_scope else None,
        deny_fields=list(raw["deny_fields"]) if has_deny else None,
        destinations_allow=allow,
        destinations_deny=deny,
        max_level=max_level,
        legal_basis=legal_basis,
        retention_days=retention_days,
    )


def load_canonical_policy(path: str | Path) -> CanonicalPolicy:
    """Load and validate an aegis-policy v0 document (JSON or YAML).

    Raises AegisConfigError (fail-closed) on any structural violation,
    including a policy_schema_version this reader does not support.
    """
    resolved = Path(path)
    try:
        text = resolved.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        # Coded envelope instead of a raw traceback: the docstring promises
        # AegisConfigError on any structural violation, and a missing policy
        # file is the most common operator mistake at proxy startup.
        raise AegisConfigFileNotFoundError(
            f"Canonical policy file not found: {resolved}",
            code="aegis.canonical.file.notFound",
            remediation=(
                "Check the --policy path passed to aegis-mcp-proxy (or the "
                "load_canonical_policy() argument)."
            ),
            docs_url=aegis_docs_url("aegis.canonical.file.notFound"),
        ) from exc
    if resolved.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - mirrors config.py
            raise _err(
                "pyyaml required for YAML policy documents",
                "aegis.canonical.yamlMissing",
            ) from exc
        raw = yaml.safe_load(text)
    else:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            # Node parity: canonical.ts raises aegis.canonical.topLevel.notJson.
            raise _err(
                "Canonical policy must be valid JSON",
                "aegis.canonical.topLevel.notJson",
            ) from exc
    if not isinstance(raw, dict):
        raise _err(
            "Canonical policy must be a mapping", "aegis.canonical.topLevel.notMapping"
        )

    version = raw.get("policy_schema_version")
    if version != CANONICAL_POLICY_SCHEMA_VERSION:
        raise _err(
            f"Unsupported policy_schema_version {version!r}; this reader supports "
            f"{CANONICAL_POLICY_SCHEMA_VERSION} only (fail-closed on newer versions)",
            "aegis.canonical.version.unsupported",
        )

    purposes_raw = raw.get("purposes")
    if not isinstance(purposes_raw, dict) or not purposes_raw:
        raise _err(
            "'purposes' must be a non-empty mapping",
            "aegis.canonical.purposes.notMapping",
        )
    purposes = {name: _parse_purpose(name, rule) for name, rule in purposes_raw.items()}

    tools_raw = raw.get("tools") or {}
    if not isinstance(tools_raw, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in tools_raw.items()
    ):
        raise _err(
            "'tools' must map tool names to purpose names",
            "aegis.canonical.tools.notMapping",
        )
    for tool, purpose_name in tools_raw.items():
        if purpose_name not in purposes:
            raise _err(
                f"Tool '{tool}' maps to undeclared purpose '{purpose_name}'",
                "aegis.canonical.tools.unknownPurpose",
            )

    roles_raw = raw.get("roles") or {}
    roles: dict[str, dict[str, list[str]]] = {}
    if not isinstance(roles_raw, dict):
        raise _err("'roles' must be a mapping", "aegis.canonical.roles.notMapping")
    for role_name, rule in roles_raw.items():
        if not isinstance(rule, dict):
            raise _err(
                f"Role '{role_name}' must be a mapping",
                "aegis.canonical.roles.notMapping",
            )
        allow = rule.get("allow_purposes")
        deny = rule.get("deny_purposes")
        if (allow is None) == (deny is None):
            raise _err(
                f"Role '{role_name}': exactly one of allow_purposes/deny_purposes required",
                "aegis.canonical.roles.allowDenyConflict",
            )
        if deny is not None and len(deny) == 0:
            raise _err(
                f"Role '{role_name}': deny_purposes must not be empty",
                "aegis.canonical.roles.denyEmpty",
            )
        roles[role_name] = {
            k: list(v)
            for k, v in rule.items()
            if k in ("allow_purposes", "deny_purposes")
        }

    defaults = raw.get("defaults") or {}
    if isinstance(defaults, dict):
        for key, value in defaults.items():
            if (
                key in ("unknown_purpose", "unknown_destination", "unknown_tool")
                and value != "block"
            ):
                raise _err(
                    f"defaults.{key} must be 'block' (v0 admits no permissive default)",
                    "aegis.canonical.defaults.notBlock",
                )

    return CanonicalPolicy(
        policy_id=raw.get("policy_id"), purposes=purposes, tools=tools_raw, roles=roles
    )


class CanonicalEmitter:
    """Append-only JSONL writer for aegis-audit-event v0 records.

    Path resolution: explicit argument > AEGIS_CANONICAL_AUDIT_PATH env >
    ~/.aegis/canonical_events.jsonl. Emission failures never break the
    caller's data path (parity with history.py recording semantics).
    """

    def __init__(
        self,
        enforcement_point: str,
        enforcement_runtime: str,
        path: str | Path | None = None,
        policy_id: str | None = None,
    ) -> None:
        if enforcement_point not in _ENFORCEMENT_POINTS:
            raise ValueError(
                f"enforcement_point must be one of {sorted(_ENFORCEMENT_POINTS)}"
            )
        self.enforcement_point = enforcement_point
        self.enforcement_runtime = enforcement_runtime
        self.policy_id = policy_id
        resolved = path or os.environ.get("AEGIS_CANONICAL_AUDIT_PATH")
        self.path = (
            Path(resolved)
            if resolved
            else Path.home() / ".aegis" / "canonical_events.jsonl"
        )

    def build_event(
        self,
        *,
        principal: dict[str, Any],
        purpose: str,
        operation: str,
        decision: str,
        blocked_fields: list[str],
        event_type: str = "access",
        scope: list[str] | None = None,
        deny_fields: list[str] | None = None,
        allowed_fields: list[str] | None = None,
        outcome: str | None = None,
        reason_code: str | None = None,
        destination: str | None = None,
        mode: str | None = None,
        trace_id: str | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        if event_type == "egress" and not destination:
            raise ValueError("egress events require destination (v0 requirement)")
        if not principal.get("agent_id") and not principal.get("auth_sub"):
            raise ValueError("principal requires agent_id or auth_sub")
        event: dict[str, Any] = {
            "audit_schema_version": CANONICAL_AUDIT_SCHEMA_VERSION,
            "timestamp": timestamp
            or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "enforcement_point": self.enforcement_point,
            "enforcement_runtime": self.enforcement_runtime,
            "event_type": event_type,
            "principal": {k: v for k, v in principal.items() if v is not None},
            "purpose": purpose,
            "operation": operation,
            "decision": decision,
            "blocked_fields": list(blocked_fields),
        }
        optional = {
            "scope": scope,
            "deny_fields": deny_fields,
            "allowed_fields": allowed_fields,
            "outcome": outcome,
            "reason_code": reason_code,
            "destination": destination,
            "policy_id": self.policy_id,
            "mode": mode,
            "trace_id": trace_id,
        }
        event.update({k: v for k, v in optional.items() if v is not None})
        return event

    def emit(self, **kwargs: Any) -> dict[str, Any] | None:
        """Build, append, and return the event. Returns None on write failure
        (never raises into the data path)."""
        event = self.build_event(**kwargs)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
        except OSError:
            return None
        return event
