"""Public type definitions for aegis-trust."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Mode(Enum):
    """Shield operating mode."""

    LITE = "lite"
    FULL = "full"
    AUTO = "auto"


@dataclass(frozen=True)
class AccessPolicy:
    """Defines what data an agent can access and why."""

    purpose: str
    scope: list[str]
    deny_fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuditEntry:
    """A single audit log record."""

    seq: int
    timestamp: str
    hash: str
    action: str


@dataclass(frozen=True)
class ShieldResult:
    """Result wrapper returned by @shield in full mode."""

    data: Any
    mode: Mode
    purpose: str
    scope: list[str]
    filtered_keys: list[str] = field(default_factory=list)


# ── Shield API types ───────────────────────────────────────


@dataclass(frozen=True)
class IngestEntry:
    """A single @shield invocation record for /shield/ingest."""

    function: str
    purpose: str
    scope: list[str]
    blocked_fields: list[str]
    timestamp: str
    count: int = 1
    deny_fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class IngestResponse:
    """Response from /shield/ingest."""

    ingested: int
    audit_seq_start: int
    audit_seq_end: int


@dataclass(frozen=True)
class AuditChainStatus:
    """Response from /audit/verify (T-140 / T-154)."""

    chain_valid: bool
    total_entries: int


@dataclass(frozen=True)
class PolicySyncEntry:
    """A single purpose policy for /shield/policy-sync."""

    scope: list[str]
    deny_fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicySyncResponse:
    """Response from /shield/policy-sync."""

    synced: int
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PurposeStats:
    """Per-purpose statistics."""

    calls: int
    blocked: int


@dataclass(frozen=True)
class FieldStats:
    """Per-field block statistics."""

    blocked_count: int


@dataclass(frozen=True)
class FunctionStats:
    """Per-function call statistics."""

    calls: int
    purposes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ShieldStats:
    """Response from /shield/stats."""

    period_from: str
    period_to: str
    total_calls: int
    total_blocked_fields: int
    by_purpose: dict[str, PurposeStats] = field(default_factory=dict)
    by_field: dict[str, FieldStats] = field(default_factory=dict)
    by_function: dict[str, FunctionStats] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityGrant:
    """Response from /capability/mint (AI-native v1, boundary-core
    AI_NATIVE_V1_CONTRACT.md). The token is opaque — only the boundary
    verifies it; clients hand it to sub-agents (delegation.capability)."""

    capability: str
    id: str
    exp: int
    depth: int
    root_delegator: str


@dataclass(frozen=True)
class StreamStatus:
    """Response from /stream/heartbeat: ok | revoked | closed (+ reason)."""

    status: str
    reason: str | None = None
