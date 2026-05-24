# aegis-trust: AI agent data access control.
#
# The public quickstart surface is intentionally a single decorator. Everything
# else (testing helpers, configuration loaders, advanced types, the optional
# enterprise backend client) lives on submodule paths and stays out of the
# top-level autocomplete to keep the agent-facing surface small and clear:
#
#     from aegis_trust import shield
#     from aegis_trust.pytest_plugin import shield_history, assert_shield_blocked
#     from aegis_trust.config import load_config
#     from aegis_trust.types import Mode  # only if you want to type-annotate the parameter
#
# v0.9.0-rc1 additions (internal-ops/sprint_001):
#     from aegis_trust.errors import AegisError, AegisValidationError, AegisConfigError, ...
#     from aegis_trust.trace import trace_context, new_trace_id, get_trace_context
#     from aegis_trust.history import HistoryStore  # .record_idempotent(key=..., ...)
#
from aegis_trust.shield import shield
from aegis_trust.errors import (
    AegisError,
    AegisValidationError,
    AegisConfigError,
    AegisIngestError,
    AegisAuditError,
    AegisHttpError,
    aegis_docs_url,
)
from aegis_trust.trace import (
    TraceContext,
    trace_context,
    with_trace_context,
    get_trace_context,
    new_trace_id,
)

__all__ = [
    "shield",
    "AegisError",
    "AegisValidationError",
    "AegisConfigError",
    "AegisIngestError",
    "AegisAuditError",
    "AegisHttpError",
    "aegis_docs_url",
    "TraceContext",
    "trace_context",
    "with_trace_context",
    "get_trace_context",
    "new_trace_id",
    "AEGIS_API_VERSION",
    "AEGIS_API_VERSION_HEADER",
    "AUDIT_SCHEMA_VERSION",
    "STABILITY_LEVEL",
]
__version__ = "0.9.0-rc6"

# Schema version for audit event format (parity with npm aegis-trust
# AUDIT_SCHEMA_VERSION). Bumped when audit record shape changes.
AUDIT_SCHEMA_VERSION = 1

# Stability level — see docs/VERSIONING.md (mirrors npm SDK).
#   "preview"    → v0.x.y-rc* : public API may change between rc tags.
#   "stable"     → v1+        : SemVer breaking change rules apply.
#   "deprecated" → marked for removal in next major.
STABILITY_LEVEL = "preview"

# Aegis-Api-Version dated header (Stripe-model 7-axis API versioning / internal-ops/sprint_003 Phase C).
# Date-based public contract version. Clients send `Aegis-Api-Version: <YYYY-MM-DD>`;
# unset → SDK uses this default. Registry: ~/internal-ops/ops/internal-ops/data/api_versioning_policy.yaml
# Sunset policy: 18-month notice + 6-month deprecation warning.
AEGIS_API_VERSION = "2026-05-18"
AEGIS_API_VERSION_HEADER = "Aegis-Api-Version"
