"""Trace context propagation for aegis-trust (Python port, v0.9.0-rc1+).

``with_trace_context(trace_id, fn)`` and the ``trace_context`` context
manager set a contextvars-backed trace for the duration. Any
``shield()``-wrapped call inside reads ``get_trace_context()`` and emits the
``trace_id`` into the audit record, so an agent reasoning step → SDK call →
local history JSONL are linked end-to-end by a single trace id
(OTel-compatible semantics).

contextvars (Python's stdlib) is the asyncio-safe equivalent of Node's
AsyncLocalStorage. Each async task and thread sees its own trace context.

Python port of TypeScript :mod:`aegis-trust` ``src/trace.ts``
(introduced in v0.9.0-rc1).
"""

from __future__ import annotations

import re
import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator

from aegis_trust.errors import AegisValidationError, aegis_docs_url


@dataclass(frozen=True)
class TraceContext:
    """Immutable trace context: trace_id (required) + optional parent_id."""

    trace_id: str
    parent_id: str | None = None


# Cross-review round 3 P0-6 fix (npm side): validate trace_id to prevent
# secrets being persisted into the audit JSONL. Allow id-like printable
# ASCII only, cap length so a stray Bearer token / API key cannot be
# passed as a trace.
_TRACE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


# Error-code labels are camelCase on the wire (S018 doctrine: shared concepts
# use error-code strings identical to the Node SDK — trace.ts emits
# aegis.trace.traceId.invalid / aegis.trace.parentId.invalid, and the
# ecosystem precedent is camelCase, e.g. aegis.audit.idempotencyKey.*).
# The human-readable message keeps the pythonic snake_case argument name.
_CODE_LABELS = {"trace_id": "traceId", "parent_id": "parentId"}


def _assert_trace_id(label: str, value: str) -> None:
    if not isinstance(value, str) or not _TRACE_ID_RE.fullmatch(value):
        code = f"aegis.trace.{_CODE_LABELS[label]}.invalid"
        raise AegisValidationError(
            f"with_trace_context: {label} must match [A-Za-z0-9._:-]{{1,128}}",
            code=code,
            remediation=(
                f"{label} must be 1-128 chars of [A-Za-z0-9._:-]. Generate one with "
                "`new_trace_id()`. Never pass secrets (Bearer tokens, API keys) as "
                "trace_id — the audit JSONL is not a secret store."
            ),
            docs_url=aegis_docs_url(code),
        )


_trace_var: ContextVar[TraceContext | None] = ContextVar("aegis_trace", default=None)


def get_trace_context() -> TraceContext | None:
    """Return the ambient :class:`TraceContext`, or ``None`` if outside scope."""
    return _trace_var.get()


@contextmanager
def trace_context(
    trace_id: str, parent_id: str | None = None
) -> Iterator[TraceContext]:
    """Context manager — set ambient trace_id for the duration of the ``with`` block.

    Usage::

        from aegis_trust.trace import trace_context, new_trace_id

        with trace_context(new_trace_id()):
            safe_fetch(customer_id)  # shield() emits trace_id to audit
    """
    _assert_trace_id("trace_id", trace_id)
    if parent_id is not None:
        _assert_trace_id("parent_id", parent_id)
    ctx = TraceContext(trace_id=trace_id, parent_id=parent_id)
    token = _trace_var.set(ctx)
    try:
        yield ctx
    finally:
        _trace_var.reset(token)


def with_trace_context(trace_id: str, fn, *args, **kwargs):
    """Function-call wrapper variant of :func:`trace_context`.

    ``with_trace_context(trace_id, fn, *args, **kwargs)`` calls ``fn`` with the
    ambient trace set, returning ``fn``'s result.
    """
    with trace_context(trace_id):
        return fn(*args, **kwargs)


def new_trace_id() -> str:
    """Generate a fresh trace_id (UUIDv4-style, 32-char hex)."""
    return secrets.token_hex(16)
