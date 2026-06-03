"""Streaming framework-adapter (Python). Mirror of node/src/adapters/stream.ts.

Shield a data accessor that yields a *sequence* of records, filtering each
record at its boundary as it arrives.

Why record-boundary, not token-boundary: shield()'s trust boundary is
field-level minimum disclosure, and field filtering needs a COMPLETE object —
you cannot safely strip ``ssn`` from a half-parsed record. So the streaming
unit here is one fully-formed record, not a partial chunk or a token. A handler
that produces rows/objects incrementally (paginated fetch, DB cursor, an
upstream LLM emitting one JSON object per step) gets each record filtered and
re-emitted the moment it is whole — without buffering the entire result first,
which is the limitation ``shielded_tool()`` has today.

Mode scope — LITE only (v1). Streaming filters each record LOCALLY as it
arrives. FULL mode's pre-execution ``/check-access`` gate cannot be honored on a
stream: the gate must run BEFORE the data accessor executes (no side effects, no
result-cardinality leak on deny), and FULL also carries an audit-completeness
contract (every authorized access ingested before its data is released). A
per-record gate would run the accessor first and emit one placeholder per
matching row on deny — leaking how many rows matched and breaking the
pre-execution guarantee ``shielded_tool()`` gives. So streaming REFUSES FULL
fail-closed (empty stream, accessor never called) rather than silently downgrade
the gate. FULL streaming (open-gate-then-stream + batched audit) is a tracked
follow-up; for FULL today, use ``shielded_tool()``.

Trust contract for the supported (LITE) path: each record passes through the
SAME shield() as the non-streaming adapter, constructed in LITE mode. There is
no second filter implementation and no divergence in the fail-closed guarantee —
LITE is a local, network-free field filter, so per-record cost is negligible.
"""

from __future__ import annotations

import inspect
import warnings
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Sequence

from aegis_trust.errors import AegisValidationError, aegis_docs_url
from aegis_trust.shield import _detect_mode, shield
from aegis_trust.types import Mode


@dataclass(frozen=True)
class ShieldedStreamTool:
    """Framework-neutral streaming shielded tool descriptor.

    ``stream()`` is an async generator that yields each record already filtered
    to the declared scope.

    Fail-closed contract (stream form of shield()'s "empty on error"):
      - If the effective mode is FULL (passed explicitly — caught at
        construction — or AUTO resolving to FULL at run time), ``stream()``
        yields nothing and the handler is NEVER called: streaming does not
        support the FULL gate yet, and refusing beats silently downgrading it.
      - If the handler raises while *starting* the stream, ``stream()`` yields
        nothing — an empty stream, never a raised exception.
      - If the underlying iterator raises *mid-stream*, iteration stops cleanly
        at that point: no further records, no re-raised error, and the raw
        record that triggered the failure is never emitted. Records already
        yielded were filtered and stand.
      - A single record that fails internal filtering resolves (via shield())
        to a type-shaped empty value rather than leaking — consistent with the
        non-streaming adapter.

    A framework therefore observes a (possibly short or empty) stream of safe
    results, never an exception that could carry withheld data. Detect upstream
    outages inside the handler if you need retry/notify.
    """

    name: str
    description: str
    schema: Any
    _guarded: Callable[..., Any]
    _handler: Callable[..., Any]
    _requested_mode: Mode

    async def stream(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        # AUTO can resolve to FULL at run time (token set + backend reachable).
        # Streaming cannot honor the FULL pre-execution gate, so refuse rather
        # than silently skip the authorization the operator configured. The
        # handler is NOT called — no side effects, no cardinality leak.
        if self._requested_mode == Mode.AUTO:
            try:
                resolved = _detect_mode()
            except Exception:
                # Undecidable detect means no reachable FULL backend → LITE.
                resolved = Mode.LITE
            if resolved == Mode.FULL:
                warnings.warn(
                    f"aegis-trust: streaming tool '{self.name}' resolves to FULL "
                    "mode, which streaming does not support yet — failing closed "
                    "to an empty stream (handler not called). Use mode='lite' for "
                    "streaming, or shielded_tool() for the FULL gate.",
                    stacklevel=2,
                )
                return

        try:
            src = self._handler(*args, **kwargs)
            if inspect.isawaitable(src):
                # Handler is a coroutine returning an iterable; resolve it before
                # iterating. An async *generator* is already an async iterable
                # and is not awaitable, so it skips this branch.
                src = await src
        except Exception:
            # Handler raised before producing anything → fail closed to an empty
            # stream. The error is withheld: it could carry the very data the
            # shield is meant to keep from the model.
            return

        try:
            async for record in _aiter(src):
                # shield() (LITE) is itself fail-closed per record: a filter
                # error yields a type-shaped empty value, never the raw record.
                # So this yield is always a safe (filtered or empty) value.
                filtered = self._guarded(record)
                if inspect.isawaitable(filtered):
                    filtered = await filtered
                yield filtered
        except Exception:
            # The underlying iterator raised mid-stream. End iteration here
            # without re-raising and without emitting the in-flight raw record —
            # an exception (or that record) could leak withheld fields. Records
            # already yielded were filtered and stand.
            return


async def _aiter(src: Any) -> AsyncIterator[Any]:
    """Normalize a sync-or-async iterable to an async iterator for ``async for``."""
    if hasattr(src, "__aiter__"):
        async for item in src:
            yield item
        return
    for item in src:
        yield item


def shielded_stream_tool(
    *,
    name: str,
    description: str,
    purpose: str,
    handler: Callable[..., Any],
    scope: Sequence[str] | None = None,
    deny_fields: Sequence[str] | None = None,
    mode: Mode | str = "auto",
    schema: Any = None,
) -> ShieldedStreamTool:
    """Build a framework-neutral :class:`ShieldedStreamTool`.

    ``handler`` receives the tool-call arguments and returns an iterable (sync
    or async, generator or otherwise, or a coroutine resolving to one) of raw
    records; each record's fields are filtered by shield() (arguments are not
    filtered). Minimum-disclosure validation is deferred to shield(): with
    neither ``scope`` nor ``deny_fields`` set, the underlying shield() call
    raises ``AegisValidationError`` — the streaming adapter, the non-streaming
    adapter, and the core share one fail-closed contract and one error code.

    Streaming v1 is LITE-only: passing ``mode="full"`` raises
    ``aegis.shield.stream.full_unsupported``; ``mode="auto"`` is honored only
    while it resolves to LITE (``stream()`` refuses fail-closed if AUTO resolves
    to FULL at run time).
    """
    # Mode validation (parity with shield()'s mode check). A mistyped string
    # ("FULL", "fulll") must raise the rich envelope, not a bare ValueError or a
    # silent downgrade — mode is a trust boundary, and the LITE pin below never
    # reaches shield()'s own check.
    if isinstance(mode, Mode):
        requested = mode
    else:
        try:
            requested = Mode(mode)
        except ValueError:
            valid = " | ".join(m.value for m in Mode)
            raise AegisValidationError(
                f"shielded_stream_tool: invalid mode {mode!r} — expected one of {valid}.",
                code="aegis.shield.mode.invalid",
                remediation=(
                    "Set mode to one of 'lite' | 'full' | 'auto' (lowercase), or use "
                    "the Mode enum (e.g. Mode.LITE). Omit mode to default to auto."
                ),
                docs_url=aegis_docs_url("aegis.shield.mode.invalid"),
            ) from None

    # Streaming v1 is LITE-only. Reject an explicit FULL request loudly at
    # construction (parity with shield()'s spec validation) rather than fail
    # closed silently at stream time.
    if requested == Mode.FULL:
        raise AegisValidationError(
            "shielded_stream_tool: FULL mode is not supported for streaming yet.",
            code="aegis.shield.stream.full_unsupported",
            remediation=(
                "Streaming supports LITE only for now. Use mode='lite' for "
                "streaming, or shielded_tool() (non-streaming) when you need the "
                "FULL /check-access gate."
            ),
            docs_url=aegis_docs_url("aegis.shield.stream.full_unsupported"),
        )

    # One shield() over an async identity record-filter, reused per record,
    # pinned to LITE so it never attempts a per-record /check-access gate. Named
    # ``name`` so shield() records the tool name (not "<lambda>") across the
    # audit log / stats — symmetric with shielded_tool().
    async def _filter(record: Any) -> Any:
        return record

    _filter.__name__ = name
    _filter.__qualname__ = name

    guarded = shield(
        purpose,
        list(scope) if scope is not None else None,
        deny_fields=list(deny_fields) if deny_fields is not None else None,
        mode=Mode.LITE,
    )(_filter)

    return ShieldedStreamTool(
        name=name,
        description=description,
        schema=schema,
        _guarded=guarded,
        _handler=handler,
        _requested_mode=requested,
    )
