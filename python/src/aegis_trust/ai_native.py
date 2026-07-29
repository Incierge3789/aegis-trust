"""AI-native interposition layer (Layer 2) — the §8 product surface.

The wire-floor client methods (``tool_call`` / ``capability_mint`` /
``stream_open`` …) are the contract FLOOR, not the product: an SDK where the
developer must REMEMBER to call ``tool_call()`` before each tool use is
fail-open by forgetting. This module puts the boundary IN the call path
(AO-001 — errors structurally impossible — applied to the SDK):

- :func:`guard_tool` — the FULL-strength sibling of LITE's ``@shield``: the
  same decorator developer experience, but every invocation of the wrapped
  tool is decided by the boundary (``POST /tool-call``) BEFORE it runs.
  Deny / outage / error → the tool never runs and the call returns ``None``
  (the ``@shield`` convention: fail closed, never raise).
- :func:`delegate` — a context manager that mints a (narrowing) child
  capability where the sub-agent is spawned and attaches it to every guarded
  call inside the block via a :class:`~contextvars.ContextVar`. Developers
  never hand-carry tokens (they leak, they log). A failed mint DENIES the
  whole window — running the child un-narrowed would be a widening.
- :func:`stream_session` — a managed continuous-authz session that owns the
  background heartbeat and INTERRUPTS the agent (exception / callback) the
  moment the boundary revokes. A revoked stream must stop the agent, not
  wait to be polled.

Wire contract: boundary-core ``docs/AI_NATIVE_V1_CONTRACT.md`` (frozen
2026-07-03, additive-only).
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import os
import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Callable, Iterator, TypeVar

from aegis_trust._delegation_context import (
    _DELEGATION_DENIED,
    _Grant,
    _capability_var,
    _delegation_denied,
    _DelegationDenied,
    current_capability,
)
from aegis_trust.errors import (
    AegisStreamDenied,
    AegisStreamRevoked,
    AegisValidationError,
    aegis_docs_url,
)

if TYPE_CHECKING:
    # FULL/gateway-mode types only — the runtime import stays inside
    # `_resolve_client()` so importing this module never pulls httpx/attrs
    # into a LITE-only install (same lazy-import discipline as shield.py).
    from aegis_trust.client import AegisClient
    from aegis_trust.types import CapabilityGrant

logger = logging.getLogger("aegis")

F = TypeVar("F", bound=Callable[..., Any])


# The delegation store lives in ``_delegation_context``: ``client.py`` must
# read it too (``check_boundary`` attaches the token), and this module imports
# ``client``, so keeping the store here would close an import cycle.
# ``current_capability`` is imported above and stays importable from here, so
# the public API surface (``__init__.py``) is unchanged.


def _resolve_client(client: AegisClient | None) -> AegisClient:
    if client is not None:
        return client
    from aegis_trust.shield import _get_client

    return _get_client()


def _resolve_owner(owner: str | None) -> str | None:
    """``owner`` param → AEGIS_OWNER → AEGIS_AGENT_ID (the mcp-proxy
    resolution order). None means unresolvable — the caller denies."""
    if owner:
        return owner
    return (
        os.environ.get("AEGIS_OWNER", "").strip()
        or os.environ.get("AEGIS_AGENT_ID", "").strip()
        or None
    )


# ── guard_tool — per-tool-call interposition ─────────────────────────


def guard_tool(
    purpose: str,
    *,
    tool: str | None = None,
    owner: str | None = None,
    fields: list[str] | None = None,
    session_id: str | None = None,
    destination: str | None = None,
    client: AegisClient | None = None,
) -> Callable[[F], F]:
    """Decorator: every invocation is decided at the boundary before it runs.

    The FULL-strength sibling of LITE's ``@shield``: same decorator DX,
    higher enforcement. Each call of the wrapped function first drives
    ``POST /tool-call`` (fail-closed: transport error, non-200, malformed
    body, non-passing outcome, or an unledgered decision is a deny). On
    deny the function is NEVER invoked and the call returns ``None`` — the
    ``@shield`` convention (no exception to handle, nothing to forget).

    Arguments never leave the process — refs and labels only (INV-6): the
    boundary sees ``tool`` / ``purpose`` / ``owner`` / declared ``fields``,
    never the call arguments or the return value.

    An enclosing :func:`delegate` window attaches its capability
    automatically; a DENIED window (failed mint) denies locally without a
    gateway round-trip. If the wrapped function itself raises after the
    grant, the exception is withheld (it can carry the very data the
    boundary governs) and the call returns ``None``.

    Args:
        purpose: why the agent invokes this tool (decided by the boundary).
        tool: boundary tool name; defaults to the wrapped function's name.
        owner: ``principal.owner`` for the gate; defaults to
            ``AEGIS_OWNER`` then ``AEGIS_AGENT_ID`` (unresolvable → deny).
        fields: optional declared field set (``data_ref.field_set``).
        session_id: optional session correlation id.
        destination: optional egress intent (e.g. ``"llm:anthropic"``).
        client: explicit :class:`AegisClient` (defaults to the module client).

    Usage::

        @guard_tool(purpose="customer_data")
        def query_business_data(q): ...

        @guard_tool(purpose="support", tool="crm_lookup", fields=["name"])
        async def lookup(id): ...
    """
    if not isinstance(purpose, str) or not purpose:
        raise AegisValidationError(
            "guard_tool: purpose must be a non-empty string.",
            code="aegis.guard_tool.purpose.required",
            remediation='Pass a non-empty string to `purpose`, e.g. "customer_data".',
            docs_url=aegis_docs_url("aegis.guard_tool.purpose.required"),
        )
    if tool is not None and (not isinstance(tool, str) or not tool):
        raise AegisValidationError(
            "guard_tool: tool must be a non-empty string when given.",
            code="aegis.guard_tool.tool.invalid",
            remediation="Pass a non-empty `tool` name, or omit it to use the function name.",
            docs_url=aegis_docs_url("aegis.guard_tool.tool.invalid"),
        )
    if fields is not None and (
        not isinstance(fields, list) or not all(isinstance(f, str) for f in fields)
    ):
        raise TypeError("fields must be a list of strings")
    _fields = list(fields) if fields is not None else None

    def decorator(fn: F) -> F:
        tool_name = tool or fn.__name__

        def _gate_sync() -> bool:
            """Fail-closed pre-execution gate. True = run the tool."""
            if _delegation_denied():
                logger.warning(
                    "guard_tool: delegation window is denied — '%s' not "
                    "invoked (fail-closed)",
                    fn.__name__,
                )
                return False
            owner_val = _resolve_owner(owner)
            if owner_val is None:
                logger.warning(
                    "guard_tool: no owner resolvable (owner param / "
                    "AEGIS_OWNER / AEGIS_AGENT_ID all unset) — '%s' not "
                    "invoked (fail-closed)",
                    fn.__name__,
                )
                return False
            try:
                allowed = _resolve_client(client).tool_allowed(
                    tool_name,
                    purpose,
                    owner_val,
                    fields=_fields,
                    session_id=session_id,
                    destination=destination,
                    capability=current_capability(),
                )
            except Exception:
                # tool_allowed is itself fail-closed and non-raising; a raise
                # here (e.g. client construction) must never grant access.
                allowed = False
            if not allowed:
                logger.warning(
                    "guard_tool: tool=%s purpose=%s denied by /tool-call — "
                    "'%s' not invoked (fail-closed)",
                    tool_name,
                    purpose,
                    fn.__name__,
                )
            return allowed

        async def _gate_async() -> bool:
            if _delegation_denied():
                logger.warning(
                    "guard_tool: delegation window is denied — '%s' not "
                    "invoked (fail-closed)",
                    fn.__name__,
                )
                return False
            owner_val = _resolve_owner(owner)
            if owner_val is None:
                logger.warning(
                    "guard_tool: no owner resolvable (owner param / "
                    "AEGIS_OWNER / AEGIS_AGENT_ID all unset) — '%s' not "
                    "invoked (fail-closed)",
                    fn.__name__,
                )
                return False
            try:
                allowed = await _resolve_client(client).atool_allowed(
                    tool_name,
                    purpose,
                    owner_val,
                    fields=_fields,
                    session_id=session_id,
                    destination=destination,
                    capability=current_capability(),
                )
            except Exception:
                allowed = False
            if not allowed:
                logger.warning(
                    "guard_tool: tool=%s purpose=%s denied by /tool-call — "
                    "'%s' not invoked (fail-closed)",
                    tool_name,
                    purpose,
                    fn.__name__,
                )
            return allowed

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if not await _gate_async():
                    return None
                try:
                    return await fn(*args, **kwargs)
                except Exception:
                    logger.error(
                        "guard_tool: '%s' raised after gate grant — returning "
                        "None (fail-closed); the exception is withheld (it can "
                        "carry governed data)",
                        fn.__name__,
                    )
                    return None

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not _gate_sync():
                return None
            try:
                return fn(*args, **kwargs)
            except Exception:
                logger.error(
                    "guard_tool: '%s' raised after gate grant — returning "
                    "None (fail-closed); the exception is withheld (it can "
                    "carry governed data)",
                    fn.__name__,
                )
                return None

        return wrapper  # type: ignore[return-value]

    return decorator


# ── delegate — automatic capability propagation at spawn boundaries ──


@contextmanager
def delegate(
    for_agent: str,
    purposes: list[str],
    *,
    scope: list[str] | None = None,
    tools: list[str] | None = None,
    ttl_secs: int | None = None,
    revoke_on_exit: bool = True,
    client: AegisClient | None = None,
) -> Iterator[CapabilityGrant | None]:
    """Context manager: mint a child capability at the sub-agent spawn
    boundary and attach it to every guarded call inside the block.

    Nesting narrows: an enclosing ``delegate()`` window's token becomes the
    ``parent_capability`` of the inner mint, so the boundary enforces that a
    child can only NARROW its parent (422 on widening) and revocation stays
    transitive over the lineage.

    Fail-closed: if the mint is refused (widening, depth, revoked ancestor)
    or unreachable, the window is DENIED — the block still runs (yielding
    ``None``) but every :func:`guard_tool` call inside returns ``None`` and
    :func:`stream_session` refuses to open, without a gateway round-trip.
    Running the child WITHOUT the narrowed token would silently widen its
    authority back to the parent's role; denial is the only safe direction.

    On exit the token is revoked by default (``revoke_on_exit=True``): the
    delegation window closes with the block, transitively cutting any
    matching open streams. Pass ``revoke_on_exit=False`` when the token must
    outlive the block (its ``exp`` still bounds it).

    The yielded :class:`CapabilityGrant` (or ``None`` on a denied window) is
    for observability and for handing to an OUT-OF-PROCESS child
    (``grant.capability``); in-process code should rely on the automatic
    context attachment instead of hand-carrying the token.
    """
    if not isinstance(for_agent, str) or not for_agent:
        raise AegisValidationError(
            "delegate: for_agent must be a non-empty string.",
            code="aegis.delegate.for_agent.required",
            remediation='Pass the sub-agent identity, e.g. for_agent="researcher-1".',
            docs_url=aegis_docs_url("aegis.delegate.for_agent.required"),
        )
    if (
        not isinstance(purposes, list)
        or len(purposes) == 0
        or not all(isinstance(p, str) and p for p in purposes)
    ):
        raise AegisValidationError(
            "delegate: purposes must be a non-empty list of strings "
            "(minimum disclosure — an unbounded delegation is refused).",
            code="aegis.delegate.purposes.required",
            remediation='Enumerate the delegated purposes, e.g. purposes=["customer_data"].',
            docs_url=aegis_docs_url("aegis.delegate.purposes.required"),
        )

    grant: CapabilityGrant | None = None
    resolved: AegisClient | None = None
    if _delegation_denied():
        # A nested window inside an already-denied window stays denied —
        # minting from a denied parent would escape the fail-closed state.
        logger.warning(
            "delegate: enclosing delegation window is denied — nested window "
            "for_agent=%s stays denied (fail-closed)",
            for_agent,
        )
        token: str | _DelegationDenied = _DELEGATION_DENIED
    else:
        try:
            resolved = _resolve_client(client)
            grant = resolved.capability_mint(
                for_agent,
                list(purposes),
                scope=list(scope) if scope is not None else None,
                tools=list(tools) if tools is not None else None,
                ttl_secs=ttl_secs,
                parent_capability=current_capability(),
            )
            token = _Grant(grant.capability, client._base_url)
        except Exception:
            # Mint refused or unreachable. The exception detail is withheld
            # (fixed strings only — house diagnostic discipline).
            logger.warning(
                "delegate: capability mint failed for_agent=%s — the "
                "delegation window is DENIED (fail-closed): guarded calls "
                "inside return None, stream sessions refuse to open",
                for_agent,
            )
            token = _DELEGATION_DENIED
    ctx_token = _capability_var.set(token)
    try:
        yield grant
    finally:
        _capability_var.reset(ctx_token)
        if grant is not None and revoke_on_exit and resolved is not None:
            try:
                resolved.capability_revoke(capability=grant.capability)
            except Exception:
                logger.warning(
                    "delegate: capability revoke on exit failed (already "
                    "expired/revoked, or gateway unreachable) — the token's "
                    "exp still bounds it"
                )


# ── stream_session — managed continuous authz ───────────────────────


def _default_interrupt_main() -> None:  # pragma: no cover — patched in tests
    import _thread

    _thread.interrupt_main()


# Indirection so tests can observe/patch the last-resort interruption
# without raising KeyboardInterrupt in the test runner's main thread.
_interrupt_main = _default_interrupt_main


class StreamSession:
    """Managed continuous-authz session (``with`` / ``async with``).

    Owns the whole stream lifecycle so the developer cannot get it wrong:

    - **Open**: ``POST /stream/open`` with the given Common Envelope (an
      enclosing :func:`delegate` capability is attached automatically). A
      deny — or a denied delegation window — raises
      :class:`AegisStreamDenied` BEFORE the block runs.
    - **Heartbeat**: a background revalidation loop (``/stream/heartbeat``)
      every ``heartbeat_interval`` seconds. ``max_heartbeat_failures``
      consecutive transport failures count as revocation
      (``gateway_unavailable``) — an unverifiable stream is a stopped
      stream, never a silently-unmonitored one.
    - **Interrupt**: the moment the boundary revokes, ``on_revoke(reason)``
      is called (if given). In the async form the session task is cancelled
      and the block raises :class:`AegisStreamRevoked`. In the sync form,
      when no callback is given, the main thread is interrupted as a last
      resort; either way ``__exit__`` raises :class:`AegisStreamRevoked` so
      a revoked session can never look like a clean run.
    - **Close**: a normal exit closes the stream (witnessed) best-effort.

    Introspection: ``.stream_id``, ``.decision``, ``.revoked`` (a
    :class:`threading.Event`), ``.revoked_reason``.
    """

    def __init__(
        self,
        envelope: dict[str, Any],
        *,
        heartbeat_interval: float = 5.0,
        max_heartbeat_failures: int = 3,
        on_revoke: Callable[[str], None] | None = None,
        client: AegisClient | None = None,
    ) -> None:
        if not isinstance(envelope, dict) or not envelope:
            raise AegisValidationError(
                "stream_session: envelope must be a non-empty dict "
                "(a full Common Envelope — the same body /v1/decide takes).",
                code="aegis.stream.envelope.required",
                remediation="Pass the Common Envelope dict used for /v1/decide.",
                docs_url=aegis_docs_url("aegis.stream.envelope.required"),
            )
        if heartbeat_interval <= 0:
            raise AegisValidationError(
                "stream_session: heartbeat_interval must be > 0.",
                code="aegis.stream.interval.invalid",
                remediation="Pass a positive heartbeat_interval in seconds (default 5.0).",
                docs_url=aegis_docs_url("aegis.stream.interval.invalid"),
            )
        self._envelope = envelope
        self._interval = float(heartbeat_interval)
        self._max_failures = max(1, int(max_heartbeat_failures))
        self._on_revoke = on_revoke
        self._client_arg = client

        self.stream_id: str | None = None
        self.decision: dict[str, Any] | None = None
        self.revoked = threading.Event()
        self.revoked_reason: str | None = None

        self._stop = threading.Event()
        self._hb_thread: threading.Thread | None = None
        self._hb_task: asyncio.Task[None] | None = None
        self._block_task: asyncio.Task[Any] | None = None
        self._cancelled_block = False

    # ── shared pieces ────────────────────────────────────────────

    def _client(self) -> AegisClient:
        return _resolve_client(self._client_arg)

    def _envelope_with_capability(self) -> dict[str, Any]:
        tok = current_capability()
        if tok is None:
            return self._envelope
        env = dict(self._envelope)
        delegation = dict(env.get("delegation") or {})
        delegation.setdefault("capability", tok)
        env["delegation"] = delegation
        return env

    def _pre_open_check(self) -> None:
        if _delegation_denied():
            raise AegisStreamDenied(
                "stream_session: the enclosing delegation window is denied — "
                "the stream is not opened (fail-closed).",
                code="aegis.stream.delegation_denied",
                remediation=(
                    "The delegate() mint failed, so everything inside the "
                    "window is denied. Fix the delegation (narrowing, depth, "
                    "revoked ancestor) or open the session outside the window."
                ),
                docs_url=aegis_docs_url("aegis.stream.delegation_denied"),
            )

    def _accept_open(self, body: dict[str, Any]) -> None:
        stream = body.get("stream")
        if stream is None:
            raise AegisStreamDenied(
                "stream_session: the boundary did not grant a stream "
                "(denied or unledgered decision).",
                code="aegis.stream.denied",
                remediation=(
                    "Gate on the decision: only PROTECTED / ACCESS_REDUCED "
                    "AND ledgered opens a stream. Check purpose/scope/role "
                    "and any active ceremony (duress / legal hold)."
                ),
                docs_url=aegis_docs_url("aegis.stream.denied"),
            )
        self.stream_id = stream["stream_id"]
        self.decision = body.get("decision")

    def _open_failed(self, exc: Exception) -> AegisStreamDenied:
        logger.warning(
            "stream_session: /stream/open failed — the session is denied "
            "(fail-closed); the transport error detail is chained"
        )
        return AegisStreamDenied(
            "stream_session: /stream/open failed — the session is denied "
            "(fail-closed).",
            code="aegis.stream.open_failed",
            remediation=(
                "The boundary was unreachable or returned a non-200. The "
                "agent block did not run. Retry when the gateway recovers."
            ),
            docs_url=aegis_docs_url("aegis.stream.open_failed"),
            cause=exc,
        )

    def _revoke_now(self, reason: str) -> None:
        """Record revocation and fire the interruption paths (idempotent)."""
        if self.revoked.is_set():
            return
        self.revoked_reason = reason
        self.revoked.set()
        logger.warning(
            "stream_session: stream %s revoked (reason=%s) — interrupting the agent",
            self.stream_id,
            reason,
        )
        if self._on_revoke is not None:
            try:
                self._on_revoke(reason)
            except Exception:
                logger.error(
                    "stream_session: on_revoke callback raised — continuing "
                    "with the interrupt (the revocation still stands)"
                )

    def _raise_revoked(self, cause: BaseException | None = None) -> None:
        reason = self.revoked_reason or "revoked"
        exc = AegisStreamRevoked(
            f"stream_session: the boundary revoked the stream (reason={reason}) "
            "— the agent was stopped.",
            code="aegis.stream.revoked",
            remediation=(
                "Stop the work driven by this session. Re-open a session "
                "when the revoking condition (duress / legal hold / "
                "delegation expiry / revocation) is lifted."
            ),
            docs_url=aegis_docs_url("aegis.stream.revoked"),
            reason=reason,
        )
        if cause is not None:
            raise exc from cause
        raise exc

    # ── sync form ────────────────────────────────────────────────

    def __enter__(self) -> StreamSession:
        self._pre_open_check()
        try:
            body = self._client().stream_open(self._envelope_with_capability())
        except Exception as exc:
            raise self._open_failed(exc) from exc
        self._accept_open(body)
        self._hb_thread = threading.Thread(
            target=self._hb_loop_sync,
            name=f"aegis-stream-heartbeat-{self.stream_id}",
            daemon=True,
        )
        self._hb_thread.start()
        return self

    def _hb_loop_sync(self) -> None:
        failures = 0
        while not self._stop.wait(self._interval):
            try:
                status = self._client().stream_heartbeat(self.stream_id or "")
            except Exception:
                failures += 1
                if failures < self._max_failures:
                    continue
                self._revoke_now("gateway_unavailable")
                self._interrupt_sync()
                return
            failures = 0
            if status.status == "ok":
                continue
            self._revoke_now(status.reason or status.status)
            self._interrupt_sync()
            return

    def _interrupt_sync(self) -> None:
        # Callback given → the callback IS the interruption channel (plus
        # the AegisStreamRevoked raised at __exit__). No callback → interrupt
        # the main thread as a last resort so the revocation cannot be
        # ignored until the block happens to finish.
        if self._on_revoke is None:
            try:
                _interrupt_main()
            except Exception:  # pragma: no cover — interpreter shutdown
                pass

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._stop.set()
        if self._hb_thread is not None:
            self._hb_thread.join(timeout=self._interval + 5.0)
        if self.revoked.is_set():
            # A revoked session can never look like a clean run. If the
            # block raised (KeyboardInterrupt from the last-resort
            # interrupt, or anything else), chain it.
            self._raise_revoked(exc if isinstance(exc, BaseException) else None)
        # Normal end (or a block exception, which propagates): witnessed
        # close, best-effort.
        try:
            if self.stream_id is not None:
                self._client().stream_close(self.stream_id)
        except Exception:
            logger.warning(
                "stream_session: stream close failed (already cut by a "
                "ceremony / revocation, or gateway unreachable)"
            )

    # ── async form ───────────────────────────────────────────────

    async def __aenter__(self) -> StreamSession:
        self._pre_open_check()
        try:
            body = await self._client().astream_open(self._envelope_with_capability())
        except Exception as exc:
            raise self._open_failed(exc) from exc
        self._accept_open(body)
        self._block_task = asyncio.current_task()
        self._hb_task = asyncio.get_running_loop().create_task(self._hb_loop_async())
        return self

    async def _hb_loop_async(self) -> None:
        failures = 0
        while True:
            await asyncio.sleep(self._interval)
            try:
                status = await self._client().astream_heartbeat(self.stream_id or "")
            except asyncio.CancelledError:
                raise
            except Exception:
                failures += 1
                if failures < self._max_failures:
                    continue
                self._interrupt_async("gateway_unavailable")
                return
            failures = 0
            if status.status == "ok":
                continue
            self._interrupt_async(status.reason or status.status)
            return

    def _interrupt_async(self, reason: str) -> None:
        self._revoke_now(reason)
        if self._block_task is not None and not self._block_task.done():
            self._cancelled_block = True
            self._block_task.cancel()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._hb_task is not None and not self._hb_task.done():
            self._hb_task.cancel()
            try:
                await self._hb_task
            except (asyncio.CancelledError, Exception):
                pass
        if self.revoked.is_set():
            if (
                exc_type is asyncio.CancelledError
                and self._cancelled_block
                and self._block_task is not None
            ):
                # Our own interruption — absorb the cancellation and raise
                # the typed revocation instead. uncancel() (3.11+) balances
                # the cancel count so the raise below isn't re-cancelled.
                if hasattr(self._block_task, "uncancel"):
                    self._block_task.uncancel()
                self._raise_revoked()
            self._raise_revoked(exc if isinstance(exc, BaseException) else None)
        if exc_type is asyncio.CancelledError:
            # External cancellation: don't touch the network from a
            # cancelled task; the stream's server-side lifecycle (heartbeat
            # expiry / ceremonies) bounds it.
            return
        try:
            if self.stream_id is not None:
                await self._client().astream_close(self.stream_id)
        except Exception:
            logger.warning(
                "stream_session: stream close failed (already cut by a "
                "ceremony / revocation, or gateway unreachable)"
            )


def stream_session(
    envelope: dict[str, Any],
    *,
    heartbeat_interval: float = 5.0,
    max_heartbeat_failures: int = 3,
    on_revoke: Callable[[str], None] | None = None,
    client: AegisClient | None = None,
) -> StreamSession:
    """Open a managed continuous-authz session (see :class:`StreamSession`).

    Usage::

        with stream_session(envelope, on_revoke=stop_agent) as s:
            run_agent(s)          # s.revoked / s.revoked_reason observable

        async with stream_session(envelope) as s:
            await run_agent(s)    # revocation cancels the block and raises
                                  # AegisStreamRevoked
    """
    return StreamSession(
        envelope,
        heartbeat_interval=heartbeat_interval,
        max_heartbeat_failures=max_heartbeat_failures,
        on_revoke=on_revoke,
        client=client,
    )
