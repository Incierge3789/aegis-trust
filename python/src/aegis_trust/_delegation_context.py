"""Delegation context — the context-local store holding the capability token
attached by an enclosing :func:`~aegis_trust.ai_native.delegate` window.

This lives in its own module for one structural reason: BOTH the AI-native
interposition layer (``ai_native.py``) and the wire-floor client
(``client.py``) must read it, and ``ai_native.py`` already imports
``client.py`` (lazily, but the dependency direction is fixed). Putting the
store in either of them and importing it from the other would close an
import cycle. A leaf module importing nothing but :mod:`contextvars` cannot.

Dependency-free by construction: a LITE-only install must be able to import
this without pulling httpx/attrs (same discipline as ``shield.py``).

``ai_native`` re-exports :func:`current_capability` so the public API surface
(``__init__.py``) is unchanged. Node parity: ``node/src/delegationContext.ts``.
"""

from __future__ import annotations

from contextvars import ContextVar


class _DelegationDenied:
    """Sentinel carried by the capability ContextVar when a ``delegate()``
    mint failed: every guarded call inside the window fails closed locally
    (no gateway round-trip, no un-narrowed execution)."""

    __slots__ = ()


_DELEGATION_DENIED = _DelegationDenied()


class _Grant:
    """A minted capability together with the origin it was minted against.

    The token alone is a bearer credential: whoever reads the store can send it
    anywhere. Cross-review (codex, 2026-07-29, severity high) showed the
    consequence — a SECOND ``AegisClient`` constructed inside the window and
    pointed at a different base URL would have the token auto-attached, shipping
    a capability minted for one boundary to a different one. ``delegate()``
    knows which client minted the grant, so the store carries that origin and
    the send path refuses a mismatch locally.

    ``origin`` is the minting client's normalized base URL — the comparable
    identity that actually decides where the token goes. Object identity would
    also refuse a legitimately re-constructed client for the same boundary.
    Node twin: ``node/src/delegationContext.ts`` ``DelegationGrant``.
    """

    __slots__ = ("origin", "token")

    def __init__(self, token: str, origin: str) -> None:
        self.token = token
        self.origin = origin


# The active delegation token for the current context. ``_Grant`` = an attached
# capability bound to its minting origin; ``_DELEGATION_DENIED`` = a denied
# window; ``None`` = no window. ContextVar propagates into asyncio tasks and
# threads started with a copied context — the spawn-boundary semantics
# delegate() wants.
_capability_var: ContextVar[str | _Grant | _DelegationDenied | None] = ContextVar(
    "aegis_capability", default=None
)


def _grant_of(value: object) -> _Grant | None:
    if isinstance(value, str):
        return _Grant(value, "")
    if isinstance(value, _Grant):
        return value
    return None


def current_capability() -> str | None:
    """The delegation capability attached to the current context (or None).

    INTROSPECTION ONLY — this ignores origin binding. Anything that puts the
    token on the wire must use :func:`current_capability_for` instead, so a
    token minted for one boundary is never shipped to another. Kept unchanged
    because it is re-exported as public API.
    """
    grant = _grant_of(_capability_var.get())
    return grant.token if grant else None


def current_capability_for(origin: str) -> str | None:
    """The ambient capability, but ONLY if it was minted against ``origin``.

    Returns ``None`` on mismatch — fail-closed: an unbound token is not
    attached rather than attached hopefully. A bare-string store entry is a
    legacy/unbound entry and is never auto-attached to a specific origin.
    """
    grant = _grant_of(_capability_var.get())
    if grant is None or not grant.origin:
        return None
    return grant.token if grant.origin == origin else None


def _delegation_denied() -> bool:
    return isinstance(_capability_var.get(), _DelegationDenied)
