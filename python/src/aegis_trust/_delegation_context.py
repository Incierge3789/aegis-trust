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

# The active delegation token for the current context. ``str`` = an attached
# capability; ``_DELEGATION_DENIED`` = a denied window; ``None`` = no window.
# ContextVar propagates into asyncio tasks and threads started with a copied
# context, which is exactly the spawn-boundary semantics delegate() wants.
_capability_var: ContextVar[str | _DelegationDenied | None] = ContextVar(
    "aegis_capability", default=None
)


def current_capability() -> str | None:
    """The delegation capability attached to the current context (or None)."""
    tok = _capability_var.get()
    return tok if isinstance(tok, str) else None


def _delegation_denied() -> bool:
    return isinstance(_capability_var.get(), _DelegationDenied)
