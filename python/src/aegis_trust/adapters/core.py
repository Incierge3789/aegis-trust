"""Framework-adapter core (Python). Mirror of node/src/adapters/core.ts.

shield() is the trust boundary; it filters the *return value* of a data
accessor to the declared purpose/scope before that value leaves. An agent
framework's "tool" is that accessor exposed to the model with a name, a
description, and an argument schema. ``shielded_tool()`` bakes the shield in
once and produces a framework-neutral descriptor; the per-framework binders
(``.langchain`` / ``.crewai``) map that descriptor onto each framework's native
tool shape WITHOUT this package depending on — or pinning a version of — any of
them.
"""
from __future__ import annotations

import functools
import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from aegis_trust.shield import shield
from aegis_trust.types import Mode


@dataclass(frozen=True)
class ShieldedTool:
    """Framework-neutral shielded tool descriptor.

    ``run`` returns the filtered value; ``call`` returns it serialized to a
    string (for text-only tool runners). Async handlers use ``arun`` / ``acall``.

    Fail-closed contract (inherited from shield()): a handler error, a denied /
    unreachable FULL-mode gate, or a serializer error resolves to a type-shaped
    empty value (e.g. ``""``), never a raised exception escaping the shield — by
    design, because an exception can carry the very data the shield withholds.
    A framework therefore sees an empty tool result, not a failure to retry on.
    """

    name: str
    description: str
    schema: Any
    _run: Callable[..., Any]
    _serialize: Callable[[Any], str]

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    def call(self, *args: Any, **kwargs: Any) -> str:
        try:
            return self._serialize(self._run(*args, **kwargs))
        except Exception:
            # A serializer error must not propagate past the shield — it could
            # carry the filtered value. Fail closed, symmetric with shield()'s
            # handler-error path.
            return ""

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        result = self._run(*args, **kwargs)
        return await result if inspect.isawaitable(result) else result

    async def acall(self, *args: Any, **kwargs: Any) -> str:
        try:
            return self._serialize(await self.arun(*args, **kwargs))
        except Exception:
            return ""


def shielded_tool(
    *,
    name: str,
    description: str,
    purpose: str,
    handler: Callable[..., Any],
    scope: Sequence[str] | None = None,
    deny_fields: Sequence[str] | None = None,
    mode: Mode | str = "auto",
    schema: Any = None,
    serialize: Callable[[Any], str] | None = None,
) -> ShieldedTool:
    """Build a framework-neutral :class:`ShieldedTool`.

    ``handler`` receives the tool-call arguments and returns the raw record(s);
    its return value is what shield() filters (arguments are not filtered).
    Minimum-disclosure validation is deferred to shield(): with neither
    ``scope`` nor ``deny_fields`` set, the underlying shield() call raises
    ``AegisValidationError`` — the adapter and core share one fail-closed
    contract and one error code.
    """
    # Name the accessor so shield() records the tool name (not the handler's
    # incidental ``__name__``, e.g. "<lambda>") across the audit log / stats /
    # FULL-mode ingest. shield() reads ``fn.__name__`` when it wraps. (mirror of
    # the Node spec.name audit-identity fix.)
    if inspect.iscoroutinefunction(handler):
        @functools.wraps(handler)
        async def _accessor(*a: Any, **k: Any) -> Any:
            return await handler(*a, **k)
    else:
        @functools.wraps(handler)
        def _accessor(*a: Any, **k: Any) -> Any:
            return handler(*a, **k)
    _accessor.__name__ = name
    _accessor.__qualname__ = name

    guarded = shield(
        purpose,
        list(scope) if scope is not None else None,
        deny_fields=list(deny_fields) if deny_fields is not None else None,
        mode=mode,
    )(_accessor)

    _serialize = serialize or (lambda v: json.dumps(v, default=str, ensure_ascii=False))
    return ShieldedTool(
        name=name,
        description=description,
        schema=schema,
        _run=guarded,
        _serialize=_serialize,
    )
