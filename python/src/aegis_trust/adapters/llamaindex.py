"""LlamaIndex (Python) binder. Maps a ShieldedTool onto a LlamaIndex tool.

The LlamaIndex ``FunctionTool.from_defaults`` factory is INJECTED by the
caller, so aegis-trust takes no dependency on LlamaIndex and is immune to its
internal version churn — only that public factory signature has to hold.
"""

from __future__ import annotations

from typing import Any, Callable

from aegis_trust.adapters.core import ShieldedTool


def to_llamaindex_tool(
    function_tool_from_defaults: Callable[..., Any],
    tool: ShieldedTool,
    **extra: Any,
) -> Any:
    """Bind a :class:`ShieldedTool` to a LlamaIndex ``FunctionTool``.

    Example::

        from llama_index.core.tools import FunctionTool
        from aegis_trust.adapters import shielded_tool, to_llamaindex_tool

        lookup = shielded_tool(
            name="customer_lookup",
            description="Look up a customer record by id for support.",
            purpose="customer_support",
            scope=["name", "issue"],
            handler=lambda customer_id: db.fetch(customer_id),
        )
        li_tool = to_llamaindex_tool(FunctionTool.from_defaults, lookup)

    :param function_tool_from_defaults: ``FunctionTool.from_defaults``
        (dependency-injected). The wrapped function returns the filtered value
        serialized to a string (what a LlamaIndex tool emits to the model).
    :param tool: the shielded tool descriptor.
    """

    def _func(**kwargs: Any) -> str:
        return tool.call(**kwargs)

    kwargs: dict[str, Any] = {
        "fn": _func,
        "name": tool.name,
        "description": tool.description,
    }
    if tool.schema is not None:
        # LlamaIndex names this parameter ``fn_schema`` (a pydantic model),
        # unlike LangChain's ``args_schema``.
        kwargs["fn_schema"] = tool.schema
    kwargs.update(extra)
    return function_tool_from_defaults(**kwargs)
