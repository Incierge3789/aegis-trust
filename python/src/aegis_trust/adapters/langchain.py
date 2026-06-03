"""LangChain (Python) binder. Maps a ShieldedTool onto a LangChain tool.

The LangChain ``StructuredTool.from_function`` factory is INJECTED by the
caller, so aegis-trust takes no dependency on LangChain and is immune to its
internal version churn — only that public factory signature has to hold.
"""
from __future__ import annotations

from typing import Any, Callable

from aegis_trust.adapters.core import ShieldedTool


def to_langchain_tool(
    structured_tool_from_function: Callable[..., Any],
    tool: ShieldedTool,
    **extra: Any,
) -> Any:
    """Bind a :class:`ShieldedTool` to a LangChain (Python) StructuredTool.

    Example::

        from langchain_core.tools import StructuredTool
        from aegis_trust.adapters import shielded_tool, to_langchain_tool

        lookup = shielded_tool(
            name="customer_lookup",
            description="Look up a customer record by id for support.",
            purpose="customer_support",
            scope=["name", "issue"],
            handler=lambda customer_id: db.fetch(customer_id),
        )
        lc_tool = to_langchain_tool(StructuredTool.from_function, lookup)

    :param structured_tool_from_function: ``StructuredTool.from_function``
        (dependency-injected). The wrapped function returns the filtered value
        serialized to a string (what a LangChain tool emits to the model).
    :param tool: the shielded tool descriptor.
    """
    def _func(**kwargs: Any) -> str:
        return tool.call(**kwargs)

    kwargs: dict[str, Any] = {
        "func": _func,
        "name": tool.name,
        "description": tool.description,
    }
    if tool.schema is not None:
        kwargs["args_schema"] = tool.schema
    kwargs.update(extra)
    return structured_tool_from_function(**kwargs)
