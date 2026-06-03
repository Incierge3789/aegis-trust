"""CrewAI (Python) binder. Maps a ShieldedTool onto a CrewAI BaseTool subclass.

The CrewAI ``BaseTool`` class is INJECTED by the caller, so aegis-trust takes
no dependency on CrewAI and is immune to its internal version churn. A fresh
BaseTool subclass is built with the shielded ``run`` wired into ``_run``.
"""

from __future__ import annotations

from typing import Any

from aegis_trust.adapters.core import ShieldedTool


def to_crewai_tool(base_tool_cls: type, tool: ShieldedTool) -> Any:
    """Bind a :class:`ShieldedTool` to a CrewAI (Python) tool instance.

    Because the shield lives at the data layer, the same descriptor works for
    any agent that accepts a BaseTool — give each agent its own purpose/scope
    and the same record yields a different per-agent view.

    Example::

        from crewai.tools import BaseTool
        from aegis_trust.adapters import shielded_tool, to_crewai_tool

        support_lookup = shielded_tool(
            name="customer_lookup_support",
            description="Look up a customer for support work.",
            purpose="customer_support",
            scope=["name", "issue"],
            handler=lambda customer_id: db.fetch(customer_id),
        )
        agent = Agent(role="...", tools=[to_crewai_tool(BaseTool, support_lookup)])

    :param base_tool_cls: ``crewai.tools.BaseTool`` (dependency-injected).
    :param tool: the shielded tool descriptor.
    """
    shielded = tool

    class _ShieldedCrewaiTool(base_tool_cls):  # type: ignore[misc, valid-type]
        name: str = shielded.name
        description: str = shielded.description

        def _run(self, **kwargs: Any) -> Any:
            return shielded.run(**kwargs)

    if shielded.schema is not None:
        _ShieldedCrewaiTool.args_schema = shielded.schema  # type: ignore[attr-defined]

    return _ShieldedCrewaiTool()
