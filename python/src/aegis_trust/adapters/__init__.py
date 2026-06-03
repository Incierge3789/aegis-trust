"""aegis-trust framework adapters (Python).

    from aegis_trust.adapters import shielded_tool, to_langchain_tool

``shielded_tool()`` bakes a shield() over a data accessor and produces a
framework-neutral tool descriptor; each ``to_<framework>_tool`` binder maps it
onto a framework's native tool shape. The binders take no runtime dependency on
the frameworks (the framework factory / base class is injected), so they are
version-tolerant and need no framework installed to import or test.
"""

from aegis_trust.adapters.core import ShieldedTool, shielded_tool
from aegis_trust.adapters.stream import ShieldedStreamTool, shielded_stream_tool
from aegis_trust.adapters.langchain import to_langchain_tool
from aegis_trust.adapters.crewai import to_crewai_tool

__all__ = [
    "ShieldedTool",
    "shielded_tool",
    "ShieldedStreamTool",
    "shielded_stream_tool",
    "to_langchain_tool",
    "to_crewai_tool",
]
