# aegis-trust

**The trust layer for AI agents.** Declare *purpose* + *scope*; the SDK enforces what data the agent can see. Local-first, fail-closed.

- **Python**: [`pip install 'aegis-trust==0.9.0rc5' --pre`](https://pypi.org/project/aegis-trust/) — source in [`python/`](python/)
- **TypeScript / Node**: [`npm install aegis-trust@rc`](https://www.npmjs.com/package/aegis-trust) — source in [`node/`](node/)

```python
from aegis_trust import shield

@shield(purpose="customer_support", scope=["name", "issue"])
def get_customer(id):
    return db.fetch(id)   # returns 30 fields

get_customer(1)
# → {"name": "...", "issue": "..."} — everything else stripped before the agent sees it
```

```typescript
import { shield } from "aegis-trust";

const safeFetch = shield({ purpose: "customer_support", scope: ["name", "issue"] })(db.fetch);
const u = await safeFetch("C-001"); // agent only ever sees { name, issue }
```

## Status

- **Python**: `aegis-trust@0.9.0rc5` on PyPI (pre-GA preview, `STABILITY_LEVEL = "preview"`). v1.0.0 GA pending 5-oracle readability review + verifier coverage uplift.
- **TypeScript**: `aegis-trust@0.9.0-rc5` on npm (same status). npm `latest` tag currently still points to `0.9.0-rc3`; install with `@rc` or pin `@0.9.0-rc5` to get the current preview.
- **License**: MIT (see [`LICENSE`](LICENSE); `python/LICENSE` is identical, byte-for-byte).
- **API versioning**: `Aegis-Api-Version: 2026-05-18` (dated header).
- **Not production-ready, not GA, not enterprise-ready.** This is an Alpha preview. SLA: none. Production use is at your own risk.

## Alpha limitations (read before adopting)

Honest list of what does NOT work in `0.9.0-rc5`. We list these here so a real evaluator does not have to discover them from code:

- **LLM streaming responses are not preserved.** `shield()` buffers the entire return value before filtering. SSE / chunked / generator responses from Anthropic, OpenAI, Vercel AI SDK and similar streaming APIs are not supported in rc5. A streaming-aware wrapper is planned for a later release.
- **No first-party adapter packages for Anthropic / OpenAI / Vercel AI SDK / Mastra / LlamaIndex / Bedrock / AutoGen.** These SDKs interoperate with the generic `shield()` wrapper at the data-access boundary (see [Drop-in wrapper pattern](#drop-in-wrapper-pattern) below), but there are no dedicated adapter modules or runnable example files for them yet. Treat the SDKs above as **compatible-by-pattern**, not **integrated**.
- **Python and Node ingest-failure semantics currently differ.** Python returns empty (fail-closed) on a gateway ingest exception; Node returns the filtered data anyway (fail-open on audit). This divergence will be reconciled before v1.0 GA. Operators that rely on AO-003 audit completeness should prefer Python until then.
- **Audit storage format differs by SDK.** Python writes SQLite (`~/.aegis/history.db`); Node writes JSONL (`~/.aegis/history.jsonl`). Both are hash-linked, but inspecting them currently requires separate tooling per language.
- **No top-level CI yet.** The monorepo root does not have `.github/workflows/`; a PR opened against this repo does not run automated tests on merge today. Top-level CI provisioning is in progress.
- **PyPI `latest` is `0.8.1` (the pre-rename package state).** A bare `pip install aegis-trust` returns rc-era-old code, not rc5. Use the explicit pin in the install command above.
- **Error-code reference page is hosted, not in-repo.** Error envelopes carry `docs_url: https://aegis-trust.dev/errors/<code>` (per [`python/src/aegis_trust/errors.py`](python/src/aegis_trust/errors.py) + [`node/src/errors.ts`](node/src/errors.ts)). The hosted page is the authoritative registry; the in-repo file [`node/docs/errors/README.md`](node/docs/errors/README.md) is a partial mirror. Use the `code` field on `AegisError` as the stable identifier; the Web URL may be empty for some codes during preview.

If any of the above is a blocker for your use case, wait for v1.0 GA rather than adopting rc5.

## Runnable integrations today

The table below lists what has a working example file in this repo and what is exercised by the test suite. If an integration is **not** in this table, it does not have a dedicated example or test yet — use the generic [Drop-in wrapper pattern](#drop-in-wrapper-pattern) instead.

| Integration | Language | Example file(s) | Test |
|---|---|---|---|
| Model Context Protocol (MCP) | Node | [`node/examples/mcpTool.ts`](node/examples/mcpTool.ts), [`node/examples/mcpEndToEnd.ts`](node/examples/mcpEndToEnd.ts) | [`node/tests/mcp/run_end_to_end.mjs`](node/tests/mcp/run_end_to_end.mjs) |
| LangChain.js | Node | [`node/examples/langchainExample.ts`](node/examples/langchainExample.ts) | optional dependency; example falls back when `@langchain/openai` is not installed |
| CrewAI (Node port) | Node | [`node/examples/crewaiExample.ts`](node/examples/crewaiExample.ts) | optional dependency; example falls back when `crewai` is not installed |
| FastAPI / FastMCP | Python | recipes in [`python/README.md`](python/README.md) | underlying `shield()` covered by `python/tests/`; no dedicated FastAPI / FastMCP integration test yet |
| Generic async / deny-fields / multi-purpose / dot-notation / sandbox / crypto-wallet | Node | [`node/examples/`](node/examples/) | per-example |

Integrations that are **not yet runnable as dedicated adapters in this repo** (use the drop-in wrapper instead):

- Anthropic SDK (`anthropic`, `@anthropic-ai/sdk`)
- OpenAI SDK (`openai`)
- Vercel AI SDK (`ai`)
- Mastra (`@mastra/core`)
- LlamaIndex, Bedrock, AutoGen.js

These are compatible-by-pattern. Purpose-built example files for them are planned but not present in rc5.

## Drop-in wrapper pattern

For any framework or SDK that is not in the table above, wrap the **data-access function** (not the LLM client). The wrapped function keeps the same signature and can be passed into any tool registry, message-building step, or callback the framework already accepts.

```python
# Python — wrap your data accessor, then hand it to your agent framework / LLM SDK
from aegis_trust import shield

@shield(purpose="customer_support", scope=["name", "issue"])
def get_customer(id):
    return db.fetch(id)

# Now use get_customer wherever you would have used the raw accessor:
#   - Anthropic / OpenAI / Bedrock: include get_customer(id) in your messages payload
#   - Vercel AI SDK: register get_customer as the execute callback of a tool
#   - LangChain / LlamaIndex / CrewAI / AutoGen: same — pass the wrapped function in
```

```typescript
// Node — same pattern. shield returns a function with the same signature as db.fetch
import { shield } from "aegis-trust";

const getCustomer = shield({
  purpose: "customer_support",
  scope: ["name", "issue"],
})(db.fetch);

// Now hand getCustomer to your framework's tool registry.
// Working examples in this repo: node/examples/langchainExample.ts, node/examples/mcpTool.ts,
// node/examples/crewaiExample.ts.
```

These snippets are **not adapters**. They are the same generic `shield()` wrapper applied at the data-access boundary. They work in `0.9.0-rc5` today, but they require you to wire them into your framework yourself; the framework integration code is not in this repo.

## Repository layout

```
aegis-trust/
├── python/        # Python SDK (pip install aegis-trust)
│   ├── src/
│   │   ├── aegis_trust/         # canonical module (v0.9.0-rc5+)
│   │   └── aegis/               # back-compat shim (DeprecationWarning, removal v2.0.0)
│   ├── tests/
│   ├── pyproject.toml
│   └── README.md
└── node/          # TypeScript / Node SDK (npm install aegis-trust)
    ├── src/
    ├── tests/
    ├── examples/                # MCP, LangChain.js, CrewAI, async, deny-fields, multi-purpose,
    │                            # dot-notation, sandbox, crypto-wallet, docker. (See the
    │                            # Runnable integrations table above for the authoritative list.)
    ├── package.json
    └── README.md
```

## Origin

This repository consolidates the Python SDK (previously hosted in `Incierge3789/aegis-shield`) and the TypeScript SDK (previously hosted in `Incierge3789/aegis_core/sdk/node-trust/`) into a single `aegis-trust` SDK home.

The old locations now carry "source moved" notices. Git history of pre-migration commits remains in those source repos.
