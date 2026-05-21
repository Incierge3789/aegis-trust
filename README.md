# aegis-trust

**The trust layer for AI agents.** Declare *purpose* + *scope*; the SDK enforces what data the agent can see. Local-first, fail-closed.

- **Python**: [`pip install aegis-trust`](https://pypi.org/project/aegis-trust/) — source in [`python/`](python/)
- **TypeScript / Node**: [`npm install aegis-trust`](https://www.npmjs.com/package/aegis-trust) — source in [`node/`](node/)

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

- **Python**: `aegis-trust@0.9.0rc5` on PyPI (pre-GA preview). v1.0.0 GA pending 5-oracle readability review + verifier coverage uplift.
- **TypeScript**: `aegis-trust@0.9.0-rc5` on npm (same status).
- **License**: MIT (see [`python/LICENSE`](python/LICENSE) + [`node/LICENSE`](node/LICENSE)).
- **API versioning**: `Aegis-Api-Version: 2026-05-18` (dated header; see [productization-ops/data/api_versioning_policy.yaml](https://github.com/Incierge3789/aegis-trust)).

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
    ├── examples/  # LangChain.js / CrewAI / MCP / Vercel AI SDK / Mastra
    ├── package.json
    └── README.md
```

## Origin

This repository consolidates the Python SDK (previously hosted in `Incierge3789/aegis-shield`) and the TypeScript SDK (previously hosted in `Incierge3789/aegis_core/sdk/node-trust/`) into a single `aegis-trust` SDK home.

The old locations now carry "source moved" notices. Git history of pre-migration commits remains in those source repos.
