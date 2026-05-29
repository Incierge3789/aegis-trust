# aegis-trust

**The trust layer for AI agents.** Declare *purpose* + *scope*; the SDK enforces what data the agent can see. Local-first, fail-closed.

- **Python**: [`pip install --pre aegis-trust`](https://pypi.org/project/aegis-trust/) — resolves to `0.9.0rc7` (current on PyPI) — source in [`python/`](python/)
- **TypeScript / Node**: [`npm install aegis-trust@rc`](https://www.npmjs.com/package/aegis-trust) — source in [`node/`](node/)

> **Publish status (rc8)**: `0.9.0-rc8` supersedes rc7 with the
> `productization-ops/sprint_015` fail-closed remediation — four Node data-path
> edges reconciled to the Python SDK's fail-closed contract, plus a Node-only
> prototype-name `scope` bypass closed (see `node/CHANGELOG.md`). Python behavior
> is unchanged (it was already fail-closed); rc8 keeps the cross-SDK
> version-lock. npm `aegis-trust@0.9.0-rc8` publishes via Block C Trusted
> Publisher OIDC automation in `.github/workflows/release-attestation.yml` (no
> token, no OTP, npm ≥11.5.1) under the `rc` dist-tag, with `dist-tags.latest`
> promoted to `0.9.0-rc8` so bare `npm install aegis-trust` **and** `@rc` both
> resolve to rc8. **PyPI currently ships `aegis-trust==0.9.0rc7`** (`pip install
> --pre aegis-trust`); the rc8 changes are **Node-only** (the Python SDK was
> already the fail-closed reference — zero Python code change), so PyPI rc7 is
> behavior-current for Python. The rc8 Python artifacts are attached to the
> GitHub Release `v0.9.0-rc8`; the PyPI rc8 version-lock publish is pending the
> release pipeline. The prior
> `0.9.0-rc3` (release-integrity incident F-054) remains npm-deprecated and
> version-scoped. `npm publish --provenance` is intentionally **omitted** while
> this repo is private (npm 422-rejects provenance from private source repos);
> customer-side provenance verification is via `cosign verify-blob` against the
> GitHub Release `.whl` / `.tar.gz` / `.tgz` attached at `v0.9.0-rc8` (Block B
> Phase 2, keyless Sigstore Rekor log).

Both snippets below are **self-contained and run as written** (LITE mode, no
gateway, no token). The literal record stands in for your real data source.

```python
from aegis_trust import shield

@shield(purpose="customer_support", scope=["name", "issue"])
def get_customer(id):
    # your real DB/API call goes here; this literal stands in for a 30-field row
    return {"name": "Tanaka Taro", "issue": "Login problem",
            "email": "t@example.com", "ssn": "123-45-6789"}

print(get_customer(1))
# → {'name': 'Tanaka Taro', 'issue': 'Login problem'} — email/ssn stripped before the agent sees it
```

```typescript
import { shield } from "aegis-trust";

const getCustomer = shield({ purpose: "customer_support", scope: ["name", "issue"] })(
  (_id: string) => ({
    name: "Tanaka Taro", issue: "Login problem",
    email: "t@example.com", ssn: "123-45-6789", // your real fetch goes here
  }),
);

console.log(getCustomer("C-001"));
// → { name: "Tanaka Taro", issue: "Login problem" } — email/ssn stripped before the agent sees it
```

## Status

- **Python**: `aegis-trust==0.9.0rc7` is current on PyPI (`pip install --pre aegis-trust`; pre-GA preview, `STABILITY_LEVEL = "preview"`). The rc8 release was Node-only (no Python code change); the PyPI rc8 version-lock publish is pending. v1.0.0 GA pending 5-oracle readability review + verifier coverage uplift.
- **TypeScript**: `aegis-trust@0.9.0-rc8` is live on npm under the `rc` dist-tag (published via Block C Trusted Publisher OIDC automation). Install with `npm install aegis-trust` (now resolves to rc8 — `dist-tags.latest` promoted to `0.9.0-rc8` on 2026-05-30), `npm install aegis-trust@rc`, or pin `@0.9.0-rc8` explicitly.
- **License**: MIT (see [`LICENSE`](LICENSE); `python/LICENSE` is identical, byte-for-byte).
- **API versioning**: `Aegis-Api-Version: 2026-05-18` (dated header).
- **Not production-ready, not GA, not enterprise-ready.** This is an Alpha preview. SLA: none. Production use is at your own risk.

## Alpha limitations (read before adopting)

Honest list of what does NOT work in `0.9.0-rc8`. We list these here so a real evaluator does not have to discover them from code:

- **LLM streaming responses are not preserved.** `shield()` buffers the entire return value before filtering. SSE / chunked / generator responses from Anthropic, OpenAI, Vercel AI SDK and similar streaming APIs are not supported in rc8. A streaming-aware wrapper is planned for a later release.
- **No first-party adapter packages for Anthropic / OpenAI / Vercel AI SDK / Mastra / LlamaIndex / Bedrock / AutoGen.** These SDKs interoperate with the generic `shield()` wrapper at the data-access boundary (see [Drop-in wrapper pattern](#drop-in-wrapper-pattern) below), but there are no dedicated adapter modules or runnable example files for them yet. Treat the SDKs above as **compatible-by-pattern**, not **integrated**.
- **Python and Node ingest-failure semantics are now aligned (fail-closed) as of rc8.** Both SDKs return a type-shaped empty on a gateway ingest exception in FULL mode — the filtered data is released only after the audit record is durably accepted (AO-003 audit completeness). rc7 and earlier Node returned the filtered data anyway (fail-open on audit); that divergence was reconciled in `productization-ops/sprint_015` (see `node/CHANGELOG.md`).
- **Local audit logs are append-only, NOT hash-chained or tamper-evident in the SDK.** Python writes SQLite (`~/.aegis/history.db`); Node writes JSONL (`~/.aegis/history.jsonl`). These are plain append-only local records (no `prev_hash` chaining); editing or deleting an entry leaves no cryptographic trace. Tamper-evidence is a property of the **aegis-core gateway's** server-side audit log in FULL mode (`/audit/verify` → `chain_valid`), not of these local files. Inspecting the local logs currently requires separate tooling per language.
- **PyPI bare `pip install aegis-trust` returns `0.8.1` (the pre-rename stable); the current pre-release on PyPI is `0.9.0rc7`.** PyPI has no manually movable `latest` for pre-releases, and its default resolver only picks rc lines when `--pre` is set. Use `pip install --pre aegis-trust` (latest pre-release → `0.9.0rc7`) or pin `pip install 'aegis-trust==0.9.0rc7'`. **rc8 is not yet on PyPI** — it was a Node-only fix release; the Python code is unchanged from rc7 (rc7 is behavior-current for Python), and the rc8 Python wheel/sdist are attached to the GitHub Release `v0.9.0-rc8` pending the PyPI version-lock publish. The bare `pip install aegis-trust` → pre-release redirect lands with the **v1.0.0 GA cut** (no rc-tagged release can promote itself to stable). On npm this differs: Block C OIDC automation publishes pre-releases with `--tag rc`, and `dist-tags.latest` was promoted to `0.9.0-rc8` on 2026-05-30, so both `npm install aegis-trust` and `@rc` resolve to `0.9.0-rc8`. (npm has no `--pre`-style exclusion, so leaving `latest` on the deprecated `0.9.0-rc3` would serve a known release-integrity-incident version by default; serving the current clean rc8 is preferred.)
- **Error-code reference page is hosted, not in-repo.** Error envelopes carry `docs_url: https://aegis-trust.dev/errors/<code>` (per [`python/src/aegis_trust/errors.py`](python/src/aegis_trust/errors.py) + [`node/src/errors.ts`](node/src/errors.ts)). The hosted page is the authoritative registry; the in-repo file [`node/docs/errors/README.md`](node/docs/errors/README.md) is a partial mirror. Use the `code` field on `AegisError` as the stable identifier; the Web URL may be empty for some codes during preview.

If any of the above is a blocker for your use case, wait for v1.0 GA rather than adopting rc8.

## Procurement & Compliance posture (Alpha)

Honest disclosure for procurement teams, security review, and compliance officers. None of the below is a marketing claim — it is the literal state of this preview. If your evaluation requires anything beyond what is listed, the answer for `0.9.0-rc8` is "not yet".

**Commercial / procurement**

- **License**: MIT (see [`LICENSE`](LICENSE); `python/LICENSE` is identical byte-for-byte). No contribution under any other license is solicited or accepted.
- **SLA**: **none**. There is no uptime, support response, or remediation timeline commitment in this preview release.
- **Support channel**: GitHub issues at this repo + email `contact@aegisagentcontrol.com`. No paid tier. No 24/7 channel.
- **Vendor of record**: Incierge3789 (info@incierge.jp). Single-maintainer project at preview stage. Procurement teams that require multi-engineer bus-factor evidence should treat this as a risk factor for rc8.
- **Enterprise agreement / DPA / MSA**: not offered for rc8. The MIT license is the only legal instrument.
- **Pricing**: open-source SDK is free. No commercial SKU is available.

**Audit / compliance attestation**

- **SOC 2 Type II / ISO 27001 / PCI-DSS / HIPAA**: **no certification or attestation exists** for `aegis-trust` or its aegis-core gateway dependency in the preview release. Compliance evaluation is the operator's responsibility.
- **GDPR**: the SDK is a *data-minimization tool by design* (declared `purpose` × `scope` enforces field-level reduction before data leaves the function boundary), but no Data Processing Agreement is offered, no controller / processor split is contractually defined, and no DSR (data subject request) tooling is provided. Operators integrating into a GDPR-regulated pipeline must perform their own DPIA.
- **CCPA / CPRA**: same posture as GDPR — minimization helps, no contractual instruments provided.
- **Data residency**: the SDK in `LITE` mode does not transmit data; in `FULL` mode it calls an `aegis-core` gateway whose deployment topology is operator-controlled. There is no managed-service control over residency.
- **Audit log retention**: written locally (`~/.aegis/history.jsonl` for Node, `~/.aegis/history.db` for Python). The SDK does not manage retention, encryption-at-rest, or transport to a SIEM — that is the operator's responsibility.
- **Breach notification**: best-effort via the security disclosure process documented in [`python/SECURITY.md`](python/SECURITY.md) / [`node/SECURITY.md`](node/SECURITY.md) (48h acknowledgment, 7-day triage, 30-day fix for CVSS ≥ 7.0). No track record exists for the preview release.
- **Right to be forgotten / data deletion**: the SDK is stateless except for the local audit log. Deletion of audit entries is the operator's responsibility.
- **SBOM / SLSA / supply-chain attestation**: CycloneDX SBOMs (node + python) and Sigstore cosign-signed SDK artifacts (npm tarball, Python wheel, sdist) are attached to the GitHub Release at `v0.9.0-rc8` (`Block B Phase 2` in `release-attestation.yml`, keyless OIDC signing, Sigstore Rekor public log). npm publish to the `rc` dist-tag happens via Block C Trusted Publisher OIDC (token-free, OTP-free) on the same workflow run. `npm publish --provenance` is **intentionally omitted** while this repo is private (npm registry 422-rejects provenance from private source repos); the `--provenance` flag will be re-enabled the same day the repo flips public. Customer-side provenance verification today is via `cosign verify-blob` against the GitHub Release `.tgz` / `.whl` / `.tar.gz` (byte-identical to the npm-published tarball — same artifact handoff). PyPI Trusted Publisher attestation is the remaining follow-up (currently `twine` + token). Tracked as `supply_chain_attestation` in operational-trust-review.

**What this section is not**: a compliance certification, a legal commitment, a roadmap commitment, or an invitation to negotiate. It is an honest static snapshot of preview-state posture so a procurement or compliance review can make a `proceed / wait for GA / decline` call without a back-and-forth with the maintainer.

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

These are compatible-by-pattern. Purpose-built example files for them are planned but not present in rc8.

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

These snippets are **not adapters**. They are the same generic `shield()` wrapper applied at the data-access boundary. They work in `0.9.0-rc8` today, but they require you to wire them into your framework yourself; the framework integration code is not in this repo.

## Repository layout

```
aegis-trust/
├── python/        # Python SDK (pip install aegis-trust)
│   ├── src/
│   │   ├── aegis_trust/         # canonical module (v0.9.0-rc8+)
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
