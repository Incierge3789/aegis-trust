# aegis-trust LITE — Artifact Inventory and Metadata

Everything an external evaluator can download, read, or run for LITE mode,
with the commands that verify each item. Version numbers in this file are
**time-of-writing snapshots**; the verification commands are the source of
truth.

## 1. Packages

| Artifact | Registry | Name | Version (at writing) | License |
|---|---|---|---|---|
| Node SDK | npm | `aegis-trust` | 0.9.2 | MIT |
| Python SDK | PyPI | `aegis-trust` | 0.9.2 | MIT |

**Verify (one command, all sources):**

```bash
cd node && npm run parity          # local files + git tag + live npm + live PyPI
cd node && npm run parity -- --offline   # same check without network (registries skipped)
```

`scripts/version-parity.mjs` compares `node/package.json`, `node/VERSION`,
`node/src/index.ts`, `python/pyproject.toml`, the latest git tag, and (online)
the live registry versions, normalized PEP 440-style. Exit 0 = full parity.

## 2. Schemas (public contract, v0)

| Artifact | Path | What it pins |
|---|---|---|
| Policy schema | `schemas/v0/aegis-policy.v0.schema.json` | The one policy document shape shared by every enforcement point (SDK in-process, proxy, gateway) |
| Audit event schema | `schemas/v0/aegis-audit-event.v0.schema.json` | The one audit-event shape emitted across enforcement points |
| Design notes | `schemas/v0/DESIGN.md` | Why one contract, three enforcement points |
| Validator | `schemas/v0/validate.py` | Validates policy/audit documents against the v0 schemas |
| Examples | `schemas/v0/examples/` | Known-good documents |

## 3. SDK source layout

| Surface | Node | Python |
|---|---|---|
| In-process shield (LITE core) | `node/src/shield.ts`, `node/src/filter.ts` | `python/src/aegis_trust/shield.py` |
| Types (canonical: Python) | `node/src/types.ts` | `python/src/aegis_trust/types.py` |
| Client (FULL path + metering hook) | `node/src/client.ts` | `python/src/aegis_trust/client.py` |
| Boundary receipt surface | `node/src/client.ts` (`checkBoundary` → `BoundaryDecisionView`) | `python/src/aegis_trust/client.py` (`check_boundary` / `acheck_boundary` → `BoundaryDecisionView`) |
| Machine-parseable errors | `node/src/errors.ts` | `python/src/aegis_trust/errors.py` |
| Agent-readable summary | `node/llms.txt` | `python/llms.txt` |
| Versioning doctrine | `node/docs/VERSIONING.md` | (shared doctrine, documented on the Node side) |

## 4. Runnable examples (referenced by the quickstart)

Node (`node/examples/`): `quickstart.ts`, `asyncExample.ts`,
`denyFieldsExample.ts`, `dotNotationExample.ts`, `multiPurpose.ts`,
`langchainExample.ts`, `crewaiExample.ts`, `vercelAiExample.ts`,
`mcpTool.ts`, `mcpEndToEnd.ts`, `streamExample.ts`, `doctorExample.ts`,
`sandboxDemo.ts`, `cryptoWallet.ts`, `devAgentWorkflow.ts` (dev-agent
workflow reference: dot-notation scope + denyFields, behaviorally pinned by
`node/tests/devAgentWorkflow.test.ts`), `docker/`.

Python (`python/examples/`): `langchain_example.py`, `crewai_example.py`,
`stream_example.py`, `doctor_example.py`.

**Verify (existence):**

```bash
ls node/examples python/examples
```

## 5. Test and build commands (verifier-owned)

```bash
cd node && npm ci          # clean clone: install the locked dependency set first
cd node && npm run build   # tsc build of dist/ — required before tests (one suite runs the built bin-shim)
cd node && npm test        # vitest suite (shield/filter/doctor/fullMode/...)
cd node && npm run lint
```

## 6. Provenance and releases

Release flow, gating, and attestation are documented in `RELEASING.md`
(repository root). That document separates internally-verified steps from
externally-verifiable ones; this inventory does not repeat its claims.

## 7. What is *not* in this inventory

- No gateway/Core artifacts (FULL mode). They are separate deliverables with
  their own documentation.
- No hosted service. There is no managed endpoint to list here today.
- No certification artifacts (none exist; see `LITE_CLAIMS.md`, "What this
  document is not").
