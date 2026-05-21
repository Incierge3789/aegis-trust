# Changelog

## [0.9.0-rc5] — 2026-05-21 — cross-SDK version-lock (PyPI rc5 parity, no functional change)

`productization-ops/sprint_006` Tier 0 follow-up. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). **Functional content identical to v0.9.0-rc4.**

### Why rc5 (no behaviour change on the npm side)

The Python `aegis-trust@0.9.0rc5` PyPI package was published with the F-055 wheel-packaging fix (the legacy `aegis` back-compat shim was re-included after the rc4 wheel target dropped it). The PyPI shim issue is Python-specific (module rename `aegis` → `aegis_trust`); npm has no analogous concept. Bumping npm to rc5 keeps cross-SDK version-lock per the "Version-locked to PyPI" doctrine.

### Changed

- `VERSION` 0.9.0-rc4 → 0.9.0-rc5
- `package.json` version bump
- `src/index.ts` `VERSION` export bump

No source / behavioural changes vs v0.9.0-rc4.

### Refs

- F-054 published-artifact parity gate doctrine
- F-055 wheel-packaging shim drift (PyPI-side)
- Paired with PyPI `aegis-trust 0.9.0rc5`
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0) — closed the source ↔ registry drift that surfaced when `aegis-trust@0.9.0-rc5` was published to npm from `aegis-core/sdk/node-trust/` (commit `080d02cf`) without committing back to this monorepo. The published rc5 npm package was content-identical to rc4 at publish time and remains so.

## [0.9.0-rc4] — 2026-05-21 — pre-GA preview (cross-SDK env-var canonicalisation + AUTO probe-first)

`productization-ops/sprint_004` post-canonical-audit cross-SDK parity closure. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). Public API surface is additive over v0.9.0-rc3 with one **breaking-for-direct-callers** semantic change on an exported helper (see Migration below). Paired with PyPI `aegis-trust@0.9.0-rc4`.

> **Why rc4 (not rc3)**: npm published `aegis-trust@0.9.0-rc3` from a commit that carried only the `Aegis-Api-Version` dated header + repository-metadata polish. The PyPI parity closure work below missed the rc3 cut and lands as v0.9.0-rc4 on both PyPI and npm in parity.

### Added — `AEGIS_URL` canonical, `AEGIS_BASE_URL` deprecation alias

- `resolveBaseUrl()` in `src/client.ts` resolves the gateway base URL via a documented precedence order: `AEGIS_URL` (canonical, parity with PyPI `aegis-trust` `shield.py:119`) → `AEGIS_BASE_URL` (deprecation alias) → `DEFAULT_BASE_URL` (`https://localhost:8443/api/v1`).
- `AEGIS_BASE_URL` continues to work for v0.8.x → v0.9.x backward compatibility but emits a one-shot `console.warn` per process the first time it is read. The warning is re-armed by `resetModuleClient()` so test fixtures see one warning per logical reset. **`AEGIS_BASE_URL` will be removed in v1.0.0** per [`docs/VERSIONING.md`](docs/VERSIONING.md) deprecation policy.
- `userIntendsFull()` (exported) now inspects `AEGIS_URL` and `AEGIS_BASE_URL` (alongside `AEGIS_TOKEN`) when deciding whether the user expects Full mode. Local hosts (`localhost` / `127.0.0.1` / `::1` / `*.local`) are treated as dev regardless of port so dev fixtures keep working.

### Added — Mode detection TTL cache (parity with PyPI `_DETECT_MODE_TTL_S = 60.0`)

- `_DETECT_MODE_TTL_MS = 60_000` in `src/client.ts`. `AEGIS_MODE=auto` re-probes the backend every 60 s so process state stays in sync with reality without a per-call probe.
- Without this TTL, a stuck `lite` detection survives gateway recovery, and a stuck fail-closed `full` keeps warning even after the backend is healthy.

### Changed — AUTO probe-first behaviour matrix (parity with PyPI `shield.py:_detect_mode` line 162-177)

`detectMode()` now probes the backend FIRST and consults `userIntendsFull()` only when the probe fails. The full behaviour matrix:

- `AEGIS_MODE=lite` → Lite.
- `AEGIS_MODE=full` → Full (calls fail-closed at the gateway until the backend recovers).
- `AEGIS_MODE=auto` + no Full intent (no token AND no non-dev URL) → Lite.
- `AEGIS_MODE=auto` + Full intent + reachable backend → Full.
- `AEGIS_MODE=auto` + Full intent + **unreachable backend** → **fail-closed Full** + one `console.warn`. Previously silently fell back to Lite, which would skip the user-visible warning and provide weaker semantics than the user asked for.

### Migration — `userIntendsFull()` breaking-for-direct-callers (semantic)

- **Pre-rc4**: `userIntendsFull()` returned `true` for `AEGIS_MODE=full` alone (no token / URL required).
- **rc4+**: `userIntendsFull()` requires `AEGIS_TOKEN` OR a non-dev URL (via `AEGIS_URL` or `AEGIS_BASE_URL`). `AEGIS_MODE=full` is handled separately in `detectMode()` and is no longer a sole intent signal for direct callers of `userIntendsFull()`.
- **Who is affected**: callers that import and invoke `userIntendsFull()` directly from `aegis-trust` and rely on `AEGIS_MODE=full` returning `true` from it.
- **Migration recipe**: set `AEGIS_TOKEN` or a non-dev `AEGIS_URL` alongside `AEGIS_MODE=full`. Callers that use only `detectMode()` (the primary entry point) are unaffected — `AEGIS_MODE=full` continues to produce Full mode via the matrix above.

### Tests

- New `tests/fullMode.test.ts` coverage (5 added → 9 total): AUTO probe-first behaviour (LITE fallback when token absent AND backend unreachable; opportunistic FULL when backend reachable; FULL when token + backend reachable; fail-closed FULL with one warn when intent + unreachable), `AEGIS_BASE_URL` deprecation alias (exactly one warn per process), `AEGIS_URL` precedence over `AEGIS_BASE_URL` with no warn.

### Refs

- Paired with PyPI `aegis-trust@0.9.0-rc4` env-var canonicalisation + AUTO probe-first.
- Mirrors PyPI `shield.py` `_resolve_base_url`, `_user_intends_full` extension, and `_detect_mode` probe-first ordering.
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0).

## [0.9.0-rc1] — 2026-05-17 — pre-GA preview

`productization-ops/sprint_001` rollup. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). Public API surface is additive over v0.8.1; no breaking changes. SLA: none. Production use: at your own risk. See [`docs/VERSIONING.md`](docs/VERSIONING.md).

### Added — machine-parseable error model

- `AegisError` base class + `AegisValidationError`, `AegisConfigError`,
  `AegisIngestError`, `AegisAuditError`, `AegisHttpError` (`src/errors.ts`).
  Every error carries `code` + `remediation` + `docs_url`.
- `aegisDocsUrl(code)` helper.
- All `shield()` / `wrap()` / `loadConfig()` validation paths now throw
  typed errors. Internal HTTP / test-time errors unchanged.
- Error code registry: [`docs/errors/README.md`](docs/errors/README.md).

### Added — trace propagation

- `withTraceContext({ traceId }, fn)` opens an `AsyncLocalStorage` scope.
- `shield()` reads the ambient `trace_id` and emits it on every audit
  record.
- `newTraceId()` helper (uses `crypto.randomUUID` when available).
- `trace_id` field added to `HistoryRecord`.

### Added — idempotent local audit

- `HistoryStore.recordIdempotent(args, idempotencyKey)` — Stripe
  Idempotency-Key model translated to the local JSONL store. Cross-run
  dedup via lazy key cache seeded from existing records.
- `idempotencyKey` field added to `HistoryRecord`.

### Added — versioning doctrine

- `STABILITY_LEVEL`, `AUDIT_SCHEMA_VERSION` exports from `src/index.ts`.
- [`docs/VERSIONING.md`](docs/VERSIONING.md) — 7-axis versioning doctrine
  (SemVer + schema_version + stability level + breaking change rule +
  dated API version reservation + deprecation policy + error code
  contract).

### Added — productization gates

- `tests/timing/first_call_script.js` + `tests/timing/run_timing_gate.sh`
  — 60s `time_to_first_call` verifier harness.
- `tests/idempotency/invocation.py` + `invocation_runner.mjs` — 100x
  retry `idempotency_guarantee` verifier harness.
- `tests/mcp/run_end_to_end.mjs` — agent → shield → audit end-to-end
  proof, materialises audit JSONL for `trace_propagation` verifier.
- `.github/workflows/node-trust-ci.yml` — added P0 5 verifier steps
  (advisory; release.yml is the authoritative gate via Path A).

### Changed

- `VERSION` 0.8.1 → 0.9.0-rc1.
- `package.json` version bumped; `dist-tag=rc` recommended for publish.
- README first-fold polished per Stripe Press archetype
  (category positioning + 1-line primitive composition + 30s readability).

### Migration (v0.8.1 → v0.9.0-rc1)

- All existing v0.8.1 code continues to work unchanged.
- `shield({ purpose: "" })` and `wrap(value, { purpose: "" })` now throw
  `AegisValidationError` instead of bare `TypeError`. `AegisValidationError`
  extends `Error` and is named `"AegisValidationError"`, so `catch (e: Error)`
  and `instanceof Error` still work; tests asserting `/purpose/` on the
  message still pass.
- aegis.yaml config validation now throws `AegisConfigError` instead of
  bare `Error`. Same compatibility — extends `Error`, message text is
  preserved.

## [0.8.1] — 2026-05-16

First release of `aegis-trust` on npm — TypeScript / Node port of the
`aegis-trust` Python package on PyPI. Version-locked to PyPI 0.8.1 to
signal feature parity with the same semantic guarantees.

### Added — full parity with PyPI aegis-trust 0.8.1

- `shield(options)(fn)` HOF — wraps a sync or async function, filters its
  return value by purpose-bound `scope` / `denyFields`.
- `wrap(value, options)` — direct value filter (TS-only convenience) that
  returns a `ShieldResult` with `filteredKeys` for audit.
- `Mode.LITE / FULL / AUTO` — operating mode (parity with Python).
- `AegisClient` — full HTTP wrapper for aegis-core REST API:
  `/health`, `/check-access`, `/audit-log`, `/shield/ingest`,
  `/audit/verify`, `/shield/policy-sync`, `/shield/stats`, `/shield/report`.
- `loadConfig` / `getPurposePolicy` / `resetConfig` — YAML policy loader
  (requires optional `yaml` dep).
- `HistoryStore` / `recordIfEnabled` / `resetStore` — local audit log
  (JSONL backend, no native SQLite available in Node stdlib).
- `useShieldHistory` / `assertShieldBlocked` / `assertShieldPassed` —
  vitest helpers (parity with Python pytest plugin).
- `aegis` CLI — `aegis history`, `aegis stats` for local inspection.
- `syncPolicies` / `refreshToken` / `reset` — admin helpers.
- `setMetricsHook` — instrumentation hook called after each backend
  request.
- TLS verify prod-lock (`AEGIS_DEV_INSECURE=1` + dev host only).
- Mode.FULL fire-and-forget ingest; telemetry failures never bubble to
  caller.

### Fail-closed invariants (parity with Python)

- bare leaf scope over list-of-records → drop key (`scope: ["users"]`
  with `{ users: [{ssn: "..."}] }` returns `{}`).
- scope expects nested but value is scalar → drop key.
- broader deny wins over child deny (`denyFields: ["profile",
  "profile.ssn"]` collapses to deny `profile` entirely).
- `authorize`: 200 without `allowed: true` → deny.
- `ingest`: non-monotonic seq → reject.

### Parity-by-design difference (documented, intentional)

- Local audit backend: PyPI uses stdlib SQLite. Node has no stdlib
  SQLite, so this port uses an append-only JSONL file. Public API
  surface (`record`, `getHistory`, `getStats`) is identical.
- ORM detection: PyPI auto-detects pydantic v1/v2 / SQLAlchemy /
  dataclass / NamedTuple. TS handles plain objects and class instances
  with `__dict__`-like enumerable keys. Adapter pattern for Zod / Prisma
  / TypeORM is deferred to a future minor release once design alignment
  is set.

## See also

For full sprint history of the Python package (v0.1.0 → v0.8.1), see
the [aegis-trust PyPI CHANGELOG](https://pypi.org/project/aegis-trust/).
The TS port catches the Python package up at the v0.8.1 mark and tracks
it from here.
