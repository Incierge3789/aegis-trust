# Changelog

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
