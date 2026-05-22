# Changelog

## [Unreleased]

### Changed — `shield()` FULL mode now performs a real `/check-access` trust gate

- **`shield()` FULL mode previously did client-side filtering + best-effort
  audit ingest only — it never called `/check-access`.** The `authorize()`
  gate existed on `AegisClient` but `shield()` did not invoke it, so a FULL
  `shield()` call was effectively `LITE` + telemetry. This release wires the
  gate (`T-SDK-FULL-GATE-01`):
  - In `FULL` mode, the async `shield()` wrapper now `await`s a pre-call
    `/check-access` authorization **before the wrapped function runs**. The
    protected function executes **only** after authorization is granted —
    the gate prevents its side effects / DB reads, it does not merely
    discard their result.
  - Deny / `403` / `503` (audit-fail-closed) / gateway-unreachable / network
    error all cause the wrapped function to **never be invoked**, and the
    call returns `null`. Because the function never ran there is no return
    shape to mirror, so the fail-closed value is a bare `null` (no caller
    data, ever).
  - Audit ingest now runs **only after** authorization succeeds — it is
    post-authorization telemetry (fire-and-forget, fail-open), never the
    trust gate.
  - A function not declared `async`, wrapped with explicit `Mode.FULL`, now
    throws `AegisValidationError`
    (`code: aegis.shield.mode.sync_full_unsupported`) instead of being
    silently mislabelled "full" while running un-gated `LITE` semantics. The
    `async` declaration is the wrapper's pre-execution await point; without
    it the gate cannot run before the function. `AUTO` on a non-`async`
    function resolves to `LITE`.
  - Internal filter/freeze errors **after a granted authorization** are
    caught and return the type-shaped safe empty value (`emptyFor(data)` —
    the function ran, so the data shape can be mirrored). The "fail-closed
    decorator" claim is now true for the Node SDK (previously a filter
    exception propagated).
  - Local audit/history emission (`AEGIS_HISTORY=1`) is fully fail-safe:
    `recordIfEnabled()` now initialises the history store **inside** its
    try/catch, so an unwritable history path cannot turn a FULL-deny
    `null` return — or a fail-closed filter error — into a thrown
    exception. Audit is telemetry; it never breaks the data path.
- **Local diagnostic**: a non-granted FULL authorization is recorded to the
  local history log with `decision` (`deny` / `fail_closed`) + `reason`
  (`denied` / `unreachable` / `core_503` / `http_error` / `internal_error`),
  and emits a single `console.warn` line carrying only those enum labels +
  `purpose` / `function` — no caller data. New additive
  `AegisClient.authorizeDetailed()` returns the reason; the boolean
  `authorize()` public contract is unchanged.
- This **corrects two inaccuracies** in the prior "trust-boundary claim
  scoping" entry below: the `FULL`-mode row's "per-call `/check-access`
  admission" and the headline "decorator fail-closed → empty on internal
  error" were not true of the code at that time. They are true now.

### Changed — documentation: FULL-mode docs updated to match the gate

- `README.md` `FULL`-mode policy row, **Trust-boundary scope** section, and a
  new sync-vs-`Mode.FULL` note now describe the real pre-call gate behaviour.
- Known follow-up recorded: the `authorize()` access cache has a 30 s TTL, so
  a same-token server-side policy change is invisible for ≤ 30 s (P1).

### Changed — documentation: trust-boundary claim scoping

- `README.md` now states the `aegis-core` `FULL`-mode trust-boundary
  guarantees as explicitly scoped claims, in a new **Trust-boundary scope**
  section. Following the aegis-core Core Security Remediation track
  (S173–S176), exactly four guarantees are claimed: `/check-access` JWT
  identity binding, `/check-access` ingress deny-by-default,
  `/check-access` audit-fail-closed, and `AEGIS_PROFILE=production`
  fail-secure boot validation.
- Three broad claims are now explicitly **not** made: no gateway-wide
  audit-fail-closed, no field-level `purpose × scope` minimum-disclosure
  at the gateway, and not production-ready out of the box.
- Four known follow-ups are recorded in the same section: gateway-wide
  `audit.append` sweep, `AEGIS_CAPSULE_ROOT`-missing → 500 no-audit gap,
  `scope` → RBAC/Reflex/field-level wiring, and debug-log redaction.
- The headline, the "30-second understanding" bullet, the "Why" section,
  and the `FULL`-mode policy row were reworded to drop unscoped
  guarantee language. The SDK's `LITE`-mode client-side filtering and
  fail-closed decorator behaviour are unchanged and still accurately
  described — only wording that over-claimed a server-enforced trust
  boundary was corrected.
- No code change, no API change. `python/README.md` was reviewed and is
  unchanged: it makes no `FULL`-mode gateway over-claim.

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
