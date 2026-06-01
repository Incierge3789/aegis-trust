# Changelog

## [Unreleased]

### Changed (internal-ops/sprint_018 — LITE error-parity remediation)
- **Rich error envelope on the LITE validation/config path (D2).** The Python
  LITE path now raises the already-public `AegisValidationError` /
  `AegisConfigError` envelopes — carrying `.code` / `.remediation` /
  `.docs_url` / `.to_dict()`. The `code` strings match the Node SDK for the
  shared concepts (`aegis.shield.spec.required`, `aegis.shield.mode.invalid`,
  and every `aegis.config.*` code), so a polyglot consumer can switch on the
  same `code` across SDKs. New Python-side codes: `aegis.shield.spec.conflict`,
  `aegis.shield.deny_fields.empty`, `aegis.shield.field_path.invalid`.
  `load_config()` now also wraps YAML parse failures
  (`aegis.config.yamlParseError`) and missing explicit paths
  (`aegis.config.fileNotFound`) with the machine-parseable envelope.
- **Backward compatibility — every natural `except` contract is preserved
  (D2, P1 audit fix).** The rich envelope is layered *onto* the builtin
  exception type each path historically raised, not in place of it:
  - `except ValueError` — validation + config-structure errors
    (`AegisValidationError` / `AegisConfigError` subclass `ValueError`).
  - `except TypeError` — `scope` / `deny_fields` type-shape checks stay raw
    `TypeError` (deliberately not ValueError-family).
  - `except FileNotFoundError` / `except OSError` — a missing config file now
    raises `AegisConfigFileNotFoundError`, which **is a** `FileNotFoundError`
    (hence an `OSError`) as well as an `AegisConfigError` / `ValueError`.
  - `except ImportError` — a missing optional `yaml` dependency now raises
    `AegisConfigImportError`, which **is an** `ImportError` as well as an
    `AegisConfigError` / `ValueError`.

  All of the above simultaneously expose `.code` / `.remediation` /
  `.docs_url` / `.to_dict()`. (An interim S018 build briefly broke
  `except FileNotFoundError` / `except OSError` / `except ImportError` by
  raising only a `ValueError`-based `AegisConfigError`; the adversarial audit
  flagged it and this release restores the natural catches.)
  `get_purpose_policy()` still degrades to `None` for "no config available"
  (missing file / missing `yaml` dep) and still surfaces a malformed
  `aegis.yaml`.
- **Conversion-failure diagnostic — minimum-disclosure by default (D1, P1
  secret-leak hardening).** When a record→dict conversion (`model_dump` /
  `.dict` / `dataclasses.asdict` / SQLAlchemy `__table__` walk / NamedTuple
  `_asdict`) *raises*, `@shield` emits a developer diagnostic that **withholds
  the exception message, the traceback (no `exc_info`), and any view of the
  failing object** (only the object *type name* is read — the instance's
  `__repr__` / `__str__` is never invoked). It surfaces safe identifiers only:
  that a conversion failed, the converter shape, the object type name, the
  exception *class* name, a fixed remediation, and the active `trace_id` if one
  is set. A failing record's exception message routinely echoes the very field
  values being filtered (`customer_ssn=…`, `stripe_secret_key=…`, PHI, internal
  prompts); the earlier S018 build logged that message + full traceback, which
  an adversarial audit showed leaked PII/secrets through the default log
  surface even though the data-*return* path failed closed. There is no opt-in
  to dump the raw message/traceback — minimum-disclosure is the only mode. The
  genuinely-unsupported return type (a bare scalar) still gets its distinct
  "cannot filter `<type>`" diagnostic. Fail-closed unchanged.
- **Local-history write-failure visibility — path/message withheld (D3, P1
  hardening).** With `AEGIS_HISTORY=1`, a history store init/write failure no
  longer (a) escapes and breaks the `@shield` data path (store init runs inside
  the guarded block, Node parity), or (b) logs a cause-less line. It emits a
  one-shot developer diagnostic stating local audit evidence is **not** being
  recorded and naming the exception *class*, but **withholds the
  `AEGIS_HISTORY_PATH` value** (it may embed tenant / user / secret path
  segments) and the raw exception message + traceback (an `OSError` message
  echoes the path). Local developer diagnostic only — not an authoritative-audit
  guarantee.
- Real-framework verification: the conversion-failure leak/fail-closed tests
  now run against the genuine Pydantic v2, Pydantic v1, and SQLAlchemy code
  paths (added to the `dev` / `frameworks` extras), not duck-typed simulations.
- Not a parity item: empty / Unicode `purpose` remains accepted in Python (it
  is a free-text label, not a validated field — Node validates it). No `Actor` /
  `Decision` / `resource_*` / proof / tamper-evidence / Core changes.

### Added (internal-ops/sprint_017 — schema_version contract)
- `schema_version` is now stamped on every audit event the SDK emits, from a
  single source (`aegis_trust._constants.AUDIT_SCHEMA_VERSION = 1`, re-exported
  by the package root). Wired to both surfaces consistently: local SQLite
  history (`shield_history.schema_version INTEGER NOT NULL DEFAULT 1`;
  `HistoryStore.record` / `record_idempotent` stamp it from the constant, so the
  caller→store keyword signature is unchanged — this structurally prevents a
  silent-failure drift class) and the `/shield/ingest` wire payload (additive
  field; the aegis-core gateway ignores unknown fields, backward-compatible —
  the gateway does not yet persist/use it).
- Backward compatibility: existing v0.8.x/v0.9.x databases are migrated with an
  idempotent `ALTER TABLE … ADD COLUMN schema_version INTEGER NOT NULL DEFAULT
  1`; rows written before the column read back as `1`.
- `schema_version` is intentionally **excluded** from the idempotency
  `_payload_hash` — cross-language SHA-256 byte parity with the Node SDK is
  unchanged.
- Deferred (not implemented): typed `Actor`, `Decision` enum,
  `resource_id`/`resource_type` (the latter is the schema_version=2 shape, gated
  behind a separate decision).

## [0.9.0-rc8] — 2026-05-30 — cross-SDK version-lock (no Python code change)

`internal-ops/sprint_015`. **No Python API or behavior change.** This SDK
is the fail-closed reference; rc8 reconciled the **Node** SDK to match Python
on four data-path edges (empty-spec rejection, deny-over-non-record, wrapped-fn
exception, FULL-mode audit-completeness) plus a Node-only prototype-name `scope`
bypass. Python was already fail-closed on all of these and is unchanged. Version
bumped to keep the cross-SDK version-lock with npm `aegis-trust@0.9.0-rc8`.

## [0.9.0-rc7] — 2026-05-26 — Pre-publish substrate gate wire + CHANGELOG artifact cleanup (internal-ops/sprint_S202)

`internal-ops/sprint_S202` rc7 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). **No public API change**; this release moves the productization 9-verifier gate into the release pipeline so every future tag push is mechanically audited before any artifact is built or published, and cleans sprint-internal Japanese strings out of the shipped `CHANGELOG.md`. Paired with npm `aegis-trust@0.9.0-rc7` (cross-SDK version-lock).

### Changed — release pipeline now runs a fail-closed 9-verifier gate before publish

- `.github/workflows/release-attestation.yml`: new `productization-gate` job (runs-on self-hosted self-hosted-runner). Invokes `~/internal-ops/ops/internal-ops/_shared/scripts/dogfood_aegis_trust.sh` which exercises the internal-ops 9 verifiers (5 P0 + 4 P1) against the workspace. `sbom-node` + `sbom-python` now `needs: [productization-gate]`; `collect-and-sign` / `pack-and-sign-sdk` / `publish-npm-trusted-publisher` are transitively gated. If any P0 verifier fails on a tag push, **no SBOM is generated and nothing is published**. P1 verifiers in `MANUAL_PENDING` (per sprint_005 transitional doctrine, e.g. `top_1_pct_readability` while the 5-oracle survey is queued, or `agent_callable_surface` for JSDoc-incomplete TS exports) do not block.
- The gate substrate lives in `~/internal-ops/ops/internal-ops/`; the workflow assumes the self-hosted runner has that path. Different runner / clean machine → gate fails closed (`runner not found` exit 2). This is the internal-ops `pre_release_gate_productization.sh` literal contract, wired into the public release pipeline for the first time.

### Changed — `CHANGELOG.md` is now english-first (artifact cleanup, no code change)

- `python/CHANGELOG.md` S023 + S024 entries: drop sprint-internal annotation that was non-english (it referenced the integration sprint's working title in the original ops language). The CHANGELOG is bundled inside the PyPI wheel / sdist (`hatch.build.targets.sdist` includes `CHANGELOG.md`), so customer-facing artifact text must be english-first per `internal-ops/9-verifier #2 english_first_artifact`. The S024 entry now reads "Beta attestation + live Full-mode end-to-end proof"; the S023 entry now reads "Full-mode live wiring". No semantic difference from the prior text — the dropped strings were sprint-internal annotation, never customer-facing claims.
- Same fix on the Node side (`node/CHANGELOG.md` S179 reference line): the non-english sprint annotation is replaced with "mil-spec test-honesty doctrine".

### Added — Python-side idempotency invocation script (closes verifier coverage gap)

- `python/tests/idempotency/invocation.py`: mirrors `node/tests/idempotency/invocation.py` contract. The internal-ops `idempotency_guarantee` verifier copies this script to `python/.productization_idempotency_test.tmp` and exercises `HistoryStore.record_idempotent` under a fixed `idempotency_key` for 1 initial + 100 retries. State is observed via a deterministic JSONL snapshot of audit rows projected to fields that are invariant under idempotent retry (function / purpose / scope / deny_fields / blocked_fields / mode); SQLite row id + timestamp are excluded because they would differ across the initial-vs-retry boundary if the system clock or auto-increment counter advanced. Previously the Python-side verifier ran with no invocation script and reported `ERROR`; rc7 fixes this gap so the gate produces a real PASS/FAIL verdict for both SDKs.

### Routed scenarios (internal review)

- `family_5_ops_ci_release / supply_chain_attestation`: incremental — gate is now invoked by the publish pipeline (was only a maintainer-local dogfood through rc6). Still `closure_candidate` until external oracle walk closes the literal residual.
- `family_5_ops_ci_release / npm_pypi_latest_rc_tag_drift`: unchanged — `dist-tags.latest` intentionally stays on `0.9.0-rc3` per the pre-release-doesn't-promote-to-latest design. `npm install aegis-trust@rc` resolves to rc7.



`internal-ops/sprint_011` rc6 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API is additive over rc5 with one **behavioral change** on FULL-mode fail-closed return value (see `shield()` FULL mode entry below: shape-preserving empty → `None`). Paired with npm `aegis-trust@0.9.0-rc6` (cross-SDK version-lock).

This is also the **first release cut from the `aegis-trust` monorepo itself** (rc1–rc5 were published from `aegis-shield`, the historical mirror; see `aegis-shield/README.md` L1 `📍 Source moved`). Provenance attestation (SBOM + cosign keyless signatures + GitHub Release artifact attach) is generated by `.github/workflows/release-attestation.yml` (Block B Phase 2) on the `v0.9.0-rc6` tag push.

### Changed — `_detect_mode` now intent-first (matches AUTO behaviour matrix; Node parity)

- `python/src/aegis_trust/shield.py` `_detect_mode()` checks
  `_user_intends_full()` BEFORE probing the backend, parity with the
  node `detectMode` intent-first fix (same release). Removes the
  opportunistic-upgrade path that called `/check-access` from no-token
  dev environments and contradicted the documented matrix.
- New behaviour:
  - `AUTO + no Full intent` (no `AEGIS_TOKEN`, no non-dev URL) → LITE
    (no probe, no `/check-access`).
  - `AUTO + Full intent + reachable backend` → FULL (opportunistic
    upgrade with intent).
  - `AUTO + Full intent + unreachable backend` → fail-closed FULL +
    warning. Unchanged.
- **Routed scenarios** (internal review verification batch 1):
  `python_node_parity` divergence #2 (AUTO degrade) — resolved.

### Changed — `shield()` FULL mode now performs a real `/check-access` trust gate (T-SDK-FULL-GATE-01 parity)

- **Python `shield()` FULL mode previously executed the wrapped function BEFORE calling `/check-access`** — the gate fired on the already-computed result, so any side effects (DB writes, billing, etc.) had already happened by the time the gate could deny. This release brings the Python SDK to parity with the Node `T-SDK-FULL-GATE-01` fix (landed on `main` 2026-05-22, commit `b687e99`):
  - In `FULL` mode, both the async and sync shield wrappers now `await client.aauthorize(...)` / call `client.authorize(...)` **before** the wrapped function runs. The wrapped function executes **only** after authorization is granted.
  - Deny / `/check-access` raised (network error, gateway unreachable) → wrapped function **never invoked**, call returns a bare `None`. Because the function never ran, there is no return shape to mirror — the fail-closed value is `None`, not the prior `_empty_for(data)` (shape-preserving empty). This is the same contract as the Node SDK.
  - Audit ingest (`/shield/ingest`) runs only **after** authorization succeeds — post-authorization telemetry, never the gate.
  - Filter / freeze exceptions after a granted authorization still fall back to a type-shaped safe empty (`_empty_for(data)`) since the function ran and the data shape is known.
- Internal helpers `_shield_full`, `_shield_full_async`, `_shield_deny`, `_shield_deny_async` gain a keyword-only `pre_authorized: bool = False` parameter. When invoked from the shield wrapper (which now does the pre-call gate), the helpers skip the in-helper `authorize()` call to avoid a double audit. External call sites are unaffected (additive keyword arg, default preserves prior behaviour).
- **Behavioral change**: callers that previously received a shape-preserving empty (`{}` / `[]` / `""`) on FULL deny / unreachable now receive `None`. Test fixtures asserting `result == {}` on fail-closed FULL must be updated to `result is None`; this release updates the in-repo Python tests accordingly.
- **Routed scenarios** (internal review verification batch 1): `async_sync_behavior` (confirmed P0) — resolved. `python_node_parity` divergence #1 (FULL-mode gate timing) — resolved. Remaining parity divergences (AUTO degrade / mode TTL) are tracked separately; `isAsyncFn` `.bind()` mis-classification was refuted by ES §10.4.1.3 (BoundFunctionCreate preserves `AsyncFunction`).

### Changed — README: `FULL mode — gateway trust-boundary guarantees` subsection (CSR 4/4 claim-scoping)

- `README.md`: added a `### FULL mode — gateway trust-boundary guarantees` subsection. It states, in **scoped** wording verified against aegis-core code, the four guarantees the gateway `/check-access` ingress provides after the Core Security Remediation track (CSR 4/4, landed in aegis-core 2026-05-21): identity binding to the auth-middleware identity, ingress denial of unknown purpose / scope / malformed capsule, audit-or-deny (HTTP 503) fail-closed, and `AEGIS_PROFILE=production` boot-time config validation. The subsection also states explicitly what is **not** guaranteed (no gateway-wide audit fail-closed, no purpose × scope field-level minimum-disclosure, not production-ready out of the box, no all-gateway-operations audit-complete claim) and records four tracked follow-ups.

## [0.9.0-rc5] — 2026-05-21 — wheel-packaging fix for legacy `aegis` shim (release-integrity follow-up)

`internal-ops/sprint_006` Tier 0 follow-up to the F-054 release-integrity remediation. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API surface is identical to rc4; this release fixes wheel packaging so the documented back-compat shim is actually shipped.

### Fixed — `from aegis import shield` legacy shim now packaged (F-055)

- `pyproject.toml` `[tool.hatch.build.targets.wheel] packages` updated from `["src/aegis_trust"]` to `["src/aegis_trust", "src/aegis"]`. The rc2 CHANGELOG entry promised the `aegis` back-compat shim would remain until v2.0.0, but the wheel target only included `src/aegis_trust`. `pip install aegis-trust==0.9.0rc4` therefore did not provide `import aegis` compatibility, contradicting the documented migration path.
- Verified post-publish on the live PyPI artifact: wheel contains both `aegis_trust/__init__.py` (canonical) and `aegis/__init__.py` (shim, emits `DeprecationWarning`). `pip install aegis-trust==0.9.0rc5 && python -c "from aegis import shield"` works as documented.

### Release-integrity gate (post-F-054)

The live PyPI `aegis-trust==0.9.0rc5` artifact was originally published from `aegis-shield` (commit `0419f2a`, 2026-05-18; the `e06ac9df` reference recorded at rc5 ship time was a squash-artifact hash that does not resolve in the canonical `aegis-shield` history — `git -C aegis-shield log -1 0419f2a` shows `[internal-ops/sprint_004 follow-up] rc5 wheel packaging fix for legacy aegis shim (F-055)`, the actual rc5 source commit) via the **Published Artifact Parity Gate** (5-stage: local build → record artifact hash → publish to PyPI → download from registry → verify local hash == registry hash → clean venv install → canonical import + legacy shim import + `AEGIS_BASE_URL` alias all PASS).

> **Hard rule going forward**: No release claim unless source, build config, registry artifact, clean install, and documented compatibility behavior all match.

### Changed

- `VERSION` 0.9.0-rc4 → 0.9.0-rc5
- `pyproject.toml` version bump
- `src/aegis_trust/__init__.py` `__version__` bump

### Refs

- F-054 release-integrity incident (published rc3 source ≠ canonical repo source)
- F-055 wheel-packaging shim drift (rc4 wheel missed `src/aegis`, fixed in rc5)
- Paired with npm `aegis-trust@0.9.0-rc5` (cross-SDK version-lock; npm rc5 is content-identical to rc4 because the wheel-shim issue is Python-specific)
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0) — closed the source ↔ registry drift that surfaced when `aegis-trust@0.9.0rc5` was published to PyPI from `aegis-shield` without committing back to this monorepo.

## [0.9.0-rc4] — 2026-05-21 — pre-GA preview (cross-SDK env-var canonicalisation + AUTO probe-first)

`internal-ops/sprint_004` post-canonical-audit cross-SDK parity closure. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API surface is additive over v0.9.0-rc3 with one **breaking-for-direct-callers** semantic change on an exported helper (see Migration below). Paired with npm `aegis-trust@0.9.0-rc4`.

### Added — `AEGIS_URL` canonical, `AEGIS_BASE_URL` npm-parity deprecation alias

- `_resolve_base_url()` in `src/aegis_trust/shield.py` resolves the gateway base URL via a documented precedence order: `AEGIS_URL` (canonical, parity with npm `aegis-trust` `client.ts:resolveBaseUrl`) → `AEGIS_BASE_URL` (npm-parity deprecation alias) → default (`https://localhost:8443/api/v1`).
- The npm SDK historically read `AEGIS_BASE_URL`; from v0.9.0-rc3 onward, both SDKs accept both env vars, with `AEGIS_URL` as the canonical name. `AEGIS_BASE_URL` continues to work but emits a one-shot `logger.warning` per process the first time it is read. The warning is re-armed by `reset()` so test fixtures see one warning per logical reset. **`AEGIS_BASE_URL` will be removed in v1.0.0** per [`docs/VERSIONING.md`](docs/VERSIONING.md) deprecation policy.
- `_user_intends_full()` extended to inspect `AEGIS_URL` / `AEGIS_BASE_URL` (alongside `AEGIS_TOKEN`) when deciding whether the user expects Full mode. Local hosts (`localhost` / `127.0.0.1` / `::1` / `*.local`) are treated as dev regardless of port so dev fixtures keep working.

### Added — Mode detection TTL cache (parity with npm `_DETECT_MODE_TTL_MS = 60_000`)

- The existing `_DETECT_MODE_TTL_S = 60.0` constant in `shield.py` is now mirrored on the npm side so both SDKs re-probe the backend every 60 s under `AEGIS_MODE=auto`. Without this TTL, a stuck `lite` detection survives gateway recovery, and a stuck fail-closed `full` keeps warning even after the backend is healthy.

### Changed — AUTO probe-first behaviour matrix

`_detect_mode()` continues to probe the backend FIRST and consults `_user_intends_full()` only when the probe fails. The full behaviour matrix (now also enforced on the npm side):

- `AEGIS_MODE=lite` → Lite.
- `AEGIS_MODE=full` → Full (calls fail-closed at the gateway until the backend recovers).
- `AEGIS_MODE=auto` + no Full intent (no token AND no non-dev URL) → Lite.
- `AEGIS_MODE=auto` + Full intent + reachable backend → Full.
- `AEGIS_MODE=auto` + Full intent + **unreachable backend** → **fail-closed Full** + one `logger.warning`. Previously silently fell back to Lite, which would skip the user-visible warning and provide weaker semantics than the user asked for.

### Added — `[tool.mypy]` strict configuration with documented exemptions

- `pyproject.toml` `[tool.mypy]` block: `files = ["src/aegis_trust"]`, `ignore_missing_imports = true`, and `disable_error_code = ["arg-type", "no-any-return", "no-untyped-def", "attr-defined"]` for pre-existing type-narrowing tech debt in `shield.py` / `config.py` / `history.py`. Documented exemption per F-005 (no silent bypass; explicit + audit-visible). Tightening is queued for a dedicated sprint.
- Productization gate `type_safety` verifier compatible.

### Changed — `reset()` re-arms deprecation-warning state

- `reset()` now also resets `_base_url_alias_warned` so test fixtures can verify the deprecation-warning contract repeatedly (one warning per logical reset). Mirrors npm `resetModuleClient()`.

### Migration — `_user_intends_full()` breaking-for-direct-callers (semantic)

- **Pre-rc4**: `_user_intends_full()` returned `True` for `AEGIS_MODE=full` alone (no token / URL required).
- **rc4+**: `_user_intends_full()` requires `AEGIS_TOKEN` OR a non-dev URL (via `AEGIS_URL` or `AEGIS_BASE_URL`). `AEGIS_MODE=full` is handled separately in `_detect_mode()` and is no longer a sole intent signal for direct callers.
- **Who is affected**: callers that invoke `_user_intends_full()` directly from `aegis_trust.shield` (or its re-exports) and rely on `AEGIS_MODE=full` returning `True` from it.
- **Migration recipe**: set `AEGIS_TOKEN` or a non-dev `AEGIS_URL` alongside `AEGIS_MODE=full`. Callers that use only `_detect_mode()` (the primary entry point) are unaffected — `AEGIS_MODE=full` continues to produce Full mode via the matrix above.

### Refs

- Paired with npm `aegis-trust@0.9.0-rc4` env-var canonicalisation + AUTO probe-first.
- Mirrors npm `client.ts` `resolveBaseUrl`, `userIntendsFull` extension, and `detectMode` probe-first ordering.
- T-006c-1 monorepo reconciliation (sprint_006 Tier 0).

## [0.9.0-rc2] — 2026-05-18 — Python module rename `aegis` → `aegis_trust` (internal-ops/sprint_003)

`internal-ops/sprint_003` Phase A. **Breaking-but-shimmed**: the Python module
was renamed from `aegis` to `aegis_trust` to match the PyPI package name. Existing
`from aegis import shield` continues to work via a `DeprecationWarning`-emitting
back-compat shim slated for removal in **v2.0.0**.

### Changed — module rename
- `src/aegis/` → `src/aegis_trust/` (literal directory rename, git history preserved).
- `from aegis_trust import shield` is now the canonical import path.
- `from aegis_trust.client import AegisClient`, `from aegis_trust.types import ...`,
  `from aegis_trust.shield import ...` etc. are the canonical submodule paths.
- `pyproject.toml`: `[project.scripts]` `aegis = "aegis_trust.cli:cli_entry"`;
  `[project.entry-points."pytest11"]` `aegis = "aegis_trust.pytest_plugin"`;
  `[tool.hatch.build.targets.wheel]` `packages = ["src/aegis_trust"]`.

### Deprecated — `import aegis`
- `import aegis` / `from aegis import shield` emits `DeprecationWarning` and
  re-exports the public surface from `aegis_trust`. **Removal: v2.0.0**.
- Migration is a single sed: `sed -i 's/from aegis import/from aegis_trust import/g'`.
  Submodule paths: `aegis.X` → `aegis_trust.X`.

### Added — Aegis-Api-Version dated header registry (internal-ops/data/)
- `~/internal-ops/ops/internal-ops/data/api_versioning_policy.yaml`: dated
  API version registry (`Aegis-Api-Version: 2026-05-18` initial), sunset policy
  (18-month notice + 6-month deprecation), stability levels, breaking-change
  classification, migration tooling requirements. SDK header install lands in
  v1.0.0 GA (sprint_003 Phase C).

## [0.9.0-rc1] — 2026-05-18 — pre-GA preview (internal-ops/sprint_001)

`internal-ops/sprint_001` Build phase Python port. **Preview release**
(`STABILITY_LEVEL = "preview"`). Mirrors `@aegis_trust/sdk@0.9.0-rc1` (npm,
TypeScript port). Public API is additive over v0.8.1; no breaking changes.

### Added — machine-parseable error model (`aegis.errors`)

- `AegisError` base + `AegisValidationError` / `AegisConfigError` /
  `AegisIngestError` / `AegisAuditError` / `AegisHttpError`. Every error
  carries `code` + `remediation` + `docs_url`. All except `AegisHttpError`
  also extend `ValueError` for backward-compat with existing
  `except ValueError` callers.
- `aegis_docs_url(code)` helper.

### Added — trace context propagation (`aegis.trace`)

- `trace_context(trace_id, parent_id=None)` context manager — sets
  ambient `contextvars.ContextVar` for the duration. Asyncio-safe,
  thread-safe.
- `with_trace_context(trace_id, fn, *args, **kwargs)` function-call wrapper.
- `get_trace_context() -> TraceContext | None`.
- `new_trace_id()` — 32-char hex via `secrets.token_hex(16)`.
- traceId regex validation: `^[A-Za-z0-9._:-]{1,128}$` — prevents Bearer
  tokens / secrets being persisted into audit JSONL.

### Added — idempotent local audit (`aegis.history`)

- `HistoryStore.record_idempotent(args, idempotency_key)` — Stripe
  Idempotency-Key model translated to the SQLite store. Cross-run dedup
  via SQL key lookup. Divergent-payload retries with the same key raise
  `AegisAuditError` (`aegis.audit.idempotencyKey.payloadDivergence`).
- SQLite migration: add `trace_id` + `idempotency_key` columns to
  existing v0.8.x databases (idempotent `ALTER TABLE ADD COLUMN`).
- `record()` now accepts optional `trace_id` kwarg.

### Added — versioning doctrine exports

- `AUDIT_SCHEMA_VERSION = 1` — on-disk / on-wire audit event shape version.
- `STABILITY_LEVEL = "preview"` — see npm SDK `docs/VERSIONING.md`.
- `__version__` bumped 0.8.1 → 0.9.0-rc1.

### Test

- 429/430 pytest pass (1 unrelated ci-matrix.sh test, pre-existing infra issue).
- New surface verified via smoke test (trace_context + record_idempotent +
  payload-divergence detection).

### Refs

- internal-ops/sprint_001 npm SDK D-001..D-025 + sprint_002 carry-over
- Session 3 scope per kickoff handoff (PyPI port deferred from npm publish day)
- aegis-trust feature parity: npm `@aegis_trust/sdk@0.9.0-rc1` (2026-05-18 JST)

## [0.8.1] — 2026-04-17

Sprint S024 "Beta attestation + live Full-mode end-to-end proof" — closes S023's
"electricity never confirmed" gap. v0.8.0 shipped the Full-mode
wiring but the Tier β workflow had never seen a live green run;
`docker compose up --build` hung on a 40-50 minute Rust rebuild
twice and was cancelled by hand. v0.8.1 rewires the β substrate so
`scripts/aegis-core-dev.sh up` reuses the cached image via a
content-addressed SHA tag, produces a tamper-evident attestation
for every run, fixes a file-descriptor leak in `AegisClient.set_token`,
and records the project's first live all-green Tier β pass
(52 passed / 3 skipped / 0 failed against
`aegis-core-dev@sha256:4dad2fb0…`).

### Fixed

- `AegisClient.set_token()` no longer leaks sockets on JWT rotation.
  The prior implementation dropped both `httpx.Client` and
  `httpx.AsyncClient` references without releasing their connection
  pools. `set_token` now closes the sync client inline and, when
  called from a running event loop, schedules
  `old_async.aclose()` as a task whose reference is held in
  `self._pending_aclose_tasks` until `add_done_callback` clears it
  (bpo-44665 weakref GC). Outside a loop a `ResourceWarning` now
  fires so operators see the leak vector instead of discovering it
  via growing FD counts in production.
- `scripts/pre-push` now invokes `.venv/bin/{ruff,pytest,pip-audit}`
  directly so developers whose shells have not activated the venv
  stop falling through to system tooling (or silently skipping the
  gate). `pip-audit>=2.7` is now part of the `[dev]` extra so the
  gate is reachable from a clean `pip install -e ".[dev]"`.
- `scripts/install-hooks.sh` is idempotent and warns when the
  installed hook drifts from the canonical copy, so re-install is
  safe at any time.
- `tests/test_shield_full.py` scope-filter tests now skip with
  `requires_authed_check_access` instead of spuriously failing on
  the live gateway's (correct) `401` response. The counterpart
  `test_full_mode_unauthed_returns_empty` pins the AO-003
  fail-closed path those tests used to imply.

### Added — β CI substrate

- `scripts/aegis-core-dev.sh` (T-158/T-175):
  - `docker image inspect aegis-core-dev:<sha>` cache hit path —
    rebuilds the Rust gateway image only when the aegis-core source
    SHA has changed, eliminating the ~40-min scratch build on every
    CI run. Warm cache healthcheck clears in <10 s.
  - `sha` / `image` subcommands emit the aegis-core source SHA and
    the image's sha256 digest for attestation.
  - `AEGIS_CORE_DIR` origin remote is checked against an anchored
    allowlist (`^(https://|git@)github\.com[:/]Incierge3789/aegis[_-]core(\.git)?$`),
    with `AEGIS_CORE_REMOTE_ALLOWLIST` as the escape hatch. STRIDE
    spoofing mitigation against an attacker-controlled checkout
    sharing the directory name.
- `scripts/aegis-core.compose.yml` (T-159) is now runtime-only —
  build logic lives in the CLI wrapper — and carries the full dev
  env map (`AEGIS_GATEWAY_AUDIT_PATH`, `AEGIS_CAPSULE_ROOT`,
  `AEGIS_WORKSPACE_ROOT`, `AEGIS_CONFIG_PATH`, `AEGIS_TLS_*`,
  `AEGIS_MTLS_REQUIRED=false`, `AEGIS_SWAGGER_AUTH=false`,
  `AEGIS_METRICS_AUTH=false`, `AEGIS_IP_ALLOWLIST` widened for
  Docker Desktop bridges, `AEGIS_SOCKET_PATH`,
  `AEGIS_RATE_LIMIT_PER_MIN=6000`). A bind-mounted
  `scripts/aegis-core-dev-config/` supplies the minimum
  `purpose_map.yaml` / `policy.yaml` / `rbac.yaml` the gateway
  requires but the production image's `aegis-gateway init` does not
  yet emit.
- `scripts/aegis-attest.sh` (T-171) writes a schema_version=1 JSON
  attestation containing the aegis-shield commit, aegis-core commit
  and remote, the image's SHA-pinned digest, fixture hashes for the
  compose spec, CLI wrapper and workflow, and best-effort cosign +
  syft slots when those tools are installed. JSON is rendered
  through `python3 json.dumps` so shell-unsafe characters in cosign
  failure text cannot corrupt the record.
- `.github/workflows/tier-beta.yml` (T-160) rewired for the
  SHA-tagged cache: cache hit/miss recorded as a workflow output,
  startup poll synced to the compose 60 s healthcheck, 45-minute
  cold-path ceiling, `push: sprint/**` trigger restored, and every
  run emits the attestation JSON as a 90-day retained artifact.

### Documented

- `docs/S024_first_beta_green.md` — first live Tier β green report
  (52 passed / 3 skipped / 0 failed, image digest
  `sha256:4dad2fb0…`, aegis-core source `eb353fec55c4`), plus the
  warm×2 + cold×1 + nightly×3 push-trigger acceptance matrix that
  replaces the original self-referential gate.
- `attestations/tier-beta-first-green-2026-04-17.json` — machine-
  readable companion of the above.

### Deferred to S025 (documented handoff)

- `make generate-sdk` against the live OpenAPI (46 paths, 38
  schemas) — deferred because regenerating `src/aegis/_generated/`
  has a high chance of reshaping symbols that every Lite test
  imports. The live spec has been pulled to `/tmp/live_openapi.json`
  so S025 can diff it cleanly against the checked-in stub.
- `tests/integration/` load harness (100-concurrent-req observation
  of `_detect_mode` thundering herd, `_access_cache` TTL race, and
  async FD growth) — the FD-leak fix from T-172 already removes the
  highest-impact known issue. S025 builds the observation suite
  on top of that and bakes load thresholds into CI.
- GHCR publication + cosign keyless signing — S024 closed the
  non-repudiation gap with a content-addressed local digest; GHCR
  and signing raise the evidence bar further once aegis-core
  itself publishes images.
- `_detect_mode` TTL re-probe lock, `_access_cache` LRU bound, and
  the sync/async 4-way de-duplication refactor — all structural
  follow-ups deferred in S023 whose non-structural halves are
  addressed here.

## [0.8.0] — 2026-04-14

Sprint S023 "Full-mode live wiring" — first end-to-end Full mode integration
sprint. v0.7.x shipped Full mode code paths (`@shield` Full,
`AegisClient.ingest`, audit POST, `_diff_keys`) but they had never been
exercised against a live aegis-core. v0.8.0 closes that gap on the
gateway-uniqueness, fail-secure, and non-repudiation axes called for
by the AO philosophy and the US military fail-secure /
defense-in-depth standards.

### Added — Full mode hardening

- `_resolve_verify_ssl()` (AO-001 + AO-005 fail-secure prod-lock):
  `AEGIS_VERIFY_SSL=false` is now silently overridden to `True` on any
  non-dev host. Local dev (`localhost` / `127.0.0.1` / `::1` / `*.local`)
  requires both `AEGIS_VERIFY_SSL=false` AND a new explicit
  `AEGIS_DEV_INSECURE=1` opt-in.
- `AegisClient.aingest` / `aauthorize` / `acheck_access` /
  `averify_audit_chain` / `averify_inclusion` / `ais_available` /
  `aclose` (async path uses `httpx.AsyncClient` end-to-end so
  `@shield`-decorated coroutines never block the event loop on backend
  I/O).
- `AegisClient.authorize` / `aauthorize` (AO-003 enforcement): every
  Full mode call now hits `/check-access` before filtering. Allow
  decisions cache for 30s keyed by `(token_epoch, purpose, sorted scope)`;
  deny is never cached. Fail-OPEN is closed: the 200 body must contain
  `{"allowed": true}`.
- `AegisClient.set_token` / `aegis.shield.refresh_token` (AO-001 +
  AO-004): rotates the bearer token, bumps `_token_epoch` so any
  in-flight `authorize()` cannot poison the new principal's cache,
  discards cached httpx clients, best-effort zeroizes a `bytearray`
  token in place.
- `AegisClient.verify_audit_chain` / `verify_inclusion` (AO-004
  per-call non-repudiation): SDK retains the highest seq returned by
  every ingest and exposes a helper that proves *this* call's record
  landed in a valid intact chain — `/audit/verify` alone only proved
  chain health.
- `AegisClient._parse_ingest_body` / `_parse_chain_body` (AO-002
  malformed-200 fail-secure): a 200 with a body that diverges from the
  OpenAPI contract is now classified as a transport error and
  fail-closed.
- `aegis.client.set_metrics_hook` (AO-006 — replaces a proposed direct
  `prometheus_client` dependency): single pluggable callback
  `(endpoint, duration_s, status) -> None` invoked after every backend
  request. Hook exceptions are swallowed; instrumentation never breaks
  the data path.
- Mode detection TTL (60s) + degrade-event log (`shield: mode changed
  X → Y`): `AEGIS_MODE=auto` re-probes the backend within an SLO
  window; any mode flip emits an explicit AO-006 event so audit
  readers can distinguish "always-Lite" from "Full degraded
  mid-process".
- `_user_intends_full()` heuristic + Full + fail-closed on unreachable
  backend: under `AEGIS_MODE=auto`, an explicit `AEGIS_TOKEN` or
  non-dev `AEGIS_URL` keeps the SDK in Full mode and denies all calls
  until the gateway recovers — Gateway-uniqueness (AO-001) outranks
  availability.
- `_collect_removed` cycle guard (Mythos M5): attacker-shaped circular
  structures (`d["self"] = d`) no longer trigger RecursionError or
  hang. The guard is path-local so legitimate aliasing
  (`{"x": shared, "y": shared}`) is still diffed correctly.
- `aegis.client._clear_sensitive` + new SECURITY.md "Memory posture"
  section (AO-005): documents the SDK best-effort / gateway-authoritative
  split for in-memory secret zeroize on CPython.

### Added — Operational

- `scripts/aegis-core.compose.yml` + `scripts/aegis-core-dev.sh` for
  local Tier β provisioning. `AEGIS_CORE_DIR` is required and produces
  a clean error message when missing — no brittle absolute paths.
- `.github/workflows/tier-beta.yml` runs the Full mode integration
  suite against a live aegis-core container on `workflow_dispatch`,
  `push` to `sprint/**`, and a nightly cron.
- `tests/test_contract_gate.py` static-parses every httpx path literal
  in `client.py` and asserts each exists in `openapi.json`. CI fails
  when the SDK calls a route the OpenAPI spec does not declare.

### Changed

- `openapi.json`: backported `/shield/ingest`, `/shield/policy-sync`,
  `/shield/stats`, `/shield/report` paths from aegis-core's `utoipa`
  source so the contract gate passes. Full schemas regenerate next
  time `make generate-sdk` runs against a live aegis-core.

### Backward compatibility notes

- `AEGIS_VERIFY_SSL=false` alone is now a no-op outside dev hosts,
  and a no-op even on dev hosts unless `AEGIS_DEV_INSECURE=1` is also
  set. v0.7.x callers relying on `AEGIS_VERIFY_SSL=false` against a
  local aegis-core must export `AEGIS_DEV_INSECURE=1` as well.
  Lite-mode users see no behavior change.
- Full mode now performs `/check-access` before every
  `/shield/ingest`. Cached for 30s per `(token, purpose, scope)`; the
  first call after rotation (or a new combination) pays a second RTT.
  Wire `set_metrics_hook()` to surface the impact in your own
  observability stack.

### Deferred to S024 (handoff)

- sync/async pair de-duplication
  (`authorize`/`aauthorize`, `ingest`/`aingest`,
  `_shield_full`/`_shield_full_async`, deny pair) — large refactor,
  deliberately deferred to keep the v0.8.0 behavior diff small and
  reviewable.
- `tests/conftest.py` extraction of duplicated fixtures.
- `_access_cache` bounded eviction (LRU + maxsize).
- `_detect_mode` TTL re-probe lock for concurrent first-call thundering
  herd.
- `set_token` async client `aclose` scheduling on the running loop.

## [0.7.1] — 2026-04-14

Security hardening from the first formal adversarial sprint against the
v0.7.0 new surface. No new public API; three security fixes + one
defense-in-depth fix promoted this to a patch release per the Sprint
S022 "any shipped security fix => patch release" policy.

### Security

- **A1/R8 — `__slots__` fail-closed**: classes using `__slots__` (no
  `__dict__`) are now treated as record-like, so `list[SlottedUser]`
  under a leaf scope drops fail-closed instead of leaking named
  attributes.
- **A2-A5 + A11 / R1 + R4 — `_is_traversable` helper**: `_filter_dict`
  leaf-drop, `_deny_filter_dict` recursion, and `_collect_removed` audit
  diff now cover the full non-str / non-bytes / non-`Mapping` iterable
  surface (`list`, `tuple`, `set`, `frozenset`, `deque`, `memoryview`,
  `range`, `array.array`, generators, custom `__iter__`). Pre-S022 they
  hardcoded `(list, tuple)` and let `collections.deque` / `set` /
  generator envelopes silently pass record-like payloads.
- **A6+A7+A12 / R2 — symmetric deny scalar drop**: `_deny_filter_dict`
  now drops the key fail-closed when the subtree expects descent but
  the value is a scalar — matching `_filter_dict`'s behavior. Pre-S022
  it kept the scalar, letting `deny_fields=["users.ssn"]` silently pass
  through a scalar `users` value.
- **A3 / R3 — narrowed SQLAlchemy probe**: `_is_sqla_declarative_like`
  now requires SQLAlchemy to be importable and the instance to be a
  `DeclarativeBase` subclass (or `__table__` to be a real
  `sqlalchemy.Table`). Pre-S022 duck-typing (`hasattr(__table__,
  "columns")`) accepted attacker-forged metadata — a confused-deputy
  surface.
- **A4+A9 / R9 — Pydantic v2 return-type gate**: `_to_filterable` now
  requires `model_dump()` to return a `dict`, symmetric with the v1
  path. Non-`dict` returns fail-closed.
- **A10 / R10 — NamedTuple normalization**: `typing.NamedTuple` and
  `collections.namedtuple` instances are now detected by
  `_is_record_like` and normalized via `_asdict()` in `_to_filterable`.

### Backward compatibility notes

- **Deny-mode scalar contract change**: callers relying on
  `deny_fields=["a.b"]` to keep a scalar `a` value unchanged must
  either add the scalar to an allowed path or redesign the caller to
  return a consistent shape. The pre-S022 behavior was asymmetric with
  scope and was producing silent leaks.
- **SQLAlchemy probe narrowing**: callers using duck-typed
  `__table__.columns` without installing SQLAlchemy will now fall
  through to the `__dict__` / fail-closed path. Install SQLAlchemy or
  switch to `@dataclass` / Pydantic if `_to_filterable` normalization
  is needed.
- **Pydantic v2**: any custom `model_dump()` that returns a non-`dict`
  (list / str / None / ...) will now fail-closed. Return a `dict` (the
  canonical contract) or bypass `@shield` for that path.

## [0.7.0] — 2026-04-14

Minor release. `@shield` now auto-normalizes common Python return shapes
(`@dataclass`, Pydantic v1/v2, SQLAlchemy Declarative) before filtering,
removing the boilerplate of converting objects to `dict` inside every
wrapped function. Detection is duck-typed — neither Pydantic nor
SQLAlchemy is added as a dependency.

Pre-1.0 (0.6.x → 0.7.0) bump. No breaking change for `dict` / `list` /
`None` callers. Callers who previously returned a Pydantic model or a
dataclass from a `@shield`-wrapped function were hitting the non-dict
fail-closed path and receiving `""`. That case now returns a filtered
`dict`.

### Added

- **`_to_filterable()` helper** runs at the top of `_filter_result` and
  `_deny_filter_result`. Detection order (hottest first):
  1. `dict` / `list` / `None` — pass-through.
  2. Pydantic v2 — `.model_dump()`.
  3. SQLAlchemy Declarative — iterates `__table__.columns`. Checked
     before Pydantic v1 because some ORM mixins also define `.dict`;
     `__table__.columns` is the more specific signature.
  4. Pydantic v1 — `.dict()` (only accepted when the call returns a
     `dict`).
  5. `@dataclass` — `dataclasses.asdict`.
  6. Unknown — returned unchanged; the existing non-dict fail-closed
     path fires.
- **SQLModel-like hybrid support**: objects with both `.model_dump` and
  `__table__.columns` resolve via the Pydantic v2 branch, so custom
  serializers (aliases, computed fields, validators) are preserved.
- **Top-level `list[<model>]` support**: returning `[Customer(), ...]`
  from a `@shield`-wrapped function (where `Customer` is a dataclass or
  Pydantic model) works via recursion — each element is normalized
  individually.
- **13 new tests** in `tests/test_orm_pydantic.py`: dict / list-of-dict
  regression, `@dataclass` (scope + deny), Pydantic v2 flat + nested,
  Pydantic v1 flat (optional via `skipif`), SQLAlchemy-shape duck
  typing, top-level `list[@dataclass]`, top-level `list[BaseModel]`,
  SQLModel hybrid branch-order, unknown opaque fail-closed, conversion
  exception fail-closed.
- **README "Supported return types"** table documents the full matrix,
  including the optional-dependency posture and the hybrid fallthrough.

### Fail-closed

- Conversion exceptions (`model_dump` / `asdict` / `__table__`
  traversal) return `""`, which the existing non-dict path converts to
  an empty result. Callers never see partial or exception-tainted data.

## [0.6.5.6] — 2026-04-14 — *superseded by 0.7.0*

> **This version was not published to PyPI.** Sprint S021 consolidated the
> 0.6.5.6 hotfix work with the 0.7.0 ORM/Pydantic/dataclass support in a
> single squash-merge, so only `0.7.0` exists as a PyPI release. Everything
> below is contained in `0.7.0` (plus the Plan-Review follow-ups:
> `collections.abc.Mapping`-aware drop, `_diff_keys` audit-trail fix, and
> public docstring refresh). Keep the entry for historical trace; upgrade
> path is `pip install -U aegis-trust` (resolves to 0.7.0 or later).

Hotfix release. Closes a silent-pass leak path in `scope` filtering over
list-of-dict return values, and removes five user-visible instances of a
"contact <email>…" verb/name duplication introduced during the 0.6.5.5
hotfix sweep. Also adds a lint guard so the duplication cannot recur.

Releases 0.6.5.3 and 0.6.5.4 carry obsolete contact addresses on a
domain that was never set up. They are **yanked on PyPI** with the
reason *"obsolete contact metadata; use 0.6.5.5+"*. Yank is
non-destructive: existing installs keep working, and pinned installs
(`aegis-trust==0.6.5.3`) still resolve. Default `pip install
aegis-trust` will resolve to 0.6.5.6 or later.

### Fixed

- **Silent-pass leak on `scope=["key"]` over a list of dicts** (minimum
  disclosure, fail-closed). A bare leaf whitelist over a list containing
  dict elements now drops the key and emits an `aegis` logger WARNING
  pointing at the `key.<field>` dot-notation fix. Data behavior is
  breaking for callers that relied on the previous pass-through, and the
  change is intentional — the previous behavior released inner fields the
  caller never whitelisted. Detection uses `any(isinstance(x, dict) for x
  in v)` so heterogeneous lists (`[1, {"ssn": "x"}]`) are caught too.
- **`deny_fields` symmetry**: `_deny_filter_dict`'s docstring now states
  the contract explicitly. `deny_fields=["users"]` drops the whole key;
  `deny_fields=["users.ssn"]` removes the `ssn` field from each list
  element; bare `deny_fields=["ssn"]` matches the top-level key only and
  does not recurse into child collections. No code change — the prior
  behavior already satisfies the contract; the docstring closes the
  ambiguity.
- **"contact <email>" duplication removed** from five user-visible
  locations: `shield.py` module docstring, the backend policy synchronization helper docstring,
  the backend policy synchronization helper `RuntimeError` message, `README.md` "Beyond local
  filtering" section, `SECURITY.md` attestation note, `llms.txt` optional
  extras. Verb changed from `contact` to `email` wherever the following
  token is the email address itself.

### Added

- **README "Filtering inside lists"** section documents the new drop
  semantics with copy-pasteable examples (dot-notation fix, bare-leaf
  drop, empty-list and list-of-primitive pass-through, deny-side
  symmetry).
- **Lint regression guard** (`scripts/check_trojan_compliance.py`): the
  pattern `contact\s+`?contact@` is banned in both public files and
  source-side user-visible strings. The verb/name duplication cannot
  recur silently — reintroduction fails the lint with a specific
  violation line.

### Migration

If any call site relied on `scope=["key"]` returning a list of unfiltered
dicts, change it to `scope=["key.<field>"]` with the fields the agent is
actually allowed to see. The new behavior is strictly safer: the previous
form silently released every inner field regardless of the declared
scope.

If you pinned `aegis-trust==0.6.5.3` or `==0.6.5.4`, upgrade explicitly —
those versions' contact addresses bounced.

## [0.6.5.5] — 2026-04-13

Hotfix release. Corrects a non-trivial documentation bug: releases 0.6.5.3
and 0.6.5.4 listed contact addresses on a placeholder domain that was
never actually owned or set up for mail. Messages sent to those
addresses would bounce. This release replaces every user-visible contact
channel with `contact@aegisagentcontrol.com` — the single real, owned
address — and locks the new value in the lint gate so the regression
cannot recur.

### Fixed
- **Contact address corrected everywhere**: `pyproject.toml` author email,
  README, AGENTS.md, SECURITY.md, llms.txt, NOTICE, the backend policy
  synchronization helper RuntimeError message, and every historical
  CHANGELOG reference now point at `contact@aegisagentcontrol.com`. The
  previous placeholder domain had no mail server and never did.

### Added
- **`scripts/check_trojan_compliance.py`** allowlist tightened to the
  single approved address (`contact@aegisagentcontrol.com`), and the ban
  list extended with the obsolete placeholder domain so any future
  reappearance fails the Trojan Horse lint.

### Migration
- If you saved a contact address from 0.6.5.3 or 0.6.5.4, replace it
  with `contact@aegisagentcontrol.com`. Previous versions' mails were
  not reaching anyone.

## [0.6.5.4] — 2026-04-13

Hotfix release. Closes the four agent-facing Trojan Horse leaks discovered in
the post-ship `pip install aegis-trust==0.6.5.3` review of `help()` / `dir()`.
Pure documentation, signature, and namespace cleanup. No runtime behavior change.

### Changed
- **`@shield(...)` `mode` default**: the displayed default is now the string
  `"auto"` instead of the internal enum repr form. Behavior is identical
  (the function accepts both forms), but `help(shield)` no longer surfaces
  the internal enum name.
- **`@shield(...)` docstring**: removed internal compliance code
  references. The user-facing principles ("data flow must be explicit",
  "minimum disclosure required", "fail-closed") remain unchanged.
- **`AegisClient.__init__` `base_url`** now defaults to `None` and the actual
  default URL is resolved from the module-level `_DEFAULT_BASE_URL` constant.
  `help(AegisClient)` no longer surfaces the development localhost URL in the
  signature. Behavior is identical: `base_url=None` resolves to the same value.
- **`from aegis import *`** now exports only `shield`. Direct submodule
  imports (for example `from aegis.types import Mode`, or
  `from aegis.types import IngestEntry`) continue to work. `dir(aegis)`
  shrinks from 19 names to 4.
- **Logger messages and `_validate_field_path` warnings**: stripped
  internal compliance codes from the user-visible
  `logger.{warning,error}(...)` strings. Only the human-readable principle
  text is kept ("fail-closed", "minimum disclosure", etc.).

### Added
- **`scripts/check_trojan_compliance.py` source-side scope refined**: now
  walks public top-level functions, public classes (and all their methods),
  the module docstring, and every `logger.<level>(...)` string literal.
  Private function docstrings (`_filter_dict`, `_deny_filter_dict`, etc.)
  remain free to use internal terminology for engineers reading the source.
  internal compliance codes are now banned in the same scope as other
  internal nomenclature (Full mode, legacy `aegis-shield`, etc.).

### Migration
- `from aegis import *` consumers that previously expected `Mode`,
  `AegisClient`, `IngestEntry`, etc. to be re-exported should switch to
  named imports: `from aegis.types import Mode`, `from aegis.client import
  AegisClient`. Direct named imports were never broken.

## [0.6.5.3] — 2026-04-13

### Changed
- **Documentation revamp for world release (Sprint S020 Docs).** README rewritten
  for a 30-second value scan, copy-pasteable `python -c` quickstart, and six inline
  use cases (Quickstart, FastAPI, FastMCP, `aegis.yaml`, async, `deny_fields`). All
  example imports use `from fastmcp import FastMCP` consistently across README and
  AGENTS.md.
- **PyPI metadata polished.** `keywords` extended with `mcp`, `scope`, `trust`,
  `purpose`, `field-level`, `decorator`, `minimum-disclosure`. `Development Status`
  bumped to Beta. `Framework :: Pytest` classifier added. `authors.email` now
  routes to `contact@aegisagentcontrol.com`.
- **`llms.txt` rewritten** for AI-agent discoverability and packaged inside the
  wheel (`aegis/llms.txt`) via `hatch force-include`. AGENTS.md and SECURITY.md
  rewritten for the `aegis-trust` brand and the approved
  `sales@/security@/contact@aegisagentcontrol.com` contact channels.

### Added
- **Four enforcement scripts** under `scripts/` make the S020 Agent-Friendly
  checklist runnable instead of subjective:
  - `check_public_api_docstrings.py` — every public API has a docstring (E-1).
  - `check_error_messages.py` — every `ValueError`/`RuntimeError` is actionable
    and free of internal product names (I-2).
  - `check_trojan_compliance.py` — public files plus `src/` docstrings and
    `logger.*` strings are scanned for legacy or internal-only terms.
  - `test_5min_quickstart.sh` — clean-venv `pip install` plus `python -c`
    quickstart asserted to complete inside 300 seconds (I-3, I-4). Local run
    measures roughly three seconds.

### Fixed
- **Public-surface Trojan leaks.** `client.py`, `shield.py`, and the @shield
  decorator's docstring no longer enumerate internal mode names or refer to the
  enterprise backend by its internal codename. Runtime log lines were rephrased
  in the same way. The the backend policy synchronization helper `RuntimeError` now points users at local
  filtering or `contact@aegisagentcontrol.com`, with no internal name in the message.

### Migration
- No code changes required from `aegis-trust 0.6.5.2`. This release is
  documentation, metadata, and lint-gate only.

## [0.6.5.2] — 2026-04-13

### Changed
- **Package renamed: `aegis-shield` → `aegis-trust`**. The PyPI distribution name was changed to `aegis-trust` because `aegis-shield` was already registered on PyPI by an unrelated party. The new name also better reflects the category positioning: `aegis-trust` is the trust layer for AI agents.
  - `pip install aegis-trust` (was: `pip install aegis-shield`)
  - Import path **unchanged**: `from aegis import shield` continues to work identically.
  - All internal module names (`aegis.shield`, `aegis.client`, `aegis.config`, etc.) remain the same.
  - No code changes in `src/aegis/`. Package is functionally identical to 0.6.5.1.

### Migration
- For TestPyPI users of `aegis-shield==0.6.5.1`: uninstall and reinstall as `aegis-trust==0.6.5.2`. No application-source changes needed.

## [0.6.5.1] — 2026-04-13

### Changed
- **Release metadata hardening (Trojan Horse strategy)**: package metadata now reflects the proprietary Aegis platform positioning. `pip install aegis-shield` continues to provide the full `@shield` decorator, but distribution metadata no longer exposes implementation details of the Aegis platform.
  - Removed `Homepage` / `Repository` / `Changelog` URLs from `pyproject.toml` (source repository is private).
  - Removed GitHub-hosted badges from `README.md`.
  - Replaced Operating Modes section with Aegis Platform category positioning; production deployments now direct to `contact@aegisagentcontrol.com`.
  - Removed Architecture section that exposed internal Aegis component names.
  - Replaced private-repo relative links (`examples/`, `docs/decisions/`, `SECURITY.md`) with `contact@aegisagentcontrol.com` contact.

### Added
- **NOTICE file**: explicit patent reservation. MIT License grants copyright permissions only; patent rights in Aegis platform technologies are expressly reserved by Incierge Inc. Commercial and patent licensing inquiries routed to `contact@aegisagentcontrol.com`.

## [0.6.5.0] — 2026-04-12

### Fixed
- **deny_fields fail-open vulnerability (minimum disclosure)**: `deny_fields=["profile", "profile.ssn"]` silently leaked `profile.age`, `profile.salary`, etc. because path tree merge made the parent non-leaf. `_parse_paths(broader_wins=True)` now ensures broader deny paths always win over narrower children. Scope mode (whitelist) is unaffected.
- **filtering path exception guard (fail-closed)**: exceptions during `_filter_result`/`_deny_filter_result` (e.g., malicious dict subclass raising on `.items()`) now return empty string instead of crashing. All three shield modes (lite, full, deny) are guarded.
- **CI checkout SHA test**: tightened from accepting mutable tags (`v4`) to requiring full 40-char SHA pin.

### Added
- **Adversarial regression suite** (`tests/adversarial/`): 10 test files, 111 tests covering scope bypass, deny_fields bypass, REST API boundary, exception info leak, YAML injection, SQLite injection, `_test_hook` abuse, CI/CD attack vectors, validation boundaries, and supply chain integrity. AI Red Team Sprint S018.
- **Direct unit tests for `_parse_paths(broader_wins=True)`**: 7 tests covering duplicates, 4-level depth chains, mixed independent paths, same-depth non-parent fields, and backwards compatibility.

### Security
- AI Red Team Sprint S018: adversarial penetration testing of v0.6.4.1 from AI attacker perspective. 10 attack scenarios, 111 adversarial tests. Found and fixed 1 MEDIUM vulnerability (deny_fields path tree merge fail-open) and 1 LOW hardening gap (filtering path exception guard).

## [0.6.4.1] — 2026-04-12

### Fixed
- **LaunchAgent log paths**: moved stdout/stderr from world-readable `/tmp/` to user-only `~/.aegis/logs/` directory. `install.sh` now replaces `__HOME__` placeholder and creates the log directory.
- **CI supply chain hardening**: `actions/checkout@v5` pinned to SHA `93cb6efe18208431cddfb8368fd83d5badbf9bfd` to prevent tag-based supply chain attacks.
- **`.gitignore` credential protection**: replaced specific `.env` / `.env.local` entries with `.env*` wildcard to prevent accidental commit of `.env.production` or similar files.

### Added
- **`uv.lock`** tracked for reproducible builds and supply chain protection.

### Security
- Security Sprint S017: systematic OWASP Top 10 + STRIDE coverage audit of v0.4-v0.6.4 codebase. Manual code review of shield.py, client.py, scripts/, launchd/, CI/CD, and dependency supply chain. Result: CRITICAL=0, HIGH=0. All findings fixed.

## [0.6.4] — 2026-04-12

### Fixed
- **CI attestation completeness (S014 T-105 root cause)**: `make ci-matrix` Makefile recipe used `/bin/sh` with `pip install ... | tail -1` and `pytest ... | tail -3`, masking non-zero exit codes behind `tail`. This caused a false "ALL PASSED" display even when all steps failed. Extracted to `scripts/ci-matrix.sh` with `set -euo pipefail`, individual exit code checks, and no pipe masking.
- **attestation integrity (S014 T-107)**: `scripts/ci-attest.sh` appended the OPENTIMESTAMPS status line after `ots stamp`, invalidating the proof. Now uses sidecar `.ots-status` file; the attestation file is never modified after stamping.
- **fail-closed CI**: `pip-audit` failure no longer silently continues attestation generation (`|| true` removed). Non-zero exit from `pip-audit` aborts attestation.
- **Same-pattern pipe mask** in `ci-attest.sh` (`pip install ... | tail -1`) fixed to `uv pip install` with direct exit code check.
- **Pre-push hook fragile grep** (`grep -q "No known vulnerabilities found"`) replaced with exit-code-based `pip-audit` check.

### Added
- **`scripts/ci-matrix.sh`** — standalone CI matrix runner with bash strict mode (`set -euo pipefail`), `uv pip install --python` for pip-less venvs, per-version result tracking.
- **`VERSION` file** — single source of truth for version. `tests/test_version_ssot.py` asserts `VERSION` = `pyproject.toml::version` = `aegis.__version__`.
- **Pre-PQC bridging**: attestation hash upgraded from SHA-256 to **SHA-3-512** (NIST FIPS 202). `tests/test_sha3_known_vector.py` validates against NIST test vectors and prevents SHA-512/256 confusion.
- **`scripts/ots-verify-external.sh`** — multi-source independent OTS verification via blockstream.info + mempool.space APIs (replaces local Bitcoin node requirement).
- **`launchd/`** directory with version-controlled LaunchAgent plists and scripts for CI cost monitoring, OTS confirmation watching, and watchdog.
- **`docs/RUNNER_HARDENING.md`** — self-hosted runner threat model and credential rotation plan.
- **`tests/test_ci_scripts.py`** — automated regression tests for CI script failure propagation (CI attestation).
- **Shellcheck CI step** in GitHub Actions workflow.
- **OTS ≠ PQC disclosure** in README.md and SECURITY.md per PQC migration roadmap commitment.

### Changed
- `actions/checkout` bumped from v4 to **v5** (v6 ignored via dependabot config, per Aegis policy).
- `attrs` dependency relaxed from `<25.0` to `<27.0` (no breaking change impact; aegis-shield does not use `field_transformer`).
- CI workflow `pip install` replaced with `uv pip install --python` for consistency with local CI matrix.
- `examples/crypto_wallet.py` — plausible secret strings replaced with `<REDACTED>` placeholders (eliminates gitleaks false positives).
- PQC migration roadmap updated: SHA-3-512 moved from v0.7 to v0.6.4, task ID corrected to T-209.

## [0.6.3] — 2026-04-10

### Changed
- **CI moved to self-hosted GitHub Actions runner.** Eliminates dependency on GitHub-hosted Actions billing entirely. The runner runs on the canonical maintainer machine (Apple Silicon, macOS) and consumes zero GitHub Actions minutes. CI matrix completes in ~1m 44s.
- **Workflow trigger restricted to `push` only.** PRs from forks are no longer auto-CI'd. This eliminates the fork-PR-attacks-self-hosted-runner attack vector entirely. To CI a contribution, the maintainer pushes it to a branch in this repo (typically `task/...`).

### Added
- **Self-hosted runner setup documentation** in `docs/RELEASE.md` — full step-by-step setup including SHA-256 verification of the runner binary, security model explanation (Aegis runner trust boundary), and persistence options.
- **Fork detection guard step** in every CI job — defense-in-depth check for `github.event.repository.fork` (trust boundary).

### Security
- Each job has explicit `runs-on: [self-hosted, macOS, ARM64, aegis-shield]` labels to prevent accidental cross-project execution.
- Workflow YAML now uses `uv` to manage Python versions on the runner instead of `actions/setup-python` (faster + more controllable).

## [0.6.2] — 2026-04-10

### Added
- **Manual CI Attestation infrastructure** — when automated CI (GitHub Actions, etc.) is unavailable, releases can be verified via local matrix CI bound to commit SHA + timestamp + SHA-256 self-signature + (optional) OpenTimestamps proof. This is the Aegis-aligned alternative to merging without CI evidence (CI attestation completeness).
  - `make ci-matrix` — runs pytest + ruff across Python 3.10/3.11/3.12/3.13 via uv
  - `make ci-attest` — generates `.gstack/ci-attestations/SXXX-vX.Y.Z.txt` (commit-bound, signed)
  - `make ci-act` — runs `.github/workflows/ci.yml` locally via `act` (validates the workflow YAML itself)
  - `scripts/ci-attest.sh` — attestation generator with OpenTimestamps anchoring
  - `scripts/ci-act.sh` — act wrapper with pre-flight checks
  - `docs/RELEASE.md` — full release process documentation (standard + manual attestation paths)
- **`SECURITY.md`** — vulnerability reporting policy with AO-aligned severity baselines
- **`.github/CODEOWNERS`** — required reviewers for security-critical files (review enforcement)
- **`.github/dependabot.yml`** — automated dependency update tracking (independent of GitHub Actions billing)
- **README badges** — CI status, PyPI version, Python versions, license, Aegis AO compliance

### Changed
- `Makefile` — added `lint`, `format`, `audit`, `ci-matrix`, `ci-attest`, `ci-act` targets
- `clean` target now also removes `.ci-venv-*` directories

## [0.6.1] — 2026-04-10

### Breaking Changes
- `@shield` decorated functions that raise an exception now return empty string `""` instead of propagating the exception (fail-closed). This prevents sensitive data (DB connection strings, customer data, error context) from leaking via tracebacks. Errors are still logged via `logger.error` for internal observability.

### Security
- **Fail-closed fix (M1)**: scope bypass on dot-path mismatch — when `scope=["profile.age"]` but the value at `profile` is a scalar (string, int, etc.), the key is now dropped (fail-closed) instead of passed through unfiltered. Previously, scalar values bypassed nested-path filtering.
- **Fail-closed fix (M2)**: exception propagation — `@shield` now wraps user function calls in try/except, returning empty string on exception. Prevents leaking internal data via tracebacks.
- **DoS hardening (M3)**: Added 10s `httpx.Timeout` to `AegisClient`. Prevents indefinite blocking when aegis-core is unresponsive.

### Added
- **CI/CD pipeline (M4)**: GitHub Actions workflow (`.github/workflows/ci.yml`) running pytest (Python 3.10-3.13) + ruff + pip-audit on push/PR.
- 9 regression tests covering M1 (scope scalar drop, deny scalar keep), M2 (sync + async exception sanitization), M3 (httpx timeout configured).

## [0.6.0] — 2026-04-10

### Breaking Changes
- `@shield` decorated functions returning non-dict/non-list values (int, str, dataclass, etc.) now return empty string `""` instead of passing through unfiltered (fail-closed). `None` still passes through. Previously these values bypassed field filtering silently.

### Added
- **aegis.yaml policy file** — centralize purpose-based scope/deny_fields in a single YAML config. `@shield(purpose="support")` auto-loads policies from `aegis.yaml` when scope/deny_fields are omitted
- `load_config()` and `reset_config()` public API for explicit config management
- Config file search order: `./aegis.yaml` → `./aegis.yml` → `AEGIS_CONFIG` env var
- Config validation: mutual exclusion of scope/deny_fields (explicit data flow), field path validation, empty deny_fields rejection (minimum disclosure)
- **pytest plugin** — `shield_history` fixture captures @shield calls in-memory during tests
- `assert_shield_blocked(records, field)` and `assert_shield_passed(records, field)` test helpers
- Plugin auto-registers via `pytest11` entry point
- **Agent Friendly files** — `llms.txt` (AI agent SDK summary), `AGENTS.md` (integration guide), `py.typed` (PEP 561 marker)
- **5 new examples**: `async_example.py`, `multi_purpose.py`, `deny_fields_example.py`, `dot_notation_example.py`, `crypto_wallet.py`

### Changed
- `pyyaml` is now an optional dependency: `pip install aegis-shield[yaml]`
- `@shield(purpose="x")` without scope/deny_fields now tries aegis.yaml before raising ValueError

### Security
- **Fail-closed fix**: Non-dict/non-list return values from `@shield` decorated functions now return empty string instead of passing through unfiltered. Previously, scalar values (int, str, etc.) bypassed field filtering silently. `None` still passes through.
- Added `requirements.lock` for deterministic dependency resolution (supply chain hardening)

## [0.5.0] — 2026-04-10

### Breaking Changes
- `scope=["name"]` now applies to top-level only (v0.4 applied to all nesting levels). Use `scope=["name", "profile.name"]` to include nested paths.
- `deny_fields=["ssn"]` now applies to top-level only. Use `deny_fields=["profile.ssn"]` for nested paths.
- `_diff_keys` now reports removed fields as dot-notation paths (e.g. `"profile.ssn"` instead of `"ssn"`)

### Added
- **Dot-notation** for `scope` and `deny_fields` — precise nested path control (e.g. `scope=["name", "profile.age"]`, `deny_fields=["profile.ssn"]`)
- Field path validation: empty strings, leading/trailing dots, consecutive dots are rejected with `ValueError`
- **Local history store** (`history.py`) — SQLite-backed recording of @shield invocations (enable with `AEGIS_HISTORY=1`)
- `HistoryStore` class with `get_history(limit, purpose)` and `get_stats()` methods
- **CLI** (`aegis history`, `aegis stats`) — inspect local filtering history from the terminal
- `AEGIS_HISTORY_PATH` environment variable to customize history database location (default: `~/.aegis/history.db`)

### Changed
- Filtering engine rewritten: `_filter_dict` / `_deny_filter_dict` now use path-tree matching instead of flat key sets
- `_parse_paths()` converts dot-notation field lists into nested tree structures
- `_shield_lite`, `_shield_full`, `_shield_deny` now record to local history when enabled

## [0.4.0] — 2026-04-09

### Added
- Recursive `deny_fields` filtering — denied keys are removed at every nesting level (minimum disclosure)
- Recursive `scope` filtering — only allowed keys are kept at every nesting level (minimum disclosure)
- Element type validation: `scope` and `deny_fields` elements must all be strings
- Defensive list copy: mutating the original scope/deny_fields list after decoration has no effect
- `IngestEntry.deny_fields` field — aegis-core audit now records which deny_fields were configured
- Recursive `_diff_keys` — audit `blocked_fields` now accurately reports all removed keys including nested ones (audit completeness)

### Changed
- `_filter_dict` and `_deny_filter_dict` are now recursive (previously top-level only)
- `_diff_keys` now recursively collects removed keys from nested dicts and lists

### Security
- Fixed: `deny_fields=["ssn"]` previously did not remove `ssn` from nested dicts like `{"profile": {"ssn": "..."}}` — now removed at all levels
- Fixed: `scope=["name"]` previously passed through all nested content under allowed keys — now filtered recursively
- Fixed: audit `blocked_fields` under-reported removals for nested data (audit completeness)

## [0.3.1] — 2026-04-08

### Fixed
- Empty `deny_fields=[]` now raises `ValueError` (fail-open risk detected by /cross-review)

## [0.3.0] — 2026-04-08

### Added
- `deny_fields` parameter for `@shield` — blacklist mode (hide specific fields, keep everything else)
- FastMCP integration example (`examples/fastmcp_tool.py`)
- Full README rewrite with 30-second quickstart, FastMCP example, and API reference

### Changed
- `scope` parameter is now optional (either `scope` or `deny_fields` required)
- Specifying both `scope` and `deny_fields` raises `ValueError` (explicit data flow)
- Specifying neither `scope` nor `deny_fields` raises `ValueError` (minimum disclosure)
- Empty `deny_fields=[]` raises `ValueError` (hides nothing, fail-open risk)

## [0.2.0] — 2026-04-08

### Added
- Shield API client: `ingest()`, `policy_sync()`, `get_stats()`, `get_report()`
- `backend policy synchronization()` function for purpose policy synchronization
- Fail-closed mode: `@shield` returns empty result when audit fails (audit completeness)
- `_diff_keys` handles `list[dict]` inputs for accurate blocked field reporting
- Shield API types: `IngestEntry`, `IngestResponse`, `PolicySyncEntry`, `PolicySyncResponse`, `ShieldStats`
- Pre-push quality gate (ruff + pytest + pip-audit)

### Changed
- `_shield_full` now uses `/shield/ingest` instead of `/audit-log`
- All Shield API methods unwrap aegis-core `{success, data}` envelope
- the backend policy synchronization helper raises `RuntimeError` in Lite mode

## [0.1.1] — 2026-04-07

### Added
- Async function support: `@shield` now works with `async def` functions
- Full-mode integration tests (9 tests, requires aegis-core)

### Fixed
- Empty token no longer sends invalid `Bearer ` header to aegis-core

## [0.1.0] — 2026-04-07

### Added
- `@shield(purpose, scope)` decorator for AI agent data access control
- Three operating modes: Lite (local filtering), Full (aegis-core), Auto (detect)
- `AegisClient` for aegis-core REST API communication
- Type definitions: `Mode`, `AccessPolicy`, `AuditEntry`, `ShieldResult`
- Auto-generated client for 31 aegis-core API endpoints
- 12 lite-mode unit tests
- Quickstart example
