# Changelog

## [Unreleased]

### Docs (internal-ops/sprint_018 — LITE error-parity remediation)
- **No Node code change.** The Python SDK reached parity on the LITE
  validation/config error path (it now raises `AegisValidationError` /
  `AegisConfigError` with the same `code` strings Node already used). The
  shared error registry (`node/docs/errors/README.md`) is updated to record,
  per code, which SDK(s) emit it (`both` / `node` / `python`) so the
  cross-SDK contract is explicit. Node-only codes
  (`aegis.shield.purpose.required`, `aegis.shield.mode.sync_full_unsupported`,
  the `aegis.wrap.*` codes) and Python-only codes (`aegis.shield.spec.conflict`,
  `aegis.shield.deny_fields.empty`, `aegis.shield.field_path.invalid`) reflect
  real, intentional API differences, not gaps to close.
- **P1 follow-up (Python-side, doc updated here).** A parallel adversarial audit
  found that the Python conversion-failure and local-history-failure log
  *diagnostics* leaked PII/secrets (exception message + traceback; raw
  `AEGIS_HISTORY_PATH`) on the default surface, and that the interim Python
  envelope had broken `except FileNotFoundError` / `except OSError` /
  `except ImportError`. Both are fixed in the Python SDK (diagnostics are now
  minimum-disclosure; config errors restore the natural builtin catches via
  `AegisConfigFileNotFoundError` / `AegisConfigImportError`). The shared error
  registry (`node/docs/errors/README.md`) records the catch-compat and
  minimum-disclosure guarantees. Node behaviour is unchanged (Node already
  withheld these); no Node code change.

### failure-UX hardening + claim-integrity (internal-ops/sprint_016)

`internal-ops/sprint_016` Collison-grade production-readiness review +
in-scope hardening. No data-path leak was found (fail-closed re-confirmed); the
fixes below close **silent** failure-UX trust gaps and **false documentation
claims** — the worst defect class for a trust product. Source-committed on branch
`sprint/S016`; **not yet released** (rc9 publish is gate-blocked, carried forward).

### Added (internal-ops/sprint_017 — schema_version contract)
- `schema_version` is now stamped on every audit event the SDK emits, from a
  single source (`src/constants.ts` `AUDIT_SCHEMA_VERSION = 1`, re-exported by
  `index.ts`). Wired to both surfaces consistently: local JSONL history records
  (`HistoryStore.record` / `recordIdempotent`) and the `/shield/ingest` wire
  payload (additive field; the aegis-core gateway ignores unknown fields, so it
  is backward-compatible — the gateway does not yet persist/use it).
- Backward compatibility: a history record written before this field reads back
  as `schemaVersion: 1` (missing → 1).
- `schema_version` is intentionally **excluded** from the idempotency
  `payloadHash` — `payloadHash` is unchanged by this sprint, so cross-language
  SHA-256 byte parity with Python is preserved.
- Deferred (not implemented): typed `Actor`, `Decision` enum,
  `resource_id`/`resource_type` (the latter is the schema_version=2 shape, gated
  behind a separate decision).

### Changed — invalid / mis-cased `mode` now throws (no silent downgrade)

- `shield({ mode })` with an unrecognized or mis-cased string (e.g. `"FULL"`,
  `"Lite"`, `"fulll"`) now throws `AegisValidationError`
  (`aegis.shield.mode.invalid`) instead of silently falling through to AUTO —
  which had downgraded a caller asking for strict FULL gating into un-gated LITE
  with zero signal. Mode is a trust boundary. (`src/shield.ts`; tests
  `tests/shield.test.ts` "invalid mode is rejected (S016)".)

### Changed — FULL-mode audit-ingest failure is no longer silent

- A post-authorization `/shield/ingest` failure already failed **closed** (data
  withheld, AO-003); it now also emits a `console.warn` with remediation + a
  `fail_closed`/`ingest_failed` audit record, so the caller does not mistake the
  empty result for "no data". (`src/shield.ts` `gateAndRunFull`.)

### Changed — `AEGIS_HISTORY=1` write failure now warns once

- When the local audit log cannot be written, `recordIfEnabled()` now warns once
  ("audit evidence is NOT being recorded") instead of silently swallowing the
  error. The data path stays unbroken; the broken-evidence condition is visible.
  (`src/history.ts`.)

### Fixed — documentation claim integrity

- Corrected the npm README's forward-pending "PyPI ships rc8" claim (PyPI is on
  rc7) and removed an over-stated local-audit integrity claim. FULL-mode gateway
  guarantees remain explicitly scoped with a "Not guaranteed" carve-out.
  (`README.md`.)

### Review artifact

- `deploy/s016/COLLISON_REVIEW.md` — the 10-dimension production-readiness review.
  (Regenerated in S017; the S016 run committed the code but did not persist the
  document.) Execution evidence — `vitest`, `tsc --noEmit`, clean-room install —
  is pending the S017 execution pass and is **not** asserted as re-run.

## [0.9.0-rc8] — 2026-05-30 — fail-open → fail-closed remediation (internal-ops/sprint_015)

`internal-ops/sprint_015` remediation of the S014 distribution-readiness
NO-GO. Adversarial falsification (single-model + a 3-reviewer cross-model pass)
found data-path edges where the Node SDK returned data **fail-open** while the
Python SDK fail-closes, contradicting both READMEs' fail-closed contract — incl.
a prototype-name `scope` bypass that the first single-model sweep missed. All
are now aligned to Python (Direction A). **Behavioral / breaking** for callers
that relied on the previous fail-open shapes. Verified: prototype-name + 25
adversarial surfaces → 0 leaks; suite 130/130; `sdk_public_surface_parity` PASS.
Paired with PyPI `aegis-trust==0.9.0rc8` (cross-SDK version-lock).

### Changed — `shield()` / `wrap()` reject an empty spec (minimum disclosure)

- Calling `shield({ purpose })` (or `wrap(value, { purpose })`) with **neither
  `scope` nor `denyFields`** now throws `AegisValidationError`
  (`aegis.shield.spec.required` / `aegis.wrap.spec.required`). Previously the
  wrapped function's data was returned **entirely unfiltered**, leaking every
  field. Parity with Python `shield.py:761-774`.
  **Migration:** pass an explicit `scope` (whitelist) or `denyFields`
  (blacklist). An empty spec was never safe.

### Fixed — prototype-name fields no longer bypass `scope` (fail-closed)

- A returned field whose name collides with an `Object.prototype` member
  (`toString`, `constructor`, `hasOwnProperty`, `valueOf`, `__proto__`, …) was
  kept and returned **raw** even when not whitelisted, because the scope check
  used `key in pathTree` (which walks the prototype chain). Scope is a
  whitelist, so this was fail-OPEN. Fixed: the path tree is now a
  null-prototype object and both the scope and deny checks use
  `hasOwnProperty`. (Pre-existing since rc2; the Python SDK was never affected
  because it uses a real `dict`.) Surfaced by a multi-reviewer cross-model
  pass during S015.

### Changed — `denyFields` over a non-record value fails closed

- `denyFields` applied to a **scalar** (e.g. a bare string) or an
  **array of scalars** now returns a type-shaped empty (via `emptyFor`:
  `""` for a string, `0` for a number, `false` for a boolean, `[]`/`["…"]` for
  arrays), instead of the raw value. This is the fail-closed direction; a
  blacklist cannot prove a bare scalar is not itself the secret. (Python
  `_deny_filter_result` returns `""` for all non-record scalars; Node mirrors
  the *fail-closed intent* but keeps the value's empty-of-type shape — a
  documented, benign shape difference, never a leak.) Objects (incl. class
  instances, normalized via `toFilterable`) are filtered field-wise as before
  — only field-less shapes fail closed.

### Note — `scope: []` / empty spec is stricter than Python (safe direction)

- Node throws on an explicit empty spec (`scope: []` with no `denyFields`),
  whereas Python treats `scope=[]` as "disclose nothing" and returns `{}`.
  Node's filter passes unfiltered data through when `scope.length === 0`, so
  rejecting the empty spec at construction is the fail-closed choice. This is
  an intentional, safe-direction divergence, not a parity bug.

### Changed — a wrapped function that throws now fails closed

- If the protected function throws, all paths (LITE sync/async, AUTO→LITE,
  FULL `gateAndRunFull`) now catch and return a fail-closed empty rather than
  letting the exception propagate raw. A thrown error can carry PII in its
  message/stack; re-raising it leaked that data past the shield. Parity with
  Python `shield.py:921-929`.

### Changed — FULL-mode audit ingest is fail-closed (AO-003 audit completeness)

- FULL-mode `/shield/ingest` is now **awaited** and part of the trust
  contract: filtered data is released only after the audit record is durably
  accepted. On ingest failure the call fails closed to a type-shaped empty,
  matching Python `shield.py:1017-1035`. Previously ingest was fire-and-forget
  (fail-open) and the rc7 code documented this as a `python_node_parity`
  divergence deferred to v1.0 GA — that divergence is now **resolved** in favor
  of the Python fail-closed contract.

## [0.9.0-rc7] — 2026-05-26 — Pre-publish substrate gate wire + CHANGELOG artifact cleanup (internal-ops/sprint_S202)

`internal-ops/sprint_S202` rc7 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). **No public API change**; this release moves the productization 9-verifier gate into the release pipeline so every future tag push is mechanically audited before any artifact is built or published, and cleans sprint-internal Japanese strings out of the shipped `CHANGELOG.md`. Paired with PyPI `aegis-trust==0.9.0rc7` (cross-SDK version-lock).

### Changed — release pipeline now runs a fail-closed 9-verifier gate before publish

- `.github/workflows/release-attestation.yml`: new `productization-gate` job (runs-on self-hosted self-hosted-runner). Invokes `~/internal-ops/ops/internal-ops/_shared/scripts/dogfood_aegis_trust.sh` which exercises the internal-ops 9 verifiers (5 P0 + 4 P1) against the workspace. `sbom-node` + `sbom-python` now `needs: [productization-gate]`; `collect-and-sign` / `pack-and-sign-sdk` / `publish-npm-trusted-publisher` are transitively gated. If any P0 verifier fails on a tag push, **no SBOM is generated and nothing is published**. P1 verifiers in `MANUAL_PENDING` (per sprint_005 transitional doctrine) do not block.

### Changed — `CHANGELOG.md` is now english-first (artifact cleanup, no code change)

- `node/CHANGELOG.md` S179 reference line: replace the non-english sprint annotation with "mil-spec test-honesty doctrine". CHANGELOG ships inside the npm tarball, so customer-facing artifact text must be english-first per `internal-ops/9-verifier #2 english_first_artifact`.
- Same fix on the Python side (`python/CHANGELOG.md` S023 + S024 entries). No semantic difference; the dropped strings were sprint-internal annotation that leaked into the shipped artifact.

### Routed scenarios (internal review)

- `family_5_ops_ci_release / supply_chain_attestation`: incremental — gate is now invoked by the publish pipeline (was only a maintainer-local dogfood through rc6). Still `closure_candidate` until external oracle walk closes the literal residual.
- `family_5_ops_ci_release / npm_pypi_latest_rc_tag_drift`: unchanged — `dist-tags.latest` intentionally stays on `0.9.0-rc3` per the pre-release-doesn't-promote-to-latest design. `npm install aegis-trust@rc` resolves to rc7.



`internal-ops/sprint_011` rc6 cut. **Preview release** (`STABILITY_LEVEL = "preview"`). Public API is additive over rc5 with one **behavioral change** on FULL-mode fail-closed return value (see `shield()` FULL mode entry below: shape-preserving empty → `null` for the data-path deny / unreachable cases). Paired with PyPI `aegis-trust==0.9.0rc6` (cross-SDK version-lock).

This is also the **first release cut from the `aegis-trust` monorepo itself** (rc1–rc5 were published from `aegis-shield`, the historical mirror; see `aegis-shield/README.md` L1 `📍 Source moved`). Provenance attestation (SBOM + cosign keyless signatures + GitHub Release artifact attach) is generated by `.github/workflows/release-attestation.yml` (Block B Phase 2) on the `v0.9.0-rc6` tag push.

### Changed — `detectMode` now intent-first (matches README AUTO behaviour matrix)

- `node/src/client.ts` `detectMode()` checks `userIntendsFull()` BEFORE
  probing the backend. Earlier rc4-rc5 builds probed `/health` first and
  opportunistically upgraded AUTO to Full whenever the gateway was
  reachable, even without intent — that contradicted the README matrix
  line "auto + no Full intent → Lite" and made dev environments without
  credentials call `/check-access` against the gateway. The intent-first
  variant restores the documented matrix exactly.
- New behaviour:
  - `AUTO + no Full intent` (no `AEGIS_TOKEN` AND no non-dev URL) → LITE
    (no probe, no `/check-access`).
  - `AUTO + Full intent + reachable backend` → FULL (opportunistic upgrade
    with intent).
  - `AUTO + Full intent + unreachable backend` → fail-closed FULL + one
    `console.warn`. Unchanged.
- `tests/fullMode.test.ts`: the rc4 "AUTO opportunistically upgrades to
  FULL when backend reachable, even without AEGIS_TOKEN" test asserted
  the now-removed probe-first behaviour. Replaced with the matrix-aligned
  assertion: "AUTO + no token + reachable backend → LITE (no opportunistic
  upgrade without intent)".
- **Routed scenarios** (internal review verification batch 1):
  `python_node_parity` divergence #2 (AUTO degrade semantics) — resolved.
  `auto_mode_behavior` (P1) — resolved.

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
### Changed — README: `FULL mode — gateway trust-boundary guarantees` subsection (CSR 4/4 claim-scoping)

- `README.md`: added a `### FULL mode — gateway trust-boundary guarantees` subsection. It states, in **scoped** wording verified against aegis-core code, the four guarantees the gateway `/check-access` ingress provides after the Core Security Remediation track (CSR 4/4, landed in aegis-core 2026-05-21): identity binding to the auth-middleware identity, ingress denial of unknown purpose / scope / malformed capsule, audit-or-deny (HTTP 503) fail-closed, and `AEGIS_PROFILE=production` boot-time config validation. The subsection also states explicitly what is **not** guaranteed (no gateway-wide audit fail-closed, no purpose × scope field-level minimum-disclosure, not production-ready out of the box, no all-gateway-operations audit-complete claim) and records four tracked follow-ups.

### Fixed

- **CLI bin-shim silent-exit** (`src/cli.ts`): every `aegis` subcommand invoked through the npm bin shim (`node_modules/.bin/aegis`, including the `npx aegis ...` path that goes through it) silently exited with 0 bytes on both stdout and stderr and exit code 0. Root cause: the ESM "is main module" check compared `basename(process.argv[1])` (`"aegis"` under the bin shim) against the end of `import.meta.url` (`"cli.js"`); the two never matched, so `main()` was never called. Fixed by canonicalising both sides with `realpathSync(fileURLToPath(import.meta.url))` vs `realpathSync(process.argv[1])`. Customers who ran `npm install aegis-trust && npx aegis sandbox` on rc3 / rc4 / rc5 observed zero output and no error message. The next release cut ships the fix. Direct invocation (`node path/to/dist/cli.js sandbox`) was unaffected.
- Regression test added: `tests/cli_bin_invocation.test.ts` spawns the compiled `dist/cli.js` through a symlink in a temp directory (the same shape npm creates at install time) and asserts non-empty stdout + correct exit codes for `--help`, `sandbox`, `history`, `stats`, no-arg, and unknown-command invocations.

### Refs

- T-S179-cli-bin-shim (`internal-ops/sprint_006` Tier 0)
- Codex Operational Scenario Review finding #2 (2026-05-21)
- Memory `feedback_test_honesty.md`: fail-silent violates the mil-spec test-honesty doctrine

## [0.9.0-rc5] — 2026-05-21 — cross-SDK version-lock (PyPI rc5 parity, no functional change)

`internal-ops/sprint_006` Tier 0 follow-up. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). **Functional content identical to v0.9.0-rc4.**

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

`internal-ops/sprint_004` post-canonical-audit cross-SDK parity closure. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). Public API surface is additive over v0.9.0-rc3 with one **breaking-for-direct-callers** semantic change on an exported helper (see Migration below). Paired with PyPI `aegis-trust@0.9.0-rc4`.

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

`internal-ops/sprint_001` rollup. **Preview release** (`STABILITY_LEVEL = "preview"`, npm `dist-tag=rc`). Public API surface is additive over v0.8.1; no breaking changes. SLA: none. Production use: at your own risk. See [`docs/VERSIONING.md`](docs/VERSIONING.md).

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
