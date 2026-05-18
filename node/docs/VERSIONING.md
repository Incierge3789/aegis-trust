# aegis-trust versioning doctrine (v0.9.0-rc1+)

This document describes the seven independent axes of versioning the SDK
follows. Mirrors the productization-ops doctrine
(`~/ops-meta/doctrine/api_versioning.md`).

## 1. SemVer for the npm package

`aegis-trust` follows [SemVer 2.0.0](https://semver.org/):

| Component | When it changes |
|---|---|
| MAJOR | Breaking change to a public export (`shield`, `wrap`, `AegisClient`, error codes). |
| MINOR | Additive — new public export, new option, new error code. |
| PATCH | Bug fix or doc-only change with no public-surface impact. |

Pre-1.0 (current): API may break between minor versions, but every break
must be called out in CHANGELOG + a `MIGRATING_...md` file.

## 2. `schema_version` for the audit event

`AUDIT_SCHEMA_VERSION` (exported from `src/index.ts`, currently `1`) is the
on-disk / on-wire shape of `HistoryRecord` and the `/shield/ingest` payload.
It moves independently of the npm SemVer:

- Adding an optional field → no bump.
- Renaming or removing a field → bump.
- Changing a field's semantic meaning → bump.

The current local audit JSONL is implicitly schema 1; future versions will
include a top-level `schema_version` line at file genesis.

## 3. Stability level

`STABILITY_LEVEL` (exported from `src/index.ts`, currently `"preview"`):

| Level | Meaning |
|---|---|
| `preview` | v0.x / `-rc*` — public API may change between releases. Don't pin in production unless you're ready to migrate. |
| `stable` | v1+ — SemVer breaking-change rules apply. |
| `deprecated` | Marked for removal in next MAJOR. |

## 4. Breaking change rule

While `STABILITY_LEVEL === "preview"`:

- **Additive only by default.** New exports, new options, new error codes
  may land in a MINOR.
- **Breaking changes require explicit call-out** in CHANGELOG, a
  `MIGRATING_<from>_to_<to>.md` document at the repo root, and a deprecation
  notice in the prior minor (when feasible).

At `STABILITY_LEVEL === "stable"` (v1+):

- **No breaking changes in MINOR or PATCH.** Period.
- Renaming, removing, or repurposing a public export → MAJOR.
- Changing a function signature (param order, return type) → MAJOR.

## 5. Dated API version header (preview, full implementation in sprint_002)

For Mode.FULL backend communication, the client will eventually send an
`Aegis-API-Version: YYYY-MM-DD` header. The server is responsible for
honoring the requested date and emitting deprecation warnings for older
dates. The header is reserved in v0.9.0-rc1; full implementation lands in
the v0.9.0 → v0.9.x window.

## 6. Deprecation policy template

When a public export is deprecated, the SDK ships the following four
signals **simultaneously**:

1. **Runtime warning** — `console.warn` on first use per process, with the
   export name + the canonical replacement.
2. **CHANGELOG entry** — under a `### Deprecated` section, with the target
   removal version.
3. **JSDoc `@deprecated` tag** — visible in IDE tooltips.
4. **Docs cross-reference** — README / AGENTS.md updated to point
   readers at the canonical replacement.

A deprecated export must remain available for **at least one MAJOR
release** before removal (e.g. deprecated in v1.x → removed in v2.0,
not v1.5).

## 7. Error codes are part of the contract

Error codes thrown by the SDK (`aegis.shield.purpose.required`, etc.) are
part of the public API:

| Action | Bump |
|---|---|
| Add a new code | MINOR (additive). |
| Change `code` string for an existing condition | MAJOR. |
| Remove a code | MAJOR. |
| Change `message` free-text | None (free-text is not contract). |
| Change `remediation` free-text | None (free-text is not contract). |
| Change `docs_url` location | None (URL is informational). |

See [`docs/errors/README.md`](errors/README.md) for the canonical error
code registry.

## Compatibility matrix (v0.9.0-rc1)

| Surface | Stability |
|---|---|
| `shield()` / `wrap()` | preview (additive only) |
| `AegisClient` | preview (additive only) |
| `Mode.LITE` / `Mode.FULL` / `Mode.AUTO` | preview |
| `HistoryStore.record()` | preview |
| `HistoryStore.recordIdempotent()` (new in v0.9.0-rc1) | preview |
| `AegisError` and derived classes | preview |
| `aegis history` / `aegis stats` CLI | preview |
| `aegis.yaml` config schema | preview |
| `AUDIT_SCHEMA_VERSION = 1` | preview |
