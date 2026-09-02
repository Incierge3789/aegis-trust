# Handoff — registry bindings after the org move (0.10.1)

- date: 2026-09-02
- author: machine session (Company OS lane), handed to the aegis-trust lane at the operator's instruction
- repo: nemotek-inc/aegis-trust (PUBLIC), default branch `main`
- scope: get both registries back on the **token-free, attested** path after the 2026-09-01 move to the `nemotek-inc` organization, and finish the 0.10.1 npm release. Nothing in this document requires a code change to either SDK.

## State on 2026-09-02 (measured)

| | State |
|---|---|
| PyPI `aegis-trust` | `0.10.1` is live — uploaded on 2026-09-01 by `pypi-token-upload.yml` (workflow_dispatch, run 33495913685) from the cosign-signed artifacts of `release-attestation` run 33492829433. **No PEP 740 attestations** on this version (token path). Trusted Publisher on pypi.org still names the previous owner. |
| npm `aegis-trust` | latest is still `0.9.3`. The token-free upload job of `release-attestation` fails with `ENEEDAUTH` because the npm Trusted Publisher binding names the previous owner. `npm-token-upload.yml` (PR #146, merged) is the fallback, but the repository has **no `NPM_TOKEN` secret** and the machine has no npm credential. |
| Repository secrets | `PYPI_TOKEN` (2026-09-01) — temporary. `SITE_SYNC_DISPATCH_TOKEN` (unrelated). |
| Attestation run for 0.10.1 | 33492829433: all 9 verifier gates PASS, artifacts + cosign signatures + SBOM attached; only the two registry upload jobs failed (binding mismatch). |
| Dependabot | `pypa/gh-action-pypi-publish` 1.14.0 → 1.14.2 PR open (`ci` green, `audit` red — see below). The pinned action's twine rejects Metadata-Version 2.5 wheels; `pypi-token-upload.yml` already uses current twine (PR #145). |

## Owner-only steps (npmjs.com / pypi.org accounts; nobody else can do these)

1. **npm — re-register the Trusted Publisher** for package `aegis-trust`: Settings → Trusted publisher → GitHub Actions → org `nemotek-inc` / repository `aegis-trust` / workflow `release-attestation.yml` (environment empty). 2FA required. Remove the binding that names the previous owner.
   - Alternative if re-registration is not wanted right now: create an npm granular access token (publish rights on `aegis-trust`, bypass-2FA-for-automation) and store it as the repository secret `NPM_TOKEN` (`gh secret set NPM_TOKEN --repo nemotek-inc/aegis-trust`). The machine then runs the fallback (step M1 below).
2. **PyPI — re-register the Trusted Publisher** for project `aegis-trust`: Manage → Publishing → add GitHub publisher owner `nemotek-inc` / repository `aegis-trust` / workflow `release-attestation.yml` / environment empty. Remove the row that names the previous owner.

## Machine steps (aegis-trust lane, after each owner step)

- **M1 — npm 0.10.1**
  - If the binding was re-registered: `gh run rerun 33492829433 --failed --repo nemotek-inc/aegis-trust` → the token-free npm job publishes 0.10.1 **with provenance**. Verify `npm view aegis-trust version` → `0.10.1`, and the provenance badge on npmjs.com.
  - If `NPM_TOKEN` was provided instead: `gh workflow run npm-token-upload.yml -f run_id=33492829433 -f expected_version=0.10.1` → verify `npm view aegis-trust version`. No provenance on this version (same class as the PyPI note in README). Delete `NPM_TOKEN` and `npm-token-upload.yml` once the binding is re-registered.
- **M2 — PyPI back on the attested path** (after owner step 2)
  - Bump `pypa/gh-action-pypi-publish` in `release-attestation.yml` to a version whose twine accepts Metadata-Version 2.5 (the open Dependabot PR to 1.14.2 is the candidate; confirm the `audit` job failure is the pre-existing advisory noise and not this change).
  - Delete the repository secret `PYPI_TOKEN` and remove `pypi-token-upload.yml`.
  - The next release (0.10.2 or 0.11.0) goes through `release-attestation.yml` end-to-end: rerun the verifier gates, cosign, PEP 740 attestations, npm provenance. Do **not** re-upload 0.10.1 to PyPI (immutable).
- **M3 — README**: rewrite the "0.10.1 note" paragraph once both bindings are back (state which versions carry attestations/provenance and which do not).
- **M4 — audit workflow**: the `audit` job is red on `main` since 2026-09-01 independent of these changes; triage it in the same sprint so the release path is green end-to-end.

## What this does not touch

- No SDK code, no version bump (0.10.1 stays 0.10.1). `destination_resource_id` (PR #141) is already in both SDKs and in 0.10.1.
- Downstream consumers pin `aegis-trust[full]==0.10.1` from PyPI and are unaffected by the npm gap.

## Verification checklist (what "done" means)

- [ ] `npm view aegis-trust version` → `0.10.1`
- [ ] npmjs.com and pypi.org both show the `nemotek-inc` / `release-attestation.yml` publisher and no previous-owner row
- [ ] `PYPI_TOKEN` / `NPM_TOKEN` secrets deleted, `pypi-token-upload.yml` / `npm-token-upload.yml` removed
- [ ] `release-attestation.yml` green end-to-end on the next tag (attestations + provenance present)
- [ ] README release note updated
