# Releasing aegis-trust

This document describes how aegis-trust releases are prepared, gated, and
published — and, separately, which of those guarantees an adopter can verify
from the outside. It exists so that adopters can evaluate our release
discipline and so that maintainers cut every release the same way.

## Release flow

1. **Version bump + parity.** The release version must be identical across
   `node/package.json`, `node/VERSION`, `node/src/index.ts`,
   `python/pyproject.toml`, and the git tag. Maintainers run
   `npm --prefix node run parity` locally; the scheduled `version-parity`
   workflow cross-checks the same set against the live npm and PyPI registries
   daily and notifies maintainers on drift.
2. **Internal readiness verification (maintainer-side, pre-tag).** Before a
   release tag is created, maintainers run an internal, fail-closed
   ship-readiness verifier covering security-review and
   productization-review cadence over the recent engineering window, among
   other criteria. This step is part of our internal process and is **not
   externally auditable from this repository** — adopters should rely on the
   externally verifiable layers listed below rather than on this statement.
3. **Version bump merge → tag.** Merging the version-bump pull request to
   `main` runs `release-on-main.yml`, which creates the `v<version>` tag at
   the merged commit and calls the release workflow with it; a pushed `v*`
   tag starts the same workflow directly (a manual `workflow_dispatch` is a
   preview run and never uploads). Either way the tag push (or call) starts the
   `release-attestation` workflow; `pull_request_target` is never used in
   release workflows. After the tag, the workflow runs its own in-repo
   quality gate job (`productization-gate`) in CI — a second, CI-side layer
   independent of the maintainer-side step above.
4. **Sign + publish.** With all third-party actions pinned to 40-char commit
   SHAs:
   - CycloneDX SBOMs for the Node and Python SDKs are generated and signed
     with Sigstore cosign **keyless signatures** (`cosign sign-blob`,
     recorded in the public Rekor transparency log), then attached to the
     GitHub Release. Signing runs on a designated self-hosted release runner.
   - The SDK artifacts themselves (npm `.tgz`, Python wheel and sdist) are
     cosign-signed the same way and attached to the GitHub Release.
   - npm and PyPI publishes use **Trusted Publisher OIDC** (token exchange
     on GitHub-hosted runners; no long-lived registry tokens exist in this
     repository's secrets for publishing). The signing path and the publish
     path run on separate runner classes by design: no cosign identity or
     signing operation exists on the GitHub-hosted publish jobs.

## What an adopter can verify externally

- **Version parity**: compare the npm/PyPI artifact versions, the git tag,
  and the version sources above; the `version-parity` workflow definition is
  in this repository.
- **Artifact signatures**: verify the cosign signatures of the SBOMs and SDK
  artifacts attached to each GitHub Release with `cosign verify-blob` against
  the Rekor public log.
- **Workflow safety properties**: the release workflow source in
  `.github/workflows/release-attestation.yml` — trigger restrictions, action
  SHA pinning, runner separation, and the OIDC publish path — is itself
  public and reviewable.

## What blocks a release

- Version parity mismatch across the five version sources or the live
  registries.
- The maintainer-side readiness verifier reporting an open release-class gap
  (internal, see step 2).
- The CI-side `productization-gate` job or any release workflow safety
  invariant failing after the tag.

`SECURITY.md` describes how to report issues in a published release.
