# Releasing aegis-trust

This document describes how aegis-trust releases are prepared, gated, and
published — and, separately, which of those guarantees an adopter can verify
from the outside. It exists so that adopters can evaluate our release
discipline and so that maintainers cut every release the same way.

## Release flow

1. **Version bump + parity.** The release version must be identical across
   the six in-repo sources — `node/package.json`, `node/VERSION`,
   `node/src/index.ts`, `python/pyproject.toml`, `python/VERSION`,
   `python/src/aegis_trust/__init__.py` — and the git tag. Maintainers run
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
   `main` runs the release workflow, whose first job (`resolve-release`,
   GitHub-hosted) creates the `v<version>` tag at the merged commit when all
   six version sources agree and the pin changed in that push; a pushed `v*`
   tag starts the same workflow directly (a manual `workflow_dispatch` is a
   preview run and never uploads). The contract of a push to `main` is
   fail-closed: **green** means either released, or the pin is unchanged and
   its tag exists; **a release** happens only when the pin changed in that
   push and no tag exists for it (a pushed `v*` tag releases only if it
   equals `v<version>` of the six sources at the tagged commit); **anything
   else is red** with the way out
   printed — a changed pin whose tag already exists at another commit, an
   untagged pin the push did not change (an earlier bump that never shipped,
   or a deleted tag), or a push whose range cannot be read (force-push). An
   existing tag is never moved. Recovery is a re-run of the bump merge's own
   workflow run (its pushed range is preserved) — after a red
   classification, first merge a new version bump or push / delete the tag
   as the run's message says: if the release failed after the tag exists,
   the first job resumes and both registry uploads skip a version that is
   already published; if the first job itself failed before the tag
   existed, the re-run creates it. Either way the release runs in the
   `release-attestation` workflow itself — it has no `workflow_call` entry,
   so the registries' Trusted Publisher bindings see that filename as the
   publishing identity; `pull_request_target` is never used in release
   workflows. The self-hosted release runner's trust boundary is repository
   write access (any ref that starts the workflow runs the workflow version
   stored at that ref), which is why `main` and `v*` tags are governed by
   repository rulesets rather than by the workflow itself. npm uploads are
   serialised across runs (one running and one queued; a third release
   arriving while two are in flight has its queued upload cancelled by
   GitHub's one-running-one-pending rule and is re-run within the one-day
   artifact retention), and `latest` never moves
   backwards: a stable version published while a higher one already exists
   lands under the `previous` dist-tag, and the job stops rather than guess
   when the registry's version list cannot be read. After the tag, the workflow runs its own in-repo
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

- Version parity mismatch across the six in-repo version sources, the tag,
  or the live registries (the release workflow refuses to tag a bump whose
  sources disagree).
- The maintainer-side readiness verifier reporting an open release-class gap
  (internal, see step 2).
- The CI-side `productization-gate` job or any release workflow safety
  invariant failing after the tag.

`SECURITY.md` describes how to report issues in a published release.
