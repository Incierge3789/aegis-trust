# Releasing aegis-trust

This document describes how aegis-trust releases are prepared, gated, and
published. It exists so that adopters can verify our release discipline, and so
that maintainers cut every release the same way.

## Release flow

1. **Version bump + parity.** The release version must be identical across
   `node/package.json`, `node/VERSION`, `node/src/index.ts`,
   `python/pyproject.toml`, and the git tag. Run `npm --prefix node run parity`
   locally; the scheduled `version-parity` workflow cross-checks the same set
   against the live npm and PyPI registries daily and notifies maintainers on
   drift.
2. **Readiness verification (fail-closed).** Before a release tag is created,
   the maintainers run an internal ship-readiness verifier. The verifier is
   fail-closed: any applicable gap blocks the tag. Among other criteria it
   enforces a release cadence requirement — the recent engineering review
   window must include both recurring security review activity (security
   review / adversarial red-team exercises) and recurring productization
   review activity (packaging, metadata, quickstart, claims verification). If
   the recent window lacks either, the release is held until the corresponding
   review work completes. Release tags are never created with the verifier
   reporting an open release-class gap.
3. **Tag push.** A `v*` tag (manual `workflow_dispatch` is the only other
   trigger) starts the `release-attestation` workflow. `pull_request_target`
   is never used in release workflows.
4. **Attestation + publish.** The release workflow produces, on a designated
   self-hosted release runner, with all third-party actions pinned to 40-char
   commit SHAs:
   - CycloneDX SBOMs for the Node and Python SDKs, attached to the GitHub
     Release;
   - Sigstore cosign keyless signatures and GitHub native build provenance
     attestations (SLSA Level 3 equivalent, as wired in
     `.github/workflows/release-attestation.yml`) with the source-snapshot SHA
     recorded in the attestation predicate;
   - npm publish via npm Trusted Publisher OIDC and PyPI publish via PyPI
     Trusted Publisher OIDC — no long-lived registry tokens exist in this
     repository's secrets for publishing.

## Verifying a release

- Compare the npm/PyPI artifact versions against the git tag and the SBOM
  attached to the GitHub Release.
- Verify the cosign signatures and provenance attestations against the GitHub
  Release artifacts.
- `SECURITY.md` describes how to report issues in a published release.

## What blocks a release

- Version parity mismatch across the five version sources or the live
  registries.
- An open release-class gap in the fail-closed readiness verifier, including
  the security-review and productization-review cadence requirements above.
- Any release workflow safety invariant in
  `.github/workflows/release-attestation.yml` failing (runner class, action
  pinning, OIDC publish path).
