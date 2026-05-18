# Release Process — aegis-shield

This document describes the release process for aegis-shield, including the **Manual CI Attestation** path used when automated CI is unavailable.

## Aegis principles

Releases enforce these AO principles:

- **AO-004 (audit completeness)**: every release is bound to an immutable, verifiable audit record (CI run or manual attestation)
- **AO-006 (data flow explicitness)**: every step of the release process is scriptable and reproducible — no implicit knowledge

## Release types

| Type | When | Version bump | CI requirement |
|---|---|---|---|
| **Patch** | Bug fix, security fix, doc fix | `0.6.X+1` | CI green OR manual attestation |
| **Minor** | New feature, backwards-compatible | `0.X+1.0` | CI green required |
| **Major** | Breaking change | `X+1.0.0` | CI green + Acceptance Sprint |

## Standard release flow (automated CI available)

1. **Branch from main**: `git checkout -b sprint/SXXX` or `hotfix/<description>`
2. **Implement changes** (follow Aegis Sprint phases)
3. **Bump version**: edit `src/aegis/__init__.py` and `pyproject.toml`
4. **Update CHANGELOG.md**: add entry under new version header
5. **Run local checks**: `make ci-matrix && make audit`
6. **Push + create PR**: `git push -u origin <branch> && gh pr create`
7. **Wait for GitHub Actions**: all checks must pass (Test & Lint, Security Audit)
8. **Code review**: cross-review (codex + cursor-agent) for security-sensitive changes
9. **Merge**: `gh pr merge --squash --delete-branch`
10. **Tag**: `git tag -a "v$(cat src/aegis/__init__.py | grep __version__ | cut -d'"' -f2)" -m "Release ..." && git push origin "v..."`
11. **(Future) Publish to PyPI**: `python -m build && twine upload dist/*` (after Acceptance Sprint)

## Manual attestation flow (automated CI unavailable)

When GitHub Actions cannot run (billing failure, outage, fork without CI permissions), use this path. **It is not a shortcut** — it is the Aegis-aligned alternative that preserves AO-004 by using a different audit substrate.

### When to use

| Situation | Use manual attestation? |
|---|---|
| GitHub Actions billing failure | ✅ yes |
| GitHub Actions outage (~hours) | ✅ yes |
| Fork without CI access | ✅ yes |
| You're impatient and don't want to wait for CI | ❌ no — wait for CI |
| Testing in a sandboxed environment | ❌ no — use `make ci-matrix` directly |
| Production release | ⚠️ only if automated CI is genuinely unavailable; document the reason in the PR |

### Steps

1. **Run the matrix**: `make ci-matrix`
   - Runs pytest + ruff across Python 3.10/3.11/3.12/3.13 via uv
   - Must exit 0 on every version

2. **Run the audit**: `make audit`
   - `pip-audit` against current dependencies
   - Must report no vulnerabilities (or only documented exceptions)

3. **Generate the attestation**: `make ci-attest`
   - Wraps the matrix + audit in `scripts/ci-attest.sh`
   - Writes `.gstack/ci-attestations/SXXX-vX.Y.Z.txt` containing:
     - Commit SHA (full)
     - Branch name
     - Version
     - Sprint ID
     - Timestamp (UTC)
     - Hostname + user (auditor identity)
     - All matrix output (per-version pytest, ruff, audit results)
     - Aegis AO declaration
     - SHA-3-512 self-signature of the attestation content (NIST FIPS 202)
     - OpenTimestamps proof file (`.ots`) if `ots` is installed (independent timestamp witness)

4. **Post the attestation summary to the PR** as a comment:
   ```
   ## Manual CI Attestation (AO-004 audit completeness)

   Reason: <why automated CI is unavailable>

   Local CI Matrix Results: <paste the summary table from the attestation file>
   Security Audit (pip-audit): <result>
   Verdict: CI EQUIVALENT — ALL PASS
   Attestation file: .gstack/ci-attestations/SXXX-vX.Y.Z.txt
   SHA-3-512: <hash from the attestation>
   OpenTimestamps: <stamp status>
   ```

5. **Merge the PR** as in the standard flow.

6. **Tag the release** as in the standard flow.

7. **When automated CI returns**, re-run it on the same commit:
   ```bash
   gh run rerun <run-id>
   ```
   Compare the results to the manual attestation. They must agree. If they disagree, file a failure_log entry — that's a divergence between the local and remote CI environments and must be investigated.

### Why manual attestation is valid (not a hack)

| Property | Manual attestation | Why it satisfies the property |
|---|---|---|
| **Reproducible** | ✅ | uv pins exact Python versions; anyone with the same commit can re-run `make ci-matrix` and get the same result |
| **Independent** | ⚠️ | Single host (the auditor's). Stronger if OpenTimestamps anchoring is used (Bitcoin blockchain as independent witness) |
| **Tamper-evident** | ✅ | SHA-3-512 self-signature (NIST FIPS 202); OpenTimestamps proof anchors to an external chain |
| **Auditable chronology** | ✅ | UTC timestamp recorded inside the attestation, OpenTimestamps timestamp on Bitcoin |
| **Bound to commit** | ✅ | Full commit SHA recorded; cannot be replayed against a different commit |
| **Bound to identity** | ✅ | Hostname + user recorded in the attestation |

The weakest property is **independence** (single host). To strengthen it:

- Run `ots stamp` on the attestation file (if `ots` installed) to anchor it to Bitcoin
- Have a second maintainer run `make ci-matrix` independently and compare

### What manual attestation does NOT replace

- **Code review** (still required — cross-review or human review)
- **Acceptance Sprint** (Aegis Sprint type that decides PyPI publication)
- **Branch protection** on main (required by GIT_RULES §8b for canonical repos)

## Verifying a release

### From git tag

```bash
git fetch --tags
git show v0.6.1                 # show the release commit + tag message
git log --oneline v0.6.0..v0.6.1  # what changed between releases
```

### From CHANGELOG

```bash
grep -A 20 "## \[0.6.1\]" CHANGELOG.md
```

### From manual attestation (if used)

```bash
cat .gstack/ci-attestations/S013-v0.6.1.txt
python3 -c "import hashlib,sys; print(hashlib.sha3_512(open(sys.argv[1],'rb').read()).hexdigest())" .gstack/ci-attestations/S013-v0.6.1.txt  # compare to SHA-3-512 in the file (v0.6.4+; for v0.6.2-0.6.3 use: shasum -a 256)
ots verify .gstack/ci-attestations/S013-v0.6.1.txt.ots  # if OpenTimestamps proof exists
```

## Tooling reference

| Command | Purpose |
|---|---|
| `make ci-matrix` | Run pytest + ruff across all supported Python versions |
| `make ci-attest` | Generate manual CI attestation file |
| `make ci-act` | Run `.github/workflows/ci.yml` locally via `act` (validates the workflow YAML) |
| `make audit` | Run pip-audit against current dependencies |
| `make lint` | Run ruff check + ruff format --check |
| `make format` | Apply ruff format |
| `make test` | Run pytest only |

## Self-hosted runner setup

aegis-shield uses a **self-hosted GitHub Actions runner** to eliminate the
dependency on GitHub Actions billing. The runner runs on the maintainer's
machine and consumes zero GitHub Actions minutes.

### Why self-hosted

- **Cost**: zero. Self-hosted runners are free for both public and private repos.
- **Independence**: works even when GitHub-hosted billing fails (as it did during S013).
- **Speed**: Apple Silicon native, ~1m 44s for the full matrix.
- **Aegis AO-004**: every CI run is bound to the canonical maintainer machine,
  which provides identity binding alongside GitHub's audit log.

### Security model (public repo)

aegis-shield is a **public repo**, so a self-hosted runner has a real attack
surface: a malicious PR from a fork could execute code on the runner machine.

**Mitigations applied**:

1. **Push trigger only.** `.github/workflows/ci.yml` triggers only on `push`,
   never on `pull_request`. PRs from forks are NOT auto-tested. To CI a
   contribution, the maintainer must push it to a branch in this repo first
   (typically by checking it out and pushing under a `task/` branch).
2. **Fork detection guard.** Each job has an explicit step that checks
   `github.event.repository.fork` and exits with error if true. Belt and
   suspenders for AO-001.
3. **Repo-specific labels.** The runner has labels
   `[self-hosted, macOS, ARM64, aegis-shield]` and the workflow `runs-on`
   declaration requires all four. No accidental cross-project execution.
4. **Maintainer machine isolation.** The runner does not run as root and
   has no special capabilities. Standard user account security applies.

### Setup (one-time)

These are the exact steps used to set up the current runner. Replace
`<TOKEN>` with a registration token (next section).

```bash
RUNNER_DIR="$HOME/.github-actions-runner-aegis-shield"
mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

# 1. Get the latest osx-arm64 runner URL
LATEST=$(gh api repos/actions/runner/releases/latest \
  --jq '.assets[] | select(.name | test("osx-arm64.*\\.tar\\.gz$")) | .browser_download_url' \
  | head -1)

# 2. Download
curl -L -o actions-runner.tar.gz "$LATEST"

# 3. Verify SHA-256 (extracted from the release notes)
EXPECTED_SHA=$(gh api repos/actions/runner/releases/latest --jq '.body' \
  | grep -A1 "osx-arm64" | grep -oE '[a-f0-9]{64}' | head -1)
ACTUAL_SHA=$(shasum -a 256 actions-runner.tar.gz | awk '{print $1}')
[ "$EXPECTED_SHA" = "$ACTUAL_SHA" ] || { echo "checksum mismatch"; exit 1; }

# 4. Extract
tar xzf actions-runner.tar.gz

# 5. Get a registration token (requires repo admin)
TOKEN=$(gh api -X POST repos/Incierge3789/aegis-shield/actions/runners/registration-token \
  --jq .token)

# 6. Configure the runner
./config.sh \
  --url https://github.com/Incierge3789/aegis-shield \
  --token "$TOKEN" \
  --name "incierge-mac-aegis-shield" \
  --labels "self-hosted,macOS,ARM64,aegis-shield" \
  --work "_work" \
  --replace \
  --unattended

# 7. Start the runner (foreground)
./run.sh
```

### Persistent runner (optional)

To run the runner as a background service that auto-starts on login:

```bash
cd "$HOME/.github-actions-runner-aegis-shield"
./svc.sh install   # creates a launchd plist
./svc.sh start
./svc.sh status
```

To stop:
```bash
./svc.sh stop
./svc.sh uninstall
```

### Required tools on the runner machine

- `uv` (https://github.com/astral-sh/uv) — installed via Homebrew
- `git`
- A working internet connection (for downloading Python via uv)

### Verifying the runner is online

```bash
gh api repos/Incierge3789/aegis-shield/actions/runners --jq \
  '.runners[] | "\(.name): status=\(.status), busy=\(.busy)"'
```

### Triggering CI

Just push to a branch matching the workflow's `branches` pattern:

```bash
git push origin <branch-name>   # main, sprint/**, hotfix/**, task/**
```

The runner will pick up the job within ~5 seconds.

### Falling back to manual attestation

If the self-hosted runner is offline (e.g., maintainer machine off), use
the manual attestation flow described above (`make ci-attest`). The two
flows are interchangeable for AO-004 purposes — both bind verification to
a specific commit + identity.

## Future work

| Item | Why |
|---|---|
| Sigstore / cosign signing of release artifacts | Independent transparency log for releases |
| GPG-signed git tags | Identity binding for release tags |
| ~~Self-hosted GitHub Actions runner~~ | ✅ Done (S013 hotfix) |
| Reproducible builds (PyPI sdist + wheel) | Anyone can rebuild and verify byte-for-byte |
| Persistent runner via launchd | Auto-start runner on machine boot |
