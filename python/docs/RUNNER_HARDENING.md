# Runner Hardening: Self-Hosted GitHub Actions

aegis-shield runs CI on a self-hosted runner (Apple Silicon, macOS) owned by the canonical maintainer.
This document records the actual threat model and defenses — not aspirational ones.

## Threat Model

### What the runner is

A single macOS ARM64 machine registered to `Incierge3789/aegis-shield` with labels
`[self-hosted, macOS, ARM64, aegis-shield]`. It runs all CI jobs defined in
`.github/workflows/ci.yml`.

### What fork PRs cannot do

The workflow triggers on `push` only — not `pull_request`:

```yaml
on:
  push:
    branches: [main, "sprint/**", "hotfix/**", "task/**"]
```

Fork PRs never trigger CI. Period. The fork detection check in the workflow
(`github.event.repository.fork == "true"`) is therefore **dead defense** — it can
never fire because the trigger condition (`push` to the canonical repo) already
excludes forks. It exists as belt-and-suspenders documentation of intent, not as an
active security layer. Do not count on it.

### The real threat

A malicious push to the canonical repo by someone with write access. This is the
only way to trigger the self-hosted runner. Attack scenarios:

1. **Compromised maintainer credentials** — attacker pushes to `sprint/**` branch
2. **Collaborator gone rogue** — someone with push access injects workflow changes
3. **PAT leak** — stolen Personal Access Token used to push directly

### Defense layers (in order of activation)

| Layer | Mechanism | What it stops |
|-------|-----------|---------------|
| 1 | **CODEOWNERS** (`.github/CODEOWNERS`) | Every change requires review by `@Incierge3789`. Workflow files (`.github/workflows/`) are explicitly owned. |
| 2 | **Branch protection: required status checks** | 5 jobs (test-lint x4 Python versions + security audit) must pass before merge to `main`. |
| 3 | **Branch protection: `enforce_admins=true`** | Even admins cannot bypass review requirements or status checks. |
| 4 | **Runner label scoping** | Labels `[self-hosted, macOS, ARM64, aegis-shield]` prevent other repos from scheduling jobs on this runner. Only workflows in `aegis-shield` that request all four labels will match. |

### What is NOT defended

- Direct push to `sprint/**` branches bypasses PR review (branch protection only
  covers `main`). The runner will execute whatever is in the workflow file. This is
  accepted because only the maintainer has push access today.
- If GitHub itself is compromised, all bets are off. Out of scope.

## Credential Rotation Plan

### GitHub PAT

- **Minimum scope**: `repo` + `workflow` (needed for `gh api` calls in
  `launchd/runner-monitor.sh` and runner registration)
- **Rotation cadence**: every 90 days
- **How to rotate**:
  ```bash
  gh auth refresh
  gh auth status  # verify new expiry
  ```
- Store in macOS Keychain via `gh auth login`, never in plaintext files

### Runner registration token

- Auto-expires after 1 hour (GitHub's policy)
- If the runner goes offline and can't reconnect, re-register:
  ```bash
  cd ~/actions-runner
  ./config.sh remove
  # Get new token from repo Settings > Actions > Runners
  ./config.sh --url https://github.com/Incierge3789/aegis-shield \
    --token <NEW_TOKEN> \
    --labels self-hosted,macOS,ARM64,aegis-shield
  ```

### SSH keys

- Runner machine SSH keys are separate from any deployment keys
- Do not reuse the same key for GitHub SSH access and runner registration
- Rotate SSH keys on the same 90-day cadence as PATs

## Secret Exposure Mitigation

### GitHub-side

- GitHub Actions automatically masks any value stored in repository Secrets when it
  appears in log output
- Workflow YAML must never `echo` or `printenv` secrets. The current `ci.yml` does not
  reference any repository secrets (it only uses `AEGIS_MODE: lite`)

### Local verification

- Use `act` to dry-run the workflow locally before pushing. This validates that the
  workflow YAML doesn't accidentally expose environment variables:
  ```bash
  ./scripts/ci-act.sh --job test-lint
  ```
  See `scripts/ci-act.sh` for details.

### Runner diagnostic logs

- The GitHub Actions runner writes diagnostic logs to `_diag/` inside the runner
  directory
- These logs may contain token fragments or environment details
- Exclude `_diag/` from backups and cloud sync (iCloud, Dropbox, etc.)
- The runner's `work/` directory should also be excluded — it contains checked-out
  repo contents during job execution

### CI venv cleanup

- Each job in `ci.yml` has a `Cleanup venv` step (`if: always()`) that removes
  `.ci-venv` / `.ci-venv-audit` after every run, preventing credential or artifact
  accumulation between jobs

## Monitoring

### `launchd/runner-monitor.sh`

- Runs every **5 minutes** (`StartInterval: 300` in `launchd/com.aegis.runner-monitor.plist`)
- Calls `gh api repos/Incierge3789/aegis-shield/actions/runners` to check runner status
- If zero runners are online, sends a macOS notification via `osascript`
- Logs to `~/.aegis/logs/runner-monitor.log`

### `launchd/watchdog.sh`

- Runs every **15 minutes** (`StartInterval: 900` in `launchd/com.aegis.watchdog.plist`)
- Monitors `com.aegis.runner-monitor` and `com.aegis.ots-watcher` launchd services
- If a service is not loaded, attempts to bootstrap it from `~/Library/LaunchAgents/`
- Sends macOS notification on service restart
- Logs to `~/.aegis/logs/watchdog.log`

### Log locations

| Log | Path |
|-----|------|
| runner-monitor | `~/.aegis/logs/runner-monitor.log` |
| watchdog | `~/.aegis/logs/watchdog.log` |
| launchd stdout/stderr | `/tmp/com.aegis.runner-monitor.{stdout,stderr}.log` |
| launchd stdout/stderr | `/tmp/com.aegis.watchdog.{stdout,stderr}.log` |
| GitHub runner diagnostics | `~/actions-runner/_diag/` |

### What is NOT monitored

- There is no alerting beyond macOS notification center. If the machine is unattended
  (lid closed, user logged out), notifications are missed. Consider adding a webhook
  or email alert for production use.
- Runner resource exhaustion (disk full, memory pressure) is not checked.
