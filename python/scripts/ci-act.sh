#!/usr/bin/env bash
# ci-act.sh — Run the GitHub Actions workflow YAML locally via `act`
#
# Aegis AO-004: validates the workflow file ITSELF (not just the test commands)
# without depending on GitHub Actions billing or network. Uses Docker.
#
# Why this matters:
#   `make ci-matrix` runs the same TESTS as GitHub Actions, but it does NOT
#   validate that .github/workflows/ci.yml is correct. A broken workflow YAML
#   would silently produce no CI runs. `act` exercises the actual workflow
#   parser and runner.
#
# Usage:
#   ./scripts/ci-act.sh                # run all jobs
#   ./scripts/ci-act.sh --job test-lint  # specific job
#
# Requires:
#   - act (https://github.com/nektos/act)  — `brew install act`
#   - Docker Desktop (or compatible container runtime)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repository" >&2
  exit 1
}
cd "$REPO_ROOT"

# ─── Pre-flight ────────────────────────────────────────────────────
if ! command -v act >/dev/null 2>&1; then
  cat <<'EOF'
ERROR: act is not installed.

  Install:
    macOS:    brew install act
    Linux:    curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

  Then re-run this script.

  Alternative if you can't install act:
    make ci-matrix    # validates the test commands but not the workflow file
EOF
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running. Start Docker Desktop and re-run." >&2
  exit 1
fi

if [[ ! -f .github/workflows/ci.yml ]]; then
  echo "ERROR: .github/workflows/ci.yml not found." >&2
  exit 1
fi

# ─── Run ───────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo "  Running .github/workflows/ci.yml via act"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Note: act uses Docker images that approximate GitHub's runners."
echo "      Some edge cases may differ — for full fidelity, use GitHub Actions."
echo ""

# Use medium-size image for python availability without huge download
act "$@" \
  --pull=false \
  --workflows .github/workflows/ci.yml \
  --platform ubuntu-latest=catthehacker/ubuntu:act-latest

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  act run complete"
echo "═══════════════════════════════════════════════════════════════"
