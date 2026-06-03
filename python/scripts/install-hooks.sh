#!/bin/bash
# Install git hooks for aegis-trust quality gate.
# Idempotent reinstall — safe to run any time the canonical hook in scripts/
# has changed. Warns if the installed hook differs from the canonical copy.
#
# Run once after clone, and again whenever scripts/pre-push changes:
#   bash scripts/install-hooks.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CANONICAL="$REPO_ROOT/scripts/pre-push"
INSTALLED="$REPO_ROOT/.git/hooks/pre-push"
VENV="$REPO_ROOT/.venv"

if [ ! -f "$CANONICAL" ]; then
    echo "error: canonical hook $CANONICAL missing" >&2
    exit 1
fi

if [ -f "$INSTALLED" ] && ! diff -q "$CANONICAL" "$INSTALLED" >/dev/null 2>&1; then
    echo "[install-hooks] installed hook differs from canonical — overwriting"
fi

cp "$CANONICAL" "$INSTALLED"
chmod +x "$INSTALLED"

if [ ! -d "$VENV" ]; then
    cat <<EOF
[install-hooks] WARNING: $VENV not found.
The pre-push hook requires .venv/ at repo root. Create it with:

    python3.12 -m venv .venv
    .venv/bin/pip install -e ".[dev]"

Until then, pushes will fail with a clear error (no silent skip).
EOF
fi

echo "[install-hooks] pre-push installed at $INSTALLED"
