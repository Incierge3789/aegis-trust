#!/usr/bin/env bash
# S020 checklist I-3/I-4/E-4 acceptance test (T-810).
#
# Verifies that `pip install aegis-trust` followed by the README quickstart
# completes in under 300 seconds (5 minutes) on a clean virtualenv, and that
# field-level filtering produces the documented output.
#
# Usage:
#   scripts/test_5min_quickstart.sh                # uses local source tree
#   AEGIS_QUICKSTART_SOURCE=pypi scripts/test_5min_quickstart.sh   # tests PROD PyPI
#
# Aegis 米軍規格: skip = fail.

set -euo pipefail

DEADLINE_SECONDS=300
SOURCE="${AEGIS_QUICKSTART_SOURCE:-local}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d -t aegis-quickstart-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

START_TS=$(date +%s)
echo "[T-810] start ($SOURCE source) — workdir: $WORK_DIR"

cd "$WORK_DIR"

# Pick a Python 3 interpreter that supports venv. uv-managed Python works too.
if command -v python3.13 >/dev/null 2>&1; then
    PY=python3.13
elif command -v python3.12 >/dev/null 2>&1; then
    PY=python3.12
elif command -v python3.11 >/dev/null 2>&1; then
    PY=python3.11
elif command -v python3.10 >/dev/null 2>&1; then
    PY=python3.10
else
    PY=python3
fi
echo "[T-810] interpreter: $($PY --version)"

"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

pip install --quiet --upgrade pip

case "$SOURCE" in
    local)
        echo "[T-810] installing from local source: $REPO_ROOT"
        pip install --quiet "$REPO_ROOT"
        ;;
    pypi)
        echo "[T-810] installing aegis-trust from PROD PyPI"
        pip install --quiet aegis-trust
        ;;
    *)
        echo "[T-810] FAIL: unknown AEGIS_QUICKSTART_SOURCE '$SOURCE' (use 'local' or 'pypi')" >&2
        exit 1
        ;;
esac

# README documented quickstart, exact form (single python -c command).
ACTUAL=$(python -c "
from aegis_trust import shield
f = shield(purpose='support', scope=['name'])(lambda: {'name': 'Aria', 'ssn': '123-45-6789'})
print(f())
")

EXPECTED="{'name': 'Aria'}"
if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "[T-810] FAIL: quickstart output mismatch" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 1
fi

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))

if [ "$ELAPSED" -gt "$DEADLINE_SECONDS" ]; then
    echo "[T-810] FAIL: elapsed ${ELAPSED}s exceeds ${DEADLINE_SECONDS}s deadline" >&2
    exit 1
fi

echo "[T-810] PASS: quickstart completed in ${ELAPSED}s (deadline ${DEADLINE_SECONDS}s)"
echo "[T-810] output: $ACTUAL"
