#!/usr/bin/env bash
# ci-matrix.sh — Local CI matrix runner for aegis-trust
#
# Runs the same checks GitHub Actions would run, across all supported Python
# versions, using uv-managed interpreters. Use this when GitHub Actions is
# unavailable or as a fast local pre-flight before pushing.
#
# Aegis AO-004 (audit completeness): every step's exit code is checked
# individually. No pipes mask failures. No false "ALL PASSED".
#
# Usage:
#   ./scripts/ci-matrix.sh                       # all versions
#   PYTHON_VERSIONS="3.12" ./scripts/ci-matrix.sh  # single version

set -euo pipefail

PYTHON_VERSIONS="${PYTHON_VERSIONS:-3.10 3.11 3.12 3.13}"

# T-006c-1b 2026-05-21: in the canonical aegis-trust monorepo, "Python
# package root" is python/ (not the git toplevel which is the monorepo
# root containing python/ + node/). Use script-relative path so the
# script works regardless of cwd, with fallback to git-toplevel for
# aegis-trust-flat-layout compat.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [[ ! -f "${REPO_ROOT}/pyproject.toml" ]]; then
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "ERROR: pyproject.toml not found at ${SCRIPT_DIR}/.. and not in a git repo" >&2
    exit 1
  }
fi
cd "$REPO_ROOT"

command -v uv >/dev/null 2>&1 || {
  echo "ERROR: uv not installed. See https://github.com/astral-sh/uv" >&2
  exit 1
}

VERSION="unknown"
if [[ -f VERSION ]]; then
  VERSION=$(cat VERSION)
elif [[ -f pyproject.toml ]]; then
  VERSION=$(grep '^version' pyproject.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  CI Matrix — Python versions: ${PYTHON_VERSIONS}"
echo "  Version: ${VERSION}"
echo "═══════════════════════════════════════════════════════════════"

FAIL_COUNT=0
PASS_COUNT=0
RESULTS=()

for v in ${PYTHON_VERSIONS}; do
  echo ""
  echo "─── Python ${v} ─────────────────────────────────────────"

  VENV_DIR=".ci-venv-${v}"
  STEP_FAILED=0

  uv venv --python "${v}" "${VENV_DIR}" --quiet || {
    echo "[${v}] FAIL: uv venv creation failed"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("[${v}] FAIL (venv)")
    continue
  }

  VENV_PYTHON="${VENV_DIR}/bin/python"

  echo "[${v}] installing dependencies..."
  if ! uv pip install --python "${VENV_PYTHON}" -e ".[dev]" --quiet 2>&1; then
    echo "[${v}] FAIL: pip install failed"
    STEP_FAILED=1
  fi

  if [[ ${STEP_FAILED} -eq 0 ]]; then
    echo "[${v}] pytest:"
    if ! AEGIS_MODE=lite "${VENV_PYTHON}" -m pytest tests/ -q --tb=line -m "not integration" 2>&1; then
      echo "[${v}] FAIL: pytest failed"
      STEP_FAILED=1
    fi
  fi

  if [[ ${STEP_FAILED} -eq 0 ]]; then
    echo "[${v}] ruff check:"
    if ! "${VENV_PYTHON}" -m ruff check src/ tests/ 2>&1; then
      echo "[${v}] FAIL: ruff check failed"
      STEP_FAILED=1
    fi
  fi

  if [[ ${STEP_FAILED} -eq 0 ]]; then
    echo "[${v}] ruff format --check:"
    if ! "${VENV_PYTHON}" -m ruff format --check src/ tests/ 2>&1; then
      echo "[${v}] FAIL: ruff format check failed"
      STEP_FAILED=1
    fi
  fi

  rm -rf "${VENV_DIR}"

  if [[ ${STEP_FAILED} -eq 0 ]]; then
    echo "[${v}] PASS"
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS+=("[${v}] PASS")
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("[${v}] FAIL")
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  CI Matrix Results:"
for r in "${RESULTS[@]}"; do
  echo "    ${r}"
done
echo ""
if [[ ${FAIL_COUNT} -gt 0 ]]; then
  echo "  CI Matrix: ${FAIL_COUNT} FAILED, ${PASS_COUNT} passed"
  echo "═══════════════════════════════════════════════════════════════"
  exit 1
else
  echo "  CI Matrix: ALL ${PASS_COUNT} PASSED"
  echo "═══════════════════════════════════════════════════════════════"
  exit 0
fi
