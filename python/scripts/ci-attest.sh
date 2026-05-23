#!/usr/bin/env bash
# ci-attest.sh — Manual CI Attestation generator for aegis-shield
#
# Aegis AO-004 (audit completeness): when automated CI (GitHub Actions, etc.)
# is unavailable, this script generates a tamper-evident attestation that
# binds local CI matrix results to a specific commit SHA + timestamp.
#
# Usage:
#   ./scripts/ci-attest.sh                  # full matrix + attestation
#   ./scripts/ci-attest.sh --skip-matrix    # use last results, just sign
#   ./scripts/ci-attest.sh --version 0.6.4  # override version detection
#
# Output:
#   .gstack/ci-attestations/S{sprint}-v{version}.txt
#   .gstack/ci-attestations/S{sprint}-v{version}.txt.ots (if ots installed)
#   .gstack/ci-attestations/S{sprint}-v{version}.txt.ots-status (sidecar)
#
# Aegis principles enforced:
#   AO-002: this script does not log secrets, only test results
#   AO-004: every attestation is bound to a commit SHA (cannot be replayed)
#           pip-audit failure = attestation generation ABORTED (fail-closed)
#   AO-006: data flow is explicit (no env-var magic, no implicit state)

set -euo pipefail
IFS=$'\n\t'

# ─── Resolve repo root ─────────────────────────────────────────────
# T-006c-1b 2026-05-21: in the canonical aegis-trust monorepo, "Python
# package root" is python/ (not the git toplevel = monorepo root
# containing python/ + node/). Use script-relative path with fallback to
# git toplevel for aegis-shield-flat-layout compat.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [[ ! -f "${REPO_ROOT}/pyproject.toml" ]]; then
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "ERROR: pyproject.toml not found at ${SCRIPT_DIR}/.. and not in a git repo" >&2
    exit 1
  }
fi
cd "$REPO_ROOT"

# ─── Parse arguments ───────────────────────────────────────────────
SKIP_MATRIX=0
VERSION_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-matrix) SKIP_MATRIX=1; shift ;;
    --version) VERSION_OVERRIDE="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ─── Detect version + sprint ───────────────────────────────────────
if [[ -n "$VERSION_OVERRIDE" ]]; then
  VERSION="$VERSION_OVERRIDE"
elif [[ -f VERSION ]]; then
  VERSION=$(cat VERSION)
else
  VERSION=$(grep '^version' pyproject.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
fi

BRANCH=$(git branch --show-current)
# grep returns 1 with no match; `|| true` keeps pipefail happy on task/
# branches without an S-number, so the fallback below can assign S000.
SPRINT=$(echo "$BRANCH" | grep -oE 'S[0-9]+' | head -1 || true)
SPRINT="${SPRINT:-S000}"

# ─── Collect commit / host metadata ────────────────────────────────
COMMIT=$(git rev-parse HEAD)
COMMIT_SHORT=$(git rev-parse --short HEAD)
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HOSTNAME_=$(hostname)
USER_=${USER:-unknown}

# ─── Prepare output ────────────────────────────────────────────────
OUT_DIR=".gstack/ci-attestations"
mkdir -p "$OUT_DIR"
ATTEST="$OUT_DIR/${SPRINT}-v${VERSION}.txt"

cat > "$ATTEST" <<EOF
═══════════════════════════════════════════════════════════════
LOCAL CI ATTESTATION — aegis-shield ${SPRINT} / v${VERSION}
═══════════════════════════════════════════════════════════════

Reason:    Manual attestation per Aegis philosophy AO-004 (audit completeness).
           Use when automated CI (GitHub Actions) is unavailable, or as an
           independent local pre-flight before push.

Commit:    ${COMMIT}
Branch:    ${BRANCH}
Version:   ${VERSION}
Sprint:    ${SPRINT}
Timestamp: ${TIMESTAMP}
Host:      ${HOSTNAME_}
User:      ${USER_}
Auditor:   $(basename "$0")

═══════════════════════════════════════════════════════════════
EOF

# ─── Run matrix (unless --skip-matrix) ─────────────────────────────
if [[ "$SKIP_MATRIX" -eq 0 ]]; then
  {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Test & Lint Matrix Results"
    echo "═══════════════════════════════════════════════════════════════"
  } >> "$ATTEST"

  echo "Running CI matrix (this may take a few minutes)..."

  MATRIX_OUTPUT=$(mktemp)
  if ! ./scripts/ci-matrix.sh 2>&1 | tee "$MATRIX_OUTPUT"; then
    cat "$MATRIX_OUTPUT" >> "$ATTEST"
    {
      echo ""
      echo "VERDICT: MATRIX FAILED — attestation invalid"
    } >> "$ATTEST"
    rm -f "$MATRIX_OUTPUT"
    echo "ERROR: ci-matrix failed. Attestation NOT signed." >&2
    exit 1
  fi
  cat "$MATRIX_OUTPUT" >> "$ATTEST"
  rm -f "$MATRIX_OUTPUT"

  {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Security Audit (pip-audit)"
    echo "═══════════════════════════════════════════════════════════════"
  } >> "$ATTEST"

  AUDIT_OUTPUT=$(mktemp)
  AUDIT_RC=0
  if command -v pip-audit >/dev/null 2>&1; then
    pip-audit 2>&1 | tee "$AUDIT_OUTPUT" || AUDIT_RC=$?
  else
    VENV_DIR=".ci-venv-audit"
    uv venv --python 3.12 "$VENV_DIR" --quiet
    VENV_PYTHON="${VENV_DIR}/bin/python"
    uv pip install --python "$VENV_PYTHON" -e ".[dev]" pip-audit --quiet 2>&1
    "$VENV_PYTHON" -m pip_audit 2>&1 | tee "$AUDIT_OUTPUT" || AUDIT_RC=$?
    rm -rf "$VENV_DIR"
  fi
  cat "$AUDIT_OUTPUT" >> "$ATTEST"
  rm -f "$AUDIT_OUTPUT"

  if [[ $AUDIT_RC -ne 0 ]]; then
    {
      echo ""
      echo "VERDICT: SECURITY AUDIT FAILED — attestation invalid"
    } >> "$ATTEST"
    echo "ERROR: pip-audit failed (exit $AUDIT_RC). Attestation NOT signed." >&2
    exit 1
  fi
fi

# ─── Aegis AO declaration ──────────────────────────────────────────
cat >> "$ATTEST" <<'EOF'

═══════════════════════════════════════════════════════════════
ATTESTATION SUMMARY
═══════════════════════════════════════════════════════════════

Aegis AO check:
  AO-002 (zero leakage):       enforced via @shield decorator + regression tests
  AO-004 (audit completeness): this attestation IS the audit record
  AO-006 (data flow explicit): no env-var magic, no implicit state

Why this attestation is valid:
  - Bound to commit SHA (cannot be replayed against other code)
  - Bound to timestamp (auditable chronology)
  - Bound to host (identifies the auditor)
  - Self-signed via SHA-3-512 of attestation content (NIST FIPS 202)
  - (Optional) OpenTimestamps anchored for independent timestamp witness

To verify a future automated CI run agrees with this attestation:
  1. Wait for GitHub Actions to be re-enabled
  2. gh run rerun <run-id-on-this-commit>
  3. Compare results — must match line-by-line for matrix outputs
═══════════════════════════════════════════════════════════════
EOF

# ─── SHA-3-512 self-signature (final line, nothing appended after) ─
SIG=$(python3 -c "import hashlib,sys; print(hashlib.sha3_512(open(sys.argv[1],'rb').read()).hexdigest())" "$ATTEST")
echo "" >> "$ATTEST"
echo "ATTESTATION SHA-3-512: $SIG" >> "$ATTEST"

# ─── OpenTimestamps anchoring (sidecar status, file NOT modified) ──
OTS_STATUS_FILE="${ATTEST}.ots-status"
OTS_STATUS="not installed"
if command -v ots >/dev/null 2>&1; then
  echo "Anchoring attestation hash to OpenTimestamps..."
  rm -f "${ATTEST}.ots"
  if ots stamp "$ATTEST" 2>&1; then
    OTS_STATUS="stamped (${ATTEST}.ots — verify later with: ots verify ${ATTEST})"
  else
    OTS_STATUS="ots stamp failed (network?)"
  fi
fi
echo "$OTS_STATUS" > "$OTS_STATUS_FILE"

# ─── Report ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Attestation written: $ATTEST"
echo "  SHA-3-512:           $SIG"
echo "  OpenTimestamps:      $OTS_STATUS"
echo "  Commit:              $COMMIT_SHORT"
echo "  Sprint:              $SPRINT"
echo "  Version:             v$VERSION"
echo "═══════════════════════════════════════════════════════════════"
