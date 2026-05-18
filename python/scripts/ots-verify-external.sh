#!/usr/bin/env bash
# ots-verify-external.sh — Multi-source independent OTS verification
#
# NOT "trustless" — this is a practical alternative when no local Bitcoin
# full node is available. Queries two independent block explorers and
# cross-checks that the block hash at the proof's height matches.
#
# Usage:
#   ./scripts/ots-verify-external.sh path/to/file.ots
#   ./scripts/ots-verify-external.sh path/to/file       # appends .ots automatically
#
# Exit codes:
#   0 — PASS: both sources agree on block hash
#   1 — FAIL: mismatch, missing tool, bad file, or network error

set -euo pipefail
IFS=$'\n\t'

# ─── Constants ─────────────────────────────────────────────────────
CURL_TIMEOUT=10
BLOCKSTREAM_API="https://blockstream.info/api"
MEMPOOL_API="https://mempool.space/api"

# ─── Helpers ───────────────────────────────────────────────────────
die() {
  echo "FAIL: $1" >&2
  exit 1
}

info() {
  echo "INFO: $1"
}

# ─── Preconditions ─────────────────────────────────────────────────
command -v ots >/dev/null 2>&1 || die "ots (opentimestamps-client) is not installed"
command -v curl >/dev/null 2>&1 || die "curl is not installed"

# ─── Resolve .ots file path ───────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <file.ots | file>" >&2
  exit 1
fi

OTS_FILE="$1"

# If the argument doesn't end in .ots, append it
if [[ "${OTS_FILE}" != *.ots ]]; then
  OTS_FILE="${OTS_FILE}.ots"
fi

[[ -f "${OTS_FILE}" ]] || die "file not found: ${OTS_FILE}"

# ─── Extract block height from ots info ────────────────────────────
info "Running ots info on ${OTS_FILE}"
OTS_INFO="$(ots info "${OTS_FILE}" 2>&1)" || die "ots info failed: ${OTS_INFO}"

# ots info output contains lines like "verify BitcoinBlockHeaderAttestation(N)"
# or "Bitcoin block height N" depending on version. Try both patterns.
BLOCK_HEIGHT=""
# Extract block height using sed (macOS BSD grep does not support -P/PCRE)
BLOCK_HEIGHT="$(echo "${OTS_INFO}" | sed -n 's/.*BitcoinBlockHeaderAttestation(\([0-9]*\)).*/\1/p' | head -1)" || true

if [[ -z "${BLOCK_HEIGHT}" ]]; then
  BLOCK_HEIGHT="$(echo "${OTS_INFO}" | sed -n 's/.*Bitcoin block height \([0-9]*\).*/\1/p' | head -1)" || true
fi

if [[ -z "${BLOCK_HEIGHT}" ]]; then
  BLOCK_HEIGHT="$(echo "${OTS_INFO}" | sed -n 's/.*block \([0-9]*\).*/\1/p' | head -1)" || true
fi

if [[ -z "${BLOCK_HEIGHT}" ]]; then
  die "could not extract block height from ots info output. The proof may be pending (not yet confirmed on-chain). ots info output was:
${OTS_INFO}"
fi

info "Extracted Bitcoin block height: ${BLOCK_HEIGHT}"

# ─── Query Blockstream API ────────────────────────────────────────
info "Querying Blockstream API for block height ${BLOCK_HEIGHT}..."
BLOCKSTREAM_HASH="$(curl -sfL --max-time "${CURL_TIMEOUT}" \
  "${BLOCKSTREAM_API}/block-height/${BLOCK_HEIGHT}" 2>&1)" || \
  die "Blockstream API request failed (timeout or HTTP error)"

if [[ -z "${BLOCKSTREAM_HASH}" ]]; then
  die "Blockstream API returned empty response for height ${BLOCK_HEIGHT}"
fi

# Validate it looks like a block hash (64 hex chars)
if [[ ! "${BLOCKSTREAM_HASH}" =~ ^[0-9a-f]{64}$ ]]; then
  die "Blockstream API returned invalid block hash: ${BLOCKSTREAM_HASH}"
fi

info "Blockstream block hash: ${BLOCKSTREAM_HASH}"

# ─── Query Mempool.space API ──────────────────────────────────────
info "Querying Mempool.space API for block height ${BLOCK_HEIGHT}..."
MEMPOOL_HASH="$(curl -sfL --max-time "${CURL_TIMEOUT}" \
  "${MEMPOOL_API}/block-height/${BLOCK_HEIGHT}" 2>&1)" || \
  die "Mempool.space API request failed (timeout or HTTP error)"

if [[ -z "${MEMPOOL_HASH}" ]]; then
  die "Mempool.space API returned empty response for height ${BLOCK_HEIGHT}"
fi

# Validate it looks like a block hash (64 hex chars)
if [[ ! "${MEMPOOL_HASH}" =~ ^[0-9a-f]{64}$ ]]; then
  die "Mempool.space API returned invalid block hash: ${MEMPOOL_HASH}"
fi

info "Mempool.space block hash: ${MEMPOOL_HASH}"

# ─── Compare ──────────────────────────────────────────────────────
if [[ "${BLOCKSTREAM_HASH}" == "${MEMPOOL_HASH}" ]]; then
  echo ""
  echo "PASS: Block hashes match across 2 independent sources"
  echo "  Block height : ${BLOCK_HEIGHT}"
  echo "  Block hash   : ${BLOCKSTREAM_HASH}"
  echo "  Sources      : blockstream.info, mempool.space"
  echo ""
  echo "NOTE: This is NOT a trustless verification. For full trustless"
  echo "      verification, use: ots verify <file> (requires a local"
  echo "      Bitcoin full node or a trusted calendar server)."
  exit 0
else
  echo ""
  die "Block hash MISMATCH between sources!
  Blockstream : ${BLOCKSTREAM_HASH}
  Mempool     : ${MEMPOOL_HASH}
  Block height: ${BLOCK_HEIGHT}
  This could indicate a chain reorganization or API inconsistency.
  Do NOT trust this timestamp until resolved."
fi
