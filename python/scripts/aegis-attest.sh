#!/usr/bin/env bash
# T-171 (S024): produce a JSON attestation for a Tier β run.
#
# AO-004 demands that the β attestation point at immutable artifacts
# (Plan Review C1 + CU-ST1). Tag names like aegis-core-dev:<sha> can be
# retagged, so the attestation records the image's sha256 digest, the
# aegis-core source SHA, and hashes of the compose/config fixture
# files. Cosign/SBOM are emitted when available — the digest by itself
# already closes the non-repudiation gap for local runs.
#
# The JSON body is rendered through python's json module instead of
# raw printf to keep the file parseable even when cosign/syft emit
# shell-unsafe characters in their error output (Phase 5 Cursor
# review, P2 Repudiation/Tampering).
#
# Usage:
#   AEGIS_CORE_DIR=$HOME/projects/aegis-core ./scripts/aegis-attest.sh \
#       > attestations/tier-beta-<run_id>.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -z "${AEGIS_CORE_DIR:-}" ]]; then
  echo "error: AEGIS_CORE_DIR is not set" >&2
  exit 2
fi

core_sha="$("$SCRIPT_DIR/aegis-core-dev.sh" sha)"
# Resolve the digest from the SHA-pinned tag so the attestation cannot
# pair a new source commit with a stale :latest retag. If that tag is
# absent the attestation fails rather than emit weak evidence.
image_digest="$(docker image inspect --format='{{.Id}}' \
  "aegis-core-dev:${core_sha}" 2>/dev/null || true)"
if [[ -z "$image_digest" ]]; then
  echo "error: aegis-core-dev:${core_sha} not found locally; run scripts/aegis-core-dev.sh up first" >&2
  exit 3
fi

core_remote="$(git -C "$AEGIS_CORE_DIR" remote get-url origin)"
core_dirty="$(git -C "$AEGIS_CORE_DIR" status --porcelain | wc -l | tr -d ' ')"
shield_sha="$(git -C "$REPO_ROOT" rev-parse HEAD)"
shield_dirty="$(git -C "$REPO_ROOT" status --porcelain | wc -l | tr -d ' ')"

hash_file() {
  if [[ -f "$1" ]]; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "missing"
  fi
}

compose_hash="$(hash_file "$SCRIPT_DIR/aegis-core.compose.yml")"
dev_cli_hash="$(hash_file "$SCRIPT_DIR/aegis-core-dev.sh")"
workflow_hash="$(hash_file "$REPO_ROOT/.github/workflows/tier-beta.yml")"

cosign_sig="unavailable"
if command -v cosign >/dev/null 2>&1 && [[ -n "$image_digest" ]]; then
  if out="$(COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
      --output-signature /tmp/aegis-attest.sig \
      --output-certificate /tmp/aegis-attest.cert \
      <(printf '%s' "$image_digest") 2>&1)"; then
    cosign_sig="$(shasum -a 256 /tmp/aegis-attest.sig | awk '{print $1}')"
  else
    cosign_sig="failed: ${out##*$'\n'}"
  fi
fi

sbom_summary="unavailable"
if command -v syft >/dev/null 2>&1; then
  sbom_path="/tmp/aegis-sbom-${core_sha}.spdx.json"
  # Pin syft against the SHA-tagged image so the SBOM is scoped to the
  # same build the attestation claims, not whatever :latest points at.
  if syft "aegis-core-dev:${core_sha}" -o spdx-json="$sbom_path" >/dev/null 2>&1; then
    sbom_summary="$(shasum -a 256 "$sbom_path" | awk '{print $1}')"
  fi
fi

export CORE_SHA="$core_sha"
export IMAGE_DIGEST="$image_digest"
export CORE_REMOTE="$core_remote"
export CORE_DIRTY="$core_dirty"
export SHIELD_SHA="$shield_sha"
export SHIELD_DIRTY="$shield_dirty"
export COMPOSE_HASH="$compose_hash"
export DEV_CLI_HASH="$dev_cli_hash"
export WORKFLOW_HASH="$workflow_hash"
export COSIGN_SIG="$cosign_sig"
export SBOM_SUMMARY="$sbom_summary"

python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

out = {
    "schema_version": 1,
    "attested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "aegis_shield": {
        "commit": os.environ["SHIELD_SHA"],
        "working_tree_dirty_files": int(os.environ["SHIELD_DIRTY"]),
    },
    "aegis_core": {
        "remote": os.environ["CORE_REMOTE"],
        "commit_short": os.environ["CORE_SHA"],
        "working_tree_dirty_files": int(os.environ["CORE_DIRTY"]),
    },
    "image": {
        "tag_latest": "aegis-core-dev:latest",
        "tag_sha": f"aegis-core-dev:{os.environ['CORE_SHA']}",
        "digest": os.environ["IMAGE_DIGEST"],
    },
    "fixture_hashes": {
        "compose": f"sha256:{os.environ['COMPOSE_HASH']}",
        "dev_cli": f"sha256:{os.environ['DEV_CLI_HASH']}",
        "workflow": f"sha256:{os.environ['WORKFLOW_HASH']}",
    },
    "cosign": os.environ["COSIGN_SIG"],
    "sbom": os.environ["SBOM_SUMMARY"],
}
print(json.dumps(out, indent=2))
PY
