#!/usr/bin/env bash
# promote_to_ga.sh — @aegis_trust/sdk v0.9.0-rc* → v0.9.0 GA promotion
#
# Prerequisites (sprint_002 hard gate, NOT automatically verified by this script —
# operator must literal confirm before running):
#   1. 5 external oracle survey: top_1_pct_readability + dx_friction_audit verifier PASS
#      with 4/5 acceptance (productization_doctrine_complete label)
#   2. D-952 5 architectural P0 hardening verified (sprint_002 hardening sprint close)
#   3. ≥ 30 day monitoring window since rc1 publish (memory feedback_distribution_*.md)
#   4. ≥ 3 external dev usage signals (npm DL trend / GitHub issue / community feedback)
#   5. F-014 v3 15-checklist 15/15 PASS literal
#
# What this script does (idempotent, dry-run by default):
#   1. Verify rc1 still latest on npm (catch accidental re-publish)
#   2. dist-tag promotion: latest=0.9.0 (replacing 0.8.1)
#   3. dist-tag retire: rc (no longer needed for production users)
#   4. Tag v0.9.0 in git + push → release.yml GA fire
#   5. README + AGENTS.md + CHANGELOG: STABILITY_LEVEL "preview" → "stable" + GA note
#
# Usage:
#   bash scripts/promote_to_ga.sh --dry-run         # preview, no changes (default)
#   bash scripts/promote_to_ga.sh --confirm-prereqs # actually promote (operator confirms 1-5)
#
# AO-check: Gate-1~6 considerations
# - AO-001/002: dist-tag change is npm registry-side, not Aegis trust boundary
# - AO-003: tag promotion event must be recorded in decision_log (D-XXX)
# - AO-006: no secrets, OTP via authenticator app required for npm dist-tag promote

set -euo pipefail

MODE="${1:-}"
[ "$MODE" != "--dry-run" ] && [ "$MODE" != "--confirm-prereqs" ] && {
    echo "Usage: $0 [--dry-run | --confirm-prereqs]"
    echo ""
    sed -n '2,30p' "$0"
    exit 2
}

DRY_RUN=1
[ "$MODE" = "--confirm-prereqs" ] && DRY_RUN=0

cd "$(dirname "$0")/.."  # cwd = sdk/node-trust

echo "=== Step 1: verify rc1 status ==="
npm view @aegis_trust/sdk@0.9.0-rc1 version 2>&1 | head -2 || { echo "ERROR: 0.9.0-rc1 not published" >&2; exit 2; }
echo ""

echo "=== Step 2: dist-tag promotion preview ==="
echo "  current dist-tags:"
npm dist-tag ls @aegis_trust/sdk 2>&1 | sed 's/^/    /'
echo "  planned after promotion:"
echo "    latest: 0.9.0"
echo "    (rc tag retired)"
echo ""

if [ "$DRY_RUN" = "1" ]; then
    echo "=== DRY RUN — no changes made ==="
    echo "Operator: confirm 5 prereqs (see top of script comments), then re-run with --confirm-prereqs"
    exit 0
fi

echo "=== CONFIRM-PREREQS mode — operator has attested 1-5 hard gate ==="
echo "Press Ctrl-C within 10 seconds to abort..."
sleep 10
echo ""

echo "=== Step 3: bump source v0.9.0-rc1 → v0.9.0 ==="
sed -i.bak 's/"version": "0.9.0-rc1"/"version": "0.9.0"/' package.json
echo "0.9.0" > VERSION
sed -i.bak 's/STABILITY_LEVEL: "preview" | "stable" | "deprecated" = "preview"/STABILITY_LEVEL: "preview" | "stable" | "deprecated" = "stable"/' src/index.ts
echo "  package.json, VERSION, src/index.ts updated"
echo ""

echo "=== Step 4: build + test ==="
npm run build
npm test
echo ""

echo "=== Step 5: git commit + tag + push ==="
cd ..
git add sdk/node-trust/{package.json,VERSION,src/index.ts}
git commit -m "[GA] @aegis_trust/sdk v0.9.0 GA promotion — 5 oracle PASS + D-952 + 30d monitoring complete"
git tag -a "v0.9.0" -m "@aegis_trust/sdk v0.9.0 GA — internal-ops sprint_002 close + 30d monitoring"
git push origin "$(git branch --show-current)"
git push origin v0.9.0
echo ""

echo "=== Step 6: npm publish v0.9.0 + dist-tag promote ==="
echo "  Requires OTP from authenticator app (recovery codes for breakglass only)"
echo "  Run manually after Giri authorization:"
echo "    cd sdk/node-trust && npm publish --tag latest --access public --otp=<TOTP>"
echo "    npm dist-tag rm @aegis_trust/sdk rc"
echo ""

echo "=== Step 7: post-promotion verify ==="
echo "  npm view @aegis_trust/sdk version  # expect 0.9.0"
echo "  npm dist-tag ls @aegis_trust/sdk    # expect latest=0.9.0 only"
echo ""

echo "[GA promotion completed in script — manual npm publish + dist-tag step pending operator]"
