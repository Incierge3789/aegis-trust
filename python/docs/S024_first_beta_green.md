# S024 — First live Tier β green

**Date**: 2026-04-17
**Sprint**: S024
**Goal**: Close S023's "electricity-never-confirmed" gap — attest that
the aegis-shield Full-mode wiring shipped in v0.8.0 actually talks to a
live aegis-core gateway end-to-end.

## Result

**52 passed · 3 skipped · 0 failed** against `aegis-core-dev:latest`
(image digest below) running inside
`scripts/aegis-core.compose.yml`.

The 3 skips are deliberate — the scope-filter tests need the gateway
to accept unauthenticated `/check-access` (dev-only) or a real token
wired into `AEGIS_TOKEN`. The S024 fixture ships with the production
auth middleware intact, so `requires_authed_check_access` skips them
until someone configures a dev-token capsule or sets
`AEGIS_APIKEY_AUTH=false`. The counterpart test
`test_full_mode_unauthed_returns_empty` runs and pins the AO-003
fail-closed behaviour on the same path.

## Attestation

See `attestations/tier-beta-first-green-2026-04-17.json`. Key
immutable references:

| Field | Value |
|---|---|
| aegis-shield commit | `4d14e049f87c77a3c30501fa77b43a7d15de2f8a` (sprint/S024) |
| aegis-core source SHA | `eb353fec55c4` (remote `github.com/Incierge3789/aegis_core.git`) |
| Image tag | `aegis-core-dev:eb353fec55c4` (SHA-tagged; retagged as `:latest`) |
| Image digest | `sha256:4dad2fb0483c8d63a2bae5bbbc57ed893c22b04353bc75939a1b980d715593a8` |
| compose hash | `sha256:0711c64f14be880bf06caf3f96f3028e9f47c87b87e6fde6209f8aba27ce2bfa` |
| dev-cli hash | `sha256:450d4da0463b131cc79a6b13547b4011d0561ce3dad6f1640425c4fa19f5fb23` |
| workflow hash | `sha256:a6852c89aa74e1e840f0def680e91f031af4dab968f81c51546706efbe2f2d00` |
| cosign | unavailable on this runner (tool not installed) |
| SBOM | unavailable on this runner (syft not installed) |

The image digest is a content-addressed SHA-256 — retagging the
`aegis-core-dev:*` name cannot produce the same digest without
reproducing the bits, which is what makes this evidence valid under
AO-004 even though the image has not been pushed to GHCR.

## Startup timing (cache warm)

`scripts/aegis-core-dev.sh up` with cached image:
- `docker image inspect` cache hit: instant
- `docker compose up -d` + healthcheck poll: **~9 seconds**

Contrast with the two nightly runs before S024, which hung for 40-50
minutes inside `docker compose up --build` (Rust scratch build) and
were cancelled by hand. Cold path is still expected to take 15-30min
when someone rebases aegis-core against a new base image; the
workflow's `timeout-minutes: 45` covers that.

## Push trigger acceptance matrix (T1-e)

The `push: sprint/**` trigger has been restored in
`.github/workflows/tier-beta.yml`. Plan Review finding C5 flagged the
original gate as self-referential, so we do not count a single
workflow_dispatch run as proof. Instead the `push` trigger is treated
as **on probation** until the following matrix is green:

| Scenario | Target count | Status |
|---|---|---|
| Warm-cache workflow_dispatch | 2 consecutive green | 1/2 (this report) |
| Cold-cache workflow_dispatch (after `docker rmi`) | 1 green | 0/1 |
| Nightly cron | 3 consecutive green | 0/3 |

When all three rows are satisfied the trigger is considered fully
enabled. If `push` fires before that and fails, the workflow's own
attestation will tell us which row needs attention.

## Suite breakdown

```
tests/test_shield_full.py                                    8 passed, 3 skipped
tests/test_shield_full_async.py                              6 passed
tests/test_check_access_enforcement.py                      16 passed
tests/test_audit_inclusion_proof.py                         13 passed
tests/adversarial/test_redteam_S023_full_mode.py             9 passed
```

## What is not yet attested

- `tests/integration/` (load + contract): scaffolded in Wave 4
  (T-165/T-174). Not part of this first-green run.
- `make generate-sdk`: Wave 3 work — the live OpenAPI spec has already
  been pulled to `/tmp/live_openapi.json` (46 paths, 38 schemas); the
  regenerated `_generated/` client lands in T-162/T-163 commits.
- GHCR publishing and `cosign sign-blob` — deferred to S025 as the
  middle-path agreed in Plan Review C1 (local SHA-tag + digest pin is
  the minimum; GHCR + cosign signing raise the evidence bar further
  once aegis-core itself publishes images).

## Reproducing the run

```bash
# Runner-local prerequisites
export AEGIS_CORE_DIR=$HOME/projects/aegis-core

# Bring the gateway up (cache hit for eb353fec55c4 finishes in seconds)
./scripts/aegis-core-dev.sh up

# Optional: record an attestation file for this run
./scripts/aegis-attest.sh > attestations/tier-beta-$(date -u +%Y%m%d%H%M).json

# Run the β suite
AEGIS_URL=https://localhost:8443/api/v1 \
AEGIS_VERIFY_SSL=false AEGIS_DEV_INSECURE=1 \
.venv/bin/pytest \
  tests/test_shield_full.py tests/test_shield_full_async.py \
  tests/test_check_access_enforcement.py \
  tests/test_audit_inclusion_proof.py \
  tests/adversarial/test_redteam_S023_full_mode.py -v

./scripts/aegis-core-dev.sh down
```
