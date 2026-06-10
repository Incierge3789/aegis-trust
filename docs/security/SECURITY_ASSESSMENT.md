# Security Assessment — aegis-trust

- **Assessment date:** 2026-06-10
- **Executor:** sprint S002 executor agent (Claude Code), recorded in
  `~/agent-ops/beads/aegis-trust/sprints/sprint_002.md`
- **Scope:** dependency supply chain (Python + Node), secrets hygiene
  (full git history), CI/CD pipeline controls, access-control implementation
  inventory
- **Method:** every claim below is backed by a tool run with the exact
  command, tool version, and exit code. Raw logs are committed under
  [`evidence/`](evidence/). No claim in this document is hand-asserted.

## 1. Results summary

| Layer | Tool (version) | Command | Before | After | Exit (after) |
|---|---|---|---|---|---|
| Python deps | pip-audit 2.10.0 | `python/.venv/bin/pip-audit --strict` | 2 vulnerabilities | **0** | 0 |
| Node deps | npm audit (npm 10.9.4, node 22.22.1) | `npm audit --audit-level=low` (in `node/`) | 4 vulnerabilities | **0** | 0 |
| Secrets (git history) | gitleaks 8.30.1 | `gitleaks detect --config .gitleaks.toml --no-banner --redact` | 0 leaks (131 commits) | 0 leaks | 0 |

Raw logs: [`evidence/s002-pip-audit-before.log`](evidence/s002-pip-audit-before.log),
[`evidence/s002-pip-audit-after.log`](evidence/s002-pip-audit-after.log),
[`evidence/s002-npm-audit-before.log`](evidence/s002-npm-audit-before.log),
[`evidence/s002-npm-audit-after.log`](evidence/s002-npm-audit-after.log),
[`evidence/s002-gitleaks.log`](evidence/s002-gitleaks.log).

## 2. Findings and dispositions

| ID | Severity | Component | Finding | Disposition |
|---|---|---|---|---|
| S002-DEP-1 | medium | python (transitive: idna 3.11 via httpx/requests/anyio) | CVE-2026-45409, fix ≥3.15 | **Fixed** — dev env upgraded to idna 3.18; consumers resolve fresh (no upper pin in `pyproject.toml`); CI `audit.yml` re-resolves and fails closed on regression |
| S002-DEP-2 | medium | python tooling (pip 26.1.1) | PYSEC-2026-196, fix 26.1.2 | **Fixed** — pip 26.1.2; `audit.yml` runs `pip install --upgrade pip` before auditing |
| S002-DEP-3 | **critical** | node devDependency (vitest ≤3.2.5, direct) | GHSA-5xrq-8626-4rwp — Vitest UI server arbitrary file read/execute | **Fixed** — vitest `^1.6.0` → `^4.1.8` (`node/package.json` + lockfile); full suite green after upgrade: 17 files / 222 tests passed |
| S002-DEP-4 | moderate ×3 | node transitive (esbuild GHSA-67mh-4wv8-2f99, vite GHSA-4w7w-66w2-5vf9, vite-node) | dev-server request/path-traversal class issues, all reachable only through the vitest chain | **Fixed** — eliminated by the vitest 4.1.8 upgrade (audit after: 0) |
| S002-CI-1 | high (process) | CI/CD | `SECURITY.md` claimed "dependency audit on every CI build" but `ci.yml` ran none — control existed in the M4-era workflow (`python/CHANGELOG.md` M4 entry) and was lost in a refactor | **Fixed** — [`.github/workflows/audit.yml`](../../.github/workflows/audit.yml) added (push/PR + weekly schedule, fail-closed, SHA-pinned); `SECURITY.md` wording aligned to the verifiable control |
| S002-CI-2 | medium (process) | CI/CD | A second workflow file could silently reopen the supply-chain surface the S018 adversarial tests close for `ci.yml` only | **Fixed** — `python/tests/adversarial/test_redteam_S002_audit_workflow.py` (9 tests) enforces the same invariants on `audit.yml`: no `pull_request_target`, branch restrictions, `permissions: contents: read` only, no `id-token`, no secrets, 40-char SHA pins, no `\|\| true` / `continue-on-error`, aggregator present |

## 3. Access-control implementation inventory (NIST 800-171 AC substance)

The repository implements access control in product code; this section is the
auditable index of where (verifier note: src-layout — implementation lives
under `python/src/aegis_trust/`):

| Mechanism | Implementation | Verifying tests |
|---|---|---|
| Purpose-based policy gate | `python/src/aegis_trust/config.py` `get_purpose_policy()`; consumed in `shield.py` policy sync | `python/tests/test_shield_full.py`, `python/tests/test_plugin.py` |
| Authoritative principal = JWT subject (server-side), never client-asserted | `python/src/aegis_trust/client.py` (`/check-access` contract, CSR-03) | `python/tests/test_check_access_enforcement.py`, `python/tests/test_client_boundary.py` |
| Fail-closed multi-scope deny (no silent purpose-level widening) | `python/src/aegis_trust/client.py` `authorize`/`aauthorize` (Review finding B) | `python/tests/test_check_access_enforcement.py`, `python/tests/adversarial/test_redteam_S018_scope_bypass.py` |
| Field-level minimum disclosure | `@shield` filtering in `python/src/aegis_trust/shield.py`; conversion failures fail closed (`_ConversionFailed` sentinel, S018 D1) | `python/tests/test_clear_sensitive.py`, `python/tests/adversarial/test_redteam_S018_exception_leak.py` |
| Token lifecycle | token exchange/rotation via generated gateway client (`_generated/.../api/auth/`), rotation helper in `shield.py` | `python/tests/test_token_rotation.py` |
| Transport lock | `verify_ssl` production lock in `client.py` | `python/tests/test_verify_ssl_prod_lock.py` |

## 4. Delta vs prior assessment (S017)

S017 (recorded in `python/CHANGELOG.md`: "Security Sprint S017: systematic
OWASP Top 10 + STRIDE coverage audit of v0.4–v0.6.4… CRITICAL=0, HIGH=0")
was a manual code-review pass. This S002 pass adds:

1. machine-verified dependency layer (pip-audit/npm audit, before/after logs);
2. machine-verified secrets layer over full history (gitleaks, 131 commits);
3. restoration of the CI dependency-audit control lost since the M4-era
   workflow, now mechanically protected against regression (S002-CI-2);
4. this committed, evidence-linked assessment format itself.

New code-level findings this pass: none (no product-code vulnerabilities
identified; all findings were dependency- or process-level).

## 5. Accepted risks (with owner and review deadline)

| ID | Risk | Why accepted now | Review by |
|---|---|---|---|
| S002-AR-1 | `audit-gate` is not yet a required status check in branch protection (merges can land with a failing audit until the operator adds it) | Branch-protection changes are an operator (repo-admin) action outside agent authority; workflow + weekly schedule already surface findings | S003 (next security-family sprint) |
| S002-AR-2 | Node/TypeScript sources are outside the org-level ship-readiness AC verifier glob patterns (`.rs`/`.py` only) | Verifier-side limitation, not a repo defect; node parity is covered in-repo by tests and `version-parity.yml` | S003 |
| S002-AR-3 | `python/.venv` fixes (idna/pip) are dev-machine-local state, not committed artifacts | The package declares no vulnerable pin (`httpx>=0.23,<1.0`); CI `audit.yml` resolves fresh on every run and fails closed, covering both consumers and CI | continuous (audit.yml) |

## 6. Maintenance rule

This document is regenerated only from real tool runs (command + version +
exit code + committed raw log). Hand-written claims without a matching
evidence file are prohibited — see `docs/security/README.md`.
