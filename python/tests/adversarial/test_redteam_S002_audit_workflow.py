"""S002: audit.yml workflow safety invariants.

The dependency-audit workflow added in sprint S002 must carry the same
supply-chain protections that `test_redteam_S018_ci_attack.py` enforces for
`ci.yml`. A second workflow file with weaker invariants would silently
reopen the attack surface the S018 tests closed (new-workflow regression
vector flagged in the S002 plan cross-review).

Checked invariants (mirroring ci.yml):
  1. no `pull_request_target` in any executable region
  2. push/pull_request triggers restricted to controlled branches
  3. top-level permissions: contents: read, and no `id-token: write`
  4. all `uses:` references pinned to a full 40-char commit SHA
  6. fail-closed: no `|| true`, no `continue-on-error` (a finding must
     fail the job — S017 doctrine)
"""

import re
from pathlib import Path

import yaml

# parents[0] = adversarial/  parents[1] = tests/  parents[2] = python/  parents[3] = repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
AUDIT_YML = REPO_ROOT / ".github" / "workflows" / "audit.yml"


def _load_audit() -> dict:
    return yaml.safe_load(AUDIT_YML.read_text())


def _read_audit_non_comment() -> str:
    """audit.yml with `#`-comment regions stripped per line (the header
    documents forbidden strings; raw-text checks would false-trigger)."""
    return "\n".join(
        line.split("#", 1)[0] for line in AUDIT_YML.read_text().splitlines()
    )


def _triggers(wf: dict) -> dict:
    """`on:` block, accounting for PyYAML 1.1 `True`-key normalization."""
    return wf.get("on", wf.get(True, {}))


def test_audit_workflow_exists():
    assert AUDIT_YML.exists(), "audit.yml must exist (MA: dependency audit control)"


def test_audit_no_pull_request_target_anywhere():
    assert "pull_request_target" not in _read_audit_non_comment(), (
        "Executable region of audit workflow must not mention pull_request_target"
    )


def test_audit_branch_restrictions():
    wf = _load_audit()
    triggers = _triggers(wf)
    for trig in ("push", "pull_request"):
        branches = (triggers.get(trig) or {}).get("branches", [])
        assert len(branches) > 0, f"audit {trig} trigger must restrict branches"
        for b in branches:
            assert b not in ("*", "**"), "audit must not trigger on all branches"


def test_audit_minimal_permissions():
    wf = _load_audit()
    perms = wf.get("permissions", {})
    assert perms == {"contents": "read"}, (
        "audit.yml must declare exactly `permissions: contents: read`"
    )


def test_audit_no_id_token_write():
    assert "id-token" not in _read_audit_non_comment(), (
        "audit.yml must not request id-token (OIDC/signing) permissions"
    )


def test_audit_no_secrets_in_env():
    assert "secrets." not in _read_audit_non_comment(), (
        "audit.yml is read-only CI and must not reference secrets"
    )


def test_audit_actions_pinned_to_sha():
    text = _read_audit_non_comment()
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses, "audit.yml must use at least one action (checkout)"
    for ref in uses:
        _, _, pin = ref.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", pin), (
            f"action {ref} must be pinned to a full 40-char commit SHA"
        )


def test_audit_fail_closed():
    text = _read_audit_non_comment()
    assert "|| true" not in text, "audit jobs must not swallow failures (|| true)"
    assert "continue-on-error" not in text, (
        "audit jobs must not set continue-on-error"
    )


def test_audit_gate_aggregator_exists():
    wf = _load_audit()
    jobs = wf.get("jobs", {})
    assert "audit-gate" in jobs, "audit.yml must keep the audit-gate aggregator job"
    needs = jobs["audit-gate"].get("needs", [])
    assert set(needs) == {"pip-audit", "npm-audit"}, (
        "audit-gate must aggregate pip-audit and npm-audit"
    )
