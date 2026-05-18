"""T-509: CI/CD malicious branch push scenario.

AI Red Team S018 — analysis of CI/CD attack vectors.
These tests verify CI configuration properties, not runtime behavior.
"""

import yaml


# ── Attack 1: Verify CI only triggers on push ────────────────────


def test_ci_only_triggers_on_push():
    """CI must only trigger on push events, not pull_request.
    Fork PRs on self-hosted runners = arbitrary code execution.
    """
    with open(".github/workflows/ci.yml") as f:
        ci = yaml.safe_load(f)

    triggers = ci.get("on", ci.get(True, {}))
    assert "pull_request" not in triggers, (
        "CI must NOT trigger on pull_request (self-hosted runner attack vector)"
    )
    assert "push" in triggers


# ── Attack 2: Verify branch pattern restrictions ─────────────────


def test_ci_branch_restrictions():
    """CI must only run on controlled branches, not arbitrary patterns."""
    with open(".github/workflows/ci.yml") as f:
        ci = yaml.safe_load(f)

    triggers = ci.get("on", ci.get(True, {}))
    push_config = triggers.get("push", {})
    branches = push_config.get("branches", [])

    # Must have branch restrictions
    assert len(branches) > 0, "CI push trigger must have branch restrictions"

    # Must not have wildcard that matches everything
    for b in branches:
        assert b != "*", "CI must not trigger on all branches"
        assert b != "**", "CI must not trigger on all branches"


# ── Attack 3: Verify minimal permissions ─────────────────────────


def test_ci_minimal_permissions():
    """CI must use minimal permissions (contents: read)."""
    with open(".github/workflows/ci.yml") as f:
        ci = yaml.safe_load(f)

    perms = ci.get("permissions", {})
    assert perms.get("contents") == "read", (
        "CI permissions must be contents: read (minimal)"
    )

    # Must not have write permissions
    for key, value in perms.items():
        assert value != "write", f"CI must not have {key}: write permission"


# ── Attack 4: Verify checkout uses pinned SHA ────────────────────


def test_ci_checkout_pinned_sha():
    """actions/checkout must use a pinned SHA, not a mutable tag."""
    with open(".github/workflows/ci.yml") as f:
        content = f.read()

    # Look for checkout action usage
    ci = yaml.safe_load(content)
    for job_name, job in ci.get("jobs", {}).items():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if "actions/checkout" in uses:
                # Must use SHA, not just tag
                assert "@" in uses, f"checkout in {job_name} must pin a version"
                ref = uses.split("@")[1]
                # SHA is 40 hex chars; mutable tags like 'v4' are NOT acceptable
                assert len(ref) >= 40, (
                    f"checkout in {job_name} must use full SHA pin, not tag: {uses}"
                )


# ── Attack 5: Verify fork trust boundary check ──────────────────


def test_ci_fork_trust_boundary():
    """CI must check for fork execution and refuse to run."""
    with open(".github/workflows/ci.yml") as f:
        content = f.read()

    assert "repository.fork" in content, "CI must check github.event.repository.fork"
    assert "Refusing to run on fork" in content or "fork" in content.lower()


# ── Attack 6: Verify no secret exposure in env ───────────────────


def test_ci_no_secrets_in_env():
    """CI must not expose secrets in environment variables."""
    with open(".github/workflows/ci.yml") as f:
        content = f.read()

    # Check for common secret exposure patterns
    assert "secrets." not in content.lower() or "secrets.GITHUB_TOKEN" in content, (
        "CI should not reference custom secrets (self-hosted runner uses local creds)"
    )


# ── Attack 7: Verify no expression injection ─────────────────────


def test_ci_no_expression_injection():
    """CI must not use untrusted input in run: steps without sanitization.
    github.event.pull_request.title, github.event.issue.title, etc.
    are common injection vectors.
    """
    with open(".github/workflows/ci.yml") as f:
        content = f.read()

    dangerous_contexts = [
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.comment.body",
        "github.event.head_commit.message",
    ]

    for ctx in dangerous_contexts:
        assert ctx not in content, (
            f"CI uses untrusted context '{ctx}' — potential expression injection"
        )
