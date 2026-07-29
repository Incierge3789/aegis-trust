"""Machine pins for `.github/dependabot.yml`.

Cross-review (cursor, 2026-07-29) flagged this as [P1] on the merged change:
two dependency-hygiene defects were fixed in PR #126 and nothing pinned either
fix, so both could be reverted and CI would stay green.

What is pinned here, and why each one is load-bearing:

1. `package-ecosystem: uv` for /python, NOT `pip`. The source of truth is
   `python/uv.lock` plus `uv sync`. The pip ecosystem edits pyproject
   constraints without reliably relocking, which reproduces exactly the failure
   this file exists to prevent: a pyproject change landing while uv.lock stays
   stale. That happened once already (PR #117 pinned ruff and left the lock at
   the old version).

2. `dependency-type: development` on every group. `patterns: "*"` does NOT mean
   "dev only" — it means every entry in the ecosystem. Without the scope, a
   runtime dependency gets swept into a pull request labelled
   `dev-dependencies`, which is the review-dilution shape a supply-chain
   attacker wants.

3. `--locked` on both `uv sync` invocations. Without it uv silently re-resolves
   and rewrites the lockfile when pyproject has drifted, so CI tests a
   dependency set nobody committed. The audit workflow already had a test
   asserting this (`test_redteam_S002_audit_workflow.py`); ci.yml did not.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
DEPENDABOT = REPO / ".github" / "dependabot.yml"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
AUDIT_YML = REPO / ".github" / "workflows" / "audit.yml"


def _config() -> dict:
    return yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))


def test_dependabot_config_exists_and_is_v2() -> None:
    assert DEPENDABOT.is_file(), f"{DEPENDABOT} is missing"
    assert _config()["version"] == 2


def test_scan_is_non_vacuous() -> None:
    """A guard that iterates an empty update list must fail, not pass."""
    updates = _config()["updates"]
    assert len(updates) >= 3, (
        f"expected npm + uv + github-actions ecosystems, found {len(updates)}"
    )


def test_python_ecosystem_is_uv_not_pip() -> None:
    updates = _config()["updates"]
    py = [u for u in updates if str(u.get("directory", "")).rstrip("/") == "/python"]
    assert py, "no dependabot entry for /python"
    for entry in py:
        assert entry["package-ecosystem"] == "uv", (
            "the /python project is uv-locked; `pip` updates pyproject without "
            "reliably relocking uv.lock, which is how PR #117 shipped a pinned "
            "ruff against a stale lock"
        )


def test_every_group_is_scoped_to_development() -> None:
    for entry in _config()["updates"]:
        for name, group in (entry.get("groups") or {}).items():
            assert group.get("dependency-type") == "development", (
                f"{entry['package-ecosystem']}{entry.get('directory')} group "
                f"{name!r} has no `dependency-type: development`. "
                '`patterns: "*"` alone matches runtime dependencies too, so a '
                "runtime bump would land in a PR labelled dev-dependencies."
            )


@pytest.mark.parametrize("workflow", [CI_YML, AUDIT_YML], ids=["ci", "audit"])
def test_uv_sync_is_locked(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    if "uv sync" not in text:
        pytest.skip(f"{workflow.name} does not run uv sync")
    assert "uv sync --extra dev --locked" in text, (
        f"{workflow.name}: `uv sync` must pass --locked. Without it uv "
        "re-resolves a drifted lockfile instead of failing, and CI reports on a "
        "dependency set that was never committed."
    )
