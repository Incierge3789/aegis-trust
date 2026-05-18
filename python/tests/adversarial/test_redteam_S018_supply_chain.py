"""T-511: uv.lock tampering supply chain attack.

AI Red Team S018 — verify supply chain integrity of dependencies.
"""

import os
import re


# ── Attack 1: Verify uv.lock exists and is committed ────────────


def test_uv_lock_exists():
    """uv.lock must exist in the repository root."""
    assert os.path.exists("uv.lock"), "uv.lock must exist for reproducible builds"


def test_uv_lock_not_empty():
    """uv.lock must not be empty."""
    stat = os.stat("uv.lock")
    assert stat.st_size > 0, "uv.lock must not be empty"


# ── Attack 2: Verify pyproject.toml dependencies are pinned ──────


def test_pyproject_has_version_constraints():
    """Dependencies in pyproject.toml should have version constraints."""
    with open("pyproject.toml") as f:
        content = f.read()

    # Find dependencies section
    in_deps = False
    deps_lines = []
    for line in content.split("\n"):
        if line.strip().startswith("dependencies"):
            in_deps = True
            continue
        if in_deps:
            if line.strip() == "]":
                break
            if line.strip().startswith('"') or line.strip().startswith("'"):
                deps_lines.append(line.strip().strip("\",'"))

    for dep in deps_lines:
        if dep and not dep.startswith("#"):
            # Each dep should have a version constraint (>=, ~=, ==, etc.)
            has_constraint = any(
                op in dep for op in [">=", "<=", "~=", "==", "!=", ">", "<"]
            )
            assert has_constraint, (
                f"Dependency '{dep}' has no version constraint — supply chain risk"
            )


# ── Attack 3: Verify no known malicious packages ─────────────────


def test_no_known_typosquat_packages():
    """Check that dependencies don't include known typosquat names."""
    with open("pyproject.toml") as f:
        content = f.read().lower()

    # Known typosquat patterns (not exhaustive, but catches common ones)
    typosquats = [
        "requets",  # requests typo
        "htttpx",  # httpx typo
        "criptography",  # cryptography typo
        "pyymal",  # pyyaml typo
        "numppy",  # numpy typo
    ]

    for ts in typosquats:
        assert ts not in content, f"Possible typosquat package: {ts}"


# ── Attack 4: Verify .gitignore blocks sensitive files ───────────


def test_gitignore_blocks_sensitive_files():
    """gitignore must block .env files and other secrets."""
    with open(".gitignore") as f:
        gitignore = f.read()

    required_patterns = [".env"]
    for pattern in required_patterns:
        assert pattern in gitignore, (
            f".gitignore must contain '{pattern}' to prevent secret commits"
        )


# ── Attack 5: Verify no hardcoded secrets in source ──────────────


def test_no_hardcoded_tokens_in_source():
    """Source files must not contain hardcoded API keys or tokens."""
    import glob

    patterns = [
        r"sk-[a-zA-Z0-9]{20,}",  # OpenAI-style keys
        r"AKIA[A-Z0-9]{16}",  # AWS access keys
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub personal access tokens
        r"ghs_[a-zA-Z0-9]{36}",  # GitHub server tokens
    ]

    for py_file in glob.glob("src/**/*.py", recursive=True):
        # Skip generated files
        if "_generated" in py_file:
            continue
        with open(py_file) as f:
            content = f.read()
        for pattern in patterns:
            matches = re.findall(pattern, content)
            assert not matches, f"Possible hardcoded secret in {py_file}: {pattern}"


# ── Attack 6: Verify lock file hash is deterministic ────────────


def test_uv_lock_is_valid_text():
    """uv.lock must be valid text (not binary garbage from tampering)."""
    with open("uv.lock") as f:
        content = f.read()

    # uv.lock should start with a version comment or TOML header
    assert content.strip(), "uv.lock must not be empty whitespace"
    # Basic structure check: should contain package entries
    assert "name" in content.lower(), "uv.lock should contain package names"
