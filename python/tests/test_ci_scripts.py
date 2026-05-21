"""Regression tests for CI scripts — AO-004 audit completeness.

These tests verify that scripts/ci-matrix.sh and scripts/ci-attest.sh
correctly propagate failures (no false "ALL PASSED").

T-006c-1b iter-1 cross-review P1 closure (2026-05-21): the integration
tests below invoke ci-matrix.sh / ci-attest.sh as subprocesses; the
scripts require `uv` (Python version manager) on PATH + the matrix
Python interpreters (e.g., 3.12) installable via `uv python install`.
On hosts without `uv`, the scripts fail at the install step and the
tests collected as failures rather than skips, masking the actual
contract gap (T-006c-1c: portable test-env provisioning). Until
T-006c-1c lands the integration tests skip cleanly when `uv` is
absent so the test report reflects honest skip semantics rather than
"failure" semantics for an unavailable runtime.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_MATRIX = REPO_ROOT / "scripts" / "ci-matrix.sh"
CI_ATTEST = REPO_ROOT / "scripts" / "ci-attest.sh"

# T-006c-1b iter-1 cross-review P1 (codex + cursor consensus):
# `test_single_version_pass` fails on hosts without `uv` because
# ci-matrix.sh reaches `uv pip install` and errors at "uv not installed".
# Skip the integration tests honestly when `uv` is absent, instead of
# reporting them as failures. Routes the underlying contract gap
# (script-portability across CI envs) to T-006c-1c.
_HAS_UV = shutil.which("uv") is not None
_UV_SKIP_REASON = (
    "Skipping: ci-matrix.sh / ci-attest.sh require `uv` on PATH "
    "(install via `pip install uv` or the standalone installer). "
    "T-006c-1c will close this skip by either (a) provisioning uv "
    "in the canonical test env or (b) rewriting the scripts to use "
    "a pre-existing Python installation without uv."
)


@pytest.mark.integration
@pytest.mark.skipif(not _HAS_UV, reason=_UV_SKIP_REASON)
class TestCiMatrixFailurePropagation:
    """ci-matrix.sh must exit non-zero when any step fails."""

    def test_invalid_pytest_flag_fails(self, tmp_path):
        """Inject a broken pytest invocation via a poisoned conftest."""
        env = os.environ.copy()
        env["PYTHON_VERSIONS"] = "3.12"
        env["_AEGIS_CI_MATRIX_INNER"] = "1"
        conftest = REPO_ROOT / "conftest.py"
        conftest_backup = None
        if conftest.exists():
            conftest_backup = conftest.read_text()
        try:
            conftest.write_text("raise SystemExit('INJECTED FAILURE')\n")
            result = subprocess.run(
                [str(CI_MATRIX)],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=300,
            )
            assert result.returncode != 0, (
                f"ci-matrix.sh should have failed but exited 0.\nstdout: {result.stdout[-500:]}"
            )
        finally:
            if conftest_backup is not None:
                conftest.write_text(conftest_backup)
            else:
                conftest.unlink(missing_ok=True)

    def test_single_version_pass(self):
        """Sanity: ci-matrix.sh passes with a single good version."""
        env = os.environ.copy()
        env["PYTHON_VERSIONS"] = "3.12"
        result = subprocess.run(
            [str(CI_MATRIX)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=env,
            timeout=300,
        )
        assert result.returncode == 0, (
            f"ci-matrix.sh failed unexpectedly.\nstderr: {result.stderr[-500:]}"
        )
        assert "PASS" in result.stdout


@pytest.mark.integration
@pytest.mark.skipif(not _HAS_UV, reason=_UV_SKIP_REASON)
class TestCiAttestFailurePropagation:
    """ci-attest.sh must preserve attestation integrity."""

    def test_sha3_512_is_last_line(self):
        """The SHA-3-512 self-declaration must be the final line."""
        env = os.environ.copy()
        result = subprocess.run(
            [str(CI_ATTEST), "--skip-matrix"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"ci-attest.sh --skip-matrix failed.\nstderr: {result.stderr[-500:]}"
        )
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        ).stdout.strip()
        sprint = "S000"
        import re

        m = re.search(r"S\d+", branch)
        if m:
            sprint = m.group(0)

        version = "unknown"
        vf = REPO_ROOT / "VERSION"
        if vf.exists():
            version = vf.read_text().strip()

        attest_path = (
            REPO_ROOT / ".gstack" / "ci-attestations" / f"{sprint}-v{version}.txt"
        )
        if not attest_path.exists():
            pytest.skip(f"Attestation file not found: {attest_path}")

        lines = attest_path.read_text().rstrip("\n").split("\n")
        last_line = lines[-1]
        assert last_line.startswith("ATTESTATION SHA-3-512:"), (
            f"Last line should be SHA-3-512 declaration, got: {last_line!r}"
        )

    def test_attestation_tamper_detection(self):
        """Modifying the attestation file should invalidate SHA-3-512."""
        import hashlib

        env = os.environ.copy()
        subprocess.run(
            [str(CI_ATTEST), "--skip-matrix"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=env,
            timeout=60,
        )

        attest_files = list((REPO_ROOT / ".gstack" / "ci-attestations").glob("*.txt"))
        if not attest_files:
            pytest.skip("No attestation files found")

        attest_path = attest_files[-1]
        content = attest_path.read_text()
        lines = content.rstrip("\n").split("\n")

        sig_line = lines[-1]
        assert sig_line.startswith("ATTESTATION SHA-3-512:"), "Missing signature line"
        declared_hash = sig_line.split(": ", 1)[1].strip()

        tampered = content.replace("Commit:", "Commit: TAMPERED", 1)
        tampered_lines = tampered.rstrip("\n").split("\n")
        tampered_body = "\n".join(tampered_lines[:-1]) + "\n"
        tampered_hash = hashlib.sha3_512(tampered_body.encode()).hexdigest()
        assert tampered_hash != declared_hash, (
            "Tampered content should not match declared hash"
        )
