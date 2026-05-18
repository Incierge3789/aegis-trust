"""Tests for scripts/ots-verify-external.sh."""

import os
import stat
import subprocess

import pytest

SCRIPT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "scripts", "ots-verify-external.sh"
)
SCRIPT_PATH = os.path.normpath(SCRIPT_PATH)


@pytest.mark.integration
class TestOtsVerifyExternal:
    """Basic integration tests for ots-verify-external.sh."""

    def test_script_exists(self):
        """The script file exists on disk."""
        assert os.path.isfile(SCRIPT_PATH), f"Script not found: {SCRIPT_PATH}"

    def test_script_is_executable(self):
        """The script has the executable bit set."""
        mode = os.stat(SCRIPT_PATH).st_mode
        assert mode & stat.S_IXUSR, "Script is not executable (missing u+x)"

    def test_nonexistent_file_exits_nonzero(self):
        """Running with a path that does not exist should exit non-zero."""
        result = subprocess.run(
            [SCRIPT_PATH, "/tmp/nonexistent-file-that-does-not-exist.ots"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
        assert "FAIL" in result.stderr

    def test_no_arguments_exits_nonzero(self):
        """Running with no arguments should exit non-zero."""
        result = subprocess.run(
            [SCRIPT_PATH],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
        assert "Usage" in result.stderr
