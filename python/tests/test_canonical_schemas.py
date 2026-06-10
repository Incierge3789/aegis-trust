"""Wire the schemas/v0 truth-source harnesses into the pytest suite (CI).

These subprocess the standalone harnesses so the schema-level negative tests
(validate.py) and the gateway projection selftest run on every CI pass, not
only when invoked by hand.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas" / "v0"


@pytest.mark.parametrize(
    "script, args",
    [
        ("validate.py", []),
        ("project_gateway_audit.py", ["--selftest"]),
    ],
)
def test_schema_harness(script: str, args: list[str]) -> None:
    pytest.importorskip("jsonschema")
    result = subprocess.run(
        [sys.executable, str(SCHEMA_DIR / script), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"{script} failed:\n{result.stdout}\n{result.stderr}"
