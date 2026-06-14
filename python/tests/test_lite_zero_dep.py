"""LITE-only install is dependency-free (adoption-friction reduction).

The headline LITE path — `pip install aegis-trust` then `from aegis_trust import
shield` and filter a dict in-process — must pull NO runtime dependencies. The
gateway/FULL deps (httpx, attrs) are an opt-in `[full]` extra. These tests pin:

1. the packaging contract (core deps empty; gateway deps in `[full]`),
2. that the LITE import + filter actually works with httpx/attrs absent, and
3. that driving FULL without the extra fails with an actionable, machine-
   parseable error (not a raw ModuleNotFoundError).

(2) and (3) run in a subprocess with httpx/attrs blocked so the parent test
process — where httpx IS installed — is never polluted.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_lite_core_dependencies_are_empty() -> None:
    """`pip install aegis-trust` (LITE) must be dependency-free.

    Text-matched (no tomllib/tomli) so the contract is pinned identically on
    every supported Python (3.10 has no stdlib TOML parser).
    """
    text = PYPROJECT.read_text()
    assert re.search(r"(?m)^dependencies\s*=\s*\[\s*\]", text), (
        "LITE core dependencies must be empty []; gateway deps belong in [full]"
    )


def test_gateway_deps_live_in_full_extra() -> None:
    """httpx + attrs are the gateway/FULL extra, not core deps."""
    text = PYPROJECT.read_text()
    m = re.search(r"(?ms)^full\s*=\s*\[(.*?)\]", text)
    assert m, "no `full` block under [project.optional-dependencies]"
    block = m.group(1)
    assert "httpx" in block and "attrs" in block, block


def test_lite_import_and_filter_without_gateway_extra() -> None:
    """`from aegis_trust import shield` + filter works with httpx/attrs absent."""
    code = (
        "import sys\n"
        "sys.modules['httpx'] = None\n"  # force ImportError on `import httpx`
        "sys.modules['attrs'] = None\n"
        "from aegis_trust import shield\n"
        "@shield(purpose='p', scope=['name'])\n"
        "def get_user():\n"
        "    return {'name': 'a', 'ssn': 'x'}\n"
        "out = get_user()\n"
        "assert out == {'name': 'a'}, out\n"
        "print('LITE_OK')\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    assert "LITE_OK" in r.stdout


def test_full_mode_without_gateway_extra_is_actionable() -> None:
    """Driving FULL without the extra raises AegisConfigError pointing at [full]."""
    code = (
        "import sys, os\n"
        "sys.modules['httpx'] = None\n"
        "sys.modules['attrs'] = None\n"
        "os.environ['AEGIS_MODE'] = 'full'\n"
        "from aegis_trust import shield\n"
        "from aegis_trust.errors import AegisConfigError\n"
        "@shield(purpose='p', scope=['name'])\n"
        "def h():\n"
        "    return {'name': 'a'}\n"
        "try:\n"
        "    h()\n"
        "    print('NO_ERROR')\n"
        "except AegisConfigError as e:\n"
        "    print('ACTIONABLE' if 'aegis-trust[full]' in str(e) else 'WRONG:' + str(e))\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    assert "ACTIONABLE" in r.stdout, r.stdout
