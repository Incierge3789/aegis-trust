"""VERSION SSOT — verify all version sources agree."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_version_ssot():
    version_file = (REPO_ROOT / "VERSION").read_text().strip()

    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert m, "version not found in pyproject.toml"
    pyproject_version = m.group(1)

    import aegis_trust

    init_version = aegis_trust.__version__

    assert version_file == pyproject_version, (
        f"VERSION ({version_file}) != pyproject.toml ({pyproject_version})"
    )
    assert version_file == init_version, (
        f"VERSION ({version_file}) != aegis_trust.__version__ ({init_version})"
    )
