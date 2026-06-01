"""S018 P1 — Python catch-compatibility for the rich error envelope.

An adversarial audit confirmed that the S018 rich-envelope work preserved
``except ValueError`` and ``except TypeError`` but **broke** the natural
``except FileNotFoundError`` / ``except OSError`` (config missing file) and
``except ImportError`` (yaml dep missing) catches that pre-S018 callers relied
on — because ``AegisConfigError`` only subclassed ``ValueError``.

Fix: ``AegisConfigFileNotFoundError`` and ``AegisConfigImportError`` mix in the
matching builtin so every natural catch keeps working, while all of them still
carry the machine-parseable ``.code`` / ``.remediation`` / ``.docs_url`` /
``.to_dict()`` envelope (and remain catchable as ``AegisConfigError`` /
``ValueError`` — additive, for callers who adopted the S018 advice).

These tests lock all five catch contracts simultaneously with the envelope.
"""

import sys

import pytest

from aegis_trust import (
    AegisConfigError,
    AegisValidationError,
    shield,
)
from aegis_trust.config import load_config, reset_config
from aegis_trust.errors import (
    AegisConfigFileNotFoundError,
    AegisConfigImportError,
)
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean():
    reset_config()
    reset()
    yield
    reset_config()
    reset()


def _assert_envelope(err, code: str) -> None:
    assert err.code == code
    assert err.remediation and isinstance(err.remediation, str)
    assert err.docs_url == f"https://aegis-trust.dev/errors/{code}"
    d = err.to_dict()
    assert d["code"] == code
    assert d["remediation"] == err.remediation
    assert d["docs_url"] == err.docs_url
    assert d["message"]


# ── No layout conflict: the multiple-inheritance design actually loads ──


def test_config_error_subtypes_are_constructible():
    e1 = AegisConfigFileNotFoundError(
        "x", code="aegis.config.fileNotFound", remediation="r", docs_url="u"
    )
    e2 = AegisConfigImportError(
        "y", code="aegis.config.yamlMissing", remediation="r", docs_url="u"
    )
    assert str(e1) == "x" and e1.code == "aegis.config.fileNotFound"
    assert str(e2) == "y" and e2.code == "aegis.config.yamlMissing"


# ── except ValueError — validation errors (unchanged contract) ──────


def test_except_value_error_still_catches_validation():
    with pytest.raises(ValueError) as ei:
        shield(purpose="p", scope=["a"], deny_fields=["b"])
    assert isinstance(ei.value, AegisValidationError)
    _assert_envelope(ei.value, "aegis.shield.spec.conflict")


# ── except TypeError — type-shape checks stay raw TypeError ─────────


def test_except_type_error_still_catches_shape():
    with pytest.raises(TypeError):
        shield(purpose="p", scope="notalist")
    # And the envelope classes are NOT TypeError (so they don't accidentally
    # widen the TypeError surface).
    assert not issubclass(AegisValidationError, TypeError)
    assert not issubclass(AegisConfigError, TypeError)


# ── except FileNotFoundError / OSError — config missing file ────────


def test_except_file_not_found_still_catches_missing_config(tmp_path):
    missing = tmp_path / "nope.yaml"
    with pytest.raises(FileNotFoundError) as ei:
        load_config(str(missing))
    assert isinstance(ei.value, AegisConfigFileNotFoundError)
    # Still the rich envelope, and still an AegisConfigError / ValueError.
    assert isinstance(ei.value, AegisConfigError)
    assert isinstance(ei.value, ValueError)
    _assert_envelope(ei.value, "aegis.config.fileNotFound")


def test_except_os_error_still_catches_missing_config(tmp_path, monkeypatch):
    # No aegis.yaml in cwd, no AEGIS_CONFIG → fileNotFound, catchable as OSError
    # (FileNotFoundError is a subclass of OSError).
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)
    with pytest.raises(OSError) as ei:  # noqa: PT011 — intentional builtin-compat check
        load_config()
    assert isinstance(ei.value, AegisConfigFileNotFoundError)
    _assert_envelope(ei.value, "aegis.config.fileNotFound")


# ── except ImportError — yaml dependency missing ────────────────────


def test_except_import_error_still_catches_missing_yaml(tmp_path, monkeypatch):
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  s:\n    scope: [name]\n")
    monkeypatch.setitem(sys.modules, "yaml", None)  # `import yaml` → ImportError
    with pytest.raises(ImportError) as ei:
        load_config(str(p))
    assert isinstance(ei.value, AegisConfigImportError)
    assert isinstance(ei.value, AegisConfigError)
    assert isinstance(ei.value, ValueError)
    _assert_envelope(ei.value, "aegis.config.yamlMissing")


# ── all builtin catches PLUS the envelope at once (the headline claim) ──


def test_missing_file_satisfies_every_catch_contract(tmp_path):
    missing = tmp_path / "nope.yaml"
    try:
        load_config(str(missing))
    except Exception as e:  # noqa: BLE001 — we then assert the full contract
        assert isinstance(e, FileNotFoundError)
        assert isinstance(e, OSError)
        assert isinstance(e, ValueError)
        assert isinstance(e, AegisConfigError)
        assert e.code == "aegis.config.fileNotFound"
        assert e.remediation and e.docs_url and e.to_dict()["code"]
    else:
        pytest.fail("expected AegisConfigFileNotFoundError")
