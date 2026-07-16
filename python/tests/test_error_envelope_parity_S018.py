"""S018 D2 — Python LITE rich error envelope parity with the Node SDK.

The Node SDK already raises ``AegisValidationError`` / ``AegisConfigError``
with a machine-parseable ``code`` on validation/config failures. Before S018
the Python LITE path raised raw ``ValueError`` / ``FileNotFoundError`` /
``ImportError`` and never actually used the rich envelope it publicly
exported. These tests lock the Python paths to:

  - raise the rich envelope (``.code`` / ``.remediation`` / ``.docs_url`` /
    ``.to_dict()``),
  - use error-code strings identical to the Node SDK for the shared concepts
    (so a polyglot consumer can switch on the same code across SDKs), and
  - preserve backward-compat: every envelope still subclasses ``ValueError``.
"""

import sys
import textwrap

import pytest

from aegis_trust import AegisConfigError, AegisValidationError, shield
from aegis_trust.config import get_purpose_policy, load_config, reset_config
from aegis_trust.shield import reset
from aegis_trust.types import Mode


@pytest.fixture(autouse=True)
def _clean():
    reset_config()
    reset()
    yield
    reset_config()
    reset()


# ── Node SSOT: error codes the two SDKs MUST agree on ──────────────
# Grep-sourced from node/src/shield.ts + node/src/config.ts (S018 audit).
# Shared concepts only — Node-only (purpose.required, sync_full_unsupported)
# and Python-shared (spec.conflict, deny_fields.empty, field_path.invalid)
# codes are exercised separately below.
_NODE_SHARED_CODES = {
    "shield.spec.required": "aegis.shield.spec.required",
    "shield.mode.invalid": "aegis.shield.mode.invalid",
    "config.yamlMissing": "aegis.config.yamlMissing",
    "config.fileNotFound": "aegis.config.fileNotFound",
    "config.yamlParseError": "aegis.config.yamlParseError",
    "config.topLevel.notMapping": "aegis.config.topLevel.notMapping",
    "config.purposes.notMapping": "aegis.config.purposes.notMapping",
    "config.purpose.notMapping": "aegis.config.purpose.notMapping",
    "config.purpose.scopeDenyConflict": "aegis.config.purpose.scopeDenyConflict",
    "config.purpose.empty": "aegis.config.purpose.empty",
    "config.fields.notList": "aegis.config.fields.notList",
    "config.fields.elementNotString": "aegis.config.fields.elementNotString",
    "config.denyFields.empty": "aegis.config.denyFields.empty",
    "config.fieldPath.invalid": "aegis.config.fieldPath.invalid",
}


def _assert_envelope(err, code: str) -> None:
    """A rich envelope must carry all four machine-parseable fields."""
    assert err.code == code
    assert err.remediation and isinstance(err.remediation, str)
    assert err.docs_url == f"https://aegis-trust.dev/errors/{code}"
    d = err.to_dict()
    assert d["code"] == code
    assert d["remediation"] == err.remediation
    assert d["docs_url"] == err.docs_url
    assert d["message"]
    # Backward-compat: every Aegis validation/config error IS a ValueError.
    assert isinstance(err, ValueError)


# ── D2 shield(): validation failures raise AegisValidationError ────


def test_shield_spec_conflict_envelope():
    with pytest.raises(AegisValidationError) as ei:
        shield(purpose="p", scope=["a"], deny_fields=["b"])
    _assert_envelope(ei.value, "aegis.shield.spec.conflict")
    assert "mutually exclusive" in str(ei.value)


def test_shield_spec_required_envelope():
    with pytest.raises(AegisValidationError) as ei:
        shield(purpose="p")  # no scope, no deny, no aegis.yaml
    _assert_envelope(ei.value, _NODE_SHARED_CODES["shield.spec.required"])


def test_shield_deny_fields_empty_envelope():
    with pytest.raises(AegisValidationError) as ei:
        shield(purpose="p", deny_fields=[])
    _assert_envelope(ei.value, "aegis.shield.deny_fields.empty")


def test_shield_mode_invalid_envelope():
    with pytest.raises(AegisValidationError) as ei:
        shield(purpose="p", scope=["a"], mode="FULL")  # mis-cased / invalid
    _assert_envelope(ei.value, _NODE_SHARED_CODES["shield.mode.invalid"])


def test_shield_field_path_invalid_envelope():
    with pytest.raises(AegisValidationError) as ei:
        shield(purpose="p", scope=[".bad"])
    _assert_envelope(ei.value, "aegis.shield.field_path.invalid")


def test_valid_mode_enum_still_accepted():
    # Regression: the mode-invalid wrapper must not reject the valid enum.
    deco = shield(purpose="p", scope=["a"], mode=Mode.LITE)
    assert callable(deco)


# ── D2 shield(): type-shape errors stay raw TypeError (compat) ─────


def test_scope_type_error_stays_typeerror():
    # Deliberate parity boundary: type-shape checks are NOT ValueError-family,
    # so they stay raw TypeError to keep `except TypeError` callers working.
    with pytest.raises(TypeError, match="scope must be a list"):
        shield(purpose="p", scope="notalist")
    assert not issubclass(AegisValidationError, TypeError)


# ── D2 config: load/validate failures raise AegisConfigError ───────


def test_config_file_not_found_envelope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)
    with pytest.raises(AegisConfigError) as ei:
        load_config()
    _assert_envelope(ei.value, _NODE_SHARED_CODES["config.fileNotFound"])


def test_config_explicit_path_missing_envelope(tmp_path):
    missing = tmp_path / "nope.yaml"
    with pytest.raises(AegisConfigError) as ei:
        load_config(str(missing))
    _assert_envelope(ei.value, _NODE_SHARED_CODES["config.fileNotFound"])


def test_config_yaml_missing_envelope(tmp_path, monkeypatch):
    # Simulate the optional `yaml` dep being absent: `import yaml` then raises
    # ImportError, which load_config() must wrap as the rich envelope.
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  s:\n    scope: [name]\n")
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(AegisConfigError) as ei:
        load_config(str(p))
    _assert_envelope(ei.value, _NODE_SHARED_CODES["config.yamlMissing"])


def test_config_yaml_parse_error_envelope(tmp_path):
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  support:\n   scope: [a\n  : : :\n")  # broken YAML
    with pytest.raises(AegisConfigError) as ei:
        load_config(str(p))
    _assert_envelope(ei.value, _NODE_SHARED_CODES["config.yamlParseError"])


def test_config_top_level_not_mapping_envelope(tmp_path):
    p = tmp_path / "aegis.yaml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(AegisConfigError) as ei:
        load_config(str(p))
    _assert_envelope(ei.value, _NODE_SHARED_CODES["config.topLevel.notMapping"])


@pytest.mark.parametrize(
    "yaml_body, code_key",
    [
        ("purposes: [not, a, mapping]\n", "config.purposes.notMapping"),
        ("purposes:\n  s: [not, mapping]\n", "config.purpose.notMapping"),
        (
            "purposes:\n  s:\n    scope: [a]\n    deny_fields: [b]\n",
            "config.purpose.scopeDenyConflict",
        ),
        ("purposes:\n  s: {}\n", "config.purpose.empty"),
        ("purposes:\n  s:\n    scope: notalist\n", "config.fields.notList"),
        ("purposes:\n  s:\n    scope: [123]\n", "config.fields.elementNotString"),
        ("purposes:\n  s:\n    deny_fields: []\n", "config.denyFields.empty"),
        ("purposes:\n  s:\n    scope: ['.bad']\n", "config.fieldPath.invalid"),
    ],
)
def test_config_validation_envelopes(tmp_path, yaml_body, code_key):
    p = tmp_path / "aegis.yaml"
    p.write_text(textwrap.dedent(yaml_body))
    with pytest.raises(AegisConfigError) as ei:
        load_config(str(p))
    _assert_envelope(ei.value, _NODE_SHARED_CODES[code_key])


# ── Backward-compat: existing `except ValueError` callers keep working ──


def test_value_error_catch_still_works_shield():
    try:
        shield(purpose="p", scope=["a"], deny_fields=["b"])
    except ValueError as e:
        assert isinstance(e, AegisValidationError)
    else:
        pytest.fail("expected a ValueError-compatible error")


def test_value_error_catch_still_works_config(tmp_path):
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  s: {}\n")
    try:
        load_config(str(p))
    except ValueError as e:
        assert isinstance(e, AegisConfigError)
    else:
        pytest.fail("expected a ValueError-compatible error")


# ── get_purpose_policy: "no config" degrades, malformed surfaces ───
# This distinction is subtle and changed shape in S018 (it now branches on
# AegisConfigError.code); lock both directions against regression.


def test_get_purpose_policy_degrades_when_no_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)
    # No aegis.yaml present → fileNotFound is swallowed → None (so an explicit
    # @shield spec / LITE no-config path can proceed).
    assert get_purpose_policy("anything") is None


def test_get_purpose_policy_degrades_when_yaml_missing(tmp_path, monkeypatch):
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  s:\n    scope: [name]\n")
    monkeypatch.setenv("AEGIS_CONFIG", str(p))
    monkeypatch.setitem(sys.modules, "yaml", None)
    # Missing optional yaml dep → yamlMissing is swallowed → None.
    assert get_purpose_policy("s") is None


def test_get_purpose_policy_surfaces_malformed_config(tmp_path, monkeypatch):
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  s: {}\n")  # neither scope nor deny_fields
    monkeypatch.setenv("AEGIS_CONFIG", str(p))
    # A malformed aegis.yaml must NOT be silently ignored — it surfaces the
    # rich envelope (which is also ValueError-compatible).
    with pytest.raises(AegisConfigError) as ei:
        get_purpose_policy("s")
    assert ei.value.code == "aegis.config.purpose.empty"


# ── S022 audit remediation: trace codes must match Node (camelCase) ─


def test_trace_id_code_matches_node():
    from aegis_trust.trace import trace_context

    with pytest.raises(AegisValidationError) as ei:
        with trace_context("bad id with spaces"):
            pass
    _assert_envelope(ei.value, "aegis.trace.traceId.invalid")


def test_parent_id_code_matches_node():
    from aegis_trust.trace import trace_context

    with pytest.raises(AegisValidationError) as ei:
        with trace_context("ok-trace", "bad parent!"):
            pass
    _assert_envelope(ei.value, "aegis.trace.parentId.invalid")
