"""Tests for aegis.config — aegis.yaml policy loader."""

import textwrap

import pytest

from aegis_trust.config import (
    _validate_config,
    get_purpose_policy,
    load_config,
    reset_config,
)
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean():
    """Reset config and shield state before each test."""
    reset_config()
    reset()
    yield
    reset_config()
    reset()


# --- load_config ---


def test_load_from_explicit_path(tmp_path):
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  support:\n    scope: [name, email]\n")
    config = load_config(str(p))
    assert config["purposes"]["support"]["scope"] == ["name", "email"]


def test_load_from_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "aegis.yaml").write_text(
        "purposes:\n  billing:\n    deny_fields: [ssn]\n"
    )
    config = load_config()
    assert config["purposes"]["billing"]["deny_fields"] == ["ssn"]


def test_load_from_yml_extension(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "aegis.yml").write_text("purposes:\n  support:\n    scope: [name]\n")
    config = load_config()
    assert "support" in config["purposes"]


def test_load_from_env_var(tmp_path, monkeypatch):
    p = tmp_path / "custom.yaml"
    p.write_text("purposes:\n  support:\n    scope: [name]\n")
    monkeypatch.setenv("AEGIS_CONFIG", str(p))
    config = load_config()
    assert "support" in config["purposes"]


def test_load_file_not_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)
    # S018 D2: upgraded from raw FileNotFoundError to the rich AegisConfigError
    # envelope. It still subclasses ValueError for backward-compat.
    from aegis_trust.errors import AegisConfigError

    with pytest.raises(AegisConfigError, match="No aegis config file found") as ei:
        load_config()
    assert ei.value.code == "aegis.config.fileNotFound"
    assert isinstance(ei.value, ValueError)


def test_load_caches_result(tmp_path):
    p = tmp_path / "aegis.yaml"
    p.write_text("purposes:\n  support:\n    scope: [name]\n")
    c1 = load_config(str(p))
    c2 = load_config()  # Should use cache
    assert c1 is c2


def test_load_invalid_yaml_type(tmp_path):
    p = tmp_path / "aegis.yaml"
    p.write_text("- just a list\n")
    with pytest.raises(ValueError, match="must be a YAML mapping"):
        load_config(str(p))


# --- _validate_config ---


def test_validate_scope_and_deny_fields_mutual_exclusion():
    with pytest.raises(ValueError, match="mutually exclusive"):
        _validate_config(
            {"purposes": {"bad": {"scope": ["name"], "deny_fields": ["ssn"]}}}
        )


def test_validate_neither_scope_nor_deny():
    with pytest.raises(ValueError, match="either scope or deny_fields"):
        _validate_config({"purposes": {"bad": {}}})


def test_validate_empty_deny_fields():
    with pytest.raises(ValueError, match="must not be empty"):
        _validate_config({"purposes": {"bad": {"deny_fields": []}}})


def test_validate_invalid_field_path():
    with pytest.raises(ValueError, match="leading or trailing dot"):
        _validate_config({"purposes": {"bad": {"scope": [".name"]}}})


def test_validate_non_string_field():
    with pytest.raises(ValueError, match="must be strings"):
        _validate_config({"purposes": {"bad": {"scope": [123]}}})


def test_validate_scope_not_list():
    with pytest.raises(ValueError, match="must be a list"):
        _validate_config({"purposes": {"bad": {"scope": "name"}}})


def test_validate_purpose_not_mapping():
    with pytest.raises(ValueError, match="must be a mapping"):
        _validate_config({"purposes": {"bad": "invalid"}})


def test_validate_empty_purposes():
    # No purposes section is valid
    _validate_config({})


# --- get_purpose_policy ---


def test_get_purpose_policy_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "aegis.yaml").write_text(
        "purposes:\n  support:\n    scope: [name, issue]\n"
    )
    policy = get_purpose_policy("support")
    assert policy == {"scope": ["name", "issue"]}


def test_get_purpose_policy_not_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "aegis.yaml").write_text("purposes:\n  support:\n    scope: [name]\n")
    policy = get_purpose_policy("billing")
    assert policy is None


def test_get_purpose_policy_no_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)
    policy = get_purpose_policy("support")
    assert policy is None


# --- shield() with aegis.yaml fallback ---


def test_shield_fallback_to_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AEGIS_MODE", "lite")
    (tmp_path / "aegis.yaml").write_text(
        "purposes:\n  support:\n    scope: [name, issue]\n"
    )

    from aegis_trust.shield import shield

    @shield(purpose="support")
    def get_data():
        return {"name": "Alice", "issue": "Bug", "ssn": "123"}

    result = get_data()
    assert result == {"name": "Alice", "issue": "Bug"}
    assert "ssn" not in result


def test_shield_fallback_deny_fields(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AEGIS_MODE", "lite")
    (tmp_path / "aegis.yaml").write_text(
        "purposes:\n  billing:\n    deny_fields: [ssn]\n"
    )

    from aegis_trust.shield import shield

    @shield(purpose="billing")
    def get_data():
        return {"name": "Alice", "ssn": "123", "plan": "pro"}

    result = get_data()
    assert result == {"name": "Alice", "plan": "pro"}


def test_shield_no_config_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_CONFIG", raising=False)

    from aegis_trust.shield import shield

    with pytest.raises(ValueError, match="Either scope or deny_fields"):

        @shield(purpose="unknown")
        def get_data():
            return {}


def test_shield_explicit_scope_overrides_config(tmp_path, monkeypatch):
    """Explicit scope parameter takes precedence over aegis.yaml."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AEGIS_MODE", "lite")
    (tmp_path / "aegis.yaml").write_text(
        "purposes:\n  support:\n    scope: [name, issue, email]\n"
    )

    from aegis_trust.shield import shield

    @shield(purpose="support", scope=["name"])
    def get_data():
        return {"name": "Alice", "issue": "Bug", "email": "a@b.com"}

    result = get_data()
    assert result == {"name": "Alice"}


def test_shield_dot_notation_from_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AEGIS_MODE", "lite")
    (tmp_path / "aegis.yaml").write_text(
        textwrap.dedent("""\
        purposes:
          support:
            scope:
              - name
              - profile.age
        """)
    )

    from aegis_trust.shield import shield

    @shield(purpose="support")
    def get_data():
        return {"name": "Alice", "profile": {"age": 30, "ssn": "123"}}

    result = get_data()
    assert result == {"name": "Alice", "profile": {"age": 30}}
