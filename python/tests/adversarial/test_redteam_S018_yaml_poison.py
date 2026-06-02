"""T-506: aegis.yaml policy poisoning — malicious YAML injection (AO-003).

AI Red Team S018 — adversarial attempts to inject malicious YAML
into aegis.yaml configuration.
"""

import os
import tempfile

import pytest

from aegis_trust.config import load_config, reset_config


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset_config()
    # Ensure no default config file interferes
    monkeypatch.chdir(tempfile.mkdtemp())
    yield
    reset_config()


def _write_yaml(content: str) -> str:
    """Write YAML content to a temp file and return path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.write(fd, content.encode())
    os.close(fd)
    return path


# ── Attack 1: YAML deserialization (!!python/object) ─────────────


def test_yaml_python_object_injection():
    """Attacker injects !!python/object to execute arbitrary code.
    yaml.safe_load must reject this.
    """
    malicious = """
purposes:
  evil:
    scope: !!python/object/apply:os.system
      args: ["echo pwned"]
"""
    path = _write_yaml(malicious)
    # yaml.safe_load raises ConstructorError for unsafe tags
    with pytest.raises(Exception):
        load_config(path)


def test_yaml_python_module_injection():
    """Attacker tries !!python/module to import arbitrary code."""
    malicious = """
purposes:
  evil:
    scope: !!python/module:os
"""
    path = _write_yaml(malicious)
    with pytest.raises(Exception):
        load_config(path)


def test_yaml_python_name_injection():
    """Attacker tries !!python/name to reference Python objects."""
    malicious = """
purposes:
  evil:
    scope: !!python/name:os.system
"""
    path = _write_yaml(malicious)
    with pytest.raises(Exception):
        load_config(path)


# ── Attack 2: YAML bomb (billion laughs) ─────────────────────────


def test_yaml_billion_laughs():
    """Attacker sends exponentially expanding YAML anchors.
    yaml.safe_load should handle this (pyyaml has built-in protection).
    """
    bomb = """
a: &a ["lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c]
purposes:
  evil:
    scope: *d
"""
    path = _write_yaml(bomb)
    # This will either parse (with expanded but bounded data)
    # or raise a validation error (scope must be list of strings)
    with pytest.raises((ValueError, TypeError)):
        load_config(path)


# ── Attack 3: Invalid structure attacks ──────────────────────────


def test_yaml_scope_not_a_list():
    """Attacker sets scope to a string instead of list."""
    malicious = """
purposes:
  evil:
    scope: "name ssn card"
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="scope must be a list"):
        load_config(path)


def test_yaml_scope_with_non_string_elements():
    """Attacker puts integers in scope list."""
    malicious = """
purposes:
  evil:
    scope:
      - name
      - 42
      - true
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="must be strings"):
        load_config(path)


def test_yaml_purposes_not_a_mapping():
    """Attacker sets purposes to a list."""
    malicious = """
purposes:
  - name: evil
    scope: ["name"]
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="must be a mapping"):
        load_config(path)


def test_yaml_purpose_both_scope_and_deny():
    """Attacker tries to set both scope and deny_fields."""
    malicious = """
purposes:
  evil:
    scope: ["name"]
    deny_fields: ["ssn"]
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="mutually exclusive"):
        load_config(path)


def test_yaml_purpose_neither_scope_nor_deny():
    """Attacker creates purpose with no scope or deny_fields."""
    malicious = """
purposes:
  evil:
    description: "no filtering"
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="either scope or deny_fields"):
        load_config(path)


def test_yaml_deny_fields_empty_list():
    """Attacker sets deny_fields to empty list."""
    malicious = """
purposes:
  evil:
    deny_fields: []
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="must not be empty"):
        load_config(path)


# ── Attack 4: Path traversal via AEGIS_CONFIG ────────────────────


def test_aegis_config_env_nonexistent_file(monkeypatch):
    """AEGIS_CONFIG pointing to nonexistent file must fail safely.

    S018 D2: upgraded from raw FileNotFoundError to the rich AegisConfigError
    envelope (still fail-closed, still ValueError-compatible).
    """
    from aegis_trust.errors import AegisConfigError

    monkeypatch.setenv("AEGIS_CONFIG", "/tmp/nonexistent_aegis_config_12345.yaml")
    reset_config()
    with pytest.raises(AegisConfigError) as ei:
        load_config()
    assert ei.value.code == "aegis.config.fileNotFound"
    assert isinstance(ei.value, ValueError)


# ── Attack 5: YAML with dot-notation validation bypass ───────────


def test_yaml_scope_invalid_dot_notation():
    """Attacker uses invalid dot-notation in YAML config."""
    malicious = """
purposes:
  evil:
    scope:
      - "name"
      - ".leading_dot"
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="leading or trailing dot"):
        load_config(path)


def test_yaml_scope_consecutive_dots():
    """Attacker uses consecutive dots in YAML config."""
    malicious = """
purposes:
  evil:
    scope:
      - "profile..ssn"
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="consecutive dots"):
        load_config(path)


def test_yaml_scope_empty_string():
    """Attacker puts empty string in scope."""
    malicious = """
purposes:
  evil:
    scope:
      - ""
"""
    path = _write_yaml(malicious)
    with pytest.raises(ValueError, match="must not be empty"):
        load_config(path)


# ── Attack 6: Valid config loads correctly ────────────────────────


def test_valid_config_loads():
    """Sanity: valid config must work."""
    valid = """
purposes:
  support:
    scope:
      - name
      - email
  analytics:
    deny_fields:
      - ssn
      - card
"""
    path = _write_yaml(valid)
    config = load_config(path)
    assert config["purposes"]["support"]["scope"] == ["name", "email"]
    assert config["purposes"]["analytics"]["deny_fields"] == ["ssn", "card"]
