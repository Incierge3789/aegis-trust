"""aegis.yaml policy configuration loader.

Reads purpose-based scope/deny_fields from a YAML config file,
enabling centralized policy management instead of per-decorator arguments.

Requires: pip install aegis-trust[yaml]
"""

from __future__ import annotations

import os
from typing import Any

from aegis_trust.shield import _validate_field_path

# Module-level cache
_config: dict[str, Any] | None = None
_config_path: str | None = None


def _find_config_file() -> str | None:
    """Search for aegis config file in priority order."""
    env_path = os.environ.get("AEGIS_CONFIG")
    if env_path:
        if os.path.isfile(env_path):
            return env_path
        return None

    for name in ("aegis.yaml", "aegis.yml"):
        if os.path.isfile(name):
            return name
    return None


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load and cache aegis config from YAML file.

    Args:
        path: Explicit path to config file. If None, searches automatically.

    Returns:
        Parsed config dict.

    Raises:
        ImportError: If pyyaml is not installed.
        FileNotFoundError: If no config file found.
        ValueError: If config structure is invalid.
    """
    global _config, _config_path

    if _config is not None and (path is None or path == _config_path):
        return _config

    try:
        import yaml
    except ImportError:
        raise ImportError(
            "pyyaml is required to use aegis.yaml config. "
            "Install it with: pip install aegis-trust[yaml]"
        )

    resolved = path or _find_config_file()
    if resolved is None:
        raise FileNotFoundError(
            "No aegis config file found. Create aegis.yaml or set AEGIS_CONFIG env var."
        )

    with open(resolved) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(
            f"aegis config must be a YAML mapping, got {type(raw).__name__}. "
            f"The top-level structure should be a mapping with a 'purposes' key. "
            f'Example: \'purposes:\\n  support:\\n    scope: ["name", "issue"]\''
        )

    _validate_config(raw)
    _config = raw
    _config_path = resolved
    return _config


def _validate_config(config: dict[str, Any]) -> None:
    """Validate aegis config structure."""
    purposes = config.get("purposes")
    if purposes is None:
        return  # No purposes section is valid (empty config)

    if not isinstance(purposes, dict):
        raise ValueError(
            "'purposes' must be a mapping of purpose name to policy. "
            'Example: \'purposes:\\n  support:\\n    scope: ["name", "issue"]\''
        )

    for name, policy in purposes.items():
        if not isinstance(policy, dict):
            raise ValueError(
                f"Purpose '{name}' must be a mapping containing scope or deny_fields. "
                f'Example: \'{name}:\\n  scope: ["name", "issue"]\''
            )

        has_scope = "scope" in policy
        has_deny = "deny_fields" in policy

        if has_scope and has_deny:
            raise ValueError(
                f"Purpose '{name}': scope and deny_fields are mutually exclusive. "
                f"Use scope (whitelist) OR deny_fields (blacklist), not both."
            )
        if not has_scope and not has_deny:
            raise ValueError(
                f"Purpose '{name}': either scope or deny_fields is required. "
                f"Specify scope=[...] (whitelist) or deny_fields=[...] (blacklist)."
            )

        # Validate field paths
        for key in ("scope", "deny_fields"):
            fields = policy.get(key)
            if fields is None:
                continue
            if not isinstance(fields, list):
                raise ValueError(
                    f"Purpose '{name}': {key} must be a list of field names. "
                    f'Example: \'{key}: ["name", "issue"]\''
                )
            for field in fields:
                if not isinstance(field, str):
                    raise ValueError(
                        f"Purpose '{name}': {key} elements must be strings (got {type(field).__name__}). "
                        f'Example: \'{key}: ["name", "profile.age"]\''
                    )
                _validate_field_path(field)

        if has_deny and len(policy["deny_fields"]) == 0:
            raise ValueError(
                f"Purpose '{name}': deny_fields must not be empty. "
                f"An empty deny list hides nothing. "
                f'Specify field names like deny_fields: ["ssn", "card"].'
            )


def get_purpose_policy(purpose: str) -> dict[str, Any] | None:
    """Get scope/deny_fields for a purpose from loaded config.

    Returns:
        Dict with 'scope' or 'deny_fields' key, or None if purpose not defined.
    """
    try:
        config = load_config()
    except (FileNotFoundError, ImportError):
        return None

    purposes = config.get("purposes", {})
    return purposes.get(purpose)


def reset_config() -> None:
    """Clear cached config. Useful for testing."""
    global _config, _config_path
    _config = None
    _config_path = None
