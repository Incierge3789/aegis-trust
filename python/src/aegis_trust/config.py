"""aegis.yaml policy configuration loader.

Reads purpose-based scope/deny_fields from a YAML config file,
enabling centralized policy management instead of per-decorator arguments.

Requires: pip install aegis-trust[yaml]
"""

from __future__ import annotations

import os
from typing import Any

from aegis_trust.errors import AegisConfigError, aegis_docs_url
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
        AegisConfigError: If pyyaml is missing, the file is not found, the YAML
            fails to parse, or the config structure is invalid. The envelope
            carries a machine-parseable ``.code`` matching the Node SDK
            (S018 D2). ``AegisConfigError`` subclasses :class:`ValueError`, so
            existing ``except ValueError`` callers keep working.
    """
    global _config, _config_path

    if _config is not None and (path is None or path == _config_path):
        return _config

    try:
        import yaml
    except ImportError as exc:
        raise AegisConfigError(
            "pyyaml is required to use aegis.yaml config. "
            "Install it with: pip install aegis-trust[yaml]",
            code="aegis.config.yamlMissing",
            remediation="Install the optional yaml dependency: pip install aegis-trust[yaml].",
            docs_url=aegis_docs_url("aegis.config.yamlMissing"),
            cause=exc,
        ) from exc

    resolved = path or _find_config_file()
    if resolved is None:
        raise AegisConfigError(
            "No aegis config file found. Create aegis.yaml or set AEGIS_CONFIG env var.",
            code="aegis.config.fileNotFound",
            remediation="Create `aegis.yaml` in CWD or set AEGIS_CONFIG to a YAML file path.",
            docs_url=aegis_docs_url("aegis.config.fileNotFound"),
        )

    # S018 D2 (Node config.ts S016 P1 parity): an explicit `path` argument
    # bypasses _find_config_file()'s isfile() guard, so a missing explicit path
    # escaped as a raw FileNotFoundError from open() — breaking the
    # machine-parseable contract. Guard it with the same envelope.
    if not os.path.isfile(resolved):
        raise AegisConfigError(
            f"aegis config file not found: {resolved}",
            code="aegis.config.fileNotFound",
            remediation=(
                "The path passed to load_config() does not exist. Pass a path to an "
                "existing YAML file, or omit it to auto-discover aegis.yaml / AEGIS_CONFIG."
            ),
            docs_url=aegis_docs_url("aegis.config.fileNotFound"),
        )

    with open(resolved) as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            # S018 D2 (Node aegis.config.yamlParseError parity): a YAML syntax
            # error escaped as a raw parser error with no code. Wrap it.
            raise AegisConfigError(
                f"aegis config YAML parse error in {resolved}",
                code="aegis.config.yamlParseError",
                remediation="Fix the YAML syntax in aegis.yaml. Run `yq . aegis.yaml` to locate it.",
                docs_url=aegis_docs_url("aegis.config.yamlParseError"),
                cause=exc,
            ) from exc

    if not isinstance(raw, dict):
        raise AegisConfigError(
            f"aegis config must be a YAML mapping, got {type(raw).__name__}. "
            f"The top-level structure should be a mapping with a 'purposes' key. "
            f'Example: \'purposes:\\n  support:\\n    scope: ["name", "issue"]\'',
            code="aegis.config.topLevel.notMapping",
            remediation="Top-level config must be a YAML mapping with a 'purposes' key.",
            docs_url=aegis_docs_url("aegis.config.topLevel.notMapping"),
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
        raise AegisConfigError(
            "'purposes' must be a mapping of purpose name to policy. "
            'Example: \'purposes:\\n  support:\\n    scope: ["name", "issue"]\'',
            code="aegis.config.purposes.notMapping",
            remediation="Set top-level 'purposes' to a mapping of purpose name to policy.",
            docs_url=aegis_docs_url("aegis.config.purposes.notMapping"),
        )

    for name, policy in purposes.items():
        if not isinstance(policy, dict):
            raise AegisConfigError(
                f"Purpose '{name}' must be a mapping containing scope or deny_fields. "
                f'Example: \'{name}:\\n  scope: ["name", "issue"]\'',
                code="aegis.config.purpose.notMapping",
                remediation="Each purpose entry must be a mapping with `scope` or `deny_fields`.",
                docs_url=aegis_docs_url("aegis.config.purpose.notMapping"),
            )

        has_scope = "scope" in policy
        has_deny = "deny_fields" in policy

        if has_scope and has_deny:
            raise AegisConfigError(
                f"Purpose '{name}': scope and deny_fields are mutually exclusive. "
                f"Use scope (whitelist) OR deny_fields (blacklist), not both.",
                code="aegis.config.purpose.scopeDenyConflict",
                remediation="Use either `scope` or `deny_fields` per purpose, never both.",
                docs_url=aegis_docs_url("aegis.config.purpose.scopeDenyConflict"),
            )
        if not has_scope and not has_deny:
            raise AegisConfigError(
                f"Purpose '{name}': either scope or deny_fields is required. "
                f"Specify scope=[...] (whitelist) or deny_fields=[...] (blacklist).",
                code="aegis.config.purpose.empty",
                remediation="Add `scope: [...]` or `deny_fields: [...]` to the purpose entry.",
                docs_url=aegis_docs_url("aegis.config.purpose.empty"),
            )

        # Validate field paths
        for key in ("scope", "deny_fields"):
            fields = policy.get(key)
            if fields is None:
                continue
            if not isinstance(fields, list):
                raise AegisConfigError(
                    f"Purpose '{name}': {key} must be a list of field names. "
                    f'Example: \'{key}: ["name", "issue"]\'',
                    code="aegis.config.fields.notList",
                    remediation=f"Set `{key}` to a YAML list of field name strings.",
                    docs_url=aegis_docs_url("aegis.config.fields.notList"),
                )
            for field in fields:
                if not isinstance(field, str):
                    raise AegisConfigError(
                        f"Purpose '{name}': {key} elements must be strings (got {type(field).__name__}). "
                        f'Example: \'{key}: ["name", "profile.age"]\'',
                        code="aegis.config.fields.elementNotString",
                        remediation=f"Each entry in `{key}` must be a string field path.",
                        docs_url=aegis_docs_url("aegis.config.fields.elementNotString"),
                    )
                _validate_field_path(
                    field,
                    error_cls=AegisConfigError,
                    code="aegis.config.fieldPath.invalid",
                )

        if has_deny and len(policy["deny_fields"]) == 0:
            raise AegisConfigError(
                f"Purpose '{name}': deny_fields must not be empty. "
                f"An empty deny list hides nothing. "
                f'Specify field names like deny_fields: ["ssn", "card"].',
                code="aegis.config.denyFields.empty",
                remediation="Provide at least one field path in `deny_fields`, or remove the key.",
                docs_url=aegis_docs_url("aegis.config.denyFields.empty"),
            )


def get_purpose_policy(purpose: str) -> dict[str, Any] | None:
    """Get scope/deny_fields for a purpose from loaded config.

    Returns:
        Dict with 'scope' or 'deny_fields' key, or None if purpose not defined.
    """
    try:
        config = load_config()
    except AegisConfigError as exc:
        # S018 D2: "no config available" (missing file / missing yaml dep)
        # degrades to None so an explicit @shield spec or the LITE no-config
        # path proceeds. A *malformed* config (any other code) still surfaces
        # so a broken aegis.yaml is not silently ignored — unchanged from the
        # pre-S018 behaviour, where ValueError propagated and only
        # FileNotFoundError / ImportError were swallowed.
        if exc.code in ("aegis.config.fileNotFound", "aegis.config.yamlMissing"):
            return None
        raise
    except (FileNotFoundError, ImportError):
        # Defensive: a raw FileNotFoundError can still arise from an open()
        # race after the isfile() guard. Preserve the graceful degrade.
        return None

    purposes = config.get("purposes", {})
    return purposes.get(purpose)


def reset_config() -> None:
    """Clear cached config. Useful for testing."""
    global _config, _config_path
    _config = None
    _config_path = None
