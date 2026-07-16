"""Endpoint contract gate (T-150, S023 Phase 4 Build).

Closes codex C1 finding: the SDK's hand-rolled httpx calls (/shield/ingest,
/shield/policy-sync, /shield/stats, /shield/report, /check-access,
/audit/verify, /health, /audit-log) are not visible to the auto-generated
client. This test catches SDK→openapi.json drift without needing a live
aegis-core — every endpoint client.py hits must also exist in the committed
openapi.json. If the endpoint is missing here, either the spec is stale
(refresh python/openapi.json from a running dev gateway — see
`_generated/__init__.py` for the regeneration steps; there is no Makefile in
this repo) or the SDK is calling a route the gateway does not expose.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLIENT_PY = REPO_ROOT / "src" / "aegis_trust" / "client.py"
OPENAPI_JSON = REPO_ROOT / "openapi.json"

# Endpoints here are constructed dynamically or do not belong in the SDK's
# contract with aegis-core (e.g., CLI-only). Keep this short — everything
# else should live in the spec.
ALLOWED_MISSING: set[str] = set()


def _string_paths_in_client() -> set[str]:
    """Extract every httpx path literal in client.py.

    A path is defined as a string literal passed as the first positional
    arg to a method whose name starts with 'post', 'get', 'put', 'patch',
    'delete' on an expression chain of `.post(`, `.get(`, etc.
    """
    tree = ast.parse(CLIENT_PY.read_text())
    paths: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in {"post", "get", "put", "patch", "delete"}:
            continue
        if not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            val = first.value
            if val.startswith("/"):
                paths.add(val)
    return paths


def _spec_paths() -> set[str]:
    spec = json.loads(OPENAPI_JSON.read_text())
    return set(spec.get("paths", {}).keys())


def test_every_client_path_is_in_openapi_spec():
    client_paths = _string_paths_in_client()
    assert client_paths, "contract gate found no paths in client.py — parser bug?"
    spec_paths = _spec_paths()
    missing = {p for p in client_paths if p not in spec_paths} - ALLOWED_MISSING
    assert not missing, (
        f"Contract drift — SDK client.py calls {sorted(missing)} but these "
        f"endpoints are not in openapi.json. Regenerate the spec "
        f"(refresh python/openapi.json from a running dev gateway; see "
        f"_generated/__init__.py) or remove the stale "
        f"client call. Known SDK paths: {sorted(client_paths)}. Known spec "
        f"paths (sample): {sorted(list(spec_paths)[:8])}."
    )


def test_audit_verify_contract_fields():
    """AuditVerifyResponse must expose chain_valid + total_entries so the
    SDK's verify_inclusion() helper (T-154) has the fields it needs.
    """
    spec = json.loads(OPENAPI_JSON.read_text())
    schemas = spec.get("components", {}).get("schemas", {})
    assert "AuditVerifyResponse" in schemas
    props = schemas["AuditVerifyResponse"].get("properties", {})
    assert "chain_valid" in props
    assert "total_entries" in props


def test_check_access_is_post():
    spec = json.loads(OPENAPI_JSON.read_text())
    ca = spec.get("paths", {}).get("/check-access", {})
    assert "post" in ca, "/check-access must expose POST for AO-003 gate"


def test_no_secrets_literal_in_client():
    """AO-006 sanity: the committed client.py should not contain a literal
    token/password/api-key string (credentials must come from env).
    """
    text = CLIENT_PY.read_text()
    patterns = [
        r"Bearer\s+[A-Za-z0-9_\-]{16,}",
        r"api[_-]?key\s*=\s*['\"]?[A-Za-z0-9]{16,}",
    ]
    offenders = [p for p in patterns if re.search(p, text, re.IGNORECASE)]
    assert not offenders, f"possible credential literal in client.py: {offenders}"


def _method_paths_in_client() -> set[tuple[str, str]]:
    """Extract every (HTTP method, path literal) pair the client calls.

    Same AST walk as `_string_paths_in_client`, keeping the method name —
    the S233-era gap: path-only checking let /audit/verify (client GETs,
    spec said post) and /audit-log (client POSTs, spec said get) drift
    inverted through CI for multiple releases.
    """
    tree = ast.parse(CLIENT_PY.read_text())
    pairs: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in {"post", "get", "put", "patch", "delete"}:
            continue
        if not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            if first.value.startswith("/"):
                pairs.add((func.attr, first.value))
    return pairs


def test_every_client_call_verb_matches_openapi_spec():
    """Every (method, path) the client uses must be DECLARED with that verb.

    Path-presence alone (the test above) cannot catch an inverted verb; this
    closes that hole permanently.
    """
    spec = json.loads(OPENAPI_JSON.read_text())
    spec_paths = spec.get("paths", {})
    mismatches = []
    for method, path in sorted(_method_paths_in_client()):
        if path in ALLOWED_MISSING:
            continue
        declared = spec_paths.get(path, {})
        if method not in declared:
            mismatches.append(
                f"{method.upper()} {path} (spec declares: "
                f"{sorted(k for k in declared if k in {'get', 'post', 'put', 'patch', 'delete'})})"
            )
    assert not mismatches, (
        "Contract verb drift — the SDK calls these endpoints with a verb the "
        f"spec does not declare: {mismatches}"
    )
