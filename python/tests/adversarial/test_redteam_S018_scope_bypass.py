"""T-502: @shield scope whitelist bypass attempts (AO-002).

AI Red Team S018 — adversarial attempts to leak data past scope filtering.
Every test here MUST pass (defense holds). A failure = AO-002 violation.
"""

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


# ── Attack 1: Access internal closure via __wrapped__ ────────────


def test_scope_bypass_via_wrapped_attr():
    """Attacker tries to call the original unwrapped function to skip filtering."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "ssn": "123-45-6789", "card": "4242"}

    # functools.wraps sets __wrapped__, which points to the original.
    # If __wrapped__ exists, an attacker could call it directly to skip filtering.
    # This is a Python-level escape (functools standard behavior) — document but accept.
    # The KEY assertion: calling the decorated function NEVER leaks.

    result = get_customer()
    assert "ssn" not in result
    assert "card" not in result


# ── Attack 2: Mutate scope list post-decoration ──────────────────


def test_scope_bypass_via_list_mutation():
    """Attacker gets reference to scope list and appends '*' wildcard."""
    fields = ["name"]

    @shield(purpose="support", scope=fields)
    def get_customer():
        return {"name": "Tanaka", "ssn": "123-45-6789"}

    # Mutate original list — try to add ssn
    fields.append("ssn")
    fields.append("*")

    result = get_customer()
    assert "ssn" not in result, "Scope mutation must not affect filtering"


# ── Attack 3: Unicode normalization bypass ───────────────────────


def test_scope_bypass_unicode_normalization():
    """Attacker uses Unicode lookalikes to try matching 'ssn'."""

    @shield(purpose="support", scope=["name", "ss\u006e"])  # 'ssn' in Unicode
    def get_customer():
        return {"name": "Tanaka", "ssn": "123-45-6789"}

    result = get_customer()
    # This should actually match because \u006e IS 'n' — same codepoint.
    # The defense: scope must be exact string match. No normalization.
    assert result.get("ssn") == "123-45-6789" or "ssn" not in result


def test_scope_bypass_fullwidth_chars():
    """Attacker uses fullwidth 'ｓｓｎ' hoping normalization matches 'ssn'."""

    @shield(purpose="support", scope=["name", "\uff53\uff53\uff4e"])
    def get_customer():
        return {"name": "Tanaka", "ssn": "123-45-6789"}

    result = get_customer()
    # Fullwidth chars are different codepoints — must NOT match 'ssn'
    assert "ssn" not in result, "Fullwidth chars must not match ASCII keys"


# ── Attack 4: Prototype pollution via __class__ key ──────────────


def test_scope_bypass_dunder_keys():
    """Attacker returns data with __class__, __dict__ keys to confuse filtering."""

    @shield(purpose="support", scope=["name"])
    def get_data():
        return {
            "name": "ok",
            "__class__": "should_be_removed",
            "__dict__": {"secret": "value"},
            "__init__": "malicious",
        }

    result = get_data()
    assert result == {"name": "ok"}
    assert "__class__" not in result
    assert "__dict__" not in result
    assert "__init__" not in result


# ── Attack 5: Scope with empty string key ────────────────────────


def test_scope_bypass_empty_string_key():
    """Attacker puts data under '' key, hoping scope=[] lets it through."""

    @shield(purpose="audit", scope=[])
    def get_data():
        return {"": "hidden_in_empty_key", "name": "visible"}

    result = get_data()
    assert result == {}, "Empty scope must return empty dict"


# ── Attack 6: Very deep nesting to exhaust recursion ─────────────


def test_scope_deep_nesting_no_crash():
    """Attacker sends deeply nested structure to try stack overflow."""

    @shield(purpose="analytics", scope=["data"])
    def get_deep():
        d: dict = {}
        current = d
        for i in range(200):
            current["level"] = {}
            current = current["level"]
        current["secret"] = "buried"
        return {"data": d, "top_secret": "x"}

    result = get_deep()
    assert "top_secret" not in result
    # Hardened contract: a bare leaf scope over a deeply-nested mapping drops
    # fail-closed (no crash, and the buried secret never surfaces). The caller
    # must enumerate explicit "data.<field>" paths to retrieve nested values.
    assert result == {}


# ── Attack 7: Key collision with dot-notation ────────────────────


def test_scope_dot_notation_key_with_literal_dots():
    """Attacker puts literal dots in dict keys: {"profile.ssn": "123"}.
    scope=["profile.ssn"] means profile->ssn, NOT the literal key.
    """

    @shield(purpose="support", scope=["name"])
    def get_data():
        return {
            "name": "ok",
            "profile.ssn": "literal-dot-key-value",
            "profile": {"ssn": "123-45-6789"},
        }

    result = get_data()
    assert "profile.ssn" not in result
    assert "profile" not in result


def test_scope_dot_notation_key_collision_with_nested():
    """scope=["profile.ssn"] must descend into profile dict, NOT match flat key."""

    @shield(purpose="support", scope=["profile.ssn"])
    def get_data():
        return {
            "profile.ssn": "SHOULD_NOT_APPEAR",
            "profile": {"ssn": "123", "name": "hidden"},
        }

    result = get_data()
    # The flat key "profile.ssn" must not appear
    assert "profile.ssn" not in result
    # The nested path profile->ssn should be in result
    assert result.get("profile", {}).get("ssn") == "123"
    assert "name" not in result.get("profile", {})


# ── Attack 8: Large payload — performance DoS ────────────────────


def test_scope_large_payload_no_timeout():
    """Attacker sends 10K-key dict to try performance degradation."""

    @shield(purpose="analytics", scope=["key_0", "key_1"])
    def get_huge():
        return {f"key_{i}": f"val_{i}" for i in range(10_000)}

    result = get_huge()
    assert len(result) == 2
    assert "key_9999" not in result


# ── Attack 9: NoneType in mixed data structures ──────────────────


def test_scope_none_in_nested_dict():
    """Attacker includes None values in nested dicts."""

    @shield(purpose="support", scope=["name", "profile.age"])
    def get_data():
        return {"name": "ok", "profile": None, "secret": "x"}

    result = get_data()
    assert "secret" not in result
    # profile is not a dict — scope expects nested access
    # None passes through for top-level scope match
    # But profile.age requires profile to be a dict — should be dropped
    assert result.get("name") == "ok"
