"""T-503: @shield deny_fields blacklist bypass attempts (AO-002).

AI Red Team S018 — adversarial attempts to leak data past deny_fields filtering.
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


# ── Attack 1: Key case sensitivity bypass ────────────────────────


def test_deny_bypass_case_sensitivity():
    """Attacker uses 'SSN' hoping deny_fields=['ssn'] misses it."""

    @shield(purpose="support", deny_fields=["ssn"])
    def get_data():
        return {"name": "ok", "ssn": "123", "SSN": "456", "Ssn": "789"}

    result = get_data()
    assert "ssn" not in result
    # SSN and Ssn are different keys — deny_fields is case-sensitive (by design)
    # This is NOT a vulnerability: keys are literal matches
    # The developer must deny all case variants if data has inconsistent casing
    assert "SSN" in result  # Different key, not denied


# ── Attack 2: Mutate deny_fields list post-decoration ────────────


def test_deny_bypass_list_mutation():
    """Attacker clears the deny_fields list after decoration."""
    fields = ["ssn", "card"]

    @shield(purpose="support", deny_fields=fields)
    def get_data():
        return {"name": "ok", "ssn": "123", "card": "4242"}

    # Mutate: try to empty the deny list
    fields.clear()

    result = get_data()
    assert "ssn" not in result, "Clearing deny list must not affect filtering"
    assert "card" not in result, "Clearing deny list must not affect filtering"


# ── Attack 3: Unicode key collision in deny_fields ───────────────


def test_deny_bypass_unicode_key():
    """Attacker uses homoglyph key to evade deny_fields."""

    @shield(purpose="support", deny_fields=["ssn"])
    def get_data():
        return {
            "name": "ok",
            "ssn": "123",
            "s\u0455n": "cyrillic-s-lookalike",  # Cyrillic 's'
        }

    result = get_data()
    assert "ssn" not in result
    # Cyrillic lookalike IS a different key — passes through (by design)
    # This is a data modeling concern, not a shield bypass


# ── Attack 4: Nested deny_fields with conflicting paths ──────────


def test_deny_conflicting_nested_paths():
    """AO-002 fix: deny_fields=['profile', 'profile.ssn'] — broader deny wins.

    Before fix: tree merged to {"profile": {"ssn": {}}} → only ssn removed,
    age leaked through. AO-002 fail-open violation.

    After fix: broader path "profile" wins → entire profile removed.
    """

    @shield(purpose="support", deny_fields=["profile", "profile.ssn"])
    def get_data():
        return {
            "name": "ok",
            "profile": {"ssn": "123", "age": 30},
        }

    result = get_data()
    # AO-002 fail-closed: broader deny "profile" wins → entire profile removed
    assert "profile" not in result
    assert result == {"name": "ok"}


def test_deny_conflicting_nested_paths_reverse_order():
    """Same as above but fields in reverse order — result must be identical."""

    @shield(purpose="support", deny_fields=["profile.ssn", "profile"])
    def get_data():
        return {
            "name": "ok",
            "profile": {"ssn": "123", "age": 30, "salary": 8500000},
        }

    result = get_data()
    assert "profile" not in result
    assert result == {"name": "ok"}


def test_deny_conflicting_3_level_depth():
    """Broader deny at depth 2 wins over depth 3."""

    @shield(purpose="support", deny_fields=["a.b", "a.b.c"])
    def get_data():
        return {"a": {"b": {"c": "secret", "d": "also_secret"}, "e": "visible"}}

    result = get_data()
    # "a.b" is broader → entire a.b subtree denied, a.e survives
    assert result == {"a": {"e": "visible"}}


def test_deny_independent_paths_both_denied():
    """Two independent deny paths (no parent-child) — both work."""

    @shield(purpose="support", deny_fields=["profile.ssn", "profile.age"])
    def get_data():
        return {
            "name": "ok",
            "profile": {"ssn": "123", "age": 30, "email": "t@x.com"},
        }

    result = get_data()
    assert result == {"name": "ok", "profile": {"email": "t@x.com"}}


# ── Attack 4b: Direct _parse_paths(broader_wins=True) unit tests ──


def test_parse_paths_broader_wins_direct():
    """Direct unit test for _parse_paths tree collapsing."""
    from aegis_trust.shield import _parse_paths

    # Parent wins over child
    assert _parse_paths(["profile", "profile.ssn"], broader_wins=True) == {
        "profile": {}
    }
    # Reverse order — same result
    assert _parse_paths(["profile.ssn", "profile"], broader_wins=True) == {
        "profile": {}
    }
    # Independent paths — both kept
    assert _parse_paths(["x", "y"], broader_wins=True) == {"x": {}, "y": {}}
    # Single segment
    assert _parse_paths(["x"], broader_wins=True) == {"x": {}}


def test_parse_paths_broader_wins_duplicates():
    """Duplicate entries must not break collapsing."""
    from aegis_trust.shield import _parse_paths

    assert _parse_paths(["profile", "profile", "profile.ssn"], broader_wins=True) == {
        "profile": {}
    }


def test_parse_paths_broader_wins_4_level_chain():
    """4-level chain: topmost wins."""
    from aegis_trust.shield import _parse_paths

    result = _parse_paths(["a.b.c.d", "a.b", "a", "a.b.c"], broader_wins=True)
    assert result == {"a": {}}


def test_parse_paths_broader_wins_mixed_independent():
    """Mixed parent-child + independent paths."""
    from aegis_trust.shield import _parse_paths

    result = _parse_paths(["profile", "profile.ssn", "billing.card"], broader_wins=True)
    assert result == {"profile": {}, "billing": {"card": {}}}


def test_parse_paths_broader_wins_same_depth_non_parent():
    """Same dot-count but not parent-child (ab vs abc)."""
    from aegis_trust.shield import _parse_paths

    result = _parse_paths(["ab", "abc"], broader_wins=True)
    # ab and abc are independent — both should be leaves
    assert result == {"ab": {}, "abc": {}}


def test_parse_paths_broader_wins_false_unchanged():
    """broader_wins=False preserves original behavior."""
    from aegis_trust.shield import _parse_paths

    # Without broader_wins, child expands parent
    result = _parse_paths(["profile", "profile.ssn"], broader_wins=False)
    assert result == {"profile": {"ssn": {}}}


# ── Attack 5: deny_fields with __proto__ key ─────────────────────


def test_deny_fields_proto_pollution():
    """Attacker returns data with __proto__ and constructor keys."""

    @shield(purpose="support", deny_fields=["secret"])
    def get_data():
        return {
            "name": "ok",
            "__proto__": {"isAdmin": True},
            "constructor": {"prototype": {"isAdmin": True}},
            "secret": "hidden",
        }

    result = get_data()
    assert "secret" not in result
    # __proto__ and constructor pass through (not in deny list)
    # but they're just dict keys in Python, no prototype pollution possible
    assert "__proto__" in result


# ── Attack 6: Very large number of deny_fields ───────────────────


def test_deny_fields_large_list():
    """Attacker specifies 1000 deny fields — must still work correctly."""

    deny = [f"field_{i}" for i in range(1000)]

    @shield(purpose="audit", deny_fields=deny)
    def get_data():
        data = {f"field_{i}": f"val_{i}" for i in range(1000)}
        data["name"] = "allowed"
        return data

    result = get_data()
    assert result == {"name": "allowed"}


# ── Attack 7: deny_fields with None value in data ────────────────


def test_deny_fields_none_value():
    """Attacker has None-valued keys — deny must still remove them."""

    @shield(purpose="support", deny_fields=["ssn"])
    def get_data():
        return {"name": "ok", "ssn": None}

    result = get_data()
    assert "ssn" not in result


# ── Attack 8: deny_fields on list of mixed types ─────────────────


def test_deny_fields_list_mixed_types():
    """List contains dicts, strings, ints — deny_fields on non-dicts."""

    @shield(purpose="analytics", deny_fields=["secret"])
    def get_data():
        return [
            {"id": 1, "secret": "a"},
            "not_a_dict",
            42,
            None,
            {"id": 2, "secret": "b"},
        ]

    result = get_data()
    assert result[0] == {"id": 1}
    assert result[1] == ""  # Non-dict fail-closed
    assert result[2] == ""  # Non-dict fail-closed
    assert result[3] is None  # None passes through
    assert result[4] == {"id": 2}


# ── Attack 9: deny_fields bypass via nested list-of-list ─────────


def test_deny_fields_nested_list_of_lists():
    """Attacker nests lists inside lists to try escaping deny filter."""

    @shield(purpose="analytics", deny_fields=["secret"])
    def get_data():
        return [
            [{"id": 1, "secret": "a"}],
            {"id": 2, "secret": "b"},
        ]

    result = get_data()
    # Inner list: _deny_filter_result recurses into list items
    assert result[0] == [{"id": 1}]
    assert result[1] == {"id": 2}
