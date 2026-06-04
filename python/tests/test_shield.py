"""Tests for @shield decorator — lite mode (no aegis-core required)."""

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset
from aegis_trust.types import Mode


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    """Reset shield state and force lite mode for each test."""
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


# ── Basic dict filtering ──────────────────────────────────────


def test_filters_dict_by_scope():
    @shield(purpose="support", scope=["name", "issue"])
    def get_customer():
        return {
            "name": "Tanaka Taro",
            "email": "tanaka@example.com",
            "card": "4242-****-****-1234",
            "issue": "Login problem",
        }

    result = get_customer()
    assert result == {"name": "Tanaka Taro", "issue": "Login problem"}
    assert "email" not in result
    assert "card" not in result


def test_empty_scope_returns_empty_dict():
    @shield(purpose="audit", scope=[])
    def get_data():
        return {"secret": "value", "other": 123}

    assert get_data() == {}


def test_full_scope_returns_all():
    @shield(purpose="admin", scope=["a", "b", "c"])
    def get_data():
        return {"a": 1, "b": 2, "c": 3}

    assert get_data() == {"a": 1, "b": 2, "c": 3}


# ── List of dicts ─────────────────────────────────────────────


def test_filters_list_of_dicts():
    @shield(purpose="analytics", scope=["id", "status"])
    def list_orders():
        return [
            {"id": 1, "status": "shipped", "address": "Tokyo"},
            {"id": 2, "status": "pending", "address": "Osaka"},
        ]

    result = list_orders()
    assert result == [
        {"id": 1, "status": "shipped"},
        {"id": 2, "status": "pending"},
    ]


# ── Non-dict/non-list: fail-closed (AO-002) ─────────────────


def test_non_dict_returns_empty(caplog):
    @shield(purpose="info", scope=["x"])
    def get_number():
        return 42

    assert get_number() == ""
    assert "unsupported_return_shape" in caplog.text


def test_string_returns_empty(caplog):
    @shield(purpose="info", scope=["x"])
    def get_message():
        return "hello"

    assert get_message() == ""
    assert "unsupported_return_shape" in caplog.text


def test_none_passthrough():
    @shield(purpose="info", scope=["x"])
    def get_nothing():
        return None

    assert get_nothing() is None


# ── Function arguments preserved ──────────────────────────────


def test_passes_args_to_wrapped_function():
    @shield(purpose="lookup", scope=["name"])
    def get_user(user_id: int, *, active: bool = True):
        return {"name": f"User-{user_id}", "active": active, "secret": "x"}

    result = get_user(42, active=False)
    assert result == {"name": "User-42"}


# ── Mode parameter ────────────────────────────────────────────


def test_explicit_lite_mode():
    @shield(purpose="test", scope=["a"], mode=Mode.LITE)
    def fn():
        return {"a": 1, "b": 2}

    assert fn() == {"a": 1}


def test_mode_string():
    @shield(purpose="test", scope=["a"], mode="lite")
    def fn():
        return {"a": 1, "b": 2}

    assert fn() == {"a": 1}


# ── Nested dicts ──────────────────────────────────────────────


def test_nested_dict_top_level_filter():
    @shield(purpose="report", scope=["summary"])
    def get_report():
        return {
            "summary": {"total": 100, "avg": 50},
            "raw_data": [1, 2, 3],
        }

    result = get_report()
    # Trust-boundary hardening: a bare leaf scope over a nested mapping drops
    # fail-closed (it would otherwise disclose the whole subtree the caller never
    # enumerated). "raw_data" (not in scope) is filtered; "summary" (record-like)
    # is withheld until requested as explicit "summary.<field>" paths.
    assert result == {}

    @shield(purpose="report", scope=["summary.total", "summary.avg"])
    def get_report_explicit():
        return {"summary": {"total": 100, "avg": 50}, "raw_data": [1, 2, 3]}

    assert get_report_explicit() == {"summary": {"total": 100, "avg": 50}}


# ── functools.wraps preserved ─────────────────────────────────


def test_scope_nested_dict_recursive():
    """AO-002: scope filters keys recursively at every nesting level."""

    @shield(purpose="support", scope=["name", "age"])
    def get_customer():
        return {
            "name": "Tanaka",
            "profile": {"name": "Tanaka", "ssn": "123-45-6789", "age": 30},
        }

    result = get_customer()
    # "profile" not in scope → removed entirely
    assert result == {"name": "Tanaka"}


def test_scope_nested_with_parent_in_scope():
    """Use dot-notation to filter within a nested dict."""

    @shield(purpose="report", scope=["name", "details.count"])
    def get_report():
        return {
            "name": "Q1 Report",
            "details": {"count": 100, "secret": "hidden"},
            "raw": [1, 2, 3],
        }

    result = get_report()
    assert result == {"name": "Q1 Report", "details": {"count": 100}}


def test_scope_deeply_nested():
    """AO-002: dot-notation scope works at 3+ nesting levels."""

    @shield(purpose="analytics", scope=["id", "data.value"])
    def get_data():
        return {
            "id": 1,
            "data": {
                "value": 42,
                "nested": {
                    "value": 99,
                    "secret": "hidden",
                },
            },
        }

    result = get_data()
    assert result == {"id": 1, "data": {"value": 42}}


def test_scope_nested_in_list():
    """AO-002: scope filters nested dicts inside lists."""

    @shield(purpose="analytics", scope=["id", "name"])
    def list_items():
        return [
            {"id": 1, "name": "A", "secret": "x"},
            {"id": 2, "data": {"name": "B", "secret": "y"}},
        ]

    result = list_items()
    assert result == [
        {"id": 1, "name": "A"},
        {"id": 2},
    ]


def test_preserves_function_metadata():
    @shield(purpose="test", scope=["x"])
    def my_func():
        """My docstring."""
        return {"x": 1}

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "My docstring."


# ── deny_fields (blacklist mode) ─────────────────────────────


def test_deny_fields_removes_specified_keys():
    @shield(purpose="support", deny_fields=["card", "ssn"])
    def get_customer():
        return {
            "name": "Tanaka Taro",
            "email": "tanaka@example.com",
            "card": "4242-****-****-1234",
            "ssn": "123-45-6789",
            "issue": "Login problem",
        }

    result = get_customer()
    assert result == {
        "name": "Tanaka Taro",
        "email": "tanaka@example.com",
        "issue": "Login problem",
    }
    assert "card" not in result
    assert "ssn" not in result


def test_deny_fields_empty_list_raises_valueerror():
    with pytest.raises(ValueError, match="must not be empty"):

        @shield(purpose="audit", deny_fields=[])
        def get_data():
            return {"a": 1, "b": 2, "c": 3}


def test_deny_fields_list_of_dicts():
    @shield(purpose="analytics", deny_fields=["address"])
    def list_orders():
        return [
            {"id": 1, "status": "shipped", "address": "Tokyo"},
            {"id": 2, "status": "pending", "address": "Osaka"},
        ]

    result = list_orders()
    assert result == [
        {"id": 1, "status": "shipped"},
        {"id": 2, "status": "pending"},
    ]


def test_deny_fields_non_dict_returns_empty(caplog):
    @shield(purpose="info", deny_fields=["x"])
    def get_number():
        return 42

    assert get_number() == ""
    assert "unsupported_return_shape" in caplog.text


def test_deny_fields_none_passthrough():
    @shield(purpose="info", deny_fields=["x"])
    def get_nothing():
        return None

    assert get_nothing() is None


# ── scope + deny_fields mutual exclusion ─────────────────────


def test_scope_and_deny_fields_raises_valueerror():
    with pytest.raises(ValueError, match="mutually exclusive"):

        @shield(purpose="test", scope=["a"], deny_fields=["b"])
        def fn():
            return {"a": 1, "b": 2}


def test_neither_scope_nor_deny_fields_raises_valueerror():
    with pytest.raises(ValueError, match="Either scope or deny_fields"):

        @shield(purpose="test")
        def fn():
            return {"a": 1}


def test_deny_fields_string_raises_typeerror():
    with pytest.raises(TypeError, match="deny_fields must be a list"):

        @shield(purpose="test", deny_fields="card")
        def fn():
            return {"card": "x"}


def test_scope_string_raises_typeerror():
    with pytest.raises(TypeError, match="scope must be a list"):

        @shield(purpose="test", scope="name")
        def fn():
            return {"name": "x"}


def test_deny_fields_nested_dict():
    """AO-002: deny_fields with dot-notation removes nested keys."""

    @shield(purpose="support", deny_fields=["profile.ssn"])
    def get_customer():
        return {
            "name": "Tanaka Taro",
            "profile": {"ssn": "123-45-6789", "age": 30},
        }

    result = get_customer()
    assert result == {"name": "Tanaka Taro", "profile": {"age": 30}}
    assert "ssn" not in result.get("profile", {})


def test_deny_fields_deeply_nested():
    """AO-002: deny_fields with dot-notation works at 3+ nesting levels."""

    @shield(purpose="support", deny_fields=["level1.level2.secret"])
    def get_data():
        return {
            "level1": {
                "level2": {
                    "secret": "hidden",
                    "visible": "ok",
                }
            }
        }

    result = get_data()
    assert result == {"level1": {"level2": {"visible": "ok"}}}


def test_deny_fields_nested_in_list():
    """AO-002: deny_fields with dot-notation removes keys inside dicts within lists."""

    @shield(purpose="analytics", deny_fields=["ssn", "profile.ssn"])
    def list_customers():
        return [
            {"name": "A", "ssn": "111"},
            {"name": "B", "profile": {"ssn": "222", "age": 25}},
        ]

    result = list_customers()
    assert result == [
        {"name": "A"},
        {"name": "B", "profile": {"age": 25}},
    ]


def test_deny_fields_non_str_element_raises_typeerror():
    with pytest.raises(TypeError, match="deny_fields elements must all be strings"):

        @shield(purpose="test", deny_fields=["card", 42])
        def fn():
            return {"card": "x"}


def test_scope_non_str_element_raises_typeerror():
    with pytest.raises(TypeError, match="scope elements must all be strings"):

        @shield(purpose="test", scope=["name", 42])
        def fn():
            return {"name": "x"}


def test_deny_fields_list_mutation_does_not_change_policy():
    """Mutating the original deny_fields list after decoration must not affect filtering."""
    fields = ["card", "ssn"]

    @shield(purpose="support", deny_fields=fields)
    def get_customer():
        return {"name": "Tanaka", "card": "4242", "ssn": "123"}

    # Mutate original list after decoration
    fields.append("name")

    result = get_customer()
    # "name" must still be present — mutation should have no effect
    assert result == {"name": "Tanaka"}


def test_scope_list_mutation_does_not_change_policy():
    """Mutating the original scope list after decoration must not affect filtering."""
    fields = ["name", "email"]

    @shield(purpose="support", scope=fields)
    def get_customer():
        return {"name": "Tanaka", "email": "t@x.com", "card": "4242"}

    # Mutate original list after decoration
    fields.append("card")

    result = get_customer()
    # "card" must NOT be present — mutation should have no effect
    assert result == {"name": "Tanaka", "email": "t@x.com"}
    assert "card" not in result


def test_deny_fields_preserves_function_metadata():
    @shield(purpose="test", deny_fields=["secret"])
    def my_func():
        """My docstring."""
        return {"x": 1, "secret": 2}

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "My docstring."


# ── dot-notation scope ───────────────────────────────────────


def test_dot_notation_scope_specific_nested_path():
    """dot-notation allows precise control over nested fields."""

    @shield(purpose="support", scope=["name", "profile.age"])
    def get_customer():
        return {
            "name": "Tanaka",
            "profile": {"age": 30, "ssn": "123-45-6789", "email": "t@x.com"},
            "secret": "hidden",
        }

    result = get_customer()
    assert result == {"name": "Tanaka", "profile": {"age": 30}}


def test_dot_notation_scope_3_levels():
    """dot-notation works at 3+ levels."""

    @shield(purpose="analytics", scope=["id", "data.nested.value"])
    def get_data():
        return {
            "id": 1,
            "data": {
                "value": 42,
                "nested": {"value": 99, "secret": "hidden"},
            },
        }

    result = get_data()
    assert result == {"id": 1, "data": {"nested": {"value": 99}}}


def test_dot_notation_scope_flat_and_dot_mixed():
    """Flat keys and dot-notation can coexist."""

    @shield(purpose="report", scope=["id", "name", "address.city"])
    def get_user():
        return {
            "id": 1,
            "name": "Tanaka",
            "address": {"city": "Tokyo", "zip": "100-0001"},
            "secret": "x",
        }

    result = get_user()
    assert result == {"id": 1, "name": "Tanaka", "address": {"city": "Tokyo"}}


def test_dot_notation_scope_leaf_over_mapping_drops_fail_closed():
    """A bare leaf scope over a nested mapping drops fail-closed.

    Trust-boundary hardening (doctor-v0 fail-open class): ``scope=["profile"]``
    must NOT silently disclose every child of ``profile`` (including secrets the
    operator never enumerated). The caller must request explicit
    ``profile.<field>`` paths."""

    @shield(purpose="admin", scope=["profile"])
    def get_user():
        return {
            "profile": {"name": "A", "age": 30, "nested": {"x": 1}},
            "secret": "hidden",
        }

    assert get_user() == {}

    @shield(purpose="admin", scope=["profile.name", "profile.age"])
    def get_user_explicit():
        return {
            "profile": {"name": "A", "age": 30, "ssn": "leak"},
            "secret": "hidden",
        }

    # Explicit leaves disclose only what was enumerated; ssn stays withheld.
    assert get_user_explicit() == {"profile": {"name": "A", "age": 30}}


def test_dot_notation_scope_in_list_of_dicts():
    """dot-notation scope works on dicts inside lists."""

    @shield(purpose="analytics", scope=["id", "meta.status"])
    def list_items():
        return [
            {"id": 1, "meta": {"status": "ok", "secret": "x"}},
            {"id": 2, "meta": {"status": "fail", "secret": "y"}},
        ]

    result = list_items()
    assert result == [
        {"id": 1, "meta": {"status": "ok"}},
        {"id": 2, "meta": {"status": "fail"}},
    ]


def test_dot_notation_scope_nonexistent_path():
    """Referencing a path that doesn't exist in data returns empty for that branch."""

    @shield(purpose="test", scope=["name", "profile.nonexistent"])
    def get_data():
        return {"name": "A", "profile": {"age": 30}}

    result = get_data()
    assert result == {"name": "A", "profile": {}}


# ── dot-notation deny_fields ─────────────────────────────────


def test_dot_notation_deny_fields_specific_nested_path():
    """dot-notation deny_fields removes only the specific nested field."""

    @shield(purpose="support", deny_fields=["profile.ssn"])
    def get_customer():
        return {
            "name": "Tanaka",
            "profile": {"age": 30, "ssn": "123-45-6789"},
        }

    result = get_customer()
    assert result == {"name": "Tanaka", "profile": {"age": 30}}


def test_dot_notation_deny_fields_top_level_only():
    """Flat deny_fields only removes top-level keys, not nested ones."""

    @shield(purpose="support", deny_fields=["ssn"])
    def get_customer():
        return {
            "name": "Tanaka",
            "ssn": "top-level-ssn",
            "profile": {"ssn": "nested-ssn", "age": 30},
        }

    result = get_customer()
    # Top-level ssn removed, nested ssn kept
    assert result == {"name": "Tanaka", "profile": {"ssn": "nested-ssn", "age": 30}}


# ── dot-notation validation ──────────────────────────────────


def test_dot_notation_empty_path_raises_valueerror():
    with pytest.raises(ValueError, match="must not be empty"):

        @shield(purpose="test", scope=["name", ""])
        def fn():
            return {}


def test_dot_notation_leading_dot_raises_valueerror():
    with pytest.raises(ValueError, match="leading or trailing dot"):

        @shield(purpose="test", scope=[".name"])
        def fn():
            return {}


def test_dot_notation_trailing_dot_raises_valueerror():
    with pytest.raises(ValueError, match="leading or trailing dot"):

        @shield(purpose="test", deny_fields=["name."])
        def fn():
            return {}


def test_dot_notation_consecutive_dots_raises_valueerror():
    with pytest.raises(ValueError, match="consecutive dots"):

        @shield(purpose="test", scope=["profile..name"])
        def fn():
            return {}


# ── M1 regression: scope bypass scalar passthrough (AO-002) ─────


def test_scope_dot_notation_scalar_where_dict_expected_drops_key():
    """AO-002 regression (S013/M1): scope expects nested path but value is scalar.

    scope=["profile.age"] expects profile to be a dict.
    If profile is a scalar string, it must be dropped (fail-closed),
    not passed through.
    """

    @shield(purpose="support", scope=["name", "profile.age"])
    def get_customer():
        return {"name": "Tanaka", "profile": "secret_string"}

    result = get_customer()
    assert result == {"name": "Tanaka"}
    assert "profile" not in result


def test_scope_dot_notation_scalar_int_where_dict_expected():
    """AO-002 regression (S013/M1): scalar int where dict expected."""

    @shield(purpose="support", scope=["id", "data.value"])
    def get_data():
        return {"id": 1, "data": 42}

    result = get_data()
    assert result == {"id": 1}
    assert "data" not in result


def test_scope_dot_notation_scalar_in_list_drops_key():
    """AO-002 regression (S013/M1): scalar in list of mixed types."""

    @shield(purpose="analytics", scope=["id", "meta.status"])
    def list_items():
        return [
            {"id": 1, "meta": {"status": "ok", "secret": "x"}},
            {"id": 2, "meta": "not_a_dict"},
        ]

    result = list_items()
    assert result == [
        {"id": 1, "meta": {"status": "ok"}},
        {"id": 2},
    ]


def test_deny_fields_scalar_where_dict_expected_drops_fail_closed():
    """Deny mode: scalar where subtree expected → drop fail-closed.

    S022 R2/A12: symmetric with scope semantics. Pre-S022 kept the value
    (asymmetric fail-open); post-S022 drops the key because the caller
    declared ``profile.ssn`` should be scrubbed and the value is not a
    dict we can descend into.
    """

    @shield(purpose="support", deny_fields=["profile.ssn"])
    def get_customer():
        return {"name": "Tanaka", "profile": "not_a_dict"}

    result = get_customer()
    assert result == {"name": "Tanaka"}


# ── M2 regression: exception sanitization (AO-002) ──────────────


def test_exception_in_wrapped_function_returns_empty(caplog):
    """AO-002 regression (S013/M2): exceptions must not propagate unredacted."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        raise RuntimeError("DB connection failed: password=secret123")

    result = get_customer()
    assert result == ""
    assert "returning empty (fail-closed)" in caplog.text
    # The sensitive error message must NOT appear in the return value
    assert "secret123" not in str(result)


def test_exception_in_deny_fields_wrapped_returns_empty(caplog):
    """AO-002 regression (S013/M2): deny_fields mode also catches exceptions."""

    @shield(purpose="support", deny_fields=["ssn"])
    def get_customer():
        raise ValueError("Sensitive internal error detail")

    result = get_customer()
    assert result == ""
    assert "returning empty (fail-closed)" in caplog.text


# ── list[dict] footgun — minimum-disclosure fail-closed (v0.6.5.6) ─


def test_scope_leaf_over_list_of_dicts_drops_with_warning(caplog):
    """Bare scope=['users'] over list-of-dicts drops the key (fail-closed)."""
    import logging

    @shield(purpose="support", scope=["users"])
    def list_users():
        return {
            "users": [
                {"name": "Aria", "ssn": "111"},
                {"name": "Ben", "ssn": "222"},
            ],
            "count": 2,
        }

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = list_users()

    # users key is dropped entirely; count is also absent (not in scope).
    assert result == {}
    assert "scope_bare_field_over_record_collection" in caplog.text
    assert "fail-closed" in caplog.text


def test_scope_leaf_over_heterogeneous_list_also_drops(caplog):
    """Heterogeneous list [primitive, dict] also triggers drop (any() detection)."""
    import logging

    @shield(purpose="support", scope=["items"])
    def f():
        return {"items": [1, 2, {"ssn": "111"}, 3]}

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    # First element is int (not dict), but the third is dict — any() catches it.
    assert result == {}
    assert "scope_bare_field_over_record_collection" in caplog.text


def test_scope_leaf_over_empty_list_passes():
    """Empty list [] at a leaf passes through (no dicts, no leak)."""

    @shield(purpose="support", scope=["items"])
    def f():
        return {"items": [], "other": "dropped"}

    assert f() == {"items": []}


def test_scope_leaf_over_list_of_primitives_passes():
    """List[primitive] at a leaf passes through unchanged."""

    @shield(purpose="support", scope=["tags"])
    def f():
        return {"tags": ["red", "blue", "green"], "note": "dropped"}

    assert f() == {"tags": ["red", "blue", "green"]}


def test_scope_dot_notation_filters_list_of_dicts():
    """scope=['users.name'] filters each dict element — regression."""

    @shield(purpose="support", scope=["users.name"])
    def list_users():
        return {
            "users": [
                {"name": "Aria", "ssn": "111"},
                {"name": "Ben", "ssn": "222"},
            ]
        }

    assert list_users() == {"users": [{"name": "Aria"}, {"name": "Ben"}]}


def test_scope_leaf_over_tuple_of_dicts_drops_like_list(caplog):
    """Tuple-of-dicts at a leaf drops just like list-of-dicts (fail-closed)."""
    import logging

    @shield(purpose="support", scope=["pair"])
    def f():
        return {"pair": ({"ssn": "111"}, {"ssn": "222"}), "other": "dropped"}

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    # Tuple of dicts is the same silent-pass footgun — drop fail-closed.
    assert result == {}
    assert "scope_bare_field_over_record_collection" in caplog.text


def test_scope_leaf_over_tuple_of_primitives_passes():
    """Tuple of primitives passes through — no dict-like elements, no leak path."""

    @shield(purpose="support", scope=["pair"])
    def f():
        return {"pair": ("red", "blue"), "other": "dropped"}

    assert f() == {"pair": ("red", "blue")}


def test_scope_leaf_over_mapping_proxy_list_drops(caplog):
    """MappingProxyType is a Mapping but not a dict — the drop guard must catch it."""
    import logging
    from types import MappingProxyType

    @shield(purpose="support", scope=["users"])
    def f():
        return {
            "users": [MappingProxyType({"name": "Aria", "ssn": "111"})],
        }

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == {}
    assert "scope_bare_field_over_record_collection" in caplog.text


def test_scope_leaf_over_userdict_list_drops(caplog):
    """collections.UserDict is a Mapping but not a dict — the drop guard must catch it."""
    import logging
    from collections import UserDict

    class MyDict(UserDict):
        pass

    @shield(purpose="support", scope=["users"])
    def f():
        return {"users": [MyDict({"name": "Aria", "ssn": "111"})]}

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == {}
    assert "scope_bare_field_over_record_collection" in caplog.text


def test_scope_leaf_over_simplenamespace_list_drops(caplog):
    """SimpleNamespace is not a Mapping, but carries __dict__ fields — drop.

    Codex Re-Review P1: non-Mapping record objects (SimpleNamespace, ORM
    rows, any custom class with attribute storage) in a leaf-scope
    collection still leak their attribute fields. The record-like guard
    closes that shape.
    """
    import logging
    from types import SimpleNamespace

    @shield(purpose="support", scope=["users"])
    def f():
        return {"users": [SimpleNamespace(name="Aria", ssn="111")]}

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == {}
    assert "scope_bare_field_over_record_collection" in caplog.text


def test_scope_leaf_over_custom_object_list_drops(caplog):
    """Custom class instance with __dict__ fields triggers the drop."""
    import logging

    class Row:
        def __init__(self, name: str, ssn: str) -> None:
            self.name = name
            self.ssn = ssn

    @shield(purpose="support", scope=["users"])
    def f():
        return {"users": [Row("Aria", "111")]}

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == {}
    assert "scope_bare_field_over_record_collection" in caplog.text


def test_deny_fields_at_leaf_over_list_of_dicts_drops_whole_key():
    """Option C: deny_fields=['users'] drops the whole key when value is list-of-dicts."""

    @shield(purpose="billing", deny_fields=["users"])
    def f():
        return {"users": [{"ssn": "111"}], "count": 1}

    assert f() == {"count": 1}


def test_deny_fields_dot_notation_removes_per_element():
    """Option C: deny_fields=['users.ssn'] removes ssn from each dict element."""

    @shield(purpose="billing", deny_fields=["users.ssn"])
    def f():
        return {
            "users": [
                {"name": "Aria", "ssn": "111"},
                {"name": "Ben", "ssn": "222"},
            ]
        }

    assert f() == {"users": [{"name": "Aria"}, {"name": "Ben"}]}
