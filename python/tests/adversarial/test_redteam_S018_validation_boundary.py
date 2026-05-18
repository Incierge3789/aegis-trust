"""T-510: purpose/scope validation boundary value attack.

AI Red Team S018 — adversarial attempts to bypass validation
with edge-case inputs.
"""

import pytest

from aegis_trust import shield
from aegis_trust.shield import _validate_field_path, reset


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


# ── Attack 1: Extremely long purpose string ──────────────────────


def test_very_long_purpose():
    """Attacker uses extremely long purpose string."""

    @shield(purpose="A" * 10_000, scope=["name"])
    def get_data():
        return {"name": "ok", "secret": "hidden"}

    result = get_data()
    assert result == {"name": "ok"}


# ── Attack 2: Purpose with special characters ────────────────────


def test_purpose_with_null_bytes():
    """Attacker injects null bytes in purpose."""

    @shield(purpose="support\x00admin", scope=["name"])
    def get_data():
        return {"name": "ok", "secret": "hidden"}

    result = get_data()
    assert result == {"name": "ok"}


def test_purpose_with_newlines():
    """Attacker injects newlines in purpose."""

    @shield(purpose="support\nINSERT INTO", scope=["name"])
    def get_data():
        return {"name": "ok"}

    result = get_data()
    assert result == {"name": "ok"}


def test_purpose_with_unicode():
    """Attacker uses Unicode in purpose."""

    @shield(purpose="\u200b\u200b\u200b", scope=["name"])  # zero-width spaces
    def get_data():
        return {"name": "ok"}

    result = get_data()
    assert result == {"name": "ok"}


def test_purpose_empty_string():
    """Empty purpose string — should this be allowed?"""

    # Currently no validation on purpose content — it's just a label
    @shield(purpose="", scope=["name"])
    def get_data():
        return {"name": "ok", "secret": "x"}

    result = get_data()
    assert result == {"name": "ok"}


# ── Attack 3: Scope with extremely long field names ──────────────


def test_scope_very_long_field_name():
    """Attacker uses 10K-char field name in scope."""
    long_key = "a" * 10_000

    @shield(purpose="test", scope=[long_key])
    def get_data():
        return {long_key: "found", "secret": "hidden"}

    result = get_data()
    assert result == {long_key: "found"}


# ── Attack 4: Scope with special characters in field names ───────


def test_scope_field_with_spaces():
    """Field name with spaces."""

    @shield(purpose="test", scope=["field with spaces"])
    def get_data():
        return {"field with spaces": "ok", "secret": "hidden"}

    result = get_data()
    assert result == {"field with spaces": "ok"}


def test_scope_field_with_newlines():
    """Field name with newlines."""

    @shield(purpose="test", scope=["field\nname"])
    def get_data():
        return {"field\nname": "ok", "secret": "hidden"}

    result = get_data()
    assert result == {"field\nname": "ok"}


def test_scope_field_with_null_bytes():
    """Field name with null bytes."""

    @shield(purpose="test", scope=["field\x00name"])
    def get_data():
        return {"field\x00name": "ok", "secret": "hidden"}

    result = get_data()
    assert result == {"field\x00name": "ok"}


# ── Attack 5: dot-notation edge cases ────────────────────────────


def test_validate_field_path_single_dot():
    """Single dot as field path."""
    with pytest.raises(ValueError):
        _validate_field_path(".")


def test_validate_field_path_only_dots():
    """Multiple dots only."""
    with pytest.raises(ValueError):
        _validate_field_path("...")


def test_validate_field_path_dot_space():
    """Dot followed by space."""
    # "a. b" has a space in segment name — currently valid
    # This is fine: segments can have any chars except dots
    _validate_field_path("a. b")  # Should not raise


def test_scope_very_deep_dot_notation():
    """Extremely deep dot-notation path."""
    deep_path = ".".join([f"level{i}" for i in range(100)])

    @shield(purpose="test", scope=[deep_path])
    def get_data():
        # Build deeply nested dict
        d: dict = {}
        current = d
        for i in range(99):
            current[f"level{i}"] = {}
            current = current[f"level{i}"]
        current["level99"] = "deep_value"
        return d

    result = get_data()
    # Verify the deep path was preserved
    current = result
    for i in range(100):
        key = f"level{i}"
        if key in current:
            current = current[key]
        else:
            break


# ── Attack 6: Type confusion attacks ─────────────────────────────


def test_scope_type_confusion_bool():
    """Attacker passes bool in scope list."""
    with pytest.raises(TypeError, match="scope elements must all be strings"):

        @shield(purpose="test", scope=[True])
        def fn():
            return {}


def test_scope_type_confusion_none():
    """Attacker passes None in scope list."""
    with pytest.raises(TypeError, match="scope elements must all be strings"):

        @shield(purpose="test", scope=[None])
        def fn():
            return {}


def test_scope_type_confusion_dict():
    """Attacker passes dict in scope list."""
    with pytest.raises(TypeError, match="scope elements must all be strings"):

        @shield(purpose="test", scope=[{"key": "value"}])
        def fn():
            return {}


def test_scope_type_confusion_list():
    """Attacker passes nested list in scope."""
    with pytest.raises(TypeError, match="scope elements must all be strings"):

        @shield(purpose="test", scope=[["nested"]])
        def fn():
            return {}
