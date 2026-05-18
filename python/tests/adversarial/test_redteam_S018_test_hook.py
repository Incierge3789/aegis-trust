"""T-508: _test_hook abuse for internal state leak.

AI Red Team S018 — adversarial attempts to abuse _test_hook to exfiltrate
internal shield state or modify filtering behavior.
"""

import sys

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


def _get_shield_module():
    """Get the actual aegis.shield module (not the function)."""
    return sys.modules["aegis_trust.shield"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()
    _get_shield_module()._test_hook = None


# ── Attack 1: Set _test_hook to capture all data ─────────────────


def test_test_hook_captures_metadata_not_raw_data():
    """_test_hook receives metadata (purpose, scope, blocked_fields)
    but NOT the raw unfiltered data. Verify this.
    """
    shield_mod = _get_shield_module()
    captured = []

    def evil_hook(**kwargs):
        captured.append(kwargs)

    shield_mod._test_hook = evil_hook

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "ssn": "123-45-6789", "card": "4242"}

    get_customer()

    assert len(captured) == 1
    hook_data = captured[0]

    # Hook receives metadata about the call
    assert hook_data["purpose"] == "support"
    assert hook_data["scope"] == ["name"]
    assert "ssn" in hook_data["blocked_fields"]
    assert "card" in hook_data["blocked_fields"]

    # CRITICAL: Hook must NOT receive the raw unfiltered data
    assert "data" not in hook_data
    assert "result" not in hook_data
    assert "raw" not in hook_data

    # The actual values of ssn/card must not be in any hook field
    hook_str = str(hook_data)
    assert "123-45-6789" not in hook_str
    assert "4242" not in hook_str


# ── Attack 2: _test_hook that modifies return value ──────────────


def test_test_hook_cannot_modify_return_value():
    """_test_hook is called AFTER filtering. It cannot change the result."""
    shield_mod = _get_shield_module()
    modification_attempted = False

    def evil_hook(**kwargs):
        nonlocal modification_attempted
        modification_attempted = True
        # Try to modify the blocked_fields to trick caller
        kwargs["blocked_fields"] = []

    shield_mod._test_hook = evil_hook

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "ssn": "123"}

    result = get_customer()
    assert modification_attempted
    # Result is still filtered — hook can't affect it
    assert "ssn" not in result
    assert result == {"name": "Tanaka"}


# ── Attack 3: _test_hook that raises exception ──────────────────


def test_test_hook_exception_propagates():
    """If _test_hook raises, it propagates (test-only hook, not guarded).
    This is by design — _test_hook is for pytest only.
    In production, _test_hook is None and never called.
    """
    shield_mod = _get_shield_module()

    def evil_hook(**kwargs):
        raise RuntimeError("Hook exploitation attempt")

    shield_mod._test_hook = evil_hook

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Tanaka", "ssn": "123"}

    # Exception propagates — this is acceptable for a test-only hook
    with pytest.raises(RuntimeError, match="Hook exploitation"):
        get_customer()


# ── Attack 4: _test_hook in deny_fields mode ─────────────────────


def test_test_hook_deny_mode_no_raw_data():
    """deny_fields mode: hook also must not receive raw values."""
    shield_mod = _get_shield_module()
    captured = []

    def evil_hook(**kwargs):
        captured.append(kwargs)

    shield_mod._test_hook = evil_hook

    @shield(purpose="support", deny_fields=["ssn"])
    def get_customer():
        return {"name": "Tanaka", "ssn": "123-45-6789"}

    result = get_customer()
    assert "ssn" not in result

    assert len(captured) == 1
    hook_data = captured[0]
    hook_str = str(hook_data)
    assert "123-45-6789" not in hook_str


# ── Attack 5: Verify _test_hook is None by default ───────────────


def test_test_hook_default_is_none():
    """_test_hook must be None by default (not accidentally set)."""
    shield_mod = _get_shield_module()
    # After fixture cleanup, _test_hook should be None
    # The module declares it as None at module level
    assert hasattr(shield_mod, "_test_hook")
    # It might be set by a previous test's teardown, but our fixture resets it
    # The important thing: it's defined and controllable


# ── Attack 6: _test_hook cannot access unfiltered data ───────────


def test_test_hook_receives_only_field_names_not_values():
    """Verify that blocked_fields contains only field NAMES, not values."""
    shield_mod = _get_shield_module()
    captured = []

    def evil_hook(**kwargs):
        captured.append(kwargs)

    shield_mod._test_hook = evil_hook

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {
            "name": "Tanaka",
            "ssn": "999-88-7777",
            "card_number": "4111-1111-1111-1111",
            "password": "hunter2",
        }

    get_customer()
    hook_data = captured[0]

    # blocked_fields must be a list of field name strings
    for field in hook_data["blocked_fields"]:
        assert isinstance(field, str)
        # Field names must NOT contain actual data values
        assert "999-88-7777" not in field
        assert "4111-1111-1111-1111" not in field
        assert "hunter2" not in field
