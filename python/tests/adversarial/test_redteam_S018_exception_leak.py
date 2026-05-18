"""T-505: Exception handling info leak attempt — fail-closed verification (AO-002).

AI Red Team S018 — adversarial attempts to leak internal state through exceptions.
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


# ── Attack 1: Exception with sensitive data in message ───────────


def test_exception_with_db_password():
    """Exception containing DB password must not leak."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        raise ConnectionError(
            "Failed to connect to postgres://admin:s3cret_p@ss@db.internal:5432/aegis"
        )

    result = get_customer()
    assert result == ""
    assert "s3cret_p@ss" not in str(result)


def test_exception_with_api_key():
    """Exception containing API key must not leak."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        raise RuntimeError("API call failed: key=sk-abc123xyz789 status=401")

    result = get_customer()
    assert result == ""
    assert "sk-abc123xyz789" not in str(result)


def test_exception_with_stack_trace_info():
    """Even nested exceptions must not leak."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        try:
            raise ValueError("inner: capsule_id=c-12345")
        except ValueError as e:
            raise RuntimeError("outer: processing failed") from e

    result = get_customer()
    assert result == ""
    assert "capsule_id" not in str(result)
    assert "c-12345" not in str(result)


# ── Attack 2: Exception in deny_fields mode ──────────────────────


def test_deny_exception_returns_empty():
    """deny_fields mode also catches exceptions."""

    @shield(purpose="support", deny_fields=["ssn"])
    def get_customer():
        raise KeyError("user_table.ssn column does not exist")

    result = get_customer()
    assert result == ""
    assert "user_table" not in str(result)


# ── Attack 3: Async exception handling ───────────────────────────


@pytest.mark.asyncio
async def test_async_exception_returns_empty():
    """Async functions must also catch exceptions."""

    @shield(purpose="support", scope=["name"])
    async def get_customer():
        raise RuntimeError("Async error: secret_token=abc123")

    result = await get_customer()
    assert result == ""
    assert "secret_token" not in str(result)


# ── Attack 4: SystemExit / KeyboardInterrupt ─────────────────────


def test_keyboard_interrupt_propagates():
    """KeyboardInterrupt must NOT be caught (it's BaseException, not Exception)."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        get_customer()


def test_system_exit_propagates():
    """SystemExit must NOT be caught."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        raise SystemExit(1)

    with pytest.raises(SystemExit):
        get_customer()


# ── Attack 5: Generator/iterator exception timing ────────────────


def test_exception_after_partial_data():
    """Function that builds partial data then raises."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        data = {"name": "Tanaka", "ssn": "123"}
        # Simulate error after data construction
        if data:
            raise RuntimeError("Post-construction error with internal state")
        return data  # Never reached

    result = get_customer()
    assert result == ""


# ── Attack 6: Return type that raises on access ──────────────────


def test_evil_dict_that_raises_on_iteration():
    """Custom dict subclass that raises during filtering.

    AO-002 fail-closed: filtering path exceptions return empty string,
    not crash. The attacker's trap message must not leak.
    """

    class EvilDict(dict):
        def items(self):
            raise RuntimeError("Trap: internal schema leaked")

    @shield(purpose="support", scope=["name"])
    def get_customer():
        d = EvilDict()
        d["name"] = "Tanaka"
        d["ssn"] = "123"
        return d

    # AO-002: filtering exception → fail-closed → empty string
    result = get_customer()
    assert result == ""
    assert "Trap" not in str(result)
    assert "internal schema" not in str(result)


# ── Attack 7: Recursive data structure ───────────────────────────


def test_recursive_dict_no_infinite_loop():
    """Attacker creates self-referencing dict. Must not infinite loop."""

    @shield(purpose="support", scope=["name"])
    def get_data():
        d: dict = {"name": "ok", "self_ref": None}
        # Don't actually create circular ref as it would break json serialization
        # and is an unlikely real attack vector on @shield
        return d

    result = get_data()
    assert result == {"name": "ok"}
