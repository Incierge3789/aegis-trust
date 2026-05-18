"""Tests for @shield decorator — async function support."""

import inspect

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


# ── Async basic filtering ───────────────────────────────────


@pytest.mark.asyncio
async def test_async_filters_dict():
    @shield(purpose="support", scope=["name", "issue"])
    async def get_customer():
        return {
            "name": "Tanaka Taro",
            "email": "tanaka@example.com",
            "card": "4242-****-****-1234",
            "issue": "Login problem",
        }

    result = await get_customer()
    assert result == {"name": "Tanaka Taro", "issue": "Login problem"}
    assert "email" not in result


@pytest.mark.asyncio
async def test_async_empty_scope():
    @shield(purpose="audit", scope=[])
    async def get_data():
        return {"secret": "value"}

    assert await get_data() == {}


@pytest.mark.asyncio
async def test_async_list_of_dicts():
    @shield(purpose="analytics", scope=["id"])
    async def list_items():
        return [{"id": 1, "secret": "a"}, {"id": 2, "secret": "b"}]

    result = await list_items()
    assert result == [{"id": 1}, {"id": 2}]


# ── Async non-dict: fail-closed (AO-002) ────────────────────


@pytest.mark.asyncio
async def test_async_scope_nested():
    @shield(purpose="support", scope=["name", "details.age"])
    async def get_customer():
        return {
            "name": "Tanaka",
            "details": {"age": 30, "ssn": "123-45-6789"},
        }

    result = await get_customer()
    assert result == {"name": "Tanaka", "details": {"age": 30}}


@pytest.mark.asyncio
async def test_async_non_dict_returns_empty():
    @shield(purpose="info", scope=["x"])
    async def get_number():
        return 42

    assert await get_number() == ""


# ── Async preserves coroutine nature ────────────────────────


def test_async_decorated_is_coroutine():
    @shield(purpose="test", scope=["a"])
    async def fn():
        return {"a": 1}

    assert inspect.iscoroutinefunction(fn)


def test_sync_decorated_is_not_coroutine():
    @shield(purpose="test", scope=["a"])
    def fn():
        return {"a": 1}

    assert not inspect.iscoroutinefunction(fn)


# ── Async with arguments ────────────────────────────────────


@pytest.mark.asyncio
async def test_async_passes_args():
    @shield(purpose="lookup", scope=["name"])
    async def get_user(user_id: int, *, active: bool = True):
        return {"name": f"User-{user_id}", "active": active, "secret": "x"}

    result = await get_user(42, active=False)
    assert result == {"name": "User-42"}


# ── Async metadata preserved ────────────────────────────────


def test_async_preserves_metadata():
    @shield(purpose="test", scope=["x"])
    async def my_async_func():
        """Async docstring."""
        return {"x": 1}

    assert my_async_func.__name__ == "my_async_func"
    assert my_async_func.__doc__ == "Async docstring."


# ── Async deny_fields ──────────────────────────────────────


@pytest.mark.asyncio
async def test_async_deny_fields():
    @shield(purpose="billing", deny_fields=["card", "ssn"])
    async def get_customer():
        return {
            "name": "Tanaka Taro",
            "card": "4242-****-****-1234",
            "ssn": "123-45-6789",
            "plan": "enterprise",
        }

    result = await get_customer()
    assert result == {"name": "Tanaka Taro", "plan": "enterprise"}
    assert "card" not in result
    assert "ssn" not in result


@pytest.mark.asyncio
async def test_async_deny_fields_nested():
    @shield(purpose="billing", deny_fields=["profile.ssn"])
    async def get_customer():
        return {
            "name": "Tanaka",
            "profile": {"ssn": "123-45-6789", "plan": "enterprise"},
        }

    result = await get_customer()
    assert result == {"name": "Tanaka", "profile": {"plan": "enterprise"}}
    assert "ssn" not in result["profile"]


@pytest.mark.asyncio
async def test_async_deny_fields_list_of_dicts():
    @shield(purpose="analytics", deny_fields=["secret"])
    async def list_items():
        return [{"id": 1, "secret": "a"}, {"id": 2, "secret": "b"}]

    result = await list_items()
    assert result == [{"id": 1}, {"id": 2}]


# ── M1 regression: scope bypass scalar passthrough (AO-002) ─────


@pytest.mark.asyncio
async def test_async_scope_scalar_where_dict_expected_drops_key():
    """AO-002 regression (S013/M1): async scalar passthrough must be dropped."""

    @shield(purpose="support", scope=["name", "profile.age"])
    async def get_customer():
        return {"name": "Tanaka", "profile": "secret_string"}

    result = await get_customer()
    assert result == {"name": "Tanaka"}
    assert "profile" not in result


# ── M2 regression: exception sanitization (AO-002) ──────────────


@pytest.mark.asyncio
async def test_async_exception_returns_empty():
    """AO-002 regression (S013/M2): async exceptions must not propagate."""

    @shield(purpose="support", scope=["name"])
    async def get_customer():
        raise RuntimeError("DB error: password=secret123")

    result = await get_customer()
    assert result == ""
