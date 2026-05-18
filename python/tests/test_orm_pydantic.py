"""v0.7.0 — @shield auto-normalizes ORM / Pydantic / dataclass return values.

`_to_filterable()` runs at the top of `_filter_result` / `_deny_filter_result`
and converts well-known object shapes to `dict` before field filtering.
Detection is duck-typed — Pydantic and SQLAlchemy are never imported or
required by aegis-trust.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


try:
    import pydantic

    _PYDANTIC_AVAILABLE = True
    _PYDANTIC_MAJOR = int(pydantic.VERSION.split(".")[0])
except ImportError:
    _PYDANTIC_AVAILABLE = False
    _PYDANTIC_MAJOR = 0


requires_pydantic_v2 = pytest.mark.skipif(
    not _PYDANTIC_AVAILABLE or _PYDANTIC_MAJOR < 2,
    reason="pydantic v2 not installed",
)
requires_pydantic_v1 = pytest.mark.skipif(
    not _PYDANTIC_AVAILABLE or _PYDANTIC_MAJOR >= 2,
    reason="pydantic v1 not installed",
)


# ── dict / list pass-through (regression) ──────────────────────


def test_dict_still_filtered():
    """dict pass-through — unchanged from pre-v0.7.0."""

    @shield(purpose="support", scope=["name"])
    def f():
        return {"name": "Aria", "ssn": "111"}

    assert f() == {"name": "Aria"}


def test_list_of_dicts_still_filtered_with_dot_notation():
    """list[dict] with dot-notation scope — regression for existing behavior."""

    @shield(purpose="support", scope=["users.name"])
    def f():
        return {"users": [{"name": "A", "ssn": "1"}, {"name": "B", "ssn": "2"}]}

    assert f() == {"users": [{"name": "A"}, {"name": "B"}]}


# ── @dataclass ─────────────────────────────────────────────────


def test_dataclass_filtered():
    @dataclass
    class Customer:
        name: str
        ssn: str

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return Customer(name="Aria", ssn="111")

    assert get_customer() == {"name": "Aria"}


def test_dataclass_deny_fields():
    @dataclass
    class Customer:
        name: str
        ssn: str

    @shield(purpose="billing", deny_fields=["ssn"])
    def get_customer():
        return Customer(name="Aria", ssn="111")

    assert get_customer() == {"name": "Aria"}


# ── Pydantic v2 (optional dep) ─────────────────────────────────


@requires_pydantic_v2
def test_pydantic_v2_flat_filtered():
    from pydantic import BaseModel

    class Customer(BaseModel):
        name: str
        ssn: str

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return Customer(name="Aria", ssn="111")

    assert get_customer() == {"name": "Aria"}


@requires_pydantic_v2
def test_pydantic_v2_nested_filtered():
    from pydantic import BaseModel

    class Profile(BaseModel):
        age: int
        ssn: str

    class Customer(BaseModel):
        name: str
        profile: Profile

    @shield(purpose="support", scope=["name", "profile.age"])
    def get_customer():
        return Customer(name="Aria", profile=Profile(age=30, ssn="111"))

    assert get_customer() == {"name": "Aria", "profile": {"age": 30}}


# ── Pydantic v1 (optional dep; skip if only v2 installed) ──────


@requires_pydantic_v1
def test_pydantic_v1_flat_filtered():
    from pydantic import BaseModel

    class Customer(BaseModel):
        name: str
        ssn: str

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return Customer(name="Aria", ssn="111")

    assert get_customer() == {"name": "Aria"}


# ── SQLAlchemy (duck-typed shape; no dependency) ───────────────


class _FakeColumn:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeTable:
    def __init__(self, names: list[str]) -> None:
        self.columns = [_FakeColumn(n) for n in names]


try:
    import sqlalchemy as _sa  # noqa: F401

    _SQLA_AVAILABLE = True
except ImportError:
    _SQLA_AVAILABLE = False


requires_sqlalchemy = pytest.mark.skipif(
    not _SQLA_AVAILABLE,
    reason="sqlalchemy not installed",
)


@requires_sqlalchemy
def test_sqlalchemy_declarative_shape_filtered():
    """S022 R3: only real SQLAlchemy Declarative instances are normalized.

    Duck-typed `__table__.columns` is no longer accepted because it was a
    confused-deputy surface — attacker-controlled classes could forge the
    metadata. This test now uses a real ``DeclarativeBase`` subclass.
    """
    from sqlalchemy import Column, Integer, String
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):
        pass

    class Customer(Base):
        __tablename__ = "customers"
        id = Column(Integer, primary_key=True)
        name = Column(String, nullable=False)
        ssn = Column(String, nullable=False)

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return Customer(id=1, name="Aria", ssn="111")

    assert get_customer() == {"name": "Aria"}


def test_fake_sqla_shape_rejected_fail_closed():
    """S022 R3 / A3: duck-typed SQLA (attacker-controlled __table__) is
    rejected, so the normalizer doesn't trust forged column metadata."""

    class FakeORM:
        __table__ = _FakeTable(["name", "ssn"])

        def __init__(self, name: str, ssn: str) -> None:
            self.name = name
            self.ssn = ssn

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return FakeORM(name="Aria", ssn="111")

    result = get_customer()
    # Either fail-closed empty (probe rejected + no fallback path matched)
    # or filtered via the __dict__ fallback to {"name": "Aria"}. Either way
    # `ssn` MUST NOT be present.
    assert result in ("", {"name": "Aria"})
    if isinstance(result, dict):
        assert "ssn" not in result


# ── Top-level list of model instances ──────────────────────────


def test_top_level_list_of_dataclass_filtered():
    """Returning list[@dataclass] at the top level is handled by recursion."""

    @dataclass
    class Customer:
        name: str
        ssn: str

    @shield(purpose="support", scope=["name"])
    def list_customers():
        return [Customer(name="Aria", ssn="1"), Customer(name="Ben", ssn="2")]

    assert list_customers() == [{"name": "Aria"}, {"name": "Ben"}]


@requires_pydantic_v2
def test_top_level_list_of_pydantic_filtered():
    """Returning list[BaseModel] at the top level is handled by recursion."""
    from pydantic import BaseModel

    class Customer(BaseModel):
        name: str
        ssn: str

    @shield(purpose="support", scope=["name"])
    def list_customers():
        return [Customer(name="Aria", ssn="1"), Customer(name="Ben", ssn="2")]

    assert list_customers() == [{"name": "Aria"}, {"name": "Ben"}]


# ── SQLModel-like hybrid (Pydantic v2 wins over SQLAlchemy) ────


def test_sqlmodel_like_hybrid_prefers_pydantic_v2():
    """When an object has both `model_dump` AND `__table__.columns`, the
    Pydantic v2 branch wins. SQLModel is the canonical case: it subclasses
    Pydantic v2 and is also SQLAlchemy-Declarative-shaped. Selecting
    SQLAlchemy instead would lose Pydantic-specific serializer behavior
    (aliases, computed fields, validators)."""

    class Hybrid:
        """Simulated SQLModel: has both shapes, we assert v2 branch fires."""

        __table__ = _FakeTable(["name", "ssn"])

        def __init__(self, name: str, ssn: str) -> None:
            self.name = name
            self.ssn = ssn

        def model_dump(self) -> dict:
            # Deliberately DIFFERENT from __table__ traversal — this is the
            # branch we want to take. Pydantic-style aliasing / computed
            # fields would appear here in a real SQLModel.
            return {"name": self.name, "ssn": self.ssn, "pydantic_marker": True}

    @shield(purpose="support", scope=["name", "pydantic_marker"])
    def get_hybrid():
        return Hybrid(name="Aria", ssn="111")

    result = get_hybrid()
    # pydantic_marker proves model_dump ran (not __table__ walk).
    assert result == {"name": "Aria", "pydantic_marker": True}


# ── Fail-closed for unknown / exception ────────────────────────


def test_unknown_object_still_fail_closed(caplog):
    """Objects with no supported conversion still return '' (fail-closed)."""
    import logging

    class Opaque:
        def __init__(self) -> None:
            self.name = "Aria"
            self.ssn = "111"

    @shield(purpose="support", scope=["name"])
    def f():
        return Opaque()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == ""
    assert "fail-closed" in caplog.text


def test_conversion_exception_is_fail_closed():
    """If model_dump raises, _to_filterable returns '' and the result is empty."""

    class Broken:
        def model_dump(self):
            raise RuntimeError("simulated model_dump failure")

    @shield(purpose="support", scope=["name"])
    def f():
        return Broken()

    result = f()
    assert result == ""
