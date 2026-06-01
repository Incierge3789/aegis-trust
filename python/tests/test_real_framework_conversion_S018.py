"""S018 D1/P1 — real-framework conversion-failure leak + fail-closed tests.

`python/README.md` publicly claims `@shield` "works with" Pydantic v2,
Pydantic v1, and SQLAlchemy. The audit (correctly) refused to close on
duck-typed simulations alone. These tests install and drive the **genuine
library code paths** and assert, when the real conversion raises, that:

  - the data-return path fails closed (safe empty, no partial data), and
  - the default diagnostic surface leaks no secret value, no traceback, and
    no internal source path.

Authentic failure triggers (not overridden SDK methods):
  - Pydantic v2: a real ``@computed_field`` property raises inside the real
    ``model_dump()``.
  - Pydantic v1: a real ``pydantic.v1.BaseModel`` whose ``Any`` field holds a
    ``dict`` subclass whose ``.items()`` raises — pydantic v1's own
    ``_get_value`` calls it during the real ``.dict()``.
  - SQLAlchemy: a real mapped instance is detached from its Session, so the
    real ``__table__`` column walk's ``getattr`` raises ``DetachedInstanceError``
    (the canonical "DB session detached" scenario).
"""

import logging
from typing import Any

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset

pydantic = pytest.importorskip("pydantic")
sqlalchemy = pytest.importorskip("sqlalchemy")


def _messages(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def _has_traceback(caplog) -> bool:
    return any(r.exc_info is not None or r.exc_text for r in caplog.records)


_SECRET_NEEDLES = (
    "customer_ssn",
    "123-45-6789",
    "sk_live_",
    "patient_name",
    "Alice",
    "HIV",
    "diagnosis",
    "999-88-7777",
)


def _assert_no_leak(caplog, result):
    msgs = _messages(caplog)
    assert result == ""  # fail-closed (no partial data)
    for needle in _SECRET_NEEDLES:
        assert needle not in msgs, f"LEAKED: {needle!r}"
    assert not _has_traceback(caplog)
    assert "Traceback" not in msgs
    assert "conversion_failed" in msgs  # safe fixed diagnostic still emitted


@pytest.fixture(autouse=True)
def _clean():
    reset()
    yield
    reset()


def test_real_pydantic_v2_model_dump_failure(caplog):
    from pydantic import BaseModel, computed_field

    class Patient(BaseModel):
        name: str = "Aria"

        @computed_field  # type: ignore[prop-decorator]
        @property
        def record(self) -> str:
            # Realistic: a derived field that fails during serialization,
            # carrying the very PII/secret the SDK must not echo.
            raise RuntimeError(
                "customer_ssn=123-45-6789 stripe=sk_live_V2 patient_name=Alice diagnosis=HIV"
            )

    @shield(purpose="support", scope=["name"], mode="lite")
    def fetch():
        return Patient()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = fetch()

    assert "stage=pydantic_model_dump" in _messages(caplog)  # fixed stage label
    _assert_no_leak(caplog, result)


def test_real_pydantic_v1_dict_failure(caplog):
    import pydantic.v1 as pv1

    class EvilItems(dict):
        def items(self):  # invoked by pydantic v1 _get_value during .dict()
            raise RuntimeError("customer_ssn=123-45-6789 sk_live_V1 diagnosis=HIV")

    class Record(pv1.BaseModel):
        class Config:
            arbitrary_types_allowed = True

        name: str = "Aria"
        payload: Any = None

    @shield(purpose="support", scope=["name"], mode="lite")
    def fetch():
        return Record(payload=EvilItems(a=1))

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = fetch()

    assert "stage=pydantic_dict" in _messages(caplog)  # fixed stage label
    _assert_no_leak(caplog, result)


def test_real_sqlalchemy_table_walk_failure(caplog):
    import sqlalchemy as sa
    from sqlalchemy.orm import Session, declarative_base

    Base = declarative_base()

    class User(Base):
        __tablename__ = "users_s018"
        id = sa.Column(sa.Integer, primary_key=True)
        ssn = sa.Column(sa.String)

    engine = sa.create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    user = User(id=1, ssn="999-88-7777")
    session.add(user)
    session.commit()
    session.close()  # detach → column getattr raises DetachedInstanceError

    @shield(purpose="support", scope=["id"], mode="lite")
    def fetch():
        return user

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = fetch()

    msgs = _messages(caplog)
    assert "stage=sqlalchemy_conversion" in msgs  # fixed stage label
    # Fail-closed + no leak. The diagnostic surfaces only the fixed
    # `conversion_failed stage=sqlalchemy_conversion` marker — no exception
    # class name, no stored value; the stored ssn must never appear.
    assert result == ""
    for needle in _SECRET_NEEDLES:
        assert needle not in msgs, f"LEAKED: {needle!r}"
    assert not _has_traceback(caplog)
