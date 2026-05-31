"""S018 D1 — Python conversion-failure diagnostic.

When a record→dict conversion (Pydantic ``model_dump`` / ``.dict``,
``dataclasses.asdict``, SQLAlchemy ``__table__`` walk, NamedTuple
``_asdict``) *raises*, the original cause used to be swallowed and the
downstream symptom was reported as ``"cannot filter str"`` — misattributing
the failure to the wrong return type. These tests lock:

  1. the *original cause* is surfaced in a developer diagnostic,
  2. a genuine conversion failure is NOT re-attributed to "cannot filter str",
  3. a *genuinely unsupported* return type (bare scalar) keeps its existing
     "cannot filter <type>" diagnostic (the two cases stay distinguished), and
  4. fail-closed is preserved — no data is passed through on failure.
"""

import logging

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


class _Unpicklable:
    """A leaf value whose deep-copy raises — breaks ``dataclasses.asdict``."""

    def __deepcopy__(self, memo):
        raise RuntimeError("simulated asdict deepcopy failure")


@pytest.fixture(autouse=True)
def _clean():
    reset()
    yield
    reset()


def test_conversion_exception_surfaces_original_cause(caplog):
    class Broken:
        def model_dump(self):
            raise RuntimeError("db column 'ssn' is encrypted and cannot serialize")

    @shield(purpose="support", scope=["name"])
    def f():
        return Broken()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    # Fail-closed preserved.
    assert result == ""
    # Original cause is visible to the developer (type + message).
    assert "RuntimeError" in caplog.text
    assert "db column 'ssn' is encrypted" in caplog.text
    # The conversion shape that failed is named.
    assert "model_dump" in caplog.text
    # NOT misattributed to the downstream "cannot filter str" symptom.
    assert "cannot filter str" not in caplog.text


def test_dataclass_conversion_failure_diagnostic(caplog):
    import dataclasses

    @dataclasses.dataclass
    class Weird:
        # asdict() deep-copies leaf values; a field whose __deepcopy__ raises
        # breaks the conversion.
        bad: object = dataclasses.field(default_factory=_Unpicklable)

    @shield(purpose="support", scope=["bad"])
    def f():
        return Weird()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == ""
    assert "asdict" in caplog.text
    assert "cannot filter str" not in caplog.text


def test_genuinely_unsupported_type_keeps_its_diagnostic(caplog):
    # A bare scalar never enters a conversion branch — it is genuinely
    # unsupported, and must keep the existing "cannot filter int" message,
    # NOT the conversion-failure diagnostic.
    @shield(purpose="info", scope=["x"])
    def f():
        return 42

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == ""
    assert "cannot filter int" in caplog.text
    assert "conversion failed" not in caplog.text


def test_deny_fields_conversion_failure_also_fail_closed(caplog):
    class Broken:
        def model_dump(self):
            raise ValueError("boom")

    @shield(purpose="support", deny_fields=["ssn"])
    def f():
        return Broken()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    assert result == ""
    assert "model_dump" in caplog.text
    assert "cannot filter str" not in caplog.text
