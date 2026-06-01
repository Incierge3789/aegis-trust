"""S018 D1 — Python conversion-failure diagnostic (P1 secret-leak hardened).

When a record→dict conversion (Pydantic ``model_dump`` / ``.dict``,
``dataclasses.asdict``, SQLAlchemy ``__table__`` walk, NamedTuple ``_asdict``)
*raises*, the diagnostic must help a developer **without** leaking the failing
object's values. The original S018 implementation logged the exception message
and a full traceback (``exc_info``); an adversarial audit showed that leaked
``customer_ssn`` / ``stripe_secret_key`` / PHI / internal prompts through the
default log surface, violating the minimum-disclosure contract even though the
data-*return* path failed closed.

These tests lock the hardened contract:

  1. SAFE identifiers ARE surfaced — that a conversion failed, the converter
     shape, the object *type name*, the exception *class name*.
  2. NO exception message, NO traceback (``exc_info`` / ``exc_text``), NO
     ``repr(data)`` / ``str(data)`` of the failing object.
  3. a *genuinely unsupported* return type (bare scalar) keeps its existing
     "cannot filter <type>" diagnostic (the two cases stay distinguished), and
  4. fail-closed is preserved — no data is passed through on failure.
"""

import logging

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


def _messages(caplog) -> str:
    """Rendered log-record messages only.

    Deliberately NOT ``caplog.text`` — that includes pytest's own
    ``module:lineno`` decoration (e.g. ``shield.py:NNN``), which is a capture
    artifact, not part of the emitted diagnostic. We assert against what the
    SDK actually puts in the record.
    """
    return "\n".join(r.getMessage() for r in caplog.records)


def _has_traceback(caplog) -> bool:
    return any(r.exc_info is not None or r.exc_text for r in caplog.records)


class _Unpicklable:
    """A leaf value whose deep-copy raises — breaks ``dataclasses.asdict``."""

    def __deepcopy__(self, memo):
        raise RuntimeError("simulated asdict deepcopy failure customer_ssn=000-00-0000")


@pytest.fixture(autouse=True)
def _clean():
    reset()
    yield
    reset()


def test_conversion_failure_surfaces_safe_identifiers_only(caplog):
    class Broken:
        model_fields = {}  # pydantic-v2-like

        def model_dump(self):
            raise RuntimeError("db column 'ssn' is encrypted and cannot serialize")

    @shield(purpose="support", scope=["name"])
    def f():
        return Broken()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    # Fail-closed preserved.
    assert result == ""
    # SAFE identifiers ARE surfaced.
    assert "conversion failed" in msgs
    assert "model_dump" in msgs  # converter shape
    assert "RuntimeError" in msgs  # exception class name
    assert "Broken" in msgs  # object type name (safe; never calls instance repr)
    # The exception MESSAGE must NOT leak.
    assert "ssn" not in msgs
    assert "encrypted" not in msgs
    # No traceback / exc_info.
    assert not _has_traceback(caplog)
    # NOT misattributed to the downstream "cannot filter str" symptom.
    assert "cannot filter str" not in msgs


def test_adversarial_secrets_in_exception_message_do_not_leak(caplog):
    secret_msg = (
        "customer_ssn=123-45-6789 stripe_secret_key=sk_live_TEST_SECRET "
        "patient_name=Alice diagnosis=HIV internal_prompt=CONFIDENTIAL_SYSTEM_PROMPT"
    )

    class Broken:
        model_fields = {}

        def model_dump(self):
            raise RuntimeError(secret_msg)

    @shield(purpose="support", scope=["name"])
    def f():
        return Broken()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""  # fail-closed
    for needle in (
        "customer_ssn",
        "123-45-6789",
        "stripe_secret_key",
        "sk_live_TEST_SECRET",
        "patient_name",
        "Alice",
        "HIV",
        "diagnosis",
        "internal_prompt",
        "CONFIDENTIAL_SYSTEM_PROMPT",
    ):
        assert needle not in msgs, f"LEAKED secret needle: {needle!r}"
    # No traceback / internal source path in the emitted record.
    assert not _has_traceback(caplog)
    assert "Traceback" not in msgs


def test_adversarial_secret_in_object_repr_does_not_leak(caplog):
    """The failing object's ``__repr__`` / ``__str__`` must never be invoked —
    so a value-bearing or exception-raising repr cannot leak either."""

    class EvilRepr:
        model_fields = {}

        def model_dump(self):
            raise RuntimeError("boom")

        def __repr__(self):
            return "EvilRepr(customer_ssn=999-99-9999, stripe_secret_key=sk_live_REPR)"

        __str__ = __repr__

    @shield(purpose="support", scope=["name"])
    def f():
        return EvilRepr()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "999-99-9999" not in msgs
    assert "sk_live_REPR" not in msgs
    assert "customer_ssn" not in msgs


def test_object_repr_that_raises_does_not_break_diagnostic(caplog):
    """If the failing object's ``__repr__`` itself raises, the diagnostic must
    still emit cleanly (because we never call repr on the instance)."""

    class ReprBomb:
        model_fields = {}

        def model_dump(self):
            raise RuntimeError("boom")

        def __repr__(self):
            raise RuntimeError("repr explodes with secret sk_live_BOOM")

        __str__ = __repr__

    @shield(purpose="support", scope=["name"])
    def f():
        return ReprBomb()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()  # must not raise

    msgs = _messages(caplog)
    assert result == ""
    assert "conversion failed" in msgs
    assert "ReprBomb" in msgs
    assert "sk_live_BOOM" not in msgs


def test_dataclass_conversion_failure_diagnostic(caplog):
    import dataclasses

    @dataclasses.dataclass
    class Weird:
        # asdict() deep-copies leaf values; a field whose __deepcopy__ raises
        # breaks the conversion. The deepcopy error message embeds a secret-like
        # token to prove it is not echoed.
        bad: object = dataclasses.field(default_factory=_Unpicklable)

    @shield(purpose="support", scope=["bad"])
    def f():
        return Weird()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "asdict" in msgs  # converter shape surfaced
    assert "000-00-0000" not in msgs  # deepcopy error message NOT echoed
    assert not _has_traceback(caplog)
    assert "cannot filter str" not in msgs


def test_genuinely_unsupported_type_keeps_its_diagnostic(caplog):
    # A bare scalar never enters a conversion branch — it is genuinely
    # unsupported, and must keep the existing "cannot filter int" message,
    # NOT the conversion-failure diagnostic.
    @shield(purpose="info", scope=["x"])
    def f():
        return 42

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "cannot filter int" in msgs
    assert "conversion failed" not in msgs


def test_deny_fields_conversion_failure_also_fail_closed(caplog):
    class Broken:
        model_fields = {}

        def model_dump(self):
            raise ValueError("boom customer_ssn=555-55-5555")

    @shield(purpose="support", deny_fields=["ssn"])
    def f():
        return Broken()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "model_dump" in msgs
    assert "555-55-5555" not in msgs
    assert "cannot filter str" not in msgs
