"""S018 D1 — Python conversion-failure diagnostic (P1 + P2 secret-leak hardened).

When a record→dict conversion (Pydantic ``model_dump`` / ``.dict``,
``dataclasses.asdict``, SQLAlchemy ``__table__`` walk, NamedTuple ``_asdict``)
*raises*, the diagnostic must help a developer **without** leaking any
application-controlled string. Two audit rounds shaped this contract:

  P1 — the original build logged the exception message + traceback (``exc_info``),
       leaking ``customer_ssn`` / ``stripe_secret_key`` / PHI / internal prompts.
  P2 — the P1 fix still surfaced ``type(cause).__name__`` / ``type(data).__name__``;
       an independent re-audit showed a *dynamically named* exception/object
       class leaks its name (e.g. ``type("customer_ssn_123_..._Error", ...)``).

Hardened contract — the default diagnostic emits ONLY SDK-controlled fixed
strings: a ``conversion_failed`` marker, a fixed ``stage=<label>`` enum, and a
fixed remediation. It surfaces NO exception message, NO traceback, NO
``repr``/``str`` of the object, NO type/exception class name, and NO
``trace_id`` (P2-2: the trace_id validator accepts secret-shaped tokens, so it
is withheld from the diagnostic too). Fail-closed (return ``""``) is preserved.
"""

import logging

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


def _messages(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def _has_traceback(caplog) -> bool:
    return any(r.exc_info is not None or r.exc_text for r in caplog.records)


class _Unpicklable:
    def __deepcopy__(self, memo):
        raise RuntimeError("simulated asdict deepcopy failure customer_ssn=000-00-0000")


@pytest.fixture(autouse=True)
def _clean():
    reset()
    yield
    reset()


def test_conversion_failure_surfaces_only_fixed_stage_label(caplog):
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
    assert result == ""  # fail-closed
    # SDK-controlled fixed strings ARE surfaced.
    assert "conversion_failed" in msgs
    assert "stage=pydantic_model_dump" in msgs
    # NO application-controlled identifiers: exception message, exception class
    # name, or object type name.
    assert "ssn" not in msgs
    assert "encrypted" not in msgs
    assert "RuntimeError" not in msgs  # exception class name withheld
    assert "Broken" not in msgs  # object type name withheld
    assert not _has_traceback(caplog)
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
    assert result == ""
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
    assert not _has_traceback(caplog)
    assert "Traceback" not in msgs


def test_adversarial_secret_shaped_trace_id_not_surfaced(caplog):
    """P2-2 (independent CAG finding): a secret-shaped trace_id that passes the
    shape validator (`^[A-Za-z0-9._:-]{1,128}$` — underscores allowed) must NOT
    be surfaced on the conversion diagnostic surface."""
    from aegis_trust.trace import trace_context

    class Broken:
        model_fields = {}

        def model_dump(self):
            raise RuntimeError("boom")

    @shield(purpose="support", scope=["name"])
    def f():
        return Broken()

    secret_trace = "sk_live_TRACEIDSECRET_abcdef"  # passes the trace_id validator
    with caplog.at_level(logging.WARNING, logger="aegis"):
        with trace_context(secret_trace):
            result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "conversion_failed" in msgs  # fixed marker still emitted
    assert "sk_live_TRACEIDSECRET" not in msgs, "LEAKED via trace_id"
    assert secret_trace not in msgs
    assert (
        "trace_id" not in msgs
    )  # trace_id no longer surfaced on the diagnostic at all


def test_adversarial_secret_in_exception_class_name_does_not_leak(caplog):
    """P2-1: a dynamically named exception class must not leak its name."""
    EvilExc = type(
        "customer_ssn_123_45_6789_sk_live_TEST_SECRET_Error", (RuntimeError,), {}
    )

    class Broken:
        model_fields = {}

        def model_dump(self):
            raise EvilExc("boom")

    @shield(purpose="support", scope=["name"])
    def f():
        return Broken()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "conversion_failed" in msgs  # fixed marker still emitted
    for needle in ("customer_ssn", "123_45_6789", "123-45-6789", "sk_live_TEST_SECRET"):
        assert needle not in msgs, f"LEAKED via exception class name: {needle!r}"


def test_adversarial_secret_in_object_type_name_does_not_leak(caplog):
    """P2-1: a dynamically named return-object class must not leak its name."""

    def _boom(self):
        raise RuntimeError("boom")

    EvilType = type(
        "patient_name_Alice_diagnosis_HIV_CONFIDENTIAL_SYSTEM_PROMPT_Model",
        (object,),
        {"model_fields": {}, "model_dump": _boom},
    )

    @shield(purpose="support", scope=["name"])
    def f():
        return EvilType()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "conversion_failed" in msgs
    for needle in (
        "patient_name",
        "Alice",
        "diagnosis",
        "HIV",
        "CONFIDENTIAL_SYSTEM_PROMPT",
    ):
        assert needle not in msgs, f"LEAKED via object type name: {needle!r}"


def test_adversarial_secret_in_unsupported_object_type_name_does_not_leak(caplog):
    """P2-1: the unsupported-return-shape path must not leak the type name."""
    EvilOpaque = type("stripe_secret_key_sk_live_OPAQUE_LEAK_Thing", (object,), {})

    @shield(purpose="info", scope=["x"])
    def f():
        return EvilOpaque()  # not convertible, not dict/list → unsupported

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "unsupported_return_shape" in msgs  # fixed marker
    assert "sk_live_OPAQUE_LEAK" not in msgs
    assert "stripe_secret_key" not in msgs


def test_adversarial_secret_in_object_repr_does_not_leak(caplog):
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
    assert "conversion_failed" in msgs
    assert "ReprBomb" not in msgs  # object type name withheld
    assert "sk_live_BOOM" not in msgs


def test_dataclass_conversion_failure_diagnostic(caplog):
    import dataclasses

    @dataclasses.dataclass
    class Weird:
        bad: object = dataclasses.field(default_factory=_Unpicklable)

    @shield(purpose="support", scope=["bad"])
    def f():
        return Weird()

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "stage=dataclass_conversion" in msgs  # fixed label surfaced
    assert "000-00-0000" not in msgs  # deepcopy error message NOT echoed
    assert "Weird" not in msgs  # object type name withheld
    assert not _has_traceback(caplog)
    assert "cannot filter str" not in msgs


def test_genuinely_unsupported_type_uses_distinct_fixed_marker(caplog):
    # A bare scalar is genuinely unsupported → distinct fixed marker
    # ``unsupported_return_shape``, NOT the conversion-failure marker, and the
    # type name is withheld.
    @shield(purpose="info", scope=["x"])
    def f():
        return 42

    with caplog.at_level(logging.WARNING, logger="aegis"):
        result = f()

    msgs = _messages(caplog)
    assert result == ""
    assert "unsupported_return_shape" in msgs
    assert "conversion_failed" not in msgs  # distinguished from conversion failure
    assert "cannot filter int" not in msgs  # old type-bearing message gone
    # (type-name withholding for opaque/dynamic types is covered by
    # test_adversarial_secret_in_unsupported_object_type_name_does_not_leak)


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
    assert "stage=pydantic_model_dump" in msgs
    assert "555-55-5555" not in msgs
    assert "cannot filter str" not in msgs
