"""Unit tests for the Python `wrap()` direct value filter (Node SDK parity).

Behaviour parity (data + removed keys) across SDKs is pinned separately by the
shared corpus (test_filter_parity_corpus.py). This file locks `wrap`'s own
contract: the ShieldResult shape and the machine-parseable validation errors.
"""

from __future__ import annotations

import pytest

from aegis_trust import ShieldResult, wrap
from aegis_trust.errors import AegisValidationError
from aegis_trust.types import Mode


def test_wrap_scope_returns_shieldresult() -> None:
    res = wrap({"name": "Aria", "ssn": "x"}, purpose="support", scope=["name"])
    assert isinstance(res, ShieldResult)
    assert res.data == {"name": "Aria"}
    assert res.filtered_keys == ["ssn"]
    assert res.mode is Mode.LITE
    assert res.purpose == "support"
    assert res.scope == ["name"]


def test_wrap_deny_fields() -> None:
    res = wrap({"name": "Aria", "ssn": "x"}, purpose="p", deny_fields=["ssn"])
    assert res.data == {"name": "Aria"}
    assert res.filtered_keys == ["ssn"]
    assert res.scope == []


def test_wrap_empty_scope_discloses_nothing() -> None:
    res = wrap({"name": "Aria", "ssn": "x"}, purpose="p", scope=[])
    assert res.data == {}
    assert sorted(res.filtered_keys) == ["name", "ssn"]


def test_wrap_purpose_required() -> None:
    with pytest.raises(AegisValidationError) as ei:
        wrap({"a": 1}, purpose="", scope=["a"])
    assert ei.value.code == "aegis.wrap.purpose.required"


def test_wrap_spec_required_when_neither_given() -> None:
    with pytest.raises(AegisValidationError) as ei:
        wrap({"a": 1}, purpose="p")
    assert ei.value.code == "aegis.wrap.spec.required"


def test_wrap_scope_and_deny_mutually_exclusive() -> None:
    with pytest.raises(AegisValidationError) as ei:
        wrap({"a": 1}, purpose="p", scope=["a"], deny_fields=["a"])
    assert ei.value.code == "aegis.wrap.spec.conflict"


def test_wrap_deny_fields_empty_invalid() -> None:
    with pytest.raises(AegisValidationError) as ei:
        wrap({"a": 1}, purpose="p", deny_fields=[])
    assert (
        ei.value.code == "aegis.wrap.spec.required"
    )  # empty deny + no scope = no spec


def test_wrap_invalid_field_path() -> None:
    with pytest.raises(AegisValidationError):
        wrap({"a": 1}, purpose="p", scope=["a..b"])
