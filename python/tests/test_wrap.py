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


# ── S017 adversarial-sweep regressions ───────────────────────────────


def test_wrap_mixed_type_keys_do_not_crash() -> None:
    """S017 H5: a payload mixing string and non-string dict keys, where at least
    one key is filtered out, used to raise an uncaught TypeError from
    `sorted(removed)` (str vs int) — it propagated out of the public wrap() API
    (the @shield decorator path caught it and fail-closed). The removed-key
    paths are now sorted by their string form, so wrap() no longer crashes.
    """
    res = wrap({1: "x", "name": "a", "ssn": "S"}, purpose="p", scope=["name"])
    assert res.data == {"name": "a"}
    # both the int key and ssn are reported as removed (as strings, sorted)
    assert res.filtered_keys == ["1", "ssn"]


def test_wrap_deny_flattened_dotted_key_is_removed() -> None:
    """S017 H1: deny_fields=['card.cvv'] must remove a top-level key LITERALLY
    named 'card.cvv' (flattened-key API), not only a nested card->cvv. This was
    fail-OPEN: the literal key was kept and leaked, with no warning.
    """
    res = wrap({"card.cvv": "999", "name": "a"}, purpose="p", deny_fields=["card.cvv"])
    assert res.data == {"name": "a"}
    assert res.filtered_keys == ["card.cvv"]


def test_wrap_deny_nested_still_works() -> None:
    """S017 H1 guard: the nested deny interpretation is unchanged — a nested
    card->cvv is still removed while siblings are kept."""
    res = wrap(
        {"card": {"cvv": "9", "num": "1"}, "name": "a"},
        purpose="p",
        deny_fields=["card.cvv"],
    )
    assert res.data == {"card": {"num": "1"}, "name": "a"}
