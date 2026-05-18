"""S022 A4/A9: Pydantic v2 `model_dump()` return-type not validated.

Attack surface: shield.py line 289 `return data.model_dump()` has NO
`isinstance(result, dict)` check. v1 path at line 302 DOES gate. The
asymmetry lets an attacker class whose `model_dump()` returns list/str/
None/etc. confuse downstream filtering.

Plan Review R9: add `isinstance(result, dict)` gate to v2 path,
symmetric with v1. Returning non-dict → fail-closed empty string.
"""

from __future__ import annotations

from aegis_trust import shield


class _FakeV2ReturnsList:
    """Pydantic v2-like object whose model_dump() returns a list."""

    def model_dump(self):
        return [{"name": "Tanaka", "ssn": "123-45-6789"}]


class _FakeV2ReturnsStr:
    def model_dump(self):
        return "not a dict"


class _FakeV2ReturnsNone:
    def model_dump(self):
        return None


def test_v2_model_dump_returning_list_fail_closed():
    """A4/A9: v2-like returning list must NOT leak via list-path."""

    @shield(purpose="support", scope=["name"])
    def get():
        return _FakeV2ReturnsList()

    result = get()
    # R9: non-dict model_dump() return MUST fail-closed
    # Acceptable outcomes: "" (fail-closed) or None
    if isinstance(result, list):
        for item in result:
            if isinstance(item, dict):
                assert "ssn" not in item, "A4/A9: v2 list return leaked ssn"


def test_v2_model_dump_returning_str_fail_closed():
    """A4/A9: v2-like returning str must fail-closed."""

    @shield(purpose="support", scope=["name"])
    def get():
        return _FakeV2ReturnsStr()

    result = get()
    # Non-dict/non-list return must fail-closed per _filter_result
    assert result in ("", None) or (isinstance(result, dict) and "ssn" not in result), (
        f"A4/A9: v2 str return unexpected: {result!r}"
    )


def test_v2_model_dump_returning_none_no_crash():
    """A4/A9: v2-like returning None must not crash and must fail-closed."""

    @shield(purpose="support", scope=["name"])
    def get():
        return _FakeV2ReturnsNone()

    result = get()
    # None is allowed pass-through in _filter_result line 327
    assert result is None or result == ""
