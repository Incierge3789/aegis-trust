"""S022 A10: NamedTuple path missing from `_to_filterable`.

Attack surface: `typing.NamedTuple` / `collections.namedtuple` instances
are tuple subclasses with named fields via `_asdict()`. Current
`_to_filterable` doesn't detect them — they fall through to "unknown"
path. In a list-of-NamedTuple scenario, the leaf-scope drop at line 198
DOES fire (tuple check), but a direct NamedTuple return is not
normalized to dict for field filtering.

Plan Review R10: add NamedTuple detection (`hasattr(_asdict) and
isinstance(tuple)`) to `_to_filterable`.
"""

from __future__ import annotations

from collections import namedtuple
from typing import NamedTuple

from aegis_trust import shield


class UserNT(NamedTuple):
    name: str
    ssn: str


OldStyle = namedtuple("OldStyle", ["name", "ssn"])


def test_namedtuple_direct_return_filters_by_scope():
    """A10/R10: direct NamedTuple return must be normalized to dict
    and filtered by scope (not leak ssn)."""

    @shield(purpose="support", scope=["name"])
    def get():
        return UserNT(name="Tanaka", ssn="123-45-6789")

    result = get()
    # R10 accepted outcomes:
    #   A. {"name": "Tanaka"} (normalized via _asdict + filtered)
    #   B. "" fail-closed
    # UNACCEPTABLE: tuple-like with ssn still accessible
    if isinstance(result, dict):
        assert "ssn" not in result, "A10: NamedTuple dict path leaked ssn"
    elif isinstance(result, tuple):
        # If returned as tuple, must not expose ssn
        assert getattr(result, "ssn", None) is None, "A10: NamedTuple tuple leaked ssn"


def test_namedtuple_old_style_filters_by_scope():
    """A10/R10: collections.namedtuple works identically."""

    @shield(purpose="support", scope=["name"])
    def get():
        return OldStyle(name="Tanaka", ssn="123-45-6789")

    result = get()
    if isinstance(result, dict):
        assert "ssn" not in result, "A10: old-style namedtuple leaked ssn"
    elif isinstance(result, tuple):
        assert getattr(result, "ssn", None) is None


def test_list_of_namedtuple_leaf_scope_drops():
    """A10/R10: list[NamedTuple] under leaf scope drops (fail-closed).

    This already works via `_is_record_like` (NamedTuple has _asdict()
    — post-R10 it matches a probe). Pre-R10: NamedTuple has __dict__
    on Python 3.13+? Verify via `__dict__` fallback line 174.
    """

    @shield(purpose="support", scope=["users"])
    def get():
        return {"users": [UserNT(name="Tanaka", ssn="123-45-6789")]}

    result = get()
    if "users" in result:
        for u in result["users"]:
            assert getattr(u, "ssn", None) is None, "A10: list[NT] leaked ssn"
