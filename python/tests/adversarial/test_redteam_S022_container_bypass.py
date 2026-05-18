"""S022 A2/A5/A13: traversable Collection bypass (non list/tuple).

Attack surface: shield.py `_filter_dict` leaf-drop at line 198 only fires
on ``isinstance(v, (list, tuple))``. Other non-str/non-bytes/non-Mapping
containers carrying record-like elements skip the fail-closed drop and
leak inner fields past a bare leaf scope.

These tests MUST pass (defense holds). A failure = AO-002 violation.

S021 defer regression (A2/E3): collections.deque of dicts.
Plan Review R1: generalize to "non-str/non-bytes/non-Mapping Collection".
"""

from __future__ import annotations

import array
from collections import deque

from aegis_trust import shield

# ── A2: collections.deque silent-pass ──────────────────────────────


def test_deque_of_dicts_leaf_scope_drops_fail_closed():
    """A2: leaf scope over deque[dict] MUST drop (fail-closed)."""

    @shield(purpose="support", scope=["users"])
    def get_customers():
        return {"users": deque([{"name": "Tanaka", "ssn": "123-45-6789"}])}

    result = get_customers()
    # Fail-closed: either drop the key, or the inner ssn must be absent.
    if "users" in result:
        for u in result["users"]:
            assert "ssn" not in u, "A2: deque leaf-scope leaked ssn"


# ── A5: misc Sequence — memoryview / array / range / custom iter ───


def test_set_of_dicts_leaf_scope_drops_fail_closed():
    """A5/R1: leaf scope over set carrying dict-like objects drops."""

    class Hashable:
        __slots__ = ("name", "ssn")

        def __init__(self, n, s):
            self.name = n
            self.ssn = s

        def __hash__(self):
            return hash((self.name, self.ssn))

        def __eq__(self, other):
            return isinstance(other, Hashable) and (self.name, self.ssn) == (
                other.name,
                other.ssn,
            )

    @shield(purpose="support", scope=["users"])
    def get_customers():
        return {"users": {Hashable("Tanaka", "123-45-6789")}}

    result = get_customers()
    if "users" in result:
        for u in result["users"]:
            # slots carries ssn — must not pass through raw
            assert not hasattr(u, "ssn") or getattr(u, "ssn", None) is None, (
                "A5/R1: set[slots-record] leaked ssn"
            )


def test_frozenset_of_namedtuple_leaf_scope_drops_fail_closed():
    """A5/R1: frozenset of record-like (NamedTuple) elements drops.

    Plain 2-tuples are not record-like (no ``_asdict``, no ``__dict__``);
    a NamedTuple IS record-like per S022 R10.
    """
    from typing import NamedTuple

    class Leak(NamedTuple):
        key: str
        ssn: str

    @shield(purpose="support", scope=["meta"])
    def get():
        return {"meta": frozenset([Leak("id", "123-45-6789")])}

    result = get()
    # R1 fail-closed: either 'meta' is absent or it carries no ssn content.
    if "meta" in result:
        for item in result["meta"]:
            ssn_attr = getattr(item, "ssn", None)
            assert ssn_attr is None, (
                f"A5/R1: frozenset[NamedTuple] leaked ssn via {item!r}"
            )


def test_generator_of_dicts_leaf_scope_drops_fail_closed():
    """A5/R1: generator yielding record-like drops (materialize + detect)."""

    def _gen():
        yield {"name": "Tanaka", "ssn": "123-45-6789"}

    @shield(purpose="support", scope=["users"])
    def get():
        return {"users": _gen()}

    result = get()
    if "users" in result:
        materialized = (
            list(result["users"]) if hasattr(result["users"], "__iter__") else []
        )
        for u in materialized:
            if isinstance(u, dict):
                assert "ssn" not in u, "A5/R1: generator leaked ssn"


def test_array_of_scalars_passes_through_safely():
    """A5/R1 negative case: array.array of scalars (no record-like) keeps."""

    @shield(purpose="support", scope=["counts"])
    def get():
        return {"counts": array.array("i", [1, 2, 3])}

    result = get()
    # Scalar array: safe to pass through (no named fields to leak)
    assert "counts" in result


def test_memoryview_of_bytes_passes_through_safely():
    """A5/R1 negative: memoryview over bytes — no record-like, safe."""

    @shield(purpose="support", scope=["payload"])
    def get():
        return {"payload": memoryview(b"\x00\x01\x02")}

    result = get()
    assert "payload" in result


# ── A13: str/bytes MUST NOT be treated as traversable ──────────────


def test_str_value_not_treated_as_traversable_collection():
    """R1/CM-1: str is a Sequence but MUST NOT trigger record-like traversal."""

    @shield(purpose="support", scope=["name"])
    def get():
        return {"name": "Tanaka"}

    result = get()
    # str must be kept as scalar, not iterated char-by-char
    assert result == {"name": "Tanaka"}


def test_bytes_value_not_treated_as_traversable_collection():
    """R1/CM-1: bytes must be kept as scalar."""

    @shield(purpose="support", scope=["payload"])
    def get():
        return {"payload": b"abc"}

    result = get()
    assert result == {"payload": b"abc"}
