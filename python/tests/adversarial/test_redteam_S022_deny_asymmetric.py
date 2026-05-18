"""S022 A6/A7/A12: `_deny_filter_dict` asymmetric with `_filter_dict`.

Attack surface: shield.py:255 recurses only for ``list`` (no tuple/deque/
set), and shield.py:260 KEEPS scalar when subtree expects nested access
(opposite of `_filter_dict` which DROPS fail-closed at line 215-220).

Plan Review R2: flip line 260 from KEEP to DROP (symmetric fail-closed).
Plan Review R11: symmetric table across allow/deny for all container
paths (list/tuple/deque/set/...).
"""

from __future__ import annotations

from collections import deque

from aegis_trust import shield

# ── A7: deny recursion only handles list, not tuple/deque ──────────


def test_deny_dot_notation_into_tuple_applies():
    """A7: deny_fields=['users.ssn'] with tuple[dict] MUST remove ssn."""

    @shield(purpose="support", deny_fields=["users.ssn"])
    def get():
        return {"users": ({"name": "Tanaka", "ssn": "123-45-6789"},)}

    result = get()
    if "users" in result:
        for u in result["users"]:
            if isinstance(u, dict):
                assert "ssn" not in u, "A7: deny into tuple failed to remove ssn"


def test_deny_dot_notation_into_deque_applies():
    """A7: deny_fields=['users.ssn'] with deque[dict] MUST remove ssn."""

    @shield(purpose="support", deny_fields=["users.ssn"])
    def get():
        return {"users": deque([{"name": "Tanaka", "ssn": "123-45-6789"}])}

    result = get()
    if "users" in result:
        for u in result["users"]:
            if isinstance(u, dict):
                assert "ssn" not in u, "A7: deny into deque failed to remove ssn"


# ── A6/A12: deny line 260 scalar fallback — must DROP (R2) ─────────


def test_deny_subtree_expected_but_scalar_drops():
    """A6/A12/R2: deny_fields=['users.ssn'] with users=scalar MUST drop
    the entire 'users' key (fail-closed, symmetric with scope)."""

    @shield(purpose="support", deny_fields=["users.ssn"])
    def get():
        return {"users": "not_a_dict_or_list", "other": "kept"}

    result = get()
    # R2: when subtree expects descent but value is scalar, drop fail-closed
    assert "users" not in result, (
        f"A6/A12/R2: scalar users kept under deny with subtree: {result!r}"
    )
    assert "other" in result  # Untouched key remains


def test_deny_subtree_expected_but_non_recursable_container_fail_closes():
    """A6/R2: deny with subtree expected but traversable container holds
    non-descendable scalars (e.g. frozenset of strings) — each element
    MUST fail-closed to empty string (no raw scalars surface)."""

    secret = "123-45-6789"

    @shield(purpose="support", deny_fields=["users.ssn"])
    def get():
        return {"users": frozenset(["not", "a", secret])}

    result = get()
    if "users" in result:
        for item in result["users"]:
            assert item != secret, f"R2: non-recursable element leaked secret: {item!r}"
