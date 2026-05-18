"""S022 A1: __slots__ class leaf-drop bypass.

Attack surface: shield.py `_is_record_like` line 174 falls back to
``hasattr(x, "__dict__")``. Classes using ``__slots__`` have NO
``__dict__`` yet carry named fields — they bypass record-like detection
and leak through leaf-scope drops.

Plan Review R8: "slots instance → always record-like" (fail-closed default).
"""

from __future__ import annotations

from aegis_trust import shield


class SlottedUser:
    __slots__ = ("name", "ssn")

    def __init__(self, name: str, ssn: str):
        self.name = name
        self.ssn = ssn


def test_slots_class_in_list_leaf_scope_drops_fail_closed():
    """A1: list[SlottedUser] under leaf scope MUST drop (fail-closed)."""

    @shield(purpose="support", scope=["users"])
    def get():
        return {"users": [SlottedUser("Tanaka", "123-45-6789")]}

    result = get()
    if "users" in result:
        for u in result["users"]:
            assert getattr(u, "ssn", None) is None, "A1: slots ssn leaked"


def test_slots_class_in_tuple_leaf_scope_drops_fail_closed():
    """A1: tuple[SlottedUser] — same attack via tuple."""

    @shield(purpose="support", scope=["users"])
    def get():
        return {"users": (SlottedUser("Tanaka", "123-45-6789"),)}

    result = get()
    if "users" in result:
        for u in result["users"]:
            assert getattr(u, "ssn", None) is None, "A1: slots ssn via tuple leaked"


def test_slots_class_direct_return_fail_closed():
    """A1: direct slots return (no container) — _to_filterable must
    not pass through as-is since it has fields but no __dict__."""

    @shield(purpose="support", scope=["name"])
    def get():
        return SlottedUser("Tanaka", "123-45-6789")

    result = get()
    # Must either return filtered dict {name: ...} or fail-closed ""
    assert result == {"name": "Tanaka"} or result == "" or result is None, (
        f"A1: slots direct return leaked: {result!r}"
    )
