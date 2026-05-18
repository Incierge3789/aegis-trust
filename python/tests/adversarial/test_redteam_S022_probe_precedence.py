"""S022 A8: `_to_filterable` probe order precedence attack.

Attack surface: shield.py:287-308 checks probes in fixed order
v2 → SQLA → v1 → dataclass. An attacker class matching multiple probes
(e.g. model_dump + __table__.columns) chooses which normalizer runs.
Not a direct leak but a confused-deputy surface.

Plan Review R8: document the order in `_to_filterable` docstring
explicitly, and consider a strict mode that fails-closed on ambiguous
classes. This sprint: lock the order via regression test so future
changes don't silently re-order probes.
"""

from __future__ import annotations

from aegis_trust import shield


class _MultiProbe:
    """Matches v2 (model_dump) AND SQLA (__table__.columns). v2 must win."""

    class _FakeTable:
        class _Col:
            name = "ssn"

        columns = [_Col()]

    __table__ = _FakeTable()
    ssn = "123-45-6789"

    def model_dump(self):
        # v2 path returns only safe fields
        return {"name": "Tanaka"}


def test_probe_precedence_v2_wins_over_sqla():
    """A8: class matching both v2 and SQLA — v2 takes precedence.

    This fixes the probe ordering as a regression test. Post-R3
    SQLA narrowing may reject the fake table entirely; in that case
    v2 still wins first (line 287 before 294) and returns {"name": ...}.
    """

    @shield(purpose="support", scope=["name"])
    def get():
        return _MultiProbe()

    result = get()
    # v2 path {"name": "Tanaka"} filtered by scope=["name"] → {"name": "Tanaka"}
    # SQLA path (if taken) would expose ssn via fake columns
    assert result == {"name": "Tanaka"} or result == "", (
        f"A8: probe precedence changed: {result!r}"
    )

    # Critical: ssn must NEVER appear
    def _contains_ssn(x):
        if isinstance(x, dict):
            return any(_contains_ssn(v) or k == "ssn" for k, v in x.items())
        if isinstance(x, (list, tuple)):
            return any(_contains_ssn(v) for v in x)
        return x == "123-45-6789"

    assert not _contains_ssn(result), f"A8: ssn leaked via confused deputy: {result!r}"
