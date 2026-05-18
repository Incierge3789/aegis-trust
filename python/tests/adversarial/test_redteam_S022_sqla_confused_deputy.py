"""S022 A3: SQLAlchemy Declarative probe confused deputy.

Attack surface: shield.py:135 `_is_sqla_declarative_like` checks only
`hasattr(x, "__table__") and hasattr(x.__table__, "columns")` —
attacker-controlled class with a fake `__table__.columns` gets routed
through the SQLA normalizer at line 296, which then trusts attacker
metadata via `getattr(data, c.name)` loop.

Plan Review R3: narrow the probe (SQLA `Table`/`DeclarativeBase` check)
and fail-closed when SQLAlchemy is not importable.
"""

from __future__ import annotations

from aegis_trust import shield


class _FakeColumn:
    def __init__(self, name: str):
        self.name = name


class _FakeTable:
    # Attacker declares arbitrary columns — if shield trusts this,
    # getattr(obj, c.name) will pull whatever attribute the attacker chose.
    columns = [_FakeColumn("admin_token"), _FakeColumn("name")]


class _FakeORMModel:
    __table__ = _FakeTable()

    def __init__(self):
        # Attacker sets these attributes to exfiltrate via the
        # `{c.name: getattr(obj, c.name) for c in columns}` path.
        self.admin_token = "secret-token-xyz"
        self.name = "Tanaka"
        # ssn is NOT in the fake columns list — still, the object
        # has the attribute; only the fake columns decide what's
        # extracted.
        self.ssn = "123-45-6789"


def test_fake_sqla_table_does_not_route_attacker_columns_to_scope():
    """A3: attacker-defined __table__ must NOT cause unfiltered trust.

    Expected post-R3: probe narrowed → fake table rejected → object
    falls through to "unknown" path → _filter_result fail-closes
    (return "" or filters by its __dict__).
    """

    @shield(purpose="support", scope=["name"])
    def get():
        return _FakeORMModel()

    result = get()
    # Post-R3 acceptable outcomes:
    #   A. "" fail-closed (fake probe rejected, object unknown)
    #   B. {"name": "Tanaka"} via __dict__ filter (slots/dict fallback)
    # UNACCEPTABLE:
    #   - admin_token present anywhere in result
    #   - ssn present anywhere in result

    def _flatten(x):
        if isinstance(x, dict):
            for k, v in x.items():
                yield k
                yield v
                yield from _flatten(v)
        elif isinstance(x, (list, tuple)):
            for it in x:
                yield from _flatten(it)
        else:
            yield x

    flat = list(_flatten(result))
    assert "secret-token-xyz" not in flat, (
        f"A3: fake __table__ leaked admin_token: {result!r}"
    )
    assert "123-45-6789" not in flat, f"A3: fake __table__ leaked ssn: {result!r}"
