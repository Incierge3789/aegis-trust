"""Mythos M5 — _collect_removed circular reference guard (T-148, S023).

Regression for the S022 Mythos finding: attacker-shaped circular structures
(``d = {"a": {}}; d["a"]["self"] = d``) used to cause unbounded recursion in
_diff_keys / _collect_removed. Two attack outcomes we close:

  - RecursionError leaks a traceback (AO-002 violation).
  - Infinite hang == DoS on the ingest path.

Now: the helper detects revisited container ids and caps depth. Circular
input is processed silently and the decorator still returns the fail-closed
value.
"""

from __future__ import annotations

import time

import pytest

from aegis_trust import shield
from aegis_trust.shield import _collect_removed, reset


@pytest.fixture(autouse=True)
def _reset():
    reset()
    yield
    reset()


def test_direct_self_cycle_on_dict():
    d: dict = {"a": 1}
    d["self"] = d
    filtered = {"a": 1}
    removed: set[str] = set()
    _collect_removed(d, filtered, "", removed)
    assert "self" in removed


def test_nested_cycle_does_not_hang():
    d: dict = {"outer": {"inner": {}}}
    d["outer"]["inner"]["loop"] = d["outer"]
    filtered: dict = {"outer": {"inner": {}}}
    removed: set[str] = set()
    start = time.perf_counter()
    _collect_removed(d, filtered, "", removed)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"cycle took {elapsed:.2f}s — guard likely broken"


def test_deep_non_circular_still_truncates_safely():
    """Linear depth > 128 — must not raise; just truncates at the cap."""
    root: dict = {}
    node = root
    for i in range(200):
        node["child"] = {}
        node = node["child"]
    filtered: dict = {}
    removed: set[str] = set()
    _collect_removed(root, filtered, "", removed)
    assert "child" in removed


def test_shield_decorator_handles_circular_return():
    """End-to-end: @shield-wrapped function returns circular dict → no hang,
    decorator returns fail-closed value without raising.
    """

    @shield(purpose="support", scope=["name"])
    def get_cyclic() -> dict:
        d = {"name": "alice", "extra": {}}
        d["extra"]["back"] = d
        return d

    start = time.perf_counter()
    result = get_cyclic()
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0
    # Either the filter returned {"name": "alice"} successfully, or
    # fail-closed returned {} / "" — both are acceptable. What matters is
    # no RecursionError and no hang.
    assert result in ({"name": "alice"}, {}, "")


def test_cycle_across_list_and_dict():
    d: dict = {"list": []}
    d["list"].append(d)  # list → dict → list …
    filtered: dict = {"list": []}
    removed: set[str] = set()
    start = time.perf_counter()
    _collect_removed(d, filtered, "", removed)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0
