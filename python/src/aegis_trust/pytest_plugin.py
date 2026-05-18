"""pytest plugin for aegis-trust — test what @shield filters.

Provides fixtures and helpers to verify field-level access control
in your test suite without touching SQLite or external services.

Registered automatically via pytest11 entry point.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
import pytest

# In-memory record storage (thread-safe)
_records: list[ShieldRecord] = []
_lock = threading.Lock()
_capture_enabled = False


@dataclass(frozen=True)
class ShieldRecord:
    """A single @shield invocation record."""

    function: str
    purpose: str
    scope: list[str]
    deny_fields: list[str]
    blocked_fields: list[str]
    mode: str


def _on_shield_call(
    *,
    function: str,
    purpose: str,
    scope: list[str],
    deny_fields: list[str],
    blocked_fields: list[str],
    timestamp: str,
    mode: str,
) -> None:
    """Hook called by shield internals when capture is enabled."""
    if not _capture_enabled:
        return
    record = ShieldRecord(
        function=function,
        purpose=purpose,
        scope=scope,
        deny_fields=deny_fields,
        blocked_fields=blocked_fields,
        mode=mode,
    )
    with _lock:
        _records.append(record)


def _start_capture() -> None:
    global _capture_enabled
    with _lock:
        _records.clear()
        _capture_enabled = True


def _stop_capture() -> list[ShieldRecord]:
    global _capture_enabled
    with _lock:
        _capture_enabled = False
        result = list(_records)
        _records.clear()
    return result


@pytest.fixture()
def shield_history():
    """Fixture that captures @shield calls during the test.

    Returns a list of ShieldRecord objects after the test body runs.
    Use with assert_shield_blocked / assert_shield_passed helpers.

    Usage::

        def test_support_hides_ssn(shield_history):
            get_customer("id-1")  # calls @shield decorated function
            records = shield_history()
            assert_shield_blocked(records, "ssn")
    """
    # Patch the shield module to call our hook
    import sys

    shield_mod = sys.modules["aegis_trust.shield"]
    original = shield_mod._test_hook
    shield_mod._test_hook = _on_shield_call
    _start_capture()

    captured: list[ShieldRecord] = []

    def get_records() -> list[ShieldRecord]:
        if not captured:
            captured.extend(_stop_capture())
        return captured

    yield get_records

    # Restore
    _stop_capture()
    shield_mod._test_hook = original


def assert_shield_blocked(records: list[ShieldRecord], field: str) -> None:
    """Assert that a field was blocked in at least one @shield call.

    Args:
        records: List of ShieldRecord from shield_history fixture.
        field: Field name (supports dot-notation, e.g. "profile.ssn").

    Raises:
        AssertionError: If the field was not blocked.
    """
    all_blocked: set[str] = set()
    for r in records:
        all_blocked.update(r.blocked_fields)
    assert field in all_blocked, (
        f"Expected '{field}' to be blocked, but it was not. "
        f"Blocked fields: {sorted(all_blocked)}"
    )


def assert_shield_passed(records: list[ShieldRecord], field: str) -> None:
    """Assert that a field was NOT blocked in any @shield call.

    Args:
        records: List of ShieldRecord from shield_history fixture.
        field: Field name (supports dot-notation, e.g. "name").

    Raises:
        AssertionError: If the field was blocked.
    """
    all_blocked: set[str] = set()
    for r in records:
        all_blocked.update(r.blocked_fields)
    assert field not in all_blocked, (
        f"Expected '{field}' to pass through, but it was blocked. "
        f"Blocked fields: {sorted(all_blocked)}"
    )
