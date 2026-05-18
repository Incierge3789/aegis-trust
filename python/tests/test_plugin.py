"""Tests for aegis pytest plugin — shield_history fixture + assertion helpers."""

import pytest

from aegis_trust.pytest_plugin import (
    ShieldRecord,
    assert_shield_blocked,
    assert_shield_passed,
)
from aegis_trust.shield import reset, shield


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AEGIS_MODE", "lite")
    reset()
    yield
    reset()


# --- shield_history fixture ---


def test_shield_history_captures_calls(shield_history):
    @shield(purpose="support", scope=["name"])
    def get_data():
        return {"name": "Alice", "ssn": "123"}

    get_data()
    records = shield_history()
    assert len(records) == 1
    assert records[0].function == "get_data"
    assert records[0].purpose == "support"
    assert records[0].scope == ["name"]
    assert "ssn" in records[0].blocked_fields


def test_shield_history_captures_deny_fields(shield_history):
    @shield(purpose="billing", deny_fields=["ssn"])
    def get_data():
        return {"name": "Alice", "ssn": "123"}

    get_data()
    records = shield_history()
    assert len(records) == 1
    assert records[0].deny_fields == ["ssn"]
    assert "ssn" in records[0].blocked_fields


def test_shield_history_multiple_calls(shield_history):
    @shield(purpose="support", scope=["name"])
    def get_a():
        return {"name": "Alice", "email": "a@b.com"}

    @shield(purpose="billing", deny_fields=["ssn"])
    def get_b():
        return {"name": "Bob", "ssn": "456"}

    get_a()
    get_b()
    records = shield_history()
    assert len(records) == 2
    assert records[0].purpose == "support"
    assert records[1].purpose == "billing"


def test_shield_history_empty_when_no_calls(shield_history):
    records = shield_history()
    assert records == []


def test_shield_history_dot_notation(shield_history):
    @shield(purpose="support", scope=["name", "profile.age"])
    def get_data():
        return {"name": "Alice", "profile": {"age": 30, "ssn": "123"}}

    get_data()
    records = shield_history()
    assert "profile.ssn" in records[0].blocked_fields


# --- assert_shield_blocked / assert_shield_passed ---


def test_assert_shield_blocked_passes(shield_history):
    @shield(purpose="support", scope=["name"])
    def get_data():
        return {"name": "Alice", "ssn": "123"}

    get_data()
    records = shield_history()
    assert_shield_blocked(records, "ssn")


def test_assert_shield_blocked_fails():
    records = [
        ShieldRecord(
            function="f",
            purpose="p",
            scope=["name"],
            deny_fields=[],
            blocked_fields=["email"],
            mode="lite",
        )
    ]
    with pytest.raises(AssertionError, match="Expected 'ssn' to be blocked"):
        assert_shield_blocked(records, "ssn")


def test_assert_shield_passed_passes(shield_history):
    @shield(purpose="support", scope=["name"])
    def get_data():
        return {"name": "Alice", "ssn": "123"}

    get_data()
    records = shield_history()
    assert_shield_passed(records, "name")


def test_assert_shield_passed_fails():
    records = [
        ShieldRecord(
            function="f",
            purpose="p",
            scope=["name"],
            deny_fields=[],
            blocked_fields=["ssn"],
            mode="lite",
        )
    ]
    with pytest.raises(AssertionError, match="Expected 'ssn' to pass through"):
        assert_shield_passed(records, "ssn")
