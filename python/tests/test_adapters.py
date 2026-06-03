"""Tests for the framework adapters (aegis_trust.adapters).

Mirror of node/tests/adapters.test.ts. Framework-free: the LangChain factory
and CrewAI BaseTool are mocked, so no framework needs to be installed.
"""

import json

import pytest

from aegis_trust.adapters import (
    ShieldedTool,
    shielded_tool,
    to_crewai_tool,
    to_langchain_tool,
)
from aegis_trust.errors import AegisValidationError
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


RECORD = {
    "name": "Tanaka Taro",
    "email": "tanaka@example.com",
    "ssn": "123-45-6789",
    "credit_card": "4242-****-****-1234",
    "issue": "Cannot reset password",
}
SCOPED = {"name": "Tanaka Taro", "issue": "Cannot reset password"}


def _lookup() -> ShieldedTool:
    return shielded_tool(
        name="customer_lookup",
        description="Look up a customer record by id for support.",
        purpose="customer_support",
        scope=["name", "issue"],
        handler=lambda **kw: RECORD,
    )


class TestCore:
    def test_run_returns_only_scoped_fields(self):
        assert _lookup().run(customer_id="C-1001") == SCOPED

    def test_call_serializes_without_blocked_fields(self):
        s = _lookup().call(customer_id="C-1001")
        assert json.loads(s) == SCOPED
        for blocked in ("ssn", "123-45-6789", "credit_card", "email"):
            assert blocked not in s

    def test_passes_arguments_through_to_handler(self):
        seen = {}

        def handler(**kw):
            seen.update(kw)
            return RECORD

        t = shielded_tool(
            name="t", description="d", purpose="p", scope=["name"], handler=handler
        )
        t.run(customer_id="C-42")
        assert seen == {"customer_id": "C-42"}

    def test_deny_fields_only_spec(self):
        t = shielded_tool(
            name="customer_lookup_deny",
            description="Look up a customer, stripping sensitive fields.",
            purpose="customer_support",
            deny_fields=["ssn", "credit_card", "email"],
            handler=lambda **kw: RECORD,
        )
        assert t.run(customer_id="C-1001") == SCOPED

    def test_custom_serializer(self):
        t = shielded_tool(
            name="t",
            description="d",
            purpose="p",
            scope=["name"],
            handler=lambda **kw: RECORD,
            serialize=lambda v: f"<<{json.dumps(v)}>>",
        )
        assert t.call() == '<<{"name": "Tanaka Taro"}>>'

    def test_minimum_disclosure_raises(self):
        with pytest.raises(AegisValidationError):
            shielded_tool(
                name="t", description="d", purpose="p", handler=lambda **kw: RECORD
            )

    def test_fail_closed_handler_raises(self):
        def boom(**kw):
            raise RuntimeError("db error: ssn=123-45-6789")

        t = shielded_tool(
            name="t", description="d", purpose="p", scope=["name"], handler=boom
        )
        out = t.run()
        assert not out
        assert "123-45-6789" not in t.call()

    def test_audit_identity_records_tool_name(self):
        # shield() records ``fn.__name__``; the accessor is named from the tool
        # name so the audit trail is not "<lambda>". (mirror of Node fix.)
        t = _lookup()
        assert t._run.__name__ == "customer_lookup"

    def test_async_handler_via_sync_call_fails_closed(self):
        # An async handler reached through the synchronous call() path must fail
        # closed to "" (never serialize the coroutine). Async callers use acall.
        import warnings

        async def handler(**kw):
            return RECORD

        t = shielded_tool(
            name="async_lookup",
            description="d",
            purpose="p",
            scope=["name"],
            handler=handler,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # "coroutine never awaited" -> error
            assert t.call(customer_id="C-1") == ""

    @pytest.mark.asyncio
    async def test_acall_awaits_async_handler(self):
        async def handler(**kw):
            return RECORD

        t = shielded_tool(
            name="async_lookup",
            description="d",
            purpose="p",
            scope=["name", "issue"],
            handler=handler,
        )
        assert json.loads(await t.acall(customer_id="C-1")) == SCOPED


class TestLangChain:
    def test_binds_via_injected_factory(self):
        schema = object()
        t = shielded_tool(
            name="customer_lookup",
            description="Look up a customer.",
            purpose="customer_support",
            scope=["name", "issue"],
            schema=schema,
            handler=lambda **kw: RECORD,
        )
        captured = {}

        def fake_from_function(**kwargs):
            captured.update(kwargs)
            return "LC_TOOL"

        result = to_langchain_tool(fake_from_function, t)
        assert result == "LC_TOOL"
        assert captured["name"] == "customer_lookup"
        assert captured["description"] == "Look up a customer."
        assert captured["args_schema"] is schema
        out = captured["func"](customer_id="C-1001")
        assert json.loads(out) == SCOPED

    def test_omits_schema_when_absent(self):
        captured = {}

        def fake_from_function(**kwargs):
            captured.update(kwargs)
            return None

        to_langchain_tool(fake_from_function, _lookup())
        assert "args_schema" not in captured


class TestCrewai:
    def test_builds_basetool_subclass(self):
        class MockBaseTool:
            pass

        crew_tool = to_crewai_tool(MockBaseTool, _lookup())
        assert isinstance(crew_tool, MockBaseTool)
        assert crew_tool.name == "customer_lookup"
        assert crew_tool.description == "Look up a customer record by id for support."
        assert crew_tool._run(customer_id="C-1001") == SCOPED
