"""Tests for the streaming framework adapter (aegis_trust.adapters).

Mirror of node/tests/adaptersStream.test.ts. Framework-free.
"""

import json
import warnings

import pytest

from aegis_trust.adapters import ShieldedStreamTool, shielded_stream_tool
from aegis_trust.errors import AegisValidationError
from aegis_trust.shield import reset
from aegis_trust.types import Mode


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


RECORDS = [
    {
        "name": "Tanaka Taro",
        "email": "tanaka@example.com",
        "ssn": "123-45-6789",
        "issue": "Login",
    },
    {
        "name": "Sato Hanako",
        "email": "sato@example.com",
        "ssn": "987-65-4321",
        "issue": "Billing",
    },
    {
        "name": "Suzuki Ken",
        "email": "suzuki@example.com",
        "ssn": "555-55-5555",
        "issue": "Refund",
    },
]
SCOPED = [
    {"name": "Tanaka Taro", "issue": "Login"},
    {"name": "Sato Hanako", "issue": "Billing"},
    {"name": "Suzuki Ken", "issue": "Refund"},
]


def _stream_tool(handler) -> ShieldedStreamTool:
    return shielded_stream_tool(
        name="customer_rows",
        description="Stream customer records for a support session.",
        purpose="customer_support",
        scope=["name", "issue"],
        handler=handler,
    )


async def _collect(aiter):
    out = []
    async for r in aiter:
        out.append(r)
    return out


class TestStream:
    @pytest.mark.asyncio
    async def test_filters_each_record_from_async_generator(self):
        async def handler(**kw):
            for r in RECORDS:
                yield r

        got = await _collect(_stream_tool(handler).stream(q="open"))
        assert got == SCOPED

    @pytest.mark.asyncio
    async def test_filters_records_from_sync_generator(self):
        def handler(**kw):
            for r in RECORDS:
                yield r

        got = await _collect(_stream_tool(handler).stream(q="open"))
        assert got == SCOPED

    @pytest.mark.asyncio
    async def test_filters_records_from_plain_list(self):
        # handler returns a plain (already-materialized) iterable
        got = await _collect(_stream_tool(lambda **kw: list(RECORDS)).stream(q="open"))
        assert got == SCOPED

    @pytest.mark.asyncio
    async def test_handler_coroutine_resolving_to_iterable(self):
        async def handler(**kw):
            return list(RECORDS)

        got = await _collect(_stream_tool(handler).stream(q="open"))
        assert got == SCOPED

    @pytest.mark.asyncio
    async def test_never_emits_blocked_fields(self):
        async def handler(**kw):
            for r in RECORDS:
                yield r

        got = await _collect(_stream_tool(handler).stream(q="open"))
        blob = json.dumps(got)
        assert "ssn" not in blob
        assert "123-45-6789" not in blob
        assert "email" not in blob
        assert "@example.com" not in blob

    @pytest.mark.asyncio
    async def test_fail_closed_empty_when_handler_raises_before_producing(self):
        def handler(**kw):
            raise RuntimeError("upstream down — must not surface, may carry data")

        got = await _collect(_stream_tool(handler).stream(q="open"))
        assert got == []

    @pytest.mark.asyncio
    async def test_fail_closed_midstream_keeps_filtered_records_leaks_nothing(self):
        async def handler(**kw):
            yield RECORDS[0]
            yield RECORDS[1]
            raise RuntimeError("cursor exploded with raw row in the message")

        got = await _collect(_stream_tool(handler).stream(q="open"))
        # The two records produced before the raise stand — filtered.
        assert got == [SCOPED[0], SCOPED[1]]
        # And nothing from the failure leaked.
        assert "ssn" not in json.dumps(got)

    @pytest.mark.asyncio
    async def test_empty_stream_when_handler_yields_nothing(self):
        async def handler(**kw):
            return
            yield  # pragma: no cover — makes this an async generator

        got = await _collect(_stream_tool(handler).stream(q="open"))
        assert got == []

    def test_raises_validation_error_when_no_scope_or_deny(self):
        async def handler(**kw):
            yield RECORDS[0]

        with pytest.raises(AegisValidationError):
            shielded_stream_tool(
                name="bad",
                description="missing scope and deny_fields",
                purpose="customer_support",
                handler=handler,
            )

    @pytest.mark.asyncio
    async def test_deny_fields_blacklist_per_record(self):
        async def handler(**kw):
            yield RECORDS[0]

        tool = shielded_stream_tool(
            name="customer_rows_deny",
            description="Stream rows with sensitive fields stripped.",
            purpose="customer_support",
            deny_fields=["ssn", "email"],
            handler=handler,
        )
        got = await _collect(tool.stream(q="open"))
        assert got == [{"name": "Tanaka Taro", "issue": "Login"}]
        assert "ssn" not in got[0]
        assert "email" not in got[0]

    def test_raises_full_unsupported_when_mode_full_requested(self):
        async def handler(**kw):
            yield RECORDS[0]

        for full in ("full", Mode.FULL):
            with pytest.raises(AegisValidationError):
                shielded_stream_tool(
                    name="full_stream",
                    description="FULL is not supported for streaming yet",
                    purpose="customer_support",
                    scope=["name", "issue"],
                    mode=full,
                    handler=handler,
                )

    def test_raises_mode_invalid_for_mistyped_mode(self):
        async def handler(**kw):
            yield RECORDS[0]

        for bad in ("FULL", "Lite", "fulll", "AUTO"):
            with pytest.raises(AegisValidationError):
                shielded_stream_tool(
                    name="bad_mode",
                    description="mistyped mode must fail closed, not downgrade to LITE",
                    purpose="customer_support",
                    scope=["name", "issue"],
                    mode=bad,
                    handler=handler,
                )

    @pytest.mark.asyncio
    async def test_refuses_failclosed_when_auto_resolves_to_full(self, monkeypatch):
        # Explicit FULL intent via env → _detect_mode() resolves AUTO to FULL.
        # Streaming must refuse (empty stream, handler never called), never
        # silently downgrade the gate the operator configured.
        monkeypatch.setenv("AEGIS_MODE", "full")
        reset()  # clear the detect-mode TTL cache so the env takes effect

        called = {"v": False}

        async def handler(**kw):
            called["v"] = True  # must never run
            yield RECORDS[0]

        tool = shielded_stream_tool(
            name="auto_full_stream",
            description="AUTO that resolves to FULL must refuse, not downgrade",
            purpose="customer_support",
            scope=["name", "issue"],
            handler=handler,  # no mode → AUTO
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            got = await _collect(tool.stream(q="open"))
        assert got == []  # empty stream — no cardinality leak
        assert called["v"] is False  # accessor never executed — no side effects

    def test_audit_identity_records_tool_name(self):
        # shield() records ``fn.__name__``; the identity record-filter is named
        # from the tool name so the audit trail is not "<lambda>" / generic.
        async def handler(**kw):
            yield RECORDS[0]

        assert _stream_tool(handler)._guarded.__name__ == "customer_rows"
