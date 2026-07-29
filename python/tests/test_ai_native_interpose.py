"""AI-native Layer 2 interposition — guard_tool / delegate / stream_session.

The wire floor (test_ai_native_client.py) proves the client speaks the frozen
contract; THIS file proves the boundary sits IN the call path: forgetting is
impossible, deny/error → None (the @shield convention), a failed delegation
mint denies the whole window, and a revoked stream stops the agent.

MockTransport house pattern (test_client_boundary.py), client injected via the
explicit ``client=`` DI kwarg.
"""

from __future__ import annotations

import asyncio
import json
import threading

import httpx
import pytest

import aegis_trust.ai_native as ai_native
from aegis_trust.ai_native import (
    current_capability,
    delegate,
    guard_tool,
    stream_session,
)
from aegis_trust.client import AegisClient
from aegis_trust.errors import (
    AegisStreamDenied,
    AegisStreamRevoked,
    AegisValidationError,
)

DECISION_OK = {"outcome": "PROTECTED", "ledgered": True, "decision_id": "d-1"}
DECISION_BLOCKED = {"outcome": "BLOCKED", "ledgered": True, "decision_id": "d-2"}
GRANT = {
    "capability": "cap-token-1",
    "id": "a" * 32,
    "exp": 4102444800,
    "depth": 1,
    "root_delegator": "root-sub",
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Owner resolution must be deterministic — clear ambient identity env."""
    monkeypatch.delenv("AEGIS_OWNER", raising=False)
    monkeypatch.delenv("AEGIS_AGENT_ID", raising=False)


def _client(handler, base_url: str = "https://localhost:8443/api/v1") -> AegisClient:
    c = AegisClient(base_url=base_url, verify_ssl=False)
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    c._async_httpx = httpx.AsyncClient(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={},
        timeout=httpx.Timeout(10.0),
    )
    return c


def _recording_handler(routes):
    """Return (handler, calls). ``routes`` maps a path suffix to a callable
    (body → httpx.Response) or a static httpx.Response."""
    calls: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        calls.append((request.url.path, body))
        for suffix, resp in routes.items():
            if request.url.path.endswith(suffix):
                return resp(body) if callable(resp) else resp
        return httpx.Response(404, json={})

    return handler, calls


def _tool_ok(body):
    return httpx.Response(200, json={"decision": DECISION_OK, "enforcement": None})


# ── guard_tool ───────────────────────────────────────────────────────


def test_guard_tool_allow_runs_fn_and_sends_wire_body():
    handler, calls = _recording_handler({"/tool-call": _tool_ok})

    @guard_tool(
        purpose="customer_data",
        owner="acme",
        fields=["name"],
        session_id="s-1",
        destination="llm:anthropic",
        client=_client(handler),
    )
    def query_business_data(q):
        return {"rows": [q]}

    assert query_business_data("x") == {"rows": ["x"]}
    path, body = calls[0]
    assert path.endswith("/tool-call")
    assert body == {
        "tool": "query_business_data",  # defaults to the function name
        "purpose": "customer_data",
        "owner": "acme",
        "fields": ["name"],
        "session_id": "s-1",
        "destination": "llm:anthropic",
    }


def test_guard_tool_deny_never_invokes_fn():
    handler, calls = _recording_handler(
        {
            "/tool-call": httpx.Response(
                200, json={"decision": DECISION_BLOCKED, "enforcement": None}
            )
        }
    )
    ran = []

    @guard_tool(purpose="p", owner="o", client=_client(handler))
    def tool():
        ran.append(1)
        return "secret"

    assert tool() is None
    assert ran == []
    assert len(calls) == 1  # the gate WAS consulted


def test_guard_tool_fail_closed_on_transport_error_and_unledgered():
    def boom(request):
        raise httpx.ConnectError("down")

    @guard_tool(purpose="p", owner="o", client=_client(boom))
    def t1():
        return "x"

    assert t1() is None

    handler, _ = _recording_handler(
        {
            "/tool-call": httpx.Response(
                200,
                json={"decision": {"outcome": "PROTECTED", "ledgered": False}},
            )
        }
    )

    @guard_tool(purpose="p", owner="o", client=_client(handler))
    def t2():
        return "x"

    assert t2() is None


def test_guard_tool_owner_unresolvable_denies_without_gateway_call():
    handler, calls = _recording_handler({"/tool-call": _tool_ok})

    @guard_tool(purpose="p", client=_client(handler))
    def tool():
        return "x"

    assert tool() is None
    assert calls == []  # denied locally, no round-trip


def test_guard_tool_owner_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_OWNER", "env-owner")
    handler, calls = _recording_handler({"/tool-call": _tool_ok})

    @guard_tool(purpose="p", client=_client(handler))
    def tool():
        return "x"

    assert tool() == "x"
    assert calls[0][1]["owner"] == "env-owner"


def test_guard_tool_fn_raise_after_grant_returns_none():
    handler, _ = _recording_handler({"/tool-call": _tool_ok})

    @guard_tool(purpose="p", owner="o", client=_client(handler))
    def tool():
        raise RuntimeError("ssn=123-45-6789")  # must be withheld

    assert tool() is None


@pytest.mark.asyncio
async def test_guard_tool_async_allow_and_deny():
    handler, calls = _recording_handler({"/tool-call": _tool_ok})

    @guard_tool(purpose="p", owner="o", client=_client(handler))
    async def tool(x):
        return x * 2

    assert await tool(21) == 42
    assert calls[0][1]["tool"] == "tool"

    handler2, _ = _recording_handler(
        {
            "/tool-call": httpx.Response(
                200, json={"decision": DECISION_BLOCKED, "enforcement": None}
            )
        }
    )
    ran = []

    @guard_tool(purpose="p", owner="o", client=_client(handler2))
    async def denied():
        ran.append(1)

    assert await denied() is None
    assert ran == []


def test_guard_tool_decoration_time_validation():
    with pytest.raises(AegisValidationError, match="purpose"):
        guard_tool("")
    with pytest.raises(AegisValidationError, match="tool"):
        guard_tool("p", tool="")
    with pytest.raises(TypeError, match="fields"):
        guard_tool("p", fields="name")  # type: ignore[arg-type]


# ── delegate ─────────────────────────────────────────────────────────


def test_delegate_mints_attaches_and_revokes():
    handler, calls = _recording_handler(
        {
            "/capability/mint": httpx.Response(200, json=GRANT),
            "/capability/revoke": httpx.Response(
                200, json={"ok": True, "revoked": GRANT["id"]}
            ),
            "/tool-call": _tool_ok,
        }
    )
    c = _client(handler)

    assert current_capability() is None
    with delegate("researcher", ["customer_data"], client=c) as grant:
        assert grant is not None and grant.capability == "cap-token-1"
        assert current_capability() == "cap-token-1"

        @guard_tool(purpose="customer_data", owner="acme", client=c)
        def tool():
            return "ok"

        assert tool() == "ok"
    assert current_capability() is None

    mint_body = calls[0][1]
    assert calls[0][0].endswith("/capability/mint")
    assert mint_body["for_agent"] == "researcher"
    assert "parent_capability" not in mint_body  # root mint
    tool_body = next(b for p, b in calls if p.endswith("/tool-call"))
    assert tool_body["capability"] == "cap-token-1"  # auto-attached
    assert calls[-1][0].endswith("/capability/revoke")
    assert calls[-1][1] == {"capability": "cap-token-1"}


def test_delegate_nested_narrowing_carries_parent():
    child = dict(GRANT, capability="cap-token-2", depth=2)
    minted = []

    def mint(body):
        minted.append(body)
        return httpx.Response(200, json=GRANT if len(minted) == 1 else child)

    handler, _ = _recording_handler(
        {
            "/capability/mint": mint,
            "/capability/revoke": httpx.Response(
                200, json={"ok": True, "revoked": "x" * 32}
            ),
        }
    )
    c = _client(handler)
    with delegate("outer", ["p1"], client=c):
        with delegate("inner", ["p1"], client=c) as inner:
            assert inner is not None
            assert current_capability() == "cap-token-2"
        assert current_capability() == "cap-token-1"
    assert "parent_capability" not in minted[0]
    assert minted[1]["parent_capability"] == "cap-token-1"


def test_delegate_mint_failure_denies_window():
    handler, calls = _recording_handler(
        {
            "/capability/mint": httpx.Response(422, json={"error": "widening"}),
            "/tool-call": _tool_ok,
        }
    )
    c = _client(handler)
    with delegate("child", ["p"], client=c) as grant:
        assert grant is None
        assert current_capability() is None  # denied, not a token

        @guard_tool(purpose="p", owner="o", client=c)
        def tool():
            return "x"

        assert tool() is None  # denied LOCALLY

        # a nested window inside a denied window stays denied (no mint call)
        with delegate("grandchild", ["p"], client=c) as inner:
            assert inner is None
    # only the failed mint reached the wire — no tool-call, no second mint
    assert [p for p, _ in calls] == [calls[0][0]]
    assert calls[0][0].endswith("/capability/mint")


def test_delegate_revoke_on_exit_false_and_revoke_failure_swallowed():
    handler, calls = _recording_handler(
        {
            "/capability/mint": httpx.Response(200, json=GRANT),
            "/capability/revoke": httpx.Response(503, json={}),
        }
    )
    c = _client(handler)
    with delegate("a", ["p"], revoke_on_exit=False, client=c):
        pass
    assert [p for p, _ in calls if p.endswith("/capability/revoke")] == []

    # revoke failure must not raise out of the context manager
    with delegate("a", ["p"], client=c):
        pass
    assert calls[-1][0].endswith("/capability/revoke")


def test_delegate_validation():
    with pytest.raises(AegisValidationError, match="for_agent"):
        with delegate("", ["p"]):
            pass
    with pytest.raises(AegisValidationError, match="purposes"):
        with delegate("a", []):
            pass


# ── stream_session ───────────────────────────────────────────────────


def _stream_routes(heartbeat_responses, calls_out=None):
    """Stub /stream/* with a scripted heartbeat sequence (last repeats)."""
    seq = list(heartbeat_responses)

    def heartbeat(body):
        payload = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(payload, Exception):
            raise payload
        return httpx.Response(200, json=payload)

    return {
        "/stream/open": httpx.Response(
            200,
            json={
                "decision": DECISION_OK,
                "enforcement": None,
                "stream": {"stream_id": "st-1", "status": "open"},
            },
        ),
        "/stream/heartbeat": heartbeat,
        "/stream/close": httpx.Response(200, json={"ok": True}),
    }


def test_stream_session_normal_lifecycle_closes():
    handler, calls = _recording_handler(_stream_routes([{"status": "ok"}]))
    with stream_session(
        {"envelope": "e"}, heartbeat_interval=0.02, client=_client(handler)
    ) as s:
        assert s.stream_id == "st-1"
        assert s.decision["outcome"] == "PROTECTED"
    assert calls[-1][0].endswith("/stream/close")
    assert calls[-1][1] == {"stream_id": "st-1"}


def test_stream_session_open_denied_block_never_runs():
    handler, _ = _recording_handler(
        {
            "/stream/open": httpx.Response(
                200,
                json={
                    "decision": DECISION_BLOCKED,
                    "enforcement": None,
                    "stream": None,
                },
            )
        }
    )
    with pytest.raises(AegisStreamDenied) as ei:
        with stream_session({"e": 1}, client=_client(handler)):
            raise AssertionError("block must not run")
    assert ei.value.code == "aegis.stream.denied"


def test_stream_session_open_transport_error_fail_closed():
    def boom(request):
        raise httpx.ConnectError("down")

    with pytest.raises(AegisStreamDenied) as ei:
        with stream_session({"e": 1}, client=_client(boom)):
            raise AssertionError("block must not run")
    assert ei.value.code == "aegis.stream.open_failed"


def test_stream_session_revoke_fires_callback_and_raises():
    handler, _ = _recording_handler(
        _stream_routes(
            [{"status": "ok"}, {"status": "revoked", "reason": "duress_active"}]
        )
    )
    seen: list[str] = []
    with pytest.raises(AegisStreamRevoked) as ei:
        with stream_session(
            {"e": 1},
            heartbeat_interval=0.02,
            on_revoke=seen.append,
            client=_client(handler),
        ) as s:
            assert s.revoked.wait(timeout=5.0)
    assert ei.value.reason == "duress_active"
    assert seen == ["duress_active"]


def test_stream_session_heartbeat_outage_is_revocation():
    handler, _ = _recording_handler(_stream_routes([httpx.ConnectError("down")]))
    with pytest.raises(AegisStreamRevoked) as ei:
        with stream_session(
            {"e": 1},
            heartbeat_interval=0.02,
            max_heartbeat_failures=3,
            on_revoke=lambda r: None,
            client=_client(handler),
        ) as s:
            assert s.revoked.wait(timeout=5.0)
    assert ei.value.reason == "gateway_unavailable"


def test_stream_session_no_callback_interrupts_main(monkeypatch):
    interrupted = threading.Event()
    monkeypatch.setattr(ai_native, "_interrupt_main", interrupted.set)
    handler, _ = _recording_handler(
        _stream_routes([{"status": "revoked", "reason": "legal_hold"}])
    )
    with pytest.raises(AegisStreamRevoked):
        with stream_session(
            {"e": 1}, heartbeat_interval=0.02, client=_client(handler)
        ) as s:
            assert s.revoked.wait(timeout=5.0)
    assert interrupted.is_set()


def test_stream_session_denied_delegation_window_refuses_locally():
    handler, calls = _recording_handler(
        {"/capability/mint": httpx.Response(403, json={})}
    )
    c = _client(handler)
    with delegate("a", ["p"], client=c):
        with pytest.raises(AegisStreamDenied) as ei:
            with stream_session({"e": 1}, client=c):
                raise AssertionError("block must not run")
    assert ei.value.code == "aegis.stream.delegation_denied"
    assert [p for p, _ in calls if p.endswith("/stream/open")] == []


def test_stream_session_attaches_delegation_capability():
    routes = _stream_routes([{"status": "ok"}])
    routes["/capability/mint"] = httpx.Response(200, json=GRANT)
    routes["/capability/revoke"] = httpx.Response(
        200, json={"ok": True, "revoked": GRANT["id"]}
    )
    handler, calls = _recording_handler(routes)
    c = _client(handler)
    with delegate("a", ["p"], client=c):
        with stream_session({"principal": {}}, heartbeat_interval=1.0, client=c):
            pass
    open_body = next(b for p, b in calls if p.endswith("/stream/open"))
    assert open_body["envelope"]["delegation"]["capability"] == "cap-token-1"


def test_stream_session_does_not_attach_through_a_different_client():
    # Node twin: checkBoundaryDelegation.test.ts "streamSession does NOT send
    # the ambient token through a different client". The positive above proves
    # attachment happens; without this negative, a regression that attaches
    # unconditionally would still be green. Cross-review (cursor, 2026-07-29)
    # called the parity gap after Node closed it.
    routes = _stream_routes([{"status": "ok"}])
    routes["/capability/mint"] = httpx.Response(200, json=GRANT)
    routes["/capability/revoke"] = httpx.Response(
        200, json={"ok": True, "revoked": GRANT["id"]}
    )
    handler, calls = _recording_handler(routes)
    minting = _client(handler)
    # Constructed at a different base URL, not mutated after the fact — the
    # binding must hold for a client that was never the minting one.
    other = _client(handler, base_url="https://other.invalid/api/v1")
    with delegate("a", ["p"], client=minting):
        with stream_session({"principal": {}}, heartbeat_interval=1.0, client=other):
            pass
        with stream_session({"principal": {}}, heartbeat_interval=1.0, client=minting):
            pass
    opens = [b for p, b in calls if p.endswith("/stream/open")]
    assert len(opens) == 2
    # Negative AND positive in one case: an always-refuse regression would pass
    # the negative alone, so the pair is what makes this non-vacuous.
    assert "delegation" not in opens[0]["envelope"]
    assert opens[1]["envelope"]["delegation"]["capability"] == "cap-token-1"


def test_stream_session_validation():
    with pytest.raises(AegisValidationError, match="envelope"):
        stream_session({})
    with pytest.raises(AegisValidationError, match="interval"):
        stream_session({"e": 1}, heartbeat_interval=0)


@pytest.mark.asyncio
async def test_stream_session_async_revoke_cancels_block():
    handler, _ = _recording_handler(
        _stream_routes(
            [{"status": "ok"}, {"status": "revoked", "reason": "duress_active"}]
        )
    )
    reached_end = []
    with pytest.raises(AegisStreamRevoked) as ei:
        async with stream_session(
            {"e": 1}, heartbeat_interval=0.02, client=_client(handler)
        ):
            await asyncio.sleep(30)  # cancelled by the revocation
            reached_end.append(1)
    assert ei.value.reason == "duress_active"
    assert reached_end == []


@pytest.mark.asyncio
async def test_stream_session_async_normal_completion_closes():
    handler, calls = _recording_handler(_stream_routes([{"status": "ok"}]))
    async with stream_session(
        {"e": 1}, heartbeat_interval=0.5, client=_client(handler)
    ) as s:
        assert s.stream_id == "st-1"
    assert calls[-1][0].endswith("/stream/close")
