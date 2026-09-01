"""check_boundary × A-1 delegation — the token reaches the wire without the
caller carrying it.

Node parity: node/tests/checkBoundaryDelegation.test.ts (same cases, same
order). The point of this file is the FORGETTING case: a ``capability``
parameter the developer must remember to pass is fail-open by omission — the
call is decided at full width while the enclosing ``delegate()`` window
believes its narrowing applied. So the load-bearing assertions here are the
ones nobody wrote a parameter for.

MockTransport house pattern (test_client_boundary.py), client injected via the
explicit ``client=`` DI kwarg.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import threading

import httpx
import pytest

from aegis_trust.ai_native import delegate, guard_tool
from aegis_trust.client import AegisClient
from aegis_trust.errors import AegisHttpError, AegisValidationError

GRANT = {
    "capability": "cap-token-1",
    "id": "a" * 32,
    "exp": 4102444800,
    "depth": 1,
    "root_delegator": "root-sub",
}

VIEW = {
    "source": "CORE",
    "outcome": "PROTECTED",
    "purpose_label": "customer_support",
    "allowed_fields": ["name"],
    "withheld_fields": [],
    "reason_code": "minimum_disclosure",
    "reason_label": "Minimum disclosure",
    "evidence_available": False,
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
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
    return c


def _recording_handler(routes):
    calls: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        calls.append((request.url.path, body))
        for suffix, resp in routes.items():
            if request.url.path.endswith(suffix):
                return resp(body) if callable(resp) else resp
        return httpx.Response(404, json={})

    return handler, calls


def _boundary_ok(body):
    return httpx.Response(200, json=VIEW)


def _mint_ok(body):
    return httpx.Response(200, json=GRANT)


def _revoke_ok(body):
    return httpx.Response(200, json={"ok": True, "revoked": GRANT["id"]})


def _refuse(body):
    # aegis_gateway rest.rs check_boundary, "A-1 delegation refusal".
    return httpx.Response(
        501,
        json={"error": "this surface does not evaluate delegated capabilities"},
    )


_DELEGATION_ROUTES = {
    "/capability/mint": _mint_ok,
    "/capability/revoke": _revoke_ok,
}


def _boundary_body(calls) -> dict:
    return next(b for p, b in calls if p.endswith("/check-boundary"))


# ── automatic delegation attachment ──────────────────────────────────


def test_attaches_enclosing_delegate_token_with_no_caller_change():
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        # The call site is byte-identical to pre-A-1 code: no capability arg.
        c.check_boundary("customer_support", ["name"])
    assert _boundary_body(calls)["capability"] == "cap-token-1"


def test_sends_no_capability_outside_a_delegation_window():
    handler, calls = _recording_handler({"/check-boundary": _boundary_ok})
    _client(handler).check_boundary("customer_support", ["name"])
    # Byte-identical to prior SDKs: the key is absent, not present-and-null.
    assert "capability" not in _boundary_body(calls)


def test_explicit_capability_wins_over_the_ambient_window():
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        c.check_boundary("customer_support", ["name"], capability="cap-explicit")
    assert _boundary_body(calls)["capability"] == "cap-explicit"


def test_explicit_none_opts_out_for_one_call():
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        c.check_boundary("customer_support", ["name"], capability=None)
    assert "capability" not in _boundary_body(calls)


def test_denied_window_refuses_locally():
    handler, calls = _recording_handler(
        {
            "/capability/mint": lambda b: httpx.Response(
                422, json={"error": "widening"}
            ),
            "/check-boundary": _boundary_ok,
        }
    )
    c = _client(handler)
    with delegate("child", ["p"], client=c) as grant:
        assert grant is None
        with pytest.raises(AegisValidationError) as ei:
            c.check_boundary("customer_support", ["name"])
    assert ei.value.code == "aegis.boundary.delegationDenied"
    # The mint failed, so there is no token to narrow with. Asking anyway would
    # answer at the PARENT's full width, and Doctor hands that answer's
    # allowed_fields to the agent as authorization (check_with_core →
    # BoundaryDecision.allowed_data). So the request must not leave the process
    # at all: only the failed mint reached the wire.
    assert [p.rsplit("/", 1)[-1] for p, _ in calls] == ["mint"]


@pytest.mark.parametrize("cap", [None, ""], ids=["none", "empty-string"])
def test_denied_window_refuses_even_with_an_explicit_opt_out(cap):
    # The refusal above was scoped to "argument unset", which left the explicit
    # opt-out as a one-keystroke way past it. ``None`` and ``""`` carry no
    # token, so inside a denied window they are the widening being denied, not
    # a legitimate opt-out. Cross-review (codex + cursor, 2026-07-29) found this
    # hole adjacent to the one the previous round closed; both models also noted
    # the test gap — opt-out was only ever exercised after a SUCCESSFUL mint,
    # denial only with unset or an explicit string, never the combination.
    handler, calls = _recording_handler(
        {
            "/capability/mint": lambda b: httpx.Response(
                422, json={"error": "widening"}
            ),
            "/check-boundary": _boundary_ok,
        }
    )
    c = _client(handler)
    with delegate("child", ["p"], client=c) as grant:
        assert grant is None
        with pytest.raises(AegisValidationError) as ei:
            c.check_boundary("customer_support", ["name"], capability=cap)
    assert ei.value.code == "aegis.boundary.delegationDenied"
    # Same oracle as the unset case: nothing but the failed mint may reach the
    # wire. A /check-boundary here means the opt-out asked at parent width.
    assert [p.rsplit("/", 1)[-1] for p, _ in calls] == ["mint"]


def test_explicit_none_opt_out_is_still_honoured_in_a_granted_window():
    # The fix must not turn opt-out into a no-op. Outside denial, ``None`` still
    # means "ask this one question without attaching the ambient token".
    handler, calls = _recording_handler(
        {"/capability/mint": _mint_ok, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("child", ["p"], client=c) as grant:
        assert grant is not None
        c.check_boundary("customer_support", ["name"], capability=None)
    assert "capability" not in _boundary_body(calls)


def test_delegate_without_an_explicit_client_still_mints(monkeypatch):
    # Regression: the origin was first read off the `client` ARGUMENT, which is
    # None when the caller relies on the module client. That raised
    # AttributeError inside delegate(), the broad except swallowed it, and every
    # default-usage window silently became DENIED. Every existing test passed an
    # explicit client, so nothing caught it — found by cross-review (cursor,
    # 2026-07-29). The origin now comes from the RESOLVED client.
    #
    # This drives the REAL resolution path (shield._get_client singleton), not a
    # monkeypatched _resolve_client: a stub resolver would still pass if the
    # resolution itself were the broken part (cursor's follow-up [P2]).
    # `import aegis_trust.shield as _shield` binds the FUNCTION: the package
    # re-exports `shield()`, which shadows the submodule attribute. Reach the
    # module through sys.modules instead.
    import sys

    import aegis_trust.shield  # noqa: F401  (ensure it is imported)

    _shield = sys.modules["aegis_trust.shield"]

    handler, calls = _recording_handler(
        {"/capability/mint": _mint_ok, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    prev = _shield._client
    _shield._client = c
    try:
        with delegate("child", ["p"]) as grant:
            assert grant is not None, "default-client window was denied"
            c.check_boundary("customer_support", ["name"])
    finally:
        _shield._client = prev
    assert "capability" in _boundary_body(calls)


def test_ambient_token_does_not_attach_to_a_different_client():
    # The store used to hold a bare bearer string, so any client built inside
    # the window picked it up — including one pointed at a different base URL.
    # That ships a capability minted for one boundary to another. Found by
    # cross-review (codex, 2026-07-29, severity high) on the merged change; the
    # store now carries the minting origin and the send path refuses mismatches.
    handler, calls = _recording_handler(
        {"/capability/mint": _mint_ok, "/check-boundary": _boundary_ok}
    )
    minting = _client(handler)
    other = _client(handler, base_url="https://other.invalid/api/v1")
    with delegate("child", ["p"], client=minting) as grant:
        assert grant is not None
        other.check_boundary("customer_support", ["name"])
    assert "capability" not in _boundary_body(calls)


def test_ambient_token_does_attach_to_the_minting_client():
    # Non-vacuity for the test above: if binding were always-refuse, the
    # negative test would pass while auto-attach was dead.
    handler, calls = _recording_handler(
        {"/capability/mint": _mint_ok, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("child", ["p"], client=c):
        c.check_boundary("customer_support", ["name"])
    assert "capability" in _boundary_body(calls)


def test_guard_tool_does_not_send_the_token_through_a_different_client(monkeypatch):
    # Path-level origin pin. The binding lives in one shared helper, but
    # cross-review (cursor, 2026-07-29) called shared-helper coverage what it
    # is: indirect. Each send path gets its own positive+negative pair so a path
    # that stops calling the helper fails HERE, not only in check_boundary.
    def routes(body):
        return httpx.Response(200, json={"outcome": "PASS"})

    handler, calls = _recording_handler(
        {"/capability/mint": _mint_ok, "/tool-call": routes}
    )
    minting = _client(handler)
    other = _client(handler, base_url="https://other.invalid/api/v1")
    monkeypatch.setenv("AEGIS_OWNER", "owner-1")
    with delegate("child", ["p"], client=minting):
        guard_tool(purpose="customer_support", client=other)(lambda: "ok")()
        guard_tool(purpose="customer_support", client=minting)(lambda: "ok")()
    tool_calls = [b for p_, b in calls if p_.endswith("/tool-call")]
    assert len(tool_calls) == 2
    assert "capability" not in tool_calls[0]  # other client
    assert "capability" in tool_calls[1]  # minting client


def test_nested_delegate_does_not_carry_the_parent_token_to_another_client():
    handler, calls = _recording_handler({"/capability/mint": _mint_ok})
    minting = _client(handler)
    other = _client(handler, base_url="https://other.invalid/api/v1")
    with delegate("child", ["p"], client=minting):
        with delegate("grand", ["p"], client=other):
            pass
        with delegate("grand2", ["p"], client=minting):
            pass
    mints = [b for p_, b in calls if p_.endswith("/mint")]
    assert len(mints) == 3
    assert "parent_capability" not in mints[1]  # other client
    assert "parent_capability" in mints[2]  # minting client


def test_explicit_capability_still_works_inside_a_denied_window():
    # The refusal is about the ambient path (nothing to attach). A caller
    # carrying a token across a process boundary by hand is not guessing.
    handler, calls = _recording_handler(
        {
            "/capability/mint": lambda b: httpx.Response(
                422, json={"error": "widening"}
            ),
            "/check-boundary": _boundary_ok,
        }
    )
    c = _client(handler)
    with delegate("child", ["p"], client=c):
        c.check_boundary("customer_support", ["name"], capability="cap-carried")
    assert _boundary_body(calls)["capability"] == "cap-carried"


# ── async boundaries ─────────────────────────────────────────────────


def test_acheck_boundary_captures_token_at_call_time_not_await_time():
    """The coroutine is CREATED inside the window and awaited after it exits.

    ``acheck_boundary`` is a plain ``def`` precisely so the ContextVar is read
    at call time; an ``async def`` would read it at await time — after the
    window reset it — and ask at full width with nothing to signal the loss.
    Node parity: the async prefix of ``checkBoundary`` runs inside the
    AsyncLocalStorage scope.
    """
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    c._async_httpx = httpx.AsyncClient(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={},
        timeout=httpx.Timeout(10.0),
    )

    pending = []
    with delegate("researcher", ["customer_support"], client=c):
        pending.append(c.acheck_boundary("customer_support", ["name"]))
    # Awaited OUTSIDE the window — the ContextVar has already been reset.
    asyncio.run(_await_all(pending))
    assert _boundary_body(calls)["capability"] == "cap-token-1"


async def _await_all(coros):
    return await asyncio.gather(*coros)


def test_token_does_not_leak_to_a_call_after_the_window_closed():
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        c.check_boundary("inside", ["name"])
    c.check_boundary("outside", ["name"])

    bodies = [b for p, b in calls if p.endswith("/check-boundary")]
    assert bodies[0]["capability"] == "cap-token-1"
    assert "capability" not in bodies[1]


def test_threads_without_a_copied_context_do_not_inherit_the_token():
    """Documents the mechanism's real edge: a bare ``threading.Thread`` does
    NOT inherit the ContextVar, so the call is made un-narrowed.

    This is the auto-attach contract's blind spot — the same forgetting the
    feature removes at the call site reappears at a thread boundary, with no
    signal. Pinned here so the limitation is visible rather than assumed away;
    callers crossing a thread must pass ``capability`` explicitly.
    """
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        t = threading.Thread(target=lambda: c.check_boundary("in_thread", ["name"]))
        t.start()
        t.join()
    assert "capability" not in _boundary_body(calls)


def test_contextvars_copy_context_does_carry_the_token_into_a_thread():
    """The documented escape hatch actually works: run the worker under a
    copied context and the narrowing survives the thread boundary."""
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        ctx = contextvars.copy_context()
        t = threading.Thread(
            target=lambda: ctx.run(c.check_boundary, "in_thread", ["name"])
        )
        t.start()
        t.join()
    assert _boundary_body(calls)["capability"] == "cap-token-1"


# ── wire shape (flat face, not the envelope dialect) ─────────────────


def test_never_nests_the_token_under_delegation():
    handler, calls = _recording_handler(
        {**_DELEGATION_ROUTES, "/check-boundary": _boundary_ok}
    )
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        c.check_boundary("customer_support", ["name"])
    body = _boundary_body(calls)
    # The server-side flat-wire handler refuses a nested `delegation`
    # outright, precisely so a wrong-shape token is never dropped silently and
    # answered at full width. Sending the flat key is the contract.
    assert "delegation" not in body
    assert body["capability"] == "cap-token-1"


# ── the 501 delegation refusal is named, not generic ─────────────────


def test_maps_501_with_capability_to_delegation_unsupported():
    handler, _ = _recording_handler({**_DELEGATION_ROUTES, "/check-boundary": _refuse})
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        with pytest.raises(AegisHttpError) as ei:
            c.check_boundary("customer_support", ["name"])
    assert ei.value.code == "aegis.boundary.delegationUnsupported"
    assert ei.value.status == 501
    # The remediation must name the DEPLOYMENT — an operator reading
    # "retry if 5xx" would wait out a condition that never clears.
    assert "decide-plane" in ei.value.remediation


def test_501_still_raises_fail_closed():
    handler, _ = _recording_handler({**_DELEGATION_ROUTES, "/check-boundary": _refuse})
    c = _client(handler)
    with delegate("researcher", ["customer_support"], client=c):
        with pytest.raises(AegisHttpError):
            c.check_boundary("customer_support", ["name"])


def test_501_without_capability_stays_the_generic_envelope():
    handler, _ = _recording_handler({"/check-boundary": _refuse})
    with pytest.raises(AegisHttpError) as ei:
        _client(handler).check_boundary("customer_support", ["name"])
    assert ei.value.code == "aegis.http.nonOk"
