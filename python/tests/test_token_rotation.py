"""Token rotation tests (T-155, S023 Phase 4 Build).

Closes cursor CU1 finding: the module-level AegisClient captured the
AEGIS_TOKEN value at first _get_client() call, so subsequent env updates
(e.g., scheduled JWT refresh, bearer rotation) never reached the backend.

AegisClient.set_token() + shield.refresh_token() rotate the token, discard
the cached httpx clients, and invalidate the check-access allow cache (a
new principal invalidates prior decisions).
"""

from __future__ import annotations

import httpx
import pytest

from aegis_trust.client import AegisClient
from aegis_trust.shield import _get_client, refresh_token, reset


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    reset()
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)
    yield
    reset()


def test_set_token_updates_stored_token():
    c = AegisClient(token="old")
    assert c._token == "old"
    c.set_token("new")
    assert c._token == "new"


def test_set_token_discards_http_clients():
    c = AegisClient(token="old")
    _ = c._get_httpx()
    _ = c._get_async_httpx()
    assert c._httpx is not None and c._async_httpx is not None
    c.set_token("new")
    assert c._httpx is None and c._async_httpx is None


def test_set_token_invalidates_access_cache():
    c = AegisClient(token="old")
    c._remember_allow("support", ["name"], epoch_at_request=c._token_epoch)
    assert c._cached_allow("support", ["name"])
    c.set_token("new")
    assert not c._cached_allow("support", ["name"])


def test_set_token_bumps_epoch():
    """Phase 5 fix: epoch must change so any in-flight authorize() captured
    under the old epoch becomes a no-op when it tries to cache.
    """
    c = AegisClient(token="old")
    e0 = c._token_epoch
    c.set_token("new")
    assert c._token_epoch == e0 + 1


def test_in_flight_authorize_after_rotate_does_not_poison_cache():
    """Simulate the race: capture epoch, rotate, then call _remember_allow
    with the captured epoch — must be a no-op.
    """
    c = AegisClient(token="old")
    captured_epoch = c._token_epoch
    c.set_token("new")
    c._remember_allow("support", ["name"], epoch_at_request=captured_epoch)
    assert not c._cached_allow("support", ["name"])


def test_refresh_token_reads_env(monkeypatch):
    monkeypatch.setenv("AEGIS_TOKEN", "initial")
    client = _get_client()
    assert client._token == "initial"

    monkeypatch.setenv("AEGIS_TOKEN", "rotated")
    refresh_token()
    assert client._token == "rotated"


def test_next_request_uses_new_token(monkeypatch):
    """End-to-end: rotating the token changes the Authorization header sent
    on the next httpx call.
    """
    seen_auth: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("Authorization"))
        if request.url.path.endswith("/check-access"):
            return httpx.Response(200, json={"allowed": True})
        return httpx.Response(200, json={"status": "ok"})

    c = AegisClient(token="first")
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer first"},
        timeout=httpx.Timeout(5.0),
    )
    c.check_access("support", ["name"])
    assert seen_auth[-1] == "Bearer first"

    c.set_token("second")
    # set_token discarded the client; recreate with the same handler.
    c._httpx = httpx.Client(
        base_url=c._base_url,
        transport=httpx.MockTransport(handler),
        headers=c._auth_headers(),
        timeout=httpx.Timeout(5.0),
    )
    c.check_access("support", ["name"])
    assert seen_auth[-1] == "Bearer second"


def test_rotate_zeroizes_old_bytearray_token():
    old = bytearray(b"super-secret-jwt-12345")
    c = AegisClient(token=old)
    # aliasing the buffer ensures _clear_sensitive mutates in place
    c.set_token("new")

    # Buffer contents are expected to be wiped. Tolerate either full
    # zeroing or length preservation depending on platform.
    assert bytes(old) != b"super-secret-jwt-12345" or len(old) == 0


# ── FD leak regression (T-172, S024 Phase 3 cross-review C2) ───────────


def test_set_token_closes_sync_client():
    """set_token() must close the old sync httpx.Client; otherwise
    repeated rotations leak one socket each."""
    c = AegisClient(token="first")
    # Force construction of the sync client.
    sync_client = c._get_httpx()
    assert sync_client is not None

    c.set_token("second")

    # Old client is detached from the AegisClient instance and was
    # explicitly closed so its connection pool released.
    assert c._httpx is not sync_client
    assert sync_client.is_closed, (
        "set_token must close the old sync httpx.Client to avoid FD leaks"
    )


def test_set_token_outside_loop_warns():
    """Rotating outside an event loop cannot `await aclose()`. Emit a
    ResourceWarning so operators catch the leak vector instead of
    silently discarding an open AsyncClient."""
    import warnings

    c = AegisClient(token="first")
    # Force the async client to exist without awaiting anything.
    c._get_async_httpx()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        c.set_token("second")

    leaked = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert leaked, "expected ResourceWarning when rotating outside an event loop"


def test_set_token_inside_loop_schedules_close():
    """Inside an event loop, set_token must schedule aclose() on the
    old AsyncClient rather than warn."""
    import asyncio

    async def runner():
        c = AegisClient(token="first")
        # Swap in a MockTransport-backed AsyncClient so we hold a
        # reference and can assert it was closed after set_token().
        c._async_httpx = httpx.AsyncClient(
            base_url=c._base_url,
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, json={"allowed": True})
            ),
            headers=c._auth_headers(),
            timeout=httpx.Timeout(5.0),
        )
        tracked = c._async_httpx
        c.set_token("second")
        # Yield to let the scheduled task run.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert tracked.is_closed, (
            "set_token inside a loop must schedule the async client's aclose()"
        )

    asyncio.run(runner())
