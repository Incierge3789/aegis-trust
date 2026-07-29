"""INV-3 — LITE performs no outbound communication, observed directly (Python).

This file exists to satisfy a rule, and the rule is the point.

invariants.v0.json states that absence of a network dependency is NOT accepted
as satisfaction of INV-3: it is evidence about packaging, not about behaviour,
and it stops being true the moment the dependency arrives for an unrelated
reason. Python's entire prior inventory for this invariant was of that shape --
test_lite_zero_dep.py greps pyproject.toml and runs a subprocess with
sys.modules['httpx'] = None. Both prove the SDK CANNOT reach the network in a
LITE install. Neither observes that it DOES NOT.

The tempting move was to mark Python exempt on the grounds that it is
structurally incapable. That is precisely the exemption the suite forbids:
structural impossibility is a claim, and unverified claims are what this exists
to remove. So the indirect proof is promoted to direct observation here rather
than annotated as satisfied.

WHY THE SOCKET LAYER, NOT httpx. The Node counterpart replaces globalThis.fetch
and asserts zero calls -- genuine direct observation, but blind to node:http,
raw sockets, DNS, and child processes. Patching httpx here would inherit that
blindness, and would also observe nothing at all in a LITE install where httpx
is never imported. socket.socket.connect and socket.getaddrinfo sit underneath
every egress path Python has, so an observation there covers routes nobody
thought to enumerate. This is deliberately STRONGER than the Node side; the Node
gap is recorded as a hole in invariants.v0.json rather than matched downward.

NON-VACUITY. An observer that silently fails to observe reports a clean result,
which is the exact failure mode this whole suite was built after finding. So the
observer proves itself first: test_observer_actually_observes makes a real
connection attempt inside the observer and asserts it is recorded. If that test
is removed or weakened, every other assertion here becomes worthless.

Mirror: node/tests/fullMode.test.ts "Mode.LITE explicit > never calls backend"
(narrower: fetch surface only).
"""

from __future__ import annotations

import socket
from contextlib import contextmanager
from typing import Any

import pytest

from aegis_trust import shield, wrap
from aegis_trust.doctor import ActionPlan, check
from aegis_trust.types import Mode


class _EgressObserver:
    """Records every attempt to reach the network, at the lowest layer available."""

    def __init__(self) -> None:
        self.attempts: list[str] = []


@contextmanager
def observe_egress(monkeypatch: pytest.MonkeyPatch):
    """Record (and refuse) any outbound attempt for the duration of the block.

    Refusing rather than allowing matters: if the code under test DID try to
    egress, we want a loud failure inside the SDK rather than a real connection
    to a real host from a test run.
    """
    obs = _EgressObserver()
    real_connect = socket.socket.connect

    def spy_connect(self: socket.socket, address: Any) -> None:  # noqa: ANN401
        obs.attempts.append(f"socket.connect({address!r})")
        raise AssertionError(f"LITE attempted an outbound connection to {address!r}")

    def spy_getaddrinfo(host: Any, port: Any, *a: Any, **k: Any) -> Any:  # noqa: ANN401
        obs.attempts.append(f"getaddrinfo({host!r}, {port!r})")
        raise AssertionError(f"LITE attempted a DNS lookup for {host!r}")

    monkeypatch.setattr(socket.socket, "connect", spy_connect, raising=True)
    monkeypatch.setattr(socket, "getaddrinfo", spy_getaddrinfo, raising=True)
    try:
        yield obs
    finally:
        monkeypatch.setattr(socket.socket, "connect", real_connect, raising=True)


def test_observer_actually_observes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-vacuity: prove the observer sees an egress attempt before trusting a clean run.

    Without this, a typo in the patch target would make every assertion below
    pass by observing nothing. That is the failure mode the conformance suite was
    built after finding, and it applies to observers as much as to tests.
    """
    with observe_egress(monkeypatch) as obs:
        with pytest.raises(AssertionError):
            socket.create_connection(("example.invalid", 80), timeout=0.01)
    assert obs.attempts, (
        "the observer recorded nothing on a real attempt — it is broken"
    )


@pytest.mark.parametrize("mode_env", ["lite", None])
def test_wrap_does_not_egress(
    monkeypatch: pytest.MonkeyPatch, mode_env: str | None
) -> None:
    """wrap() is the most-used LITE entry point and had no egress observation at all."""
    if mode_env:
        monkeypatch.setenv("AEGIS_MODE", mode_env)
    else:
        monkeypatch.delenv("AEGIS_MODE", raising=False)
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)

    with observe_egress(monkeypatch) as obs:
        result = wrap(
            {"name": "a", "email": "b@c.d", "ssn": "x"},
            purpose="support",
            scope=["name"],
        )
    assert result.data == {"name": "a"}
    assert obs.attempts == [], f"LITE wrap() egressed: {obs.attempts}"


def test_shield_decorator_does_not_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    """The path the Node suite observes, observed here too, at a lower layer."""
    monkeypatch.setenv("AEGIS_MODE", "lite")
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)

    @shield(purpose="support", scope=["name"])
    def get_user() -> dict[str, str]:
        return {"name": "a", "secret": "s"}

    with observe_egress(monkeypatch) as obs:
        out = get_user()
    assert "secret" not in out
    assert obs.attempts == [], f"LITE shield() egressed: {obs.attempts}"


def test_doctor_check_does_not_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    """doctor.check is the local decision source and must never consult anything.

    Listed as an uncovered LITE path in invariants.v0.json; covered here.
    """
    monkeypatch.setenv("AEGIS_MODE", "lite")
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)

    with observe_egress(monkeypatch) as obs:
        decision = check(
            ActionPlan(
                purpose="support",
                action_type="send",
                data_requested=["name", "ssn"],
                destinations=["internal_reply"],
            )
        )
    assert decision is not None
    assert obs.attempts == [], f"doctor.check egressed: {obs.attempts}"


def test_auto_without_token_resolves_to_lite_without_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AUTO resolution is itself a boundary decision, and it is registered as a backend.

    Node asserts AUTO-with-no-token stays local; Python had no equivalent. If
    resolution ever probes the backend before deciding, that probe IS egress and
    this fails.
    """
    monkeypatch.setenv("AEGIS_MODE", "auto")
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)

    with observe_egress(monkeypatch) as obs:
        result = wrap({"name": "a", "ssn": "x"}, purpose="support", scope=["name"])
    assert result.data == {"name": "a"}
    assert obs.attempts == [], (
        f"AUTO without a token egressed while resolving: {obs.attempts}"
    )


def test_lite_mode_is_what_we_think_it_is(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards against the suite passing because nothing ran in LITE at all.

    Every assertion above is worthless if the calls silently executed in some
    other mode, so pin that LITE is the mode actually exercised.
    """
    monkeypatch.setenv("AEGIS_MODE", "lite")
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)
    result = wrap({"name": "a"}, purpose="support", scope=["name"])
    assert result.mode == Mode.LITE, f"expected LITE, ran as {result.mode}"
