"""S1005 — adversarial pass on the @shield LITE-mode trust-boundary claims.

THREAT_MODEL.md §1 (LITE, local-first) makes four load-bearing statements
about what the in-process boundary does and does not defend. A security
assessment is only honest if those statements are mechanically exercised —
both the *positive* protections (which must hold) and the *negative*
non-claims (which must remain true, i.e. the documented escape hatches stay
open so the doc keeps telling the truth).

Mapping to THREAT_MODEL.md §1:
  Claim 1 (positive): in-process minimum-disclosure filtering — an
          @shield-wrapped function returns no field outside the declared
          scope, even when the underlying handler returns more.
  Claim 2 (positive): exception-payload leaks fail closed — a handler that
          raises with sensitive data in the message yields empty, not the
          payload.
  Claim 3 (positive): conversion-failure leaks fail closed — an object the
          normalizer cannot convert returns empty (the _ConversionFailed
          sentinel path), never the opaque object.
  Claim 4 (negative / honesty): LITE does NOT defend against a malicious
          host process in the same interpreter. The doc says such code can
          "call the unwrapped function" or "monkey-patch the decorator".
          These tests assert those bypasses still work — if a future change
          silently closed them, LITE's documented threat boundary (and the
          "use FULL mode against a hostile host" guidance) would be wrong
          and must be re-reviewed, not celebrated.

Claims 1–3 are regression guards. Claim 4 is a documentation-honesty guard.
"""

from __future__ import annotations

import importlib

import pytest

from aegis_trust import shield
from aegis_trust.shield import reset


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset()
    monkeypatch.setenv("AEGIS_MODE", "lite")
    yield
    reset()


# ── Claim 1: in-process minimum-disclosure filtering holds ──────────


def test_claim1_scope_drops_undeclared_fields():
    """A wrapped handler returning extra fields leaks none outside scope."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {
            "name": "Aki",
            "ssn": "123-45-6789",
            "card": "4111-1111-1111-1111",
            "internal_note": "VIP — do not disclose",
        }

    result = get_customer()
    assert result == {"name": "Aki"}
    for secret in ("ssn", "card", "internal_note"):
        assert secret not in result


def test_claim1_deny_fields_strips_named_paths():
    """deny_fields blacklist removes exactly the named path, in-process."""

    @shield(purpose="support", deny_fields=["ssn"])
    def get_customer():
        return {"name": "Aki", "ssn": "123-45-6789"}

    result = get_customer()
    assert result.get("name") == "Aki"
    assert "ssn" not in result


# ── Claim 2: exception-payload leaks fail closed ────────────────────


def test_claim2_exception_payload_does_not_leak():
    """Sensitive data in a raised exception must not reach the caller."""

    @shield(purpose="support", scope=["name"])
    def get_customer():
        raise ConnectionError(
            "connect failed: postgres://admin:s3cr3t_pw@db.internal:5432/t"
        )

    result = get_customer()
    assert result == ""
    assert "s3cr3t_pw" not in str(result)


# ── Claim 3: conversion-failure leaks fail closed ───────────────────


def test_claim3_unconvertible_object_returns_empty():
    """An opaque object the normalizer cannot convert must fail closed.

    The handler returns an instance whose attributes hold sensitive state.
    The shield normalizer has no conversion path for a plain opaque object,
    so the documented behaviour is to return empty (fail-closed), never the
    object or its secret-bearing repr.
    """

    class Opaque:
        def __init__(self):
            self.ssn = "123-45-6789"

        def __repr__(self):  # pragma: no cover - must never be disclosed
            return f"Opaque(ssn={self.ssn})"

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return Opaque()

    result = get_customer()
    assert result == "" or result == {} or result is None
    assert "123-45-6789" not in str(result)


# ── Claim 4: same-process bypasses remain open (doc honesty) ────────


def test_claim4_unwrapped_function_is_reachable():
    """THREAT_MODEL §1 says same-interpreter code can call the unwrapped fn.

    @functools.wraps exposes __wrapped__. This is BY DESIGN: LITE does not
    defend against a hostile host. If __wrapped__ ever disappears, the
    threat-model statement is stale and the boundary section must be
    re-reviewed — this test failing means "go fix the doc", not "ship it".
    """

    @shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Aki", "ssn": "123-45-6789"}

    # Filtered path: secret withheld.
    assert "ssn" not in get_customer()

    # Same-process attacker reaches the raw handler via the documented
    # escape hatch and recovers everything. LITE makes no claim to stop this.
    raw = get_customer.__wrapped__
    leaked = raw()
    assert leaked["ssn"] == "123-45-6789"


def test_claim4_monkeypatch_of_decorator_is_possible(monkeypatch):
    """THREAT_MODEL §1 says same-interpreter code can monkey-patch the decorator.

    We replace the module-level shield with an identity decorator, re-bind a
    handler through it, and confirm filtering is gone. This models a
    compromised host neutralizing LITE enforcement — explicitly out of scope
    for LITE and the reason FULL mode exists. Asserting it remains possible
    keeps the documented non-claim truthful.
    """
    mod = importlib.import_module("aegis_trust.shield")

    def identity_decorator(*_args, **_kwargs):
        def wrap(fn):
            return fn

        return wrap

    monkeypatch.setattr(mod, "shield", identity_decorator)

    @mod.shield(purpose="support", scope=["name"])
    def get_customer():
        return {"name": "Aki", "ssn": "123-45-6789"}

    # Enforcement neutralized by the in-process patch: full record flows.
    result = get_customer()
    assert result["ssn"] == "123-45-6789"
