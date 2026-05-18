"""Best-effort zeroize helper tests (T-138, S023 Phase 4 Build).

Verifies SDK-side `_clear_sensitive()` behavior per the split-responsibility
model documented in SECURITY.md §Memory posture. Authoritative zeroize is a
gateway responsibility; this helper only covers the in-process best-effort.
"""

from __future__ import annotations

from aegis_trust.client import _clear_sensitive


def test_bytearray_is_zeroed_in_place():
    buf = bytearray(b"super-secret-token-12345")
    _clear_sensitive(buf)
    assert buf == bytearray(len(b"super-secret-token-12345"))
    assert all(byte == 0 for byte in buf)


def test_multiple_bytearrays_all_zeroed():
    a = bytearray(b"token-a")
    b = bytearray(b"token-b-longer")
    _clear_sensitive(a, b)
    assert all(x == 0 for x in a)
    assert all(x == 0 for x in b)


def test_non_bytearray_is_ignored_without_raising():
    """str/bytes cannot be mutated in CPython. Helper must not raise; the
    SECURITY.md posture already disclaims this path.
    """
    s = "a secret string"
    b = b"a secret bytes"
    _clear_sensitive(s, b, 42, None)


def test_empty_call_is_noop():
    _clear_sensitive()


def test_empty_bytearray():
    buf = bytearray(b"")
    _clear_sensitive(buf)
    assert buf == bytearray(b"")
