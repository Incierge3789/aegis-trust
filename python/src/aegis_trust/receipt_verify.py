"""Keyless (LITE) structural verifier for Aegis boundary receipts.

What the SDK CAN verify without any key material (gap 1 — the consumer-side
receipt verifier):

* ``session_dag_root`` — recompute the SHA-256 aggregation root over a Session
  Receipt's ``event_receipt_refs`` + ``fragment_tags`` (cross-impl pinned with
  Aegis Core ``boundary_adapter::session_dag_root``).
* ``verify_session_receipt_structure`` — schema tag, sorted/deduped refs+tags,
  dag_root recomputation, value-free fragment tags.
* ``dangling_prior_receipt_refs`` — Cross-Agent Receipt Linkage integrity
  (S139 VULN-2): every cited prior receipt must exist in the receipt set you
  hold.
* ``compute_lineage_root`` / ``verify_lineage_root`` — the fragment lineage
  hash (domain ``aegis-fragment-lineage.v1``), byte-for-byte with Core.

HONESTY BOUNDARY (LITE vs FULL — never overclaim): ``audit_chain_link`` is an
HMAC keyed by the tenant's boundary master key. WITHOUT that key this module
can only check structure and internal consistency — it can NOT prove
authenticity or chain integrity. Keyed verification is Aegis Core's runtime
territory (``verify_session_receipt`` in the engine). Zero-dep stdlib only.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Mapping, Sequence

SPAN_CRYPTO_SCHEMA_TAG = "aegis-span-crypto.v0"
LINEAGE_ROOT_LEN = 32
_LINEAGE_DOMAIN = b"aegis-fragment-lineage.v1"
_SESSION_DAG_DOMAIN = b"aegis-session-receipt.v1"
_VALUE_FREE_EXTRA = frozenset("._:-")


def is_value_free_label(s: str) -> bool:
    """Value-free metadata label gate: ASCII ``[A-Za-z0-9._:-]``, 1..=128."""
    return 1 <= len(s) <= 128 and all(
        (c.isalnum() and c.isascii()) or c in _VALUE_FREE_EXTRA for c in s
    )


def session_dag_root(
    event_receipt_refs: Sequence[str], fragment_tags: Sequence[str]
) -> str:
    """Recompute a Session Receipt's ``dag_root`` (hex). Inputs are used AS
    STORED on the receipt (Core sorts + dedups before sealing)."""
    h = hashlib.sha256()
    h.update(_SESSION_DAG_DOMAIN)
    for r in event_receipt_refs:
        h.update(r.encode("utf-8"))
        h.update(b"\x00")
    h.update(b"\xff")
    for t in fragment_tags:
        h.update(t.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def verify_session_receipt_structure(receipt: Mapping[str, object]) -> list[str]:
    """Structural verification of a Session Receipt. Returns the list of
    problems found (empty = structurally sound). NEVER claims authenticity —
    the keyed ``audit_chain_link`` is verifiable only by the key holder.

    Hostile-input contract (S022 hardening): non-string members in
    ``event_receipt_refs`` / ``fragment_tags`` are reported as problems —
    this function returns, it never raises (previously mixed unorderable
    types raised ``TypeError`` out of ``sorted()``, breaking the documented
    returns-problems contract)."""
    problems: list[str] = []
    schema = receipt.get("schema")
    if schema != SPAN_CRYPTO_SCHEMA_TAG:
        problems.append(f"schema is {schema!r}, expected {SPAN_CRYPTO_SCHEMA_TAG!r}")
    refs = list(receipt.get("event_receipt_refs") or [])  # type: ignore[call-overload]
    tags = list(receipt.get("fragment_tags") or [])  # type: ignore[call-overload]
    refs_ok = all(isinstance(r, str) for r in refs)
    tags_ok = all(isinstance(t, str) for t in tags)
    if not refs_ok:
        problems.append("event_receipt_refs contain non-string members")
    elif refs != sorted(set(refs)):
        problems.append("event_receipt_refs are not sorted+deduplicated")
    if not tags_ok:
        problems.append("fragment_tags contain non-string members")
    elif tags != sorted(set(tags)):
        problems.append("fragment_tags are not sorted+deduplicated")
    for t in tags:
        if not isinstance(t, str) or not is_value_free_label(t):
            problems.append(f"fragment_tag {t!r} is not a value-free label")
    claimed = receipt.get("dag_root")
    if refs_ok and tags_ok:
        recomputed = session_dag_root(refs, tags)
        if claimed != recomputed:
            problems.append("dag_root does not recompute over the stored refs+tags")
    else:
        # Never hash coerced values: a receipt whose dag_root was sealed over
        # str()-coerced non-strings must not be reported as recomputing.
        problems.append("dag_root not checked (non-string refs/tags cannot be hashed)")
    if not receipt.get("audit_chain_link"):
        problems.append("audit_chain_link missing (keyed link is Core-verifiable only)")
    return problems


def dangling_prior_receipt_refs(
    declared: Iterable[str], existing: Iterable[str]
) -> tuple[str, ...]:
    """The declared prior receipt refs that do NOT exist in ``existing`` —
    dangling / fabricated links (S139 VULN-2). Order-preserving, deduplicated.
    Empty result = every cited prior exists in the receipt set you hold."""
    existing_set = set(existing)
    seen: set[str] = set()
    out: list[str] = []
    for d in declared:
        if d in existing_set or d in seen:
            continue
        seen.add(d)
        out.append(d)
    return tuple(out)


def _len_prefixed(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def compute_lineage_root(
    fragment_tag: str,
    source_kind: str,
    locator: str,
    field_set: Sequence[str] = (),
    prior_lineage_roots: Sequence[bytes] = (),
) -> bytes:
    """The 32-byte fragment lineage root (domain ``aegis-fragment-lineage.v1``).
    Byte-for-byte with Core (``lineage::compute_lineage_root``) and the
    aegisbase reference (``fragment_ledger.compute_lineage_root``)."""
    if not fragment_tag or not fragment_tag.strip():
        raise ValueError("fragment_tag must be non-empty")
    if not is_value_free_label(fragment_tag):
        raise ValueError(
            "fragment_tag must be a value-free label ([A-Za-z0-9._:-], <=128)"
        )
    for r in prior_lineage_roots:
        if len(r) != LINEAGE_ROOT_LEN:
            raise ValueError("each prior lineage_root must be 32 bytes")
    if len(set(prior_lineage_roots)) != len(prior_lineage_roots):
        raise ValueError("duplicate parent lineage_root (cite each parent once)")
    h = hashlib.sha256()
    h.update(_LINEAGE_DOMAIN)
    h.update(_len_prefixed(fragment_tag.encode("utf-8")))
    h.update(_len_prefixed(source_kind.encode("utf-8")))
    h.update(_len_prefixed(locator.encode("utf-8")))
    fields = sorted(set(field_set))
    h.update(len(fields).to_bytes(4, "big"))
    for f in fields:
        h.update(_len_prefixed(f.encode("utf-8")))
    h.update(len(prior_lineage_roots).to_bytes(4, "big"))
    for r in sorted(prior_lineage_roots):
        h.update(r)
    return h.digest()


def verify_lineage_root(
    fragment_tag: str,
    source_kind: str,
    locator: str,
    field_set: Sequence[str],
    resolved_parent_roots: Sequence[bytes],
    claimed_root: bytes,
) -> None:
    """Forged-lineage guard: recompute over the RESOLVED parents and compare.
    Raises ``ValueError`` on mismatch (fail-closed)."""
    expected = compute_lineage_root(
        fragment_tag, source_kind, locator, field_set, resolved_parent_roots
    )
    if expected != claimed_root:
        raise ValueError(
            "lineage_root does not match resolved parents (forged lineage)"
        )
