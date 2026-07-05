"""Keyless receipt verifier — cross-impl pinned vectors + structure checks.

The hex vectors below are PINNED on both sides: Aegis Core pins the same
values in ``boundary_adapter::tests::session_dag_root_cross_impl_pinned_vectors``
and ``lineage::tests`` (aegis-boundary-core). A change on either side that
breaks these is a coordinated wire-schema change, not a refactor.
"""

from aegis_trust.receipt_verify import (
    SPAN_CRYPTO_SCHEMA_TAG,
    compute_lineage_root,
    dangling_prior_receipt_refs,
    session_dag_root,
    verify_lineage_root,
    verify_session_receipt_structure,
)


def test_session_dag_root_cross_impl_pinned_vectors():
    assert (
        session_dag_root([], [])
        == "00c3c8b5599715ad4288d8d4a1b3bfe6e4f92e6ba0b26bc1fc7fb650ae08e973"
    )
    assert (
        session_dag_root(["ev-1", "ev-2"], ["sensitive:Finance", "sensitive:Patent"])
        == "a44775d7432f7d21231e3410af0ca72a8dcad00d187f02aeb5539eddb6ca0dab"
    )


def _receipt():
    refs = ["ev-1", "ev-2"]
    tags = ["sensitive:Finance", "sensitive:Patent"]
    return {
        "schema": SPAN_CRYPTO_SCHEMA_TAG,
        "session_id": "s1",
        "event_receipt_refs": refs,
        "fragment_tags": tags,
        "dag_root": session_dag_root(refs, tags),
        "audit_chain_link": "ab" * 32,
    }


def test_structurally_sound_receipt_has_no_problems():
    assert verify_session_receipt_structure(_receipt()) == []


def test_tampered_receipt_is_detected():
    r = _receipt()
    r["fragment_tags"] = ["sensitive:Finance"]  # tag stripped after sealing
    problems = verify_session_receipt_structure(r)
    assert any("dag_root" in p for p in problems)

    r2 = _receipt()
    r2["schema"] = "aegis-span-crypto.v999"
    assert any("schema" in p for p in verify_session_receipt_structure(r2))

    r3 = _receipt()
    r3["fragment_tags"] = ["自己資金は1200万円"]  # value smuggled into a tag
    assert any("value-free" in p for p in verify_session_receipt_structure(r3))


def test_dangling_prior_refs_detected():
    existing = {"ev-1", "ev-2"}
    assert dangling_prior_receipt_refs(["ev-2", "ev-9", "ev-9", "ev-8"], existing) == (
        "ev-9",
        "ev-8",
    )
    assert dangling_prior_receipt_refs(["ev-1"], existing) == ()


def test_lineage_root_cross_impl_pinned_vectors():
    # Same vectors pinned in Core lineage::tests (Python aegisbase oracle).
    r1 = compute_lineage_root("crm:customer", "file", "doc-123", ["name", "addr"])
    assert r1.hex() == "9d36c954ae2595be57ff3e1c07090212bc1c3a20cb8a27bcce82a1940edabb97"
    r2 = compute_lineage_root("crm:contract_value", "file", "doc-456", ["amount"], [r1])
    assert r2.hex() == "404ec0c907d7dc2cc463f159f744e017bd1cca9e3aaaab6a894907dbcc8877f3"
    ra = compute_lineage_root("t.x", "s", "l", ["b", "a", "a"], sorted([r1, r2]))
    rb = compute_lineage_root("t.x", "s", "l", ["a", "b"], [r2, r1])
    assert ra == rb
    assert ra.hex() == "5b93afcd12a957a54306e356d406d4790808c55a0541f68f9853710e451e0223"


def test_forged_lineage_fails_closed():
    parent = compute_lineage_root("a", "file", "doc-1", ["name"])
    good = compute_lineage_root("b", "file", "doc-1", ["name"], [parent])
    verify_lineage_root("b", "file", "doc-1", ["name"], [parent], good)  # ok
    try:
        verify_lineage_root("b", "file", "doc-1", ["name"], [], good)
        raise AssertionError("must fail on wrong parent set")
    except ValueError:
        pass
    try:
        compute_lineage_root("has space", "s", "l")
        raise AssertionError("value-bearing tag must be refused")
    except ValueError:
        pass
