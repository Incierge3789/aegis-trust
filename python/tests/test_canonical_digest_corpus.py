"""Cross-SDK canonical idempotency-digest conformance — Python runner.

Executes the shared corpus (`conformance/canonical_digest.v0.json`) through the
Python SDK's shipped ``_payload_hash``. The Node SDK runs the SAME corpus
(node/tests/canonicalDigestCorpus.test.ts) through its shipped ``_payloadHash``.

Before this corpus the expected digest was a string literal duplicated in both
suites, with nothing forcing the two copies to agree — an edit to one side would
have left the other green and surfaced the divergence to a customer rather than
to CI. There is now exactly one place the digest is written down.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_trust.history import _payload_hash

CORPUS = (
    Path(__file__).resolve().parents[2] / "conformance" / "canonical_digest.v0.json"
)


def _load() -> dict:
    data = json.loads(CORPUS.read_text())
    assert data["version"] == 0
    assert data["algorithm"] == "sha256"
    return data


CORPUS_DATA = _load()
CASES = CORPUS_DATA["cases"]


def _digest(case_input: dict) -> str:
    return _payload_hash(
        function=case_input["function"],
        purpose=case_input["purpose"],
        scope=case_input["scope"],
        deny_fields=case_input["denyFields"],
        blocked_fields=case_input["blockedFields"],
        mode=case_input["mode"],
    )


def test_corpus_is_present_and_nonempty() -> None:
    assert CASES, "shared canonical-digest corpus must define cases"


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_canonical_digest_vector(case: dict) -> None:
    got = _digest(case["input"])
    assert got == case["expected_digest"], (
        f"{case['id']}: digest mismatch\n"
        f"  got={got}\n  exp={case['expected_digest']}\n"
        f"  {case['doc']}"
    )


def test_schema_version_is_not_an_input_to_the_digest() -> None:
    """S017 D-D, structurally: the signature has no place to accept it.

    ``_payload_hash`` is keyword-only, so passing ``schema_version`` raises
    rather than silently participating in the hash. That is a stronger guarantee
    than asserting the digest is unchanged, which a future implementation could
    satisfy while still reading the value.
    """
    anchor = next(c for c in CASES if c["id"] == "anchor-sorted-input")
    with pytest.raises(TypeError):
        _payload_hash(  # type: ignore[call-arg]
            function=anchor["input"]["function"],
            purpose=anchor["input"]["purpose"],
            scope=anchor["input"]["scope"],
            deny_fields=anchor["input"]["denyFields"],
            blocked_fields=anchor["input"]["blockedFields"],
            mode=anchor["input"]["mode"],
            schema_version=99,
        )
