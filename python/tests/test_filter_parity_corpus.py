"""Cross-SDK LITE filtering conformance — Python runner.

Executes the shared corpus (`conformance/filter_parity.v0.json`) through the
Python SDK's public `wrap()` and asserts each vector's `data` and removed-key
SET. The Node SDK runs the SAME corpus (node/tests/filterParityCorpus.test.ts).
Both passing on one corpus is the drift-proof guarantee that the two SDKs filter
identically — the foundation hand-mirrored per-SDK tests cannot provide.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_trust import wrap

CORPUS = Path(__file__).resolve().parents[2] / "conformance" / "filter_parity.v0.json"


def _load_cases() -> list[dict]:
    data = json.loads(CORPUS.read_text())
    assert data["version"] == 0
    return data["cases"]


CASES = _load_cases()


def test_corpus_is_present_and_nonempty() -> None:
    assert CASES, "shared filter-parity corpus must define cases"


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_filter_parity_vector(case: dict) -> None:
    result = wrap(
        case["input"],
        purpose=case["purpose"],
        scope=case.get("scope"),
        deny_fields=case.get("deny_fields"),
    )
    assert result.data == case["expected_data"], (
        f"{case['id']}: data mismatch\n  got={result.data}\n  exp={case['expected_data']}"
    )
    # Order-independent: both SDKs report the same SET of removed paths.
    assert sorted(result.filtered_keys) == sorted(case["expected_filtered_keys"]), (
        f"{case['id']}: filtered_keys mismatch\n"
        f"  got={sorted(result.filtered_keys)}\n  exp={sorted(case['expected_filtered_keys'])}"
    )
