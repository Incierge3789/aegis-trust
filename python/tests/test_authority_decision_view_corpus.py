"""Cross-SDK AI-native ``decision`` reader conformance — Python runner.

Executes ``conformance/authority_decision_view.v0.json`` through the SHIPPED
:func:`aegis_trust.client.parse_authority_decision`. The Node SDK runs the
same corpus. Every invalid vector pins the refusal code AND a message
fragment, so both SDKs name the same member in the same words.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aegis_trust.client import AuthorityDecisionView, parse_authority_decision
from aegis_trust.errors import AegisValidationError

CORPUS = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "authority_decision_view.v0.json"
    ).read_text(encoding="utf-8")
)


def test_corpus_version_pinned() -> None:
    assert CORPUS["version"] == "v0"
    assert CORPUS["valid"] and CORPUS["invalid"]


def _project(view: AuthorityDecisionView, expect: dict[str, Any]) -> dict[str, Any]:
    """Project the parsed view onto the keys the vector asserts."""
    out: dict[str, Any] = {}
    for key in expect:
        if key == "parts_boundaries":
            out[key] = [p.boundary for p in view.parts]
        elif key == "parts_1_fragment_tags":
            out[key] = list(view.parts[1].fragment_tags)
        else:
            value = getattr(view, key)
            # The view holds tuples (immutable); the corpus writes JSON lists.
            out[key] = list(value) if isinstance(value, tuple) else value
    return out


@pytest.mark.parametrize("vector", CORPUS["valid"], ids=lambda v: v["id"])
def test_valid(vector: dict[str, Any]) -> None:
    view = parse_authority_decision(vector["decision"])
    assert _project(view, vector["expect"]) == vector["expect"], vector["why"]


@pytest.mark.parametrize("vector", CORPUS["invalid"], ids=lambda v: v["id"])
def test_invalid(vector: dict[str, Any]) -> None:
    with pytest.raises(AegisValidationError) as excinfo:
        parse_authority_decision(vector["decision"])
    assert excinfo.value.code == vector["expect_error"], vector["why"]
    assert excinfo.value.code == CORPUS["error_code"]
    assert vector["expect_detail"] in str(excinfo.value), vector["why"]
    # Backward-compat envelope: still a ValueError for pre-rich-envelope callers.
    assert isinstance(excinfo.value, ValueError)
