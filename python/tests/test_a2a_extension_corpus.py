"""Cross-SDK A2A extension surface conformance — Python runner.

Executes ``conformance/a2a_extension.v0.json`` through the SHIPPED negotiation,
honesty guard, placeholder guard, and metadata placement. The Node SDK runs the
same corpus through its shipped equivalents.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_trust.a2a.extension import (
    AEGIS_A2A_EXTENSION_URI_V0,
    A2AExtensionError,
    assert_no_enforcement_claim,
    build_agent_card_extension,
    is_placeholder_extension_uri,
    negotiate_extensions,
    place_decision_metadata,
)
from aegis_trust.errors import AegisError

CORPUS = Path(__file__).resolve().parents[2] / "conformance" / "a2a_extension.v0.json"
_DATA = json.loads(CORPUS.read_text())


def test_corpus_version_and_identifier_are_pinned() -> None:
    assert _DATA["version"] == "v0"
    assert _DATA["extension_uri"] == AEGIS_A2A_EXTENSION_URI_V0


@pytest.mark.parametrize("vector", _DATA["negotiation"], ids=lambda v: v["id"])
def test_negotiation(vector: dict) -> None:
    result = negotiate_extensions(vector["header"])
    assert result.activated == vector["expect"]["activated"]
    assert list(result.requested) == vector["expect"]["requested"]
    assert list(result.echo) == vector["expect"]["echo"]
    assert result.reason == vector["expect"].get("reason")


@pytest.mark.parametrize("vector", _DATA["honesty"], ids=lambda v: v["id"])
def test_honesty_guard(vector: dict) -> None:
    if not vector["expect_rejected"]:
        assert_no_enforcement_claim(vector["text"], "corpus")
        return
    with pytest.raises(A2AExtensionError) as excinfo:
        assert_no_enforcement_claim(vector["text"], "corpus")
    assert excinfo.value.code == vector["expect_code"]


@pytest.mark.parametrize("vector", _DATA["placeholder"], ids=lambda v: v["id"])
def test_placeholder_guard(vector: dict) -> None:
    assert is_placeholder_extension_uri(vector["uri"]) is vector["expect_placeholder"]


@pytest.mark.parametrize("vector", _DATA["metadata_placement"], ids=lambda v: v["id"])
def test_metadata_placement(vector: dict) -> None:
    negotiation = negotiate_extensions(
        AEGIS_A2A_EXTENSION_URI_V0 if vector["activated"] else None
    )
    existing = dict(vector["existing_metadata"])
    provenance = vector.get("provenance", {})
    kwargs = {
        "declared_field_names": provenance.get("declared_field_names"),
        "approver_roles": provenance.get("approver_roles"),
    }
    if "expect_error" in vector:
        # Emission-side refusals cross module boundaries (activation errors are
        # A2AExtensionError, honesty errors too, producer-assertion errors are
        # A2AVerificationError, provenance errors are A2APrivacyError) — all
        # are AegisError with a pinned stable code.
        with pytest.raises(AegisError) as excinfo:
            place_decision_metadata(existing, vector["substate"], negotiation, **kwargs)
        assert excinfo.value.code == vector["expect_error"]
        return
    out = place_decision_metadata(existing, vector["substate"], negotiation, **kwargs)
    # The COMPLETE output is pinned, not just the named keys — a mutant that
    # smuggles an extra sibling into the result would otherwise stay green
    # (round-1 codex, the corpus/battery survivor).
    assert out == {
        **vector["existing_metadata"],
        vector["expect_key"]: vector["expect_value"],
    }
    # The caller's mapping is not mutated.
    assert vector["expect_key"] not in existing


def test_agent_card_declaration_makes_no_enforcement_claim() -> None:
    decl = build_agent_card_extension()
    assert decl["uri"] == AEGIS_A2A_EXTENSION_URI_V0
    # Never ``required: True`` — that is a request-construction notice, not a
    # gate, and a "required" security-flavoured extension invites the exact
    # misreading this surface must avoid.
    assert decl["required"] is False
    assert decl["params"]["identifier_is_placeholder"] is True
    assert_no_enforcement_claim(json.dumps(decl), "AgentCard declaration")


def test_shipped_identifier_stays_detectable_as_a_placeholder() -> None:
    # If this ever goes green with a real URI, registration happened — which is
    # an ownership decision, not a code change.
    assert is_placeholder_extension_uri(AEGIS_A2A_EXTENSION_URI_V0) is True
