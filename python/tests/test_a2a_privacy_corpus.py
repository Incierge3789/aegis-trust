"""Cross-SDK A2A privacy / verification / activation conformance — Python runner.

Executes ``conformance/a2a_privacy.v0.json`` through the SHIPPED per-field
validator, producer trust-assertion guard, consumer verification derivation,
and per-principal delivery filter. The Node SDK runs the same corpus.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from aegis_trust.a2a.activation import (
    WITHHELD_STATUS,
    A2AActivationError,
    bind_activation,
    filter_decision_metadata_for_delivery,
)
from aegis_trust.a2a.mapping import A2AMappingError
from aegis_trust.a2a.privacy import A2APrivacyError, validate_decision_substate
from aegis_trust.a2a.verification import (
    A2AVerificationError,
    assert_no_producer_trust_assertions,
    derive_verification_status,
)

CORPUS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "conformance" / "a2a_privacy.v0.json"
    ).read_text(encoding="utf-8")
)

URI = CORPUS["extension_uri"]


def test_corpus_version_pinned() -> None:
    assert CORPUS["version"] == "v0"


@pytest.mark.parametrize("vector", CORPUS["substate_validation"], ids=lambda v: v["id"])
def test_substate_validation(vector: dict[str, Any]) -> None:
    provenance = vector["provenance"]
    kwargs = {
        "declared_field_names": provenance.get("declared_field_names"),
        "approver_roles": provenance.get("approver_roles"),
    }
    if vector.get("expect_valid"):
        validate_decision_substate(vector["substate"], **kwargs)
        return
    # Pair-inventory failures surface as mapping errors; everything else as
    # privacy errors. Both are fail-closed refusals with stable codes.
    with pytest.raises((A2APrivacyError, A2AMappingError)) as excinfo:
        validate_decision_substate(vector["substate"], **kwargs)
    assert excinfo.value.code == vector["expect_error"], vector["why"]


@pytest.mark.parametrize("vector", CORPUS["producer_assertions"], ids=lambda v: v["id"])
def test_producer_assertions(vector: dict[str, Any]) -> None:
    if vector.get("expect_clean"):
        assert_no_producer_trust_assertions(vector["payload"], vector["id"])
        return
    with pytest.raises(A2AVerificationError) as excinfo:
        assert_no_producer_trust_assertions(vector["payload"], vector["id"])
    assert excinfo.value.code == vector["expect_error"], vector["why"]


@pytest.mark.parametrize(
    "vector", CORPUS["verification_derivation"], ids=lambda v: v["id"]
)
def test_verification_derivation(vector: dict[str, Any]) -> None:
    provenance = vector["provenance"]
    kwargs = {
        "substate": vector["substate"],
        "declared_field_names": provenance.get("declared_field_names"),
        "approver_roles": provenance.get("approver_roles"),
        "receipt_structure": vector["receipt_structure"],
    }
    if "expect_error" in vector:
        with pytest.raises(A2AVerificationError) as excinfo:
            derive_verification_status(**kwargs)
        assert excinfo.value.code == vector["expect_error"], vector["why"]
        return
    derived = derive_verification_status(**kwargs)
    assert derived.status == vector["expect"]["status"], vector["why"]
    assert list(derived.basis) == vector["expect"]["basis"], vector["why"]
    # The ceiling is part of the contract: what this does NOT establish is
    # always stated, and the status vocabulary has no issuer-authenticated
    # member for a keyless consumer to reach.
    assert derived.status in ("unverified", "structure_verified")
    assert list(derived.limits) == [
        "does_not_establish_issuer_identity",
        "does_not_establish_enforcement",
        "keyed_chain_verification_is_core_territory",
    ]


@pytest.mark.parametrize("vector", CORPUS["delivery_filter"], ids=lambda v: v["id"])
def test_delivery_filter(vector: dict[str, Any]) -> None:
    metadata = vector["metadata"]
    before = copy.deepcopy(metadata)
    filtered = filter_decision_metadata_for_delivery(
        metadata,
        vector["bindings"],
        principal=vector["query"]["principal"],
        task_id=vector["query"]["task_id"],
        channel=vector["query"]["channel"],
    )
    # Never mutates the caller's mapping.
    assert metadata == before

    kind = vector["expect"]["kind"]
    if kind == "passthrough":
        assert filtered == metadata, vector["why"]
        return
    if kind == "unchanged_absent":
        assert filtered == metadata, vector["why"]
        assert URI not in filtered
        return
    # withheld: the key survives (distinguishable from never-reported), the
    # content does not.
    assert URI in filtered, vector["why"]
    marker = filtered[URI]
    assert sorted(marker) == ["reason", "status", "version"], vector["why"]
    assert marker["status"] == WITHHELD_STATUS
    for banned in ("outcome", "reason_code", "withheld_fields", "approver"):
        assert banned not in marker
    # Unrelated metadata is untouched.
    for k, val in metadata.items():
        if k != URI:
            assert filtered[k] == val


@pytest.mark.parametrize("vector", CORPUS["activation_binding"], ids=lambda v: v["id"])
def test_activation_binding(vector: dict[str, Any]) -> None:
    if "expect_error" in vector:
        with pytest.raises(A2AActivationError) as excinfo:
            bind_activation(vector["existing"], vector["bind"])
        assert excinfo.value.code == vector["expect_error"], vector["why"]
        return
    bindings = bind_activation(vector["existing"], vector["bind"])
    if vector.get("bind_again"):
        bindings = bind_activation(bindings, vector["bind"])
    assert len(bindings) == vector["expect_count"], vector["why"]
