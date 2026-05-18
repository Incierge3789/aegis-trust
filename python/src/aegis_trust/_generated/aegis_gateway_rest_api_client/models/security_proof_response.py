from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.audit_chain_schema import AuditChainSchema
    from ..models.policy_compliance_schema import PolicyComplianceSchema
    from ..models.proof_summary_schema import ProofSummarySchema


T = TypeVar("T", bound="SecurityProofResponse")


@_attrs_define
class SecurityProofResponse:
    """
    Attributes:
        audit_chain (AuditChainSchema):
        generated_at (str): Generation timestamp
        policy_compliance (PolicyComplianceSchema):
        proof_id (str): Unique proof identifier (sp-*)
        session_id (str): Session this proof covers
        summary (ProofSummarySchema):
    """

    audit_chain: AuditChainSchema
    generated_at: str
    policy_compliance: PolicyComplianceSchema
    proof_id: str
    session_id: str
    summary: ProofSummarySchema
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        audit_chain = self.audit_chain.to_dict()

        generated_at = self.generated_at

        policy_compliance = self.policy_compliance.to_dict()

        proof_id = self.proof_id

        session_id = self.session_id

        summary = self.summary.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "audit_chain": audit_chain,
                "generated_at": generated_at,
                "policy_compliance": policy_compliance,
                "proof_id": proof_id,
                "session_id": session_id,
                "summary": summary,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.audit_chain_schema import AuditChainSchema
        from ..models.policy_compliance_schema import PolicyComplianceSchema
        from ..models.proof_summary_schema import ProofSummarySchema

        d = dict(src_dict)
        audit_chain = AuditChainSchema.from_dict(d.pop("audit_chain"))

        generated_at = d.pop("generated_at")

        policy_compliance = PolicyComplianceSchema.from_dict(d.pop("policy_compliance"))

        proof_id = d.pop("proof_id")

        session_id = d.pop("session_id")

        summary = ProofSummarySchema.from_dict(d.pop("summary"))

        security_proof_response = cls(
            audit_chain=audit_chain,
            generated_at=generated_at,
            policy_compliance=policy_compliance,
            proof_id=proof_id,
            session_id=session_id,
            summary=summary,
        )

        security_proof_response.additional_properties = d
        return security_proof_response

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
