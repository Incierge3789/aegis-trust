from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="PolicyComplianceSchema")


@_attrs_define
class PolicyComplianceSchema:
    """
    Attributes:
        ao_001_gateway_sole_boundary (str):
        ao_002_minimum_disclosure (str):
        ao_003_tamper_evident_audit (str):
        ao_004_capsule_integrity (str):
    """

    ao_001_gateway_sole_boundary: str
    ao_002_minimum_disclosure: str
    ao_003_tamper_evident_audit: str
    ao_004_capsule_integrity: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ao_001_gateway_sole_boundary = self.ao_001_gateway_sole_boundary

        ao_002_minimum_disclosure = self.ao_002_minimum_disclosure

        ao_003_tamper_evident_audit = self.ao_003_tamper_evident_audit

        ao_004_capsule_integrity = self.ao_004_capsule_integrity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ao_001_gateway_sole_boundary": ao_001_gateway_sole_boundary,
                "ao_002_minimum_disclosure": ao_002_minimum_disclosure,
                "ao_003_tamper_evident_audit": ao_003_tamper_evident_audit,
                "ao_004_capsule_integrity": ao_004_capsule_integrity,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ao_001_gateway_sole_boundary = d.pop("ao_001_gateway_sole_boundary")

        ao_002_minimum_disclosure = d.pop("ao_002_minimum_disclosure")

        ao_003_tamper_evident_audit = d.pop("ao_003_tamper_evident_audit")

        ao_004_capsule_integrity = d.pop("ao_004_capsule_integrity")

        policy_compliance_schema = cls(
            ao_001_gateway_sole_boundary=ao_001_gateway_sole_boundary,
            ao_002_minimum_disclosure=ao_002_minimum_disclosure,
            ao_003_tamper_evident_audit=ao_003_tamper_evident_audit,
            ao_004_capsule_integrity=ao_004_capsule_integrity,
        )

        policy_compliance_schema.additional_properties = d
        return policy_compliance_schema

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
