from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ProofSummarySchema")


@_attrs_define
class ProofSummarySchema:
    """
    Attributes:
        allowed (int):
        denied (int):
        protocols_used (list[str]):
        total_requests (int):
        unique_agents (list[str]):
        unique_scopes_used (list[str]):
    """

    allowed: int
    denied: int
    protocols_used: list[str]
    total_requests: int
    unique_agents: list[str]
    unique_scopes_used: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        allowed = self.allowed

        denied = self.denied

        protocols_used = self.protocols_used

        total_requests = self.total_requests

        unique_agents = self.unique_agents

        unique_scopes_used = self.unique_scopes_used

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "allowed": allowed,
                "denied": denied,
                "protocols_used": protocols_used,
                "total_requests": total_requests,
                "unique_agents": unique_agents,
                "unique_scopes_used": unique_scopes_used,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        allowed = d.pop("allowed")

        denied = d.pop("denied")

        protocols_used = cast(list[str], d.pop("protocols_used"))

        total_requests = d.pop("total_requests")

        unique_agents = cast(list[str], d.pop("unique_agents"))

        unique_scopes_used = cast(list[str], d.pop("unique_scopes_used"))

        proof_summary_schema = cls(
            allowed=allowed,
            denied=denied,
            protocols_used=protocols_used,
            total_requests=total_requests,
            unique_agents=unique_agents,
            unique_scopes_used=unique_scopes_used,
        )

        proof_summary_schema.additional_properties = d
        return proof_summary_schema

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
