from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AuditChainSchema")


@_attrs_define
class AuditChainSchema:
    """
    Attributes:
        chain_integrity (str): "VERIFIED" or "FAILED"
        first_hash (str):
        last_hash (str):
        total_entries (int):
    """

    chain_integrity: str
    first_hash: str
    last_hash: str
    total_entries: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        chain_integrity = self.chain_integrity

        first_hash = self.first_hash

        last_hash = self.last_hash

        total_entries = self.total_entries

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "chain_integrity": chain_integrity,
                "first_hash": first_hash,
                "last_hash": last_hash,
                "total_entries": total_entries,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chain_integrity = d.pop("chain_integrity")

        first_hash = d.pop("first_hash")

        last_hash = d.pop("last_hash")

        total_entries = d.pop("total_entries")

        audit_chain_schema = cls(
            chain_integrity=chain_integrity,
            first_hash=first_hash,
            last_hash=last_hash,
            total_entries=total_entries,
        )

        audit_chain_schema.additional_properties = d
        return audit_chain_schema

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
