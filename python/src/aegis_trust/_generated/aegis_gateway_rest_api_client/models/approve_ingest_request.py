from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ApproveIngestRequest")


@_attrs_define
class ApproveIngestRequest:
    """
    Attributes:
        capsule_id (str): Capsule identifier to approve
        allowed_purposes (list[str] | None | Unset): Allowed purposes for this data
    """

    capsule_id: str
    allowed_purposes: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        capsule_id = self.capsule_id

        allowed_purposes: list[str] | None | Unset
        if isinstance(self.allowed_purposes, Unset):
            allowed_purposes = UNSET
        elif isinstance(self.allowed_purposes, list):
            allowed_purposes = self.allowed_purposes

        else:
            allowed_purposes = self.allowed_purposes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "capsule_id": capsule_id,
            }
        )
        if allowed_purposes is not UNSET:
            field_dict["allowed_purposes"] = allowed_purposes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        capsule_id = d.pop("capsule_id")

        def _parse_allowed_purposes(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                allowed_purposes_type_0 = cast(list[str], data)

                return allowed_purposes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        allowed_purposes = _parse_allowed_purposes(d.pop("allowed_purposes", UNSET))

        approve_ingest_request = cls(
            capsule_id=capsule_id,
            allowed_purposes=allowed_purposes,
        )

        approve_ingest_request.additional_properties = d
        return approve_ingest_request

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
