from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="HashSignRequest")


@_attrs_define
class HashSignRequest:
    """
    Attributes:
        capsule_id (str): Capsule identifier to sign
        provider (str): Signing provider
        signer_email (str): Signer email address
        signer_name (str): Signer display name
    """

    capsule_id: str
    provider: str
    signer_email: str
    signer_name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        capsule_id = self.capsule_id

        provider = self.provider

        signer_email = self.signer_email

        signer_name = self.signer_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "capsule_id": capsule_id,
                "provider": provider,
                "signer_email": signer_email,
                "signer_name": signer_name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        capsule_id = d.pop("capsule_id")

        provider = d.pop("provider")

        signer_email = d.pop("signer_email")

        signer_name = d.pop("signer_name")

        hash_sign_request = cls(
            capsule_id=capsule_id,
            provider=provider,
            signer_email=signer_email,
            signer_name=signer_name,
        )

        hash_sign_request.additional_properties = d
        return hash_sign_request

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
