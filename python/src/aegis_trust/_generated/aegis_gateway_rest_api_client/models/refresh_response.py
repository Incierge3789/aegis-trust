from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RefreshResponse")


@_attrs_define
class RefreshResponse:
    """
    Attributes:
        access_token (str): New JWT access token
        expires_at (int): Token expiration as Unix timestamp
        expires_in (int): Token lifetime in seconds
        token (str): New JWT access token (legacy alias)
        token_type (str): Token type (always "Bearer")
    """

    access_token: str
    expires_at: int
    expires_in: int
    token: str
    token_type: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        access_token = self.access_token

        expires_at = self.expires_at

        expires_in = self.expires_in

        token = self.token

        token_type = self.token_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "access_token": access_token,
                "expires_at": expires_at,
                "expires_in": expires_in,
                "token": token,
                "token_type": token_type,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        access_token = d.pop("access_token")

        expires_at = d.pop("expires_at")

        expires_in = d.pop("expires_in")

        token = d.pop("token")

        token_type = d.pop("token_type")

        refresh_response = cls(
            access_token=access_token,
            expires_at=expires_at,
            expires_in=expires_in,
            token=token,
            token_type=token_type,
        )

        refresh_response.additional_properties = d
        return refresh_response

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
