from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BatchQueryItem")


@_attrs_define
class BatchQueryItem:
    """
    Attributes:
        purpose (str): Purpose for data access
        query (str): Query string
        destination (None | str | Unset): Optional destination for result routing
    """

    purpose: str
    query: str
    destination: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        purpose = self.purpose

        query = self.query

        destination: None | str | Unset
        if isinstance(self.destination, Unset):
            destination = UNSET
        else:
            destination = self.destination

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "purpose": purpose,
                "query": query,
            }
        )
        if destination is not UNSET:
            field_dict["destination"] = destination

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        purpose = d.pop("purpose")

        query = d.pop("query")

        def _parse_destination(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        destination = _parse_destination(d.pop("destination", UNSET))

        batch_query_item = cls(
            purpose=purpose,
            query=query,
            destination=destination,
        )

        batch_query_item.additional_properties = d
        return batch_query_item

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
