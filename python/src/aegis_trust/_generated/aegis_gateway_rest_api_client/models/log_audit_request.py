from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogAuditRequest")


@_attrs_define
class LogAuditRequest:
    """
    Attributes:
        decision (str): Access decision (allow/deny)
        purpose (str): Purpose of the audited action
        requester_id (str): Requester identifier
        tool_name (str): Tool name that performed the action
        bytes_returned (int | None | Unset): Bytes returned
        reason (None | str | Unset): Reason for decision
        session_id (None | str | Unset): Session identifier
    """

    decision: str
    purpose: str
    requester_id: str
    tool_name: str
    bytes_returned: int | None | Unset = UNSET
    reason: None | str | Unset = UNSET
    session_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        decision = self.decision

        purpose = self.purpose

        requester_id = self.requester_id

        tool_name = self.tool_name

        bytes_returned: int | None | Unset
        if isinstance(self.bytes_returned, Unset):
            bytes_returned = UNSET
        else:
            bytes_returned = self.bytes_returned

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        session_id: None | str | Unset
        if isinstance(self.session_id, Unset):
            session_id = UNSET
        else:
            session_id = self.session_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "decision": decision,
                "purpose": purpose,
                "requester_id": requester_id,
                "tool_name": tool_name,
            }
        )
        if bytes_returned is not UNSET:
            field_dict["bytes_returned"] = bytes_returned
        if reason is not UNSET:
            field_dict["reason"] = reason
        if session_id is not UNSET:
            field_dict["session_id"] = session_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        decision = d.pop("decision")

        purpose = d.pop("purpose")

        requester_id = d.pop("requester_id")

        tool_name = d.pop("tool_name")

        def _parse_bytes_returned(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        bytes_returned = _parse_bytes_returned(d.pop("bytes_returned", UNSET))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        def _parse_session_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        session_id = _parse_session_id(d.pop("session_id", UNSET))

        log_audit_request = cls(
            decision=decision,
            purpose=purpose,
            requester_id=requester_id,
            tool_name=tool_name,
            bytes_returned=bytes_returned,
            reason=reason,
            session_id=session_id,
        )

        log_audit_request.additional_properties = d
        return log_audit_request

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
