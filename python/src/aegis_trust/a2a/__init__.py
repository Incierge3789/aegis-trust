"""A2A extension surface (v0, prerelease, unpublished).

Reports Aegis boundary decisions using A2A's own vocabulary — an existing
``TaskState`` plus a substate in ``metadata``. Activation is client-requested
via the ``A2A-Extensions`` header; the extension is a reporting vocabulary, not
an enforcement mechanism.
"""

from aegis_trust.a2a.activation import (
    DELIVERY_CHANNELS,
    WITHHELD_STATUS,
    A2AActivationError,
    bind_activation,
    bind_activation_from_negotiation,
    filter_decision_metadata_for_delivery,
    is_activated_for,
)
from aegis_trust.a2a.extension import (
    A2A_EXTENSIONS_HEADER,
    AEGIS_A2A_EXTENSION_URI_V0,
    AEGIS_A2A_EXTENSION_VERSION,
    A2AExtensionError,
    NegotiationResult,
    assert_no_enforcement_claim,
    build_agent_card_extension,
    is_placeholder_extension_uri,
    negotiate_extensions,
    place_decision_metadata,
)
from aegis_trust.a2a.mapping import (
    LEGAL_OUTCOME_REASON_PAIRS,
    A2AMappingError,
    DecisionMapping,
    map_decision_to_a2a,
    validate_outcome_reason,
)
from aegis_trust.a2a.privacy import (
    REASON_LABELS,
    A2APrivacyError,
    validate_decision_substate,
)
from aegis_trust.a2a.reducer import (
    TERMINAL_TASK_STATES,
    A2AReducerError,
    AuthorizationRequest,
    RejectedEvent,
    TaskReduction,
    build_authorization_request,
    build_obligation_status_update,
    obligation_keys_equal,
    reduce_task_state,
)
from aegis_trust.a2a.verification import (
    PRODUCER_TRUST_ASSERTION_KEYS,
    A2AVerificationError,
    DerivedVerification,
    assert_no_producer_trust_assertions,
    derive_verification_status,
)

__all__ = [
    "A2A_EXTENSIONS_HEADER",
    "A2AActivationError",
    "A2AExtensionError",
    "A2AMappingError",
    "A2APrivacyError",
    "A2AReducerError",
    "A2AVerificationError",
    "AEGIS_A2A_EXTENSION_URI_V0",
    "AEGIS_A2A_EXTENSION_VERSION",
    "AuthorizationRequest",
    "DELIVERY_CHANNELS",
    "DecisionMapping",
    "DerivedVerification",
    "LEGAL_OUTCOME_REASON_PAIRS",
    "NegotiationResult",
    "PRODUCER_TRUST_ASSERTION_KEYS",
    "REASON_LABELS",
    "RejectedEvent",
    "TERMINAL_TASK_STATES",
    "TaskReduction",
    "WITHHELD_STATUS",
    "assert_no_enforcement_claim",
    "assert_no_producer_trust_assertions",
    "bind_activation",
    "bind_activation_from_negotiation",
    "build_agent_card_extension",
    "build_authorization_request",
    "build_obligation_status_update",
    "derive_verification_status",
    "filter_decision_metadata_for_delivery",
    "is_activated_for",
    "is_placeholder_extension_uri",
    "map_decision_to_a2a",
    "negotiate_extensions",
    "obligation_keys_equal",
    "place_decision_metadata",
    "reduce_task_state",
    "validate_decision_substate",
    "validate_outcome_reason",
]
