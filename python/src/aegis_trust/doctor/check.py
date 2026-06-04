"""Deterministic boundary diagnosis — ``doctor.check`` (Python, v0).

Given an :class:`ActionPlan` and a :class:`LocalPolicy`, return a
:class:`BoundaryDecision`. Pure, local, deterministic — no network, no LLM, no
Core. The decision's ``allowed_data`` is meant to be passed straight to
``shield(scope=...)`` (via :meth:`BoundaryDecision.scope_for_shield`).

v0 produces ALLOW / REDUCE_SCOPE / REQUIRE_APPROVAL / BLOCK. REQUIRE_CHECK is
reserved for a later release.

Hardening (doctor-v0 trust-boundary, S-redteam): all field matching is
*path-aware* and *normalized*, not flat byte-exact membership. A forbidden or
sensitive field blocks/strips any path that **is**, **descends from**, or
**encloses** it (``ssn`` blocks ``profile.ssn``; ``config`` blocks
``config.api_key``; ``a.b.c`` blocks a bare ``a.b`` request that would expand to
the whole subtree). Comparison is Unicode-NFC + casefold + whitespace-trimmed so
``SSN`` cannot dodge ``ssn``. Unknown destinations are treated as external
(fail-closed), and an unknown purpose against a non-empty policy yields an empty
allow set rather than allowing everything.
"""

from __future__ import annotations

import unicodedata

from aegis_trust.doctor.policy import LocalPolicy
from aegis_trust.doctor.types import ActionPlan, BoundaryDecision, BoundaryOutcome


def _norm(s: str) -> str:
    """Canonicalize a field/destination token for comparison.

    NFKC-normalize (so compatibility variants — full-width ``ＳＳＮ``, ligatures,
    etc. — fold to their ASCII form and cannot dodge a guard), strip surrounding
    whitespace, and casefold so ``SSN`` / ``ssn`` / ``ssn`` + trailing space all
    compare equal. Used only for *matching*; the original token is preserved in
    the decision so it still lines up with shield's view of the real data keys.
    """
    return unicodedata.normalize("NFKC", s).strip().casefold()


def _segments(path: str) -> list[str]:
    return _norm(path).split(".")


def _is_valid_path(path: str) -> bool:
    """Mirror shield's ``_validate_field_path`` rules (fail-closed at the gate).

    Rejects empty strings, leading/trailing dots, and consecutive dots so a
    malformed ``data_requested`` entry (e.g. ``"a..b"``) is caught *here* rather
    than deferred to ``shield(scope=...)`` construction.
    """
    if not path or path != path.strip():
        return False
    if path.startswith(".") or path.endswith("."):
        return False
    if ".." in path:
        return False
    return True


def _covered_by(path: str, guards: list[str]) -> bool:
    """True if ``path`` is forbidden/stripped by any guard in ``guards``.

    A guard ``g`` covers ``path`` when, after normalization, any of:
      * they are equal;
      * ``path`` descends from ``g`` (``g`` = ``ssn``, path = ``profile.ssn``
        via segment membership, or ``g`` = ``config``, path = ``config.api_key``);
      * ``path`` encloses ``g`` (``g`` = ``a.b.c``, path = ``a.b`` — requesting
        the parent would expand to the whole subtree that contains ``g``).
    """
    np = _norm(path)
    segs = set(_segments(path))
    for g in guards:
        ng = _norm(g)
        if not ng:
            continue
        if np == ng:
            return True
        if np.startswith(ng + "."):  # path descends from guard
            return True
        if ng.startswith(np + "."):  # path encloses guard
            return True
        if "." not in ng and ng in segs:  # bare-leaf guard appears as a segment
            return True
    return False


def _allowed_by_whitelist(path: str, allow: list[str]) -> bool:
    """A path is permitted by an allow-whitelist only when it *is* an allowed
    field or *descends from* one. Requesting a parent of an allowed leaf is
    **not** granted (that would over-disclose the whole container via shield).

    Matching is **exact** (NOT normalized), unlike the never/sensitive/deny
    guards. Normalization is deliberately one-directional: a *guard* normalizes
    so it blocks more (``SSN`` is caught by ``ssn`` — fail-closed); the *allow*
    list must NOT, because the matched token is emitted into ``allowed_data`` and
    handed to shield, which resolves the **literal** data key. If ``allow=["name"]``
    loosely matched a request for ``"NAME"``, doctor would authorize and shield
    would disclose the *distinct* ``NAME`` field the operator never allowed — a
    normalization confused-deputy. Exact match keeps authorization aligned with
    the operator's literal intent (fail-closed). Leading/trailing-whitespace
    requests are already rejected by ``_is_valid_path`` at the gate.
    """
    for a in allow:
        if not a:
            continue
        if path == a or path.startswith(a + "."):
            return True
    return False


def check(plan: ActionPlan, policy: LocalPolicy | None = None) -> BoundaryDecision:
    """Diagnose ``plan`` against ``policy`` and return a deterministic decision."""
    policy = policy or LocalPolicy()
    requested = list(plan.data_requested)

    # 0. Malformed field paths fail closed at the gate (don't defer to shield).
    malformed = [f for f in requested if not _is_valid_path(f)]
    if malformed:
        return BoundaryDecision(
            outcome=BoundaryOutcome.BLOCK,
            purpose=plan.purpose,
            allowed_data=[],
            blocked_data=requested,
            allowed_tools=[],
            reason_codes=["MALFORMED_FIELD_PATH"],
            receipt_required=True,
        )

    # 1. Hard block: a forbidden field requested at all (e.g. secrets, .env).
    #    Path-aware: ``never_fields=["ssn"]`` also blocks ``profile.ssn``;
    #    ``["config"]`` blocks ``config.api_key``. Fail-closed.
    hard = [f for f in requested if _covered_by(f, policy.never_fields)]
    if hard:
        return BoundaryDecision(
            outcome=BoundaryOutcome.BLOCK,
            purpose=plan.purpose,
            allowed_data=[],
            blocked_data=requested,
            allowed_tools=[],
            reason_codes=["FORBIDDEN_FIELD_REQUESTED"],
            receipt_required=True,
        )

    # 2. Per-purpose allow/deny → the baseline allowed set.
    rule = policy.purposes.get(plan.purpose)
    if rule is not None and rule.allow is not None:
        allowed = [f for f in requested if _allowed_by_whitelist(f, rule.allow)]
    elif rule is not None and rule.deny:
        allowed = [f for f in requested if not _covered_by(f, rule.deny)]
    elif rule is None and policy.purposes and policy.strict_unknown_purpose:
        # Purpose whitelist exists but this purpose is unknown: fail-closed.
        # An attacker must not disable the policy graph with a novel purpose.
        allowed = []
    else:
        allowed = list(requested)

    # 3. Minimum disclosure to external destinations: strip sensitive fields
    #    (path-aware) before anything leaves the trust boundary. A destination
    #    that is named but classified as neither internal nor external is
    #    treated as EXTERNAL (fail-closed) — an unknown sink must not receive
    #    sensitive data silently.
    def _is_external(d: str) -> bool:
        # Classifying a destination as *internal* is the permissive direction
        # (sensitive fields are NOT stripped), so — like the allow-list — it must
        # match **exactly**. Loose normalization here is a confused-deputy: a
        # variant label like ``INTERNAL_SINK`` (a *different* actual endpoint)
        # would fold onto the trusted ``internal_sink`` and sensitive data would
        # flow to it. The *external* direction is restrictive (strip), and an
        # unclassified destination defaults to external anyway, so normalizing it
        # only ever fails closed.
        if d in policy.internal_destinations:
            return False
        nd = _norm(d)
        if any(nd == _norm(x) for x in policy.external_destinations):
            return True
        # Named but unclassified → external (fail-closed).
        return True

    goes_external = any(_is_external(d) for d in plan.destinations)
    if goes_external and policy.sensitive_fields:
        allowed = [f for f in allowed if not _covered_by(f, policy.sensitive_fields)]

    blocked = [f for f in requested if f not in allowed]

    # 4. Approval seam: action-type rules.
    approval_required_for: list[str] = []
    act_rule = policy.actions.get(plan.action_type)
    if act_rule is not None and act_rule.requires_approval:
        approval_required_for.append(plan.action_type)

    # 5. Reason codes + outcome (priority: approval > reduce > allow).
    reason_codes: list[str] = []
    if blocked:
        reason_codes.append("DATA_NOT_REQUIRED_FOR_PURPOSE")
    if goes_external and any(
        _covered_by(f, policy.sensitive_fields) for f in requested
    ):
        reason_codes.append("EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE")
    if approval_required_for:
        reason_codes.append("ACTION_REQUIRES_HUMAN_APPROVAL")

    if approval_required_for:
        outcome = BoundaryOutcome.REQUIRE_APPROVAL
    elif blocked:
        outcome = BoundaryOutcome.REDUCE_SCOPE
    else:
        outcome = BoundaryOutcome.ALLOW

    return BoundaryDecision(
        outcome=outcome,
        purpose=plan.purpose,
        allowed_data=allowed,
        blocked_data=blocked,
        allowed_tools=list(plan.tools),
        approval_required_for=approval_required_for,
        reason_codes=reason_codes,
        receipt_required=(outcome is not BoundaryOutcome.ALLOW) or bool(blocked),
    )
