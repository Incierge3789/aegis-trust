"""Declarative local boundary policy — the deterministic rule source for
``doctor.check`` (Python). v0 is local-only; org-wide authoritative policy
enforcement is Core's job, not this.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PurposeRule:
    """Per-purpose field rules. Use ``allow`` (whitelist) OR ``deny`` (blacklist),
    mirroring shield's minimum-disclosure contract. ``allow=None`` means 'no
    whitelist' (fall back to deny / sensitive handling)."""

    allow: list[str] | None = None
    deny: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ActionRule:
    """Per-action-type rules."""

    requires_approval: bool = False


@dataclass(frozen=True)
class LocalPolicy:
    """The declarative rules doctor evaluates against an ActionPlan.

    - ``purposes``: per-purpose allow/deny field rules.
    - ``sensitive_fields``: fields stripped before any *external* destination.
    - ``never_fields``: fields that, if requested at all, hard-BLOCK the action
      (e.g. secrets / ``.env`` / raw card numbers).
    - ``external_destinations``: destinations explicitly treated as outside the
      trust boundary (e.g. ``external_llm``).
    - ``internal_destinations``: destinations explicitly trusted as inside the
      boundary. Any named destination that is in *neither* list is treated as
      **external** (fail-closed minimum disclosure) — an unknown sink must not
      silently receive sensitive data. Leave both empty and pass no
      destinations to keep a purely local action internal.
    - ``actions``: per-action-type rules (e.g. ``send`` requires approval).
    - ``strict_unknown_purpose``: when True (default) a ``purpose`` absent from
      ``purposes`` — while ``purposes`` is non-empty — yields an empty allow set
      (fail-closed) instead of allowing everything requested. An attacker must
      not be able to disable the whole per-purpose whitelist by inventing a
      purpose string. An empty ``purposes`` map stays permissive (caller opted
      out of purpose gating entirely).
    """

    purposes: dict[str, PurposeRule] = field(default_factory=dict)
    sensitive_fields: list[str] = field(default_factory=list)
    never_fields: list[str] = field(default_factory=list)
    external_destinations: list[str] = field(default_factory=list)
    internal_destinations: list[str] = field(default_factory=list)
    actions: dict[str, ActionRule] = field(default_factory=dict)
    strict_unknown_purpose: bool = True
