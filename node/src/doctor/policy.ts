// Declarative local boundary policy — the deterministic rule source for
// `check` (Node). 1:1 mirror of python/src/aegis_trust/doctor/policy.py.
// v0 is local-only; org-wide authoritative policy enforcement is Core's job.

/** Per-purpose field rules. Use `allow` (whitelist) OR `deny` (blacklist). `allow` omitted/null = no whitelist. */
export interface PurposeRule {
  readonly allow?: ReadonlyArray<string> | null;
  readonly deny?: ReadonlyArray<string>;
}

/** Per-action-type rules. */
export interface ActionRule {
  readonly requiresApproval?: boolean;
}

/** The declarative rules `check` evaluates against an ActionPlan. */
export interface LocalPolicy {
  /** Per-purpose allow/deny field rules. */
  readonly purposes?: Readonly<Record<string, PurposeRule>>;
  /** Fields stripped before any *external* destination. */
  readonly sensitiveFields?: ReadonlyArray<string>;
  /** Fields that, if requested at all, hard-BLOCK the action (e.g. secrets / `.env`). */
  readonly neverFields?: ReadonlyArray<string>;
  /** Destinations explicitly treated as outside the trust boundary (e.g. `external_llm`). */
  readonly externalDestinations?: ReadonlyArray<string>;
  /**
   * Destinations explicitly trusted as inside the boundary. Any named
   * destination in *neither* list is treated as **external** (fail-closed
   * minimum disclosure) — an unknown sink must not silently receive sensitive
   * data.
   */
  readonly internalDestinations?: ReadonlyArray<string>;
  /** Per-action-type rules (e.g. `send` requires approval). */
  readonly actions?: Readonly<Record<string, ActionRule>>;
  /**
   * When true (default) a `purpose` absent from `purposes` — while `purposes`
   * is non-empty — yields an empty allow set (fail-closed) instead of allowing
   * everything requested. An attacker must not disable the whole per-purpose
   * whitelist by inventing a purpose string. An empty `purposes` map stays
   * permissive (caller opted out of purpose gating entirely).
   */
  readonly strictUnknownPurpose?: boolean;
}
