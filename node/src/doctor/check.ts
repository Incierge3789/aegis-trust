// Deterministic boundary diagnosis — `check` (Node, v0). 1:1 mirror of
// python/src/aegis_trust/doctor/check.py.
//
// Given an ActionPlan and a LocalPolicy, return a BoundaryDecision. Pure, local,
// deterministic — no network, no LLM, no Core. The decision's `allowedData` is
// meant to be passed straight to `shield({ scope })` (via `scopeForShield`).
//
// v0 produces ALLOW / REDUCE_SCOPE / REQUIRE_APPROVAL / BLOCK. REQUIRE_CHECK is
// reserved for a later release.
//
// Hardening (doctor-v0 trust-boundary): all field matching is *path-aware* and
// *normalized*, not flat byte-exact membership. A forbidden/sensitive field
// blocks/strips any path that **is**, **descends from**, or **encloses** it
// (`ssn` blocks `profile.ssn`; `config` blocks `config.api_key`; `a.b.c` blocks
// a bare `a.b` request that would expand to the whole subtree). Comparison is
// Unicode-NFC + lowercase + trimmed so `SSN` cannot dodge `ssn`. Unknown
// destinations are external (fail-closed), and an unknown purpose against a
// non-empty policy yields an empty allow set.

import type { LocalPolicy } from "./policy.js";
import { BoundaryOutcome, DOCTOR_SCHEMA_VERSION } from "./types.js";
import type { ActionPlan, BoundaryDecision } from "./types.js";

/**
 * Canonicalize a field/destination token for comparison (NFKC + trim +
 * lowercase). NFKC folds compatibility variants (full-width `ＳＳＮ`, ligatures)
 * to ASCII so they cannot dodge a guard.
 *
 * Note: this uses `toLowerCase()`, whereas the Python SDK uses `casefold()`.
 * They agree for ASCII and the common accented ranges; a small set of
 * casefold-only Unicode equivalences (e.g. Greek final sigma `ς`↔`σ`) are NOT
 * unified here. Field names are virtually always ASCII, so this residual is a
 * known, low-severity Node/Python parity gap, not a general bypass. (JS has no
 * stdlib casefold; tracked as a follow-up.)
 */
function norm(s: string): string {
  return s.normalize("NFKC").trim().toLowerCase();
}

function segments(path: string): string[] {
  return norm(path).split(".");
}

/**
 * Own-property lookup. A bare `obj[key]` resolves inherited members, so an
 * attacker-controlled `purpose` / `actionType` of `"__proto__"`, `"constructor"`,
 * `"toString"`, etc. would return a truthy `Object.prototype` member and be
 * treated as a *known, rule-less* purpose — silently bypassing the
 * unknown-purpose fail-closed guard (a fail-OPEN). hasOwnProperty restricts
 * resolution to keys the policy actually declares. Parity with the null-proto /
 * hasOwnProperty guards in paths.ts / filter.ts (S015 P0); Python's `dict.get`
 * is already immune.
 */
function ownProp<T>(obj: Readonly<Record<string, T>> | undefined, key: string): T | undefined {
  if (obj == null) return undefined;
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/** Mirror shield's field-path validation (fail-closed at the gate). */
function isValidPath(path: string): boolean {
  if (!path || path !== path.trim()) return false;
  if (path.startsWith(".") || path.endsWith(".")) return false;
  if (path.includes("..")) return false;
  return true;
}

/**
 * True if `path` is forbidden/stripped by any guard in `guards`. A guard `g`
 * covers `path` when, after normalization, they are equal, `path` descends from
 * `g`, or `path` encloses `g` (requesting a parent of a forbidden leaf would
 * expand to the whole subtree that contains it).
 */
function coveredBy(path: string, guards: ReadonlyArray<string>): boolean {
  const np = norm(path);
  const segs = new Set(segments(path));
  for (const g of guards) {
    const ng = norm(g);
    if (!ng) continue;
    if (np === ng) return true;
    if (np.startsWith(ng + ".")) return true; // path descends from guard
    if (ng.startsWith(np + ".")) return true; // path encloses guard
    if (!ng.includes(".") && segs.has(ng)) return true; // bare-leaf guard as a segment
  }
  return false;
}

/**
 * A path is permitted by an allow-whitelist only when it *is* an allowed field
 * or *descends from* one. Requesting a parent of an allowed leaf is NOT granted
 * (that would over-disclose the whole container via shield).
 *
 * Matching is **exact** (NOT normalized), unlike the never/sensitive/deny
 * guards. Normalization is one-directional on purpose: a *guard* normalizes so
 * it blocks more (`SSN` is caught by `ssn` — fail-closed); the *allow* list must
 * not, because the matched token is emitted into `allowedData` and handed to
 * shield, which resolves the **literal** data key. If `allow:["name"]` loosely
 * matched a request for `"NAME"`, doctor would authorize and shield would
 * disclose the *distinct* `NAME` field the operator never allowed — a
 * normalization confused-deputy. Exact match keeps authorization aligned with
 * the operator's literal intent (fail-closed). Whitespace-bearing requests are
 * already rejected by `isValidPath` at the gate.
 */
function allowedByWhitelist(path: string, allow: ReadonlyArray<string>): boolean {
  for (const a of allow) {
    if (!a) continue;
    if (path === a || path.startsWith(a + ".")) return true;
  }
  return false;
}

/** Diagnose `plan` against `policy` and return a deterministic decision. */
export function check(plan: ActionPlan, policy: LocalPolicy = {}): BoundaryDecision {
  const requested = [...plan.dataRequested];
  const never = policy.neverFields ?? [];
  const sensitive = policy.sensitiveFields ?? [];
  const external = policy.externalDestinations ?? [];
  const internal = policy.internalDestinations ?? [];
  const strictUnknownPurpose = policy.strictUnknownPurpose ?? true;

  // 0. Malformed field paths fail closed at the gate (don't defer to shield).
  if (requested.some((f) => !isValidPath(f))) {
    return {
      outcome: BoundaryOutcome.BLOCK,
      purpose: plan.purpose,
      allowedData: [],
      blockedData: requested,
      allowedTools: [],
      approvalRequiredFor: [],
      reasonCodes: ["MALFORMED_FIELD_PATH"],
      policyVersion: "local-preview-v1",
      receiptRequired: true,
      schemaVersion: DOCTOR_SCHEMA_VERSION,
    };
  }

  // 1. Hard block: a forbidden field requested at all (e.g. secrets, .env).
  //    Path-aware: `neverFields=["ssn"]` also blocks `profile.ssn`;
  //    `["config"]` blocks `config.api_key`. Fail-closed.
  if (requested.some((f) => coveredBy(f, never))) {
    return {
      outcome: BoundaryOutcome.BLOCK,
      purpose: plan.purpose,
      allowedData: [],
      blockedData: requested,
      allowedTools: [],
      approvalRequiredFor: [],
      reasonCodes: ["FORBIDDEN_FIELD_REQUESTED"],
      policyVersion: "local-preview-v1",
      receiptRequired: true,
      schemaVersion: DOCTOR_SCHEMA_VERSION,
    };
  }

  // 2. Per-purpose allow/deny → the baseline allowed set. Own-property lookup
  //    so an attacker-supplied purpose like "__proto__" cannot resolve an
  //    inherited member and dodge the unknown-purpose fail-closed guard.
  const rule = ownProp(policy.purposes, plan.purpose);
  let allowed: string[];
  if (rule && rule.allow != null) {
    const allow = rule.allow;
    allowed = requested.filter((f) => allowedByWhitelist(f, allow));
  } else if (rule && rule.deny && rule.deny.length > 0) {
    const deny = rule.deny;
    allowed = requested.filter((f) => !coveredBy(f, deny));
  } else if (
    !rule
    && policy.purposes
    && Object.keys(policy.purposes).length > 0
    && strictUnknownPurpose
  ) {
    // Purpose whitelist exists but this purpose is unknown: fail-closed.
    // An attacker must not disable the policy graph with a novel purpose.
    allowed = [];
  } else {
    allowed = [...requested];
  }

  // 3. Minimum disclosure to external destinations: strip sensitive fields
  //    (path-aware) before anything leaves the trust boundary. A destination
  //    named but classified as neither internal nor external is treated as
  //    EXTERNAL (fail-closed) — an unknown sink must not receive sensitive data.
  const isExternal = (d: string): boolean => {
    const nd = norm(d);
    if (internal.some((x) => nd === norm(x))) return false;
    if (external.some((x) => nd === norm(x))) return true;
    return true; // named but unclassified → external (fail-closed)
  };
  const goesExternal = (plan.destinations ?? []).some(isExternal);
  if (goesExternal && sensitive.length > 0) {
    allowed = allowed.filter((f) => !coveredBy(f, sensitive));
  }

  const blocked = requested.filter((f) => !allowed.includes(f));

  // 4. Approval seam: action-type rules (own-property lookup — see `ownProp`).
  const approvalRequiredFor: string[] = [];
  if (ownProp(policy.actions, plan.actionType)?.requiresApproval) {
    approvalRequiredFor.push(plan.actionType);
  }

  // 5. Reason codes + outcome (priority: approval > reduce > allow).
  const reasonCodes: string[] = [];
  if (blocked.length > 0) reasonCodes.push("DATA_NOT_REQUIRED_FOR_PURPOSE");
  if (goesExternal && requested.some((f) => coveredBy(f, sensitive))) {
    reasonCodes.push("EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE");
  }
  if (approvalRequiredFor.length > 0) reasonCodes.push("ACTION_REQUIRES_HUMAN_APPROVAL");

  const outcome: BoundaryOutcome =
    approvalRequiredFor.length > 0
      ? BoundaryOutcome.REQUIRE_APPROVAL
      : blocked.length > 0
        ? BoundaryOutcome.REDUCE_SCOPE
        : BoundaryOutcome.ALLOW;

  return {
    outcome,
    purpose: plan.purpose,
    allowedData: allowed,
    blockedData: blocked,
    allowedTools: [...(plan.tools ?? [])],
    approvalRequiredFor,
    reasonCodes,
    policyVersion: "local-preview-v1",
    receiptRequired: outcome !== BoundaryOutcome.ALLOW || blocked.length > 0,
    schemaVersion: DOCTOR_SCHEMA_VERSION,
  };
}
