// A2A verification status — derived by the consumer, never asserted by the
// producer (S027 T-020).
//
// THE RULE. On the wire, every field is the counterparty's self-report. A
// `coreVerified: true` or `enforcementStatus: "ENFORCED"` arriving in A2A
// metadata is not a fact about enforcement — it is a string the sender chose.
// Inside this SDK those fields are produced under discipline, but the wire
// does not carry the discipline, only the bytes. A consumer that displays a
// producer's positive trust assertion next to its own derived "unverified"
// has built a UI where the attacker's field wins.
//
// So this surface has exactly one authoritative verification value: the one
// the CONSUMER derives here, from checks it ran itself. Positive
// producer-asserted trust fields are rejected outright — not ignored, not
// deprioritized, rejected — so the "derived says unverified, embedded field
// says verified" state is unrepresentable.
//
// WHAT A KEYLESS CONSUMER CAN DERIVE. The LITE SDK can check structure: the
// substate validates against its vocabulary and provenance, and a receipt's
// internal structure recomputes. It CANNOT authenticate the issuer — keyed
// verification is Aegis Core territory. `issuer_authenticated` is therefore
// not a member of the status type: a value this module cannot prove is a
// value this module cannot emit.

import { AegisError, aegisDocsUrl } from "../errors.js";
import {
  A2APrivacyError,
  validateDecisionSubstate,
  type ProvenanceDeclaration,
} from "./privacy.js";

export class A2AVerificationError extends AegisError {
  constructor(code: string, message: string, remediation: string) {
    super({ code, message, remediation, docs_url: aegisDocsUrl(code) });
    this.name = "A2AVerificationError";
  }
}

/**
 * Key names that assert trust on the producer's behalf. Matching first
 * applies Unicode NFKC (so full-width letters fold to ASCII), lower-cases,
 * then strips EVERY character outside `[a-z0-9]` — `coreVerified`,
 * `core_verified`, `CORE-VERIFIED`, `core.Verified`, and a zero-width-space
 * `core​Verified` are all the same claim. Stripping only `_`/`-` was
 * bypassable by exactly those separators nobody listed.
 */
export const PRODUCER_TRUST_ASSERTION_KEYS: readonly string[] = [
  "coreverified",
  "enforcementstatus",
  "evidencemode",
  "issuerauthenticated",
  "verificationstatus",
  "verified",
  "attested",
  "authenticated",
  "trusted",
  "trustlevel",
  "enforcementverified",
  "enforced",
  "assurancelevel",
];

const normalizeKey = (k: string): string =>
  k.normalize("NFKC").toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * Reject any payload that carries a producer-asserted trust field, at any
 * nesting depth. Runs on the CONSUMER side before derivation (so an embedded
 * claim can never coexist with a derived status) and on the PRODUCER side
 * before emission (so this SDK cannot be the producer that emits one).
 */
/**
 * The subset of trust-assertion keys that specifically impersonate THIS
 * extension's consumer-derived verification output. Used for scanning the
 * integrator's OWN sibling metadata: their generic `authenticated` /
 * `verified` / `trusted` fields are their business (round-3 codex: a
 * top-level `authenticated: false` from an auth system is not an Aegis
 * authority claim), but a sibling that names our output — `coreVerified`,
 * `enforcementStatus`, `enforced` — must not be couriered as if we produced
 * it. Our OWN emitted value is still held to the full list (we control it and
 * must emit nothing authority-flavored).
 */
export const CARRIER_IMPERSONATION_KEYS: readonly string[] = [
  "coreverified",
  "enforcementstatus",
  "evidencemode",
  "issuerauthenticated",
  "verificationstatus",
  "enforcementverified",
  "assurancelevel",
  "trustlevel",
  "enforced",
];

/** A key that names another extension's namespace: a URI or URN. Values under
 * such keys are that extension's own vocabulary and are left opaque. */
function isNamespaceKey(k: string): boolean {
  return k.includes("://") || k.toLowerCase().startsWith("urn:");
}

/**
 * Reject a producer trust-assertion KEY anywhere in a carrier EXCEPT inside
 * another extension's namespace-keyed bag.
 *
 * Round-3 fix: checking only the top-level keys (round 2) left a depth-1
 * courier hole — `{ notes: { coreVerified: true } }` rode through, because
 * `notes` is not a URI so its contents were never a "foreign bag", yet the
 * top-level scan never looked inside it. This walks the whole carrier, but
 * stops at any value whose KEY is a namespace (`://` or `urn:`): those belong
 * to other extensions (and to us — our own value was already deep-scanned
 * before the merge), and policing their vocabularies is what broke
 * co-installed extensions in round 2. Everything else is the integrator's
 * own space, where a machine-readable authority claim must not ride alongside
 * our decision metadata through this helper.
 */
export function assertNoProducerTrustAssertionsScoped(payload: unknown, where: string): void {
  const walk = (node: unknown, path: string): void => {
    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${path}[${i}]`));
      return;
    }
    if (typeof node !== "object" || node === null) return;
    for (const [k, v] of Object.entries(node)) {
      if (CARRIER_IMPERSONATION_KEYS.includes(normalizeKey(k))) {
        throw new A2AVerificationError(
          "producer_trust_assertion",
          `${where} carries a field impersonating Aegis verification output (${JSON.stringify(k)}) at ${path}.${k}.`,
          "This extension's verification is derived by the consumer; a sibling field naming that output is a self-report and is rejected. Rename it, or move it under your own extension's URI-keyed metadata. (Generic fields like 'authenticated' and other extensions' URI-keyed bags are left untouched.)",
        );
      }
      if (isNamespaceKey(k)) continue; // another extension's bag — opaque
      walk(v, `${path}.${k}`);
    }
  };
  walk(payload, "$");
}

export function assertNoProducerTrustAssertions(payload: unknown, where: string): void {
  const walk = (node: unknown, path: string): void => {
    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, `${path}[${i}]`));
      return;
    }
    if (typeof node !== "object" || node === null) return;
    for (const [k, v] of Object.entries(node)) {
      if (PRODUCER_TRUST_ASSERTION_KEYS.includes(normalizeKey(k))) {
        throw new A2AVerificationError(
          "producer_trust_assertion",
          `${where} carries producer-asserted trust field ${JSON.stringify(k)} at ${path}.`,
          "Verification status is derived by the consumer from checks it ran itself; a producer field asserting it is a self-report and is rejected. Remove the field. If the underlying value matters, ship the evidence it summarizes and let the consumer derive.",
        );
      }
      walk(v, `${path}.${k}`);
    }
  };
  walk(payload, "$");
}

/**
 * What the consumer can conclude. There is deliberately no value above
 * `structure_verified`: issuer authentication needs keys, keys are Core
 * territory, and a status this module cannot prove is a status it cannot emit.
 */
export type ConsumerVerificationStatus = "unverified" | "structure_verified";

export interface VerificationEvidence {
  /** The substate (or versioned envelope) as received. */
  readonly substate: unknown;
  /** The consumer's own provenance declarations for validation. */
  readonly provenance: ProvenanceDeclaration;
  /**
   * Result of the LITE structural receipt verification, if a receipt rode
   * along and the consumer ran it (`verifySessionReceiptStructure` /
   * `sessionDagRoot` are the existing keyless checks). "absent" when no
   * receipt was carried.
   */
  readonly receipt_structure?: "verified" | "failed" | "absent";
}

export interface DerivedVerification {
  readonly status: ConsumerVerificationStatus;
  /** The checks this consumer actually ran, machine-readable. */
  readonly basis: readonly string[];
  /**
   * What this status does NOT establish — fixed strings, always present.
   * Deriving a status without stating its ceiling is how "structurally sound"
   * gets read as "enforced".
   */
  readonly limits: readonly string[];
}

const LIMITS: readonly string[] = [
  "does_not_establish_issuer_identity",
  "does_not_establish_enforcement",
  "keyed_chain_verification_is_core_territory",
];

/**
 * Derive the one authoritative verification value from evidence the consumer
 * gathered itself. Throws `producer_trust_assertion` if the payload smuggles
 * a producer claim — rejection, not reconciliation.
 */
export function deriveVerificationStatus(evidence: VerificationEvidence): DerivedVerification {
  assertNoProducerTrustAssertions(evidence.substate, "verification evidence substate");

  const receiptInput = evidence.receipt_structure ?? "absent";
  if (receiptInput !== "verified" && receiptInput !== "failed" && receiptInput !== "absent") {
    throw new A2AVerificationError(
      "invalid_field_value",
      `Unknown receipt_structure ${JSON.stringify(receiptInput)}.`,
      "Pass 'verified', 'failed', or 'absent' from your own run of the LITE structural verifier.",
    );
  }

  const basis: string[] = [];
  try {
    validateDecisionSubstate(evidence.substate, evidence.provenance);
    basis.push("substate_schema_and_provenance");
  } catch (err) {
    if (err instanceof A2APrivacyError) {
      return {
        status: "unverified",
        basis: [`substate_invalid:${err.code}`],
        limits: LIMITS,
      };
    }
    throw err;
  }

  const receipt = receiptInput;
  if (receipt === "failed") {
    return {
      status: "unverified",
      basis: [...basis, "receipt_structure_failed"],
      limits: LIMITS,
    };
  }
  if (receipt === "verified") {
    basis.push("receipt_structure_recomputed");
  }
  return { status: "structure_verified", basis, limits: LIMITS };
}
