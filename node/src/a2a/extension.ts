// A2A extension — declaration, activation negotiation, and metadata placement.
//
// The mapping (./mapping.ts) decides WHAT to report. This module decides WHERE
// it goes on the wire and WHETHER the client asked for it at all.
//
// THREE THINGS THIS DELIBERATELY DOES NOT DO.
//
//  1. It does not claim enforcement. An A2A extension is a vocabulary the client
//     activates with the `A2A-Extensions` header. Activation is not admission
//     control, and `required: true` in an AgentCard is a notice about request
//     construction, not a gate. Aegis's enforcement lives in the gateway path.
//     `assertNoEnforcementClaim` below is the machine check for that boundary.
//  2. It does not ship a real URI. The v0 identifier is a placeholder and is
//     machine-detectably so — registering an identifier is an ownership act,
//     and this sprint does not perform it. `isPlaceholderExtensionUri` exists so
//     a release cannot carry one by accident.
//  3. It does not decide who may READ what it wrote. Negotiation here is per
//     request; binding activation to a principal, task, and delivery channel —
//     so a second principal reading the same task cannot harvest the metadata —
//     is ./activation.ts, and deliveries must pass through its filter.
//
// Normative source, pinned: a2aproject/A2A@0ef1b02, §4.6 (extensions), §14.2.2
// (the `A2A-Extensions` header). Metadata placement follows the spec's own
// example: `metadata` is keyed BY the extension URI (§4.6.1, §4.6.2).

import { AegisError, aegisDocsUrl } from "../errors.js";
import type { DecisionSubstate } from "./mapping.js";
import { validateDecisionSubstate, type ProvenanceDeclaration } from "./privacy.js";
import {
  assertNoProducerTrustAssertions,
  assertNoProducerTrustAssertionsScoped,
} from "./verification.js";

/** The header a client uses to opt in. Spec §14.2.2. */
export const A2A_EXTENSIONS_HEADER = "A2A-Extensions";

/**
 * v0 extension identifier — a PLACEHOLDER, not a registered URI.
 *
 * The `x-aegis-placeholder` authority is deliberately not resolvable and
 * deliberately not a domain anyone could mistake for a published one. Choosing
 * the real identifier is an ownership decision (it becomes the public name of
 * this vocabulary), and it is not made here.
 */
export const AEGIS_A2A_EXTENSION_URI_V0 =
  "urn:x-aegis-placeholder:a2a:boundary-decision:v0";

/** Dated version of the substate shape carried under the extension key. */
export const AEGIS_A2A_EXTENSION_VERSION = "v0";

const PLACEHOLDER_MARKERS = ["x-aegis-placeholder", "urn:x-"];

/** True while the extension identifier is still a placeholder. */
export function isPlaceholderExtensionUri(uri: string): boolean {
  const lowered = uri.toLowerCase();
  return PLACEHOLDER_MARKERS.some((marker) => lowered.includes(marker));
}

/** Raised when the extension surface is asked to do something dishonest. */
export class A2AExtensionError extends AegisError {
  constructor(code: string, message: string, remediation: string) {
    super({ code, message, remediation, docs_url: aegisDocsUrl(code) });
    this.name = "A2AExtensionError";
  }
}

// ---------------------------------------------------------------------------
// Honesty guard
// ---------------------------------------------------------------------------

// Subject words: the thing a claim could be made ABOUT.
const CLAIM_SUBJECTS = [
  "aegis",
  "extension",
  "boundary",
  "receipt",
  "decision",
  "policy",
  "access",
];

// Assurance words: what a reader would take as "this was enforced / proven".
// A banned-substring list over whole phrases is escapable by paraphrase, which
// is why this matches a SUBJECT near an ASSURANCE word instead of matching
// fixed sentences.
const ASSURANCE_WORDS = [
  "enforced",
  "enforcement",
  "guaranteed",
  "guarantees",
  "assurance",
  "assured",
  "proven",
  "proves",
  "verified",
  "certified",
  "protected by",
  "secured by",
  "compliant",
  "in effect",
  "upholds",
  "gated",
  "blocks",
  "prevents",
];
// "establishes" was dropped after round 3 (codex FP: "the policy establishes
// the document format"); cursor's "establishes that access was gated" is still
// caught via "gated". "blocks"/"prevents" added for "Aegis blocks access".
// "confirms" and "coverage" were dropped earlier: as standalone words
// they fire on honest compliance prose ("SOC 2 report confirms coverage of
// access-control reviews"). The round-1 vector they were added for ("confirms
// Aegis coverage is in effect") is still caught by "in effect" near a subject.

// Phrases that are honest precisely because they negate. Without this, the
// disclaimer sentence would trip the guard that exists to enforce it.
//
// Scope (round-1 critique fix): a negation exempts an assurance term only when
// it appears BEFORE the term, within NEGATION_WINDOW characters, in the SAME
// sentence segment. The previous rule — any negation anywhere in a ±60 window —
// was defeated by appending an unrelated negation after the claim ("Aegis
// assurance active (readers remain unverified)") and by borrowing one from the
// previous clause ("The extension is not decorative; policy enforcement is
// verified"). "unverified" is a status word, not a negation of a claim, and is
// deliberately absent.
const NEGATIONS = [
  "does not",
  "doesn't",
  "not enforcement",
  "never",
  "no guarantee",
  "cannot",
  "can't",
  "not proof",
  "is not",
];

/** Bare "value-free" is banned on this surface — see the mapping doc §7. */
const BANNED_TERMS = ["value-free", "value free"];

const WINDOW = 60;
const NEGATION_WINDOW = 35;
// Clause boundaries, comma included (round-2 codex): "Aegis does not log,
// policy enforced." must not let the first clause's negation launder the
// second clause's claim. A negation and the assurance it negates share a
// clause; anything across punctuation is borrowing.
const SENTENCE_BOUNDARY = /[.;!?,]/;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
// Word-boundaried matching (round-3): substring matching let `access` fire
// inside `inaccessible`. `\b` matches whole words and multi-word phrases at
// their ends.
const ASSURANCE_RE = new RegExp(`\\b(?:${ASSURANCE_WORDS.map(escapeRe).join("|")})\\b`, "g");
const SUBJECT_RE = new RegExp(`\\b(?:${CLAIM_SUBJECTS.map(escapeRe).join("|")})\\b`);

/** Start index of the sentence segment containing `at`. */
function segmentStart(text: string, at: number): number {
  for (let i = at - 1; i >= 0; i--) {
    if (SENTENCE_BOUNDARY.test(text[i])) return i + 1;
  }
  return 0;
}

/**
 * Reject text that reads as "this extension proves enforcement".
 *
 * Deliberately conservative about what counts as a claim. A best-effort
 * BACKSTOP, not a complete classifier: free-text prose cannot be perfectly
 * separated from enforcement claims by a word list, and the authoritative
 * anti-overclaim defenses are elsewhere — the machine-readable
 * producer-trust-assertion KEY rejection (complete for structured claims) and
 * consumers deriving verification from `deriveVerificationStatus`, never from
 * prose. Text is NFKC-normalized first, so a full-width paraphrase folds to
 * the same words.
 */
export function assertNoEnforcementClaim(text: string, where: string): void {
  const lowered = text.normalize("NFKC").toLowerCase();

  for (const term of BANNED_TERMS) {
    if (lowered.includes(term)) {
      throw new A2AExtensionError(
        "banned_claim_term",
        `${where} uses "${term}", which overstates what is carried.`,
        'Say "payload-value-omitting", or state the property in full: field names are carried, payload values are not.',
      );
    }
  }

  for (const match of lowered.matchAll(ASSURANCE_RE)) {
    const at = match.index;
    const assurance = match[0];
    const start = Math.max(0, at - WINDOW);
    const window = lowered.slice(start, at + assurance.length + WINDOW);
    if (!SUBJECT_RE.test(window)) continue;
    // A negation only exempts when it precedes the assurance term closely,
    // inside the same sentence segment.
    const negationFrom = Math.max(segmentStart(lowered, at), at - NEGATION_WINDOW);
    const negationWindow = lowered.slice(negationFrom, at + assurance.length);
    if (NEGATIONS.some((negation) => negationWindow.includes(negation))) continue;
    throw new A2AExtensionError(
      "enforcement_claim_detected",
      `${where} reads as an enforcement claim near "${assurance}".`,
      "Carrying this extension shows what was reported, by whoever emitted it. State that, or negate the claim explicitly.",
    );
  }
}

// ---------------------------------------------------------------------------
// AgentCard declaration
// ---------------------------------------------------------------------------

/** An `AgentExtension` entry for `AgentCard.capabilities.extensions`. */
export interface AgentExtensionDeclaration {
  readonly uri: string;
  readonly description: string;
  readonly required: boolean;
  readonly params?: Readonly<Record<string, unknown>>;
}

/**
 * Build the AgentCard declaration for this extension.
 *
 * `required` is fixed to `false` and is not a parameter. Marking an extension
 * required tells clients how to build requests; it does not make a counterparty
 * honour anything, and a "required" security-flavoured extension invites exactly
 * the misreading this surface must avoid.
 */
export function buildAgentCardExtension(): AgentExtensionDeclaration {
  const description =
    "Reports Aegis boundary decisions using existing A2A TaskState values plus a " +
    "substate in metadata. It is a reporting vocabulary: activating it does not " +
    "enforce anything and is not proof that anything was enforced. Field names " +
    "are carried; payload values are not. PRERELEASE: the identifier is a " +
    "placeholder and is not registered.";
  assertNoEnforcementClaim(description, "AgentCard extension description");
  return {
    uri: AEGIS_A2A_EXTENSION_URI_V0,
    description,
    required: false,
    params: {
      version: AEGIS_A2A_EXTENSION_VERSION,
      status: "prerelease",
      identifier_is_placeholder: true,
    },
  };
}

// ---------------------------------------------------------------------------
// Activation negotiation
// ---------------------------------------------------------------------------

export interface NegotiationResult {
  /** Whether this extension was requested and can be honoured. */
  readonly activated: boolean;
  /** Every URI the client asked for, in request order, de-duplicated. */
  readonly requested: readonly string[];
  /** Machine-readable reason when `activated` is false. */
  readonly reason?: "not_requested" | "unknown_extension_version";
  /**
   * What to echo in the response `A2A-Extensions` header. Empty when nothing
   * was activated — never a silent partial answer.
   */
  readonly echo: readonly string[];
}

/**
 * Parse the request `A2A-Extensions` header and decide activation.
 *
 * Extensions are inactive by default, so "the client did not ask" is a normal
 * outcome, not an error — but it is a NAMED outcome. A caller must be able to
 * tell "no decision metadata because the client did not opt in" from "no
 * decision metadata because there was nothing to report"; those look identical
 * on the wire otherwise.
 */
export function negotiateExtensions(
  headerValue: string | readonly string[] | undefined | null,
): NegotiationResult {
  const raw = Array.isArray(headerValue)
    ? headerValue.join(",")
    : typeof headerValue === "string"
      ? headerValue
      : "";
  const requested: string[] = [];
  for (const part of raw.split(",")) {
    const uri = part.trim();
    if (uri.length > 0 && !requested.includes(uri)) requested.push(uri);
  }
  if (!requested.includes(AEGIS_A2A_EXTENSION_URI_V0)) {
    return { activated: false, requested, reason: "not_requested", echo: [] };
  }
  return {
    activated: true,
    requested,
    echo: [AEGIS_A2A_EXTENSION_URI_V0],
  };
}

// ---------------------------------------------------------------------------
// Metadata placement
// ---------------------------------------------------------------------------

/** Apply the honesty guard to every string VALUE in a runtime payload.
 * The guard was born checking docs and descriptions; H-003's runtime mutant
 * (`verification_message: "Policy enforcement verified"`) rides in a value,
 * so emission walks the payload and holds values to the same standard. */
function assertHonestRuntimeStrings(payload: unknown, where: string): void {
  if (typeof payload === "string") {
    assertNoEnforcementClaim(payload, where);
    return;
  }
  if (Array.isArray(payload)) {
    payload.forEach((item, i) => assertHonestRuntimeStrings(item, `${where}[${i}]`));
    return;
  }
  if (typeof payload === "object" && payload !== null) {
    for (const [k, v] of Object.entries(payload)) {
      assertHonestRuntimeStrings(v, `${where}.${k}`);
    }
  }
}

/**
 * Place a decision substate under the extension's own metadata key.
 *
 * Spec §4.6.1/§4.6.2: `metadata` is keyed by the extension URI. Returns a new
 * object; the caller's metadata is not mutated.
 *
 * Throws when the extension was not activated. Writing extension metadata a
 * client never opted into is the quiet version of the disclosure problem —
 * fail-closed instead.
 *
 * Also refuses to EMIT dishonesty, in four layers (the emission path IS the
 * enforcement point for T-019/T-020 on the producer side — a validator that
 * only consumers run is an optional helper, not a defense):
 *
 *   1. A substate carrying a producer-asserted trust field (`coreVerified`,
 *      `enforcementStatus`, ...) is rejected with the specific code.
 *   2. The final versioned value is validated per-field against declared
 *      provenance — `withheld_fields: ["alice"]` and undeclared keys die
 *      HERE, before the wire, not merely at a well-behaved consumer.
 *   3. The merged carrier's TOP-LEVEL KEYS are checked, so a root sibling
 *      `coreVerified: true` in the caller's own metadata is refused — this
 *      SDK will not courier a machine-readable authority claim. Other
 *      extensions' URI-keyed bags are opaque: their vocabularies are theirs.
 *   4. Every string value in OUR emitted value is held to the honesty guard.
 */
export function placeDecisionMetadata(
  metadata: Readonly<Record<string, unknown>> | undefined,
  substate: DecisionSubstate | Readonly<Record<string, unknown>>,
  negotiation: NegotiationResult,
  provenance?: ProvenanceDeclaration,
): Record<string, unknown> {
  if (!negotiation.activated) {
    throw new A2AExtensionError(
      "extension_not_activated",
      "Refusing to write Aegis decision metadata for a client that did not activate the extension.",
      `Activate it by sending "${A2A_EXTENSIONS_HEADER}: ${AEGIS_A2A_EXTENSION_URI_V0}", or report the decision outside the A2A extension.`,
    );
  }
  assertNoProducerTrustAssertions(substate, "decision substate");
  const value = {
    version: AEGIS_A2A_EXTENSION_VERSION,
    ...substate,
  };
  validateDecisionSubstate(value, provenance ?? {});
  const merged = {
    ...(metadata ?? {}),
    [AEGIS_A2A_EXTENSION_URI_V0]: value,
  };
  // Carrier scan, namespace-scoped (round-2 + round-3 critique): trust
  // assertion KEYS are refused anywhere in the carrier EXCEPT inside another
  // extension's namespace-keyed bag. Round 2 stopped co-installed extensions
  // from breaking (their URI bags are opaque); round 3 closed the depth-1
  // courier hole this left (`{ notes: { coreVerified: true } }`). The honesty
  // string walk stays on OUR value only — the integrator's own prose is the
  // integrator's own claim.
  assertNoProducerTrustAssertionsScoped(merged, "decision metadata carrier");
  assertHonestRuntimeStrings(value, "decision metadata value");
  return merged;
}
