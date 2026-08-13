// A2A extension activation binding — who may READ what was written
// (S027 T-022).
//
// Negotiation (./extension.ts) answers "did the requester opt in, on this
// request". That is not the same question as "may the principal receiving
// THIS delivery see the decision metadata". A task outlives its originating
// request: a second principal can GetTask it, a subscriber can stream it, a
// webhook can push it to a party that never sent an `A2A-Extensions` header
// in its life. If activation is a property of the request, every one of those
// paths leaks the substate to principals who never opted in.
//
// So activation is bound as STATE: (principal, task, extension URI, version,
// delivery channel). A binding on one channel does not cover another —
// opting in on the request/response path says nothing about wanting the
// substate pushed to a webhook endpoint.
//
// THE REVERSE PROBLEM. Stripping the metadata for non-activated readers
// cannot simply delete the key: a reader entitled to know that governance
// reporting EXISTS would then see a task indistinguishable from one that was
// never reported on at all — and "Aegis reporting is present on this task"
// silently degrades to "there is no Aegis reporting". The filter therefore
// replaces the value with a WITHHELD marker that carries zero decision
// content (no outcome, no reason, no field names): existence is disclosed,
// content is not. Where no report exists, no marker is invented — absence
// stays absence.

import { AegisError, aegisDocsUrl } from "../errors.js";
import {
  AEGIS_A2A_EXTENSION_URI_V0,
  AEGIS_A2A_EXTENSION_VERSION,
  type NegotiationResult,
} from "./extension.js";

export class A2AActivationError extends AegisError {
  constructor(code: string, message: string, remediation: string) {
    super({ code, message, remediation, docs_url: aegisDocsUrl(code) });
    this.name = "A2AActivationError";
  }
}

/** Delivery paths a task's metadata can reach a principal through. */
export type DeliveryChannel = "request_response" | "get_task" | "subscribe" | "webhook";

/** The closed channel vocabulary, as a value (parity with the Python export). */
export const DELIVERY_CHANNELS: readonly string[] = [
  "request_response",
  "get_task",
  "subscribe",
  "webhook",
];

/**
 * One principal's opt-in, as state. All five fields participate: a binding is
 * per principal, per task, per extension identity, per channel.
 */
export interface ActivationBinding {
  readonly principal: string;
  readonly task_id: string;
  readonly uri: string;
  readonly version: string;
  readonly channel: DeliveryChannel;
}

/** A delivery about to happen: who is receiving, which task, over what path. */
export interface DeliveryQuery {
  readonly principal: string;
  readonly task_id: string;
  readonly channel: DeliveryChannel;
}

function validateBinding(b: ActivationBinding): void {
  if (typeof b.principal !== "string" || b.principal.length === 0) {
    throw new A2AActivationError(
      "invalid_activation_binding",
      "Activation binding needs a non-empty principal.",
      "Bind activation to the authenticated principal identity, not to a request.",
    );
  }
  if (typeof b.task_id !== "string" || b.task_id.length === 0) {
    throw new A2AActivationError(
      "invalid_activation_binding",
      "Activation binding needs a non-empty task_id.",
      "Activation is per task; a blanket opt-in would leak future tasks.",
    );
  }
  if (b.uri !== AEGIS_A2A_EXTENSION_URI_V0) {
    throw new A2AActivationError(
      "unknown_extension_uri",
      `This surface manages activation for ${AEGIS_A2A_EXTENSION_URI_V0} only.`,
      "Bind other extensions in their own registries; a shared bag of URIs is how a near-miss identifier inherits someone else's opt-in.",
    );
  }
  if (b.version !== AEGIS_A2A_EXTENSION_VERSION) {
    throw new A2AActivationError(
      "unsupported_extension_version",
      `Unknown extension version ${JSON.stringify(b.version)}.`,
      "Activation is per dated version; an opt-in to v0 must not silently cover a future vocabulary.",
    );
  }
  if (!DELIVERY_CHANNELS.includes(b.channel)) {
    throw new A2AActivationError(
      "unknown_delivery_channel",
      `Unknown delivery channel ${JSON.stringify(b.channel)}.`,
      "Only request_response, get_task, subscribe and webhook are defined.",
    );
  }
}

/** Well-formedness without throwing — used to IGNORE poisoned records at the
 * read boundary. `bindActivation` refuses to create a malformed binding, but
 * bindings restored from persistence (JSON, a database row, an attacker who
 * can write either) never went through it. A malformed record must count as
 * no activation at all, not as whatever its raw strings happen to match. */
function isWellFormedBinding(b: ActivationBinding): boolean {
  return (
    typeof b === "object" &&
    b !== null &&
    typeof b.principal === "string" &&
    b.principal.length > 0 &&
    typeof b.task_id === "string" &&
    b.task_id.length > 0 &&
    b.uri === AEGIS_A2A_EXTENSION_URI_V0 &&
    b.version === AEGIS_A2A_EXTENSION_VERSION &&
    DELIVERY_CHANNELS.includes(b.channel)
  );
}

function isWellFormedQuery(query: DeliveryQuery): boolean {
  return (
    typeof query === "object" &&
    query !== null &&
    typeof query.principal === "string" &&
    query.principal.length > 0 &&
    typeof query.task_id === "string" &&
    query.task_id.length > 0 &&
    DELIVERY_CHANNELS.includes(query.channel)
  );
}

/**
 * Record one activation. Pure: returns a new list. Idempotent: re-binding an
 * identical tuple does not duplicate it.
 */
export function bindActivation(
  bindings: readonly ActivationBinding[],
  binding: ActivationBinding,
): ActivationBinding[] {
  validateBinding(binding);
  const exists = bindings.some(
    (b) =>
      b.principal === binding.principal &&
      b.task_id === binding.task_id &&
      b.uri === binding.uri &&
      b.version === binding.version &&
      b.channel === binding.channel,
  );
  return exists ? [...bindings] : [...bindings, binding];
}

/**
 * Record an activation FROM a successful negotiation (round-3 codex,
 * preferred over hand-constructing a binding). The provenance of a binding is
 * the request in which this principal opted in: passing the `NegotiationResult`
 * ties the binding to an actual activation rather than to a caller's say-so.
 * Refuses to bind when the negotiation did not activate the extension.
 */
export function bindActivationFromNegotiation(
  bindings: readonly ActivationBinding[],
  args: {
    readonly principal: string;
    readonly task_id: string;
    readonly channel: DeliveryChannel;
    readonly negotiation: NegotiationResult;
  },
): ActivationBinding[] {
  if (!args.negotiation.activated) {
    throw new A2AActivationError(
      "activation_not_negotiated",
      "Refusing to bind activation: the negotiation did not activate this extension.",
      "Only bind a principal that actually opted in. A binding invented without a negotiation is exactly the confused-deputy this guards against.",
    );
  }
  return bindActivation(bindings, {
    principal: args.principal,
    task_id: args.task_id,
    uri: AEGIS_A2A_EXTENSION_URI_V0,
    version: AEGIS_A2A_EXTENSION_VERSION,
    channel: args.channel,
  });
}

/**
 * Whether this exact (principal, task, channel) holds a v0 activation.
 *
 * Validates BOTH sides at the read boundary: a malformed query (unknown
 * channel, empty principal) and a malformed stored binding each count as "not
 * activated". Matching raw strings would let a poisoned persistence record
 * `{channel: "email"}` meet a same-shaped query and release the substate on a
 * channel this module has never heard of.
 */
export function isActivatedFor(
  bindings: readonly ActivationBinding[],
  query: DeliveryQuery,
): boolean {
  if (!isWellFormedQuery(query)) return false;
  return bindings.some(
    (b) =>
      isWellFormedBinding(b) &&
      b.principal === query.principal &&
      b.task_id === query.task_id &&
      b.channel === query.channel,
  );
}

/** `status` value of the withheld marker. */
export const WITHHELD_STATUS = "withheld_not_activated";

/**
 * The marker left in place of the substate for a non-activated reader.
 * Deliberately content-free: version and status only. It says "reporting
 * exists and you have not activated it" and nothing else.
 */
export interface WithheldMarker {
  readonly version: string;
  readonly status: typeof WITHHELD_STATUS;
  readonly reason: "extension_not_activated_for_principal_on_channel";
}

/**
 * Filter a task's metadata for one delivery.
 *
 *   - No extension key present → returned unchanged. No marker is invented:
 *     a task that was never reported on must stay distinguishable from one
 *     whose report is being withheld.
 *   - Key present, delivery is activated → returned unchanged.
 *   - Key present, delivery is NOT activated → the value is replaced with the
 *     withheld marker. Existence disclosed, content not.
 *
 * Pure: the caller's object is never mutated.
 */
export function filterDecisionMetadataForDelivery(
  metadata: Readonly<Record<string, unknown>> | undefined,
  bindings: readonly ActivationBinding[],
  query: DeliveryQuery,
): Record<string, unknown> {
  const source = metadata ?? {};
  if (!(AEGIS_A2A_EXTENSION_URI_V0 in source)) {
    return { ...source };
  }
  if (isActivatedFor(bindings, query)) {
    return { ...source };
  }
  const marker: WithheldMarker = {
    version: AEGIS_A2A_EXTENSION_VERSION,
    status: WITHHELD_STATUS,
    reason: "extension_not_activated_for_principal_on_channel",
  };
  return { ...source, [AEGIS_A2A_EXTENSION_URI_V0]: marker };
}
