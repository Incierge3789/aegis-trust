// Delegation context — the async-local store holding the capability token
// attached by an enclosing `delegate()` window.
//
// This lives in its own module for one structural reason: BOTH the AI-native
// interposition layer (aiNative.ts) and the wire-floor client (client.ts) must
// read it, and aiNative.ts already imports client.ts. Putting the store in
// either of them and importing it from the other would close an import cycle.
// A leaf module that imports nothing but `node:async_hooks` cannot.
//
// aiNative.ts re-exports `currentCapability` so the public API surface
// (index.ts) is unchanged. Python parity: aegis_trust/_delegation_context.py.

import { AsyncLocalStorage } from "node:async_hooks";

// Sentinel stored by delegate() when a mint failed: every guarded call
// inside the window fails closed locally (no gateway round-trip, no
// un-narrowed execution).
export const DELEGATION_DENIED: unique symbol = Symbol("aegis.delegation.denied");

// The active delegation token for the current async context. `string` = an
// attached capability; DELEGATION_DENIED = a denied window; no store = no
// window. AsyncLocalStorage propagates across awaits and into tasks spawned
// inside the scope — exactly the spawn-boundary semantics delegate() wants.
export const capabilityStorage = new AsyncLocalStorage<
  string | DelegationGrant | typeof DELEGATION_DENIED
>();

/**
 * A minted capability together with the origin it was minted against.
 *
 * The token alone is a bearer credential: whoever reads the store can send it
 * anywhere. Cross-review (codex, 2026-07-29, severity high) showed the
 * consequence — a SECOND `AegisClient` constructed inside the window, pointed
 * at a different base URL, would have the token auto-attached and would ship a
 * capability minted for one boundary to a different one. `delegate()` knows
 * which client minted the grant, so the store carries that origin and the send
 * path refuses a mismatch locally.
 *
 * `origin` is the minting client's normalized base URL. Base URL is the
 * comparable identity that matters here: it is exactly what decides where the
 * token is sent. Object identity would also refuse a legitimately
 * re-constructed client pointed at the same boundary.
 */
export interface DelegationGrant {
  readonly token: string;
  readonly origin: string;
}

function grantOf(v: unknown): DelegationGrant | null {
  if (typeof v === "string") return { token: v, origin: "" };
  if (v && typeof v === "object" && typeof (v as DelegationGrant).token === "string") {
    return v as DelegationGrant;
  }
  return null;
}

/**
 * The delegation capability attached to the current context (or null).
 *
 * INTROSPECTION ONLY — this ignores origin binding. Anything that puts the
 * token on the wire must use {@link currentCapabilityFor} instead, so a token
 * minted for one boundary cannot be shipped to another. Kept unchanged because
 * it is re-exported as public API.
 */
export function currentCapability(): string | null {
  return grantOf(capabilityStorage.getStore())?.token ?? null;
}

/**
 * The capability attached to the current context, but ONLY if it was minted
 * against `origin`. Returns null on mismatch — fail-closed: an unbound token is
 * not attached rather than attached hopefully.
 *
 * A store entry with an empty origin is a legacy bare-string entry; it is
 * treated as unbound and therefore never auto-attached to a specific origin.
 */
export function currentCapabilityFor(origin: string): string | null {
  const g = grantOf(capabilityStorage.getStore());
  if (!g || !g.origin) return null;
  return g.origin === origin ? g.token : null;
}

/** True inside a delegate() window whose mint failed. */
export function delegationDenied(): boolean {
  return capabilityStorage.getStore() === DELEGATION_DENIED;
}
