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
export const capabilityStorage = new AsyncLocalStorage<string | typeof DELEGATION_DENIED>();

/** The delegation capability attached to the current context (or null). */
export function currentCapability(): string | null {
  const v = capabilityStorage.getStore();
  return typeof v === "string" ? v : null;
}

/** True inside a delegate() window whose mint failed. */
export function delegationDenied(): boolean {
  return capabilityStorage.getStore() === DELEGATION_DENIED;
}
