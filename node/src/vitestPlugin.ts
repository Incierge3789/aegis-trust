// vitest plugin for aegis-trust — TS port of aegis.pytest_plugin.
//
// Provides:
//   - useShieldHistory(): wires beforeEach/afterEach to capture shield calls
//   - assertShieldBlocked(records, field)
//   - assertShieldPassed(records, field)
//
// Pytest's auto-injected fixture pattern doesn't 1:1 map to vitest. The
// closest idiomatic TS equivalent is a hook helper invoked at describe
// scope. Same semantic guarantee: records are isolated per-test and
// available inside the test body.

import { _setTestHook } from "./shield.js";

export interface ShieldRecord {
  readonly function: string;
  readonly purpose: string;
  readonly scope: ReadonlyArray<string>;
  readonly denyFields: ReadonlyArray<string>;
  readonly blockedFields: ReadonlyArray<string>;
  readonly timestamp: string;
}

export interface ShieldHistoryHandle {
  records(): ReadonlyArray<ShieldRecord>;
  reset(): void;
}

// Wire to vitest's beforeEach/afterEach. Caller passes them in (avoids
// hard-importing vitest from this module so non-test consumers don't
// pull it in).
export function useShieldHistory(hooks: {
  beforeEach: (fn: () => void) => void;
  afterEach: (fn: () => void) => void;
}): ShieldHistoryHandle {
  let captured: ShieldRecord[] = [];

  hooks.beforeEach(() => {
    captured = [];
    _setTestHook((r) => {
      captured.push({
        function: r.function,
        purpose: r.purpose,
        scope: r.scope,
        denyFields: r.denyFields,
        blockedFields: r.blockedFields,
        timestamp: r.timestamp,
      });
    });
  });

  hooks.afterEach(() => {
    _setTestHook(null);
    captured = [];
  });

  return {
    records: () => captured,
    reset: () => {
      captured = [];
    },
  };
}

function collectBlocked(records: ReadonlyArray<ShieldRecord>): Set<string> {
  const s = new Set<string>();
  for (const r of records) for (const f of r.blockedFields) s.add(f);
  return s;
}

export function assertShieldBlocked(
  records: ReadonlyArray<ShieldRecord>,
  field: string,
): void {
  const blocked = collectBlocked(records);
  if (!blocked.has(field)) {
    const sorted = [...blocked].sort();
    throw new Error(
      `Expected '${field}' to be blocked, but it was not. `
        + `Blocked fields: [${sorted.join(", ")}]`,
    );
  }
}

export function assertShieldPassed(
  records: ReadonlyArray<ShieldRecord>,
  field: string,
): void {
  const blocked = collectBlocked(records);
  if (blocked.has(field)) {
    const sorted = [...blocked].sort();
    throw new Error(
      `Expected '${field}' to pass through, but it was blocked. `
        + `Blocked fields: [${sorted.join(", ")}]`,
    );
  }
}
