// Idempotency invocation runner (.mjs = always ESM regardless of package.json).
//
// Called by tests/idempotency/invocation.py, which is the script handed to
// the internal-ops idempotency_guarantee verifier. The verifier writes
// the .py file to <package-dir>/.productization_idempotency_test.tmp and runs
// it under python3. The .py wrapper spawns this .mjs runner to exercise the
// real HistoryStore.recordIdempotent() primitive — keeping the actual TS
// SDK invocation in idiomatic ESM rather than a stringified -e snippet.
//
// Idempotency invariant under test: calling recordIdempotent() with the same
// idempotencyKey across 101 retries must result in exactly one appended
// record. Hash of the state JSONL file must be identical across all retries
// after the initial run.

import { HistoryStore } from "../../dist/index.js";

const stateFile = process.env.AEGIS_IDEMPOTENCY_STATE_FILE;
if (!stateFile) {
  console.error("AEGIS_IDEMPOTENCY_STATE_FILE env var not set");
  process.exit(1);
}

const store = new HistoryStore(stateFile);

const result = store.recordIdempotent(
  {
    function: "fixedFn",
    purpose: "support",
    scope: ["name", "email"],
    denyFields: [],
    blockedFields: ["ssn"],
    timestamp: "2026-05-17T00:00:00.000Z",
    mode: "lite",
  },
  "aegis.idempotency.fixed-key-001",
);

console.log(JSON.stringify(result));
