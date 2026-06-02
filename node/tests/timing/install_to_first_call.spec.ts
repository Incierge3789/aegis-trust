// In-process timing sanity test (vitest).
//
// Production gate is the internal-ops `time_to_first_call` verifier
// (runs the install + first_call_script.js end-to-end on a clean workdir,
// 60s wall-clock budget). This file is a fast in-process companion check:
// importing `shield` and making a first call must complete in < 5s once
// the package is already installed.
//
// If this test fails locally, the verifier will fail too. The verifier
// remains the source-of-truth gate.

import { describe, expect, it } from "vitest";

describe("time-to-first-call (in-process sanity)", () => {
  it("imports shield and makes a first decision in < 5s", async () => {
    const t0 = performance.now();
    const { shield } = await import("../../src/index.js");
    const safeFetch = shield({
      purpose: "support",
      scope: ["name", "email"],
    })((id: number) => ({
      id,
      name: "alice",
      email: "alice@example.com",
      ssn: "X",
    }));
    const out = safeFetch(42) as Record<string, unknown>;
    const elapsedMs = performance.now() - t0;
    expect(out).toEqual({ name: "alice", email: "alice@example.com" });
    expect(elapsedMs).toBeLessThan(5_000);
  });
});
