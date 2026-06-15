// Regression guard for the documented quickstart adoption surface.
//
// The README ("Or shield a data accessor in-process (SDK)") promises the
// snippet is "self-contained and run as written", and node/examples/quickstart.ts
// is the literal runnable form of that snippet. Before this test the example
// file had zero execution coverage: a change to shield()'s scope semantics, the
// example's import path, or its expected output could silently drift from the
// README without any test failing. For an external adopter the quickstart is the
// first thing they run, so we execute the real file via tsx — exactly as the
// README instructs (`npx tsx examples/quickstart.ts`) — and assert the shielded
// output keeps only scope=[name, issue] and strips every other field.

import { describe, expect, it, beforeAll } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const examplePath = fileURLToPath(
  new URL("../examples/quickstart.ts", import.meta.url),
);
const tsxBin = fileURLToPath(
  new URL("../node_modules/.bin/tsx", import.meta.url),
);

describe("README quickstart example (examples/quickstart.ts) runs as written", () => {
  beforeAll(() => {
    if (!existsSync(tsxBin)) {
      throw new Error(
        `tsx not found at ${tsxBin}. Run \`npm ci\` in node/ before this test; ` +
          `it executes the documented \`npx tsx examples/quickstart.ts\` path.`,
      );
    }
  });

  it("exit 0 and shielded output is exactly {name, issue} — no other field leaks", () => {
    const r = spawnSync(tsxBin, [examplePath], { encoding: "utf-8" });
    expect(r.status, `example exited non-zero. stderr:\n${r.stderr}`).toBe(0);
    expect(r.stdout.length).toBeGreaterThan(0);

    // The banner must appear exactly once; otherwise the split below would
    // silently yield an empty shielded segment and the test could pass
    // vacuously (codex S016 cross-review finding #3).
    const parts = r.stdout.split("=== With shield ===");
    expect(
      parts.length,
      `banner "=== With shield ===" must appear exactly once; stdout:\n${r.stdout}`,
    ).toBe(2);
    const [unshielded, shielded] = parts;

    // Prove the fixture genuinely carries the out-of-scope fields, so the
    // shielded absence below demonstrates real stripping rather than a fixture
    // that never had secrets (cursor S016 cross-review: "unshielded positive
    // example insufficient"). The "Without shield" block must show email + card.
    expect(unshielded).toContain("email");
    expect(unshielded).toContain("card");

    // Assert on the printed object's key SHAPE, not just sampled value
    // substrings (codex S016 cross-review finding #3): a leak in transformed,
    // masked, or re-cased form still shows up as an extra key.
    const obj = shielded.match(/\{([^}]*)\}/);
    expect(obj, `expected a printed object after the shield banner; got:\n${shielded}`).not.toBeNull();
    const body = obj![1];
    const keys = [...body.matchAll(/(\w+):/g)].map((m) => m[1]).sort();
    expect(keys).toEqual(["issue", "name"]);

    // Scoped fields are present with their values...
    expect(body).toContain("Tanaka Taro");
    expect(body).toContain("Login problem");
    // ...and no out-of-scope field leaks, in key OR value form.
    for (const leak of ["email", "card", "ssn", "@example.com", "4242", "tanaka@"]) {
      expect(body, `shielded output must not leak "${leak}"`).not.toContain(leak);
    }
  });
});
