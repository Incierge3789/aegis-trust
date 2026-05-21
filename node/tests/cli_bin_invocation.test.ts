// Regression test for the bin-shim silent-exit defect closed in PR #4
// (T-S179-cli-bin-shim).
//
// Background: the npm package's `bin` entry creates a symlink
// `node_modules/.bin/aegis` → `node_modules/aegis-trust/dist/cli.js`. Before
// this PR, dist/cli.js's ESM "is main module" check compared
// `process.argv[1].split("/").pop()` (which equals "aegis" when invoked
// via the bin shim) against the end of `import.meta.url` (which ends in
// "cli.js"). The two never matched, so `isMain` was always false on bin-shim
// invocation, `main()` was never called, and every subcommand exited
// silently with 0 bytes on stdout AND stderr and exit code 0.
//
// This test exercises the compiled artifact (`dist/cli.js`) via a symlink
// in a temp directory — the same shape npm creates at install time — and
// asserts non-silent output. Running the test against `src/cli.ts` directly
// (via the existing vitest loader) does not reproduce the bug because direct
// node invocation always satisfied the buggy check too; only the symlink
// path was broken. The test therefore deliberately targets `dist/cli.js`
// and bails with a clear message if the build has not been run.

import { describe, expect, it, beforeAll } from "vitest";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const distCli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

function runViaSymlink(args: string[]): {
  status: number | null;
  stdout: string;
  stderr: string;
} {
  const dir = mkdtempSync(join(tmpdir(), "aegis-bin-shim-test-"));
  const symlinkPath = join(dir, "aegis");
  try {
    symlinkSync(distCli, symlinkPath);
    const r = spawnSync(process.execPath, [symlinkPath, ...args], {
      encoding: "utf-8",
      env: {
        ...process.env,
        // Direct sandbox writes to its own audit file inside the temp dir
        // so the test is hermetic and never touches the user's home dir.
        AEGIS_SANDBOX_AUDIT: join(dir, "sandbox-audit.jsonl"),
        // Force history reads off the user's default db so `aegis history`
        // / `aegis stats` produce the documented "no history found" hint
        // path (which is non-empty stdout) without depending on developer state.
        AEGIS_HISTORY_PATH: join(dir, "history.jsonl"),
      },
    });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("aegis CLI bin-shim invocation (regression for silent-exit bug)", () => {
  beforeAll(() => {
    if (!existsSync(distCli)) {
      throw new Error(
        `dist/cli.js not found at ${distCli}. Run \`npm run build\` from the ` +
          `node/ package before this test. This test exercises the published ` +
          `bin-shim path; direct node-on-source invocation does not reproduce ` +
          `the silent-exit bug this test is guarding against.`,
      );
    }
  });

  it("--help via symlink: exit 0 + non-empty stdout containing usage text", () => {
    const r = runViaSymlink(["--help"]);
    expect(r.status).toBe(0);
    expect(r.stdout.length).toBeGreaterThan(0);
    expect(r.stdout).toMatch(/aegis/i);
    expect(r.stdout).toMatch(/sandbox|history|stats/i);
  });

  it("sandbox via symlink: exit 0 + non-empty stdout containing decision panel", () => {
    const r = runViaSymlink(["sandbox"]);
    expect(r.status).toBe(0);
    expect(r.stdout.length).toBeGreaterThan(0);
    expect(r.stdout).toMatch(/sandbox|customer_support|decision/i);
  });

  it("history via symlink: non-silent (records or no-history hint, exit 0 or 1)", () => {
    const r = runViaSymlink(["history"]);
    // The silent-exit regression class is defined by stdout=0 AND stderr=0.
    // The exact exit code is an existing CLI behaviour, not the bug under
    // test: when the history db does not exist (the case in this hermetic
    // test), `cmdHistory()` legitimately prints the "No history database
    // found / Enable history with AEGIS_HISTORY=1" hint and returns 1. We
    // therefore guard the regression class explicitly: stdout MUST be
    // non-empty, and the exit code must be one of the documented values
    // (0 = records shown / 1 = no-db hint shown).
    expect(r.stdout.length).toBeGreaterThan(0);
    expect([0, 1]).toContain(r.status);
    expect(r.stdout).toMatch(/no history database|record/i);
  });

  it("stats via symlink: non-silent (aggregates or no-history hint, exit 0 or 1)", () => {
    const r = runViaSymlink(["stats"]);
    // Same rationale as `history`: no-db path exits 1 with hint; with-db
    // path exits 0 with aggregates. Both are non-silent.
    expect(r.stdout.length).toBeGreaterThan(0);
    expect([0, 1]).toContain(r.status);
  });

  it("no-arg invocation via symlink: exit 0 + help text on stdout", () => {
    const r = runViaSymlink([]);
    expect(r.status).toBe(0);
    expect(r.stdout.length).toBeGreaterThan(0);
    expect(r.stdout).toMatch(/aegis|sandbox|history/i);
  });

  it("unknown command via symlink: exit 2 + error message on stderr", () => {
    const r = runViaSymlink(["definitely-not-a-real-subcommand"]);
    expect(r.status).toBe(2);
    // Existing behaviour: prints "unknown command:" + help. Both go through
    // main(); silent exit would fail the previous assertions but this guards
    // against future regressions that mute the error path specifically.
    expect(r.stderr).toMatch(/unknown command/i);
  });
});
