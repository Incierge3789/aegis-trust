import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// The "zero runtime dependencies" claim is customer-facing — it appears in
// node/README.md ("Zero runtime dependencies in Lite mode") and in
// docs/productization/LITE_QUICKSTART.md ("npm install aegis-trust # Node 18+
// — zero runtime dependencies"). Until this file existed, nothing enforced it.
//
// It had already drifted. `yaml` sat in `optionalDependencies`, which npm
// installs BY DEFAULT (it is skipped only with --omit=optional / --no-optional).
// So a plain `npm install aegis-trust` pulled a package that no shipped source
// file imports: the only `from "yaml"` in the repo is in
// node/tests/canonical.test.ts, and `files` does not ship tests. The claim was
// false as written, and the second `yaml` entry in devDependencies meant
// removing the optional one cost nothing.
//
// Found by cross-review (codex, 2026-07-29) on a change that had already been
// merged. The lesson is the S025 one: a claim nobody machine-checks is a claim
// that drifts. This test is that machine check.
//
// SCOPE: this pins the LITE surface only — the `full` / gateway extra is
// opt-in and deliberately carries httpx. That asymmetry is intentional, and
// the assertions below are about what a bare `npm install` pulls.

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_PATH = join(HERE, "..", "package.json");

interface PackageJson {
  readonly dependencies?: Record<string, string>;
  readonly optionalDependencies?: Record<string, string>;
  readonly peerDependencies?: Record<string, string>;
  readonly devDependencies?: Record<string, string>;
}

function readPkg(): PackageJson {
  return JSON.parse(readFileSync(PKG_PATH, "utf8")) as PackageJson;
}

describe("LITE zero-runtime-dependency claim", () => {
  it("declares no `dependencies`", () => {
    const deps = readPkg().dependencies ?? {};
    expect(Object.keys(deps)).toEqual([]);
  });

  it("declares no `optionalDependencies` — npm installs them by default", () => {
    // This is the one that was actually broken. `optionalDependencies` is not
    // "optional" from the consumer's side; it is installed unless they opt out.
    const optional = readPkg().optionalDependencies ?? {};
    expect(Object.keys(optional)).toEqual([]);
  });

  it("declares no `peerDependencies`", () => {
    // A peer dep is not auto-installed by npm 7+ only when it conflicts; it is
    // still a dependency the consumer must resolve. Zero means zero.
    const peer = readPkg().peerDependencies ?? {};
    expect(Object.keys(peer)).toEqual([]);
  });

  it("is non-vacuous: it reads a real manifest that declares devDependencies", () => {
    // Guard against the failure mode this repo has hit before (S025): an
    // assertion that passes because it is reading nothing. If the path breaks
    // or the parse silently yields {}, the three tests above go green while
    // checking air. A real package.json here always has devDependencies.
    const pkg = readPkg();
    expect(Object.keys(pkg.devDependencies ?? {}).length).toBeGreaterThan(0);
  });
});
