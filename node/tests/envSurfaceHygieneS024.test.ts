/**
 * S024 security sprint — env-surface hygiene guards (Node).
 *
 * Mirror of the Python guard in
 * python/tests/adversarial/test_redteam_S024_env_surface.py. Enforces four
 * source-level invariants over the SDK's environment intake so a future change
 * that widens the secret surface is rejected by CI rather than shipping:
 *
 *   1. Prefix confinement — every `process.env.X` / `process.env["X"]` read in
 *      src/ names an `AEGIS_` variable (AO-006: never read arbitrary host env).
 *   2. No bulk / indirect intake — `process.env` used bare, spread
 *      (`{...process.env}`), destructured (`const { X } = process.env`),
 *      aliased (`const e = process.env`), read with a dynamic key
 *      (`process.env[k]`), or reached as `process["env"]` is rejected. That is
 *      the "read arbitrary host env" hole in disguise.
 *   3. Token confinement — `AEGIS_TOKEN` read only in `{client.ts, shield.ts}`
 *      (matched by path relative to src/, not by basename).
 *   4. Insecure-toggle confinement — `AEGIS_DEV_INSECURE` / `AEGIS_VERIFY_SSL`
 *      read only in the TLS-resolution module `client.ts` (fail-secure
 *      prod-lock, AO-001 / AO-005).
 *
 * Implemented on the TypeScript compiler AST (typescript is a devDependency, so
 * it is available wherever this test runs). Working on the real AST — rather
 * than a regex over source text — closes the bypass classes that a text scanner
 * cannot follow: identifier aliasing (`const p = process; p.env.X`,
 * `const e = process.env; e.X`), whole-env intake (`{...process.env}`,
 * destructuring), computed / dynamic keys, optional chaining, parenthesized and
 * type-asserted heads (`(process as NodeJS.Process).env`, `process!.env`), and
 * `process["env"]` / `Reflect.get(process, "env")`. Comments, string contents
 * and regex literals cannot be mistaken for code because the parser tokenises
 * them. Verified across four rounds of the S024 cross-review (codex + cursor).
 *
 * Residual (accepted boundary): value flow that only a type-checker or runtime
 * could follow — e.g. `process` reached through a function return or a property
 * of another object, or a fully dynamic `Reflect`/`globalThis` computed member.
 * Layered with gitleaks + human review + fail-closed runtime (R-S024-1).
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

const TOKEN_MODULES = new Set(["client.ts", "shield.ts"]);
const INSECURE_TOGGLE_MODULES = new Set(["client.ts"]);
const INSECURE_TOGGLE_VARS = new Set(["AEGIS_DEV_INSECURE", "AEGIS_VERIFY_SSL"]);

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...tsFiles(full));
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

function relKey(file: string): string {
  return relative(SRC_DIR, file).split(sep).join("/");
}

interface Scan {
  reads: string[];
  indirect: number; // bulk / indirect / dynamic / reflective accesses
}

/** Strip parentheses, `!` non-null, and `as`/`satisfies` type assertions. */
function unwrap(node: ts.Expression): ts.Expression {
  let n: ts.Expression = node;
  for (;;) {
    if (ts.isParenthesizedExpression(n)) n = n.expression;
    else if (ts.isNonNullExpression(n)) n = n.expression;
    else if (ts.isAsExpression(n) || ts.isSatisfiesExpression(n)) n = n.expression;
    else return n;
  }
}

function isIdent(node: ts.Expression, name: string): boolean {
  const n = unwrap(node);
  return ts.isIdentifier(n) && n.text === name;
}

function scan(src: string): Scan {
  const sf = ts.createSourceFile("m.ts", src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const reads: string[] = [];
  let indirect = 0;

  // Identifiers bound to `process` and to `process.env`.
  const processAliases = new Set<string>(["process"]);
  const envAliases = new Set<string>();

  const isProcess = (node: ts.Expression): boolean => {
    const n = unwrap(node);
    return ts.isIdentifier(n) && processAliases.has(n.text);
  };
  // `<process>.env` (property or computed "env"), or an env-alias identifier.
  const isProcessEnv = (node: ts.Expression): boolean => {
    const n = unwrap(node);
    if (ts.isIdentifier(n) && envAliases.has(n.text)) return true;
    if (ts.isPropertyAccessExpression(n)) {
      return isProcess(n.expression) && n.name.text === "env";
    }
    if (ts.isElementAccessExpression(n)) {
      const arg = n.argumentExpression;
      return (
        isProcess(n.expression) &&
        ts.isStringLiteralLike(arg) &&
        arg.text === "env"
      );
    }
    return false;
  };

  // First pass: resolve aliases (declarations may appear before or after use,
  // so collect them fully before classifying accesses).
  const collectAliases = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = unwrap(node.initializer);
      if (ts.isIdentifier(node.name)) {
        if (isProcess(init)) processAliases.add(node.name.text);
        else if (isProcessEnv(init)) envAliases.add(node.name.text);
      }
    }
    // `p = process` / `e = process.env` assignments.
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      const rhs = unwrap(node.right);
      if (isProcess(rhs)) processAliases.add(node.left.text);
      else if (isProcessEnv(rhs)) envAliases.add(node.left.text);
    }
    ts.forEachChild(node, collectAliases);
  };
  // Alias chains (a = process; b = a) resolve in a few passes.
  for (let i = 0; i < 4; i++) {
    const before = processAliases.size + envAliases.size;
    collectAliases(sf);
    if (processAliases.size + envAliases.size === before) break;
  }

  // Node ids that are legitimate confined reads, so the catch-all below does
  // not double-count them as indirect.
  const confined = new Set<ts.Node>();

  const classify = (node: ts.Node): void => {
    // <process.env>.NAME  → confined named read
    if (ts.isPropertyAccessExpression(node) && isProcessEnv(node.expression)) {
      confined.add(node.expression);
      reads.push(node.name.text);
    }
    // <process.env>[expr]
    else if (ts.isElementAccessExpression(node) && isProcessEnv(node.expression)) {
      confined.add(node.expression);
      const arg = node.argumentExpression;
      if (ts.isStringLiteralLike(arg)) reads.push(arg.text);
      else indirect += 1; // computed / dynamic key
    }
    // Destructuring off process.env or process: `const { X } = process.env`
    else if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isObjectBindingPattern(node.name)
    ) {
      const init = unwrap(node.initializer);
      if (isProcessEnv(init)) {
        confined.add(init);
        indirect += 1; // whole-env destructure — arbitrary intake
      } else if (isProcess(init)) {
        // `const { env } = process`
        if (node.name.elements.some((e) => e.propertyName?.getText() === "env" || e.name.getText() === "env")) {
          indirect += 1;
        }
      }
    }
    // Reflect.get(process, "env") / Reflect.get(process.env, ...)
    else if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "get" &&
      isIdent(node.expression.expression, "Reflect") &&
      node.arguments.length >= 1 &&
      (isProcess(node.arguments[0]) || isProcessEnv(node.arguments[0]))
    ) {
      indirect += 1;
    }
    ts.forEachChild(node, classify);
  };
  classify(sf);

  // Catch-all: any process.env expression that is not a confined read receiver
  // and not an alias-defining initializer is a bulk / indirect access (bare
  // reference, spread element, passed as an argument, etc.).
  const catchAll = (node: ts.Node): void => {
    if (ts.isExpression(node) && isProcessEnv(node) && !confined.has(node)) {
      // Skip the RHS of an alias definition (already accounted for).
      const p = node.parent;
      const isAliasDef =
        (ts.isVariableDeclaration(p) && p.initializer && unwrap(p.initializer) === node) ||
        (ts.isBinaryExpression(p) &&
          p.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
          unwrap(p.right) === node);
      // Skip the receiver position of a confined property/element access.
      const isReceiver =
        (ts.isPropertyAccessExpression(p) && p.expression === node) ||
        (ts.isElementAccessExpression(p) && p.expression === node);
      if (!isAliasDef && !isReceiver) indirect += 1;
    }
    ts.forEachChild(node, catchAll);
  };
  catchAll(sf);

  return { reads, indirect };
}

function scanAll(): Map<string, Scan> {
  const out = new Map<string, Scan>();
  for (const file of tsFiles(SRC_DIR)) {
    const s = scan(readFileSync(file, "utf-8"));
    if (s.reads.length > 0 || s.indirect > 0) out.set(relKey(file), s);
  }
  return out;
}

describe("S024 env-surface hygiene (Node, TS-AST)", () => {
  it("scan is non-vacuous", () => {
    const scans = scanAll();
    const total = [...scans.values()].reduce((a, s) => a + s.reads.length, 0);
    expect(total).toBeGreaterThanOrEqual(10);
    const names = new Set([...scans.values()].flatMap((s) => s.reads));
    expect(names.has("AEGIS_TOKEN")).toBe(true);
  });

  it("every env read is AEGIS_-prefixed", () => {
    const scans = scanAll();
    const offenders: Record<string, string[]> = {};
    for (const [mod, s] of scans) {
      const bad = s.reads.filter((n) => !n.startsWith("AEGIS_"));
      if (bad.length) offenders[mod] = bad;
    }
    expect(offenders).toEqual({});
  });

  it("no bulk / indirect / dynamic process.env access", () => {
    const scans = scanAll();
    const offenders: Record<string, number> = {};
    for (const [mod, s] of scans) if (s.indirect) offenders[mod] = s.indirect;
    expect(offenders).toEqual({});
  });

  it("AEGIS_TOKEN intake is confined to transport modules", () => {
    const scans = scanAll();
    const readers = [...scans.entries()]
      .filter(([, s]) => s.reads.includes("AEGIS_TOKEN"))
      .map(([mod]) => mod);
    expect(readers.length).toBeGreaterThan(0);
    const stray = readers.filter((m) => !TOKEN_MODULES.has(m));
    expect(stray).toEqual([]);
  });

  it("insecure toggles are confined to the TLS module", () => {
    const scans = scanAll();
    const readers = [...scans.entries()]
      .filter(([, s]) => s.reads.some((n) => INSECURE_TOGGLE_VARS.has(n)))
      .map(([mod]) => mod);
    expect(readers.length).toBeGreaterThan(0);
    const stray = readers.filter((m) => !INSECURE_TOGGLE_MODULES.has(m));
    expect(stray).toEqual([]);
  });
});
