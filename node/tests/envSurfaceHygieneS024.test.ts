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
 * The source is passed through a string/comment-aware scanner before matching,
 * so `//` inside a string literal (e.g. "http://…") is not mistaken for a
 * comment, comment text is not mistaken for code, and template `${...}`
 * interpolations ARE scanned as code. Optional chaining (`process?.env`),
 * computed subscript keys (`process.env["A"+x]`, `` process.env[`${k}`] ``) and
 * destructuring off `process` are handled — closing the bypass classes surfaced
 * by the S024 cross-review (codex + cursor, two rounds).
 *
 * Accepted coverage boundary (defense-in-depth, not a full TS analyzer; none of
 * these appear in the SDK and each is non-idiomatic). Out of scope for a
 * regex-level lint: reflective access (`Reflect.get(process,"env")`), ESM/CJS
 * imports of the process module (`import proc from "node:process"`,
 * `require("process").env`), split declaration-then-assignment or
 * control-flow-dependent aliasing (`let p; p = process`), parenthesized or
 * type-asserted heads (`(process as NodeJS.Process).env`, `process!.env`), and
 * a read placed on the same line as a regex literal containing `//`. A real TS
 * AST would be needed to follow these; they are covered by the layered controls
 * (gitleaks + human code review + fail-closed runtime). Residual handoff
 * (R-S024-1).
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

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

/**
 * Blank out comments and string/template contents while preserving overall
 * character positions. String contents become spaces so a `//` or `process.env`
 * inside a literal is never scanned as code; comments become spaces so their
 * text is never scanned as code. Template-literal `${...}` interpolations are
 * kept as code, so a real read inside a template (`` `x=${process.env.X}` ``)
 * is not erased. String *delimiters* are kept so a literal subscript key still
 * shows its brackets — the key text is recovered from the raw source.
 */
function blankStringsAndComments(src: string): string {
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  // A stack lets template `${...}` push back to code and pop on the closing `}`.
  const stack: Array<"code" | "line" | "block" | "'" | '"' | "`"> = ["code"];
  const braceDepth: number[] = []; // depth per template-interpolation frame
  const state = () => stack[stack.length - 1];
  while (i < n) {
    const c = src[i];
    const c2 = i + 1 < n ? src[i + 1] : "";
    const s = state();
    if (s === "code") {
      if (c === "/" && c2 === "/") {
        out.push("  ");
        i += 2;
        stack.push("line");
      } else if (c === "/" && c2 === "*") {
        out.push("  ");
        i += 2;
        stack.push("block");
      } else if (c === "'" || c === '"' || c === "`") {
        out.push(c);
        i += 1;
        stack.push(c);
      } else if (c === "}" && braceDepth.length && braceDepth[braceDepth.length - 1] === 0) {
        // closing a `${...}` interpolation → pop both the code frame and its
        // brace counter, returning to the enclosing template-string state.
        braceDepth.pop();
        stack.pop();
        out.push(" ");
        i += 1;
      } else {
        if (braceDepth.length) {
          if (c === "{") braceDepth[braceDepth.length - 1] += 1;
          else if (c === "}") braceDepth[braceDepth.length - 1] -= 1;
        }
        out.push(c);
        i += 1;
      }
    } else if (s === "line") {
      if (c === "\n") {
        out.push(c);
        stack.pop();
      } else {
        out.push(" ");
      }
      i += 1;
    } else if (s === "block") {
      if (c === "*" && c2 === "/") {
        out.push("  ");
        i += 2;
        stack.pop();
      } else {
        out.push(c === "\n" ? "\n" : " ");
        i += 1;
      }
    } else {
      // inside a string/template delimited by `s`
      if (c === "\\") {
        out.push("  ");
        i += 2;
      } else if (s === "`" && c === "$" && c2 === "{") {
        // enter interpolation: treat its body as code
        out.push("  ");
        i += 2;
        stack.push("code");
        braceDepth.push(0);
      } else if (c === s) {
        out.push(c);
        i += 1;
        stack.pop();
      } else {
        out.push(c === "\n" ? "\n" : " ");
        i += 1;
      }
    }
  }
  return out.join("");
}

interface Scan {
  reads: string[];
  indirect: number; // count of bulk / indirect / dynamic accesses
}

function reEscape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// `process` reached with optional-chaining tolerance (`process?.env`).
const PROCESS_ENV = String.raw`process\s*\??\.\s*env`;

/**
 * Classify every env access reached through one "head" (`process.env`, or an
 * `<alias>.env` where the alias was bound to `process`). All matching is done on
 * the blanked code so comments/strings can neither hide nor forge an access;
 * literal subscript keys are recovered from the raw source by index.
 */
function scanHead(code: string, src: string, head: string, out: Scan): void {
  // Dot read: head.IDENT  (optional chaining allowed on either dot)
  for (const m of code.matchAll(new RegExp(head + String.raw`\s*\??\.\s*([A-Za-z_$][\w$]*)`, "g"))) {
    out.reads.push(m[1]);
  }
  // Subscript: head[...] or head?.[...] — classify literal-vs-computed on the
  // blanked inner text, recover the literal key from raw at the same span.
  const openRe = new RegExp(head + String.raw`\s*\??\.?\s*\[`, "g");
  for (const m of code.matchAll(openRe)) {
    const open = m.index + m[0].length - 1; // index of '['
    const close = code.indexOf("]", open);
    if (close < 0) {
      out.indirect += 1;
      continue;
    }
    const innerBlank = code.slice(open + 1, close);
    // A literal key shows as a quoted, blanked-empty span (delimiters kept).
    if (/^\s*(["'`])\s*\1\s*$/.test(innerBlank)) {
      const km = /(["'`])([^"'`]*)\1/.exec(src.slice(open + 1, close));
      if (km && !(km[1] === "`" && km[2].includes("${"))) out.reads.push(km[2]);
      else out.indirect += 1; // template-interpolated key → computed
    } else {
      out.indirect += 1; // dynamic / concatenated / nested key
    }
  }
  // Bulk / alias / spread: head not followed by `.`, `[`, `?`, or an ident char.
  for (const m of code.matchAll(new RegExp(head + String.raw`(?!\s*[.[\w$?])`, "g"))) {
    void m;
    out.indirect += 1;
  }
}

function scan(src: string): Scan {
  const code = blankStringsAndComments(src);
  const out: Scan = { reads: [], indirect: 0 };

  // process-aliases: `const p = process` / `const p: NodeJS.Process = process`
  // (bare process, not process. / process[). An optional type annotation before
  // `=` is tolerated so a type-annotated alias is still tracked.
  const heads = [PROCESS_ENV];
  for (const m of code.matchAll(
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*process(?!\s*[.[\w$])/g,
  )) {
    heads.push(reEscape(m[1]) + String.raw`\s*\??\.\s*env`);
  }
  for (const head of heads) scanHead(code, src, head, out);

  // Reached as process["env"] / process['env'] / process[`env`] (dynamic).
  for (const m of code.matchAll(/process\s*\??\[\s*(["'`])\s*\1\s*\]/g)) {
    void m;
    out.indirect += 1;
  }
  // Destructured off process: const { env } = process.
  for (const m of code.matchAll(/\{[^{}]*\benv\b[^{}]*\}\s*=\s*process\b/g)) {
    void m;
    out.indirect += 1;
  }
  return out;
}

function relKey(file: string): string {
  return relative(SRC_DIR, file).split(sep).join("/");
}

function scanAll(): Map<string, Scan> {
  const out = new Map<string, Scan>();
  for (const file of tsFiles(SRC_DIR)) {
    const s = scan(readFileSync(file, "utf-8"));
    if (s.reads.length > 0 || s.indirect > 0) out.set(relKey(file), s);
  }
  return out;
}

describe("S024 env-surface hygiene (Node)", () => {
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
