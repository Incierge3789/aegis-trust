/**
 * Backend registry gate — a surface cannot be added without declaring it (Node).
 *
 * invariants.v0.json says what must HOLD. backends.v0.json says what it must
 * hold FOR. This guard binds the second to reality: it parses the SDK's own
 * source and refuses any extension point that is not registered.
 *
 * This is the backend form of the pattern already proven in
 * python/tests/test_contract_gate.py, which AST-parses client.py for HTTP path
 * literals and asserts each exists in the committed openapi.json — you cannot
 * add a surface without declaring it. Nothing equivalent existed for adapters,
 * modes, or decision sources, which is exactly the condition where a new adapter
 * appears and nobody decides what it must satisfy.
 *
 * The guard earned its place while being written: the modes surface had been
 * registered with two members because the Mode enum was assumed to have two.
 * It has three. AUTO now has its own row.
 *
 * Mirror: python/tests/test_backend_registry.py.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

interface Backend {
  id: string;
  python: string | null;
  node: string | null;
  asymmetry_reason?: string;
}
interface Surface {
  id: string;
  extraction: Record<string, { file: string; symbol_source: string }>;
  backends: Backend[];
  classification_excluded?: Record<string, Record<string, string>>;
}

const registry = JSON.parse(
  readFileSync(join(REPO, "conformance", "backends.v0.json"), "utf8"),
) as {
  version: number;
  invariant_ids: string[];
  cell_states: Record<string, string>;
  surfaces: Surface[];
  coverage: Record<string, Record<string, { state: string; note?: string }>>;
};

const CELL_STATES = new Set(Object.keys(registry.cell_states));

function parse(rel: string): ts.SourceFile {
  const abs = join(REPO, rel);
  return ts.createSourceFile(abs, readFileSync(abs, "utf8"), ts.ScriptTarget.Latest, true);
}

function walk(node: ts.Node, fn: (n: ts.Node) => void): void {
  fn(node);
  ts.forEachChild(node, (c) => walk(c, fn));
}

/**
 * Every value this module exports, in any form TypeScript allows.
 *
 * Cross-review round 2 (cursor + agy, independently, both P1): the first version
 * handled only `export { a } from "..."`. `export const toFooTool = ...`,
 * `export function toFooTool()`, `export default`, and `export * from "./foo"`
 * all sailed past it. A new adapter written in any of those forms would not
 * appear in the extraction, so it would be neither registered nor flagged as
 * unclassified — the registry gate would pass while the surface grew. That is
 * the exact failure the gate exists to prevent, so the extraction has to cover
 * every form the language offers, not the one form this repo happens to use.
 *
 * `export * from` cannot be resolved without following the module graph, so it
 * is refused outright rather than silently under-reported: see
 * test_star_reexport_is_refused.
 */
function namedExports(src: ts.SourceFile): Set<string> {
  const out = new Set<string>();
  const exported = (n: ts.Node): boolean =>
    ts.canHaveModifiers(n) &&
    (ts.getModifiers(n) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);

  walk(src, (node) => {
    // export { a, b } from "..."  /  export { a }
    if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
      if (node.isTypeOnly) return; // `export type { X }` is shape, not a backend
      for (const el of node.exportClause.elements) {
        if (!el.isTypeOnly) out.add(el.name.text);
      }
    }
    // export const a = ...  /  export let a
    if (ts.isVariableStatement(node) && exported(node)) {
      for (const decl of node.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) out.add(decl.name.text);
      }
    }
    // export function a() {}  /  export class A {}  /  export enum A {}
    if (
      (ts.isFunctionDeclaration(node) ||
        ts.isClassDeclaration(node) ||
        ts.isEnumDeclaration(node)) &&
      exported(node) &&
      node.name
    ) {
      out.add(node.name.text);
    }
    // export default ...
    if (ts.isExportAssignment(node) && !node.isExportEquals) {
      out.add("default");
    }
  });
  return out;
}

/** `export * from "./x"` — unresolvable without the module graph. */
function hasStarReexport(src: ts.SourceFile): boolean {
  let found = false;
  walk(src, (node) => {
    if (ts.isExportDeclaration(node) && !node.exportClause && node.moduleSpecifier) {
      found = true;
    }
  });
  return found;
}

function enumMembers(src: ts.SourceFile, name: string): Set<string> {
  const out = new Set<string>();
  walk(src, (node) => {
    if (ts.isEnumDeclaration(node) && node.name.text === name) {
      for (const m of node.members) {
        if (ts.isIdentifier(m.name)) out.add(m.name.text);
      }
    }
  });
  return out;
}

function extract(surface: Surface): Set<string> {
  const spec = surface.extraction.node!;
  const src = parse(spec.file);
  if (spec.symbol_source === "named exports") return namedExports(src);
  if (spec.symbol_source === "Mode enum members") return enumMembers(src, "Mode");
  throw new Error(`unknown symbol_source ${spec.symbol_source}`);
}

function registered(surface: Surface): Set<string> {
  return new Set(
    surface.backends.map((b) => b.node).filter((n): n is string => n !== null),
  );
}

describe("backend registry gate", () => {
  it("registry is non-vacuous", () => {
    // A gate that enumerates nothing must fail, not pass.
    expect(registry.version).toBe(0);
    expect(registry.surfaces.length).toBeGreaterThan(0);
    expect(registry.invariant_ids.length).toBeGreaterThanOrEqual(7);
    for (const s of registry.surfaces) {
      expect(s.backends.length, `${s.id}: no backends`).toBeGreaterThan(0);
      expect(extract(s).size, `${s.id}: extraction found nothing`).toBeGreaterThan(0);
    }
  });

  for (const surface of registry.surfaces) {
    it(`${surface.id}: every export is classified`, () => {
      // Not merely "registered" — CLASSIFIED. Every exported symbol is either a
      // backend (with a coverage row deciding all seven invariants) or an
      // explicit exclusion with a stated reason. A new export is neither until
      // somebody chooses, so this fails and the choice has to be made.
      const excluded = new Set(Object.keys(surface.classification_excluded?.node ?? {}));
      const unclassified = [...extract(surface)].filter(
        (n) => !registered(surface).has(n) && !excluded.has(n),
      );
      expect(
        unclassified,
        `exported but unclassified: ${unclassified.join(", ")} — register each as a backend or exclude it with a reason`,
      ).toEqual([]);
    });

    it(`${surface.id}: star re-export is refused, not under-reported`, () => {
      // `export * from "./x"` cannot be resolved without following the module
      // graph, so the extraction would silently miss whatever it pulls in.
      // Refusing is the honest option: a gate that under-reports is worse than
      // one that stops. (cross-review round 2)
      const spec = surface.extraction.node!;
      expect(
        hasStarReexport(parse(spec.file)),
        `${spec.file} uses 'export * from', which this extraction cannot resolve — ` +
          "enumerate the exports explicitly so the registry can see them",
      ).toBe(false);
    });

    it(`${surface.id}: exclusions are justified and still exist`, () => {
      // An exemption list with no reasons is where a gate goes to quietly die:
      // the cheapest way to defeat this is to move an inconvenient backend into
      // the exclusion list. Same rule as not_corpora_reasons.
      const excluded = surface.classification_excluded?.node ?? {};
      for (const [name, reason] of Object.entries(excluded)) {
        expect(reason.length, `${surface.id}/${name}: reason too thin to audit`).toBeGreaterThan(30);
      }
      const exported = extract(surface);
      const stale = Object.keys(excluded).filter((n) => !exported.has(n));
      expect(stale, `excluded symbols no longer exported: ${stale.join(", ")}`).toEqual([]);
    });

    it(`${surface.id}: no registered backend missing from source`, () => {
      const exported = extract(surface);
      const stale = [...registered(surface)].filter((n) => !exported.has(n));
      expect(stale, `registered but absent from source: ${stale.join(", ")}`).toEqual([]);
    });

    it(`${surface.id}: cross-language asymmetry is declared`, () => {
      // Undeclared asymmetry is how two SDKs stop being the same product
      // without anyone noticing. See INV-7, where that had already happened.
      for (const b of surface.backends) {
        if (b.python === null || b.node === null) {
          expect(
            b.asymmetry_reason,
            `${surface.id}/${b.id}: one-sided with no asymmetry_reason`,
          ).toBeTruthy();
        }
      }
    });
  }

  it("every backend has a coverage row", () => {
    const declared = new Set(registry.surfaces.flatMap((s) => s.backends.map((b) => b.id)));
    const missing = [...declared].filter((d) => !(d in registry.coverage));
    expect(missing, `backends with no coverage row: ${missing.join(", ")}`).toEqual([]);
    const stale = Object.keys(registry.coverage).filter((c) => !declared.has(c));
    expect(stale, `coverage rows for unknown backends: ${stale.join(", ")}`).toEqual([]);
  });

  it("the product is complete", () => {
    // Every (backend x invariant) cell is declared. A new backend cannot be
    // registered without a decision for all seven invariants. 'none' is a valid
    // decision; silence is not.
    for (const [backend, row] of Object.entries(registry.coverage)) {
      const missing = registry.invariant_ids.filter((i) => !(i in row));
      expect(missing, `${backend}: undeclared invariants ${missing.join(", ")}`).toEqual([]);
      for (const [invId, cell] of Object.entries(row)) {
        expect(CELL_STATES.has(cell.state), `${backend}/${invId}: unknown state ${cell.state}`).toBe(true);
        if (cell.state !== "none") {
          expect(
            cell.note,
            `${backend}/${invId}: claims ${cell.state} with no note`,
          ).toBeTruthy();
        }
      }
    }
  });

  it("no cell claims full yet", () => {
    // Guards the matrix's honesty against optimistic editing. If this ever needs
    // deleting, that should be a visible argued act, not a quiet edit.
    const claimed = Object.entries(registry.coverage).flatMap(([b, row]) =>
      Object.entries(row)
        .filter(([, c]) => c.state === "full")
        .map(([i]) => `${b}/${i}`),
    );
    expect(claimed, `cells claiming 'full': ${claimed.join(", ")}`).toEqual([]);
  });
});
