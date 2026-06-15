import type { PathTree } from "./types.js";

// Parse dot-notation field list into a nested tree.
//
// Example: ["name", "profile.age", "profile.address.city"]
//   → { name: {}, profile: { age: {}, address: { city: {} } } }
//
// A leaf ({}) means "match this key directly".
// A non-empty subtree means "descend into this key and apply sub-tree".
//
// When broaderWins=true (used by denyFields): a parent path takes precedence
// over child paths. ["profile", "profile.ssn"] collapses to { profile: {} }
// so the entire subtree is denied. Enforces AO-002 fail-closed.
export function parsePaths(
  fields: ReadonlyArray<string>,
  options: { broaderWins?: boolean } = {},
): PathTree {
  const { broaderWins = false } = options;

  let working = fields;
  const covered = new Set<string>();
  if (broaderWins) {
    working = [...fields].sort(
      (a, b) => countDots(a) - countDots(b),
    );
  }

  // Null-prototype tree: lookups (`k in tree`, `tree[k]`) must never resolve
  // to Object.prototype members. A data field named `toString` / `constructor`
  // / `hasOwnProperty` etc. would otherwise pass a `k in pathTree` whitelist
  // check it was never granted and leak raw (fail-OPEN scope bypass). S015 P0.
  const tree: PathTree = Object.create(null) as PathTree;
  for (const field of working) {
    const parts = field.split(".");
    if (broaderWins) {
      let skip = false;
      for (let i = 0; i < parts.length - 1; i++) {
        const prefix = parts.slice(0, i + 1).join(".");
        if (covered.has(prefix)) {
          skip = true;
          break;
        }
      }
      if (skip) continue;
      covered.add(field);
    }
    let node: PathTree = tree;
    for (const part of parts) {
      if (!Object.prototype.hasOwnProperty.call(node, part)) {
        node[part] = Object.create(null) as PathTree;
      }
      node = node[part]!;
    }
  }
  return tree;
}

// Whether a flattened data key (one literally containing dots) is denied by a
// nested deny `pathTree`. Fail-closed for flattened-key APIs: denyFields=
// ["card.cvv"] parses to { card: { cvv: {} } }; a top-level key LITERALLY named
// "card.cvv" is not in that tree, so the un-fixed deny loop KEPT it and leaked
// it (fail-OPEN on deny). Re-interpret the flattened key: split on "." and
// walk; if any prefix lands on a leaf (a denied node), the key is denied. This
// also means denyFields=["profile"] drops a flattened "profile.ssn". Scope
// needs no analogue (an unmatched literal key is already fail-closed). S017 H1.
export function flatKeyHitsDenyLeaf(key: string, pathTree: PathTree): boolean {
  if (!key.includes(".")) return false;
  let node: PathTree = pathTree;
  for (const part of key.split(".")) {
    if (!Object.prototype.hasOwnProperty.call(node, part)) return false;
    node = node[part]!;
    if (Object.keys(node).length === 0) return true;
  }
  return false;
}

function countDots(s: string): number {
  let n = 0;
  for (const ch of s) if (ch === ".") n++;
  return n;
}
