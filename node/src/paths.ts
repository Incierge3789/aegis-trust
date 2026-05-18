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

  const tree: PathTree = {};
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
      if (!(part in node)) {
        node[part] = {};
      }
      node = node[part]!;
    }
  }
  return tree;
}

function countDots(s: string): number {
  let n = 0;
  for (const ch of s) if (ch === ".") n++;
  return n;
}
