// Keyless (LITE) structural verifier for Aegis boundary receipts — parity with
// python/src/aegis_trust/receipt_verify.py (byte-identical outputs).
//
// What the SDK CAN verify without any key material (gap 1 — the consumer-side
// receipt verifier):
//
// * `sessionDagRoot` — recompute the SHA-256 aggregation root over a Session
//   Receipt's `event_receipt_refs` + `fragment_tags` (cross-impl pinned with
//   Aegis Core `boundary_adapter::session_dag_root`).
// * `verifySessionReceiptStructure` — schema tag, sorted/deduped refs+tags,
//   dag_root recomputation, value-free fragment tags.
// * `danglingPriorReceiptRefs` — Cross-Agent Receipt Linkage integrity (S139
//   VULN-2): every cited prior receipt must exist in the receipt set you hold.
// * `computeLineageRoot` / `verifyLineageRoot` — the fragment lineage hash
//   (domain `aegis-fragment-lineage.v1`), byte-for-byte with Core.
//
// HONESTY BOUNDARY (LITE vs FULL — never overclaim): `audit_chain_link` is an
// HMAC keyed by the tenant's boundary master key. WITHOUT that key this module
// can only check structure and internal consistency — it can NOT prove
// authenticity or chain integrity. Keyed verification is Aegis Core's runtime
// territory (`verify_session_receipt` in the engine). Zero-dep node:crypto only.
//
// Errors: where the Python original raises ValueError, this module throws a
// plain Error carrying the SAME message text, so failures grep identically
// across SDKs. Problem strings from `verifySessionReceiptStructure` are also
// byte-identical to Python's (including Python-`repr` formatting of values).

import { createHash, type Hash } from "node:crypto";
import { AegisValidationError, aegisDocsUrl } from "./errors.js";

export const SPAN_CRYPTO_SCHEMA_TAG = "aegis-span-crypto.v0";
export const LINEAGE_ROOT_LEN = 32;
const LINEAGE_DOMAIN = Buffer.from("aegis-fragment-lineage.v1", "utf8");
const SESSION_DAG_DOMAIN = Buffer.from("aegis-session-receipt.v1", "utf8");
const SEP_NUL = Buffer.from([0x00]);
const SEP_FF = Buffer.from([0xff]);

// Python: `1 <= len(s) <= 128` code points of `[A-Za-z0-9._:-]`. The class is
// pure ASCII, so any string that matches has code points == UTF-16 code units
// and the {1,128} quantifier counts exactly like Python's len(); any string
// containing non-ASCII (including astral chars) fails the class in both
// implementations. No `m` flag: `^`/`$` anchor to the whole string.
const VALUE_FREE_LABEL_RE = /^[A-Za-z0-9._:-]{1,128}$/;

/** Value-free metadata label gate: ASCII `[A-Za-z0-9._:-]`, 1..=128. */
export function isValueFreeLabel(s: string): boolean {
  return VALUE_FREE_LABEL_RE.test(s);
}

/**
 * Recompute a Session Receipt's `dag_root` (hex). Inputs are used AS STORED
 * on the receipt (Core sorts + dedups before sealing).
 */
export function sessionDagRoot(
  eventReceiptRefs: readonly string[],
  fragmentTags: readonly string[],
): string {
  const h = createHash("sha256");
  h.update(SESSION_DAG_DOMAIN);
  for (const r of eventReceiptRefs) {
    h.update(Buffer.from(r, "utf8"));
    h.update(SEP_NUL);
  }
  h.update(SEP_FF);
  for (const t of fragmentTags) {
    h.update(Buffer.from(t, "utf8"));
    h.update(SEP_NUL);
  }
  return h.digest("hex"); // lowercase hex, same as Python hexdigest()
}

// Python sorts str by Unicode CODE POINT; the JS default sort compares UTF-16
// CODE UNITS. The two orders diverge when an astral char (U+10000+, encoded as
// surrogates 0xD800-0xDFFF) is compared against a BMP char in [U+E000, U+FFFF].
// Validated inputs here are ASCII (where the orders coincide), but a hostile
// receipt is sorted BEFORE its labels are validated — exactly like Python —
// so compare by code point to match Python's sorted() byte-for-byte.
function codePointCompare(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i) as number;
    const cb = b.codePointAt(j) as number;
    if (ca !== cb) return ca - cb;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  return a.length - i - (b.length - j);
}

// Python truthiness for JSON-shaped values (`x or []`, `not x`): None/absent,
// "", 0, False, and empty containers are falsy. (NaN is truthy in Python and
// here — do not use JS `!x`, which would flip 0-vs-NaN semantics.)
function pyTruthy(v: unknown): boolean {
  if (v == null || v === "" || v === 0 || v === false) return false;
  if (Array.isArray(v)) return v.length > 0;
  if (v instanceof Set || v instanceof Map) return v.size > 0;
  if (typeof v === "object") {
    const proto = Object.getPrototypeOf(v);
    if (proto === Object.prototype || proto === null) {
      return Object.keys(v as object).length > 0;
    }
  }
  return true;
}

// Python `list(x or [])`: falsy -> [], iterable -> materialized list, a
// mapping -> its keys, anything else raises TypeError (mirrored).
function pyList(v: unknown): unknown[] {
  if (!pyTruthy(v)) return [];
  if (typeof v === "string") return Array.from(v); // Python list("ab") == ["a","b"]
  if (typeof v === "object") {
    const it = (v as Record<PropertyKey, unknown>)[Symbol.iterator];
    if (typeof it === "function") return [...(v as Iterable<unknown>)];
    const proto = Object.getPrototypeOf(v);
    if (proto === Object.prototype || proto === null) {
      return Object.keys(v as object); // Python list(dict) -> keys
    }
  }
  throw new AegisValidationError({
    code: "aegis.receipt.canonical.not_iterable",
    remediation: "Receipt payloads must be JSON-shaped (objects, arrays, strings, numbers, booleans, null).",
    docs_url: aegisDocsUrl("aegis.receipt.canonical.not_iterable"),
    message: `'${typeof v}' object is not iterable`,
  });
}

// Python sorted() semantics: homogeneous str (code-point order) or number
// lists sort; anything else raises TypeError, like Python's `<` on
// unorderable / mixed types.
function pySortCompare(a: unknown, b: unknown): number {
  if (typeof a === "string" && typeof b === "string") return codePointCompare(a, b);
  if (typeof a === "number" && typeof b === "number") return a - b;
  throw new AegisValidationError({
    code: "aegis.receipt.canonical.unorderable",
    remediation: "Receipt lists must be homogeneous strings or numbers to sort canonically.",
    docs_url: aegisDocsUrl("aegis.receipt.canonical.unorderable"),
    message: `'<' not supported between instances of '${typeof b}' and '${typeof a}'`,
  });
}

// Python `sorted(set(items))`.
function sortedDeduped(items: readonly unknown[]): unknown[] {
  return [...new Set(items)].sort(pySortCompare);
}

function arraysEqual(a: readonly unknown[], b: readonly unknown[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

// Python str.isprintable(): false for Unicode categories Other (C*) and
// Separator (Z*), except the ASCII space. repr() escapes those.
const PY_NON_PRINTABLE_RE = /[\p{C}\p{Z}]/u;

function pyEscape(cp: number): string {
  if (cp <= 0xff) return "\\x" + cp.toString(16).padStart(2, "0");
  if (cp <= 0xffff) return "\\u" + cp.toString(16).padStart(4, "0");
  return "\\U" + cp.toString(16).padStart(8, "0");
}

// Python `repr()` for the value shapes a wire receipt can carry, so problem
// strings match the Python SDK byte-for-byte: strings single-quoted (double-
// quoted when they contain ' but not "), backslash/quote escaped, \n\r\t as
// mnemonics, other non-printables (category C*/Z* except space) as
// \xNN/\uNNNN/\UNNNNNNNN, printable non-ASCII kept as-is; absent/null ->
// None; booleans -> True/False. Containers fall back to JSON (best-effort;
// receipts never carry them here).
function pyRepr(v: unknown): string {
  if (v === null || v === undefined) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "number" || typeof v === "bigint") return String(v);
  if (typeof v === "string") {
    const quote = v.includes("'") && !v.includes('"') ? '"' : "'";
    let out = quote;
    for (const ch of v) {
      const cp = ch.codePointAt(0) as number;
      if (ch === "\\") out += "\\\\";
      else if (ch === quote) out += "\\" + quote;
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (ch !== " " && PY_NON_PRINTABLE_RE.test(ch)) out += pyEscape(cp);
      else out += ch;
    }
    return out + quote;
  }
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return Object.prototype.toString.call(v);
  }
}

/**
 * Structural verification of a Session Receipt. Returns the list of problems
 * found (empty = structurally sound). NEVER claims authenticity — the keyed
 * `audit_chain_link` is verifiable only by the key holder.
 */
export function verifySessionReceiptStructure(
  receipt: Readonly<Record<string, unknown>>,
): string[] {
  const problems: string[] = [];
  const schema = receipt["schema"];
  if (schema !== SPAN_CRYPTO_SCHEMA_TAG) {
    problems.push(`schema is ${pyRepr(schema)}, expected ${pyRepr(SPAN_CRYPTO_SCHEMA_TAG)}`);
  }
  const refs = pyList(receipt["event_receipt_refs"]);
  const tags = pyList(receipt["fragment_tags"]);
  // S022 hardening (mirrors Python): non-string members are reported as
  // problems — this function returns, it never throws (previously mixed
  // unorderable types threw TypeError out of the Python-parity sort).
  const refsOk = refs.every((r): r is string => typeof r === "string");
  const tagsOk = tags.every((t): t is string => typeof t === "string");
  if (!refsOk) {
    problems.push("event_receipt_refs contain non-string members");
  } else if (!arraysEqual(refs, sortedDeduped(refs))) {
    problems.push("event_receipt_refs are not sorted+deduplicated");
  }
  if (!tagsOk) {
    problems.push("fragment_tags contain non-string members");
  } else if (!arraysEqual(tags, sortedDeduped(tags))) {
    problems.push("fragment_tags are not sorted+deduplicated");
  }
  for (const t of tags) {
    if (typeof t !== "string" || !isValueFreeLabel(t)) {
      problems.push(`fragment_tag ${pyRepr(t)} is not a value-free label`);
    }
  }
  const claimed = receipt["dag_root"];
  if (refsOk && tagsOk) {
    const recomputed = sessionDagRoot(refs as string[], tags as string[]);
    if (claimed !== recomputed) {
      problems.push("dag_root does not recompute over the stored refs+tags");
    }
  } else {
    // Never hash coerced values: a receipt whose dag_root was sealed over
    // String()-coerced non-strings must not be reported as recomputing.
    problems.push("dag_root not checked (non-string refs/tags cannot be hashed)");
  }
  if (!pyTruthy(receipt["audit_chain_link"])) {
    problems.push("audit_chain_link missing (keyed link is Core-verifiable only)");
  }
  return problems;
}

/**
 * The declared prior receipt refs that do NOT exist in `existing` — dangling /
 * fabricated links (S139 VULN-2). Order-preserving, deduplicated. Empty result
 * = every cited prior exists in the receipt set you hold.
 */
export function danglingPriorReceiptRefs(
  declared: Iterable<string>,
  existing: Iterable<string>,
): string[] {
  const existingSet = new Set(existing);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const d of declared) {
    if (existingSet.has(d) || seen.has(d)) continue;
    seen.add(d);
    out.push(d);
  }
  return out;
}

// 4-byte big-endian length prefix (unambiguous concatenation — ("a","bc")
// cannot collide with ("ab","c")). Length is the UTF-8 BYTE length; throws
// (RangeError) past u32 like Python's int.to_bytes(4) OverflowError.
function u32be(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}

function updateLenPrefixed(h: Hash, b: Buffer): void {
  h.update(u32be(b.length));
  h.update(b);
}

/**
 * The 32-byte fragment lineage root (domain `aegis-fragment-lineage.v1`).
 * Byte-for-byte with Core (`lineage::compute_lineage_root`), the Python SDK
 * (`receipt_verify.compute_lineage_root`) and the aegisbase reference
 * (`fragment_ledger.compute_lineage_root`).
 */
export function computeLineageRoot(
  fragmentTag: string,
  sourceKind: string,
  locator: string,
  fieldSet: readonly string[] = [],
  priorLineageRoots: readonly Uint8Array[] = [],
): Buffer {
  // JS trim() and Python str.strip() agree on all charset-relevant whitespace;
  // either way an all-whitespace tag is refused before hashing.
  if (!fragmentTag || !fragmentTag.trim()) {
    throw new Error("fragment_tag must be non-empty");
  }
  if (!isValueFreeLabel(fragmentTag)) {
    throw new Error("fragment_tag must be a value-free label ([A-Za-z0-9._:-], <=128)");
  }
  const roots = priorLineageRoots.map((r) => (Buffer.isBuffer(r) ? r : Buffer.from(r)));
  for (const r of roots) {
    if (r.length !== LINEAGE_ROOT_LEN) {
      throw new Error("each prior lineage_root must be 32 bytes");
    }
  }
  // Python dedupes `bytes` by VALUE; a JS Set compares Buffers by reference —
  // key on the (injective) hex encoding to get value semantics.
  const unique = new Set(roots.map((r) => r.toString("hex")));
  if (unique.size !== roots.length) {
    throw new Error("duplicate parent lineage_root (cite each parent once)");
  }
  const h = createHash("sha256");
  h.update(LINEAGE_DOMAIN);
  updateLenPrefixed(h, Buffer.from(fragmentTag, "utf8"));
  // canonical data_ref identity: kind, locator, sorted+deduped field NAMES.
  updateLenPrefixed(h, Buffer.from(sourceKind, "utf8"));
  updateLenPrefixed(h, Buffer.from(locator, "utf8"));
  // Field names are not charset-gated (matching Python/Core), so sort by code
  // point — see codePointCompare — to match Python's sorted() exactly.
  const fields = [...new Set(fieldSet)].sort(codePointCompare);
  h.update(u32be(fields.length));
  for (const f of fields) {
    updateLenPrefixed(h, Buffer.from(f, "utf8"));
  }
  // parent roots: count + raw bytes sorted lexicographically (Buffer.compare
  // is unsigned bytewise order, identical to Python's sorted() on bytes).
  h.update(u32be(roots.length));
  for (const r of [...roots].sort(Buffer.compare)) {
    h.update(r);
  }
  return h.digest();
}

/**
 * Forged-lineage guard: recompute over the RESOLVED parents and compare.
 * Throws on mismatch (fail-closed).
 */
export function verifyLineageRoot(
  fragmentTag: string,
  sourceKind: string,
  locator: string,
  fieldSet: readonly string[],
  resolvedParentRoots: readonly Uint8Array[],
  claimedRoot: Uint8Array,
): void {
  const expected = computeLineageRoot(
    fragmentTag,
    sourceKind,
    locator,
    fieldSet,
    resolvedParentRoots,
  );
  if (!expected.equals(claimedRoot)) {
    throw new Error("lineage_root does not match resolved parents (forged lineage)");
  }
}
