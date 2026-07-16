// Keyless receipt verifier — cross-impl pinned vectors + structure checks.
// Parity with python/tests/test_receipt_verify.py.
//
// The hex vectors below are PINNED on all sides: Aegis Core pins the same
// values in `boundary_adapter::tests::session_dag_root_cross_impl_pinned_vectors`
// and `lineage::tests` (aegis-boundary-core), the Python SDK in
// test_receipt_verify.py. A change on any side that breaks these is a
// coordinated wire-schema change, not a refactor.

import { describe, expect, it } from "vitest";

import {
  SPAN_CRYPTO_SCHEMA_TAG,
  computeLineageRoot,
  danglingPriorReceiptRefs,
  sessionDagRoot,
  verifyLineageRoot,
  verifySessionReceiptStructure,
} from "../src/receiptVerify.js";

function receipt(): Record<string, unknown> {
  const refs = ["ev-1", "ev-2"];
  const tags = ["sensitive:Finance", "sensitive:Patent"];
  return {
    schema: SPAN_CRYPTO_SCHEMA_TAG,
    session_id: "s1",
    event_receipt_refs: refs,
    fragment_tags: tags,
    dag_root: sessionDagRoot(refs, tags),
    audit_chain_link: "ab".repeat(32),
  };
}

describe("receiptVerify.ts — keyless verifier parity with Python", () => {
  it("session_dag_root cross-impl pinned vectors", () => {
    expect(sessionDagRoot([], [])).toBe(
      "00c3c8b5599715ad4288d8d4a1b3bfe6e4f92e6ba0b26bc1fc7fb650ae08e973",
    );
    expect(
      sessionDagRoot(["ev-1", "ev-2"], ["sensitive:Finance", "sensitive:Patent"]),
    ).toBe("a44775d7432f7d21231e3410af0ca72a8dcad00d187f02aeb5539eddb6ca0dab");
  });

  it("structurally sound receipt has no problems", () => {
    expect(verifySessionReceiptStructure(receipt())).toEqual([]);
  });

  it("tampered receipt is detected", () => {
    const r = receipt();
    r.fragment_tags = ["sensitive:Finance"]; // tag stripped after sealing
    const problems = verifySessionReceiptStructure(r);
    expect(problems.some((p) => p.includes("dag_root"))).toBe(true);

    const r2 = receipt();
    r2.schema = "aegis-span-crypto.v999";
    expect(verifySessionReceiptStructure(r2).some((p) => p.includes("schema"))).toBe(true);

    const r3 = receipt();
    r3.fragment_tags = ["自己資金は1200万円"]; // value smuggled into a tag
    expect(
      verifySessionReceiptStructure(r3).some((p) => p.includes("value-free")),
    ).toBe(true);
  });

  it("dangling prior refs detected", () => {
    const existing = new Set(["ev-1", "ev-2"]);
    expect(danglingPriorReceiptRefs(["ev-2", "ev-9", "ev-9", "ev-8"], existing)).toEqual([
      "ev-9",
      "ev-8",
    ]);
    expect(danglingPriorReceiptRefs(["ev-1"], existing)).toEqual([]);
  });

  it("lineage_root cross-impl pinned vectors", () => {
    // Same vectors pinned in Core lineage::tests (Python aegisbase oracle).
    const r1 = computeLineageRoot("crm:customer", "file", "doc-123", ["name", "addr"]);
    expect(r1.toString("hex")).toBe(
      "9d36c954ae2595be57ff3e1c07090212bc1c3a20cb8a27bcce82a1940edabb97",
    );
    const r2 = computeLineageRoot("crm:contract_value", "file", "doc-456", ["amount"], [r1]);
    expect(r2.toString("hex")).toBe(
      "404ec0c907d7dc2cc463f159f744e017bd1cca9e3aaaab6a894907dbcc8877f3",
    );
    const ra = computeLineageRoot("t.x", "s", "l", ["b", "a", "a"], [r1, r2].sort(Buffer.compare));
    const rb = computeLineageRoot("t.x", "s", "l", ["a", "b"], [r2, r1]);
    expect(ra.equals(rb)).toBe(true);
    expect(ra.toString("hex")).toBe(
      "5b93afcd12a957a54306e356d406d4790808c55a0541f68f9853710e451e0223",
    );
  });

  it("forged lineage fails closed", () => {
    const parent = computeLineageRoot("a", "file", "doc-1", ["name"]);
    const good = computeLineageRoot("b", "file", "doc-1", ["name"], [parent]);
    verifyLineageRoot("b", "file", "doc-1", ["name"], [parent], good); // ok
    expect(() => verifyLineageRoot("b", "file", "doc-1", ["name"], [], good)).toThrow(
      "lineage_root does not match resolved parents (forged lineage)",
    );
    expect(() => computeLineageRoot("has space", "s", "l")).toThrow(
      "fragment_tag must be a value-free label ([A-Za-z0-9._:-], <=128)",
    );
  });
});

describe("verifySessionReceiptStructure hostile input (S022 hardening)", () => {
  it("reports non-string members instead of throwing (Python parity)", () => {
    const problems = verifySessionReceiptStructure({
      schema: SPAN_CRYPTO_SCHEMA_TAG,
      event_receipt_refs: [1, "a"], // mixed unorderable
      fragment_tags: [42],
      dag_root: "0".repeat(64),
      audit_chain_link: "deadbeef",
    });
    expect(problems).toContain("event_receipt_refs contain non-string members");
    expect(problems).toContain("fragment_tags contain non-string members");
    expect(problems).toContain("fragment_tag 42 is not a value-free label");
    expect(problems).toContain(
      "dag_root not checked (non-string refs/tags cannot be hashed)",
    );
  });

  it("still verifies a well-formed receipt clean", () => {
    const refs = ["r1", "r2"];
    const tags = ["billing"];
    expect(
      verifySessionReceiptStructure({
        schema: SPAN_CRYPTO_SCHEMA_TAG,
        event_receipt_refs: refs,
        fragment_tags: tags,
        dag_root: sessionDagRoot(refs, tags),
        audit_chain_link: "deadbeef",
      }),
    ).toEqual([]);
  });
});
