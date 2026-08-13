// Cross-SDK A2A privacy / verification / activation conformance — Node runner.
//
// Executes conformance/a2a_privacy.v0.json through the SHIPPED per-field
// validator, producer trust-assertion guard, consumer verification derivation,
// and per-principal delivery filter. The Python SDK runs the same corpus.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  A2APrivacyError,
  validateDecisionSubstate,
  type ProvenanceDeclaration,
} from "../src/a2a/privacy.js";
import {
  A2AVerificationError,
  assertNoProducerTrustAssertions,
  deriveVerificationStatus,
} from "../src/a2a/verification.js";
import {
  A2AActivationError,
  bindActivation,
  filterDecisionMetadataForDelivery,
  WITHHELD_STATUS,
  type ActivationBinding,
  type DeliveryQuery,
} from "../src/a2a/activation.js";
import { A2AMappingError } from "../src/a2a/mapping.js";

const corpus = JSON.parse(
  readFileSync(new URL("../../conformance/a2a_privacy.v0.json", import.meta.url), "utf8"),
) as {
  version: string;
  extension_uri: string;
  substate_validation: Array<{
    id: string;
    substate: unknown;
    provenance: ProvenanceDeclaration;
    expect_valid?: boolean;
    expect_error?: string;
    why: string;
  }>;
  producer_assertions: Array<{
    id: string;
    payload: unknown;
    expect_error?: string;
    expect_clean?: boolean;
    why: string;
  }>;
  verification_derivation: Array<{
    id: string;
    substate: unknown;
    provenance: ProvenanceDeclaration;
    receipt_structure: string;
    expect?: { status: string; basis: string[] };
    expect_error?: string;
    why: string;
  }>;
  delivery_filter: Array<{
    id: string;
    metadata: Record<string, unknown>;
    bindings: ActivationBinding[];
    query: DeliveryQuery;
    expect: { kind: "passthrough" | "withheld" | "unchanged_absent" };
    why: string;
  }>;
  activation_binding: Array<{
    id: string;
    existing: ActivationBinding[];
    bind: ActivationBinding;
    bind_again?: boolean;
    expect_count?: number;
    expect_error?: string;
    why: string;
  }>;
};

const URI = corpus.extension_uri;

describe("a2a privacy corpus (shared with the Python SDK)", () => {
  it("pins the corpus version", () => {
    expect(corpus.version).toBe("v0");
  });

  for (const v of corpus.substate_validation) {
    it(`substate ${v.id} — ${v.why}`, () => {
      if (v.expect_valid) {
        expect(() => validateDecisionSubstate(v.substate, v.provenance)).not.toThrow();
        return;
      }
      let thrown: unknown;
      try {
        validateDecisionSubstate(v.substate, v.provenance);
      } catch (err) {
        thrown = err;
      }
      // Pair-inventory failures surface as mapping errors; everything else as
      // privacy errors. Both are fail-closed refusals with stable codes.
      expect(
        thrown instanceof A2APrivacyError || thrown instanceof A2AMappingError,
      ).toBe(true);
      expect((thrown as A2APrivacyError).code).toBe(v.expect_error);
    });
  }

  for (const v of corpus.producer_assertions) {
    it(`producer assertion ${v.id} — ${v.why}`, () => {
      if (v.expect_clean) {
        expect(() => assertNoProducerTrustAssertions(v.payload, v.id)).not.toThrow();
        return;
      }
      let thrown: unknown;
      try {
        assertNoProducerTrustAssertions(v.payload, v.id);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(A2AVerificationError);
      expect((thrown as A2AVerificationError).code).toBe(v.expect_error);
    });
  }

  for (const v of corpus.verification_derivation) {
    it(`derivation ${v.id} — ${v.why}`, () => {
      if (v.expect_error !== undefined) {
        let thrown: unknown;
        try {
          deriveVerificationStatus({
            substate: v.substate,
            provenance: v.provenance,
            receipt_structure: v.receipt_structure as never,
          });
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(A2AVerificationError);
        expect((thrown as A2AVerificationError).code).toBe(v.expect_error);
        return;
      }
      const derived = deriveVerificationStatus({
        substate: v.substate,
        provenance: v.provenance,
        receipt_structure: v.receipt_structure as never,
      });
      const expected = v.expect as NonNullable<typeof v.expect>;
      expect(derived.status).toBe(expected.status);
      expect([...derived.basis]).toEqual(expected.basis);
      // The ceiling is part of the contract: what this does NOT establish is
      // always stated, and the status vocabulary has no issuer-authenticated
      // member for a keyless consumer to reach.
      expect(["unverified", "structure_verified"]).toContain(derived.status);
      expect([...derived.limits]).toEqual([
        "does_not_establish_issuer_identity",
        "does_not_establish_enforcement",
        "keyed_chain_verification_is_core_territory",
      ]);
    });
  }

  for (const v of corpus.delivery_filter) {
    it(`delivery ${v.id} — ${v.why}`, () => {
      const before = JSON.parse(JSON.stringify(v.metadata)) as Record<string, unknown>;
      const filtered = filterDecisionMetadataForDelivery(v.metadata, v.bindings, v.query);
      // Never mutates the caller's object.
      expect(v.metadata).toEqual(before);
      if (v.expect.kind === "passthrough") {
        expect(filtered).toEqual(v.metadata);
        return;
      }
      if (v.expect.kind === "unchanged_absent") {
        expect(filtered).toEqual(v.metadata);
        expect(Object.keys(filtered)).not.toContain(URI);
        return;
      }
      // withheld: the key survives (distinguishable from never-reported), the
      // content does not.
      expect(Object.keys(filtered)).toContain(URI);
      const marker = filtered[URI] as Record<string, unknown>;
      expect(Object.keys(marker).sort()).toEqual(["reason", "status", "version"]);
      expect(marker.status).toBe(WITHHELD_STATUS);
      for (const banned of ["outcome", "reason_code", "withheld_fields", "approver"]) {
        expect(marker).not.toHaveProperty(banned);
      }
      // Unrelated metadata is untouched.
      for (const [k, val] of Object.entries(v.metadata)) {
        if (k !== URI) expect(filtered[k]).toEqual(val);
      }
    });
  }

  for (const v of corpus.activation_binding) {
    it(`binding ${v.id} — ${v.why}`, () => {
      if (v.expect_error !== undefined) {
        let thrown: unknown;
        try {
          bindActivation(v.existing, v.bind);
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(A2AActivationError);
        expect((thrown as A2AActivationError).code).toBe(v.expect_error);
        return;
      }
      let bindings = bindActivation(v.existing, v.bind);
      if (v.bind_again) bindings = bindActivation(bindings, v.bind);
      expect(bindings.length).toBe(v.expect_count);
    });
  }
});
