import { describe, expect, it } from "vitest";

import {
  BoundaryOutcome,
  type BoundaryDecision,
  toCoreVerifiedReceipt,
  toReceipt,
} from "../src/doctor/index.js";

function decision(): BoundaryDecision {
  return {
    outcome: BoundaryOutcome.ALLOW,
    purpose: "draft_reply",
    allowedData: ["name"],
    blockedData: ["email_body"],
    allowedTools: [],
    approvalRequiredFor: [],
    reasonCodes: [],
    policyVersion: "core-v1",
    receiptRequired: false,
    schemaVersion: 1,
  };
}

const goodEvidence = {
  decision_id: "dec-123",
  enforced_by: "Aegis Core",
  integrity_checkable_at: "https://core/evidence/dec-123",
  recorded_at: "2026-06-22T00:00:00Z",
};

describe("toCoreVerifiedReceipt — §7 contract-pin: coreVerified only from Core Evidence", () => {
  it("VERIFIED: real Core evidence → coreVerified=true, evidenceMode=core, linkage carried", () => {
    const r = toCoreVerifiedReceipt(decision(), goodEvidence, { receiptId: "r1" });
    expect(r.coreVerified).toBe(true);
    expect(r.evidenceMode).toBe("core");
    expect(r.coreEvidence?.decisionId).toBe("dec-123");
    expect(r.coreEvidence?.integrityCheckableAt).toBe("https://core/evidence/dec-123");
  });

  it("FAIL-CLOSED: no evidence (null) → LITE-local, coreVerified=false", () => {
    const r = toCoreVerifiedReceipt(decision(), null, { receiptId: "r2" });
    expect(r.coreVerified).toBe(false);
    expect(r.evidenceMode).toBe("local");
    expect(r.coreEvidence).toBeNull();
  });

  it("FAIL-CLOSED: evidence missing decision_id → false (cannot self-assert)", () => {
    const r = toCoreVerifiedReceipt(decision(), { ...goodEvidence, decision_id: "" }, { receiptId: "r3" });
    expect(r.coreVerified).toBe(false);
    expect(r.coreEvidence).toBeNull();
  });

  it("FAIL-CLOSED: evidence missing integrity_checkable_at → false (not checkable)", () => {
    const r = toCoreVerifiedReceipt(decision(), { ...goodEvidence, integrity_checkable_at: undefined }, { receiptId: "r4" });
    expect(r.coreVerified).toBe(false);
    expect(r.coreEvidence).toBeNull();
  });

  it("LITE unchanged: toReceipt stays coreVerified=false, coreEvidence=null", () => {
    const r = toReceipt(decision(), { receiptId: "r5" });
    expect(r.coreVerified).toBe(false);
    expect(r.coreEvidence).toBeNull();
    expect(r.evidenceMode).toBe("local");
  });
});

import { checkWithCoreReceipt } from "../src/doctor/index.js";
import type { ActionPlan } from "../src/doctor/index.js";
import type { AegisClient, BoundaryDecisionView } from "../src/index.js";

function viewWithEvidence(withEvidence: boolean): BoundaryDecisionView {
  return {
    source: "CORE",
    outcome: "PROTECTED",
    purpose_label: "draft_reply",
    allowed_fields: ["name"],
    withheld_fields: ["email_body"],
    reason_code: "ok",
    reason_label: "ok",
    evidence_available: withEvidence,
    evidence: withEvidence
      ? {
          decision_id: "core-dec-1",
          policy: "p",
          enforced_by: "Aegis Core",
          integrity_checkable_at: "https://core/evidence/core-dec-1",
          recorded_at: "2026-06-22T00:00:00Z",
        }
      : null,
  };
}

function stubClient(view: BoundaryDecisionView | "throw"): AegisClient {
  return {
    checkBoundary: async () => {
      if (view === "throw") throw new Error("network");
      return view;
    },
  } as unknown as AegisClient;
}

const aPlan: ActionPlan = {
  purpose: "draft_reply",
  dataRequested: ["name"],
  destinations: [],
} as unknown as ActionPlan;

describe("checkWithCoreReceipt — coreVerified bound to a real Core round-trip (§7 P1)", () => {
  it("VERIFIED: Core response carries evidence → receipt.coreVerified=true", async () => {
    const { receipt } = await checkWithCoreReceipt(aPlan, {
      client: stubClient(viewWithEvidence(true)),
      receiptId: "rc1",
    });
    expect(receipt.coreVerified).toBe(true);
    expect(receipt.coreEvidence?.decisionId).toBe("core-dec-1");
  });

  it("FAIL-CLOSED: Core response without evidence → coreVerified=false (no fabrication)", async () => {
    const { receipt } = await checkWithCoreReceipt(aPlan, {
      client: stubClient(viewWithEvidence(false)),
      receiptId: "rc2",
    });
    expect(receipt.coreVerified).toBe(false);
    expect(receipt.coreEvidence).toBeNull();
  });

  it("FAIL-CLOSED: network error → BLOCK decision + LITE receipt", async () => {
    const { decision, receipt } = await checkWithCoreReceipt(aPlan, {
      client: stubClient("throw"),
      receiptId: "rc3",
    });
    expect(decision.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(receipt.coreVerified).toBe(false);
  });
});
