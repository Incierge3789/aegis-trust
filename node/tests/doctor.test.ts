import { describe, expect, it } from "vitest";

import { shield } from "../src/index.js";
import {
  DOCTOR_SCHEMA_VERSION,
  BoundaryOutcome,
  check,
  toReceipt,
  type ActionPlan,
  type LocalPolicy,
} from "../src/doctor/index.js";

const POLICY: LocalPolicy = {
  purposes: { customer_support: { allow: ["name", "issue"] } },
  sensitiveFields: ["email", "card_number"],
  neverFields: ["password", "ssn", ".env"],
  externalDestinations: ["external_llm"],
  actions: { send: { requiresApproval: true } },
};

function plan(overrides: Partial<ActionPlan> = {}): ActionPlan {
  return {
    purpose: "customer_support",
    actionType: "generate_draft",
    dataRequested: ["name", "issue"],
    destinations: ["internal_reply"],
    ...overrides,
  };
}

describe("doctor.check (v0)", () => {
  it("ALLOW when request matches the purpose", () => {
    const d = check(plan({ dataRequested: ["name", "issue"] }), POLICY);
    expect(d.outcome).toBe(BoundaryOutcome.ALLOW);
    expect(d.allowedData).toEqual(["name", "issue"]);
    expect(d.blockedData).toEqual([]);
  });

  it("REDUCE_SCOPE drops fields not needed for the purpose", () => {
    const d = check(plan({ dataRequested: ["name", "issue", "email", "card_number"] }), POLICY);
    expect(d.outcome).toBe(BoundaryOutcome.REDUCE_SCOPE);
    expect(d.allowedData).toEqual(["name", "issue"]);
    expect([...d.blockedData].sort()).toEqual(["card_number", "email"]);
    expect(d.reasonCodes).toContain("DATA_NOT_REQUIRED_FOR_PURPOSE");
  });

  it("external destination strips sensitive fields even without a purpose rule", () => {
    const d = check(
      {
        purpose: "unlisted",
        actionType: "generate_draft",
        dataRequested: ["name", "email", "card_number"],
        destinations: ["external_llm"],
      },
      POLICY,
    );
    expect(d.outcome).toBe(BoundaryOutcome.REDUCE_SCOPE);
    expect(d.allowedData).toEqual(["name"]);
    expect(d.reasonCodes).toContain("EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE");
  });

  it("REQUIRE_APPROVAL for an approval-gated action", () => {
    const d = check(plan({ actionType: "send", dataRequested: ["name", "issue"] }), POLICY);
    expect(d.outcome).toBe(BoundaryOutcome.REQUIRE_APPROVAL);
    expect(d.approvalRequiredFor).toEqual(["send"]);
    expect(d.reasonCodes).toContain("ACTION_REQUIRES_HUMAN_APPROVAL");
  });

  it("BLOCK (fail-closed) when a forbidden field is requested", () => {
    const d = check(plan({ dataRequested: ["name", "password"] }), POLICY);
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.allowedData).toEqual([]);
    expect(d.reasonCodes).toContain("FORBIDDEN_FIELD_REQUESTED");
  });

  it("decision feeds shield end-to-end", async () => {
    const p = plan({
      dataRequested: ["name", "issue", "email", "card_number"],
      destinations: ["external_llm"],
    });
    const decision = check(p, POLICY);
    const getCustomer = shield({ purpose: p.purpose, scope: [...decision.allowedData] })(() => ({
      name: "Tanaka",
      issue: "Login",
      email: "t@example.com",
      card_number: "4242",
    }));
    const out = (await getCustomer()) as Record<string, unknown>;
    expect(out).toEqual({ name: "Tanaka", issue: "Login" });
    expect(out).not.toHaveProperty("email");
    expect(out).not.toHaveProperty("card_number");
  });

  it("empty policy is permissive but deterministic", () => {
    const d = check(plan({ dataRequested: ["name", "issue", "email"] }));
    expect(d.outcome).toBe(BoundaryOutcome.ALLOW);
    expect(d.allowedData).toEqual(["name", "issue", "email"]);
  });

  it("contracts carry schemaVersion; toReceipt is local + unverified", () => {
    const d = check(plan(), POLICY);
    expect(d.schemaVersion).toBe(DOCTOR_SCHEMA_VERSION);
    const r = toReceipt(d, { receiptId: "br_001" });
    expect(r.schemaVersion).toBe(DOCTOR_SCHEMA_VERSION);
    expect(r.evidenceMode).toBe("local");
    expect(r.coreVerified).toBe(false);
  });
});
