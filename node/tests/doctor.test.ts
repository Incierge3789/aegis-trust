import { describe, expect, it } from "vitest";

import { shield } from "../src/index.js";
import {
  DOCTOR_SCHEMA_VERSION,
  BoundaryOutcome,
  check,
  scopeForShield,
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
    // strictUnknownPurpose:false opts into the permissive-unknown path so this
    // exercises the sensitive-strip seam (see the strict variant below).
    const permissive: LocalPolicy = { ...POLICY, strictUnknownPurpose: false };
    const d = check(
      {
        purpose: "unlisted",
        actionType: "generate_draft",
        dataRequested: ["name", "email", "card_number"],
        destinations: ["external_llm"],
      },
      permissive,
    );
    expect(d.outcome).toBe(BoundaryOutcome.REDUCE_SCOPE);
    expect(d.allowedData).toEqual(["name"]);
    expect(d.reasonCodes).toContain("EXTERNAL_DESTINATION_MINIMUM_DISCLOSURE");
  });

  it("unknown purpose fails closed by default (cannot disable the whitelist)", () => {
    const d = check(
      plan({ purpose: "support_v2", dataRequested: ["name", "ssn_alias", "card"] }),
      POLICY,
    );
    expect(d.allowedData).toEqual([]);
    expect(d.outcome).toBe(BoundaryOutcome.REDUCE_SCOPE);
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

// Regression suite for the doctor→shield fail-open class (S-redteam). Each case
// is a confirmed bypass that must now fail closed end-to-end (parity with the
// Python TestTrustBoundaryHardening suite).
describe("doctor.check — trust-boundary hardening (S-redteam regressions)", () => {
  const emit = (scope: string[], record: unknown) =>
    shield({ purpose: "p", scope })(() => record)();
  const p = (o: Partial<ActionPlan>): ActionPlan => ({
    purpose: "p",
    actionType: "read",
    dataRequested: [],
    destinations: [],
    ...o,
  });

  it("F1: dot-notation does not escape the never block", () => {
    const d = check(p({ dataRequested: ["profile.ssn"] }), { neverFields: ["ssn"] });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(scopeForShield(d)).toEqual([]);
  });

  it("F2: a bare parent scope does not leak a nested secret (shield fail-closed)", () => {
    expect(emit(["config"], { config: { api_key: "SECRET" } })).toEqual({});
  });

  it("F3: an unknown destination is treated as external", () => {
    const d = check(p({ actionType: "send", dataRequested: ["ssn"], destinations: ["evilcorp"] }), {
      sensitiveFields: ["ssn"],
      externalDestinations: ["external_llm"],
    });
    expect(scopeForShield(d)).toEqual([]);
  });

  it("F7: the deny blacklist is path-aware", () => {
    const d = check(p({ dataRequested: ["profile.ssn"] }), {
      purposes: { p: { deny: ["ssn"] } },
    });
    expect(scopeForShield(d)).toEqual([]);
  });

  it("F9: casing cannot dodge never", () => {
    const d = check(p({ dataRequested: ["SSN"] }), { neverFields: ["ssn"] });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
  });

  it("A1: a parent named in never blocks a child-path request", () => {
    const d = check(p({ dataRequested: ["config.api_key"] }), { neverFields: ["config"] });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
  });

  it("A2: an approval decision yields no enforceable scope", () => {
    const d = check(p({ actionType: "send", dataRequested: ["ssn", "name"] }), {
      actions: { send: { requiresApproval: true } },
    });
    expect(d.outcome).toBe(BoundaryOutcome.REQUIRE_APPROVAL);
    expect(d.allowedData).toEqual(["ssn", "name"]); // diagnostic still populated
    expect(scopeForShield(d)).toEqual([]); // but nothing flows pre-approval
    expect(emit(scopeForShield(d), { ssn: "S", name: "n" })).toEqual({});
  });

  it("F12: a malformed path fails closed at the gate", () => {
    const d = check(p({ dataRequested: ["a..b"] }), {});
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.reasonCodes).toContain("MALFORMED_FIELD_PATH");
  });

  it("CX1: a bare leaf over a Map fails closed (Map is a key→value container)", () => {
    // codex cross-review: a JS Map slipped past both isRecordLike and
    // isTraversable, leaking the whole Map through a bare leaf scope.
    const out = shield({ purpose: "p", scope: ["config"] })(() => ({
      config: new Map([["api_key", "SECRET"]]),
    }))();
    expect((out as { config?: unknown }).config).toBeUndefined();
  });

  it("CX2: NFKC folds a full-width field name onto its ASCII guard", () => {
    // codex cross-review: NFC left full-width 'ＳＳＮ' distinct from 'ssn'.
    const d = check(p({ dataRequested: ["ＳＳＮ"] }), { neverFields: ["ssn"] });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
  });

  it("CX3: a prototype-chain purpose cannot dodge the unknown-purpose guard", () => {
    // post-fix sweep: purpose '__proto__' resolved policy.purposes['__proto__']
    // to Object.prototype (truthy) → treated as a rule-less known purpose →
    // ALLOW everything. Own-property lookup now fails it closed.
    for (const purpose of ["__proto__", "constructor", "toString"]) {
      const d = check(p({ purpose, dataRequested: ["name", "ssn", "card"] }), {
        purposes: { support: { allow: ["name"] } },
      });
      expect(scopeForShield(d)).toEqual([]);
    }
  });

  it("F1: the allow-list matches exactly (no normalization confused-deputy)", () => {
    // Red-team F-1: allow=["name"] must not loosely authorize "NAME" / "Name" —
    // that would emit the attacker's token and disclose a distinct field.
    const pol: LocalPolicy = { purposes: { p: { allow: ["name"] } } };
    for (const variant of ["NAME", "Name", "ＮＡＭＥ"]) {
      const d = check(p({ dataRequested: [variant] }), pol);
      expect(scopeForShield(d)).toEqual([]);
      const out = shield({ purpose: "p", scope: scopeForShield(d) })(() => ({
        name: "ok",
        [variant]: "SECRET",
      }))();
      expect(out).toEqual({});
    }
    // legitimate exact + descendant still authorized
    const ok = check(p({ dataRequested: ["name"] }), pol);
    expect(scopeForShield(ok)).toEqual(["name"]);
    const desc = check(p({ dataRequested: ["name.first"] }), pol);
    expect(scopeForShield(desc)).toEqual(["name.first"]);
  });

  it("F2: internal-destination match is exact (no normalization confused-deputy)", () => {
    // Same class as F-1 on the destination side: a variant label must not fold
    // onto the trusted internal sink and skip the sensitive strip.
    const pol: LocalPolicy = {
      sensitiveFields: ["ssn"],
      internalDestinations: ["internal_sink"],
    };
    for (const variant of ["INTERNAL_SINK", "Internal_Sink", "ｉｎｔｅｒｎａｌ＿ｓｉｎｋ"]) {
      const d = check(
        p({ actionType: "send", dataRequested: ["ssn"], destinations: [variant] }),
        pol,
      );
      expect(scopeForShield(d)).toEqual([]); // variant → external → stripped
    }
    const okd = check(
      p({ actionType: "send", dataRequested: ["ssn"], destinations: ["internal_sink"] }),
      pol,
    );
    expect(scopeForShield(okd)).toEqual(["ssn"]); // exact internal → kept
  });
});
