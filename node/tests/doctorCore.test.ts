import { describe, expect, it } from "vitest";

import { AegisClient, type BoundaryDecisionView } from "../src/index.js";
import {
  BoundaryOutcome,
  checkWithCore,
  scopeForShield,
  type ActionPlan,
} from "../src/doctor/index.js";

function plan(overrides: Partial<ActionPlan> = {}): ActionPlan {
  return {
    purpose: "customer_support",
    actionType: "generate_draft",
    dataRequested: ["name", "issue", "email"],
    destinations: ["internal_reply"],
    ...overrides,
  };
}

// A fake client that returns a fixed view, throws, or returns malformed data.
function fakeClient(
  impl: () => Promise<BoundaryDecisionView>,
): AegisClient {
  const c = new AegisClient({ baseUrl: "https://localhost:8443/api/v1" });
  // Override the only method checkWithCore calls.
  (c as unknown as { checkBoundary: () => Promise<BoundaryDecisionView> }).checkBoundary = impl;
  return c;
}

function view(overrides: Partial<BoundaryDecisionView>): BoundaryDecisionView {
  return {
    source: "CORE",
    outcome: "PROTECTED",
    purpose_label: "customer_support",
    allowed_fields: ["name", "issue"],
    withheld_fields: [],
    reason_code: "minimum_disclosure",
    reason_label: "Minimum disclosure",
    evidence_available: true,
    evidence: {
      decision_id: "hashchain:0000042",
      policy: "customer_support.minimum_disclosure",
      enforced_by: "Aegis Core",
      integrity_checkable_at: "/api/v1/audit/integrity",
      recorded_at: "2026-06-05T00:00:00Z",
    },
    ...overrides,
  };
}

describe("doctor.checkWithCore (v1) — outcome mapping", () => {
  it("PROTECTED → ALLOW", async () => {
    const client = fakeClient(async () =>
      view({ outcome: "PROTECTED", allowed_fields: ["name", "issue"], withheld_fields: [] }),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.ALLOW);
    expect(d.allowedData).toEqual(["name", "issue"]);
    expect(d.policyVersion).toBe("core-v1");
    expect(d.reasonCodes).toContain("minimum_disclosure");
  });

  it("ACCESS_REDUCED → REDUCE_SCOPE", async () => {
    const client = fakeClient(async () =>
      view({ outcome: "ACCESS_REDUCED", allowed_fields: ["name"], withheld_fields: ["email"] }),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.REDUCE_SCOPE);
    expect(d.allowedData).toEqual(["name"]);
    expect(d.blockedData).toEqual(["email"]);
  });

  it("CHECK_REQUIRED → REQUIRE_CHECK", async () => {
    const client = fakeClient(async () => view({ outcome: "CHECK_REQUIRED" }));
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.REQUIRE_CHECK);
  });

  it("APPROVAL_REQUIRED → REQUIRE_APPROVAL (carries actionType)", async () => {
    const client = fakeClient(async () => view({ outcome: "APPROVAL_REQUIRED" }));
    const d = await checkWithCore(plan({ actionType: "send" }), { client });
    expect(d.outcome).toBe(BoundaryOutcome.REQUIRE_APPROVAL);
    expect(d.approvalRequiredFor).toEqual(["send"]);
  });

  it("BLOCKED → BLOCK", async () => {
    const client = fakeClient(async () =>
      view({ outcome: "BLOCKED", allowed_fields: [], withheld_fields: ["ssn"] }),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.allowedData).toEqual([]);
  });
});

describe("doctor.checkWithCore (v1) — fail-closed", () => {
  it("network error → BLOCK with empty allowedData", async () => {
    const client = fakeClient(async () => {
      throw new Error("ECONNREFUSED");
    });
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.allowedData).toEqual([]);
    expect(d.reasonCodes).toContain("CORE_UNAVAILABLE");
  });

  it("non-200 (httpError thrown by checkBoundary) → BLOCK with empty allowedData", async () => {
    // The real client throws httpError on non-2xx; simulate that here.
    const client = fakeClient(async () => {
      throw Object.assign(new Error("check-boundary HTTP 503"), { code: "aegis.http.nonOk" });
    });
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.allowedData).toEqual([]);
    expect(d.reasonCodes).toContain("CORE_UNAVAILABLE");
  });

  it("malformed body (no outcome) → BLOCK with empty allowedData", async () => {
    const client = fakeClient(async () => ({ source: "CORE" } as unknown as BoundaryDecisionView));
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.allowedData).toEqual([]);
    expect(d.reasonCodes).toContain("CORE_MALFORMED_RESPONSE");
  });

  it("malformed body (unknown outcome) → BLOCK", async () => {
    const client = fakeClient(async () =>
      ({ outcome: "MAYBE" } as unknown as BoundaryDecisionView),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.reasonCodes).toContain("CORE_MALFORMED_RESPONSE");
  });

  // Finding A: a partial-but-valid-JSON body must NOT map to ALLOW.
  it("partial body { outcome: PROTECTED } only → BLOCK (not ALLOW)", async () => {
    const client = fakeClient(async () =>
      ({ outcome: "PROTECTED" } as unknown as BoundaryDecisionView),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.allowedData).toEqual([]);
    expect(d.reasonCodes).toContain("CORE_MALFORMED_RESPONSE");
  });

  // Finding A: missing reason_code (otherwise full) → BLOCK.
  it("body missing reason_code → BLOCK", async () => {
    const bad = view({});
    delete (bad as unknown as Record<string, unknown>).reason_code;
    const client = fakeClient(async () => bad);
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.reasonCodes).toContain("CORE_MALFORMED_RESPONSE");
  });

  // Finding C: prototype-pollution — inherited keys must not be valid outcomes.
  it("prototype-pollution { outcome: 'toString' } → BLOCK", async () => {
    const client = fakeClient(async () =>
      ({
        source: "CORE",
        outcome: "toString",
        purpose_label: "p",
        allowed_fields: [],
        withheld_fields: [],
        reason_code: "x",
      } as unknown as BoundaryDecisionView),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.reasonCodes).toContain("CORE_MALFORMED_RESPONSE");
  });

  // Finding D: a BLOCKED outcome with non-empty allowed_fields must clear the
  // allow set (non-grant outcomes never carry an allow set).
  it("BLOCKED + non-empty allowed_fields → allowedData empty", async () => {
    const client = fakeClient(async () =>
      view({ outcome: "BLOCKED", allowed_fields: ["name", "ssn"], withheld_fields: ["ssn"] }),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.allowedData).toEqual([]);
    expect(scopeForShield(d)).toEqual([]);
  });

  // Finding D: REQUIRE_CHECK / REQUIRE_APPROVAL also clear the allow set.
  it("CHECK_REQUIRED + non-empty allowed_fields → allowedData empty", async () => {
    const client = fakeClient(async () =>
      view({ outcome: "CHECK_REQUIRED", allowed_fields: ["name"] }),
    );
    const d = await checkWithCore(plan(), { client });
    expect(d.outcome).toBe(BoundaryOutcome.REQUIRE_CHECK);
    expect(d.allowedData).toEqual([]);
  });

  // Finding E/G: a mapping error (e.g. plan.tools tampered to a non-iterable)
  // must BLOCK, not escape as a raw throw.
  it("mapping error (bad plan) → BLOCK", async () => {
    const client = fakeClient(async () => view({}));
    const badPlan = plan();
    // Force plan.tools to a non-iterable to make mapView throw on spread.
    (badPlan as unknown as Record<string, unknown>).tools = 5;
    const d = await checkWithCore(badPlan, { client });
    expect(d.outcome).toBe(BoundaryOutcome.BLOCK);
    expect(d.reasonCodes).toContain("CORE_UNAVAILABLE");
  });
});

describe("doctor.checkWithCore (v1) — destination fail-closed (finding F)", () => {
  it("single destination is sent as-is", async () => {
    let captured: Record<string, unknown> | null = null;
    const client = fakeClient(async () => view({}));
    (client as unknown as { checkBoundary: (a: Record<string, unknown>) => Promise<BoundaryDecisionView> })
      .checkBoundary = async (a) => {
      captured = a;
      return view({});
    };
    await checkWithCore(plan({ destinations: ["internal_reply"] }), { client });
    expect(captured!.destination).toBe("internal_reply");
  });

  it("multiple destinations → most-restrictive sentinel (never the first)", async () => {
    let captured: Record<string, unknown> | null = null;
    const client = fakeClient(async () => view({}));
    (client as unknown as { checkBoundary: (a: Record<string, unknown>) => Promise<BoundaryDecisionView> })
      .checkBoundary = async (a) => {
      captured = a;
      return view({});
    };
    await checkWithCore(
      plan({ destinations: ["internal_reply", "external_llm"] }),
      { client },
    );
    expect(captured!.destination).toBe("__aegis_multi_external__");
    expect(captured!.destination).not.toBe("internal_reply");
  });
});

describe("doctor.checkWithCore (v1) — scopeForShield coupling", () => {
  it("ALLOW result yields the allowed fields", async () => {
    const client = fakeClient(async () =>
      view({ outcome: "PROTECTED", allowed_fields: ["name", "issue"], withheld_fields: [] }),
    );
    const d = await checkWithCore(plan(), { client });
    expect(scopeForShield(d)).toEqual(["name", "issue"]);
  });

  it("REDUCE_SCOPE result yields only the allowed fields", async () => {
    const client = fakeClient(async () =>
      view({ outcome: "ACCESS_REDUCED", allowed_fields: ["name"], withheld_fields: ["email"] }),
    );
    const d = await checkWithCore(plan(), { client });
    expect(scopeForShield(d)).toEqual(["name"]);
  });

  it("BLOCK result yields nothing (gate not cleared)", async () => {
    const client = fakeClient(async () => view({ outcome: "BLOCKED", allowed_fields: [] }));
    const d = await checkWithCore(plan(), { client });
    expect(scopeForShield(d)).toEqual([]);
  });
});

describe("doctor.checkWithCore (v1) — request shaping", () => {
  it("sends scope as an array, omits principal, maps agentId/destination", async () => {
    let captured: Record<string, unknown> | null = null;
    const client = fakeClient(async () => view({}));
    (client as unknown as { checkBoundary: (a: Record<string, unknown>) => Promise<BoundaryDecisionView> })
      .checkBoundary = async (a) => {
      captured = a;
      return view({});
    };
    await checkWithCore(
      plan({ dataRequested: ["name", "issue"], destinations: ["external_llm"], agentId: "agent-7" }),
      { client },
    );
    expect(captured).not.toBeNull();
    expect(captured!.scope).toEqual(["name", "issue"]);
    expect(captured!.destination).toBe("external_llm");
    expect(captured!.agentId).toBe("agent-7");
    expect(captured!.principal).toBeUndefined();
  });
});
