// Cross-SDK A2A reducer conformance — Node runner.
//
// Executes conformance/a2a_reducer.v0.json through the SHIPPED reducer and
// authorization-request builder. The Python SDK runs the same corpus through
// its shipped equivalents. Obligations are compared as
// (correlation_id, generation, state) sets; rejected events as ordered
// (index, code) lists.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  A2AReducerError,
  buildAuthorizationRequest,
  buildObligationStatusUpdate,
  reduceTaskState,
  type A2ATaskEvent,
  type Obligation,
  type ObligationKey,
  type ObligationState,
  type TaskReductionInput,
} from "../src/a2a/reducer.js";
import { assertNoEnforcementClaim } from "../src/a2a/extension.js";
import { validateDecisionSubstate } from "../src/a2a/privacy.js";

interface TraceVector {
  id: string;
  permutation_of?: string;
  task_id: string;
  context_id: string;
  prior_state?: string;
  prior_obligations?: Array<{ key: ObligationKey; state: string }>;
  prior_unresolved_halt?: boolean;
  events: unknown[];
  expect: {
    task_state: string | null;
    obligations: Array<{ correlation_id: string; generation: number; state: string }>;
    rejected: Array<{ index: number; code: string }>;
    unresolved_halt?: boolean;
  };
  why: string;
}

const corpus = JSON.parse(
  readFileSync(new URL("../../conformance/a2a_reducer.v0.json", import.meta.url), "utf8"),
) as {
  version: string;
  traces: TraceVector[];
  input_errors: Array<{
    id: string;
    input: Record<string, unknown>;
    expect_error: string;
    why: string;
  }>;
  authorization_request: Array<{
    id: string;
    key: ObligationKey;
    approver_role: string;
    approver_roles: string[];
    expect?: {
      task_state: string;
      substate: Record<string, unknown>;
      message_contains: string[];
      message_and_substate_omit?: string[];
    };
    expect_error?: string;
    why: string;
  }>;
  obligation_status_update: Array<{
    id: string;
    key: ObligationKey;
    status: string;
    expect?: { substate: Record<string, unknown>; omit: string[] };
    expect_error?: string;
    why: string;
  }>;
};

function runTrace(v: TraceVector) {
  return reduceTaskState({
    task_id: v.task_id,
    context_id: v.context_id,
    prior_state: v.prior_state,
    prior_obligations: v.prior_obligations,
    prior_unresolved_halt: v.prior_unresolved_halt,
    events: v.events as readonly A2ATaskEvent[],
  } as TaskReductionInput);
}

function obligationView(obligations: readonly Obligation[]) {
  return obligations
    .map((o) => ({
      correlation_id: o.key.correlation_id,
      generation: o.key.generation,
      state: o.state,
    }))
    .sort((a, b) =>
      a.correlation_id === b.correlation_id
        ? a.generation - b.generation
        : a.correlation_id.localeCompare(b.correlation_id),
    );
}

describe("a2a reducer corpus (shared with the Python SDK)", () => {
  it("pins the corpus version", () => {
    expect(corpus.version).toBe("v0");
  });

  for (const v of corpus.traces) {
    it(`trace ${v.id} — ${v.why}`, () => {
      const result = runTrace(v);
      expect(result.task_state).toBe(v.expect.task_state);
      expect(obligationView(result.obligations)).toEqual(
        [...v.expect.obligations].sort((a, b) =>
          a.correlation_id === b.correlation_id
            ? a.generation - b.generation
            : a.correlation_id.localeCompare(b.correlation_id),
        ),
      );
      expect(result.rejected_events.map((r) => ({ index: r.index, code: r.code }))).toEqual(
        v.expect.rejected,
      );
      if (v.expect.unresolved_halt !== undefined) {
        expect(result.unresolved_halt).toBe(v.expect.unresolved_halt);
      }
    });
  }

  it("reduces commuting-permutation pairs identically", () => {
    const pairs = corpus.traces.filter((v) => v.permutation_of !== undefined);
    expect(pairs.length).toBeGreaterThan(0);
    for (const v of pairs) {
      const original = corpus.traces.find((t) => t.id === v.permutation_of);
      expect(original).toBeDefined();
      const a = runTrace(original as TraceVector);
      const b = runTrace(v);
      expect(b.task_state).toBe(a.task_state);
      expect(obligationView(b.obligations)).toEqual(obligationView(a.obligations));
      expect(b.rejected_events).toEqual(a.rejected_events);
    }
  });

  for (const v of corpus.input_errors) {
    it(`input error ${v.id} — ${v.why}`, () => {
      let thrown: unknown;
      try {
        reduceTaskState(v.input as unknown as TaskReductionInput);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(A2AReducerError);
      expect((thrown as A2AReducerError).code).toBe(v.expect_error);
    });
  }

  for (const v of corpus.authorization_request) {
    it(`authorization request ${v.id} — ${v.why}`, () => {
      if (v.expect_error !== undefined) {
        let thrown: unknown;
        try {
          buildAuthorizationRequest({
            key: v.key,
            approver_role: v.approver_role,
            approver_roles: v.approver_roles,
          });
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(A2AReducerError);
        expect((thrown as A2AReducerError).code).toBe(v.expect_error);
        return;
      }
      const request = buildAuthorizationRequest({
        key: v.key,
        approver_role: v.approver_role,
        approver_roles: v.approver_roles,
      });
      const expected = v.expect as NonNullable<typeof v.expect>;
      expect(request.task_state).toBe(expected.task_state);
      expect(request.substate).toEqual(expected.substate);
      for (const fragment of expected.message_contains) {
        expect(request.status_message).toContain(fragment);
      }
      // Producer-side capability material (server nonce, request digest) must
      // never reach the client-visible surface: the nonce is what makes a
      // pre-played credential unable to name the obligation.
      const clientVisible = request.status_message + JSON.stringify(request.substate);
      for (const secret of expected.message_and_substate_omit ?? []) {
        expect(clientVisible).not.toContain(secret);
      }
      // The builder's output satisfies the same law as everyone else's:
      // honesty guard over the message, privacy validator over the substate.
      expect(() =>
        assertNoEnforcementClaim(request.status_message, `authorization_request:${v.id}`),
      ).not.toThrow();
      expect(() =>
        validateDecisionSubstate(request.substate, { approver_roles: v.approver_roles }),
      ).not.toThrow();
    });
  }

  for (const v of corpus.obligation_status_update) {
    it(`obligation status update ${v.id} — ${v.why}`, () => {
      if (v.expect_error !== undefined) {
        let thrown: unknown;
        try {
          buildObligationStatusUpdate(v.key, v.status as ObligationState);
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(A2AReducerError);
        expect((thrown as A2AReducerError).code).toBe(v.expect_error);
        return;
      }
      const substate = buildObligationStatusUpdate(v.key, v.status as ObligationState);
      const expected = v.expect as NonNullable<typeof v.expect>;
      expect(substate).toEqual(expected.substate);
      // Wire-visible closure must not leak producer-side capability material,
      // and must pass the same validator every substate passes.
      const serialized = JSON.stringify(substate);
      for (const secret of expected.omit) {
        expect(serialized).not.toContain(secret);
      }
      expect(() => validateDecisionSubstate(substate, {})).not.toThrow();
    });
  }
});
