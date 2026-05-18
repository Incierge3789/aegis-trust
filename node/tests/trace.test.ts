import { describe, expect, it } from "vitest";

import {
  AegisValidationError,
  getTraceContext,
  newTraceId,
  withTraceContext,
} from "../src/index.js";

describe("withTraceContext — round 3 P0-6 traceId validation", () => {
  it("accepts valid traceId from newTraceId()", () => {
    const id = newTraceId();
    let captured: string | undefined;
    withTraceContext({ traceId: id }, () => {
      captured = getTraceContext()?.traceId;
    });
    expect(captured).toBe(id);
  });

  it("rejects empty traceId", () => {
    expect(() =>
      withTraceContext({ traceId: "" }, () => {}),
    ).toThrow(AegisValidationError);
  });

  it("rejects traceId longer than 128 chars (secret token cap)", () => {
    expect(() =>
      withTraceContext({ traceId: "a".repeat(129) }, () => {}),
    ).toThrow(AegisValidationError);
  });

  it("rejects traceId with whitespace (would mangle JSONL)", () => {
    expect(() =>
      withTraceContext({ traceId: "trace with space" }, () => {}),
    ).toThrow(AegisValidationError);
  });

  it("rejects traceId with Bearer-token shape (prevents secret leakage)", () => {
    expect(() =>
      withTraceContext(
        { traceId: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" },
        () => {},
      ),
    ).toThrow(AegisValidationError);
  });

  it("accepts UUID-style", () => {
    const id = "00000000-0000-4000-8000-000000000000";
    let captured: string | undefined;
    withTraceContext({ traceId: id }, () => {
      captured = getTraceContext()?.traceId;
    });
    expect(captured).toBe(id);
  });

  it("rejects invalid parentId shape", () => {
    expect(() =>
      withTraceContext({ traceId: "valid-1", parentId: "has space" }, () => {}),
    ).toThrow(AegisValidationError);
  });

  it("propagates traceId across nested async callbacks", async () => {
    const id = newTraceId();
    let inner: string | undefined;
    await withTraceContext({ traceId: id }, async () => {
      await Promise.resolve();
      inner = getTraceContext()?.traceId;
    });
    expect(inner).toBe(id);
  });

  it("outer trace untouched outside withTraceContext", () => {
    expect(getTraceContext()).toBeUndefined();
  });
});
