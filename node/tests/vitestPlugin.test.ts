import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  assertShieldBlocked,
  assertShieldPassed,
  shield,
  useShieldHistory,
} from "../src/index.js";

describe("useShieldHistory + assert helpers", () => {
  const history = useShieldHistory({ beforeEach, afterEach });

  it("captures blocked fields and supports assertShieldBlocked", () => {
    const getUser = shield({ purpose: "support", scope: ["name"] })(
      (_id: unknown) => ({ name: "A", ssn: "X" }),
    );
    getUser(1);
    assertShieldBlocked(history.records(), "ssn");
  });

  it("assertShieldBlocked throws when field not blocked", () => {
    const getUser = shield({ purpose: "support", scope: ["name", "ssn"] })(
      (_id: unknown) => ({ name: "A", ssn: "X" }),
    );
    getUser(1);
    expect(() => assertShieldBlocked(history.records(), "ssn")).toThrow(
      /Expected 'ssn' to be blocked/,
    );
  });

  it("assertShieldPassed succeeds when field passes through", () => {
    const getUser = shield({ purpose: "support", scope: ["name"] })(
      (_id: unknown) => ({ name: "A", ssn: "X" }),
    );
    getUser(1);
    assertShieldPassed(history.records(), "name");
  });

  it("assertShieldPassed throws when field was blocked", () => {
    const getUser = shield({ purpose: "support", scope: ["name"] })(
      (_id: unknown) => ({ name: "A", ssn: "X" }),
    );
    getUser(1);
    expect(() => assertShieldPassed(history.records(), "ssn")).toThrow(
      /Expected 'ssn' to pass through/,
    );
  });
});

describe("isolation between tests", () => {
  const history = useShieldHistory({ beforeEach, afterEach });

  it("first test populates", () => {
    const fn = shield({ purpose: "p", scope: ["name"] })(() => ({
      name: "A",
      ssn: "X",
    }));
    fn();
    expect(history.records()).toHaveLength(1);
  });

  it("second test starts fresh", () => {
    expect(history.records()).toHaveLength(0);
  });
});
