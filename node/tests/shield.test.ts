import { afterEach, describe, expect, it } from "vitest";

import { _setTestHook } from "../src/shield.js";
import { Mode, shield, wrap } from "../src/index.js";

afterEach(() => {
  _setTestHook(null);
});

describe("scope (allow-list)", () => {
  it("keeps only listed top-level keys", () => {
    const fn = shield({ purpose: "p", scope: ["name", "email"] })(
      (_id: unknown) => ({ id: 1, name: "A", email: "a@x", ssn: "X" }),
    );
    const out = fn(1) as Record<string, unknown>;
    expect(out).toEqual({ name: "A", email: "a@x" });
  });

  it("descends nested paths", () => {
    const fn = shield({
      purpose: "p",
      scope: ["profile.name", "profile.address.city"],
    })((_: unknown) => ({
      profile: {
        name: "A",
        age: 30,
        address: { city: "Tokyo", street: "secret" },
      },
      ssn: "X",
    }));
    expect(fn(0)).toEqual({
      profile: { name: "A", address: { city: "Tokyo" } },
    });
  });

  it("fail-closed: bare leaf scope drops list-of-records", () => {
    const fn = shield({ purpose: "p", scope: ["users"] })(
      (_: unknown) => ({ users: [{ name: "A", ssn: "X" }] }),
    );
    expect(fn(0)).toEqual({});
  });

  it("leaf scope keeps list of scalars", () => {
    const fn = shield({ purpose: "p", scope: ["tags"] })(
      (_: unknown) => ({ tags: ["red", "blue"], ssn: "X" }),
    );
    expect(fn(0)).toEqual({ tags: ["red", "blue"] });
  });

  it("descend into array of records via dot path", () => {
    const fn = shield({ purpose: "p", scope: ["users.name"] })(
      (_: unknown) => ({
        users: [
          { name: "A", ssn: "X" },
          { name: "B", ssn: "Y" },
        ],
      }),
    );
    expect(fn(0)).toEqual({
      users: [{ name: "A" }, { name: "B" }],
    });
  });

  it("scope expects nested but value scalar → drop fail-closed", () => {
    const fn = shield({ purpose: "p", scope: ["profile.name"] })(
      (_: unknown) => ({ profile: 42 }),
    );
    expect(fn(0)).toEqual({});
  });
});

describe("denyFields (block-list)", () => {
  it("removes top-level key", () => {
    const fn = shield({ purpose: "p", denyFields: ["ssn"] })(
      (_: unknown) => ({ name: "A", ssn: "X" }),
    );
    expect(fn(0)).toEqual({ name: "A" });
  });

  it("removes nested key", () => {
    const fn = shield({ purpose: "p", denyFields: ["profile.ssn"] })(
      (_: unknown) => ({ profile: { name: "A", ssn: "X" } }),
    );
    expect(fn(0)).toEqual({ profile: { name: "A" } });
  });

  it("broader deny wins over child path", () => {
    const fn = shield({
      purpose: "p",
      denyFields: ["profile", "profile.ssn"],
    })((_: unknown) => ({ profile: { name: "A", ssn: "X" }, id: 1 }));
    expect(fn(0)).toEqual({ id: 1 });
  });

  it("applies through list elements", () => {
    const fn = shield({ purpose: "p", denyFields: ["users.ssn"] })(
      (_: unknown) => ({
        users: [
          { name: "A", ssn: "X" },
          { name: "B", ssn: "Y" },
        ],
      }),
    );
    expect(fn(0)).toEqual({
      users: [{ name: "A" }, { name: "B" }],
    });
  });
});

describe("async", () => {
  it("filters resolved Promise value", async () => {
    const fn = shield({ purpose: "p", scope: ["name"] })(
      async (_: unknown) => ({ name: "A", ssn: "X" }),
    );
    await expect(fn(0)).resolves.toEqual({ name: "A" });
  });
});

describe("class instances", () => {
  it("treats class instance as record-like", () => {
    class User {
      constructor(public name: string, public ssn: string) {}
    }
    const fn = shield({ purpose: "p", scope: ["name"] })(
      (_: unknown) => new User("A", "X"),
    );
    expect(fn(0)).toEqual({ name: "A" });
  });
});

describe("wrap()", () => {
  it("returns ShieldResult with filteredKeys", () => {
    const r = wrap({ name: "A", ssn: "X" }, { purpose: "p", scope: ["name"] });
    expect(r.data).toEqual({ name: "A" });
    expect(r.filteredKeys).toContain("ssn");
    expect(r.mode).toBe(Mode.LITE);
    expect(r.purpose).toBe("p");
  });
});

describe("test hook", () => {
  it("captures invocations with blockedFields", () => {
    const records: unknown[] = [];
    _setTestHook((r) => records.push(r));
    const fn = shield({ purpose: "p", scope: ["name"] })(
      (_: unknown) => ({ name: "A", ssn: "X" }),
    );
    fn(0);
    expect(records).toHaveLength(1);
    const r = records[0] as {
      blockedFields: string[];
      purpose: string;
      mode: string;
    };
    expect(r.purpose).toBe("p");
    expect(r.blockedFields).toContain("ssn");
    expect(r.mode).toBe("lite");
  });
});

describe("validation", () => {
  it("rejects empty purpose", () => {
    expect(() => shield({ purpose: "" })).toThrow(/purpose/);
  });
});

describe("empty scope and deny → pass-through", () => {
  it("returns data unchanged", () => {
    const data = { a: 1, b: { c: 2 } };
    const fn = shield({ purpose: "p" })((_: unknown) => data);
    expect(fn(0)).toEqual(data);
  });
});
