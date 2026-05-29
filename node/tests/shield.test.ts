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

// S015 P0-1 / H5 / H9: an empty spec (neither scope nor deny) must fail
// closed at construction. rc7 returned the wrapped function's data entirely
// unfiltered here — every field, incl. PII — which is the leak D-161 found.
// Parity with Python (shield.py:761-774, raises "minimum disclosure").
describe("empty scope and deny → minimum-disclosure error (S015)", () => {
  it("shield() rejects a purpose-only spec", () => {
    expect(() => shield({ purpose: "p" })).toThrow(/minimum disclosure|required/);
  });
  it("shield() rejects explicit empty arrays", () => {
    expect(() => shield({ purpose: "p", scope: [], denyFields: [] })).toThrow(
      /minimum disclosure|required/,
    );
  });
  it("wrap() rejects a purpose-only spec", () => {
    expect(() => wrap({ ssn: "x" }, { purpose: "p" })).toThrow(/minimum disclosure|required/);
  });
});

// S015 P0-2 / H6 / H10: deny over a value that carries no named fields
// (scalar, array-of-scalars) must fail closed — rc7 returned the raw value.
describe("deny over a non-record value → fail-closed empty (S015)", () => {
  it("deny over a bare scalar returns empty string", () => {
    const fn = shield({ purpose: "p", denyFields: ["ssn"] })(() => "123-45-6789");
    expect(fn()).toBe("");
  });
  it("deny over an array of scalars returns emptied elements", () => {
    const fn = shield({ purpose: "p", denyFields: ["ssn"] })(() => ["123-45-6789", "ok"]);
    expect(fn()).toEqual(["", ""]);
  });
  it("deny over an object still removes only the denied field (control)", () => {
    const fn = shield({ purpose: "p", denyFields: ["ssn"] })(() => ({
      name: "A",
      ssn: "X",
    }));
    expect(fn()).toEqual({ name: "A" });
  });
});

// S016 failure-UX P0: an unrecognized / mis-cased mode string must throw, not
// silently fall through to AUTO (which would downgrade a developer asking for
// strict FULL gating into un-gated LITE with no signal).
describe("invalid mode is rejected (S016)", () => {
  for (const m of ["FULL", "Lite", "fulll", "full ", "strict"]) {
    it(`rejects mode=${JSON.stringify(m)}`, () => {
      expect(() => shield({ purpose: "p", scope: ["x"], mode: m as never })).toThrow(
        /invalid mode|mode/,
      );
    });
  }
  it("accepts the Mode enum values", () => {
    expect(() => shield({ purpose: "p", scope: ["x"], mode: Mode.LITE })).not.toThrow();
    expect(() => shield({ purpose: "p", scope: ["x"], mode: Mode.FULL })).not.toThrow();
    expect(() => shield({ purpose: "p", scope: ["x"], mode: Mode.AUTO })).not.toThrow();
  });
  it("accepts an omitted mode (defaults to AUTO)", () => {
    expect(() => shield({ purpose: "p", scope: ["x"] })).not.toThrow();
  });
});

// S015 P0 (prototype-name scope bypass): a data field whose name collides
// with an Object.prototype member (toString / constructor / hasOwnProperty …)
// must NOT pass the scope whitelist un-granted. `k in pathTree` walked the
// prototype chain and returned the raw field; hasOwnProperty + null-proto tree
// close it. Found by a 3-reviewer cross-model pass that agy + the first
// falsification sweep missed.
describe("prototype-name fields do not bypass scope (S015 P0)", () => {
  const PROTO_NAMES = [
    "toString",
    "constructor",
    "hasOwnProperty",
    "valueOf",
    "isPrototypeOf",
    "toLocaleString",
    "propertyIsEnumerable",
    "__proto__",
  ];
  for (const name of PROTO_NAMES) {
    it(`drops un-whitelisted field named '${name}'`, () => {
      const obj: Record<string, unknown> = { name: "n" };
      obj[name] = "111-22-3333";
      const out = shield({ purpose: "p", scope: ["name"] })(() => obj)() as Record<
        string,
        unknown
      >;
      expect(out).toEqual({ name: "n" });
      expect(JSON.stringify(out)).not.toContain("111-22-3333");
    });
  }
  it("drops a nested prototype-name field under a sub-path scope", () => {
    const fn = shield({ purpose: "p", scope: ["a.name"] })(() => ({
      a: { name: "n", toString: "111-22-3333" },
    }));
    expect(fn()).toEqual({ a: { name: "n" } });
  });
  it("still removes a denied prototype-name field", () => {
    const fn = shield({ purpose: "p", denyFields: ["constructor"] })(() => ({
      name: "n",
      constructor: "111-22-3333",
    }));
    expect(fn()).toEqual({ name: "n" });
  });
});

// S015 P0-3: a wrapped function that throws must fail closed — the exception
// can carry PII in its message/stack. rc7 let it propagate raw to the caller.
describe("wrapped function throws → fail-closed empty (S015)", () => {
  it("does not propagate a PII-carrying exception (LITE)", () => {
    const fn = shield({ purpose: "p", scope: ["name"] })(() => {
      throw new Error("db dump ssn=123-45-6789");
    });
    let threw = false;
    let out: unknown;
    try {
      out = fn();
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
    expect(out).toBe("");
  });
});
