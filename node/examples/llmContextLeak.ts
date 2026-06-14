// The one pain aegis-trust LITE solves: sensitive fields leaking INTO the LLM.
// Node mirror of python/examples/llm_context_leak.py.
//
// The real, daily agent data accident is accidental over-disclosure: a tool
// returns a record, you put it in the prompt, and ssn / card_number /
// internal_notes ride along into the model, the provider's logs, and downstream
// tool calls. The skeptic asks "I'd just pick the fields in 5 lines — why a
// library?" On a realistic NESTED record, the hand-rolled allowlist silently
// leaks; aegis-trust fails closed.
//
//   npm install aegis-trust        # zero runtime dependencies
//   npx tsx examples/llmContextLeak.ts

import { wrap } from "../src/index.js";

const CUSTOMER = {
  name: "Tanaka Taro",
  issue: "Login problem",
  profile: { age: 41, ssn: "123-45-6789" }, // ssn nested under profile
  billing: { plan: "pro", card_number: "4242-4242-4242-4242" },
  internal_notes: "VIP; churn risk; offered discount",
};

function sentToModel(label: string, payload: unknown): void {
  console.log(`\n--- ${label} — exact object that reaches the LLM (and its logs) ---`);
  console.log(payload);
}

// 1) NAIVE hand-rolled allowlist — the "5 lines, why a library?" approach. The
//    author wanted name + issue + the customer's age, so they keep "profile". A
//    flat ssn would be obvious; this nested ssn is NOT.
const naive = { name: CUSTOMER.name, issue: CUSTOMER.issue, profile: CUSTOMER.profile };
sentToModel("Hand-rolled allowlist {name, issue, profile}", naive);
console.log("  -> LEAKED:", "ssn" in naive.profile, "(profile.ssn rode along)");

// 2) aegis-trust — declare the dot-path you actually mean. Fail-closed on the rest.
const guarded = wrap(CUSTOMER, { purpose: "support_reply", scope: ["name", "issue", "profile.age"] });
sentToModel("aegis-trust scope=[name, issue, profile.age]", guarded.data);
console.log("  withheld:", guarded.filteredKeys);

// 3) The footgun aegis-trust closes by default: a BARE parent in the allowlist.
const bare = wrap(CUSTOMER, { purpose: "support_reply", scope: ["name", "issue", "profile"] });
sentToModel("aegis-trust bare scope=[name, issue, profile]", bare.data);
console.log("  withheld:", bare.filteredKeys, "(whole profile dropped, fail-closed)");

console.log(
  "\nTakeaway: the value is not stripping a top-level ssn (trivial). It is that " +
    "minimum-disclosure over nested/collection shapes is where hand-rolled code " +
    "leaks — and aegis-trust fails closed there, in one declared line.",
);
