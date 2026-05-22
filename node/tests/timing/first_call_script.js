// First-call script for the productization-ops time_to_first_call verifier.
//
// The verifier writes this file to <workdir>/first_call.script and executes it
// with `node`. Node refuses ESM `import` syntax on the unknown extension, so
// we use a CJS wrapper with a dynamic import() (the SDK is ESM-only).
//
// Goal: prove that a developer can go from `npm install aegis-trust`
// to their first `shield()` decision in under 60s on a clean machine.

(async () => {
  const sdk = await import("aegis-trust");
  const { shield } = sdk;

  function db_fetch(id) {
    return { id, name: "alice", email: "alice@example.com", ssn: "000-00-0000" };
  }

  const safeFetch = shield({
    purpose: "customer_support",
    scope: ["name", "email"],
  })(db_fetch);

  const filtered = safeFetch(42);
  const actual = Object.keys(filtered).sort();
  const want = ["email", "name"];
  if (actual.length !== want.length || actual.some((k, i) => k !== want[i])) {
    console.error(
      "first_call_script: shield output mismatch. expected=" + JSON.stringify(want) + " actual=" + JSON.stringify(actual),
    );
    process.exit(1);
  }
  console.log("first_call_script: OK (filtered keys=" + JSON.stringify(actual) + ")");
})().catch((err) => {
  console.error("first_call_script: error", err);
  process.exit(1);
});
