"""The one pain aegis-trust LITE solves: sensitive fields leaking INTO the LLM.

The real, daily agent data accident is not a malicious in-process attacker — it
is *accidental over-disclosure*: an agent tool returns a record, you put it in
the prompt, and `ssn` / `card_number` / `internal_notes` ride along into the
model, the provider's logs, your traces, and any downstream tool call.

The skeptic's fair question: "I'd just pick the fields I want in 5 lines —
why a library?" This demo answers it. On a realistic *nested* record, the
hand-rolled 5-line allowlist silently leaks; aegis-trust fails closed.

    pip install aegis-trust          # zero runtime dependencies
    python examples/llm_context_leak.py

No API key, no network, no Aegis Core — fully local and deterministic. The dict
below stands in for whatever your tool returns; treat it as "what is about to
become part of your LLM prompt."
"""

from aegis_trust import wrap

# What an agent tool actually returns — flat AND nested sensitive fields.
CUSTOMER = {
    "name": "Tanaka Taro",
    "issue": "Login problem",
    "profile": {"age": 41, "ssn": "123-45-6789"},  # ssn nested under profile
    "billing": {"plan": "pro", "card_number": "4242-4242-4242-4242"},
    "internal_notes": "VIP; churn risk; offered discount",
}


def sent_to_model(label: str, payload: dict) -> None:
    print(f"\n--- {label} — exact object that reaches the LLM (and its logs) ---")
    print(payload)


# 1) NAIVE hand-rolled allowlist — the "5 lines, why a library?" approach.
#    The author wanted name + issue + the customer's age, so they keep
#    "profile". A flat ssn would be obvious; this nested ssn is NOT.
naive = {k: CUSTOMER[k] for k in ("name", "issue", "profile")}
sent_to_model("Hand-rolled allowlist {name, issue, profile}", naive)
print("  -> LEAKED:", "ssn" in naive.get("profile", {}), "(profile.ssn rode along)")

# 2) aegis-trust — declare the dot-path you actually mean. Fail-closed on the rest.
guarded = wrap(
    CUSTOMER, purpose="support_reply", scope=["name", "issue", "profile.age"]
)
sent_to_model("aegis-trust scope=[name, issue, profile.age]", guarded.data)
print("  withheld:", guarded.filtered_keys)

# 3) The footgun aegis-trust closes by default: a BARE parent in the allowlist.
#    The naive version keeps the whole subtree; aegis-trust refuses to pass a
#    record-shaped value through a bare leaf (it cannot know the nested fields
#    are safe) and DROPS it — minimum disclosure, not silent pass-through.
bare = wrap(CUSTOMER, purpose="support_reply", scope=["name", "issue", "profile"])
sent_to_model("aegis-trust bare scope=[name, issue, profile]", bare.data)
print("  withheld:", bare.filtered_keys, "(whole profile dropped, fail-closed)")

print(
    "\nTakeaway: the value is not stripping a top-level ssn (trivial). It is that "
    "minimum-disclosure over nested/collection shapes is where hand-rolled code "
    "leaks — and aegis-trust fails closed there, in one declared line."
)
