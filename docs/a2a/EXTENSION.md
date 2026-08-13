# Aegis Boundary Decision — A2A Extension (v0)

> **PRERELEASE.** The extension identifier is a machine-detectable placeholder
> (`urn:x-aegis-placeholder:a2a:boundary-decision:v0`) and is **not registered**.
> Nothing here is published to a registry, a package index, or an extension
> catalogue. Registering an identifier is an ownership decision and has not been
> made.

**In thirty seconds:** this extension lets an A2A agent **report** an Aegis
boundary decision — one of five outcomes, a reason code, and field *names* —
inside A2A's own `Task`, `Message`, and `Artifact` objects, without inventing
new enum values and without carrying payload values. It proves that a decision
was *reported*, in a structurally checkable form, by whoever emitted it. It
does **not** prove the decision was enforced, does not prove who emitted it,
and cannot: it is a vocabulary, activated by a header, and anyone can speak a
vocabulary. Aegis's enforcement comes from the gateway path, never from this
extension.

Normative sources, pinned:

| Source | Pin | Used for |
|---|---|---|
| A2A spec | `a2aproject/A2A@0ef1b02547e959d770ebf3460d058f5c3421641c` | `TaskState` (a2a.proto:187-208), extensions (§4.6), `A2A-Extensions` header (§14.2.2), in-task authorization (§7.6, §7.6.1) |
| Decision engine | `aegis-boundary-core@324efd18`, `engine/aegis-decision/src/decision.rs:118-142` | outcome and reason vocabularies, legal pairs, fixed reason phrases |

The words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119. The shared
conformance corpora under `conformance/a2a_*.v0.json` are **normative test
data**: a second implementation conforms exactly when it passes all four
corpora (`a2a_mapping`, `a2a_extension`, `a2a_reducer`, `a2a_privacy`).

---

## 1. Identifier and versioning

- Extension URI (placeholder): `urn:x-aegis-placeholder:a2a:boundary-decision:v0`
- Substate version: `v0` (dated-version convention; the `version` field rides
  in the envelope)
- Metadata keying: A2A §4.6.1/§4.6.2 — metadata objects are keyed **by the
  extension URI**.

Consumers MUST reject substate versions they do not understand
(`invalid_field_value`), never guess a future vocabulary. Producers MUST NOT
ship the placeholder identifier in a release artifact
(`isPlaceholderExtensionUri` / `is_placeholder_extension_uri` exists for the
release gate). Deprecation policy: a vocabulary change is a new dated version
under a new metadata shape; `v0` fields are never reinterpreted in place.

## 2. Activation — request negotiation

Extensions are **inactive by default** (A2A §4.6). A client opts in by naming
the URI in the `A2A-Extensions` request header (comma-separated; the URI
**values** are matched exactly and case-sensitively). The header **name** is
matched per the transport's own rules — HTTP header names are
case-insensitive, and gRPC metadata keys are lowercased in transit — so a
producer MUST look the header up case-insensitively, not by comparing against
the literal constant. The agent echoes the extensions it actually activated in
the response header.

- Not requested → the named outcome `not_requested`, not an error. A consumer
  MUST be able to distinguish "I did not opt in" from "there was nothing to
  report".
- A producer MUST NOT write decision metadata for a request that did not
  activate the extension (`extension_not_activated` — fail-closed).
- The AgentCard declaration MUST carry `required: false`. A "required"
  security-flavoured extension invites the exact misreading (§10) this surface
  must avoid.

## 3. Activation binding — who may read a delivery

Request negotiation is not read authorization. A task outlives its originating
request: other principals can `GetTask` it, subscribers can stream it, webhooks
can push it. Activation is therefore bound as **state**:

```
(principal, task_id, extension URI, version, delivery channel)
```

with channels `request_response | get_task | subscribe | webhook`. A binding on
one channel does not cover another.

Two trust preconditions are the integrator's duty, stated normatively because
the module cannot enforce them (round-1 critique, both vendors):

- **`principal` MUST be an authenticated identity** established by the
  caller's transport/authn layer. The module compares identities; it does not
  authenticate them. Filtering deliveries with an unauthenticated,
  caller-invented principal string voids every guarantee in this section.
- **Binding state MUST be integrity-protected at rest.** `bindActivation`
  validates what it creates, but a record restored from persistence never went
  through it — which is why the read boundary re-validates both sides: a
  malformed or foreign-URI stored record counts as *no activation*, and a
  malformed delivery query is *not activated*. That re-validation bounds the
  damage of a poisoned store; it does not substitute for protecting the store.
- **A binding MUST originate from that principal's own negotiation** for the
  same task and channel — use `bindActivationFromNegotiation`, which refuses to
  bind a principal whose `NegotiationResult` did not activate the extension.
  Hand-constructing a binding for a principal who never opted in is a
  confused-deputy grant (round-3 codex).
- **`query.task_id` MUST identify the task that owns the metadata being
  filtered.** `filterDecisionMetadataForDelivery(metadata, bindings, query)`
  filters the `metadata` you hand it; it cannot verify that this metadata
  belongs to `query.task_id`. Passing task B's metadata with a task-A query
  returns task B's metadata to whoever is bound for task A. Always filter a
  task's OWN metadata with a query naming that task. (A future API taking a
  task object that carries its own id would enforce this in code; see
  R-S027-ACT.)

Delivery filtering (`filterDecisionMetadataForDelivery` /
`filter_decision_metadata_for_delivery`):

- Extension key absent → metadata unchanged. **No marker is invented**: a task
  that was never reported on stays distinguishable from one whose report is
  withheld.
- Delivery is bound → metadata unchanged.
- Delivery is not bound → the substate is replaced by the withheld marker
  `{ version, status: "withheld_not_activated", reason: ... }` — zero decision
  content (no outcome, no reason, no field names). Existence is disclosed;
  content is not. Deleting the key instead would silently degrade "reporting
  exists" to "there is no reporting", which is itself a governance failure.

## 4. Decision vocabulary

Outcomes (wire form `SCREAMING_SNAKE_CASE`):
`PROTECTED`, `ACCESS_REDUCED`, `CHECK_REQUIRED`, `APPROVAL_REQUIRED`, `BLOCKED`.

Reason codes (`snake_case`): `minimum_disclosure`, `policy_denied`,
`approval_required`, `check_required`, `invalid_scope`, `internal_failure`.

**Exactly seven legal pairs** — the engine derives the reason code from the
outcome and only `BLOCKED` branches:

| outcome | reason_code |
|---|---|
| `PROTECTED` | `minimum_disclosure` |
| `ACCESS_REDUCED` | `minimum_disclosure` |
| `CHECK_REQUIRED` | `check_required` |
| `APPROVAL_REQUIRED` | `approval_required` |
| `BLOCKED` | `policy_denied` |
| `BLOCKED` | `invalid_scope` |
| `BLOCKED` | `internal_failure` |

Implementations MUST reject unknown outcomes, unknown reason codes, and the 23
illegal pairs (`unknown_outcome` / `unknown_reason_code` /
`illegal_outcome_reason_pair`). The validator is **surface-scoped**: other
Aegis endpoints emit reason codes outside this enum (e.g.
`capsule_scope_denied`), and those MUST NOT be mapped onto A2A task state.

`reason_label`, when present, MUST be the fixed phrase for its reason code,
verbatim (pinned in `REASON_LABELS`; source `ReasonCode::human_label`). The
label is the enum speaking. Any other string is either drift or free text
smuggled into a fixed-phrase slot, and free text is how payload values leak.

## 5. Mapping — decision to TaskState

One Aegis decision is **per data access**; one A2A `TaskState` is **per task**.
The mapping returns a *recommendation*, never assigns state, and never selects
a success state — only the task executor knows whether a withheld field was
required for the requested result.

| decision | halts task? | TaskState recommendation | notes |
|---|---|---|---|
| `PROTECTED` | no | *(none)* | no lifecycle claim |
| `ACCESS_REDUCED` | no | *(none)* | narrowing is the product working; it rides in the record, not the state |
| `CHECK_REQUIRED` | pauses, boundary acts | `TASK_STATE_WORKING` | the caller need do nothing |
| `APPROVAL_REQUIRED`, fulfilment delegated to client | yes | `TASK_STATE_AUTH_REQUIRED` | takes every §7.6.1 obligation (§7) |
| `APPROVAL_REQUIRED`, fulfilment held by the boundary | pauses, client need do nothing | `TASK_STATE_WORKING` | §7.6 defines AUTH_REQUIRED as *delegating* fulfilment; an internally-resolved approval MUST NOT interrupt the client |
| `BLOCKED` / `policy_denied` | yes | `TASK_STATE_REJECTED` | a decision, not an error; not repairable |
| `BLOCKED` / `invalid_scope` | yes | `TASK_STATE_INPUT_REQUIRED` | a request defect the client can repair; terminal `REJECTED` would foreclose the repair |
| `BLOCKED` / `internal_failure` | yes | `TASK_STATE_FAILED` | fail-secure refusal on an internal error IS an error, and must stay distinguishable from a policy refusal in the audit trail |

`TASK_STATE_UNSPECIFIED`, `SUBMITTED`, `CANCELED` have no Aegis counterpart and
are never set by this extension. No new `TaskState` values exist or ever will:
the A2A extension rules forbid extending core enums, which is why the substate
exists.

## 6. Reducer — from decisions to one task state

"Only a decision that halts the task drives TaskState" is made computable by a
deterministic reducer over `(prior state, prior obligations, events)`:

- **Terminal monotonicity.** Once terminal (`COMPLETED`, `FAILED`, `CANCELED`,
  `REJECTED`), no later event changes the state; post-terminal events are
  recorded as rejected.
- **Causal ordering.** A `resolved` / `rejected` / `expired` closure with no
  matching **open** obligation MUST be rejected and recorded — never
  remembered. The remembered-event ("tombstone") implementation is a named
  attack: a credential replayed before the obligation opens pre-resolves it,
  the boundary's later genuine `APPROVAL_REQUIRED` is swallowed, and the
  destructive action proceeds while every order-invariance property still
  holds. Order invariance is therefore deliberately **not** a property of this
  reducer, except across commuting decision events (`PROTECTED`,
  `ACCESS_REDUCED`, `CHECK_REQUIRED`).
- **Per-event refusal.** A bad event is rejected and the stream continues.
  Aborting the stream on first refusal would let one injected event destroy
  the genuine events behind it.
- **No success states.** The reducer's most permissive output is
  `TASK_STATE_WORKING`. `COMPLETED` is the executor's call.
- A denied or expired approval **holds the halt** (`AUTH_REQUIRED`) until the
  boundary speaks again — closure of an obligation never widens access. A
  checkpointed `AUTH_REQUIRED` restored without its open obligation stays
  halted (fail-closed) rather than silently resuming.
- **Liveness is a producer duty, not a reducer guess.** After an obligation is
  rejected or expires, the producer MUST follow up with a boundary decision —
  typically `BLOCKED`/`policy_denied` (→ `REJECTED`) or a re-issued obligation
  at `generation + 1` — within its own policy's deadline, and MUST make the
  closure wire-visible in the meantime: emit
  `buildObligationStatusUpdate(key, "rejected" | "expired")` (the authorization
  request itself carries `obligation_status: "open"`). The reducer will not
  invent the follow-up decision — an automatic transition would fabricate an
  outcome the boundary never produced — but with the status update emitted, a
  poller can tell a still-actionable `AUTH_REQUIRED` from one waiting on the
  boundary.

### Trust boundaries (what the reducer does and does not defend)

Stated normatively because they are load-bearing (round-1 critique):

- **The event stream is trusted input.** Only authenticated boundary
  components may append events. The reducer checks *correlation* — that a
  closure names an open obligation and that a credential's binding equals its
  tuple exactly — not *authenticity*: it is keyless, and verifying who signed
  a credential is Aegis Core territory. An integrator that feeds
  counterparty-controlled bytes into `events` has moved the trust boundary
  themselves.
- **`server_nonce` is producer-side capability material.** It is issued at
  obligation-open time, shared only with the boundary's own approval channel,
  and MUST NOT appear on any A2A surface — not in the substate, not in
  `TaskStatus` text (the conformance runner asserts both). While the nonce
  stays secret, synthesizing an acceptable closure requires capability an
  outsider does not have; if it leaks, the event-stream trust boundary is the
  remaining defense.
- **Checkpoints are trusted state, and MUST persist `unresolved_halt`.**
  `prior_state` / `prior_obligations` come from the caller's own store, MUST be
  integrity-protected there, and MUST NOT be built from wire-derived input.
  A denial or expiry holds the halt until the boundary speaks again, and **that
  fact cannot be reconstructed from `(prior_state, prior_obligations)` alone** —
  a rejected obligation sitting next to an OPEN one looks identical to a task
  merely waiting on the open one. So `reduceTaskState` returns
  `unresolved_halt`, and a checkpoint MUST store it and pass it back as
  `prior_unresolved_halt`; a resume that drops it lets the sibling's later
  resolution silently lift a denial's halt. The reducer still detects the
  coarser corruption it can see (`AUTH_REQUIRED` restored with no open
  obligation and no `prior_unresolved_halt` stays halted) but cannot detect a
  store that forged `WORKING` and dropped the obligation record entirely —
  that is indistinguishable from a legitimately unhalted task.

### Obligations and credentials

An authorization obligation is identified by the full 7-field tuple:

```
(task_id, context_id, requesting_agent, request_digest,
 correlation_id, generation, server_nonce)
```

`server_nonce` is issued by the boundary **when it opens the obligation**,
which is what makes a pre-played credential unable to name it. `generation`
counts re-issues: a closed tuple can never re-open; re-asking is a new
obligation at `generation + 1`.

A `resolved` closure MUST carry the credential (A2A §7.6: "the object that
represents the approved authorization"), and the credential's binding MUST
equal the open obligation's tuple **exactly** — six matching fields and a
wrong nonce is a forgery, not a near-miss.

**Scope limit:** the reducer checks *binding*, not issuer authenticity.
Authenticating who signed a credential requires keys, and keyed verification
is Aegis Core territory. A keyless implementation claiming issuer
authentication would be lying; see §10.

## 7. §7.6.1 duties — what the builder emits, what the integrator still owes

The pin's levels, reproduced faithfully (a2a_spec_main.md §7.6.1): using a
Task and transitioning the state are unconditional **MUST**s; including a
`TaskStatus` message explaining the required authorization is a **MUST unless
the details have been negotiated out-of-band or via an extension**; arranging
to receive credentials out-of-band is a **MUST unless an in-band mechanism has
been negotiated**; maintaining active response streams and supporting messages
directed to the task are **SHOULD**s. The builder output
(`buildAuthorizationRequest` / `build_authorization_request`) supplies the
*emittable content* for these duties — it does not itself run a task server,
and a field like `accepts_task_messages: true` is a commitment the integrator
MUST make true, not a fact the field creates (round-1 critique):

| §7.6.1 duty | level (pin, verbatim condition) | builder emits | integrator still owes |
|---|---|---|---|
| use a Task to track the operation | MUST | — (per-task by construction) | a real Task object |
| transition to `TASK_STATE_AUTH_REQUIRED` | MUST | `task_state` | applying it to the Task |
| include a `TaskStatus` message explaining the required authorization | MUST, "unless the details of the authorization have been negotiated out-of-band or via an extension" — this extension negotiates no such details, so for its users the MUST is unconditional | `status_message` — fixed template over the approver **role label** and correlation fields; nothing free-form reaches it | placing it in `TaskStatus.message` |
| arrange to receive credentials out-of-band | MUST, "unless an in-band mechanism has been negotiated out-of-band or via an extension" — this extension negotiates none, so out-of-band it is | `substate.credential_receipt = "out_of_band"` (only legal value) | operating the out-of-band channel |
| support messages directed to the task (negotiate / correct / reject) | SHOULD | `substate.accepts_task_messages = true` (only legal value) | actually accepting them |
| maintain response streams / continue after credential receipt | SHOULD (streams) / MAY (immediate continue) | `substate.resume_on = "credential_resolution"` | delivering the resumed stream; the reducer supplies the resolved → `WORKING` transition |
| report obligation closure | this extension's own duty (§6 liveness) | `obligation_status: "open"` at request time; `buildObligationStatusUpdate` after closure | emitting the update substate so pollers can distinguish waiting-on-boundary from actionable |

**Credential synthesis contract.** The client never constructs the
credential's 7-field binding — it cannot: the server nonce is capability
material it never sees (§6). The client obtains the approval out of band and
communicates it; the **boundary** synthesizes the bound credential from the
received approval and matches it to the open obligation. The client's only
correlates are `correlation_id` and `generation`.

## 8. Wire placement

| carrier | content |
|---|---|
| `Task.metadata[<extension URI>]` | the versioned envelope `{ version: "v0", ...substate }` |
| `TaskStatus.message` → `Message.metadata[<extension URI>]` | the per-transition decision that drove a state change |
| `Artifact.metadata[<extension URI>]` | receipt reference material |
| AgentCard `capabilities.extensions[]` | the declaration (`required: false`, placeholder marked) |

`Message` and `Artifact` additionally carry an `extensions` field (a list of
URIs, spec fields `Message.extensions` / `Artifact.extensions`); per the pin's
examples a producer using those carriers lists this extension's URI there **as
well as** keying the metadata by it. `Task` has no such field — the metadata
key is the whole story there.

Producers MUST NOT emit, and consumers MUST reject at the door:

- **Producer trust assertions** — any field whose normalized name is one of
  a producer trust-assertion key. Key matching normalizes EXACTLY as follows,
  and a second implementation MUST reproduce it or it retains the separator
  bypasses this rule exists to close: apply Unicode NFKC, lower-case, then
  strip every character outside `[a-z0-9]` — so `coreVerified`,
  `core_verified`, `CORE-VERIFIED`, `core.Verified`, a zero-width-space
  `core​Verified`, and full-width `ｃｏｒｅＶｅｒｉｆｉｅｄ` are all the
  same claim. **Two key sets, two scopes:**
  - Our OWN emitted value is held to the **full** `PRODUCER_TRUST_ASSERTION_KEYS`
    (`coreVerified`, `enforcementStatus`, `evidenceMode`,
    `issuer_authenticated`, `verified`, `trusted`, …) at every nesting depth —
    we control it and must emit nothing authority-flavored. Consumers scan
    received values against this full set too.
  - The rest of the carrier (the integrator's OWN sibling metadata) is scanned,
    at every depth, only against the **narrow** `CARRIER_IMPERSONATION_KEYS` —
    the keys that specifically name THIS extension's output (`coreVerified`,
    `enforcementStatus`, `enforced`, `assuranceLevel`, …). A generic
    `authenticated` or `verified` field from the integrator's own auth system
    is theirs and is left alone. **Values whose KEY is a namespace (a URI or
    URN) are opaque at any depth** — other extensions' vocabularies are theirs
    (§4.6 permits independently typed extension metadata). On the wire these
    fields are the counterparty's self-report; a UI that shows them next to a
    consumer-derived "unverified" has built a display where the attacker's
    field wins. Error: `producer_trust_assertion`.
- **Enforcement claims in runtime strings** — emission walks every string
  value of the extension's OWN emitted value with the honesty guard;
  `"Policy enforcement verified"` in one of our metadata values is refused
  the same as in documentation. The integrator's own sibling prose is the
  integrator's own claim and is not policed. Error:
  `enforcement_claim_detected`. The bare term "value-free" is banned outright
  (`banned_claim_term`): the property is **payload-value-omitting**, which is
  weaker, and the difference is the threat model below.

## 9. Substate field reference (v0, closed vocabulary)

Unknown keys MUST be rejected (`undeclared_metadata_field`) — minimization is
enforced, not requested. Fields outside their outcome MUST be rejected
(`field_not_applicable`).

| field | outcome scope | validation |
|---|---|---|
| `version` | any | `"v0"` exactly |
| `outcome` | any | enum §4 |
| `reason_code` | any | enum §4, legal pair with outcome |
| `reason_label` | any | fixed phrase for `reason_code`, verbatim |
| `withheld_fields` | `ACCESS_REDUCED` | array of non-empty strings; **each MUST be a member of the caller-declared field-name set** (see §10 threat model). No declaration → reject. |
| `disposition` | `BLOCKED` | derived: `correctable` for `invalid_scope`, else `terminal` |
| `fulfillment_owner` | `APPROVAL_REQUIRED` | `client` \| `agent` |
| `approver` | `APPROVAL_REQUIRED` | member of the caller-declared role-label set; never a person's name |
| `correlation_id` | `APPROVAL_REQUIRED` | opaque grammar `[A-Za-z0-9._:-]{1,128}`; MUST be generated by the boundary and MUST NOT encode request or payload data — the grammar bounds shape, only the generation locus prevents the covert channel |
| `generation` | `APPROVAL_REQUIRED` | integer ≥ 1 |
| `obligation_status` | `APPROVAL_REQUIRED` | `open` \| `resolved` \| `rejected` \| `expired` |
| `credential_receipt` | `APPROVAL_REQUIRED` (client) | `"out_of_band"` only |
| `accepts_task_messages` | `APPROVAL_REQUIRED` (client) | `true` only |
| `resume_on` | `APPROVAL_REQUIRED` (client) | `"credential_resolution"` only |

## 10. Privacy threat model, and what validation can and cannot do

The substate is **payload-value-omitting, not information-free**:

- A field-**name** set discloses schema shape — which fields exist is itself
  data about the record.
- Reason codes disclose policy posture — a counterparty watching codes over
  time learns what this deployment blocks.
- Counts and timestamps disclose access frequency and cadence. v0 therefore
  carries **no** timestamps and no counters in the substate; a rollup shape is
  future work with its own disclosure review.
- Any free-text field is a covert channel for payload values. v0 has none:
  every string field is either an enum, a fixed phrase, an opaque identifier
  with a closed grammar, or a declared-set member.

Character-shape validation is **structurally incapable** of enforcing the
boundary that matters: `alice` and `email` are the same regex language. The
per-field validator therefore checks **provenance** — the caller declares the
field names its own schema defines and the role labels its own policy defines,
and membership in a declared set is the test. No declaration, no field.

**Declared sets MUST NOT be derived from the wire** (round-1 critique). A
consumer that copies a received `withheld_fields` into
`declared_field_names` — or a producer that declares whatever it is about to
send — has converted the provenance check into `x ∈ {x}`. Declarations come
from the schema and policy definitions the caller owns, defined before and
independently of any message. The validator cannot see where an array came
from; this requirement is why it is stated here as a MUST.

The validator sits **on the emission path**, not beside it:
`placeDecisionMetadata` / `place_decision_metadata` validates the final
versioned value against the producer's declarations, then scans the merged
carrier for producer trust-assertion KEYS at every depth **except inside
another extension's namespace-keyed bag** (a URI- or URN-keyed value — that
vocabulary is not ours to police; policing it broke co-installed extensions in
an earlier revision), and holds every string value of **our own emitted
value** to the honesty guard (the integrator's own sibling prose is the
integrator's own claim). A producer cannot reach the wire around it through
this SDK. Recipient limitation is §3 (activation binding); content limitation
is this section; both are enforced by rejection, not by promise.

## 11. Verification — derived by the consumer, never asserted by the producer

There is exactly one authoritative verification value: the one the **consumer
derives** from checks it ran itself.

```
deriveVerificationStatus / derive_verification_status
  status: "unverified" | "structure_verified"
  basis:  the checks actually run (machine-readable)
  limits: fixed, always present:
    does_not_establish_issuer_identity
    does_not_establish_enforcement
    keyed_chain_verification_is_core_territory
```

- The vocabulary is deliberately capped at `structure_verified`. A keyless
  (LITE) consumer can validate the substate and recompute a receipt's internal
  structure (`verifySessionReceiptStructure`, `sessionDagRoot`); it **cannot**
  authenticate an issuer. `issuer_authenticated` is not a member of the type —
  a value this surface cannot prove is a value it cannot emit.
- Derivation rejects producer trust assertions **before** deriving, so
  "derived unverified, embedded `coreVerified: true`" is unrepresentable.
- A receipt that fails structural recomputation poisons the derivation to
  `unverified` regardless of everything else.

## 12. What carrying this extension proves — and never proves

Proves: a decision was **reported**, in a payload-value-omitting, structurally
checkable form, by whoever emitted it.

Never proves, and conforming text MUST NOT claim: that anything was
**enforced**; that the reporter is **Aegis**; that the task's data was
**protected**; that a receipt is **authentic**. Anyone can name this extension
URI and emit a structurally valid `outcome: PROTECTED`. Enforcement is a
property of the gateway path; authenticity is a property of keyed verification
(Core). The machine form of this section is the honesty guard + the producer
trust-assertion guard, both of which run at emission and at consumption.

## 13. Negative vectors (normative)

A conforming implementation MUST reject each of these, with the code shown —
all are pinned in the corpora:

| vector | code | corpus |
|---|---|---|
| unknown outcome / reason / illegal pair | `unknown_outcome` / `unknown_reason_code` / `illegal_outcome_reason_pair` | `a2a_mapping` |
| `APPROVAL_REQUIRED` without `fulfillment_owner` | `missing_fulfillment_owner` | `a2a_mapping` |
| metadata write without activation | `extension_not_activated` | `a2a_extension` |
| emission of `coreVerified: true` | `producer_trust_assertion` | `a2a_extension` |
| runtime string "Policy enforcement verified…" | `enforcement_claim_detected` | `a2a_extension` |
| bare "value-free" claim | `banned_claim_term` | `a2a_extension` |
| closure with no open obligation (pre-play) | `no_matching_open_obligation` | `a2a_reducer` |
| credential bound to a different nonce | `credential_binding_mismatch` | `a2a_reducer` |
| `resolved` without a credential | `credential_required` | `a2a_reducer` |
| re-opening a closed tuple | `obligation_key_reused` | `a2a_reducer` |
| event after a terminal state | `event_after_terminal` | `a2a_reducer` |
| `withheld_fields: ["alice"]` against a declared schema | `withheld_field_provenance_unknown` | `a2a_privacy` |
| free text in `reason_label` | `reason_label_not_fixed_phrase` | `a2a_privacy` |
| unknown substate key | `undeclared_metadata_field` | `a2a_privacy` |
| a person's name in `approver` | `approver_not_declared_role` | `a2a_privacy` |
| delivery to an unbound principal/channel | *(withheld marker, not an error)* | `a2a_privacy` |
| event with an unknown `kind` or `closure` | `unknown_event_kind` / `invalid_field_value` | `a2a_reducer` |
| `withheld_fields: ["alice"]` at EMISSION (documented flow) | `withheld_field_provenance_unknown` | `a2a_extension` |
| sibling `coreVerified` in the caller's own metadata at emission | `producer_trust_assertion` | `a2a_extension` |
| separator/width-disguised trust keys (`core.Verified`, zero-width, full-width) | `producer_trust_assertion` | `a2a_privacy` |
| poisoned stored binding (foreign URI / unknown channel) meeting a matching query | *(withheld marker)* | `a2a_privacy` |

## 14. A2A version matrix

| A2A pin | status |
|---|---|
| `a2aproject/A2A@0ef1b02` | **verified against** — `TaskState` 9 values, §4.6 extension rules, §7.6/§7.6.1 authorization semantics, §14.2.2 header, all read from this revision |
| earlier revisions treating `AUTH_REQUIRED` as authentication-only | **not supported** — the mapping's `APPROVAL_REQUIRED` rows depend on §7.6's authorization reading |
| future revisions | re-verify §4.6 (enum prohibition), §7.6.1 (MUST list), and the 9-value `TaskState` set before claiming support |

## 15. Quickstart (local checkout — nothing is published)

Node (from `node/`):

```ts
import { negotiateExtensions, mapDecisionToA2A, placeDecisionMetadata,
         AEGIS_A2A_EXTENSION_URI_V0 } from "@aegis-trust/sdk";

const negotiation = negotiateExtensions(request.headers["a2a-extensions"]);
const mapping = mapDecisionToA2A({ outcome: "ACCESS_REDUCED",
  reason_code: "minimum_disclosure", withheld_fields: ["email"] });
task.metadata = placeDecisionMetadata(task.metadata, mapping.substate, negotiation,
  { declared_field_names: MY_SCHEMA_FIELDS });  // provenance: YOUR schema, never the wire
// → task.metadata[AEGIS_A2A_EXTENSION_URI_V0] = { version: "v0", outcome: ... }
```

Python (from `python/`):

```python
from aegis_trust.a2a import negotiate_extensions, map_decision_to_a2a, place_decision_metadata

# Header NAME lookup must be case-insensitive (§2): HTTP frameworks usually
# do this for you; a plain dict or gRPC metadata (lowercased keys) does not.
header = next((v for k, v in request.headers.items()
               if k.lower() == "a2a-extensions"), None)
negotiation = negotiate_extensions(header)
mapping = map_decision_to_a2a({"outcome": "ACCESS_REDUCED",
    "reason_code": "minimum_disclosure", "withheld_fields": ["email"]})
task_metadata = place_decision_metadata(task_metadata, mapping.substate, negotiation,
    declared_field_names=MY_SCHEMA_FIELDS)  # provenance: YOUR schema, never the wire
```

Both refuse to write when the client did not opt in, refuse undeclared fields
and undeclared withheld names, refuse a sibling that impersonates our
verification output (while leaving the integrator's own generic fields and
other extensions' namespaced bags alone — see §8), and refuse
enforcement-claim strings in our own value — the refusals are the product.
