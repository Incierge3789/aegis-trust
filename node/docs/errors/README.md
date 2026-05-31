# aegis-trust error code index

Every error thrown from `aegis-trust` is an instance of `AegisError`
(or a derived class) and carries three machine-parseable fields:

| Field | Purpose |
|---|---|
| `code` | Stable, dot-separated identifier (e.g. `aegis.shield.purpose.required`). Switch on this for retry / fallback. |
| `remediation` | One-line human/agent guidance for how to fix the input. |
| `docs_url` | Canonical URL for this code under `https://aegis-trust.dev/errors/<code>`. |

Errors are designed for agent retry: an agent that fails an `AegisValidationError`
can read `remediation`, fix its input, and retry without escalating to a human.

## Error classes

| Class | When | Base |
|---|---|---|
| `AegisError` | Base — catch this at the agent boundary. | `Error` |
| `AegisValidationError` | Input validation failure (`shield`, `wrap` purpose/scope/denyFields shape). | `AegisError` |
| `AegisConfigError` | `aegis.yaml` load / parse / shape problem. | `AegisError` |
| `AegisIngestError` | `shield/ingest` server response shape violation. | `AegisError` |
| `AegisAuditError` | `audit/verify` chain status response shape violation. | `AegisError` |
| `AegisHttpError` | Non-2xx HTTP response from aegis-core REST. Carries `status`. | `AegisError` |

## Error codes (v0.9.0-rc1)

**Cross-SDK contract (S018).** The `code` strings below are identical across
the Node and Python SDKs for the shared validation/config concepts, so a
polyglot consumer can switch on the same `code` regardless of language. The
**SDK** column records which SDK actually raises each code today:

- `both` — emitted by Node and Python with the same `code` string.
- `node` / `python` — emitted by one SDK only (a deliberate API difference,
  noted inline). These are not bugs to "fix to parity"; they reflect real
  differences in each SDK's surface (e.g. Python treats `purpose` as a free
  label and never rejects an empty one; Node types `mode` at compile time and
  has a sync-FULL guard the Python decorator does not need).

In Python every code below is carried by `AegisValidationError` /
`AegisConfigError`, both of which subclass the built-in `ValueError`, so
existing `except ValueError` callers keep working (backward-compat, S018 D2).

### shield / wrap input validation

| Code | SDK | Thrown when | Remediation |
|---|---|---|---|
| `aegis.shield.purpose.required` | node | `shield({ purpose: "" })` or non-string purpose. (Python treats `purpose` as a free label — no validation.) | Pass a non-empty string to `purpose`. |
| `aegis.wrap.purpose.required` | node | `wrap(value, { purpose: "" })` or non-string purpose. | Pass a non-empty string to `purpose`. |
| `aegis.wrap.spec.required` | node | `wrap(value, { purpose })` with neither `scope` nor `denyFields`. | Pass `scope` or `denyFields`. |
| `aegis.shield.spec.required` | both | `shield(purpose=...)` with neither `scope` nor `deny_fields` and no matching `aegis.yaml` purpose. | Pass `scope` (whitelist) or `deny_fields` (blacklist), or define the purpose in `aegis.yaml`. |
| `aegis.shield.spec.conflict` | python | `shield(purpose, scope=[...], deny_fields=[...])` — both supplied. (Node enforces this at the config layer as `aegis.config.purpose.scopeDenyConflict`.) | Use `scope` OR `deny_fields`, never both. |
| `aegis.shield.deny_fields.empty` | python | `shield(purpose, deny_fields=[])` — an empty deny list hides nothing. | Provide at least one field path, or use `scope`. |
| `aegis.shield.mode.invalid` | both | A `mode` string that is not `lite` / `full` / `auto`. | Use `lite` / `full` / `auto`, or the `Mode` enum. |
| `aegis.shield.mode.sync_full_unsupported` | node | `Mode.FULL` on a non-async wrapped function (no pre-execution await point to gate). | Declare the function `async` for FULL, or use LITE. |
| `aegis.shield.field_path.invalid` | python | A `scope` / `deny_fields` path is empty, has a leading/trailing dot, or consecutive dots. (Node validates field-path shape only inside `aegis.yaml` — see `aegis.config.fieldPath.invalid`.) | Use dot-notation like `profile.age`. |

### aegis.yaml config

All `aegis.config.*` codes below are emitted by **both** SDKs with identical
`code` strings (Python reached parity in S018 D2; before that the Python
loader raised raw `ValueError` / `FileNotFoundError` / `ImportError`).

| Code | Thrown when | Remediation |
|---|---|---|
| `aegis.config.yamlMissing` | `loadConfig()` and the optional `yaml` dep is not installed. | `npm install yaml` |
| `aegis.config.fileNotFound` | No `aegis.yaml` in CWD and `AEGIS_CONFIG` env not set, **or** an explicit path passed to `load_config(path)` / `loadConfig(path)` does not exist. | Create `aegis.yaml`, set `AEGIS_CONFIG`, or pass a path to an existing file. |
| `aegis.config.yamlParseError` | `yaml.parse()` failed on `aegis.yaml`. `cause` carries the parser exception. | Fix YAML syntax; run `yq . aegis.yaml` to locate the parse error. |
| `aegis.config.topLevel.notMapping` | YAML root is not a mapping. | Restructure as `purposes: { ... }`. |
| `aegis.config.purposes.notMapping` | `purposes` field is not a mapping. | Replace with `purposes: { support: { scope: [...] } }`. |
| `aegis.config.purpose.notMapping` | A purpose entry is not a mapping. | Each purpose entry must be a mapping. |
| `aegis.config.purpose.scopeDenyConflict` | Both `scope` and `deny_fields` set on one purpose. | Use one or the other, never both. |
| `aegis.config.purpose.empty` | Neither `scope` nor `deny_fields` set. | Add at least one. |
| `aegis.config.fields.notList` | `scope` / `deny_fields` is not a YAML list. | Use a YAML list. |
| `aegis.config.fields.elementNotString` | A list element is not a string. | Use string field paths. |
| `aegis.config.fieldPath.invalid` | A field path is not dot-separated identifiers. | Use `profile.address.city` form. |
| `aegis.config.denyFields.empty` | `deny_fields` is an empty list. | Remove the key or add entries. |

### Trace context (round 3 P0-6 hardening)

| Code | Class | Thrown when | Remediation |
|---|---|---|---|
| `aegis.trace.traceId.invalid` | `AegisValidationError` | `withTraceContext({ traceId: X }, ...)` passed a non-string or a value not matching `^[A-Za-z0-9._:-]{1,128}$`. Prevents secrets (Bearer tokens, API keys) leaking into the audit JSONL via traceId. | Use `newTraceId()` to generate a UUIDv4. Never pass raw secrets as traceId. |
| `aegis.trace.parentId.invalid` | `AegisValidationError` | `parentId` passed but does not match the traceId shape rules. | Same as above, or omit `parentId`. |

### Idempotent local audit (round 3 P0-2 hardening)

| Code | Class | Thrown when | Remediation |
|---|---|---|---|
| `aegis.audit.idempotencyKey.required` | `AegisAuditError` | `HistoryStore.recordIdempotent()` called with empty / non-string `idempotencyKey`. | Pass a non-empty string. |
| `aegis.audit.idempotencyKey.payloadDivergence` | `AegisAuditError` | Same `idempotencyKey` reused with a divergent payload (`function` / `purpose` / `scope` / `denyFields` / `blockedFields` / `mode` mismatch). Stripe-style semantics surface this as an error rather than silently dropping the retry. | Rotate the key for the new payload, or fix the caller so retries pass the same args. |

### AegisClient (FULL mode, HTTP / response shape)

Cross-review round 1 P0-2 fix (2026-05-17): the SDK's HTTP / response parse
errors now use typed errors so FULL-mode agents can `catch (AegisError)` and
switch on `code`. Previously these escaped as bare `Error` and broke the
"agent retry without human" story.

| Code | Class | Thrown when | Remediation |
|---|---|---|---|
| `aegis.http.nonOk` | `AegisHttpError` | Any aegis-core REST endpoint returns non-2xx. Carries `status`. | Inspect server logs; verify endpoint + token; retry if 5xx. |
| `aegis.ingest.responseShape` | `AegisIngestError` | `/shield/ingest` response shape (body / data / ingested / audit_seq_*) is malformed. | Server returned a malformed response. Check aegis-core version. |
| `aegis.audit.responseShape` | `AegisAuditError` | `/audit/verify` response shape (chain_valid / total_entries) is malformed. | Server returned a malformed response. Check aegis-core version. |

## Retry pattern (agent)

```typescript
import { AegisValidationError, shield } from "aegis-trust";

try {
  const safeFetch = shield({ purpose: agent.purpose, scope: agent.scope })(db.fetch);
  return await safeFetch(id);
} catch (e) {
  if (e instanceof AegisValidationError) {
    agent.log({
      code: e.code,
      remediation: e.remediation,
      docs_url: e.docs_url,
    });
    // Agent can self-correct using remediation, or fall back to a different
    // purpose / scope without escalating to a human.
    return null;
  }
  throw e;
}
```

## Stability

Error codes are part of the SDK's public contract. See [VERSIONING.md](../VERSIONING.md):

- v0.9.0-rc8 is a **preview** release (`STABILITY_LEVEL = "preview"`). Codes may
  change between rc tags without a major bump — every change will appear in
  CHANGELOG. Pin `aegis-trust@0.9.0-rc7` exactly if you switch on codes
  in production code paths.
- From v1.0.0 onward (stable): adding a new code is **additive** (no major
  bump); removing or renaming a code is **breaking** (major bump required).
- Free-text `message` is **not** part of the contract — switch on `code` only.
- Cross-review round 1 P1-E4 corrected (2026-05-17): earlier doc claimed
  "stable within v0.9.x" but the package is `preview`; fixed to match
  `STABILITY_LEVEL` in `src/index.ts`.
