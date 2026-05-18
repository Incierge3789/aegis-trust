# Security Policy

`aegis-trust` is built around a fail-closed principle: data should be unable to leak
even when the system fails. We treat security findings as first-class issues.

## Reporting a vulnerability

**Do not file a public issue. Vulnerabilities are reported privately first.**

Email `contact@aegisagentcontrol.com` with subject `[security] aegis-trust`.

Include:

- Affected version (`pip show aegis-trust`)
- Reproduction steps (minimal example)
- Expected vs actual behavior
- Which guarantee is violated, if applicable (see "Disclosure baselines" below)

We will acknowledge receipt within 48 hours and provide a remediation timeline within 7 days.

## Disclosure timeline

- **Day 0**: Report received, acknowledged
- **Day 1-7**: Triage, severity assessment, fix planning
- **Day 7-30**: Fix developed, tested, released as a patch version
- **Day 30+**: Public disclosure via CHANGELOG.md

For high-severity issues (CVSS >= 7.0), the timeline is compressed: fix within 7 days,
disclosure within 14.

## Disclosure baselines

| Type | Severity baseline |
|---|---|
| `@shield` returns more data than `scope` allows | **CRITICAL** (Minimum Disclosure violation) |
| `@shield` propagates exceptions containing user data | **HIGH** (fail-closed violation) |
| API keys readable from logs / error messages | **HIGH** (secrets hygiene violation) |
| Denial of service via unbounded resource consumption | **MEDIUM** |
| Dependency CVE in `aegis-trust` direct dependencies | **MEDIUM** to **CRITICAL** depending on exposure |

## Out of scope

- Vulnerabilities in user code that wraps `@shield` (we cannot enforce policy outside our boundary)
- Issues that require local code execution to exploit
- Issues in dependencies that are already publicly tracked (handled via dependency updates)

## Cryptographic posture

`aegis-trust` uses **OpenTimestamps (OTS)** over the Bitcoin blockchain to anchor CI
attestation timestamps. OTS provides tamper-evident chronology for release evidence.

**OTS is not a post-quantum cryptography (PQC) substitute.** OTS anchors hashes to
Bitcoin's proof-of-work chain, which relies on classical cryptographic assumptions
(SHA-256, ECDSA). These are not quantum-resistant. OTS is a pragmatic evidence-anchoring
mechanism for the pre-PQC era (through approximately 2030, per CNSA 2.0 timeline).

As of v0.6.4, attestation self-signatures use SHA-3-512 (NIST FIPS 202) as a bridging
measure toward full PQC migration.

## Memory posture (AO-005, SDK-side limits)

`aegis-trust` is a Python library. CPython does **not** offer deterministic,
prompt zeroization of in-memory secrets: references to `str` and `bytes`
objects may persist in caches, tracebacks, interpreter internals (small-int
and string interning), or garbage-collector generations after an explicit
`del`.

Therefore the SDK follows a **split-responsibility** model:

| Layer | Guarantee | Mechanism |
|---|---|---|
| **aegis-trust (Python SDK)** | Best-effort | `_clear_sensitive()`: overwrite `bytearray` buffers in place, drop references, force `gc.collect()`. Tokens are never stored outside the client instance. |
| **aegis-core (Rust gateway)** | Authoritative | Deterministic memory lifetime, `zeroize` crate for cryptographic material, no interning of secrets. |

For deployments where the SDK handles raw secrets (bearer tokens, sealed
payloads) on an untrusted host, the threat-model assumption is that the
gateway — not the SDK process — is the trust anchor. Keep the SDK process
short-lived, minimize the set of secrets it touches, and rely on the gateway
for any property stronger than "best effort."

Callers holding truly high-sensitivity material (e.g., master keys) should
use `bytearray` rather than `bytes`/`str` so the SDK can overwrite the buffer
after use.

## Supply chain

`aegis-trust` uses these supply-chain hardening practices:

- `requirements.lock` and `uv.lock` for deterministic dependency resolution
- `pip-audit` run on every CI build
- Automated dependency update tracking with explicit review before merge

## Verifying release integrity

Each release is tagged with `v<version>` (annotated tag).

```bash
pip show aegis-trust   # shows installed version
```

For production deployments requiring signed-release verification or attestation evidence,
email `contact@aegisagentcontrol.com`.

## Contact

- Security reports: `contact@aegisagentcontrol.com`
- Commercial / enterprise inquiries: `contact@aegisagentcontrol.com`
- Patent / licensing inquiries: `contact@aegisagentcontrol.com`
