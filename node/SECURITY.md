# Security Policy

`aegis-trust` is built around a fail-closed principle: data should be unable to leak even when the system fails. We treat security findings as first-class issues.

## Reporting a vulnerability

**Do not file a public issue. Vulnerabilities are reported privately first.**

Email `contact@aegisagentcontrol.com` with subject `[security] aegis-trust`.

Include:

- Affected version (`npm ls aegis-trust`)
- Reproduction steps (minimal example)
- Expected vs actual behavior
- Which guarantee is violated, if applicable (see "Disclosure baselines" below)

We will acknowledge receipt within 48 hours and provide a remediation timeline within 7 days.

## Disclosure timeline

- **Day 0**: Report received, acknowledged
- **Day 1-7**: Triage, severity assessment, fix planning
- **Day 7-30**: Fix developed, tested, released as a patch version
- **Day 30+**: Public disclosure via CHANGELOG.md

For high-severity issues (CVSS >= 7.0), the timeline is compressed: fix within 7 days, disclosure within 14.

## Disclosure baselines

| Type | Severity baseline |
|---|---|
| `shield(...)` returns more data than `scope` allows | **CRITICAL** (Minimum Disclosure violation) |
| `shield(...)` propagates exceptions containing user data | **HIGH** (fail-closed violation) |
| `AegisClient` tokens readable from logs / error messages | **HIGH** (secrets hygiene violation) |
| `authorize()` returns true on malformed 200 body | **CRITICAL** (AO-003 fail-closed violation) |
| Denial of service via unbounded resource consumption | **MEDIUM** |
| Dependency CVE in direct dependencies | **MEDIUM** to **CRITICAL** depending on exposure |

## Out of scope

- Vulnerabilities in user code that wraps `shield(...)` (we cannot enforce policy outside our boundary)
- Issues that require local code execution to exploit
- Issues in dependencies that are already publicly tracked (handled via dependency updates)

## TLS posture

`AegisClient` honours a **TLS prod-lock** (AO-001 / AO-005): the `verifySsl: false` option is ignored unless **both** of the following hold:

1. Target host is in the dev allow-list (`localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, `*.local`).
2. Environment variable `AEGIS_DEV_INSECURE=1` is set.

Any other case forces TLS verification on, even if the caller passes `verifySsl: false`. This is non-negotiable; the only escape is the explicit pair above.

Note: Node's global fetch honours `NODE_TLS_REJECT_UNAUTHORIZED=0` if set. Using that env to disable TLS verification system-wide is **not recommended** — it affects every fetch in the process, not just AegisClient. The prod-lock above is the supported path.

## Memory posture (AO-005, SDK-side limits)

`aegis-trust` is a Node.js library. V8 / Node do **not** offer deterministic, prompt zeroization of in-memory secrets: references to strings may persist in caches, V8 interning, garbage-collector generations, or backtraces after explicit `delete` or reassignment.

Therefore the SDK follows a **split-responsibility** model:

| Layer | Guarantee | Mechanism |
|---|---|---|
| **aegis-trust (Node SDK)** | Best-effort | Tokens stored only on `AegisClient` instance; `setToken` discards old token reference and clears access cache. |
| **aegis-core (Rust gateway)** | Authoritative | Deterministic memory lifetime, `zeroize` crate for cryptographic material, no interning of secrets. |

For deployments where the SDK handles raw secrets (bearer tokens, sealed payloads) on an untrusted host, the threat-model assumption is that the gateway — not the SDK process — is the trust anchor. Keep the SDK process short-lived, minimize the set of secrets it touches, and rely on the gateway for any property stronger than "best effort."

## Supply chain

`aegis-trust` has zero runtime dependencies in Lite mode. `yaml` is an optional dependency for YAML config loading only — declared in `optionalDependencies` so `npm install aegis-trust` does not pull it unless requested.

Build-time:

- `package-lock.json` for deterministic dependency resolution
- `npm audit` recommended on every CI build
- Use `npm ci` (not `npm install`) in CI to enforce the lock file

## Verifying release integrity

Each release is tagged `v<version>` in the source repository.

```bash
npm ls aegis-trust   # shows installed version
npm view aegis-trust dist.shasum   # registry-recorded shasum
```

For production deployments requiring signed-release verification or attestation evidence, email `contact@aegisagentcontrol.com`.

## Contact

- Security reports: `contact@aegisagentcontrol.com`
- Commercial / enterprise inquiries: `contact@aegisagentcontrol.com`
- Patent / licensing inquiries: `contact@aegisagentcontrol.com`
