# docs/security/ — security documentation index

| File | What it is |
|---|---|
| [`SECURITY_ASSESSMENT.md`](SECURITY_ASSESSMENT.md) | Latest tool-verified assessment: dependency audits (Python/Node), secrets scan, CI control inventory, findings with dispositions, accepted risks with deadlines |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Trust boundaries (LITE in-process vs FULL gateway), per-component STRIDE, threat→mitigation→test traceability |
| [`evidence/`](evidence/) | Raw tool logs backing the assessment (pip-audit / npm audit before+after, gitleaks) |

Policy / reporting / disclosure live in the root [`SECURITY.md`](../../SECURITY.md).

## Maintenance rules

1. **No hand-asserted claims.** Every statement of security state in
   `SECURITY_ASSESSMENT.md` must carry: exact command, tool version, exit
   code, and a committed raw log under `evidence/`.
2. **Before/after on every fix.** A dependency or control fix is recorded
   with both the failing log and the passing log.
3. **Accepted risks expire.** Each entry in §5 of the assessment names an
   owner-reviewable deadline (a sprint or "continuous" with the enforcing
   control named).
4. **Update cadence:** every security-family sprint, and immediately on any
   HIGH/CRITICAL finding (SECURITY.md disclosure baselines).
