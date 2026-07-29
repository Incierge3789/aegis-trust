# ruff 0.16.0 — deferred findings, triaged

`python/pyproject.toml` pins `ruff==0.15.22`. ruff 0.16.0 (released 2026-07-23)
enabled a much larger default rule set and reports **187 findings** against this
tree. The pin restored a deterministic gate; it did not make those findings go
away.

This file exists because "we'll handle it when Dependabot opens the PR" is not a
triage. Cross-review (codex + cursor, 2026-07-29) flagged the deferral as [P1]
and [P2] respectively on exactly that ground: deferred with no list, no
classification, and no owner is indistinguishable from suppressed.

**Reproduce the list:**

```bash
cd python && uvx ruff@0.16.0 check src/ tests/ --statistics
```

## The 187, classified

`[*]` = ruff can autofix. 47 of 187 are autofixable.

### A. Mechanical — take the autofix, no judgement needed (47)

| Count | Rule | Name |
|---:|---|---|
| 13 | I001 `[*]` | unsorted-imports |
| 9 | UP035 `[*]` | deprecated-import |
| 6 | RUF100 `[*]` | unused-noqa |
| 4 | UP037 `[*]` | quoted-annotation |
| 3 | RUF022 `[*]` | unsorted-dunder-all |
| 2 | PLR1711 `[*]` | useless-return |
| 2 | RET501 `[*]` | unnecessary-return-none |
| 1 | FURB122 `[*]` | for-loop-writes |
| 1 | PLR0402 `[*]` | manual-from-import |
| 1 | PLR1730 `[*]` | if-stmt-min-max |

RUF100 (unused-noqa) deserves a read rather than a blind fix: an unused `noqa`
often means the suppressed problem was fixed, but it can also mean the rule code
was renamed and the suppression silently stopped applying.

### B. Worth reading before deciding (78)

| Count | Rule | Name | Why it needs a look |
|---:|---|---|---|
| 58 | BLE001 | blind-except | The single biggest bucket. This codebase deliberately catches broadly in fail-closed paths (a hook or guard that raises must not take the caller down). Some of these are correct and want an explicit `# noqa: BLE001` with a reason; others are genuine over-broad catches that swallow real errors. Do not bulk-suppress. |
| 12 | PLW1510 | subprocess-run-without-check | `subprocess.run` without `check=` silently ignores a non-zero exit. In test harnesses and CI scripts this is the exact shape of a check that does not check. Highest real-defect density of any bucket here. |
| 4 | TRY004 | type-check-without-type-error | Raising the wrong exception class from a type guard. |
| 2 | S110 | try-except-pass | Silent swallow. Same family as BLE001, smaller. |
| 1 | RUF059 | unused-unpacked-variable | |
| 1 | UP028 | yield-in-for-loop | |

### C. Style / opinion — decide once, then configure (62)

| Count | Rule | Name |
|---:|---|---|
| 27 | N999 | invalid-module-name |
| 12 | SIM117 | multiple-with-statements |
| 9 | RUF012 | mutable-class-default |
| 6 | PYI036 | bad-exit-annotation |
| 4 | SIM102 | collapsible-if |
| 3 | B017 | assert-raises-exception |
| 3 | C408 | unnecessary-collection-call |
| 2 | PYI034 | non-self-return-type |
| 1 | SIM103 | needless-bool |

N999 (27) is almost certainly the generated client tree under
`src/aegis_trust/_generated/`, which is not ours to rename — that wants a
per-path exclusion in `pyproject.toml`, not 27 edits.

B017 (assert-raises-exception) is a test-quality signal worth honouring:
`pytest.raises(Exception)` passes on any failure, including the wrong one.

## Order of work

1. **B first, not A.** PLW1510 and BLE001 are where an actual defect would hide.
   A is cosmetic and can ride along at any time.
2. Configure C once (per-path excludes + explicit rule opt-outs with reasons in
   `pyproject.toml`), rather than editing 62 sites.
3. Then take the autofixes in A, review the RUF100 diff by hand.
4. Only then raise the pin. The pin moves when the tree is clean under the new
   version, not before.

## Owner

Unassigned. This lands as a Dependabot PR against `python/pyproject.toml`
(ecosystem `uv`, weekly). Whoever picks that PR up owns this list — the PR is
not mergeable by bumping the pin alone.
