#!/usr/bin/env python3
"""Mutation battery for the A2A increment-3 surfaces (S027, T-007/T-016/T-019/
T-020/T-022 + the T-008 emission guards).

Why this exists: a conformance corpus that stays green when the shipped code is
wrong is worse than no corpus, because it reads as coverage. Each mutation below
injects a defect the plan's Failure Hypotheses name — including the named
must-kill implementations (the H-008 tombstone reducer, the H-006
character-shape validator, the H-010 guardless derivation) — runs the relevant
corpus through the shipped code, and requires the corpus to FAIL. A mutation
that stays green is a vacuous oracle and is reported as such.

Run:  python3 scripts/a2a_increment3_mutation_battery.py
Exit: 0 only if every mutation was detected.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NODE_REDUCER = ROOT / "node" / "src" / "a2a" / "reducer.ts"
NODE_PRIVACY = ROOT / "node" / "src" / "a2a" / "privacy.ts"
NODE_VERIFY = ROOT / "node" / "src" / "a2a" / "verification.ts"
NODE_ACTIVATION = ROOT / "node" / "src" / "a2a" / "activation.ts"
NODE_EXT = ROOT / "node" / "src" / "a2a" / "extension.ts"
PY_REDUCER = ROOT / "python" / "src" / "aegis_trust" / "a2a" / "reducer.py"
PY_PRIVACY = ROOT / "python" / "src" / "aegis_trust" / "a2a" / "privacy.py"
PY_VERIFY = ROOT / "python" / "src" / "aegis_trust" / "a2a" / "verification.py"
PY_ACTIVATION = ROOT / "python" / "src" / "aegis_trust" / "a2a" / "activation.py"
PY_EXT = ROOT / "python" / "src" / "aegis_trust" / "a2a" / "extension.py"

SUITES: dict[str, tuple[list[str], Path]] = {
    "node:reducer": (
        ["npx", "vitest", "run", "tests/a2aReducerCorpus.test.ts"],
        ROOT / "node",
    ),
    "node:privacy": (
        ["npx", "vitest", "run", "tests/a2aPrivacyCorpus.test.ts"],
        ROOT / "node",
    ),
    "node:extension": (
        ["npx", "vitest", "run", "tests/a2aExtensionCorpus.test.ts"],
        ROOT / "node",
    ),
    "python:reducer": (
        [".venv/bin/pytest", "tests/test_a2a_reducer_corpus.py", "-q"],
        ROOT / "python",
    ),
    "python:privacy": (
        [".venv/bin/pytest", "tests/test_a2a_privacy_corpus.py", "-q"],
        ROOT / "python",
    ),
    "python:extension": (
        [".venv/bin/pytest", "tests/test_a2a_extension_corpus.py", "-q"],
        ROOT / "python",
    ),
    "node:mapping": (
        ["npx", "vitest", "run", "tests/a2aMappingCorpus.test.ts", "tests/a2aReducerCorpus.test.ts"],
        ROOT / "node",
    ),
    "python:mapping": (
        [".venv/bin/pytest", "tests/test_a2a_mapping_corpus.py", "tests/test_a2a_reducer_corpus.py", "-q"],
        ROOT / "python",
    ),
}


def suite_passes(suite: str) -> bool:
    cmd, cwd = SUITES[suite]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc.returncode == 0


# (label, file, old, new, suite-that-must-go-red)
MUTATIONS: list[tuple[str, Path, str, str, str]] = [
    (
        "node reducer: causal rule replaced by a tombstone (H-008 named kill — "
        "an early resolved is remembered instead of rejected)",
        NODE_REDUCER,
        """      reject(
        index,
        "no_matching_open_obligation",
        "No open obligation matches this closure; it is rejected, not remembered.",
      );
      return;""",
        """      obligations.set(id, { key: event.key, state: "resolved" });
      return;""",
        "node:reducer",
    ),
    (
        "node reducer: a denied/expired approval resumes the task (H-002 widening)",
        NODE_REDUCER,
        """    obligations.set(id, { key: existing.key, state: event.closure });
    unresolvedHalt = true;""",
        """    obligations.set(id, { key: existing.key, state: event.closure });
    working = true;""",
        "node:reducer",
    ),
    (
        "node reducer: terminal states un-freeze (H-002c)",
        NODE_REDUCER,
        """    if (terminal !== null) {
      reject(
        index,
        "event_after_terminal",""",
        """    if (false) {
      reject(
        index,
        "event_after_terminal",""",
        "node:reducer",
    ),
    (
        "node reducer: obligation identity drops the server nonce (6-field "
        "binding — the pre-played tuple becomes forgeable)",
        NODE_REDUCER,
        """    key.correlation_id,
    key.generation,
    key.server_nonce,
  ]);""",
        """    key.correlation_id,
    key.generation,
  ]);""",
        "node:reducer",
    ),
    (
        "node reducer: authorization request drops a 7.6.1 obligation "
        "(credential_receipt) from the substate (H-007 MUST kill)",
        NODE_REDUCER,
        '      credential_receipt: "out_of_band",\n',
        "",
        "node:reducer",
    ),
    (
        "python reducer: causal rule replaced by a tombstone (H-008 named kill)",
        PY_REDUCER,
        """            reject(
                index,
                "no_matching_open_obligation",
                "No open obligation matches this closure; it is rejected, not remembered.",
            )
            continue""",
        """            obligations[kid] = {"key": dict(key), "state": "resolved"}
            continue""",
        "python:reducer",
    ),
    (
        "python reducer: obligation identity drops the server nonce",
        PY_REDUCER,
        """        key["correlation_id"],
        key["generation"],
        key["server_nonce"],
    )""",
        """        key["correlation_id"],
        key["generation"],
    )""",
        "python:reducer",
    ),
    (
        "node privacy: provenance membership regresses to character shape "
        "(H-006 named kill — 'alice' is a perfectly-shaped field name)",
        NODE_PRIVACY,
        "      if (!declared.includes(f)) {",
        "      if (!OPAQUE_ID.test(f)) {",
        "node:privacy",
    ),
    (
        "node privacy: unknown keys stop being rejected (minimization off)",
        NODE_PRIVACY,
        "    if (!(k in OUTCOME_OF_FIELD)) {",
        "    if (false) {",
        "node:privacy",
    ),
    (
        "python privacy: reason_label free text passes (fixed-phrase check off)",
        PY_PRIVACY,
        '        "reason_label" in substate\n'
        '        and substate["reason_label"] != REASON_LABELS[reason_code]',
        "        False",
        "python:privacy",
    ),
    (
        "node verification: derivation skips the producer-assertion guard "
        "(H-010 named kill — derived status coexists with coreVerified:true)",
        NODE_VERIFY,
        '  assertNoProducerTrustAssertions(evidence.substate, "verification evidence substate");',
        "  void 0;",
        "node:privacy",
    ),
    (
        "python verification: key normalization off — case/separator variants "
        "of banned producer fields pass",
        PY_VERIFY,
        'return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", k).lower())',
        "return k",
        "python:privacy",
    ),
    (
        "node activation: delivery channel ignored (H-009 — request opt-in "
        "silently covers webhook push)",
        NODE_ACTIVATION,
        "      b.channel === query.channel,",
        "      true,",
        "node:privacy",
    ),
    (
        "node activation: withheld marker replaced by bare deletion (H-009 "
        "reverse — 'withheld from you' becomes 'no report exists')",
        NODE_ACTIVATION,
        """  const marker: WithheldMarker = {
    version: AEGIS_A2A_EXTENSION_VERSION,
    status: WITHHELD_STATUS,
    reason: "extension_not_activated_for_principal_on_channel",
  };
  return { ...source, [AEGIS_A2A_EXTENSION_URI_V0]: marker };""",
        """  const { [AEGIS_A2A_EXTENSION_URI_V0]: _omit, ...rest } = source;
  return rest;""",
        "node:privacy",
    ),
    (
        "python activation: principal ignored — one principal's opt-in reads "
        "as everyone's (H-009 core)",
        PY_ACTIVATION,
        '        and b.get("principal") == principal\n',
        "",
        "python:privacy",
    ),
    (
        "node extension: emission guards removed (T-008 — the SDK becomes the "
        "producer of the self-report its consumer side rejects)",
        NODE_EXT,
        """  assertNoProducerTrustAssertions(substate, "decision substate");
""",
        "",
        "node:extension",
    ),
    (
        "python extension: emission guards removed (T-008)",
        PY_EXT,
        """    assert_no_producer_trust_assertions(dict(substate), "decision substate")
""",
        "",
        "python:extension",
    ),
    # ---- round-1 critique mutants (cursor + codex findings, now pinned) ----
    (
        "node reducer: kind check removed — every non-decision event walks the "
        "closure path (round-1 cursor P0)",
        NODE_REDUCER,
        'if ((event as { kind?: unknown }).kind !== "obligation") {',
        "if (false) {",
        "node:reducer",
    ),
    (
        "node extension: emission skips the privacy validator (round-1 both "
        "vendors P0 — 'alice' reaches the wire through the documented flow)",
        NODE_EXT,
        "  validateDecisionSubstate(value, provenance ?? {});\n",
        "",
        "node:extension",
    ),
    (
        "python extension: emission skips the privacy validator (round-1 P0)",
        PY_EXT,
        """    validate_decision_substate(
        value,
        declared_field_names=declared_field_names,
        approver_roles=approver_roles,
    )
""",
        "",
        "python:extension",
    ),
    (
        "node extension: output smuggles a sibling coreVerified (round-1 codex "
        "P1 — the exact corpus/battery survivor, now killed by the full-output "
        "pin and the carrier rescan)",
        NODE_EXT,
        """  const merged = {
    ...(metadata ?? {}),
    [AEGIS_A2A_EXTENSION_URI_V0]: value,
  };""",
        """  const merged = {
    ...(metadata ?? {}),
    coreVerified: true,
    [AEGIS_A2A_EXTENSION_URI_V0]: value,
  };""",
        "node:extension",
    ),
    (
        "node verification: normalizer regresses to _/- stripping (round-1 "
        "cursor/codex — dot, zero-width and full-width keys pass again)",
        NODE_VERIFY,
        'k.normalize("NFKC").toLowerCase().replace(/[^a-z0-9]/g, "")',
        'k.toLowerCase().replace(/[_-]/g, "")',
        "node:privacy",
    ),
    (
        "python verification: banned-key list loses 'trusted' (round-1 cursor "
        "P2 — per-entry negatives make list edits detectable)",
        PY_VERIFY,
        '    "trusted",\n',
        "",
        "python:privacy",
    ),
    (
        "node verification: banned-key list loses 'trusted'",
        NODE_VERIFY,
        '  "trusted",\n',
        "",
        "node:privacy",
    ),
    (
        "node activation: stored bindings are trusted raw (round-1 codex P0 — "
        "a poisoned persistence record on an undeclared channel matches a "
        "same-shaped query)",
        NODE_ACTIVATION,
        "      isWellFormedBinding(b) &&\n",
        "",
        "node:privacy",
    ),
    (
        "python activation: stored bindings are trusted raw (round-1 codex P0)",
        PY_ACTIVATION,
        "        _is_well_formed_binding(b)\n        and ",
        "        ",
        "python:privacy",
    ),
    (
        "node extension: honesty negation window regresses to "
        "anywhere-in-±60 (round-1 both vendors — trailing and borrowed "
        "negations launder claims again)",
        NODE_EXT,
        """    const negationFrom = Math.max(segmentStart(lowered, at), at - NEGATION_WINDOW);
    const negationWindow = lowered.slice(negationFrom, at + assurance.length);
    if (NEGATIONS.some((negation) => negationWindow.includes(negation))) continue;""",
        """    if (NEGATIONS.some((negation) => window.includes(negation))) continue;""",
        "node:extension",
    ),
    # ---- round-2 critique mutants ----
    (
        "python extension: honesty negation window regresses (round-2 cursor "
        "P2 — the round-1 window mutant existed only for Node)",
        PY_EXT,
        """        negation_from = max(_segment_start(lowered, at), at - _NEGATION_WINDOW)
        negation_window = lowered[negation_from : at + len(assurance)]
        if any(negation in negation_window for negation in _NEGATIONS):
            continue""",
        """        if any(negation in window for negation in _NEGATIONS):
            continue""",
        "python:extension",
    ),
    (
        "node extension: comma stops being a clause boundary (round-2 codex — "
        "'does not log, policy enforced' launders again)",
        NODE_EXT,
        "const SENTENCE_BOUNDARY = /[.;!?,]/;",
        "const SENTENCE_BOUNDARY = /[.;!?]/;",
        "node:extension",
    ),
    (
        "python extension: comma stops being a clause boundary (round-2 codex)",
        PY_EXT,
        '_SENTENCE_BOUNDARY = ".;!?,"',
        '_SENTENCE_BOUNDARY = ".;!?"',
        "python:extension",
    ),
    (
        "node extension: carrier scan regresses to deep-everything (round-2 "
        "both vendors — co-installed extensions and honest sibling prose break)",
        NODE_EXT,
        """  assertNoProducerTrustAssertionsScoped(merged, "decision metadata carrier");
  assertHonestRuntimeStrings(value, "decision metadata value");""",
        """  assertNoProducerTrustAssertions(merged, "decision metadata carrier");
  assertHonestRuntimeStrings(merged, "decision metadata carrier");""",
        "node:extension",
    ),
    (
        "python extension: carrier scan regresses to deep-everything (round-2)",
        PY_EXT,
        """    assert_no_producer_trust_assertions_scoped(merged, "decision metadata carrier")
    _assert_honest_runtime_strings(value, "decision metadata value")""",
        """    assert_no_producer_trust_assertions(merged, "decision metadata carrier")
    _assert_honest_runtime_strings(merged, "decision metadata carrier")""",
        "python:extension",
    ),
    (
        "node reducer: authorization request loses obligation_status (round-2 "
        "both vendors — the poller-distinguishability signal vanishes silently)",
        NODE_REDUCER,
        '      obligation_status: "open",\n',
        "",
        "node:reducer",
    ),
    (
        "node reducer: malformed-event guard removed (round-2 codex — a null "
        "event crashes the reduction instead of being refused per-event)",
        NODE_REDUCER,
        'if (typeof event !== "object" || event === null || Array.isArray(event)) {',
        "if (false) {",
        "node:reducer",
    ),
    # ---- round-3 challenge mutants ----
    (
        "node extension: carrier scan reverts to top-level keys only (round-3 "
        "cursor P1 — the depth-1 courier hole reopens: notes.coreVerified rides)",
        NODE_VERIFY,
        "      if (isNamespaceKey(k)) continue; // another extension's bag — opaque\n      walk(v, `${path}.${k}`);",
        "      // shallow: do not recurse",
        "node:extension",
    ),
    (
        "python extension: carrier scan reverts to top-level keys only (round-3)",
        PY_VERIFY,
        "            if isinstance(k, str) and _is_namespace_key(k):\n                continue\n            walk(v, f\"{path}.{k}\")",
        "            continue",
        "python:extension",
    ),
    (
        "node extension: honesty guard drops NFKC (round-3 cursor P1 — full-width "
        "'verified' bypasses again)",
        NODE_EXT,
        'const lowered = text.normalize("NFKC").toLowerCase();',
        "const lowered = text.toLowerCase();",
        "node:extension",
    ),
    (
        "python extension: honesty guard drops NFKC (round-3 cursor P1)",
        PY_EXT,
        'lowered = unicodedata.normalize("NFKC", text).lower()',
        "lowered = text.lower()",
        "python:extension",
    ),
    (
        "node extension: honesty subjects revert to substring (round-3 cursor P1 "
        "— 'access' fires inside 'inaccessible' etc., a false positive regression)",
        NODE_EXT,
        "const SUBJECT_RE = new RegExp(`\\\\b(?:${CLAIM_SUBJECTS.map(escapeRe).join(\"|\")})\\\\b`);",
        "const SUBJECT_RE = new RegExp(`(?:${CLAIM_SUBJECTS.map(escapeRe).join(\"|\")})`);",
        "node:extension",
    ),
    (
        "python privacy: generation rejects integral floats (round-3 cursor P1 — "
        "JSON 1.0 diverges from Node again)",
        PY_PRIVACY,
        """    if isinstance(gen, float):
        return gen.is_integer() and gen >= 1
    return False""",
        """    if isinstance(gen, float):
        return False
    return False""",
        "python:privacy",
    ),
    (
        "node reducer: resolve drops unresolvedHalt (round-3 cursor P2 required "
        "kill — reject A then resolve B resumes without approval)",
        NODE_REDUCER,
        "      if (!stillOpen && !unresolvedHalt) {",
        "      unresolvedHalt = false;\n      if (!stillOpen) {",
        "node:reducer",
    ),
    (
        "python reducer: resolve drops unresolvedHalt (round-3 cursor P2 kill)",
        PY_REDUCER,
        "            if not still_open and not unresolved_halt:",
        "            unresolved_halt = False\n            if not still_open:",
        "python:reducer",
    ),
    # ---- round-3 codex challenge mutants ----
    (
        "node reducer: checkpoint ignores prior_unresolved_halt (round-3 codex "
        "P1 — a denial hidden behind an open sibling resumes across restore)",
        NODE_REDUCER,
        "    input.prior_unresolved_halt ??\n    (input.prior_state === \"TASK_STATE_AUTH_REQUIRED\" &&",
        "    (false ??\n    (input.prior_state === \"TASK_STATE_AUTH_REQUIRED\" &&",
        "node:reducer",
    ),
    (
        "python reducer: checkpoint ignores prior_unresolved_halt (round-3 codex P1)",
        PY_REDUCER,
        "    if prior_unresolved_halt is not None:\n        unresolved_halt = prior_unresolved_halt",
        "    if False:\n        unresolved_halt = prior_unresolved_halt",
        "python:reducer",
    ),
    (
        "node mapping: null decision crashes instead of unknown_outcome (round-3 "
        "codex P1 — TypeError aborts the whole event stream)",
        NODE_REDUCER.parent / "mapping.ts",
        'if (typeof decision !== "object" || decision === null || Array.isArray(decision)) {',
        "if (false) {",
        "node:mapping",
    ),
    (
        "python mapping: non-mapping decision crashes (round-3 codex P1)",
        PY_REDUCER.parent / "mapping.py",
        "    if not isinstance(decision, Mapping):",
        "    if False and not isinstance(decision, Mapping):",
        "python:mapping",
    ),
    (
        "node mapping: string withheld_fields spreads to chars (round-3 codex P1 "
        "— ['s','s','n'] ships as field names, diverging from Python)",
        NODE_REDUCER.parent / "mapping.ts",
        '!Array.isArray(wf) || wf.some((f) => typeof f !== "string" || f.length === 0)',
        "false",
        "node:mapping",
    ),
    (
        "python mapping: empty withheld element accepted (round-3 codex P1 parity)",
        PY_REDUCER.parent / "mapping.py",
        "                or any(not isinstance(f, str) or not f for f in withheld)",
        "",
        "python:mapping",
    ),
    (
        "node verification: carrier scan widens to the full list (round-3 codex "
        "P2 — a generic 'authenticated' sibling is now over-blocked)",
        NODE_VERIFY,
        "      if (CARRIER_IMPERSONATION_KEYS.includes(normalizeKey(k))) {",
        "      if (PRODUCER_TRUST_ASSERTION_KEYS.includes(normalizeKey(k))) {",
        "node:extension",
    ),
    (
        "python verification: carrier scan widens to the full list (round-3 codex P2)",
        PY_VERIFY,
        "            if isinstance(k, str) and _normalize_key(k) in CARRIER_IMPERSONATION_KEYS:",
        "            if isinstance(k, str) and _normalize_key(k) in PRODUCER_TRUST_ASSERTION_KEYS:",
        "python:extension",
    ),
    (
        "node extension: 'establishes' returns to the vocabulary (round-3 codex "
        "— reopens the 'policy establishes the document format' false positive)",
        NODE_EXT,
        '  "blocks",\n  "prevents",\n];',
        '  "blocks",\n  "prevents",\n  "establishes",\n];',
        "node:extension",
    ),
]


def main() -> int:
    print("baseline: all six suites must be green before mutating")
    baseline = {name: suite_passes(name) for name in SUITES}
    for name, ok in baseline.items():
        print(f"  {name}={'green' if ok else 'RED'}")
    if not all(baseline.values()):
        print("baseline is not green — fix that first")
        return 1

    results: list[tuple[str, bool]] = []
    for label, path, old, new, suite in MUTATIONS:
        original = path.read_text(encoding="utf-8")
        if old not in original:
            print(f"  [SKIP-ERROR] {label}: mutation anchor not found")
            results.append((label, False))
            continue
        try:
            path.write_text(original.replace(old, new, 1), encoding="utf-8")
            passed = suite_passes(suite)
        finally:
            path.write_text(original, encoding="utf-8")
        detected = not passed
        results.append((label, detected))
        print(f"  [{'DETECTED' if detected else 'SURVIVED'}] {label}")

    survived = [label for label, detected in results if not detected]
    print()
    print(f"mutations: {len(results)}  detected: {len(results) - len(survived)}  survived: {len(survived)}")
    if survived:
        print("VACUOUS ORACLES — these mutations were not caught:")
        for label in survived:
            print(f"  - {label}")
        return 1
    print("all mutations detected — the corpus is a live oracle for these defects")
    return 0


if __name__ == "__main__":
    sys.exit(main())
