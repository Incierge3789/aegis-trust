#!/usr/bin/env python3
"""Mutation battery for the A2A mapping corpus (S027, T-003/T-017/T-018).

Why this exists: a conformance corpus that stays green when the shipped mapping
is wrong is worse than no corpus, because it reads as coverage. Each mutation
below injects a specific defect the plan's Failure Hypotheses name, runs the
corpus, and requires the corpus to FAIL. A mutation that stays green is a
vacuous oracle and is reported as such.

Run:  python3 scripts/a2a_mapping_mutation_battery.py
Exit: 0 only if every mutation was detected.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE_SRC = ROOT / "node" / "src" / "a2a" / "mapping.ts"
NODE_EXT = ROOT / "node" / "src" / "a2a" / "extension.ts"
PY_SRC = ROOT / "python" / "src" / "aegis_trust" / "a2a" / "mapping.py"
PY_EXT = ROOT / "python" / "src" / "aegis_trust" / "a2a" / "extension.py"
CORPUS = ROOT / "conformance" / "a2a_mapping.v0.json"

NODE_CMD = [
    "npx",
    "vitest",
    "run",
    "tests/a2aMappingCorpus.test.ts",
    "tests/a2aExtensionCorpus.test.ts",
]
PY_CMD = [
    ".venv/bin/pytest",
    "tests/test_a2a_mapping_corpus.py",
    "tests/test_a2a_extension_corpus.py",
    "-q",
]


def run(cmd: list[str], cwd: Path) -> bool:
    """True if the suite passed."""
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc.returncode == 0


def check_node() -> bool:
    return run(NODE_CMD, ROOT / "node")


def check_python() -> bool:
    return run(PY_CMD, ROOT / "python")


MUTATIONS: list[tuple[str, Path, str, str, str]] = [
    (
        "node: collapse the fulfillment_owner split (H-007/G1) — internal approval "
        "delegated to the client",
        NODE_SRC,
        'owner === "client" ? "TASK_STATE_AUTH_REQUIRED" : "TASK_STATE_WORKING"',
        '"TASK_STATE_AUTH_REQUIRED"',
        "node",
    ),
    (
        "node: make a correctable scope error terminal (F2)",
        NODE_SRC,
        'taskStateRecommendation: "TASK_STATE_INPUT_REQUIRED",',
        'taskStateRecommendation: "TASK_STATE_REJECTED",',
        "node",
    ),
    (
        "node: let the mapping declare the task successful (F3)",
        NODE_SRC,
        """    case "PROTECTED":
      return {
        taskStateRecommendation: null,""",
        """    case "PROTECTED":
      return {
        taskStateRecommendation: "TASK_STATE_WORKING",""",
        "node",
    ),
    (
        "node: accept illegal outcome x reason pairs (G5)",
        NODE_SRC,
        "  if (!LEGAL_PAIR_KEYS.has(`${outcome} ${reasonCode}`)) {",
        "  if (false && !LEGAL_PAIR_KEYS.has(`${outcome} ${reasonCode}`)) {",
        "node",
    ),
    (
        "node: drop a legal pair from the shipped set (H-001 required kill)",
        NODE_SRC,
        '  ["BLOCKED", "internal_failure"],\n',
        "",
        "node",
    ),
    (
        "python: collapse the fulfillment_owner split (H-007/G1)",
        PY_SRC,
        '"TASK_STATE_AUTH_REQUIRED"\n                if owner == "client"\n'
        '                else "TASK_STATE_WORKING"',
        '"TASK_STATE_AUTH_REQUIRED"',
        "python",
    ),
    (
        "python: reason_code no longer validated against the legal set (G5)",
        PY_SRC,
        'if f"{outcome} {reason_code}" not in _LEGAL_PAIR_KEYS:',
        "if False:",
        "python",
    ),
    (
        "python: leak an extra field into the substate (H-006 shape)",
        PY_SRC,
        'substate={"outcome": outcome, "reason_code": reason_code},\n        )\n\n    if outcome == "ACCESS_REDUCED":',
        'substate={"outcome": outcome, "reason_code": reason_code, "raw_reason": "leaked"},\n        )\n\n    if outcome == "ACCESS_REDUCED":',
        "python",
    ),
    (
        "node: honesty guard regresses to substring matching (H-003 paraphrase)",
        NODE_EXT,
        'const ASSURANCE_WORDS = [',
        'const ASSURANCE_WORDS: string[] = [] as string[]; const UNUSED_ASSURANCE = [',
        "node",
    ),
    (
        "node: extension activates without being requested (fail-open negotiation)",
        NODE_EXT,
        'return { activated: false, requested, reason: "not_requested", echo: [] };',
        "return { activated: true, requested, echo: [AEGIS_A2A_EXTENSION_URI_V0] };",
        "node",
    ),
    (
        "node: write extension metadata for a client that did not opt in",
        NODE_EXT,
        "  if (!negotiation.activated) {",
        "  if (false && !negotiation.activated) {",
        "node",
    ),
    (
        "node: placeholder identifier stops being detectable (H-005)",
        NODE_EXT,
        'const PLACEHOLDER_MARKERS = ["x-aegis-placeholder", "urn:x-"];',
        "const PLACEHOLDER_MARKERS: string[] = [];",
        "node",
    ),
    (
        "python: drop the banned-term check from the honesty guard",
        PY_EXT,
        '_BANNED_TERMS = ("value-free", "value free")',
        "_BANNED_TERMS: tuple[str, ...] = ()",
        "python",
    ),
    (
        "python: case-fold extension identifiers during negotiation",
        PY_EXT,
        "    if AEGIS_A2A_EXTENSION_URI_V0 not in requested:",
        "    if AEGIS_A2A_EXTENSION_URI_V0.lower() not in [r.lower() for r in requested]:",
        "python",
    ),
]


def main() -> int:
    print("baseline: both suites must be green before mutating")
    node_ok, py_ok = check_node(), check_python()
    print(f"  node={'green' if node_ok else 'RED'} python={'green' if py_ok else 'RED'}")
    if not (node_ok and py_ok):
        print("baseline is not green — fix that first")
        return 1

    results: list[tuple[str, bool]] = []
    for label, path, old, new, lang in MUTATIONS:
        original = path.read_text(encoding="utf-8")
        if old not in original:
            print(f"  [SKIP-ERROR] {label}: mutation anchor not found")
            results.append((label, False))
            continue
        try:
            path.write_text(original.replace(old, new, 1), encoding="utf-8")
            passed = check_node() if lang == "node" else check_python()
        finally:
            path.write_text(original, encoding="utf-8")
        detected = not passed
        results.append((label, detected))
        print(f"  [{'DETECTED' if detected else 'SURVIVED'}] {label}")

    # Corpus-side mutation: remove a legal pair's vector and require the
    # completeness oracle to notice.
    corpus_original = CORPUS.read_text(encoding="utf-8")
    data = json.loads(corpus_original)
    data["entries"] = [e for e in data["entries"] if e["id"] != "blocked_internal_failure"]
    try:
        CORPUS.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        node_passed, py_passed = check_node(), check_python()
    finally:
        CORPUS.write_text(corpus_original, encoding="utf-8")
    label = "corpus: drop the vector for a legal pair (H-001 required kill)"
    detected = not (node_passed or py_passed)
    results.append((label, detected))
    print(f"  [{'DETECTED' if detected else 'SURVIVED'}] {label}")

    survived = [label for label, ok in results if not ok]
    print(f"\nmutations: {len(results)}  detected: {len(results) - len(survived)}")
    if survived:
        print("SURVIVING MUTANTS (vacuous oracles):")
        for label in survived:
            print(f"  - {label}")
        return 1
    print("every injected defect was caught — the corpus is not vacuous")
    return 0


if __name__ == "__main__":
    sys.exit(main())
