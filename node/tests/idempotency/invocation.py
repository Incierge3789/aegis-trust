#!/usr/bin/env python3
"""Invocation script for productization-ops idempotency_guarantee verifier.

The verifier copies this file to <package-dir>/.productization_idempotency_test.tmp
and runs it under python3 (it routes here because the file does not start with
the JS comment prefix and uses no CJS-style imports). cwd = sdk/node-trust.

This wrapper spawns the .mjs runner that exercises HistoryStore.recordIdempotent()
with a fixed idempotencyKey. After 1 initial + 100 retries, the state JSONL
file must remain byte-identical (exactly one record present).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SDK_DIR = Path(__file__).resolve().parent.parent.parent if "__file__" in globals() else Path.cwd()
if not (SDK_DIR / "dist" / "index.js").exists():
    # Fallback: assume cwd is the sdk dir (verifier sets cwd=package_dir).
    SDK_DIR = Path.cwd()

state_file = os.environ.get("AEGIS_IDEMPOTENCY_STATE_FILE")
if not state_file:
    print("AEGIS_IDEMPOTENCY_STATE_FILE env var not set", file=sys.stderr)
    sys.exit(1)

runner = SDK_DIR / "tests" / "idempotency" / "invocation_runner.mjs"
if not runner.exists():
    print(f"runner not found at {runner}", file=sys.stderr)
    sys.exit(1)

result = subprocess.run(
    ["node", str(runner)],
    cwd=str(SDK_DIR),
    capture_output=True,
    text=True,
    timeout=10,
    env={**os.environ, "AEGIS_IDEMPOTENCY_STATE_FILE": state_file},
)

if result.returncode != 0:
    print(result.stderr, file=sys.stderr)
    sys.exit(result.returncode)

print(result.stdout, end="")
