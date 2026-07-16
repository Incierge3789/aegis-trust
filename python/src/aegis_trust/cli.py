"""aegis CLI — local history inspection.

Usage:
    aegis history [--limit N] [--purpose PURPOSE]
    aegis stats
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

from aegis_trust.history import HistoryStore


def _get_db_path() -> str:
    return os.environ.get(
        "AEGIS_HISTORY_PATH",
        str(Path.home() / ".aegis" / "history.db"),
    )


def _open_store() -> HistoryStore | None:
    db_path = _get_db_path()
    if not os.path.exists(db_path):
        print(f"No history database found at {db_path}")
        print("Enable history with: AEGIS_HISTORY=1")
        return None
    try:
        return HistoryStore(db_path)
    except sqlite3.Error:
        # Not a SQLite database (e.g. AEGIS_HISTORY_PATH points at the Node
        # SDK's history.jsonl, which shares the env var name but not the
        # format). Inspection commands must hint, not stack-trace.
        print(f"History file at {db_path} is not a SQLite database.")
        print(
            "If this is the Node SDK's history.jsonl, inspect it with "
            "`npx aegis history` instead."
        )
        return None


def cmd_history(args: argparse.Namespace) -> int:
    """Print recent ``@shield`` invocation history.

    Reads from the local SQLite store (default ``~/.aegis/history.db``,
    overridable via ``AEGIS_HISTORY_PATH``). Returns 0 on success, 1 if no
    history database exists.
    """
    store = _open_store()
    if store is None:
        return 1
    records = store.get_history(limit=args.limit, purpose=args.purpose)
    store.close()

    if not records:
        print("No history records found.")
        return 0

    # Header
    print(
        f"{'ID':>5}  {'Function':<25} {'Purpose':<15} {'Blocked':<30} {'Timestamp':<25}"
    )
    print("-" * 105)

    for r in records:
        blocked = ", ".join(r.blocked_fields) if r.blocked_fields else "-"
        ts = r.timestamp[:19] if len(r.timestamp) > 19 else r.timestamp
        print(f"{r.id:>5}  {r.function:<25} {r.purpose:<15} {blocked:<30} {ts:<25}")

    print(f"\n{len(records)} record(s) shown.")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Print aggregated ``@shield`` statistics from local history.

    Shows total call count, blocked field totals, per-purpose summaries, and
    per-field block counts. Returns 0 on success, 1 if no history database exists.
    """
    store = _open_store()
    if store is None:
        return 1
    stats = store.get_stats()
    store.close()

    if stats["total_calls"] == 0:
        print("No history records found.")
        return 0

    print(f"Total calls: {stats['total_calls']}")
    print(f"Total blocked fields: {stats['total_blocked_fields']}")

    if stats["by_purpose"]:
        print(f"\n{'Purpose':<20} {'Calls':>8} {'Blocked':>8}")
        print("-" * 40)
        for purpose, data in sorted(stats["by_purpose"].items()):
            print(f"{purpose:<20} {data['calls']:>8} {data['blocked']:>8}")

    if stats["by_field"]:
        print(f"\n{'Field':<30} {'Blocked Count':>15}")
        print("-" * 48)
        for field, count in sorted(
            stats["by_field"].items(), key=lambda x: x[1], reverse=True
        ):
            print(f"{field:<30} {count:>15}")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and dispatch to the correct subcommand.

    Returns the subcommand's exit code, or 0 when no subcommand is given
    (prints help in that case).
    """
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="aegis-trust CLI — local history inspection",
    )
    subparsers = parser.add_subparsers(dest="command")

    # aegis history
    hist_parser = subparsers.add_parser("history", help="Show recent filtering history")
    hist_parser.add_argument(
        "--limit", "-n", type=int, default=20, help="Number of records (default: 20)"
    )
    hist_parser.add_argument(
        "--purpose", "-p", type=str, default=None, help="Filter by purpose"
    )

    # aegis stats
    subparsers.add_parser("stats", help="Show aggregated statistics")

    args = parser.parse_args(argv)

    if args.command == "history":
        return cmd_history(args)
    elif args.command == "stats":
        return cmd_stats(args)
    else:
        parser.print_help()
        return 0


def cli_entry() -> None:
    """Entry point used by the ``aegis`` console script (see ``pyproject.toml``)."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    # `python -m aegis_trust.cli` must behave like the `aegis` console script.
    # Without this guard the module invocation was a silent no-op with exit 0 —
    # the same silent-exit class the Node CLI fixed in PR #4.
    cli_entry()
