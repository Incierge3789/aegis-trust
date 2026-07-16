#!/usr/bin/env node
// aegis CLI — local history inspection.
//
// Usage:
//   aegis history [--limit N] [--purpose P]
//   aegis stats

import { appendFileSync, existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { HistoryStore } from "./history.js";
import { shield } from "./shield.js";

function getDbPath(): string {
  return process.env.AEGIS_HISTORY_PATH
    ?? join(homedir(), ".aegis", "history.jsonl");
}

function openStore(): HistoryStore | null {
  const dbPath = getDbPath();
  if (!existsSync(dbPath)) {
    console.log(`No history database found at ${dbPath}`);
    console.log("Enable history with: AEGIS_HISTORY=1");
    return null;
  }
  return new HistoryStore(dbPath);
}

function pad(s: string, n: number, right = false): string {
  // Pad only, never truncate (Python `f"{x:<n}"` parity): a truncated
  // Blocked column made blocked fields disappear from the audit view,
  // which reads as "this field was disclosed" — the opposite of the truth.
  if (s.length >= n) return s;
  const fill = " ".repeat(n - s.length);
  return right ? fill + s : s + fill;
}

function cmdHistory(args: { limit: number; purpose?: string }): number {
  const store = openStore();
  if (!store) return 1;
  const records = store.getHistory({ limit: args.limit, purpose: args.purpose });
  store.close();

  if (records.length === 0) {
    console.log("No history records found.");
    return 0;
  }

  console.log(
    `${pad("ID", 5, true)}  ${pad("Function", 25)} ${pad("Purpose", 15)} `
      + `${pad("Blocked", 30)} ${pad("Timestamp", 25)}`,
  );
  console.log("-".repeat(105));

  for (const r of records) {
    const blocked = r.blockedFields.length > 0 ? r.blockedFields.join(", ") : "-";
    const ts = r.timestamp.length > 19 ? r.timestamp.slice(0, 19) : r.timestamp;
    console.log(
      `${pad(String(r.id), 5, true)}  ${pad(r.function, 25)} `
        + `${pad(r.purpose, 15)} ${pad(blocked, 30)} ${pad(ts, 25)}`,
    );
  }

  console.log(`\n${records.length} record(s) shown.`);
  return 0;
}

function cmdSandbox(): number {
  // Run the 10-second aegis-trust sandbox demo (dummy data, no infra):
  //   npm install aegis-trust && npx aegis sandbox
  // Node-only command: the Python `aegis` CLI has no sandbox subcommand
  // (it offers history/stats only) — do not claim a mirror that isn't there.

  const dummyUser: Record<string, unknown> = {
    user_id: "u_123",
    name: "Aria Sato",
    email: "aria@example.com",
    phone: "+81-80-1111-2222",
    ssn: "234-56-7890",
    credit_card: "5555-****-****-4242",
    plan: "pro",
    last_login: "2026-05-15T08:23:00Z",
    internal_notes: "VIP, do not contact about renewals",
  };

  const getUser = shield({
    purpose: "customer_support",
    scope: ["user_id", "plan", "last_login"],
  })((..._args: unknown[]) => dummyUser);

  console.log("Aegis sandbox demo");
  console.log("─".repeat(60));
  console.log();
  console.log("1. Source record:");
  for (const k of Object.keys(dummyUser).sort()) {
    console.log(`     ${k}: ${dummyUser[k]}`);
  }
  console.log();
  console.log("2. Agent request:");
  console.log('     getUser("u_123")   under purpose="customer_support"');
  console.log();

  const result = getUser("u_123") as Record<string, unknown>;
  const blocked = Object.keys(dummyUser).filter((k) => !(k in result)).sort();
  const auditPath = process.env.AEGIS_SANDBOX_AUDIT
    ?? resolve(process.cwd(), "aegis-sandbox-audit.jsonl");
  const entry = {
    timestamp: new Date().toISOString(),
    agent: "support_agent",
    purpose: "customer_support",
    requested_id: "u_123",
    allowed_fields: Object.keys(result).sort(),
    blocked_fields: blocked,
    decision: "filtered",
    reason: "fields outside declared scope",
  };
  appendFileSync(auditPath, JSON.stringify(entry) + "\n");

  console.log("3. Aegis decision:");
  console.log("     ┌────────────────────────────────────────────────────────┐");
  console.log("     │ Agent:        support_agent");
  console.log("     │ Purpose:      customer_support");
  console.log(`     │ Requested:    ${Object.keys(dummyUser).sort().join(", ")}`);
  console.log(`     │ ✓ Allowed:    ${Object.keys(result).sort().join(", ")}`);
  console.log(`     │ ✗ Blocked:    ${blocked.join(", ")}`);
  console.log("     │ Decision:     filtered");
  console.log(`     │ Audit:        ${auditPath}`);
  console.log("     └────────────────────────────────────────────────────────┘");
  console.log();
  console.log("4. What the agent actually sees:");
  console.log(`     ${JSON.stringify(result, null, 2).split("\n").join("\n     ")}`);
  console.log();
  console.log("5. Use in your own code:");
  console.log('     import { shield } from "aegis-trust";');
  console.log("     const fn = shield({ purpose: \"...\", scope: [\"a\", \"b\"] })(yourTool);");
  console.log();
  console.log(`To delete sandbox artifacts:  rm ${auditPath}`);
  return 0;
}

function cmdStats(): number {
  const store = openStore();
  if (!store) return 1;
  const stats = store.getStats();
  store.close();

  if (stats.totalCalls === 0) {
    console.log("No history records found.");
    return 0;
  }

  console.log(`Total calls: ${stats.totalCalls}`);
  console.log(`Total blocked fields: ${stats.totalBlockedFields}`);

  const purposes = Object.entries(stats.byPurpose);
  if (purposes.length > 0) {
    console.log(`\n${pad("Purpose", 20)} ${pad("Calls", 8, true)} ${pad("Blocked", 8, true)}`);
    console.log("-".repeat(40));
    purposes.sort(([a], [b]) => a.localeCompare(b));
    for (const [purpose, data] of purposes) {
      console.log(
        `${pad(purpose, 20)} ${pad(String(data.calls), 8, true)} ${pad(String(data.blocked), 8, true)}`,
      );
    }
  }

  const fields = Object.entries(stats.byField);
  if (fields.length > 0) {
    console.log(`\n${pad("Field", 30)} ${pad("Blocked Count", 15, true)}`);
    console.log("-".repeat(48));
    fields.sort((a, b) => b[1] - a[1]);
    for (const [field, count] of fields) {
      console.log(`${pad(field, 30)} ${pad(String(count), 15, true)}`);
    }
  }

  return 0;
}

function printHelp(): void {
  console.log(`aegis-trust CLI

Usage:
  aegis sandbox                              Run 10-second demo (dummy data, no infra)
  aegis history [--limit N] [--purpose P]   Show recent shield() invocations
  aegis stats                                Show aggregated statistics
  aegis --help                               Print this help

Environment:
  AEGIS_HISTORY=1                            Enable history recording
  AEGIS_HISTORY_PATH=<path>                  Override history file location
  AEGIS_SANDBOX_AUDIT=<path>                 Override sandbox audit path`);
}

export function main(argv: string[]): number {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printHelp();
    return 0;
  }
  const cmd = argv[0];

  if (cmd === "sandbox") {
    return cmdSandbox();
  }

  if (cmd === "history") {
    let limit = 20;
    let purpose: string | undefined;
    for (let i = 1; i < argv.length; i++) {
      const a = argv[i];
      if (a === "--limit" || a === "-n") {
        const raw = argv[++i];
        // Python argparse parity: a bad --limit is an error (exit 2), never
        // a silent fallback. Strict integer syntax — parseInt alone accepts
        // partial garbage ("10oops" → 10, "0x10" → 0), argparse does not.
        if (raw === undefined || !/^[+-]?\d+$/.test(raw)) {
          console.error(`argument --limit/-n: invalid int value: ${raw ?? "(missing)"}`);
          return 2;
        }
        limit = parseInt(raw, 10);
      } else if (a === "--purpose" || a === "-p") {
        purpose = argv[++i];
        if (purpose === undefined) {
          // Python argparse parity: a missing value is an error, not
          // a silent "no filter" that shows everything.
          console.error("argument --purpose/-p: expected one argument");
          return 2;
        }
      } else {
        console.error(`unknown arg: ${a}`);
        return 2;
      }
    }
    return cmdHistory({ limit, purpose });
  }

  if (cmd === "stats") {
    return cmdStats();
  }

  console.error(`unknown command: ${cmd}`);
  printHelp();
  return 2;
}

// When executed as a script (not imported as a library). ESM "is main module"
// detection must handle three invocation paths:
//   1. Direct: `node path/to/cli.js sandbox`
//   2. npm bin shim: symlink at node_modules/.bin/aegis → ../aegis-trust/dist/cli.js
//   3. npx aegis: also goes through the bin shim
//
// process.argv[1] is the literal path used to launch node (a symlink for #2/#3);
// import.meta.url is the resolved module URL (the real cli.js path). The previous
// basename-suffix check failed for #2/#3 because basename("aegis") never matched
// a URL ending in "cli.js", so main() never ran — every subcommand exited silently
// with stdout=0 bytes and exit code 0. realpathSync on both sides canonicalises
// the symlink so the comparison holds across all three invocation paths.
const isMain = (() => {
  if (typeof import.meta === "undefined") return false;
  const url = import.meta.url;
  if (!url || !process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
})();

if (isMain) {
  process.exit(main(process.argv.slice(2)));
}
