// aegis-trust Docker quickstart — HTTP-served sandbox demo.
//
// A minimal HTTP server using node:http (zero deps) that exposes:
//
//   GET /health                  → 200 { status: "ok" }
//   GET /demo/agent-request      → 200 { allowed, blocked, audit }  + writes audit line
//   GET /demo/audit              → 200 ndjson of audit lines
//
// No external services. Stops when you docker compose down.

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname } from "node:path";

import { shield } from "aegis-trust";

const DUMMY_USER: Record<string, unknown> = {
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

const AUDIT_PATH = process.env.AEGIS_AUDIT_PATH ?? "/data/audit.jsonl";
mkdirSync(dirname(AUDIT_PATH), { recursive: true });

const getUser = shield({
  purpose: "customer_support",
  scope: ["user_id", "plan", "last_login"],
})((..._args: unknown[]) => DUMMY_USER);

function emitAudit(allowed: Record<string, unknown>, blocked: string[]): void {
  const entry = {
    timestamp: new Date().toISOString(),
    agent: "support_agent",
    purpose: "customer_support",
    requested_id: "u_123",
    allowed_fields: Object.keys(allowed).sort(),
    blocked_fields: blocked,
    decision: "filtered",
    reason: "fields outside declared scope",
  };
  appendFileSync(AUDIT_PATH, JSON.stringify(entry) + "\n");
}

const server = createServer((req, res) => {
  console.log(`[aegis-demo] ${req.method} ${req.url}`);
  if (req.method !== "GET") {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "method not allowed" }));
    return;
  }
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }
  if (req.url === "/demo/agent-request") {
    const allowed = getUser("u_123") as Record<string, unknown>;
    const blocked = Object.keys(DUMMY_USER).filter((k) => !(k in allowed)).sort();
    emitAudit(allowed, blocked);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      allowed,
      blocked,
      audit: {
        purpose: "customer_support",
        decision: "filtered",
        reason: "fields outside declared scope",
        path: AUDIT_PATH,
      },
    }, null, 2));
    return;
  }
  if (req.url === "/demo/audit") {
    let content = "";
    try { content = readFileSync(AUDIT_PATH, "utf8"); } catch { /* no audit yet */ }
    res.writeHead(200, { "Content-Type": "application/x-ndjson" });
    res.end(content);
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found", try: "/demo/agent-request" }));
});

const port = parseInt(process.env.PORT ?? "8080", 10);
server.listen(port, "0.0.0.0", () => {
  console.log(`[aegis-demo] listening on http://0.0.0.0:${port}`);
  console.log(`[aegis-demo] try:  curl http://localhost:${port}/demo/agent-request`);
  console.log(`[aegis-demo] audit: ${AUDIT_PATH}`);
});
