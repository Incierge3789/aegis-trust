// denyFields — blacklist mode for hiding specific sensitive fields.

import { shield } from "../src/index.js";

const getUserProfile = shield({
  purpose: "reporting",
  denyFields: ["ssn", "password_hash"],
})((_userId: string) => ({
  name: "Bob Smith",
  email: "bob@example.com",
  role: "admin",
  ssn: "987-65-4321",
  password_hash: "$2b$12$abc...",
  created_at: "2026-01-15",
}));

const getUserForAudit = shield({
  purpose: "audit",
  denyFields: ["password_hash"],
})((_userId: string) => ({
  name: "Bob Smith",
  email: "bob@example.com",
  ssn: "987-65-4321",
  password_hash: "$2b$12$abc...",
  last_login: "2026-04-10T08:30:00Z",
}));

console.log("Reporting agent sees:");
console.log(getUserProfile("U-001"));
// → ssn and password_hash removed

console.log("\nAudit agent sees:");
console.log(getUserForAudit("U-001"));
// → only password_hash removed
