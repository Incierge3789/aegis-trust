// Crypto wallet — field-level access control for financial data.

import { shield } from "../src/index.js";

const WALLET = {
  owner: "Eve Zhang",
  wallet_address: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38",
  balance: { eth: 12.5, usdc: 50000.0, btc: 0.85 },
  private_key: "<REDACTED — example only, not a real key>",
  seed_phrase: "<REDACTED — example only, not a real phrase>",
  transactions: [
    { type: "send", amount: 1.0, token: "eth", to: "0xabc..." },
    { type: "receive", amount: 500.0, token: "usdc", from: "0xdef..." },
  ],
};

// Portfolio agent sees balances — never keys or seed phrases.
const getPortfolio = shield({
  purpose: "portfolio_view",
  scope: ["owner", "wallet_address", "balance"],
})((_walletId: string) => WALLET);

// Transaction monitor sees activity but not secret keys or BTC balance.
const getForMonitoring = shield({
  purpose: "tx_monitor",
  denyFields: ["private_key", "seed_phrase", "balance.btc"],
})((_walletId: string) => WALLET);

// Public-facing agent sees only owner and address.
const getPublicInfo = shield({
  purpose: "public_display",
  scope: ["owner", "wallet_address"],
})((_walletId: string) => WALLET);

const wid = "W-001";

console.log("Portfolio agent sees:");
console.log(getPortfolio(wid));

console.log("\nMonitor agent sees:");
console.log(getForMonitoring(wid));

console.log("\nPublic display:");
console.log(getPublicInfo(wid));
