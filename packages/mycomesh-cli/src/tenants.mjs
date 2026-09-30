// Multi-tenant accounts: one owner deposit, one payment key per tenant with an on-chain budget.
// A custodial service (or any team) gives each end user an API key; the chain caps what each key can spend.
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { addressOf, encodeCall } from "./eip712.mjs";
import { rpcCall, sendTransaction } from "./chain.mjs";

const NAME = /^[a-zA-Z0-9_.-]{1,64}$/;
const file = (dir) => join(dir, "tenants.json");
export const hashApiKey = (apiKey) => createHash("sha256").update(String(apiKey)).digest("hex");

export function loadTenants(dir) {
  return existsSync(file(dir)) ? JSON.parse(readFileSync(file(dir), "utf8")).tenants : {};
}

function saveTenants(dir, tenants) {
  writeFileSync(file(dir), `${JSON.stringify({ schema: "mycomesh.v11.tenants.v1", tenants }, null, 2)}\n`, { mode: 0o600 });
  chmodSync(file(dir), 0o600);
}

export function tenantKey(dir, name) {
  const value = readFileSync(join(dir, "tenants", `${name}.key`), "utf8").trim();
  return value.startsWith("0x") ? value : `0x${value}`;
}

/** Create a tenant: a fresh payment key granted on-chain with a per-request cap and a total budget. */
export async function addTenant(network, dir, ownerPrivate, name, { maxPerRequest, budget = 0n }) {
  if (!NAME.test(name)) throw new Error("tenant names use letters, digits, '.', '_' and '-'");
  const tenants = loadTenants(dir);
  if (tenants[name]) throw new Error(`tenant ${name} already exists`);
  mkdirSync(join(dir, "tenants"), { recursive: true, mode: 0o700 });
  const keyPrivate = `0x${randomBytes(32).toString("hex")}`;
  writeFileSync(join(dir, "tenants", `${name}.key`), `${keyPrivate}\n`, { mode: 0o600 });
  const key = addressOf(keyPrivate);
  await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.settlement,
    data: encodeCall("registerKey(address,uint256,uint64)", [["address", key], ["uint", maxPerRequest], ["uint", 0]]) });
  if (budget > 0n) await setBudget(network, ownerPrivate, key, budget);
  const apiKey = `mcm_${randomBytes(24).toString("hex")}`;
  tenants[name] = { key, max_per_request: String(maxPerRequest), api_key_sha256: hashApiKey(apiKey),
    created_at: Math.floor(Date.now() / 1000), revoked: false };
  saveTenants(dir, tenants);
  return { name, key, api_key: apiKey };
}

export async function setBudget(network, ownerPrivate, key, budget) {
  await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.settlement,
    data: encodeCall("setKeyBudget(address,uint128)", [["address", key], ["uint", budget]]) });
}

export async function revokeTenant(network, dir, ownerPrivate, name) {
  const tenants = loadTenants(dir);
  if (!tenants[name]) throw new Error(`no tenant ${name}`);
  await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.settlement,
    data: encodeCall("revokeKey(address)", [["address", tenants[name].key]]) });
  tenants[name].revoked = true;
  saveTenants(dir, tenants);
}

/** Every tenant with its on-chain budget and spend. */
export async function tenantStatus(network, dir) {
  const tenants = loadTenants(dir);
  return Promise.all(Object.entries(tenants).map(async ([name, tenant]) => {
    const raw = (await rpcCall(network.rpc_urls, "eth_call", [{ to: network.settlement,
      data: encodeCall("keyBudgets(address)", [["address", tenant.key]]) }, "latest"])).slice(2);
    return { name, key: tenant.key, max_per_request: tenant.max_per_request, revoked: tenant.revoked,
      budget: BigInt(`0x${raw.slice(0, 64)}`).toString(), spent: BigInt(`0x${raw.slice(64, 128)}`).toString() };
  }));
}
