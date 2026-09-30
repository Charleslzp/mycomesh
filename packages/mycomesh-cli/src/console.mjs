// The local web console: the Bitcoin-node model, a UI served by this machine to this machine.
// The browser only ever talks to 127.0.0.1; this process reaches the network and verifies everything.
import { readFileSync } from "node:fs";
import { addressOf } from "./eip712.mjs";
import { completeWithdrawal, dispute, faucet, requestWithdrawal, settlementStatus, setup, walletStatus } from "./account.mjs";
import { listRequests, loadRequest } from "./disputes.mjs";
import { outputText } from "./protocol.mjs";
import { createWallet, ownerAddress, unlockWallet, walletAddress } from "./wallet.mjs";
import { addTenant, loadTenants, revokeTenant, setBudget, tenantStatus } from "./tenants.mjs";
import { networkPrices } from "./pricing.mjs";
import { claimRewards, rewardsSummary } from "./rewards.mjs";

const PAGE = new URL("./web/console.html", import.meta.url);

/**
 * Only this machine's own pages may call the local node: reject other Host
 * names (DNS rebinding) and cross-site Origins (a web page spending the deposit).
 */
export function localRequestAllowed(req, port) {
  const allowed = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  if (!allowed.has(String(req.headers.host || ""))) return false;
  const origin = req.headers.origin;
  return !origin || allowed.has(origin.replace(/^http:\/\//, ""));
}

export function consoleRoutes({ consumer, dataDir }) {
  const network = consumer.network;
  const owner = () => ownerAddress(undefined, dataDir);
  const withWallet = (body) => unlockWallet(dataDir, body.password);
  const units = (value, name) => {
    if (!/^[0-9]+$/.test(String(value ?? ""))) throw Object.assign(new Error(`${name} must be a whole number of base units`), { status: 400 });
    return BigInt(value);
  };
  return {
    "GET /": () => ({ type: "text/html; charset=utf-8", body: readFileSync(PAGE, "utf8") }),
    "GET /api/status": async () => {
      const address = owner();
      return {
        network: { id: network.network_id, chain_id: network.chain_id, settlement: network.settlement, faucet: Boolean(network.faucet_url) },
        payment_key: consumer.key, max_fee: String(consumer.maxFee),
        wallet: address ? await walletStatus(network, address, consumer.key) : null,
      };
    },
    "GET /api/network": async () => {
      const relays = [];
      for (const relay of await consumer.relays()) {
        let health = null; let providers = [];
        try { health = (await consumer.fetchJson(`${relay.url}/health`, { ca: network.tls_ca, pin: relay.pin, timeoutMs: 5_000 })).body; } catch {}
        try { providers = await consumer.providers(relay); } catch {}
        relays.push({ url: relay.url, signer: relay.signer, pinned: Boolean(relay.pin), healthy: Boolean(health?.ok), providers: providers.map((p) => ({
          signer: p.provider_signer, models: p.models, prices: p.prices, capacity: p.capacity })) });
      }
      const records = await consumer.reputations().catch(() => ({}));
      for (const relay of relays) for (const provider of relay.providers) provider.reputation = records[provider.signer] || null;
      return { relays };
    },
    "GET /api/pricing": async () => ({ tiers: await networkPrices(network) }),
    "GET /api/history": async () => {
      const entries = listRequests(dataDir, outputText, 50);
      await Promise.all(entries.map(async (entry) => {
        try { Object.assign(entry, await settlementStatus(network, entry.settlement_key)); } catch { entry.status = "unknown"; }
      }));
      return { entries };
    },
    "GET /api/rewards": async () => {
      const address = owner();
      return { rewards: address ? await rewardsSummary(network, address) : null };
    },
    "POST /api/rewards/claim": async (body) => {
      const ownerPrivate = withWallet(body);
      return { claimed: await claimRewards(network, ownerPrivate, addressOf(ownerPrivate)) };
    },
    "POST /api/wallet": async (body) => ({ owner: walletAddress(await createWallet(dataDir, body.password)) }),
    "POST /api/faucet": async () => {
      const address = owner();
      if (!address) throw Object.assign(new Error("create the wallet first"), { status: 400 });
      return faucet(network, address);
    },
    "POST /api/setup": async (body) => setup(network, {
      ownerPrivate: withWallet(body), key: consumer.key, deposit: units(body.deposit, "deposit"),
      limit: units(body.max_per_request ?? consumer.maxFee, "max_per_request"),
    }),
    "POST /api/withdraw": async (body) => {
      const ownerPrivate = withWallet(body);
      const status = await walletStatus(network, addressOf(ownerPrivate), null);
      if (BigInt(status.withdrawal.amount) > 0n) {
        if (status.withdrawal.available_at > Math.floor(Date.now() / 1000)) {
          throw Object.assign(new Error("the pending withdrawal is still locked"), { status: 409 });
        }
        await completeWithdrawal(network, ownerPrivate);
        return { withdrawn: status.withdrawal.amount };
      }
      const amount = body.amount ? units(body.amount, "amount") : BigInt(status.deposit);
      await requestWithdrawal(network, ownerPrivate, amount);
      return { requested: amount.toString() };
    },
    "GET /api/tenants": async () => ({ tenants: await tenantStatus(network, dataDir) }),
    "POST /api/tenants": async (body) => addTenant(network, dataDir, withWallet(body), String(body.name || ""), {
      maxPerRequest: units(body.max_per_request ?? consumer.maxFee, "max_per_request"),
      budget: body.budget ? units(body.budget, "budget") : 0n,
    }),
    "POST /api/tenants/budget": async (body) => {
      const tenant = loadTenants(dataDir)[String(body.name)];
      if (!tenant) throw Object.assign(new Error("no such tenant"), { status: 404 });
      await setBudget(network, withWallet(body), tenant.key, units(body.budget, "budget"));
      return { name: body.name, budget: String(body.budget) };
    },
    "POST /api/tenants/revoke": async (body) => {
      await revokeTenant(network, dataDir, withWallet(body), String(body.name));
      return { revoked: body.name };
    },
    "POST /api/dispute": async (body) => dispute(network, withWallet(body), loadRequest(dataDir, String(body.settlement_key)),
      { reasonCode: String(body.reason_code || "unrelated_response"), statement: String(body.statement || "") }),
  };
}
