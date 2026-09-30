// Consumer account operations shared by the CLI and the local web console.
import { addressOf, encodeCall } from "./eip712.mjs";
import { rpcCall, sendTransaction } from "./chain.mjs";
import { directoryRelays, httpJson } from "./consumer.mjs";
import { buildEvidence, evidenceHash, openDisputeCall, reportId } from "./disputes.mjs";

export const STATUSES = ["none", "pending", "disputed", "released", "confirmed", "dismissed", "timed_out", "jury_unavailable", "voided"];

async function words(network, to, signature, pairs = []) {
  const raw = (await rpcCall(network.rpc_urls, "eth_call", [{ to, data: encodeCall(signature, pairs) }, "latest"])).slice(2);
  return Array.from({ length: raw.length / 64 }, (_, i) => BigInt(`0x${raw.slice(i * 64, i * 64 + 64)}`));
}

/** Balances of the owner wallet and the payment key's grant; amounts are strings of base units. */
export async function walletStatus(network, owner, key) {
  const [eth, [tokens], [deposit], withdrawal, grant, params] = await Promise.all([
    rpcCall(network.rpc_urls, "eth_getBalance", [owner, "latest"]),
    words(network, network.stablecoin, "balanceOf(address)", [["address", owner]]),
    words(network, network.settlement, "availableBalance(address)", [["address", owner]]),
    words(network, network.settlement, "withdrawals(address)", [["address", owner]]),
    key ? words(network, network.settlement, "keyGrants(address)", [["address", key]]) : Promise.resolve(null),
    words(network, network.settlement, "params()"),
  ]);
  return {
    owner, key, eth_wei: BigInt(eth).toString(), wallet_tokens: tokens.toString(), deposit: deposit.toString(),
    withdrawal: { amount: withdrawal[0].toString(), available_at: Number(withdrawal[1]) },
    grant: grant && { active: Boolean(grant[3]) && `0x${grant[0].toString(16).padStart(40, "0")}` === owner.toLowerCase(),
      max_per_request: grant[1].toString() },
    dispute_window: Number(params[0]), reporter_bond: params[3].toString(), faucet: Boolean(network.faucet_url),
  };
}

export async function faucet(network, address) {
  if (!network.faucet_url) throw new Error("this network has no faucet");
  const reply = await httpJson(`${network.faucet_url}/v11/faucet`, { method: "POST", body: { address }, ca: network.tls_ca, timeoutMs: 400_000 });
  if (reply.status !== 200) throw new Error(`faucet: ${reply.body?.error || reply.status}`);
  return reply.body;
}

/** Deposit and grant the payment key; on testnets, top the wallet up from the faucet first. */
export async function setup(network, { ownerPrivate, key, deposit, limit, forceFaucet = false, log = () => {} }) {
  const owner = addressOf(ownerPrivate);
  const status = await walletStatus(network, owner, key);
  if (network.faucet_url && (forceFaucet || BigInt(status.eth_wei) < 2_000_000_000_000_000n || BigInt(status.wallet_tokens) < deposit)) {
    log(`funding ${owner} from the testnet faucet...`);
    await faucet(network, owner);
  }
  const send = (to, data) => sendTransaction(network.rpc_urls, ownerPrivate, { to, data });
  await send(network.stablecoin, encodeCall("approve(address,uint256)", [["address", network.settlement], ["uint", deposit]]));
  await send(network.settlement, encodeCall("deposit(uint256)", [["uint", deposit]]));
  if (!status.grant?.active || BigInt(status.grant.max_per_request) !== limit) {
    await send(network.settlement, encodeCall("registerKey(address,uint256,uint64)", [["address", key], ["uint", limit], ["uint", 0]]));
  }
  return { owner, key, deposit: deposit.toString(), max_per_request: limit.toString() };
}

/** Withdrawals take two steps: request (funds stop backing requests), then withdraw after the delay. */
export async function requestWithdrawal(network, ownerPrivate, amount) {
  await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.settlement,
    data: encodeCall("requestWithdrawal(uint256)", [["uint", amount]]) });
}

export async function completeWithdrawal(network, ownerPrivate) {
  await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.settlement, data: encodeCall("withdraw()", []) });
}

export async function settlementStatus(network, key) {
  const fields = await words(network, network.settlement, "settlementInfo(bytes32)", [["bytes32", key]]);
  return { status: STATUSES[Number(fields[14])] || "unknown", release_at: Number(fields[13]), fee: fields[10].toString() };
}

/** Commit the evidence on-chain (with the reporter bond), then hand it to every Relay's dispute desk. */
export async function dispute(network, ownerPrivate, record, { reasonCode, statement }) {
  const evidence = buildEvidence(record, { reasonCode, statement });
  const digest = evidenceHash(evidence);
  const [bond] = (await words(network, network.settlement, "params()")).slice(3, 4);
  if (bond > 0n) {
    await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.stablecoin,
      data: encodeCall("approve(address,uint256)", [["address", network.settlement], ["uint", bond]]) });
  }
  await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.settlement, data: openDisputeCall(record.settlement_key, digest) });
  let relays = network.relays;
  try { relays = [...relays, ...await directoryRelays(network)]; } catch {}
  const accepted = [];
  for (const relay of relays) {
    try {
      const reply = await httpJson(`${relay.url}/v11/evidence`, { method: "POST", body: evidence, ca: network.tls_ca, timeoutMs: 30_000 });
      if (reply.status === 200) accepted.push(relay.url);
    } catch {}
  }
  return { settlement_key: record.settlement_key, evidence_hash: digest,
    report_id: reportId(record.settlement_key, addressOf(ownerPrivate), digest), relays_accepted: accepted };
}
