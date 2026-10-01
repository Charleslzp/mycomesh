// MYCO rewards: every hour's fees mint MYCO for the Consumers who paid them (80%), their Providers (10%,
// 48 hours later, by success rate), Relays (7%) and keepers (3%). Find, show and claim an account's share.
import { encodeCall, encodeWords, hex, keccak } from "./eip712.mjs";
import { getLogs, rpcCall, sendTransaction } from "./chain.mjs";

export const ROLES = ["consumer", "provider", "relay", "bridge"];
const POINTS = hex(keccak(new TextEncoder().encode("Points(uint64,uint8,address,uint256)")));
const LOG_CHUNK = 10_000;
const CLAIM_BATCH = 100;

async function word(network, to, signature, pairs = []) {
  return BigInt(await rpcCall(network.rpc_urls, "eth_call", [{ to, data: encodeCall(signature, pairs) }, "latest"]));
}

/** role index -> emission blocks in which the account earned points. */
export async function earnedBlocks(network, account) {
  const head = Number(BigInt(await rpcCall(network.rpc_urls, "eth_blockNumber", [])));
  const topic = `0x${account.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;
  const found = new Map();
  for (let start = Number(network.emission_block || 0); start <= head; start += LOG_CHUNK) {
    const logs = await getLogs(network.rpc_urls, { address: network.emission, topics: [POINTS, null, null, topic],
      fromBlock: `0x${start.toString(16)}`, toBlock: `0x${Math.min(head, start + LOG_CHUNK - 1).toString(16)}` });
    for (const log of logs) {
      const role = Number(BigInt(log.topics[2]));
      if (!found.has(role)) found.set(role, new Set());
      found.get(role).add(Number(BigInt(log.topics[1])));
    }
  }
  return found;
}

const claimableAt = (network, block, role, account) => word(network, network.emission, "claimable(uint64,uint8,address)",
  [["uint", block], ["uint", role], ["address", account]]);

/** MYCO claimable per role (wei strings), blocks still waiting (the current hour, or a Provider's 48 hours) and the balance. */
export async function rewardsSummary(network, account) {
  if (!network.emission) return null;
  const roles = {};
  for (const [role, blocks] of await earnedBlocks(network, account)) {
    let claimable = 0n; let waiting = 0;
    for (const block of blocks) {
      const amount = await claimableAt(network, block, role, account);
      if (amount > 0n) claimable += amount;
      else if (await word(network, network.emission, "points(uint64,uint8,address)",
        [["uint", block], ["uint", role], ["address", account]]) > 0n) waiting += 1;
    }
    roles[ROLES[role]] = { claimable_wei: claimable.toString(), blocks_waiting: waiting, blocks: blocks.size };
  }
  return {
    account, roles,
    myco_balance_wei: network.token ? (await word(network, network.token, "balanceOf(address)", [["address", account]])).toString() : null,
  };
}

function encodeClaim(blocks, role) {
  const selector = encodeCall("claim(uint64[],uint8)", []);
  return selector + encodeWords([["uint", 64], ["uint", role], ["uint", blocks.length], ...blocks.map((b) => ["uint", b])]).toString("hex");
}

/** Close the finished hour if nobody has yet, then claim every claimable block in every role. */
export async function claimRewards(network, ownerPrivate, account) {
  if (!network.emission) throw new Error("this network has no MYCO emission");
  const [open, hasOpen, current] = await Promise.all(["openBlock()", "hasOpen()", "currentBlock()"]
    .map((signature) => word(network, network.emission, signature)));
  if (hasOpen && open < current) await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.emission, data: encodeCall("poke()", []) });
  const claimed = {};
  for (const [role, blocks] of await earnedBlocks(network, account)) {
    const ready = [];
    for (const block of [...blocks].sort((a, b) => a - b)) if (await claimableAt(network, block, role, account) > 0n) ready.push(block);
    for (let i = 0; i < ready.length; i += CLAIM_BATCH) {
      await sendTransaction(network.rpc_urls, ownerPrivate, { to: network.emission, data: encodeClaim(ready.slice(i, i + CLAIM_BATCH), role) });
    }
    if (ready.length) claimed[ROLES[role]] = ready.length;
  }
  return claimed;
}

/** 18-decimal wei as a short MYCO figure. */
export function formatMyco(wei) {
  const value = BigInt(wei);
  const whole = value / 10n ** 18n;
  const fraction = (value % 10n ** 18n).toString().padStart(18, "0").slice(0, 2);
  return `${whole.toLocaleString("en-US")}.${fraction}`;
}
