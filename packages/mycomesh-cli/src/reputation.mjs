// Provider ranking from what the chain and the probe ledger prove, not from what anyone claims.
import { encodeCall, keccak, hex } from "./eip712.mjs";
import { rpcCall } from "./chain.mjs";
import { evidenceHash } from "./disputes.mjs";
import { verifyProbeEvidence } from "./probes.mjs";

const PROBE_RECORDED = hex(keccak(Buffer.from("ProbeRecorded(address,address,bytes32,bytes32,uint8)")));
const LOOKBACK_BLOCKS = 50_400n; // about 7 days of 12-second blocks
const LOG_CHUNK = 10_000n;
const FRAUD_COOLDOWN = 30 * 86_400;
const MAX_VERIFIED = 20; // evidence downloads per refresh

const word = (raw, index) => BigInt(`0x${raw.slice(2 + index * 64, 2 + (index + 1) * 64)}`);
const address = (topic) => `0x${topic.slice(26)}`.toLowerCase();

async function providerRecord(network, signer) {
  const owner = address((await rpcCall(network.rpc_urls, "eth_call", [{ to: network.settlement,
    data: encodeCall("providerSignerOwner(address)", [["address", signer]]) }, "latest"])).slice(0, 66));
  const raw = await rpcCall(network.rpc_urls, "eth_call", [{ to: network.registry,
    data: encodeCall("providerOf(address)", [["address", owner]]) }, "latest"]);
  return { owner, counted_volume: word(raw, 10).toString(), counterparties: Number(word(raw, 8)),
    last_fraud_at: Number(word(raw, 9)), registered_at: Number(word(raw, 5)) };
}

async function ledgerEvents(network) {
  if (!network.probe_ledger) return [];
  const head = BigInt(await rpcCall(network.rpc_urls, "eth_blockNumber", []));
  const events = [];
  for (let from = head > LOOKBACK_BLOCKS ? head - LOOKBACK_BLOCKS : 0n; from <= head; from += LOG_CHUNK) {
    const to = from + LOG_CHUNK - 1n < head ? from + LOG_CHUNK - 1n : head;
    for (const log of await rpcCall(network.rpc_urls, "eth_getLogs", [{ address: network.probe_ledger, topics: [PROBE_RECORDED],
      fromBlock: `0x${from.toString(16)}`, toBlock: `0x${to.toString(16)}` }])) {
      events.push({ provider: address(log.topics[1]), relay: address(log.topics[2]), key: log.topics[3],
        evidence: `0x${log.data.slice(2, 66)}`, verdict: Number(BigInt(`0x${log.data.slice(66, 130)}`)) === 1 ? "pass" : "wrong" });
    }
  }
  return events;
}

/**
 * Per Provider owner: on-chain reputation plus probe verdicts. Passes are counted as reported;
 * failures count only after this machine re-grades the published evidence, so no Relay can frame anyone.
 */
export async function reputation(consumer, descriptors, relaysByOwner) {
  const network = consumer.network;
  const records = {};
  for (const descriptor of descriptors) {
    try { records[descriptor.provider_signer] = await providerRecord(network, descriptor.provider_signer); } catch {}
  }
  let events = [];
  try { events = await ledgerEvents(network); } catch {}
  const byOwner = {};
  for (const record of Object.values(records)) byOwner[record.owner] = { ...record, probes_passed: 0, probes_failed_verified: 0 };
  let verified = 0;
  for (const event of events) {
    const entry = byOwner[event.provider];
    if (!entry) continue;
    if (event.verdict === "pass") { entry.probes_passed += 1; continue; }
    const relay = relaysByOwner[event.relay];
    if (!relay || verified >= MAX_VERIFIED) continue;
    verified += 1;
    try {
      const { status, body } = await consumer.fetchJson(`${relay.url}/v11/evidence/${event.evidence}`,
        { ca: network.tls_ca, pin: relay.pin, timeoutMs: 8_000 });
      if (status === 200 && evidenceHash(body) === event.evidence && verifyProbeEvidence(body, consumer.deployment).verdict === "wrong") {
        entry.probes_failed_verified += 1;
      }
    } catch {}
  }
  return Object.fromEntries(Object.entries(records).map(([signer, record]) => [signer, byOwner[record.owner]]));
}

/** Lower is better: recent confirmed fraud last, then verified probe failure rate, then reputation, then price. */
export function rankKey(descriptor, record, now = Math.floor(Date.now() / 1000)) {
  const fraud = record && record.last_fraud_at && now < record.last_fraud_at + FRAUD_COOLDOWN ? 1 : 0;
  const probes = record ? record.probes_passed + record.probes_failed_verified : 0;
  const failure = record && probes ? Math.round((10 * record.probes_failed_verified) / probes) : 0;
  const volume = record ? -Number(BigInt(record.counted_volume) / 1000n) : 0;
  const price = descriptor.prices.output_per_1k * 1e6 + descriptor.prices.input_per_1k;
  return [fraud, failure, volume, price];
}

export function compareRank(a, b) {
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}
