// Network prices per tier (see ProviderJuryRegistryV11): base price x a multiplier that follows daily utilisation.
import { encodeCall } from "./eip712.mjs";
import { rpcCall } from "./chain.mjs";

const EPOCH = 86_400;
const UNIT = 1_000_000n;

async function words(network, signature, pairs) {
  const raw = (await rpcCall(network.rpc_urls, "eth_call", [{ to: network.registry, data: encodeCall(signature, pairs) }, "latest"])).slice(2);
  return Array.from({ length: raw.length / 64 }, (_, i) => BigInt(`0x${raw.slice(i * 64, i * 64 + 64)}`));
}

/** Every tier the manifest names, with today's prices and the utilisation that set them. */
export async function networkPrices(network) {
  const block = await rpcCall(network.rpc_urls, "eth_getBlockByNumber", ["latest", false]);
  const today = BigInt(Math.floor(Number(BigInt(block.timestamp)) / EPOCH));
  const tiers = [];
  for (const [id, meta] of Object.entries(network.tiers || {})) {
    const tier = BigInt(id);
    const [baseIn, baseOut, minFee, , targetBps, active] = await words(network, "tiers(uint32)", [["uint", tier]]);
    if (!active) continue;
    const multiplier = (await words(network, "multiplierFor(uint32,uint64)", [["uint", tier], ["uint", today]]))[0];
    const previous = (await words(network, "multiplierFor(uint32,uint64)", [["uint", tier], ["uint", today - 1n]]))[0];
    const [demand] = await words(network, "demandAt(uint32,uint64)", [["uint", tier], ["uint", today - 1n]]);
    const [supply] = await words(network, "supplyAt(uint32,uint64)", [["uint", tier], ["uint", today - 1n]]);
    const scale = (value) => ((value * multiplier + UNIT - 1n) / UNIT).toString();
    tiers.push({
      tier: Number(tier), name: meta.name, models: meta.models, target_bps: Number(targetBps),
      multiplier: Number(multiplier), multiplier_yesterday: Number(previous),
      prices: { input_per_1k: scale(baseIn), output_per_1k: scale(baseOut), minimum_fee: scale(minFee) },
      yesterday: { demand: demand.toString(), supply: supply.toString(), utilization_bps: supply ? Number((demand * 10_000n) / supply) : 0 },
    });
  }
  return tiers;
}
