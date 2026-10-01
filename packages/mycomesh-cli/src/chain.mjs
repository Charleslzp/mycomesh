// Minimal JSON-RPC for Consumer setup and balance reads, with endpoint failover.
import { addressOf, encodeCall, signLegacyTransaction } from "./eip712.mjs";

export async function rpcCall(urls, method, params, { timeoutMs = 15000 } = {}) {
  let last;
  for (const url of [].concat(urls)) {
    try {
      const response = await fetch(url, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(timeoutMs),
      });
      const body = await response.json();
      if (body.error) throw Object.assign(new Error(`${method}: ${JSON.stringify(body.error).slice(0, 300)}`), { answered: true });
      return body.result;
    } catch (error) {
      if (error.answered) throw error;
      last = error;
    }
  }
  throw new Error(`${method}: no RPC endpoint answered (${last?.message || "unknown"})`);
}

export const quantity = (value) => BigInt(value);

export async function ethCallWord(urls, to, data) {
  return BigInt(await rpcCall(urls, "eth_call", [{ to, data }, "latest"]));
}

export async function availableBalance(network, owner) {
  return ethCallWord(network.rpc_urls, network.settlement, encodeCall("availableBalance(address)", [["address", owner]]));
}

/**
 * Twice the latest base fee plus the suggested tip, as EIP-1559 wallets cap a fee. Some nodes (anvil)
 * derive eth_gasPrice from recent transactions, so pricing above it compounds block after block.
 */
export async function suggestedGasPrice(urls) {
  try {
    const [block, tip] = await Promise.all([rpcCall(urls, "eth_getBlockByNumber", ["latest", false]),
      rpcCall(urls, "eth_maxPriorityFeePerGas", [])]);
    if (block?.baseFeePerGas) return quantity(block.baseFeePerGas) * 2n + quantity(tip);
  } catch {}
  return quantity(await rpcCall(urls, "eth_gasPrice", [])) * 12n / 10n;
}

export async function sendTransaction(urls, privateKey, { to, data, gasLimit }) {
  const from = addressOf(privateKey);
  const [chainId, nonce, gasPrice] = await Promise.all([
    rpcCall(urls, "eth_chainId", []), rpcCall(urls, "eth_getTransactionCount", [from, "pending"]), suggestedGasPrice(urls),
  ]);
  const limit = gasLimit ?? (quantity(await rpcCall(urls, "eth_estimateGas", [{ from, to, data }])) * 12n / 10n + 10000n);
  const raw = signLegacyTransaction(privateKey, {
    nonce: quantity(nonce), gasPrice, gasLimit: limit, to, data, chainId: quantity(chainId),
  });
  const hash = await rpcCall(urls, "eth_sendRawTransaction", [raw]);
  for (let i = 0; i < 180; i += 1) {
    const receipt = await rpcCall(urls, "eth_getTransactionReceipt", [hash]);
    if (receipt) {
      if (receipt.status !== "0x1") throw new Error(`transaction ${hash} reverted`);
      return receipt;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`transaction ${hash} was not mined in time`);
}
