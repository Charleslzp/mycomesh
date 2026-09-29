// mycomesh-consumer (V11): init, wallet, faucet, setup, balance, request, serve, dispute.
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { addressOf, encodeCall, settlementKey } from "./eip712.mjs";
import { availableBalance, rpcCall, sendTransaction } from "./chain.mjs";
import { Consumer, directoryRelays, httpJson, loadNetwork, serveConsumer } from "./consumer.mjs";
import { createWallet, ownerAddress, ownerKey, walletAddress } from "./wallet.mjs";
import { buildEvidence, evidenceHash, loadRequest, openDisputeCall, reportId } from "./disputes.mjs";

const DEFAULT_NETWORK = join(dirname(fileURLToPath(import.meta.url)), "../networks/mycomesh-v11-sepolia.json");

const USAGE = `Usage: mycomesh-consumer <command> [options]

  init                     create the local payment key and the password-protected owner wallet
  address                  print the payment key address
  wallet                   print the owner wallet address (a V3 keystore; MetaMask can import it)
  faucet                   testnet: get gas ETH and tUSDC for the owner wallet
  setup --deposit UNITS [--max-per-request UNITS]
                           deposit into the settlement contract and authorize the payment key
                           (on testnets, tops the wallet up from the faucet first)
  balance [--owner ADDR]   show the custodied deposit
  request "prompt" [--stream]
                           send one request and print the verified answer
  serve [--port 8110]      run the local OpenAI-compatible endpoint with streaming (default)
  dispute <settlement-key|last> [--reason CODE] [--statement TEXT]
                           reveal a recorded request and response to a Provider-AI jury
                           (within 24 hours; the reporter bond is returned if fraud is confirmed)

Common: --network FILE (default: the bundled MycoMesh V11 Sepolia manifest), --data-dir DIR, --model ID,
  --max-fee UNITS, --provider SIGNER, --owner-key-file F (raw key or keystore instead of the local wallet).
The wallet password comes from MYCOMESH_WALLET_PASSWORD or a terminal prompt.`;

function dataDir(value) {
  const dir = value || process.env.MYCOMESH_CONSUMER_DATA_DIR || join(homedir(), ".mycomesh", "v11");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function readKey(path) {
  const value = readFileSync(path, "utf8").trim();
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${path} does not hold a private key`);
  return value.startsWith("0x") ? value : `0x${value}`;
}

function paymentKey(dir, create = false) {
  const path = join(dir, "payment-key");
  if (!existsSync(path)) {
    if (!create) throw new Error("no payment key; run `mycomesh-consumer init` first");
    writeFileSync(path, `0x${randomBytes(32).toString("hex")}\n`, { mode: 0o600 });
    chmodSync(path, 0o600);
  }
  return readKey(path);
}

export async function main(argv = process.argv.slice(2), { stdout = process.stdout } = {}) {
  const { values, positionals } = parseArgs({
    args: argv, allowPositionals: true,
    options: {
      network: { type: "string" }, "data-dir": { type: "string" }, "owner-key-file": { type: "string" },
      deposit: { type: "string" }, "max-per-request": { type: "string" }, owner: { type: "string" },
      model: { type: "string", default: "gpt-5.5" }, "max-fee": { type: "string", default: "1000000" },
      port: { type: "string", default: "8110" }, host: { type: "string", default: "127.0.0.1" },
      "max-output-tokens": { type: "string", default: "4096" }, help: { type: "boolean" },
      reason: { type: "string", default: "unrelated_response" }, faucet: { type: "boolean" }, provider: { type: "string" },
      statement: { type: "string", default: "" }, stream: { type: "boolean" },
    },
  });
  const [command = "serve", ...rest] = positionals;
  if (values.help || command === "help") { stdout.write(`${USAGE}\n`); return 0; }
  const dir = dataDir(values["data-dir"]);
  if (command === "address") {
    stdout.write(`${addressOf(paymentKey(dir))}\n`);
    return 0;
  }
  if (command === "init") {
    stdout.write(`${addressOf(paymentKey(dir, true))}\n`);
    if (!values["owner-key-file"]) {
      stdout.write(`owner wallet ${walletAddress(await createWallet(dir))} (${join(dir, "owner-wallet.json")})\n`);
    }
    return 0;
  }
  if (command === "wallet") {
    stdout.write(`${values["owner-key-file"] ? ownerAddress(values["owner-key-file"], dir) : walletAddress(await createWallet(dir))}\n`);
    return 0;
  }
  const network = loadNetwork(values.network || process.env.MYCOMESH_NETWORK || DEFAULT_NETWORK);
  const faucet = async (address) => {
    if (!network.faucet_url) throw new Error("this network has no faucet");
    const reply = await httpJson(`${network.faucet_url}/v11/faucet`, { method: "POST", body: { address }, ca: network.tls_ca, timeoutMs: 400_000 });
    if (reply.status !== 200) throw new Error(`faucet: ${reply.body?.error || reply.status}`);
    return reply.body;
  };
  if (command === "faucet") {
    const address = values.owner || ownerAddress(values["owner-key-file"], dir) || walletAddress(await createWallet(dir));
    stdout.write(`${JSON.stringify(await faucet(address))}\n`);
    return 0;
  }
  if (command === "setup") {
    const keyPrivate = paymentKey(dir);
    if (!values.deposit) throw new Error("--deposit UNITS is required");
    if (!values["owner-key-file"]) await createWallet(dir);
    const address = ownerAddress(values["owner-key-file"], dir);
    const deposit = BigInt(values.deposit);
    const limit = BigInt(values["max-per-request"] || values["max-fee"]);
    const eth = BigInt(await rpcCall(network.rpc_urls, "eth_getBalance", [address, "latest"]));
    const tokens = BigInt(await rpcCall(network.rpc_urls, "eth_call", [{ to: network.stablecoin,
      data: encodeCall("balanceOf(address)", [["address", address]]) }, "latest"]));
    if (network.faucet_url && (values.faucet || eth < 2_000_000_000_000_000n || tokens < deposit)) {
      stdout.write(`funding ${address} from the testnet faucet...\n`);
      await faucet(address);
    }
    const owner = await ownerKey(values["owner-key-file"], dir);
    await sendTransaction(network.rpc_urls, owner, { to: network.stablecoin,
      data: encodeCall("approve(address,uint256)", [["address", network.settlement], ["uint", deposit]]) });
    await sendTransaction(network.rpc_urls, owner, { to: network.settlement, data: encodeCall("deposit(uint256)", [["uint", deposit]]) });
    await sendTransaction(network.rpc_urls, owner, { to: network.settlement,
      data: encodeCall("registerKey(address,uint256,uint64)", [["address", addressOf(keyPrivate)], ["uint", limit], ["uint", 0]]) });
    stdout.write(`deposited ${deposit} and authorized ${addressOf(keyPrivate)} up to ${limit} per request\n`);
    return 0;
  }
  if (command === "balance") {
    const owner = values.owner || ownerAddress(values["owner-key-file"], dir);
    if (!owner) throw new Error("--owner, --owner-key-file or a local wallet (`init`) is required");
    stdout.write(`${await availableBalance(network, owner)}\n`);
    return 0;
  }
  if (command === "dispute") {
    const owner = await ownerKey(values["owner-key-file"], dir);
    const record = loadRequest(dir, rest[0] || "last");
    const evidence = buildEvidence(record, { reasonCode: values.reason, statement: values.statement || rest.slice(1).join(" ") });
    const digest = evidenceHash(evidence);
    // The reporter bond comes from the owner's wallet and is returned when fraud is confirmed.
    const params = await rpcCall(network.rpc_urls, "eth_call", [{ to: network.settlement, data: encodeCall("params()", []) }, "latest"]);
    const bond = BigInt(`0x${params.slice(2 + 64 * 3, 2 + 64 * 4)}`);
    if (bond > 0n) {
      await sendTransaction(network.rpc_urls, owner, { to: network.stablecoin,
        data: encodeCall("approve(address,uint256)", [["address", network.settlement], ["uint", bond]]) });
    }
    await sendTransaction(network.rpc_urls, owner, { to: network.settlement, data: openDisputeCall(record.settlement_key, digest) });
    const accepted = [];
    let relays = network.relays;
    try { relays = [...relays, ...await directoryRelays(network)]; } catch {}
    for (const relay of relays) {
      try {
        const reply = await httpJson(`${relay.url}/v11/evidence`, { method: "POST", body: evidence, ca: network.tls_ca, timeoutMs: 30_000 });
        if (reply.status === 200) accepted.push(relay.url);
      } catch {}
    }
    stdout.write(`${JSON.stringify({ settlement_key: record.settlement_key, evidence_hash: digest,
      report_id: reportId(record.settlement_key, addressOf(owner), digest), relays_accepted: accepted })}\n`);
    return accepted.length ? 0 : 2;
  }
  const keyPrivate = paymentKey(dir);
  const consumer = new Consumer({ network, keyPrivate, maxFee: Number(values["max-fee"]), journalDir: dir });
  if (command === "request") {
    const { response, receipt } = await consumer.request({
      endpoint: "responses", model: values.model, content: rest.join(" "), maxOutputTokens: Number(values["max-output-tokens"]),
      provider: values.provider, onDelta: values.stream ? (text) => process.stderr.write(text) : undefined,
    });
    if (values.stream) process.stderr.write("\n");
    const output = response.output;
    stdout.write(`${JSON.stringify({ output_text: output.output_text ?? output, fee: receipt.receipt.actual_fee,
      provider: receipt.authorization.provider_signer, request_id: receipt.authorization.request_id,
      settlement_key: settlementKey(receipt.authorization.key, receipt.authorization.request_id) })}\n`);
    return 0;
  }
  if (command === "serve") {
    const server = await serveConsumer(consumer, { host: values.host, port: Number(values.port), apiKey: process.env.MYCOMESH_CONSUMER_API_KEY });
    const { port } = server.address();
    stdout.write(`MycoMesh V11 Consumer on http://${values.host}:${port}/v1 (payment key ${consumer.key})\n`);
    return new Promise(() => {});
  }
  throw new Error(`unknown command ${command}\n${USAGE}`);
}
