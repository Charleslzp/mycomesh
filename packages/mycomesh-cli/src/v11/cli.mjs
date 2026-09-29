// mycomesh-consumer (V11): init, setup, balance, request, serve.
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { addressOf, encodeCall } from "./eip712.mjs";
import { availableBalance, sendTransaction } from "./chain.mjs";
import { Consumer, loadNetwork, serveConsumer } from "./consumer.mjs";

const USAGE = `Usage: mycomesh-consumer <command> [options]

  init                     create the local payment key (never leaves this machine)
  address                  print the payment key address
  setup --owner-key-file F --deposit UNITS [--max-per-request UNITS]
                           deposit into the settlement contract and authorize the payment key
  balance [--owner ADDR]   show the custodied deposit
  request "prompt"         send one request and print the verified answer
  serve [--port 8110]      run the local OpenAI-compatible endpoint (default)

Common: --network FILE (MycoMesh V11 manifest), --data-dir DIR, --model ID, --max-fee UNITS`;

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
    },
  });
  const [command = "serve", ...rest] = positionals;
  if (values.help || command === "help") { stdout.write(`${USAGE}\n`); return 0; }
  const dir = dataDir(values["data-dir"]);
  if (command === "init" || command === "address") {
    stdout.write(`${addressOf(paymentKey(dir, command === "init"))}\n`);
    return 0;
  }
  if (!values.network) throw new Error("--network is required");
  const network = loadNetwork(values.network);
  const keyPrivate = paymentKey(dir);
  if (command === "setup") {
    const owner = readKey(values["owner-key-file"]);
    const deposit = BigInt(values.deposit);
    const limit = BigInt(values["max-per-request"] || values["max-fee"]);
    await sendTransaction(network.rpc_urls, owner, { to: network.stablecoin,
      data: encodeCall("approve(address,uint256)", [["address", network.settlement], ["uint", deposit]]) });
    await sendTransaction(network.rpc_urls, owner, { to: network.settlement, data: encodeCall("deposit(uint256)", [["uint", deposit]]) });
    await sendTransaction(network.rpc_urls, owner, { to: network.settlement,
      data: encodeCall("registerKey(address,uint256,uint64)", [["address", addressOf(keyPrivate)], ["uint", limit], ["uint", 0]]) });
    stdout.write(`deposited ${deposit} and authorized ${addressOf(keyPrivate)} up to ${limit} per request\n`);
    return 0;
  }
  if (command === "balance") {
    const owner = values.owner || (values["owner-key-file"] ? addressOf(readKey(values["owner-key-file"])) : null);
    if (!owner) throw new Error("--owner or --owner-key-file is required");
    stdout.write(`${await availableBalance(network, owner)}\n`);
    return 0;
  }
  const consumer = new Consumer({ network, keyPrivate, maxFee: Number(values["max-fee"]) });
  if (command === "request") {
    const { response, receipt } = await consumer.request({
      endpoint: "responses", model: values.model, content: rest.join(" "), maxOutputTokens: Number(values["max-output-tokens"]),
    });
    const output = response.output;
    stdout.write(`${JSON.stringify({ output_text: output.output_text ?? output, fee: receipt.receipt.actual_fee,
      provider: receipt.authorization.provider_signer, request_id: receipt.authorization.request_id })}\n`);
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
