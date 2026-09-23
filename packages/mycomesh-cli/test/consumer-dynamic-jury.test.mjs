import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { ed25519 } from "@noble/curves/ed25519";

import {
  NativeConsumerState,
  parseNetworkConfig,
  verifyJuryEvidenceReference,
} from "../src/consumer-runtime.mjs";

const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const hash = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const abiAddress = (value) => `0x${value.slice(2).padStart(64, "0")}`;
const abiUint = (value) => `0x${BigInt(value).toString(16).padStart(64, "0")}`;
const bytesHex = (value) => Buffer.from(value).toString("hex");
const JURY_PRIVATE_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const JURY_PUBLIC_KEY = bytesHex(ed25519.getPublicKey(JURY_PRIVATE_KEY));
const HISTORICAL_RUNTIME = "0x6001600055";
const HISTORICAL_RUNTIME_HASH = `0x${bytesHex(keccak_256(Buffer.from(HISTORICAL_RUNTIME.slice(2), "hex")))}`;
const SETTLEMENT_RUNTIME = "0x6000";
const SETTLEMENT_RUNTIME_HASH = `0x${bytesHex(keccak_256(Buffer.from(SETTLEMENT_RUNTIME.slice(2), "hex")))}`;

function dynamicManifest() {
  const governance = address(5);
  const genesisHash = hash(50);
  return {
    protocol_version: 10,
    eip712_name: "MycoMesh Settlement",
    eip712_version: "10",
    reservation_mode: "provider_bound_channel",
    chain_domain: "10",
    max_authorization_ttl_seconds: 10800,
    authorization_deadline_seconds: 9000,
    max_channel_duration_seconds: 2592000,
    chain_id: 11155111,
    deployer: address(1),
    stablecoin: address(2),
    settlement: address(3),
    deployment_block: 100,
    deployment_block_hash: hash(56),
    settlement_runtime_code_keccak256: SETTLEMENT_RUNTIME_HASH,
    treasury: address(4),
    governance,
    channel: "codex",
    channel_hash: hash(6),
    pricing_version: 1,
    pricing_hash: hash(7),
    reward_token: address(0),
    network_id: "dynamic-jury-controlled-test",
    channel_id: "codex",
    backend_policy: "fixture",
    committee_mode: "dynamic_provider_ai_v1",
    jury_registry: address(20),
    jury_registry_governance: governance,
    reputation_authority: address(21),
    minimum_provider_reputation: 100,
    jury_size: 3,
    adjudication_threshold: 2,
    jury_selection_delay_blocks: 8,
    jury_randomness: "future_blockhash_v1",
    jury_decision_policy_hash: hash(49),
    genesis_hash: genesisHash,
    reputation_history_import: {
      schema: "mycomesh.v10.reputation-history-import.v1",
      source_network_id: "prior-v9-controlled-test",
      source_protocol_version: 9,
      source_chain_id: 11155111,
      source_genesis_hash: genesisHash,
      source_settlement_contract: address(22),
      source_runtime_code_hash: HISTORICAL_RUNTIME_HASH,
      source_deployment_block: 90,
      source_deployment_block_hash: hash(53),
      source_history_through_block: 99,
      source_history_through_block_hash: hash(54),
      confirmations: 6,
      artifact_sha256: "51".repeat(32),
      artifact_root: hash(52),
    },
    jury_relay_public_keys: [JURY_PUBLIC_KEY],
    policy: {
      dispute_window: 60,
      arbitration_timeout: 120,
      consumer_withdrawal_delay: 60,
      reporter_bond: 100,
      slash_bps: 5000,
      slash_cap: 10000,
      reporter_bounty_bps: 2000,
      stable_bounty_cap: 1000,
      token_reward: 0,
      token_reward_cap: 0,
      token_minimum_exposure: 0,
      token_minimum_penalty: 0,
      bond_penalty_recipient: address(9),
    },
    capacity_channel_ids: [hash(80)],
    settlement_rpc_urls: ["https://rpc.example"],
  };
}

async function withManifest(t, value) {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-dynamic-jury-"));
  const path = join(directory, "network.json");
  await writeFile(path, JSON.stringify(value));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return path;
}

test("dynamic Provider AI jury manifest does not require a static adjudicator roster", async (t) => {
  const manifest = dynamicManifest();
  assert.equal(manifest.adjudicators, undefined);
  const path = await withManifest(t, manifest);
  assert.throws(() => parseNetworkConfig(path), /controlled-test opt-in/);
  const network = parseNetworkConfig(path, { allowControlledTest: true });
  assert.equal(network.committee_mode, "dynamic_provider_ai_v1");
  assert.equal(network.jury_registry, manifest.jury_registry);
  assert.equal(network.jury_registry_governance, manifest.jury_registry_governance);
  assert.equal(network.reputation_authority, manifest.reputation_authority);
  assert.equal(network.minimum_provider_reputation, 100);
  assert.equal(network.jury_size, 3);
  assert.equal(network.adjudication_threshold, 2);
  assert.equal(network.jury_selection_delay_blocks, 8);
  assert.equal(network.jury_decision_policy_hash, manifest.jury_decision_policy_hash);
  assert.equal(network.genesis_hash, manifest.genesis_hash);
  assert.equal(network.deployment_block, manifest.deployment_block);
  assert.equal(network.deployment_block_hash, manifest.deployment_block_hash);
  assert.equal(
    network.settlement_runtime_code_keccak256,
    manifest.settlement_runtime_code_keccak256,
  );
  assert.deepEqual(network.reputation_history_import, manifest.reputation_history_import);
  assert.deepEqual(network.jury_relay_public_keys, [JURY_PUBLIC_KEY]);
  assert.equal(network.jury_provider_count, undefined);
});

test("dynamic Provider AI jury requires a unique canonical network Relay key set", async (t) => {
  const cases = [
    ["missing", (value) => { delete value.jury_relay_public_keys; }],
    ["empty", (value) => { value.jury_relay_public_keys = []; }],
    ["duplicate", (value) => { value.jury_relay_public_keys = [JURY_PUBLIC_KEY, JURY_PUBLIC_KEY]; }],
    ["uppercase", (value) => { value.jury_relay_public_keys = [JURY_PUBLIC_KEY.toUpperCase()]; }],
    ["too many", (value) => { value.jury_relay_public_keys = ["11", "22", "33", "44", "55"].map((part) => part.repeat(32)); }],
  ];
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-dynamic-jury-relay-keys-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const [name, mutate] of cases) {
    const manifest = dynamicManifest();
    mutate(manifest);
    const path = join(directory, `${name}.json`);
    await writeFile(path, JSON.stringify(manifest));
    assert.throws(
      () => parseNetworkConfig(path, { allowControlledTest: true }),
      /jury Relay public keys|dynamic V10 network requires/,
      name,
    );
  }
});

test("jury Relay identity pins live in the network layer, never the deployment", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-dynamic-jury-layering-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const deployment = dynamicManifest();
  delete deployment.jury_relay_public_keys;
  const deploymentPath = join(directory, "deployment.json");
  await writeFile(deploymentPath, JSON.stringify(deployment));
  const networkPath = join(directory, "network.json");
  await writeFile(networkPath, JSON.stringify({
    ...deployment,
    deployment: "deployment.json",
    jury_relay_public_keys: [JURY_PUBLIC_KEY],
  }));
  assert.deepEqual(
    parseNetworkConfig(networkPath, { allowControlledTest: true }).jury_relay_public_keys,
    [JURY_PUBLIC_KEY],
  );

  await writeFile(deploymentPath, JSON.stringify({
    ...deployment,
    jury_relay_public_keys: [JURY_PUBLIC_KEY],
  }));
  assert.throws(
    () => parseNetworkConfig(networkPath, { allowControlledTest: true }),
    /belongs only in the network manifest/,
  );
});

test("dynamic Provider AI jury manifest rejects unsafe policy and a pinned roster", async (t) => {
  const cases = [
    ["registry aliases settlement", (value) => { value.jury_registry = value.settlement; }],
    ["registry governance drift", (value) => { value.jury_registry_governance = address(99); }],
    ["non-majority threshold", (value) => { value.adjudication_threshold = 1; }],
    ["unsupported randomness", (value) => { value.jury_randomness = "latest_blockhash"; }],
    ["missing decision policy hash", (value) => { delete value.jury_decision_policy_hash; }],
    ["zero decision policy hash", (value) => { value.jury_decision_policy_hash = hash(0); }],
    ["noncanonical decision policy hash", (value) => { value.jury_decision_policy_hash = value.jury_decision_policy_hash.toUpperCase(); }],
    ["missing deployment block", (value) => { delete value.deployment_block; }],
    ["zero deployment block", (value) => { value.deployment_block = 0; }],
    ["zero deployment block hash", (value) => { value.deployment_block_hash = hash(0); }],
    ["zero Settlement runtime hash", (value) => { value.settlement_runtime_code_keccak256 = hash(0); }],
    ["missing history", (value) => { delete value.reputation_history_import; }],
    ["null history", (value) => { value.reputation_history_import = null; }],
    ["extra history field", (value) => { value.reputation_history_import.unexpected = true; }],
    ["wrong source chain", (value) => { value.reputation_history_import.source_chain_id = 1; }],
    ["wrong source genesis", (value) => { value.reputation_history_import.source_genesis_hash = hash(99); }],
    ["new settlement reused", (value) => { value.reputation_history_import.source_settlement_contract = value.settlement; }],
    ["uppercase artifact SHA", (value) => { value.reputation_history_import.artifact_sha256 = "AA".repeat(32); }],
    ["low confirmations", (value) => { value.reputation_history_import.confirmations = 1; }],
    ["zero source deployment block", (value) => { value.reputation_history_import.source_deployment_block = 0; }],
    ["history cutoff before deployment", (value) => { value.reputation_history_import.source_history_through_block = 89; }],
    ["zero history cutoff hash", (value) => { value.reputation_history_import.source_history_through_block_hash = hash(0); }],
    ["static adjudicators", (value) => { value.adjudicators = []; }],
    ["static adjudicator operators", (value) => { value.adjudicator_operators = {}; }],
    ["static independence attestation", (value) => { value.independence_attested = false; }],
    ["pinned mutable roster", (value) => { value.jury_provider_evidence = []; }],
  ];
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-dynamic-jury-invalid-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const [name, mutate] of cases) {
    const manifest = dynamicManifest();
    mutate(manifest);
    const path = join(directory, `${name.replaceAll(" ", "-")}.json`);
    await writeFile(path, JSON.stringify(manifest));
    assert.throws(() => parseNetworkConfig(path, { allowControlledTest: true }), /Invalid configured settlement network/, name);
  }
});

test("dynamic Provider AI jury rejects static committee fields carried by the network manifest", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-dynamic-jury-network-schema-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const deploymentPath = join(directory, "deployment.json");
  await writeFile(deploymentPath, JSON.stringify(dynamicManifest()));
  for (const [name, value] of Object.entries({
    adjudicators: [],
    adjudicator_operators: {},
    independence_attested: false,
    jury_provider_evidence: [],
  })) {
    const path = join(directory, `network-${name}.json`);
    await writeFile(path, JSON.stringify({
      ...dynamicManifest(),
      deployment: "deployment.json",
      [name]: value,
    }));
    assert.throws(
      () => parseNetworkConfig(path, { allowControlledTest: true }),
      new RegExp(`network manifest contains forbidden static committee fields: ${name}`),
    );
  }
});

test("dynamic Provider AI jury requires exact deployment/network history lineage parity", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-dynamic-history-layering-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const deployment = dynamicManifest();
  delete deployment.jury_relay_public_keys;
  await writeFile(join(directory, "deployment.json"), JSON.stringify(deployment));
  for (const mutation of ["missing", "drift"]) {
    const network = {
      ...deployment,
      deployment: "deployment.json",
      jury_relay_public_keys: [JURY_PUBLIC_KEY],
      reputation_history_import: mutation === "drift"
        ? { ...deployment.reputation_history_import, artifact_root: hash(99) }
        : deployment.reputation_history_import,
    };
    if (mutation === "missing") delete network.reputation_history_import;
    const path = join(directory, `${mutation}.json`);
    await writeFile(path, JSON.stringify(network));
    assert.throws(
      () => parseNetworkConfig(path, { allowControlledTest: true }),
      /history lineage differs/,
    );
  }
});

test("dynamic Provider AI jury requires exact deployment boundary parity", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-dynamic-boundary-layering-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const deployment = dynamicManifest();
  delete deployment.jury_relay_public_keys;
  await writeFile(join(directory, "deployment.json"), JSON.stringify(deployment));
  for (const mutation of ["missing", "drift"]) {
    const network = {
      ...deployment,
      deployment: "deployment.json",
      jury_relay_public_keys: [JURY_PUBLIC_KEY],
    };
    if (mutation === "missing") delete network.deployment_block_hash;
    else network.settlement_runtime_code_keccak256 = hash(99);
    const path = join(directory, `boundary-${mutation}.json`);
    await writeFile(path, JSON.stringify(network));
    assert.throws(
      () => parseNetworkConfig(path, { allowControlledTest: true }),
      /Settlement deployment boundary differs/,
    );
  }
});

function runtimeState(network, overrides = {}, rpcOverrides = {}) {
  const values = {
    "juryRegistry()": abiAddress(network.jury_registry),
    "adjudicationThreshold()": abiUint(network.adjudication_threshold),
    "settlement()": abiAddress(network.settlement_contract),
    "governance()": abiAddress(network.jury_registry_governance),
    "reputationAuthority()": abiAddress(network.reputation_authority),
    "bondPenaltyRecipient()": abiAddress(network.bond_penalty_recipient),
    "minimumReputation()": abiUint(network.minimum_provider_reputation),
    "jurySize()": abiUint(network.jury_size),
    "threshold()": abiUint(network.adjudication_threshold),
    "selectionDelayBlocks()": abiUint(network.jury_selection_delay_blocks),
    "RANDOMNESS_MODE_HASH()": `0x${Buffer.from(keccak_256(Buffer.from("future_blockhash_v1"))).toString("hex")}`,
    "rosterVersion()": abiUint(3),
    "providerCount()": abiUint(network.jury_size),
    "canFormJury()": abiUint(1),
    ...overrides,
  };
  const calls = [];
  const state = Object.create(NativeConsumerState.prototype);
  state.network = network;
  state.preferredRpcUrl = null;
  state.callRpc = async (_rpc, method, params = []) => {
    if (method === "eth_chainId") return `0x${network.chain_id.toString(16)}`;
    if (method === "eth_blockNumber") {
      return rpcOverrides.head || "0x6e";
    }
    if (method === "eth_getBlockByNumber") {
      const number = BigInt(params[0]);
      const history = network.reputation_history_import;
      if (number === 0n) return {
        number: "0x0", hash: rpcOverrides.genesisHash || network.genesis_hash,
      };
      if (number === BigInt(history.source_deployment_block)) return {
        number: params[0],
        hash: rpcOverrides.sourceDeploymentHash || history.source_deployment_block_hash,
      };
      if (number === BigInt(history.source_history_through_block)) return {
        number: params[0],
        hash: rpcOverrides.sourceThroughHash || history.source_history_through_block_hash,
      };
      if (number === BigInt(history.source_deployment_block) - 1n) return {
        number: params[0], hash: hash(55),
      };
      if (number === BigInt(network.deployment_block)) return {
        number: params[0],
        hash: rpcOverrides.settlementDeploymentHash || network.deployment_block_hash,
      };
      throw new Error(`unexpected source block ${params[0]}`);
    }
    if (method === "eth_getCode") {
      if (params[0] === network.settlement_contract) {
        return rpcOverrides.settlementCode || SETTLEMENT_RUNTIME;
      }
      if (params[0] === network.reputation_history_import.source_settlement_contract) {
        if (params[1]?.blockHash === hash(55)) {
          return rpcOverrides.predeploymentCode || "0x";
        }
        return rpcOverrides.historicalCode || HISTORICAL_RUNTIME;
      }
      return SETTLEMENT_RUNTIME;
    }
    throw new Error(`unexpected RPC method ${method}`);
  };
  state.contractCall = async (_rpc, contract, signature) => {
    calls.push([contract, signature]);
    if (!(signature in values)) throw new Error(`unexpected contract getter ${signature}`);
    return values[signature];
  };
  return { state, calls };
}

test("dynamic Provider AI jury readiness binds every Settlement and registry getter", async (t) => {
  const path = await withManifest(t, dynamicManifest());
  const network = parseNetworkConfig(path, { allowControlledTest: true });
  const { state, calls } = runtimeState(network);
  assert.equal(await state.settlementNetworkReady(), true);
  assert.deepEqual(calls.map(([, signature]) => signature), [
    "juryRegistry()", "adjudicationThreshold()", "settlement()", "governance()", "reputationAuthority()",
    "bondPenaltyRecipient()", "minimumReputation()", "jurySize()", "threshold()", "selectionDelayBlocks()",
    "RANDOMNESS_MODE_HASH()", "rosterVersion()",
    "providerCount()", "canFormJury()",
  ]);
  assert.ok(calls.slice(0, 2).every(([contract]) => contract === network.settlement_contract));
  assert.ok(calls.slice(2).every(([contract]) => contract === network.jury_registry));
});

test("dynamic Provider AI jury readiness fails closed on drift, unavailable roster, or malformed ABI", async (t) => {
  const path = await withManifest(t, dynamicManifest());
  const network = parseNetworkConfig(path, { allowControlledTest: true });
  const cases = [
    ["settlement registry", { "juryRegistry()": abiAddress(address(99)) }],
    ["settlement threshold", { "adjudicationThreshold()": abiUint(3) }],
    ["registry settlement", { "settlement()": abiAddress(address(99)) }],
    ["registry governance", { "governance()": abiAddress(address(99)) }],
    ["reputation authority", { "reputationAuthority()": abiAddress(address(99)) }],
    ["bond penalty recipient", { "bondPenaltyRecipient()": abiAddress(address(99)) }],
    ["minimum reputation", { "minimumReputation()": abiUint(99) }],
    ["jury size", { "jurySize()": abiUint(4) }],
    ["registry threshold", { "threshold()": abiUint(3) }],
    ["selection delay", { "selectionDelayBlocks()": abiUint(9) }],
    ["randomness mode", { "RANDOMNESS_MODE_HASH()": hash(99) }],
    ["zero roster version", { "rosterVersion()": abiUint(0) }],
    ["provider pool too small", { "providerCount()": abiUint(2) }],
    ["provider pool too large", { "providerCount()": abiUint(65) }],
    ["cannot form jury", { "canFormJury()": abiUint(0) }],
    ["non-canonical bool", { "canFormJury()": abiUint(2) }],
    ["malformed ABI", { "providerCount()": "0x03" }],
  ];
  for (const [name, overrides] of cases) {
    const { state } = runtimeState(network, overrides);
    await assert.rejects(() => state.settlementNetworkReady(), /all configured Settlement V10 RPC endpoints failed/, name);
  }
  for (const [name, rpcOverrides] of [
    ["genesis drift", { genesisHash: hash(99) }],
    ["historical runtime drift", { historicalCode: "0x6002600055" }],
    ["source deployment reorg", { sourceDeploymentHash: hash(99) }],
    ["history cutoff reorg", { sourceThroughHash: hash(99) }],
    ["unsafe history cutoff", { head: "0x67" }],
    ["preexisting historical contract", { predeploymentCode: "0x6000" }],
    ["Settlement deployment reorg", { settlementDeploymentHash: hash(99) }],
    ["Settlement runtime drift", { settlementCode: "0x6001" }],
  ]) {
    const { state } = runtimeState(network, {}, rpcOverrides);
    await assert.rejects(
      () => state.settlementNetworkReady(),
      /all configured Settlement V10 RPC endpoints failed/,
      name,
    );
  }
});

test("legacy static V10 committee manifests still use the existing validator", async (t) => {
  const manifest = dynamicManifest();
  manifest.chain_id = 31337;
  manifest.network_id = "static-jury-controlled-test";
  manifest.committee_mode = "controlled_test";
  manifest.independence_attested = false;
  manifest.adjudicators = [address(10), address(11), address(12)];
  manifest.adjudicator_operators = Object.fromEntries(manifest.adjudicators.map((judge) => [judge, "test-operator"]));
  for (const field of ["jury_registry", "jury_registry_governance", "reputation_authority", "minimum_provider_reputation",
    "jury_size", "jury_selection_delay_blocks", "jury_randomness", "jury_decision_policy_hash",
    "jury_provider_evidence", "jury_relay_public_keys", "reputation_history_import"]) delete manifest[field];
  const path = await withManifest(t, manifest);
  const network = parseNetworkConfig(path, { allowControlledTest: true });
  assert.equal(network.committee_mode, "controlled_test");
  assert.equal(network.jury_registry, undefined);
});

function stableStringify(value) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

function signedEvidenceReference() {
  const schema = "mycomesh.v10.provider-jury-evidence-reference.v1";
  const settlementKey = hash(90);
  const reporter = address(91);
  const evidenceHash = hash(92);
  const body = {
    schema,
    network: "eip155:11155111",
    chain_id: 11155111,
    settlement_contract: address(3),
    settlement_key: settlementKey,
    request_id: hash(93),
    request_hash: hash(94),
    evidence_hash: evidenceHash,
    predicted_report_id: `0x${bytesHex(keccak_256(Buffer.concat([
      Buffer.from(settlementKey.slice(2), "hex"),
      Buffer.alloc(12), Buffer.from(reporter.slice(2), "hex"),
      Buffer.from(evidenceHash.slice(2), "hex"),
    ])))}`,
    reporter,
    origin_relay_public_key: JURY_PUBLIC_KEY,
  };
  const metadata = {
    nonce: evidenceHash.slice(2, 34),
    public_key: JURY_PUBLIC_KEY,
    purpose: schema,
    timestamp: 1700000000,
    audience: `${schema}:eip155:11155111:${address(3)}:${reporter}`,
  };
  const message = Buffer.from(stableStringify({ document: body, signature: metadata }), "utf8");
  return {
    ...body,
    signature: { ...metadata, signature: bytesHex(ed25519.sign(message, JURY_PRIVATE_KEY)) },
  };
}

test("Consumer verifies every signed evidence-reference binding against the pinned origin", () => {
  const reference = signedEvidenceReference();
  const expected = {
    chainId: reference.chain_id,
    contract: reference.settlement_contract,
    settlementKey: reference.settlement_key,
    requestId: reference.request_id,
    requestHash: reference.request_hash,
    reporter: reference.reporter,
    issuedAt: reference.signature.timestamp,
    juryRelayPublicKeys: [JURY_PUBLIC_KEY],
  };
  assert.deepEqual(verifyJuryEvidenceReference(reference, expected), reference);
  for (const [name, changed] of [
    ["evidence hash", { ...reference, evidence_hash: hash(95) }],
    ["report id", { ...reference, predicted_report_id: hash(96) }],
    ["reporter", { ...reference, reporter: address(97) }],
    ["signature", { ...reference, signature: { ...reference.signature, signature: "00".repeat(64) } }],
  ]) {
    assert.throws(() => verifyJuryEvidenceReference(changed, expected), /jury evidence/, name);
  }
  assert.throws(
    () => verifyJuryEvidenceReference(reference, { ...expected, juryRelayPublicKeys: ["11".repeat(32)] }),
    /pinned origin/,
  );
});
