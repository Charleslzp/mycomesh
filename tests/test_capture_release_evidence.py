import contextlib
import hashlib
import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway import chain
from scripts import capture_release_evidence as capture
from scripts.release_gate import DEPLOYED_CODE_SCHEMA


ROOT = Path(__file__).parents[1]
SOURCE_COMMIT = "a" * 40
ADDRESS = "0x" + "1" * 40
TRANSACTION_HASH = "0x" + "2" * 64
BLOCK_HASH = "0x" + "3" * 64
REORG_BLOCK_HASH = "0x" + "4" * 64
STATE_BLOCK_HASH = "0x" + "5" * 64
CHANNEL_BLOCK_HASH = "0x" + "6" * 64
CHANNEL_TRANSACTION_HASH = "0x" + "7" * 64
CHANNEL_ID = ""
CHAIN_ID = 11155111
DEPLOYMENT_BLOCK = 100
CHANNEL_BLOCK = 101
STATE_BLOCK = 105
RUNTIME_CODE = "0x6001600055"
STABLECOIN_RUNTIME_CODE = "0x6002600055"
RPC_URLS = ["https://rpc-one.example", "https://rpc-two.example/v1"]
STABLECOIN = "0x" + "a1" * 20
GOVERNANCE = "0x" + "a2" * 20
TREASURY = "0x" + "a3" * 20
ADJUDICATORS = ["0x" + "b1" * 20, "0x" + "b2" * 20, "0x" + "b3" * 20]
CONSUMER_OWNER = "0x" + "c1" * 20
CONSUMER_KEY = "0x" + "c2" * 20
PROVIDER_OWNER = "0x" + "c3" * 20
PROVIDER_SIGNER = "0x" + "c4" * 20
RELAY_OWNER = "0x" + "c5" * 20
RELAY_SIGNER = "0x" + "c6" * 20
POOL = chain.ZERO_ADDRESS
CHANNEL_HASH = "0x" + "d1" * 32
PRICING_HASH = "0x" + "d2" * 32
STATE_TIMESTAMP = 1_800_000_100


def base_manifest():
    return {
        "protocol_version": 10, "chain_id": CHAIN_ID,
        "deployment_block": DEPLOYMENT_BLOCK, "settlement": ADDRESS,
        "tx_hash": TRANSACTION_HASH, "deployer": GOVERNANCE,
        "stablecoin": STABLECOIN, "reward_token": chain.ZERO_ADDRESS,
        "stablecoin_runtime_code_sha256": hashlib.sha256(
            bytes.fromhex(STABLECOIN_RUNTIME_CODE[2:])
        ).hexdigest(),
        "stablecoin_runtime_code_keccak256": "0x" + chain.keccak256(
            bytes.fromhex(STABLECOIN_RUNTIME_CODE[2:])
        ).hex(),
        "governance": GOVERNANCE, "treasury": TREASURY,
        "adjudication_threshold": 2, "adjudicators": ADJUDICATORS,
        "eip712_name": "MycoMesh Settlement", "eip712_version": "10",
        "policy": {
            "dispute_window": 300, "arbitration_timeout": 600,
            "consumer_withdrawal_delay": 300, "reporter_bond": 10_000,
            "slash_bps": 10_000, "slash_cap": 100_000,
            "reporter_bounty_bps": 2_000, "stable_bounty_cap": 20_000,
            "token_reward": 0, "token_reward_cap": 0,
            "token_minimum_exposure": 0, "token_minimum_penalty": 0,
            "bond_penalty_recipient": GOVERNANCE,
        },
        "channel_hash": CHANNEL_HASH, "pricing_version": 1,
        "pricing_hash": PRICING_HASH,
        "capacity_channel_ids": [CHANNEL_ID],
        "fresh_channel_open_tx_hashes": [CHANNEL_TRANSACTION_HASH],
        "fresh_channel_capacity": 1_000_000,
        "fresh_channel_max_fee_per_request": 100_000,
        "fresh_channel_valid_from": 1_800_000_000,
        "fresh_channel_admit_until": 1_800_010_000,
        "fresh_channel_claim_until": 1_800_020_000,
        "relay": {"payment_address": RELAY_OWNER, "attestation_address": RELAY_SIGNER},
        "relay_fallbacks": [],
    }


def base_network_manifest():
    manifest = base_manifest()
    return {
        "protocol_version": 10,
        "deployment": "deployment.json",
        **{
            key: manifest[key] for key in (
                "capacity_channel_ids", "fresh_channel_open_tx_hashes",
                "fresh_channel_capacity", "fresh_channel_max_fee_per_request",
                "fresh_channel_valid_from", "fresh_channel_admit_until",
                "fresh_channel_claim_until",
            )
        },
        "relay": {
            "payment_address": RELAY_OWNER,
            "attestation_address": RELAY_SIGNER,
        },
        "relay_fallbacks": [],
    }


def abi_word(value):
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    if isinstance(value, str) and len(value) == 42:
        return b"\0" * 12 + bytes.fromhex(value[2:])
    if isinstance(value, str) and len(value) == 66:
        return bytes.fromhex(value[2:])
    raise AssertionError(value)


def abi_result(*values):
    return "0x" + b"".join(abi_word(value) for value in values).hex()


CHANNEL_ID = capture._capacity_channel_id(
    {
        "eip712_name": "MycoMesh Settlement", "eip712_version": "10",
        "chain_id": CHAIN_ID, "settlement": ADDRESS,
    },
    [
        CONSUMER_OWNER, CONSUMER_KEY, PROVIDER_OWNER, PROVIDER_SIGNER,
        RELAY_OWNER, RELAY_SIGNER, POOL,
    ],
    CHANNEL_HASH,
    PRICING_HASH,
    {
        "pricing_version": 1,
        "capacity": 1_000_000,
        "max_fee_per_request": 100_000,
        "valid_from": 1_800_000_000,
        "admit_until": 1_800_010_000,
        "claim_until": 1_800_020_000,
        "consumer_nonce": 0,
        "provider_nonce": 0,
        "permit_deadline": 1_800_010_000,
    },
)


class FakeRPC:
    def __init__(self, manifest=None):
        self.manifest = manifest or base_manifest()
        self.calls = []
        self.chain_ids = {}
        self.heads = {}
        self.receipt_overrides = {}
        self.channel_receipt_overrides = {}
        self.transaction_overrides = {}
        self.runtime_codes = {}
        self.stablecoin_runtime_codes = {}
        self.stablecoin_balance = 2_000_000
        self.stable_liabilities = 1_500_000
        self.final_block_hashes = {}
        self.state_timestamps = {}
        self.channel_state = {}
        self.block_calls = {}

    def __call__(self, rpc_url, method, params, timeout):
        self.calls.append((rpc_url, method, params, timeout))
        if method == "eth_chainId":
            return hex(self.chain_ids.get(rpc_url, CHAIN_ID))
        if method == "eth_getTransactionReceipt":
            transaction_hash = params[0]
            if transaction_hash == CHANNEL_TRANSACTION_HASH:
                event_topic = "0x" + chain.keccak256(
                    b"CapacityChannelOpened(bytes32,address,address,uint256,uint64,uint64)"
                ).hex()
                receipt = {
                    "transactionHash": CHANNEL_TRANSACTION_HASH,
                    "blockHash": CHANNEL_BLOCK_HASH,
                    "blockNumber": hex(CHANNEL_BLOCK), "status": "0x1",
                    "to": ADDRESS, "contractAddress": None,
                    "logs": [{
                        "address": ADDRESS,
                        "transactionHash": CHANNEL_TRANSACTION_HASH,
                        "blockHash": CHANNEL_BLOCK_HASH,
                        "blockNumber": hex(CHANNEL_BLOCK),
                        "logIndex": "0x0",
                        "removed": False,
                        "topics": [
                            event_topic,
                            CHANNEL_ID,
                            abi_result(CONSUMER_OWNER),
                            abi_result(PROVIDER_OWNER),
                        ],
                        "data": abi_result(
                            self.manifest["fresh_channel_capacity"],
                            self.manifest["fresh_channel_valid_from"],
                            self.manifest["fresh_channel_claim_until"],
                        ),
                    }],
                }
            else:
                receipt = {
                    "transactionHash": TRANSACTION_HASH,
                    "blockHash": BLOCK_HASH,
                    "blockNumber": hex(DEPLOYMENT_BLOCK),
                    "status": "0x1", "contractAddress": ADDRESS,
                }
            overrides = (
                self.channel_receipt_overrides if transaction_hash == CHANNEL_TRANSACTION_HASH
                else self.receipt_overrides
            )
            receipt.update(overrides.get(rpc_url, {}))
            return receipt
        if method == "eth_getTransactionByHash":
            transaction = {"hash": TRANSACTION_HASH, "from": GOVERNANCE, "to": None,
                           "blockHash": BLOCK_HASH, "blockNumber": hex(DEPLOYMENT_BLOCK)}
            transaction.update(self.transaction_overrides.get(rpc_url, {}))
            return transaction
        if method == "eth_blockNumber":
            return hex(self.heads.get(rpc_url, STATE_BLOCK + 5))
        if method == "eth_getBlockByNumber":
            number = int(params[0], 16)
            key = (rpc_url, number)
            count = self.block_calls.get(key, 0) + 1
            self.block_calls[key] = count
            block_hash = {DEPLOYMENT_BLOCK: BLOCK_HASH, CHANNEL_BLOCK: CHANNEL_BLOCK_HASH,
                          STATE_BLOCK: STATE_BLOCK_HASH}.get(number, "0x" + "9" * 64)
            if number == DEPLOYMENT_BLOCK and count > 1:
                block_hash = self.final_block_hashes.get(rpc_url, BLOCK_HASH)
            return {"hash": block_hash, "number": hex(number),
                    "timestamp": hex(self.state_timestamps.get(rpc_url, STATE_TIMESTAMP))}
        if method == "eth_getCode":
            if params[0] == STABLECOIN:
                return self.stablecoin_runtime_codes.get(rpc_url, STABLECOIN_RUNTIME_CODE)
            return self.runtime_codes.get(rpc_url, RUNTIME_CODE)
        if method == "eth_call":
            data = params[0]["data"]
            selector = data[:10]
            selectors = {
                signature: chain.encode_contract_call(signature, [])[:10]
                for signature in (
                    "stablecoin()", "rewardToken()", "adjudicationThreshold()",
                    "governance()", "treasury()", "DOMAIN_SEPARATOR()",
                    "adjudicators()", "policy()", "latestChannelVersion(bytes32)",
                    "channelVersions(bytes32,uint64)", "channelInfo(bytes32)",
                    "stableLiabilities()", "balanceOf(address)",
                )
            }
            if selector == selectors["stablecoin()"]:
                return abi_result(STABLECOIN)
            if selector == selectors["rewardToken()"]:
                return abi_result(chain.ZERO_ADDRESS)
            if selector == selectors["adjudicationThreshold()"]:
                return abi_result(2)
            if selector == selectors["governance()"]:
                return abi_result(GOVERNANCE)
            if selector == selectors["treasury()"]:
                return abi_result(TREASURY)
            if selector == selectors["DOMAIN_SEPARATOR()"]:
                return abi_result(capture._domain_separator(self.manifest))
            if selector == selectors["stableLiabilities()"]:
                return abi_result(self.stable_liabilities)
            if selector == selectors["balanceOf(address)"]:
                return abi_result(self.stablecoin_balance)
            if selector == selectors["adjudicators()"]:
                return abi_result(32, len(ADJUDICATORS), *ADJUDICATORS)
            if selector == selectors["policy()"]:
                policy = self.manifest["policy"]
                return abi_result(
                    *(policy[name] for name in (
                        "dispute_window", "arbitration_timeout", "consumer_withdrawal_delay",
                        "reporter_bond", "slash_bps", "slash_cap", "reporter_bounty_bps",
                        "stable_bounty_cap", "token_reward", "token_reward_cap",
                        "token_minimum_exposure", "token_minimum_penalty",
                    )), policy["bond_penalty_recipient"],
                )
            if selector == selectors["latestChannelVersion(bytes32)"]:
                return abi_result(1)
            if selector == selectors["channelVersions(bytes32,uint64)"]:
                return abi_result(
                    1, 2, self.channel_state.get("minimum_fee", 3),
                    8500, 300, 200, 1000, True, TREASURY, PRICING_HASH,
                )
            if selector == selectors["channelInfo(bytes32)"]:
                return abi_result(
                    CONSUMER_OWNER, CONSUMER_KEY, PROVIDER_OWNER, PROVIDER_SIGNER,
                    RELAY_OWNER, RELAY_SIGNER, POOL, CHANNEL_HASH, 1, PRICING_HASH,
                    self.manifest["fresh_channel_capacity"],
                    self.manifest["fresh_channel_max_fee_per_request"],
                    self.manifest["fresh_channel_valid_from"],
                    self.manifest["fresh_channel_admit_until"],
                    self.manifest["fresh_channel_claim_until"],
                    0, 0, self.manifest["fresh_channel_admit_until"],
                    self.channel_state.get("settled_max_fee", 0),
                    self.channel_state.get(
                        "credit_remaining", self.manifest["fresh_channel_capacity"],
                    ),
                    self.channel_state.get(
                        "stake_remaining", self.manifest["fresh_channel_capacity"],
                    ),
                    self.channel_state.get("closed", False),
                )
            raise AssertionError(f"unexpected selector: {selector}")
        raise AssertionError(f"unexpected RPC method: {method}")


class CaptureReleaseEvidenceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.manifest = base_manifest()
        self.manifest_path = self.directory / "deployment.json"
        self.manifest_raw = self._write_manifest(self.manifest)
        self.network_manifest = base_network_manifest()
        self.network_manifest_path = self.directory / "provider-network.json"
        self.network_manifest_raw = (
            json.dumps(self.network_manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        self.network_manifest_path.write_bytes(self.network_manifest_raw)

    def _write_manifest(self, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.manifest_path.write_bytes(raw)
        return raw

    def _write_network_manifest(self, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.network_manifest_path.write_bytes(raw)
        return raw

    def _capture(self, rpc=None, **overrides):
        arguments = {
            "deployment_path": self.manifest_path,
            "provider_network_path": self.network_manifest_path,
            "source_commit": SOURCE_COMMIT,
            "rpc_urls": list(RPC_URLS),
            "confirmations": 6,
            "timeout": 7.5,
            "rpc_call": rpc or FakeRPC(self.manifest),
        }
        arguments.update(overrides)
        return capture.capture_release_evidence(**arguments)

    def test_capture_matches_release_gate_schema_and_pins_runtime_to_block_hash(self):
        rpc = FakeRPC()
        evidence = self._capture(rpc)
        runtime = bytes.fromhex(RUNTIME_CODE[2:])

        self.assertEqual(capture.SCHEMA, DEPLOYED_CODE_SCHEMA)
        self.assertEqual(
            set(evidence),
            {
                "schema", "source_commit", "chain_id", "address",
                "transaction_hash", "block_number", "block_hash", "runtime_code",
                "runtime_code_sha256", "runtime_code_keccak256", "confirmations",
                "rpc_quorum", "deployment_manifest_sha256",
                "provider_network_manifest_sha256", "deployer",
                "state_block_number", "state_block_hash", "state_block_timestamp",
                "contract_state", "capacity_channels",
            },
        )
        self.assertEqual(evidence["schema"], DEPLOYED_CODE_SCHEMA)
        self.assertEqual(evidence["source_commit"], SOURCE_COMMIT)
        self.assertEqual(evidence["chain_id"], CHAIN_ID)
        self.assertEqual(evidence["address"], ADDRESS)
        self.assertEqual(evidence["transaction_hash"], TRANSACTION_HASH)
        self.assertEqual(evidence["block_number"], DEPLOYMENT_BLOCK)
        self.assertEqual(evidence["block_hash"], BLOCK_HASH)
        self.assertEqual(evidence["runtime_code"], RUNTIME_CODE)
        self.assertEqual(evidence["runtime_code_sha256"], hashlib.sha256(runtime).hexdigest())
        self.assertEqual(
            evidence["runtime_code_keccak256"], "0x" + chain.keccak256(runtime).hex()
        )
        self.assertEqual(evidence["confirmations"], 6)
        self.assertEqual(evidence["rpc_quorum"], 2)
        self.assertEqual(evidence["deployer"], GOVERNANCE)
        self.assertEqual(evidence["state_block_number"], STATE_BLOCK)
        self.assertEqual(evidence["state_block_hash"], STATE_BLOCK_HASH)
        self.assertEqual(evidence["state_block_timestamp"], STATE_TIMESTAMP)
        self.assertEqual(evidence["capacity_channels"][0]["channel_id"], CHANNEL_ID)
        self.assertEqual(
            evidence["deployment_manifest_sha256"],
            hashlib.sha256(self.manifest_raw).hexdigest(),
        )
        self.assertEqual(
            evidence["provider_network_manifest_sha256"],
            hashlib.sha256(self.network_manifest_raw).hexdigest(),
        )

        code_calls = [
            item for item in rpc.calls
            if item[1] == "eth_getCode" and item[2][0] == ADDRESS
        ]
        self.assertEqual(len(code_calls), 2)
        for rpc_url, _, params, timeout in code_calls:
            self.assertIn(rpc_url, RPC_URLS)
            self.assertEqual(
                params,
                [ADDRESS, {"blockHash": BLOCK_HASH, "requireCanonical": True}],
            )
            self.assertEqual(timeout, 7.5)
        for rpc_url in RPC_URLS:
            self.assertEqual(rpc.block_calls[(rpc_url, DEPLOYMENT_BLOCK)], 2)
            self.assertEqual(rpc.block_calls[(rpc_url, CHANNEL_BLOCK)], 1)
            self.assertEqual(rpc.block_calls[(rpc_url, STATE_BLOCK)], 2)

    def test_repository_v10_manifest_has_capture_identity_fields(self):
        manifest_path = ROOT / "deployments/sepolia-myco-v10.json"
        manifest, raw = capture._load_manifest(manifest_path)
        self.assertEqual(manifest["protocol_version"], 10)
        self.assertGreater(manifest["chain_id"], 0)
        self.assertGreaterEqual(manifest["deployment_block"], 0)
        self.assertEqual(capture._address(manifest["settlement"], "settlement"),
                         manifest["settlement"])
        self.assertEqual(capture._hash(manifest["tx_hash"], "tx hash"),
                         manifest["tx_hash"])
        self.assertEqual(raw, manifest_path.read_bytes())

    def test_independent_rpc_runtime_disagreement_is_rejected(self):
        rpc = FakeRPC()
        rpc.runtime_codes[RPC_URLS[1]] = "0x6002600055"
        with self.assertRaisesRegex(capture.EvidenceError, "disagree"):
            self._capture(rpc)

    def test_chain_receipt_and_confirmation_must_match_manifest(self):
        cases = {
            "wrong chain": ("chain_ids", CHAIN_ID + 1, "chain id differs"),
            "failed receipt": ("receipt_overrides", {"status": "0x0"}, "receipt differs"),
            "wrong transaction": (
                "receipt_overrides", {"transactionHash": "0x" + "9" * 64},
                "receipt differs",
            ),
            "wrong contract": (
                "receipt_overrides", {"contractAddress": "0x" + "9" * 40},
                "receipt differs",
            ),
            "wrong block": (
                "receipt_overrides", {"blockNumber": hex(DEPLOYMENT_BLOCK + 1)},
                "receipt differs",
            ),
            "insufficient confirmations": (
                "heads", DEPLOYMENT_BLOCK + 4, "sufficiently confirmed",
            ),
        }
        for label, (attribute, value, message) in cases.items():
            with self.subTest(label=label):
                rpc = FakeRPC()
                getattr(rpc, attribute)[RPC_URLS[0]] = value
                with self.assertRaisesRegex(capture.EvidenceError, message):
                    self._capture(rpc)

    def test_reorganization_during_capture_is_rejected(self):
        rpc = FakeRPC()
        rpc.final_block_hashes[RPC_URLS[0]] = REORG_BLOCK_HASH
        with self.assertRaisesRegex(capture.EvidenceError, "reorganized"):
            self._capture(rpc)

    def test_network_manifest_and_confirmed_state_must_agree(self):
        changed = dict(self.network_manifest)
        changed["deployment"] = "other.json"
        self._write_network_manifest(changed)
        with self.assertRaisesRegex(capture.EvidenceError, "wrong deployment"):
            self._capture()

        changed = dict(self.network_manifest)
        changed["fresh_channel_capacity"] += 1
        self._write_network_manifest(changed)
        with self.assertRaisesRegex(capture.EvidenceError, "bindings drift"):
            self._capture()

        self._write_network_manifest(self.network_manifest)
        rpc = FakeRPC(self.manifest)
        rpc.state_timestamps[RPC_URLS[1]] = STATE_TIMESTAMP + 1
        with self.assertRaisesRegex(capture.EvidenceError, "state timestamp"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        for url in RPC_URLS:
            rpc.state_timestamps[url] = self.manifest["fresh_channel_valid_from"] - 1
        with self.assertRaisesRegex(capture.EvidenceError, "admission window"):
            self._capture(rpc)

    def test_deployment_sender_channel_budget_and_open_event_are_proven(self):
        rpc = FakeRPC(self.manifest)
        rpc.transaction_overrides[RPC_URLS[0]] = {"from": "0x" + "9" * 40}
        with self.assertRaisesRegex(capture.EvidenceError, "sender or creation target"):
            self._capture(rpc)

        cases = (
            ({"closed": True}, "usable manifest budget"),
            ({"credit_remaining": self.manifest["fresh_channel_max_fee_per_request"] - 1},
             "usable manifest budget"),
            ({"settled_max_fee": self.manifest["fresh_channel_capacity"]},
             "usable manifest budget"),
            ({"minimum_fee": 0}, "positive minimum fee"),
        )
        for state, message in cases:
            with self.subTest(state=state):
                rpc = FakeRPC(self.manifest)
                rpc.channel_state.update(state)
                with self.assertRaisesRegex(capture.EvidenceError, message):
                    self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.channel_receipt_overrides[RPC_URLS[0]] = {"logs": []}
        with self.assertRaisesRegex(capture.EvidenceError, "does not prove"):
            self._capture(rpc)

    def test_stablecoin_runtime_and_solvency_are_pinned(self):
        rpc = FakeRPC(self.manifest)
        rpc.stablecoin_runtime_codes[RPC_URLS[0]] = "0x6003600055"
        with self.assertRaisesRegex(capture.EvidenceError, "stablecoin runtime"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.stablecoin_balance = rpc.stable_liabilities - 1
        with self.assertRaisesRegex(capture.EvidenceError, "does not cover"):
            self._capture(rpc)

    def test_noncanonical_rpc_values_and_invalid_runtime_are_rejected(self):
        cases = {
            "uppercase hash": (
                "receipt_overrides", {"blockHash": BLOCK_HASH.upper()}, "invalid receipt block hash"
            ),
            "leading-zero block": (
                "receipt_overrides", {"blockNumber": "0x064"}, "invalid receipt block number"
            ),
            "empty runtime": ("runtime_codes", "0x", "invalid deployed runtime code"),
            "zero runtime": ("runtime_codes", "0x0000", "runtime code is empty"),
            "uppercase runtime": (
                "runtime_codes", "0x60AA", "invalid deployed runtime code"
            ),
        }
        for label, (attribute, value, message) in cases.items():
            with self.subTest(label=label):
                rpc = FakeRPC()
                if attribute == "receipt_overrides":
                    rpc.receipt_overrides[RPC_URLS[0]] = value
                else:
                    getattr(rpc, attribute)[RPC_URLS[0]] = value
                with self.assertRaisesRegex(capture.EvidenceError, message):
                    self._capture(rpc)

    def test_release_inputs_are_strictly_validated(self):
        invalid_calls = (
            ({"source_commit": None}, "source commit"),
            ({"source_commit": "A" * 40}, "source commit"),
            ({"confirmations": True}, "2 to 256"),
            ({"confirmations": 1}, "2 to 256"),
            ({"confirmations": 257}, "2 to 256"),
            ({"timeout": True}, "timeout"),
            ({"timeout": math.nan}, "timeout"),
            ({"timeout": 61}, "timeout"),
            ({"rpc_urls": tuple(RPC_URLS)}, "list of URLs"),
            ({"rpc_urls": [RPC_URLS[0]]}, "two distinct"),
            (
                {"rpc_urls": ["https://rpc-one.example/a", "https://rpc-one.example/b"]},
                "two distinct",
            ),
            ({"rpc_urls": ["http://rpc-one.example", RPC_URLS[1]]}, "credential-free HTTPS"),
            ({"rpc_urls": ["https://user:pass@rpc-one.example", RPC_URLS[1]]},
             "credential-free HTTPS"),
            ({"rpc_urls": ["https://rpc-one.example:bad", RPC_URLS[1]]},
             "credential-free HTTPS"),
            ({"rpc_urls": ["https://bad host.example", RPC_URLS[1]]}, "valid DNS"),
            ({"rpc_urls": [" https://rpc-one.example", RPC_URLS[1]]},
             "credential-free HTTPS"),
            ({"rpc_urls": ["https://rpc-one.example,https://fallback.example", RPC_URLS[1]]},
             "credential-free HTTPS"),
        )
        for overrides, message in invalid_calls:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(capture.EvidenceError, message):
                    self._capture(**overrides)

    def test_manifest_must_be_strict_v10_json_with_canonical_identity(self):
        raw_cases = (
            (b'{"protocol_version":10,"protocol_version":10}', "duplicate JSON key"),
            (b'{"protocol_version":10,"chain_id":NaN}', "invalid JSON constant"),
            (b'{"protocol_version":9}', "protocol V10"),
        )
        for raw, message in raw_cases:
            with self.subTest(raw=raw):
                self.manifest_path.write_bytes(raw)
                with self.assertRaisesRegex(capture.EvidenceError, message):
                    self._capture()

        invalid_manifests = (
            ({**self.manifest, "chain_id": True}, "chain_id"),
            ({**self.manifest, "deployment_block": True}, "deployment_block"),
            ({**self.manifest, "settlement": ADDRESS.upper()}, "manifest settlement"),
            ({**self.manifest, "settlement": chain.ZERO_ADDRESS}, "manifest settlement"),
            ({**self.manifest, "tx_hash": TRANSACTION_HASH.upper()}, "manifest transaction"),
        )
        for manifest, message in invalid_manifests:
            with self.subTest(manifest=manifest):
                self._write_manifest(manifest)
                with self.assertRaisesRegex(capture.EvidenceError, message):
                    self._capture()

    def test_main_writes_strict_json_once_and_refuses_to_overwrite(self):
        output = self.directory / "nested/evidence.json"
        evidence = {"schema": capture.SCHEMA, "source_commit": SOURCE_COMMIT}
        arguments = [
            "--deployment", str(self.manifest_path),
            "--provider-network", str(self.network_manifest_path),
            "--source-commit", SOURCE_COMMIT,
            "--rpc-url", RPC_URLS[0],
            "--rpc-url", RPC_URLS[1],
            "--output", str(output),
        ]
        stdout = io.StringIO()
        with patch.object(capture, "capture_release_evidence", return_value=evidence), \
                contextlib.redirect_stdout(stdout):
            self.assertEqual(capture.main(arguments), 0)
        self.assertEqual(json.loads(output.read_text()), evidence)
        self.assertEqual(json.loads(stdout.getvalue())["schema"], capture.SCHEMA)

        stderr = io.StringIO()
        with patch.object(capture, "capture_release_evidence", return_value=evidence), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(capture.main(arguments), 1)
        self.assertIn("File exists", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
