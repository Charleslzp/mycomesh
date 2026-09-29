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
JURY_REGISTRY_RUNTIME_CODE = "0x6003600055"
RPC_URLS = ["https://rpc-one.example", "https://rpc-two.example/v1"]
STABLECOIN = "0x" + "a1" * 20
GOVERNANCE = "0x" + "a2" * 20
TREASURY = "0x" + "a3" * 20
JURY_REGISTRY = "0x" + "a4" * 20
REPUTATION_AUTHORITY = "0x" + "a5" * 20
ADJUDICATORS = ["0x" + "b1" * 20, "0x" + "b2" * 20, "0x" + "b3" * 20]
CONSUMER_OWNER = "0x" + "c1" * 20
CONSUMER_KEY = "0x" + "c2" * 20
PROVIDER_OWNER = "0x" + "c3" * 20
PROVIDER_SIGNER = "0x" + "c4" * 20
RELAY_OWNER = "0x" + "c5" * 20
RELAY_SIGNER = "0x" + "c6" * 20
JURY_TRANSACTION_SENDER = "0x" + "e1" * 20
JURY_TRANSACTION_GAS_CAP_WEI = 1_000_000_000_000_000
SOURCE_SETTLEMENT = "0x" + "e2" * 20
SOURCE_GENESIS_HASH = "0x" + "8" * 64
SOURCE_RUNTIME_CODE = "0x6004600055"
SOURCE_DEPLOYMENT_BLOCK = 90
SOURCE_DEPLOYMENT_BLOCK_HASH = "0x" + "81" * 32
SOURCE_PREDEPLOYMENT_BLOCK_HASH = "0x" + "80" * 32
SOURCE_HISTORY_THROUGH_BLOCK = 99
SOURCE_HISTORY_THROUGH_BLOCK_HASH = "0x" + "82" * 32
POOL = chain.ZERO_ADDRESS
CHANNEL_HASH = "0x" + "d1" * 32
PRICING_HASH = "0x" + "d2" * 32
STATE_TIMESTAMP = 1_800_000_100
JURY_PROVIDERS = [
    {
        "owner": "0x" + f"{100 + index:040x}",
        "vote_signer": "0x" + f"{200 + index:040x}",
        "operator_id_hash": "0x" + f"{index + 1:064x}",
        "peer_id_hash": "0x" + f"{index + 11:064x}",
        "capability_hash": "0x" + f"{index + 21:064x}",
        "reputation": 90 - index,
        "active": True,
        "source_sequence": index + 1,
        "source_digest": "0x" + f"{index + 31:064x}",
    }
    for index in range(3)
]


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
        "max_channel_duration_seconds": 604_800,
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
        "fresh_channel_open_block_timestamps": [1_799_999_900],
        "fresh_channel_capacity": 1_000_000,
        "fresh_channel_max_fee_per_request": 100_000,
        "fresh_channel_valid_from": 1_800_000_000,
        "fresh_channel_admit_until": 1_800_010_000,
        "fresh_channel_claim_until": 1_800_020_000,
        "relay": {"payment_address": RELAY_OWNER, "attestation_address": RELAY_SIGNER},
        "relay_fallbacks": [],
    }


def dynamic_manifest():
    manifest = base_manifest()
    manifest.update({
        "network_id": "mycomesh-v10-dynamic-provider-ai-controlled-test",
        "genesis_hash": SOURCE_GENESIS_HASH,
        "committee_mode": capture.DYNAMIC_JURY_MODE,
        "jury_registry": JURY_REGISTRY,
        "jury_registry_governance": GOVERNANCE,
        "reputation_authority": REPUTATION_AUTHORITY,
        "minimum_provider_reputation": 80,
        "jury_size": 3,
        "jury_selection_delay_blocks": 2,
        "jury_randomness": "future_blockhash_v1",
        "jury_decision_policy_hash": "0x" + "31" * 32,
        "deployment_block_hash": BLOCK_HASH,
        "settlement_runtime_code_keccak256": "0x" + chain.keccak256(
            bytes.fromhex(RUNTIME_CODE[2:])
        ).hex(),
        capture.REPUTATION_HISTORY_FIELD: {
            "schema": capture.REPUTATION_HISTORY_SCHEMA,
            "source_network_id": "mycomesh-v9-prior",
            "source_protocol_version": 9,
            "source_chain_id": CHAIN_ID,
            "source_genesis_hash": SOURCE_GENESIS_HASH,
            "source_settlement_contract": SOURCE_SETTLEMENT,
            "source_runtime_code_hash": "0x" + chain.keccak256(
                bytes.fromhex(SOURCE_RUNTIME_CODE[2:])
            ).hex(),
            "source_deployment_block": SOURCE_DEPLOYMENT_BLOCK,
            "source_deployment_block_hash": SOURCE_DEPLOYMENT_BLOCK_HASH,
            "source_history_through_block": SOURCE_HISTORY_THROUGH_BLOCK,
            "source_history_through_block_hash": SOURCE_HISTORY_THROUGH_BLOCK_HASH,
            "confirmations": 6,
            "artifact_sha256": "71" * 32,
            "artifact_root": "0x" + "72" * 32,
        },
    })
    manifest.pop("adjudicators")
    return manifest


def base_network_manifest(manifest=None):
    manifest = manifest or base_manifest()
    return {
        "protocol_version": 10,
        "deployment": "deployment.json",
        **{
            key: manifest[key] for key in (
                "capacity_channel_ids", "fresh_channel_open_tx_hashes",
                "fresh_channel_open_block_timestamps",
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
        **({"jury_relay_public_keys": ["11" * 32]}
           if manifest.get("committee_mode") == capture.DYNAMIC_JURY_MODE else {}),
        **({
            "jury_transaction_senders": {
                "11" * 32: JURY_TRANSACTION_SENDER,
            },
            capture.JURY_TRANSACTION_GAS_CAP_FIELD:
                JURY_TRANSACTION_GAS_CAP_WEI,
            capture.REPUTATION_HISTORY_FIELD:
                manifest[capture.REPUTATION_HISTORY_FIELD],
            "deployment_block": manifest["deployment_block"],
            "deployment_block_hash": manifest["deployment_block_hash"],
            "settlement_runtime_code_keccak256": manifest[
                "settlement_runtime_code_keccak256"
            ],
        } if manifest.get("committee_mode") == capture.DYNAMIC_JURY_MODE else {}),
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
        self.registry_runtime_codes = {}
        self.registry_state_overrides = {}
        self.registry_provider_overrides = {}
        self.registry_source_overrides = {}
        self.jury_sender_codes = {}
        self.jury_sender_confirmed_nonces = {}
        self.jury_sender_latest_nonces = {}
        self.jury_sender_pending_nonces = {}
        self.jury_sender_balances = {}
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
                          STATE_BLOCK: STATE_BLOCK_HASH,
                          SOURCE_DEPLOYMENT_BLOCK: SOURCE_DEPLOYMENT_BLOCK_HASH,
                          SOURCE_DEPLOYMENT_BLOCK - 1: SOURCE_PREDEPLOYMENT_BLOCK_HASH,
                          SOURCE_HISTORY_THROUGH_BLOCK: SOURCE_HISTORY_THROUGH_BLOCK_HASH,
                          0: SOURCE_GENESIS_HASH}.get(number, "0x" + "9" * 64)
            if number == DEPLOYMENT_BLOCK and count > 1:
                block_hash = self.final_block_hashes.get(rpc_url, BLOCK_HASH)
            timestamp = (
                self.manifest["fresh_channel_open_block_timestamps"][0]
                if number == CHANNEL_BLOCK
                else self.state_timestamps.get(rpc_url, STATE_TIMESTAMP)
            )
            return {"hash": block_hash, "number": hex(number),
                    "timestamp": hex(timestamp)}
        if method == "eth_getCode":
            if params[0] == JURY_TRANSACTION_SENDER:
                return self.jury_sender_codes.get(rpc_url, "0x")
            if params[0] == STABLECOIN:
                return self.stablecoin_runtime_codes.get(rpc_url, STABLECOIN_RUNTIME_CODE)
            if params[0] == JURY_REGISTRY:
                return self.registry_runtime_codes.get(rpc_url, JURY_REGISTRY_RUNTIME_CODE)
            if params[0] == SOURCE_SETTLEMENT:
                if params[1] == {
                    "blockHash": SOURCE_PREDEPLOYMENT_BLOCK_HASH,
                    "requireCanonical": True,
                }:
                    return "0x"
                return SOURCE_RUNTIME_CODE
            return self.runtime_codes.get(rpc_url, RUNTIME_CODE)
        if method == "eth_getTransactionCount":
            if params[0] != JURY_TRANSACTION_SENDER:
                raise AssertionError(f"unexpected nonce address: {params[0]}")
            tag = params[1]
            if tag == "latest":
                return hex(self.jury_sender_latest_nonces.get(rpc_url, 7))
            if tag == "pending":
                return hex(self.jury_sender_pending_nonces.get(rpc_url, 7))
            return hex(self.jury_sender_confirmed_nonces.get(rpc_url, 6))
        if method == "eth_getBalance":
            if params[0] != JURY_TRANSACTION_SENDER:
                raise AssertionError(f"unexpected balance address: {params[0]}")
            return hex(self.jury_sender_balances.get(
                rpc_url, JURY_TRANSACTION_GAS_CAP_WEI * 2,
            ))
        if method == "eth_call":
            target = params[0]["to"]
            data = params[0]["data"]
            selector = data[:10]
            selectors = {
                signature: chain.encode_contract_call(signature, [])[:10]
                for signature in (
                    "stablecoin()", "rewardToken()", "adjudicationThreshold()",
                    "governance()", "treasury()", "DOMAIN_SEPARATOR()",
                    "MAX_CHANNEL_DURATION()",
                    "adjudicators()", "policy()", "latestChannelVersion(bytes32)",
                    "channelVersions(bytes32,uint64)", "channelInfo(bytes32)",
                    "stableLiabilities()", "balanceOf(address)", "juryRegistry()",
                    "reputationAuthority()", "settlement()", "bondPenaltyRecipient()",
                    "minimumReputation()", "jurySize()", "threshold()",
                    "selectionDelayBlocks()", "RANDOMNESS_MODE_HASH()",
                    "providerCount()", "rosterVersion()", "pendingAssignments()",
                    "canFormJury()", "canFormJuryFor(bytes32)",
                    "providerAt(uint256)", "providerSourceSequence(address)",
                    "providerSourceDigest(address)",
                )
            }
            if target == JURY_REGISTRY:
                providers = [
                    self.registry_provider_overrides.get((rpc_url, index), provider)
                    for index, provider in enumerate(JURY_PROVIDERS)
                ]
                state = {
                    "governance": self.manifest["jury_registry_governance"],
                    "reputation_authority": self.manifest["reputation_authority"],
                    "settlement": self.manifest["settlement"],
                    "bond_penalty_recipient": self.manifest["policy"][
                        "bond_penalty_recipient"
                    ],
                    "minimum_reputation": self.manifest["minimum_provider_reputation"],
                    "jury_size": self.manifest["jury_size"],
                    "threshold": self.manifest["adjudication_threshold"],
                    "selection_delay_blocks": self.manifest[
                        "jury_selection_delay_blocks"
                    ],
                    "randomness": "0x" + chain.keccak256(
                        self.manifest["jury_randomness"].encode()
                    ).hex(),
                    "provider_count": len(providers),
                    "roster_version": len(providers),
                    "pending_assignments": 0,
                    "can_form_jury": True,
                }
                state.update(self.registry_state_overrides.get(rpc_url, {}))
                registry_scalars = {
                    "governance()": "governance",
                    "reputationAuthority()": "reputation_authority",
                    "settlement()": "settlement",
                    "bondPenaltyRecipient()": "bond_penalty_recipient",
                    "minimumReputation()": "minimum_reputation",
                    "jurySize()": "jury_size",
                    "threshold()": "threshold",
                    "selectionDelayBlocks()": "selection_delay_blocks",
                    "RANDOMNESS_MODE_HASH()": "randomness",
                    "providerCount()": "provider_count",
                    "rosterVersion()": "roster_version",
                    "pendingAssignments()": "pending_assignments",
                    "canFormJury()": "can_form_jury",
                }
                for signature, key in registry_scalars.items():
                    if selector == selectors[signature]:
                        return abi_result(state[key])
                if selector == selectors["providerAt(uint256)"]:
                    index = int(data[10:74], 16)
                    provider = providers[index]
                    return abi_result(
                        provider["owner"], provider["vote_signer"],
                        provider["operator_id_hash"], provider["peer_id_hash"],
                        provider["capability_hash"], provider["reputation"],
                        provider["active"],
                    )
                if selector in {
                    selectors["providerSourceSequence(address)"],
                    selectors["providerSourceDigest(address)"],
                }:
                    owner = "0x" + data[-40:]
                    provider = next(item for item in providers if item["owner"] == owner)
                    source = {
                        "source_sequence": provider["source_sequence"],
                        "source_digest": provider["source_digest"],
                    }
                    source.update(self.registry_source_overrides.get((rpc_url, owner), {}))
                    key = (
                        "source_sequence"
                        if selector == selectors["providerSourceSequence(address)"]
                        else "source_digest"
                    )
                    return abi_result(source[key])
                if selector == selectors["canFormJuryFor(bytes32)"]:
                    return abi_result(state.get("channel_jury_ready", True))
                raise AssertionError(f"unexpected registry selector: {selector}")
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
            if selector == selectors["MAX_CHANNEL_DURATION()"]:
                return abi_result(self.manifest["max_channel_duration_seconds"])
            if selector == selectors["juryRegistry()"]:
                return abi_result(self.manifest["jury_registry"])
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
        self.consumer_manifest_path = self.directory / "consumer-network.json"
        self.consumer_manifest_raw = self._write_consumer_manifest(
            self._consumer_manifest(self.manifest, self.network_manifest)
        )

    def _write_manifest(self, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.manifest_path.write_bytes(raw)
        return raw

    def _write_network_manifest(self, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.network_manifest_path.write_bytes(raw)
        return raw

    @staticmethod
    def _consumer_manifest(manifest, network_manifest):
        return {
            **manifest,
            **{
                key: value for key, value in network_manifest.items()
                if key not in {"deployment", "tls_ca_file"}
            },
        }

    def _write_consumer_manifest(self, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.consumer_manifest_path.write_bytes(raw)
        return raw

    def _capture(self, rpc=None, **overrides):
        arguments = {
            "deployment_path": self.manifest_path,
            "provider_network_path": self.network_manifest_path,
            "consumer_network_path": self.consumer_manifest_path,
            "source_commit": SOURCE_COMMIT,
            "rpc_urls": list(RPC_URLS),
            "confirmations": 6,
            "timeout": 7.5,
            "rpc_call": rpc or FakeRPC(self.manifest),
        }
        arguments.update(overrides)
        return capture.capture_release_evidence(**arguments)

    def _use_dynamic_manifest(self):
        self.manifest = dynamic_manifest()
        self.manifest_raw = self._write_manifest(self.manifest)
        self.network_manifest = base_network_manifest(self.manifest)
        self.network_manifest_raw = self._write_network_manifest(self.network_manifest)
        self.consumer_manifest_raw = self._write_consumer_manifest(
            self._consumer_manifest(self.manifest, self.network_manifest)
        )

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
                "consumer_network_manifest_sha256",
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
        self.assertEqual(
            evidence["consumer_network_manifest_sha256"],
            hashlib.sha256(self.consumer_manifest_raw).hexdigest(),
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

    def _pin_deployment_commit(self, commit):
        self.manifest["source_commit"] = commit
        self.manifest_raw = self._write_manifest(self.manifest)
        self.network_manifest = base_network_manifest(self.manifest)
        self.network_manifest["source_commit"] = commit
        self.network_manifest_raw = self._write_network_manifest(self.network_manifest)
        self.consumer_manifest_raw = self._write_consumer_manifest(
            self._consumer_manifest(self.manifest, self.network_manifest)
        )

    def test_deployed_code_binds_to_manifest_pinned_deployment_commit(self):
        self._use_dynamic_manifest()
        deployment_commit = "c" * 40
        self._pin_deployment_commit(deployment_commit)
        evidence = self._capture(FakeRPC(self.manifest))
        # A later application release reuses the deployed contracts, so the
        # bytecode evidence names the pinned deployment commit, not the release.
        self.assertEqual(evidence["source_commit"], deployment_commit)
        self.assertNotEqual(deployment_commit, SOURCE_COMMIT)
        self._pin_deployment_commit("C" * 40)
        with self.assertRaisesRegex(capture.EvidenceError, "deployment source_commit"):
            self._capture(FakeRPC(self.manifest))

    def test_dynamic_jury_capture_pins_full_registry_snapshot_to_state_block(self):
        self._use_dynamic_manifest()
        rpc = FakeRPC(self.manifest)
        evidence = self._capture(rpc)
        registry = evidence["jury_registry_state"]
        registry_runtime = bytes.fromhex(JURY_REGISTRY_RUNTIME_CODE[2:])

        self.assertEqual(
            set(registry),
            {
                "address", "governance", "reputation_authority", "settlement",
                "bond_penalty_recipient", "minimum_reputation", "jury_size",
                "threshold", "selection_delay_blocks", "randomness",
                "provider_count", "roster_version", "pending_assignments",
                "can_form_jury", "providers", "runtime_code",
                "runtime_code_sha256", "runtime_code_keccak256",
            },
        )
        self.assertEqual(registry["address"], JURY_REGISTRY)
        self.assertEqual(registry["providers"], JURY_PROVIDERS)
        self.assertEqual(registry["provider_count"], len(JURY_PROVIDERS))
        self.assertEqual(registry["roster_version"], len(JURY_PROVIDERS))
        self.assertEqual(registry["pending_assignments"], 0)
        self.assertIs(registry["can_form_jury"], True)
        self.assertEqual(registry["runtime_code"], JURY_REGISTRY_RUNTIME_CODE)
        self.assertEqual(
            registry["runtime_code_sha256"], hashlib.sha256(registry_runtime).hexdigest()
        )
        self.assertEqual(
            registry["runtime_code_keccak256"],
            "0x" + chain.keccak256(registry_runtime).hex(),
        )
        self.assertEqual(evidence["contract_state"]["jury_registry"], JURY_REGISTRY)
        self.assertIs(evidence["capacity_channels"][0]["jury_ready"], True)
        self.assertEqual(
            evidence["jury_decision_policy_hash"],
            self.manifest["jury_decision_policy_hash"],
        )
        self.assertNotIn("adjudicators", evidence["contract_state"])
        sender = evidence["jury_transaction_senders"]["11" * 32]
        self.assertEqual(sender["address"], JURY_TRANSACTION_SENDER)
        self.assertEqual(sender["latest_nonce"], sender["pending_nonce"])
        self.assertFalse(sender["pending_transaction"])
        self.assertGreaterEqual(
            sender["balance_wei"], JURY_TRANSACTION_GAS_CAP_WEI,
        )
        self.assertEqual(
            evidence[capture.REPUTATION_HISTORY_FIELD],
            self.manifest[capture.REPUTATION_HISTORY_FIELD],
        )

        state_tag = {"blockHash": STATE_BLOCK_HASH, "requireCanonical": True}
        registry_calls = [
            call for call in rpc.calls
            if call[1] == "eth_call" and call[2][0]["to"] == JURY_REGISTRY
        ]
        self.assertGreater(len(registry_calls), len(JURY_PROVIDERS))
        for _, _, params, _ in registry_calls:
            self.assertEqual(params[1], state_tag)
        registry_code_calls = [
            call for call in rpc.calls
            if call[1] == "eth_getCode" and call[2][0] == JURY_REGISTRY
        ]
        self.assertEqual(len(registry_code_calls), len(RPC_URLS))
        for _, _, params, _ in registry_code_calls:
            self.assertEqual(params, [JURY_REGISTRY, state_tag])

        adjudicators_selector = chain.encode_contract_call("adjudicators()", [])[:10]
        provider_at_selector = chain.encode_contract_call("providerAt(uint256)", [])[:10]
        source_sequence_selector = chain.encode_contract_call(
            "providerSourceSequence(address)", [],
        )[:10]
        source_digest_selector = chain.encode_contract_call(
            "providerSourceDigest(address)", [],
        )[:10]
        channel_ready_selector = chain.encode_contract_call(
            "canFormJuryFor(bytes32)", [],
        )[:10]
        self.assertEqual(
            sum(
                call[1] == "eth_call"
                and call[2][0]["data"][:10] == provider_at_selector
                for call in rpc.calls
            ),
            len(RPC_URLS) * len(JURY_PROVIDERS),
        )
        for selector in (source_sequence_selector, source_digest_selector):
            self.assertEqual(
                sum(
                    call[1] == "eth_call"
                    and call[2][0]["data"][:10] == selector
                    for call in rpc.calls
                ),
                len(RPC_URLS) * len(JURY_PROVIDERS),
            )
        self.assertEqual(
            sum(
                call[1] == "eth_call"
                and call[2][0]["data"][:10] == channel_ready_selector
                for call in rpc.calls
            ),
            len(RPC_URLS),
        )
        self.assertFalse(any(
            call[1] == "eth_call" and call[2][0]["data"][:10] == adjudicators_selector
            for call in rpc.calls
        ))

    def test_dynamic_jury_capture_requires_canonical_nonzero_decision_policy_hash(self):
        for value in (None, "0x" + "0" * 64, "0x" + "AB" * 32):
            with self.subTest(value=value):
                self._use_dynamic_manifest()
                if value is None:
                    self.manifest.pop("jury_decision_policy_hash")
                else:
                    self.manifest["jury_decision_policy_hash"] = value
                self.manifest_raw = self._write_manifest(self.manifest)
                self.network_manifest = base_network_manifest(self.manifest)
                self.network_manifest_raw = self._write_network_manifest(
                    self.network_manifest
                )
                self.consumer_manifest_raw = self._write_consumer_manifest(
                    self._consumer_manifest(self.manifest, self.network_manifest)
                )
                with self.assertRaisesRegex(capture.EvidenceError, "decision policy hash"):
                    self._capture(FakeRPC(self.manifest))

    def test_dynamic_jury_sender_manifest_and_live_state_are_fail_closed(self):
        self._use_dynamic_manifest()
        relay_key = "11" * 32

        changed = dict(self.network_manifest)
        changed["jury_transaction_senders"] = {relay_key: GOVERNANCE}
        self._write_network_manifest(changed)
        self._write_consumer_manifest(self._consumer_manifest(self.manifest, changed))
        with self.assertRaisesRegex(capture.EvidenceError, "known manifest role"):
            self._capture(FakeRPC(self.manifest))

        self.network_manifest_raw = self._write_network_manifest(self.network_manifest)
        self.consumer_manifest_raw = self._write_consumer_manifest(
            self._consumer_manifest(self.manifest, self.network_manifest)
        )
        rpc = FakeRPC(self.manifest)
        rpc.jury_sender_codes[RPC_URLS[0]] = "0x6000"
        with self.assertRaisesRegex(capture.EvidenceError, "canonical EOA"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.jury_sender_balances[RPC_URLS[0]] = JURY_TRANSACTION_GAS_CAP_WEI - 1
        with self.assertRaisesRegex(capture.EvidenceError, "does not cover"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.jury_sender_latest_nonces[RPC_URLS[0]] = 8
        rpc.jury_sender_pending_nonces[RPC_URLS[0]] = 8
        with self.assertRaisesRegex(capture.EvidenceError, "disagree"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        for url in RPC_URLS:
            rpc.jury_sender_pending_nonces[url] = 8
        evidence = self._capture(rpc)
        sender = evidence["jury_transaction_senders"][relay_key]
        self.assertTrue(sender["pending_transaction"])
        self.assertEqual(sender["pending_nonce"], 8)

    def test_dynamic_reputation_history_lineage_is_exact_and_live_bound(self):
        self._use_dynamic_manifest()
        for mutation in (
            "missing", "null", "extra", "provider-drift", "high-confirmations",
            "invalid-history-range", "missing-boundary", "provider-boundary-drift",
        ):
            with self.subTest(mutation=mutation):
                manifest = dynamic_manifest()
                network = base_network_manifest(manifest)
                consumer = self._consumer_manifest(manifest, network)
                if mutation == "missing":
                    manifest.pop(capture.REPUTATION_HISTORY_FIELD)
                elif mutation == "null":
                    manifest[capture.REPUTATION_HISTORY_FIELD] = None
                elif mutation == "extra":
                    manifest[capture.REPUTATION_HISTORY_FIELD]["unexpected"] = True
                elif mutation == "high-confirmations":
                    manifest[capture.REPUTATION_HISTORY_FIELD]["confirmations"] = 257
                elif mutation == "provider-drift":
                    network[capture.REPUTATION_HISTORY_FIELD] = {
                        **network[capture.REPUTATION_HISTORY_FIELD],
                        "artifact_root": "0x" + "73" * 32,
                    }
                elif mutation == "missing-boundary":
                    manifest.pop("deployment_block_hash")
                elif mutation == "provider-boundary-drift":
                    network["settlement_runtime_code_keccak256"] = "0x" + "84" * 32
                else:
                    manifest[capture.REPUTATION_HISTORY_FIELD][
                        "source_history_through_block"
                    ] = SOURCE_DEPLOYMENT_BLOCK - 1
                self._write_manifest(manifest)
                self._write_network_manifest(network)
                self._write_consumer_manifest(consumer)
                with self.assertRaises(capture.EvidenceError):
                    self._capture(FakeRPC(manifest))

        self._use_dynamic_manifest()
        rpc = FakeRPC(self.manifest)
        original = self.manifest[capture.REPUTATION_HISTORY_FIELD]
        self.manifest[capture.REPUTATION_HISTORY_FIELD] = {
            **original, "source_genesis_hash": "0x" + "7" * 64,
        }
        self._write_manifest(self.manifest)
        self.network_manifest[capture.REPUTATION_HISTORY_FIELD] = self.manifest[
            capture.REPUTATION_HISTORY_FIELD
        ]
        self._write_network_manifest(self.network_manifest)
        self._write_consumer_manifest(
            self._consumer_manifest(self.manifest, self.network_manifest)
        )
        rpc.manifest = self.manifest
        with self.assertRaisesRegex(capture.EvidenceError, "prior same-chain"):
            self._capture(rpc)

        self._use_dynamic_manifest()
        changed_history = {
            **self.manifest[capture.REPUTATION_HISTORY_FIELD],
            "source_deployment_block_hash": "0x" + "83" * 32,
        }
        self.manifest[capture.REPUTATION_HISTORY_FIELD] = changed_history
        self.network_manifest[capture.REPUTATION_HISTORY_FIELD] = changed_history
        self._write_manifest(self.manifest)
        self._write_network_manifest(self.network_manifest)
        self._write_consumer_manifest(
            self._consumer_manifest(self.manifest, self.network_manifest)
        )
        with self.assertRaisesRegex(capture.EvidenceError, "deployment block is not canonical"):
            self._capture(FakeRPC(self.manifest))

        self._use_dynamic_manifest()
        wrong_runtime_hash = "0x" + "85" * 32
        self.manifest["settlement_runtime_code_keccak256"] = wrong_runtime_hash
        self.network_manifest["settlement_runtime_code_keccak256"] = wrong_runtime_hash
        self._write_manifest(self.manifest)
        self._write_network_manifest(self.network_manifest)
        self._write_consumer_manifest(
            self._consumer_manifest(self.manifest, self.network_manifest)
        )
        with self.assertRaisesRegex(capture.EvidenceError, "live Settlement deployment boundary"):
            self._capture(FakeRPC(self.manifest))

    def test_dynamic_jury_capture_rejects_static_committee_fields_in_manifests(self):
        prohibited = {
            "adjudicators": [],
            "adjudicator_operators": {},
            "independence_attested": False,
            "jury_provider_evidence": [],
        }
        for location in ("deployment", "network"):
            for field, value in prohibited.items():
                with self.subTest(location=location, field=field):
                    self._use_dynamic_manifest()
                    if location == "deployment":
                        self.manifest[field] = value
                        self.manifest_raw = self._write_manifest(self.manifest)
                    else:
                        self.network_manifest[field] = value
                        self.network_manifest_raw = self._write_network_manifest(
                            self.network_manifest
                        )
                    with self.assertRaisesRegex(
                            capture.EvidenceError,
                            "forbidden static committee fields"):
                        self._capture(FakeRPC(self.manifest))

    def test_dynamic_jury_capture_rejects_unsafe_or_disagreeing_registry(self):
        self._use_dynamic_manifest()
        rpc = FakeRPC(self.manifest)
        rpc.registry_state_overrides[RPC_URLS[0]] = {"pending_assignments": 1}
        with self.assertRaisesRegex(capture.EvidenceError, "cannot safely form"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.registry_runtime_codes[RPC_URLS[1]] = "0x6004600055"
        with self.assertRaisesRegex(capture.EvidenceError, "disagree"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.registry_state_overrides[RPC_URLS[0]] = {"can_form_jury": 2}
        with self.assertRaisesRegex(capture.EvidenceError, "invalid ABI boolean"):
            self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.registry_provider_overrides[(RPC_URLS[0], 0)] = {
            **JURY_PROVIDERS[0], "owner": "0x" + "ef" * 20,
        }
        with self.assertRaisesRegex(capture.EvidenceError, "disagree"):
            self._capture(rpc)

    def test_dynamic_jury_capture_requires_committed_reputation_sources(self):
        self._use_dynamic_manifest()
        owner = JURY_PROVIDERS[0]["owner"]
        for field, value in (
            ("source_sequence", 0),
            ("source_digest", "0x" + "0" * 64),
        ):
            with self.subTest(field=field):
                rpc = FakeRPC(self.manifest)
                rpc.registry_source_overrides[(RPC_URLS[0], owner)] = {field: value}
                with self.assertRaisesRegex(
                    capture.EvidenceError, "committed reputation source",
                ):
                    self._capture(rpc)

        rpc = FakeRPC(self.manifest)
        rpc.registry_source_overrides[(RPC_URLS[1], owner)] = {
            "source_sequence": JURY_PROVIDERS[0]["source_sequence"] + 1,
        }
        with self.assertRaisesRegex(capture.EvidenceError, "disagree"):
            self._capture(rpc)

    def test_dynamic_jury_capture_requires_each_channel_jury_ready(self):
        self._use_dynamic_manifest()
        rpc = FakeRPC(self.manifest)
        rpc.registry_state_overrides[RPC_URLS[0]] = {"channel_jury_ready": False}
        with self.assertRaisesRegex(
            capture.EvidenceError, "capacity channel cannot form",
        ):
            self._capture(rpc)

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

        rpc = FakeRPC(self.manifest)
        rpc.manifest["fresh_channel_open_block_timestamps"][0] += 1
        with self.assertRaisesRegex(capture.EvidenceError, "open block"):
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
                self._write_consumer_manifest(
                    self._consumer_manifest(manifest, self.network_manifest)
                )
                with self.assertRaisesRegex(capture.EvidenceError, message):
                    self._capture()

    def test_main_writes_strict_json_once_and_refuses_to_overwrite(self):
        output = self.directory / "nested/evidence.json"
        evidence = {"schema": capture.SCHEMA, "source_commit": SOURCE_COMMIT}
        arguments = [
            "--deployment", str(self.manifest_path),
            "--provider-network", str(self.network_manifest_path),
            "--consumer-network", str(self.consumer_manifest_path),
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
