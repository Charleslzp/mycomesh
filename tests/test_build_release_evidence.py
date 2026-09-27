import base64
import copy
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scripts.build_release_evidence import (
    DEPLOYED_CODE_SCHEMA,
    DYNAMIC_JURY_MODE,
    DYNAMIC_JURY_RANDOMNESS,
    NPM_SCHEMA,
    OCI_SCHEMA,
    RELEASE_SCHEMA,
    EMPTY_CODE_KECCAK256,
    JURY_TRANSACTION_GAS_CAP_FIELD,
    REPUTATION_HISTORY_FIELD,
    REPUTATION_HISTORY_SCHEMA,
    ReleaseEvidenceError,
    _expected_domain_separator,
    _keccak256,
    build_release_evidence,
    main,
)
from gateway.provider_jury import decision_policy_hash


def registry_abi_items():
    scalar_functions = (
        "RANDOMNESS_MODE_HASH", "governance", "reputationAuthority", "settlement",
        "bondPenaltyRecipient", "minimumReputation", "jurySize", "threshold",
        "selectionDelayBlocks", "providerCount", "rosterVersion",
        "pendingAssignments", "canFormJury",
    )
    provider_components = [
        {"name": name, "type": abi_type}
        for name, abi_type in (
            ("owner", "address"), ("voteSigner", "address"),
            ("operatorIdHash", "bytes32"), ("peerIdHash", "bytes32"),
            ("capabilityHash", "bytes32"), ("reputation", "uint64"),
            ("active", "bool"),
        )
    ]
    return [
        *(
            {"type": "function", "name": name, "inputs": [], "outputs": []}
            for name in scalar_functions
        ),
        {"type": "function", "name": "providerAt",
         "inputs": [{"type": "uint256"}], "outputs": []},
        {"type": "function", "name": "canFormJuryFor",
         "inputs": [{"type": "bytes32"}], "outputs": []},
        {"type": "function", "name": "assignmentProviderEvidence",
         "inputs": [{"type": "bytes32"}], "outputs": []},
        {"type": "function", "name": "setProvider", "inputs": [
            {"type": "tuple", "components": provider_components},
            {"type": "uint64"}, {"type": "bytes32"},
        ], "outputs": []},
        {"type": "function", "name": "providerSourceSequence",
         "inputs": [{"type": "address"}], "outputs": []},
        {"type": "function", "name": "providerSourceDigest",
         "inputs": [{"type": "address"}], "outputs": []},
        {"type": "event", "name": "ProviderUpdated", "anonymous": False, "inputs": [
            {"type": "address", "indexed": True},
            {"type": "address", "indexed": True},
            {"type": "bytes32", "indexed": True},
            {"type": "uint64", "indexed": False},
            {"type": "bool", "indexed": False},
            {"type": "uint64", "indexed": False},
            {"type": "bytes32", "indexed": False},
            {"type": "uint64", "indexed": False},
        ]},
    ]


ROOT = Path(__file__).parents[1]
SOURCE_COMMIT = "a" * 40
INDEX_DIGEST = "sha256:" + "1" * 64
PROVIDER_IMAGE = "ghcr.io/charleslzp/mycomesh-provider-codex@" + INDEX_DIGEST
JURY_RELAY_KEY = "11" * 32
JURY_TRANSACTION_SENDER = "0x" + "41" * 20
JURY_TRANSACTION_GAS_CAP_WEI = 1_000_000_000_000_000
REPUTATION_HISTORY = {
    "schema": REPUTATION_HISTORY_SCHEMA,
    "source_network_id": "mycomesh-v9-prior",
    "source_protocol_version": 9,
    "source_chain_id": 11_155_111,
    "source_genesis_hash": "0x" + "61" * 32,
    "source_settlement_contract": "0x" + "42" * 20,
    "source_runtime_code_hash": "0x" + "62" * 32,
    "source_deployment_block": 90,
    "source_deployment_block_hash": "0x" + "65" * 32,
    "source_history_through_block": 99,
    "source_history_through_block_hash": "0x" + "66" * 32,
    "confirmations": 6,
    "artifact_sha256": "63" * 32,
    "artifact_root": "0x" + "64" * 32,
}


def write_json(path: Path, value: object) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    return raw


def write_package(path: Path, name: str, version: str) -> None:
    raw = json.dumps({"name": name, "version": version}, separators=(",", ":")).encode()
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(raw)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(raw))


def package_metadata(path: Path, name: str, version: str) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "name": name,
        "version": version,
        "filename": path.name,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "npm_shasum": hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
        "npm_integrity": "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode(),
    }


class BuildReleaseEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "repo"
        for relative in (
            "deployments/sepolia-myco-v10.json",
            "deployments/sepolia-provider-network-v10.json",
            "deployments/provider-jury-policy-v1.json",
            "packages/mycomesh-cli/networks/v10-controlled-test.json",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

        self.provider_tgz = self.directory / "mycomesh-provider-0.1.38.tgz"
        self.consumer_tgz = self.directory / "mycomesh-consumer-0.1.52.tgz"
        write_package(self.provider_tgz, "mycomesh-provider", "0.1.38")
        write_package(self.consumer_tgz, "mycomesh-consumer", "0.1.52")

        self.npm_value = {
            "schema": NPM_SCHEMA,
            "source_commit": SOURCE_COMMIT,
            "provider_image": PROVIDER_IMAGE,
            "packages": {
                "provider": package_metadata(
                    self.provider_tgz, "mycomesh-provider", "0.1.38"
                ),
                "consumer": package_metadata(
                    self.consumer_tgz, "mycomesh-consumer", "0.1.52"
                ),
            },
        }
        self.npm_path = self.directory / "npm-release-candidate.json"
        write_json(self.npm_path, self.npm_value)

        self.oci_value = {
            "schema": OCI_SCHEMA,
            "image": PROVIDER_IMAGE,
            "index_digest": INDEX_DIGEST,
            "revision": SOURCE_COMMIT,
            "platforms": [
                {
                    "os": "linux",
                    "architecture": "amd64",
                    "digest": "sha256:" + "2" * 64,
                    "revision": SOURCE_COMMIT,
                },
                {
                    "os": "linux",
                    "architecture": "arm64",
                    "digest": "sha256:" + "3" * 64,
                    "revision": SOURCE_COMMIT,
                },
            ],
        }
        self.oci_path = self.directory / "oci.json"
        write_json(self.oci_path, self.oci_value)

        self.artifact_value = {
            "abi": [
                {"type": "function", "name": "MAX_CHANNEL_DURATION", "inputs": []},
                {"type": "function", "name": "openCapacityChannels", "inputs": []},
                {"type": "function", "name": "settleReservedReceipt", "inputs": []},
                {"type": "function", "name": "voteDisputeBySig", "inputs": []},
            ],
            "deployedBytecode": {
                "object": "0x60006001",
                "immutableReferences": {"fixture": [{"start": 1, "length": 1}]},
            },
        }
        self.artifact_path = self.directory / "MycoSettlementV10.json"
        write_json(self.artifact_path, self.artifact_value)

        deployment_path = self.root / "deployments/sepolia-myco-v10.json"
        deployment = json.loads(deployment_path.read_text())
        provider_network_path = self.root / "deployments/sepolia-provider-network-v10.json"
        provider_network = json.loads(provider_network_path.read_text())
        runtime = bytes.fromhex("60ff6001")
        state_block_number = deployment["deployment_block"] + 100
        channel_state = {
            "channel_hash": deployment["channel_hash"],
            "pricing_version": deployment["pricing_version"],
            "pricing_hash": deployment["pricing_hash"],
            "treasury": deployment["treasury"],
            "input_per_1k": 1000,
            "output_per_1k": 4000,
            "minimum_fee": 2000,
            "provider_bps": 8500,
            "relay_bps": 300,
            "pool_bps": 200,
            "treasury_bps": 1000,
            "active": True,
        }
        channel_configs = (
            {
                "consumer_owner": "0x452bfe4c9b59455504068b2594979bcd531c9e49",
                "consumer_key": "0x5e69a109b24e623da7af21d0137f942e6f3a65d4",
                "provider_owner": "0x94515c8903cca8e5aedb1437e947db39970792cc",
                "provider_signer": "0x6b21fd92347f055802434f83685f8089dfb943c8",
                "relay": "0x94515c8903cca8e5aedb1437e947db39970792cc",
                "relay_signer": "0x44d183a73b1a87801bc18b060a2ce0a7f3aecaaf",
                "consumer_nonce": 12, "provider_nonce": 12,
            },
            {
                "consumer_owner": "0x452bfe4c9b59455504068b2594979bcd531c9e49",
                "consumer_key": "0x5e69a109b24e623da7af21d0137f942e6f3a65d4",
                "provider_owner": "0x94515c8903cca8e5aedb1437e947db39970792cc",
                "provider_signer": "0x4d5100e6b1b05994bd5ee8e17dc94255e7af1e5f",
                "relay": "0x94515c8903cca8e5aedb1437e947db39970792cc",
                "relay_signer": "0x44d183a73b1a87801bc18b060a2ce0a7f3aecaaf",
                "consumer_nonce": 13, "provider_nonce": 13,
            },
            {
                "consumer_owner": "0x452bfe4c9b59455504068b2594979bcd531c9e49",
                "consumer_key": "0x5e69a109b24e623da7af21d0137f942e6f3a65d4",
                "provider_owner": "0x94515c8903cca8e5aedb1437e947db39970792cc",
                "provider_signer": "0xf3217abadf55b970fd029cc17beabc1cc12b099b",
                "relay": "0x94515c8903cca8e5aedb1437e947db39970792cc",
                "relay_signer": "0x420b2033a61491c268c2600c95d1b64ad9b962ca",
                "consumer_nonce": 14, "provider_nonce": 14,
            },
        )
        capacity_channels = []
        for index, (channel_id, transaction_hash, open_timestamp, config) in enumerate(zip(
            deployment["capacity_channel_ids"],
            deployment["fresh_channel_open_tx_hashes"],
            deployment["fresh_channel_open_block_timestamps"],
            channel_configs,
        )):
            capacity_channels.append({
                "channel_id": channel_id,
                "transaction_hash": transaction_hash,
                "block_number": deployment["deployment_block"] + index + 1,
                "block_hash": "0x" + f"{index + 5:x}" * 64,
                "open_block_timestamp": open_timestamp,
                **config,
                "pool": "0x" + "00" * 20,
                "channel_hash": deployment["channel_hash"],
                "pricing_hash": deployment["pricing_hash"],
                "pricing_version": deployment["pricing_version"],
                "capacity": deployment["fresh_channel_capacity"],
                "max_fee_per_request": deployment["fresh_channel_max_fee_per_request"],
                "valid_from": deployment["fresh_channel_valid_from"],
                "admit_until": deployment["fresh_channel_admit_until"],
                "claim_until": deployment["fresh_channel_claim_until"],
                "permit_deadline": 1789917096,
                "settled_max_fee": 0,
                "credit_remaining": deployment["fresh_channel_capacity"],
                "stake_remaining": deployment["fresh_channel_capacity"],
                "closed": False,
            })
        self.deployed_value = {
            "schema": DEPLOYED_CODE_SCHEMA,
            "source_commit": SOURCE_COMMIT,
            "chain_id": deployment["chain_id"],
            "address": deployment["settlement"],
            "transaction_hash": deployment["tx_hash"],
            "block_number": deployment["deployment_block"],
            "block_hash": "0x" + "4" * 64,
            "deployer": deployment["deployer"],
            "state_block_number": state_block_number,
            "state_block_hash": "0x" + "9" * 64,
            "state_block_timestamp": deployment["fresh_channel_valid_from"] + 1,
            "contract_state": {
                "stablecoin": deployment["stablecoin"],
                "reward_token": deployment["reward_token"],
                "adjudication_threshold": deployment["adjudication_threshold"],
                "governance": deployment["governance"],
                "treasury": deployment["treasury"],
                "domain_separator": _expected_domain_separator(deployment),
                "max_channel_duration_seconds": deployment[
                    "max_channel_duration_seconds"
                ],
                "adjudicators": deployment["adjudicators"],
                "policy": deployment["policy"],
                "stablecoin_runtime_code_sha256": deployment[
                    "stablecoin_runtime_code_sha256"
                ],
                "stablecoin_runtime_code_keccak256": deployment[
                    "stablecoin_runtime_code_keccak256"
                ],
                "stablecoin_balance": 2_000_000,
                "stable_liabilities": 1_500_000,
                "channel": channel_state,
            },
            "capacity_channels": capacity_channels,
            "runtime_code": "0x" + runtime.hex(),
            "runtime_code_sha256": hashlib.sha256(runtime).hexdigest(),
            "runtime_code_keccak256": _keccak256(runtime),
            "confirmations": 6,
            "rpc_quorum": 2,
            "deployment_manifest_sha256": hashlib.sha256(
                deployment_path.read_bytes()
            ).hexdigest(),
            "provider_network_manifest_sha256": hashlib.sha256(
                provider_network_path.read_bytes()
            ).hexdigest(),
            "consumer_network_manifest_sha256": hashlib.sha256(
                (self.root / "packages/mycomesh-cli/networks/v10-controlled-test.json").read_bytes()
            ).hexdigest(),
        }
        self.deployed_path = self.directory / "deployed-code.json"
        write_json(self.deployed_path, self.deployed_value)

    def tearDown(self):
        self.temporary.cleanup()

    def enable_dynamic_jury(self):
        deployment_path = self.root / "deployments/sepolia-myco-v10.json"
        deployment = json.loads(deployment_path.read_text())
        provider_path = self.root / "deployments/sepolia-provider-network-v10.json"
        provider_network = json.loads(provider_path.read_text())
        jury_policy = json.loads(
            (self.root / "deployments/provider-jury-policy-v1.json").read_text()
        )
        jury_policy_hash = decision_policy_hash(
            model=jury_policy["model"],
            system_prompt=jury_policy["system_prompt"],
            max_output_tokens=jury_policy["max_output_tokens"],
            task_ttl_seconds=jury_policy["task_ttl_seconds"],
        )
        consumer_path = self.root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
        providers = [
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
        network_id = "mycomesh-v10-dynamic-provider-ai-controlled-test"
        deployment.update({
            "network_id": network_id,
            "genesis_hash": REPUTATION_HISTORY["source_genesis_hash"],
            "committee_mode": DYNAMIC_JURY_MODE,
            "jury_registry": "0x" + "31" * 20,
            "jury_registry_governance": deployment["governance"],
            "reputation_authority": "0x" + "32" * 20,
            "minimum_provider_reputation": 80,
            "jury_size": 3,
            "adjudication_threshold": 2,
            "jury_selection_delay_blocks": 2,
            "jury_randomness": DYNAMIC_JURY_RANDOMNESS,
            "jury_decision_policy_hash": jury_policy_hash,
            "deployment_block_hash": self.deployed_value["block_hash"],
            "settlement_runtime_code_keccak256": self.deployed_value[
                "runtime_code_keccak256"
            ],
            REPUTATION_HISTORY_FIELD: copy.deepcopy(REPUTATION_HISTORY),
        })
        for key in (
            "adjudicators", "adjudicator_operators", "independence_attested",
            "monetary_policy",
        ):
            deployment.pop(key, None)
        provider_network["network_id"] = network_id
        provider_network["jury_relay_public_keys"] = [JURY_RELAY_KEY]
        provider_network["jury_transaction_senders"] = {
            JURY_RELAY_KEY: JURY_TRANSACTION_SENDER,
        }
        provider_network[JURY_TRANSACTION_GAS_CAP_FIELD] = (
            JURY_TRANSACTION_GAS_CAP_WEI
        )
        provider_network[REPUTATION_HISTORY_FIELD] = copy.deepcopy(
            deployment[REPUTATION_HISTORY_FIELD]
        )
        for field in (
            "deployment_block", "deployment_block_hash",
            "settlement_runtime_code_keccak256",
        ):
            provider_network[field] = deployment[field]
        consumer = {
            **deployment,
            **{
                key: value for key, value in provider_network.items()
                if key not in {"deployment", "tls_ca_file"}
            },
            "tls_ca_file": "v10-controlled-test.ca.crt",
        }
        write_json(deployment_path, deployment)
        write_json(provider_path, provider_network)
        write_json(consumer_path, consumer)

        self.deployed_value["contract_state"].pop("adjudicators")
        self.deployed_value["contract_state"]["jury_registry"] = deployment[
            "jury_registry"
        ]
        for channel in self.deployed_value["capacity_channels"]:
            channel["jury_ready"] = True
        registry_runtime = bytes.fromhex("61ff6001")
        self.deployed_value["jury_registry_state"] = {
            "address": deployment["jury_registry"],
            "governance": deployment["jury_registry_governance"],
            "reputation_authority": deployment["reputation_authority"],
            "settlement": deployment["settlement"],
            "bond_penalty_recipient": deployment["policy"]["bond_penalty_recipient"],
            "minimum_reputation": deployment["minimum_provider_reputation"],
            "jury_size": deployment["jury_size"],
            "threshold": deployment["adjudication_threshold"],
            "selection_delay_blocks": deployment["jury_selection_delay_blocks"],
            "randomness": _keccak256(DYNAMIC_JURY_RANDOMNESS.encode()),
            "provider_count": len(providers),
            "roster_version": len(providers),
            "pending_assignments": 0,
            "can_form_jury": True,
            "providers": providers,
            "runtime_code": "0x" + registry_runtime.hex(),
            "runtime_code_sha256": hashlib.sha256(registry_runtime).hexdigest(),
            "runtime_code_keccak256": _keccak256(registry_runtime),
        }
        self.deployed_value["jury_decision_policy_hash"] = deployment[
            "jury_decision_policy_hash"
        ]
        self.deployed_value["jury_transaction_senders"] = {
            JURY_RELAY_KEY: {
                "relay_public_key": JURY_RELAY_KEY,
                "address": JURY_TRANSACTION_SENDER,
                "block_number": self.deployed_value["state_block_number"],
                "block_hash": self.deployed_value["state_block_hash"],
                "confirmed_nonce": 6,
                "latest_nonce": 7,
                "pending_nonce": 7,
                "pending_transaction": False,
                "balance_wei": JURY_TRANSACTION_GAS_CAP_WEI * 2,
                "code_keccak256": EMPTY_CODE_KECCAK256,
                "gas_cap_wei": JURY_TRANSACTION_GAS_CAP_WEI,
            },
        }
        self.deployed_value[REPUTATION_HISTORY_FIELD] = copy.deepcopy(
            deployment[REPUTATION_HISTORY_FIELD]
        )
        self.deployed_value["deployment_manifest_sha256"] = hashlib.sha256(
            deployment_path.read_bytes()
        ).hexdigest()
        self.deployed_value["provider_network_manifest_sha256"] = hashlib.sha256(
            provider_path.read_bytes()
        ).hexdigest()
        self.deployed_value["consumer_network_manifest_sha256"] = hashlib.sha256(
            consumer_path.read_bytes()
        ).hexdigest()
        write_json(self.deployed_path, self.deployed_value)

        self.artifact_value["abi"].append(
            {"type": "function", "name": "juryRegistry", "inputs": []}
        )
        self.artifact_value["deployedBytecode"]["immutableReferences"] = {
            str(index): [{"start": 1, "length": 1}] for index in range(6)
        }
        write_json(self.artifact_path, self.artifact_value)

        self.registry_artifact_value = {
            "abi": registry_abi_items(),
            "deployedBytecode": {
                "object": "0x61006001",
                "immutableReferences": {
                    str(index): [{"start": 1, "length": 1}] for index in range(5)
                },
            },
        }
        self.registry_artifact_path = self.directory / "ProviderJuryRegistryV1.json"
        write_json(self.registry_artifact_path, self.registry_artifact_value)

    def build(self):
        return build_release_evidence(
            root=self.root,
            source_commit=SOURCE_COMMIT,
            npm_metadata_path=self.npm_path,
            provider_tgz=self.provider_tgz,
            consumer_tgz=self.consumer_tgz,
            oci_metadata_path=self.oci_path,
            deployed_code_path=self.deployed_path,
            foundry_artifact_path=self.artifact_path,
            jury_registry_artifact_path=getattr(
                self, "registry_artifact_path", None,
            ),
        )

    def test_builds_complete_release_gate_declaration(self):
        value = self.build()
        self.assertEqual(value["schema"], RELEASE_SCHEMA)
        self.assertEqual(value["source_commit"], SOURCE_COMMIT)
        self.assertEqual(value["oci"]["image"], PROVIDER_IMAGE)
        self.assertEqual(
            value["packages"]["provider"]["sha256"],
            hashlib.sha256(self.provider_tgz.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            value["contract"]["deployment_manifest_sha256"],
            self.deployed_value["deployment_manifest_sha256"],
        )
        self.assertEqual(
            value["contract"]["runtime_code_keccak256"],
            self.deployed_value["runtime_code_keccak256"],
        )
        self.assertEqual(
            value["contract"]["deployment_block"],
            self.deployed_value["block_number"],
        )
        self.assertEqual(
            value["contract"]["deployed_code_evidence_sha256"],
            hashlib.sha256(self.deployed_path.read_bytes()).hexdigest(),
        )

    def test_dynamic_jury_builds_dual_contract_declaration(self):
        self.enable_dynamic_jury()
        value = self.build()
        registry = value["contract"]["jury_registry"]
        registry_state = self.deployed_value["jury_registry_state"]
        self.assertEqual(registry["address"], registry_state["address"])
        self.assertEqual(
            registry["runtime_code_sha256"], registry_state["runtime_code_sha256"],
        )
        self.assertEqual(
            registry["abi_artifact_sha256"],
            hashlib.sha256(self.registry_artifact_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            value["contract"]["jury_decision_policy_hash"],
            self.deployed_value["jury_decision_policy_hash"],
        )
        self.assertEqual(
            value["contract"]["jury_policy"]["decision_policy_hash"],
            self.deployed_value["jury_decision_policy_hash"],
        )
        self.assertNotIn("adjudicators", self.deployed_value["contract_state"])
        self.assertEqual(
            value["contract"][REPUTATION_HISTORY_FIELD], REPUTATION_HISTORY,
        )

    def test_dynamic_jury_rejects_decision_policy_hash_drift(self):
        self.enable_dynamic_jury()
        changed = copy.deepcopy(self.deployed_value)
        changed["jury_decision_policy_hash"] = "0x" + "42" * 32
        write_json(self.deployed_path, changed)
        with self.assertRaisesRegex(ReleaseEvidenceError, "decision policy hash"):
            self.build()

    def test_dynamic_reputation_history_lineage_is_required_and_exact(self):
        self.enable_dynamic_jury()
        original = copy.deepcopy(self.deployed_value)
        for mutation in (
            "missing", "null", "extra", "evidence-drift", "high-confirmations",
            "invalid-history-range",
        ):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(original)
                if mutation == "missing":
                    changed.pop(REPUTATION_HISTORY_FIELD)
                elif mutation == "null":
                    changed[REPUTATION_HISTORY_FIELD] = None
                elif mutation == "extra":
                    changed[REPUTATION_HISTORY_FIELD]["unexpected"] = True
                elif mutation == "high-confirmations":
                    changed[REPUTATION_HISTORY_FIELD]["confirmations"] = 257
                elif mutation == "evidence-drift":
                    changed[REPUTATION_HISTORY_FIELD]["artifact_root"] = (
                        "0x" + "65" * 32
                    )
                else:
                    changed[REPUTATION_HISTORY_FIELD][
                        "source_history_through_block"
                    ] = 89
                write_json(self.deployed_path, changed)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()

    def test_dynamic_reputation_history_requires_target_genesis(self):
        self.enable_dynamic_jury()
        wrong_genesis = "0x" + "67" * 32
        deployment_path = self.root / "deployments/sepolia-myco-v10.json"
        provider_path = self.root / "deployments/sepolia-provider-network-v10.json"
        consumer_path = self.root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
        for path in (deployment_path, provider_path, consumer_path):
            manifest = json.loads(path.read_text())
            manifest[REPUTATION_HISTORY_FIELD]["source_genesis_hash"] = (
                wrong_genesis
            )
            write_json(path, manifest)
        self.deployed_value[REPUTATION_HISTORY_FIELD]["source_genesis_hash"] = (
            wrong_genesis
        )
        self.deployed_value["deployment_manifest_sha256"] = hashlib.sha256(
            deployment_path.read_bytes()
        ).hexdigest()
        self.deployed_value["provider_network_manifest_sha256"] = hashlib.sha256(
            provider_path.read_bytes()
        ).hexdigest()
        self.deployed_value["consumer_network_manifest_sha256"] = hashlib.sha256(
            consumer_path.read_bytes()
        ).hexdigest()
        write_json(self.deployed_path, self.deployed_value)
        with self.assertRaisesRegex(ReleaseEvidenceError, "prior same-chain"):
            self.build()

    def test_dynamic_settlement_deployment_boundary_is_exact_and_evidence_bound(self):
        self.enable_dynamic_jury()
        deployment_path = self.root / "deployments/sepolia-myco-v10.json"
        provider_path = self.root / "deployments/sepolia-provider-network-v10.json"
        consumer_path = self.root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
        originals = {
            deployment_path: json.loads(deployment_path.read_text()),
            provider_path: json.loads(provider_path.read_text()),
            consumer_path: json.loads(consumer_path.read_text()),
            self.deployed_path: copy.deepcopy(self.deployed_value),
        }
        for mutation in ("missing", "provider-drift", "evidence-drift"):
            with self.subTest(mutation=mutation):
                values = {path: copy.deepcopy(value) for path, value in originals.items()}
                if mutation == "missing":
                    values[deployment_path].pop("deployment_block_hash")
                elif mutation == "provider-drift":
                    values[provider_path]["settlement_runtime_code_keccak256"] = (
                        "0x" + "67" * 32
                    )
                else:
                    values[self.deployed_path]["runtime_code_keccak256"] = (
                        "0x" + "68" * 32
                    )
                for path, value in values.items():
                    write_json(path, value)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()

    def test_dynamic_jury_sender_mapping_and_live_evidence_are_fail_closed(self):
        self.enable_dynamic_jury()
        provider_path = self.root / "deployments/sepolia-provider-network-v10.json"
        consumer_path = self.root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
        deployment = json.loads(
            (self.root / "deployments/sepolia-myco-v10.json").read_text()
        )
        original_provider = json.loads(provider_path.read_text())
        original_consumer = json.loads(consumer_path.read_text())

        changed_provider = copy.deepcopy(original_provider)
        changed_provider["jury_transaction_senders"][JURY_RELAY_KEY] = deployment[
            "governance"
        ]
        changed_consumer = {
            **deployment,
            **{
                key: value for key, value in changed_provider.items()
                if key not in {"deployment", "tls_ca_file"}
            },
            "tls_ca_file": original_consumer["tls_ca_file"],
        }
        write_json(provider_path, changed_provider)
        write_json(consumer_path, changed_consumer)
        with self.assertRaisesRegex(ReleaseEvidenceError, "known manifest role"):
            self.build()

        write_json(provider_path, original_provider)
        write_json(consumer_path, original_consumer)
        mutations = (
            ("pending_transaction", True),
            ("pending_nonce", 8),
            ("balance_wei", JURY_TRANSACTION_GAS_CAP_WEI - 1),
            ("code_keccak256", "0x" + "9" * 64),
            ("address", self.deployed_value["capacity_channels"][0]["provider_owner"]),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.deployed_value)
                changed["jury_transaction_senders"][JURY_RELAY_KEY][field] = value
                write_json(self.deployed_path, changed)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()

    def test_dynamic_jury_rejects_policy_preimage_drift(self):
        self.enable_dynamic_jury()
        path = self.root / "deployments/provider-jury-policy-v1.json"
        changed = json.loads(path.read_text())
        changed["system_prompt"] += " Changed after deployment."
        write_json(path, changed)
        with self.assertRaisesRegex(ReleaseEvidenceError, "executable policy"):
            self.build()

    def test_dynamic_jury_rejects_static_committee_fields_in_every_manifest(self):
        self.enable_dynamic_jury()
        deployment_path = self.root / "deployments/sepolia-myco-v10.json"
        provider_path = self.root / "deployments/sepolia-provider-network-v10.json"
        consumer_path = self.root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
        originals = {
            deployment_path: json.loads(deployment_path.read_text()),
            provider_path: json.loads(provider_path.read_text()),
            consumer_path: json.loads(consumer_path.read_text()),
        }
        prohibited = {
            "adjudicators": [],
            "adjudicator_operators": {},
            "independence_attested": False,
            "jury_provider_evidence": [],
        }
        for location, path in (
            ("deployment", deployment_path),
            ("Provider network", provider_path),
            ("Consumer network", consumer_path),
        ):
            for field, value in prohibited.items():
                with self.subTest(location=location, field=field):
                    current = {item: copy.deepcopy(data) for item, data in originals.items()}
                    current[path][field] = value
                    if path != consumer_path:
                        current[consumer_path][field] = value
                    for item, data in current.items():
                        write_json(item, data)
                    with self.assertRaisesRegex(
                            ReleaseEvidenceError, "forbidden static committee fields"):
                        self.build()
        for path, value in originals.items():
            write_json(path, value)

    def test_dynamic_jury_requires_registry_artifact(self):
        self.enable_dynamic_jury()
        self.registry_artifact_path = None
        with self.assertRaisesRegex(ReleaseEvidenceError, "requires a jury registry"):
            self.build()

    def test_dynamic_jury_rejects_registry_state_or_runtime_tampering(self):
        self.enable_dynamic_jury()
        mutations = (
            (("can_form_jury",), False),
            (("bond_penalty_recipient",), "0x" + "9" * 40),
            (("providers", 1, "operator_id_hash"),
             self.deployed_value["jury_registry_state"]["providers"][0]["operator_id_hash"]),
            (("providers", 0, "source_sequence"), 0),
            (("providers", 0, "source_digest"), "0x" + "0" * 64),
            (("runtime_code_sha256",), "0" * 64),
        )
        original = copy.deepcopy(self.deployed_value)
        for path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(original)
                cursor = changed["jury_registry_state"]
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                write_json(self.deployed_path, changed)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()

    def test_dynamic_jury_registry_abi_and_immutable_count_are_required(self):
        self.enable_dynamic_jury()
        for mutation in (
            "missing-function", "old-set-provider", "bad-provider-updated-event",
            "wrong-immutable-count",
        ):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.registry_artifact_value)
                if mutation == "missing-function":
                    changed["abi"] = [
                        item for item in changed["abi"]
                        if item["name"] != "providerAt"
                    ]
                elif mutation == "old-set-provider":
                    item = next(
                        value for value in changed["abi"]
                        if value.get("name") == "setProvider"
                    )
                    item["inputs"] = item["inputs"][:1]
                elif mutation == "bad-provider-updated-event":
                    item = next(
                        value for value in changed["abi"]
                        if value.get("name") == "ProviderUpdated"
                    )
                    item["inputs"][5]["indexed"] = True
                else:
                    changed["deployedBytecode"]["immutableReferences"].pop("4")
                write_json(self.registry_artifact_path, changed)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()

    def test_dynamic_jury_requires_channel_specific_readiness(self):
        self.enable_dynamic_jury()
        self.deployed_value["capacity_channels"][0]["jury_ready"] = False
        write_json(self.deployed_path, self.deployed_value)
        with self.assertRaisesRegex(ReleaseEvidenceError, "differs from manifests"):
            self.build()

    def test_dynamic_jury_cli_accepts_registry_artifact(self):
        self.enable_dynamic_jury()
        output = self.directory / "dynamic-release.json"
        args = [
            "--root", str(self.root),
            "--source-commit", SOURCE_COMMIT,
            "--npm-metadata", str(self.npm_path),
            "--provider-tgz", str(self.provider_tgz),
            "--consumer-tgz", str(self.consumer_tgz),
            "--oci-metadata", str(self.oci_path),
            "--deployed-code-evidence", str(self.deployed_path),
            "--foundry-artifact", str(self.artifact_path),
            "--jury-registry-artifact", str(self.registry_artifact_path),
            "--output", str(output),
        ]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 0)
        self.assertEqual(
            json.loads(output.read_text())["contract"]["jury_registry"]["address"],
            self.deployed_value["jury_registry_state"]["address"],
        )

    def test_rejects_tarball_filename_or_digest_mismatch(self):
        self.npm_value["packages"]["provider"]["filename"] = "other.tgz"
        write_json(self.npm_path, self.npm_value)
        with self.assertRaisesRegex(ReleaseEvidenceError, "filename"):
            self.build()

        self.npm_value["packages"]["provider"] = package_metadata(
            self.provider_tgz, "mycomesh-provider", "0.1.38"
        )
        self.npm_value["packages"]["provider"]["sha256"] = "0" * 64
        write_json(self.npm_path, self.npm_value)
        with self.assertRaisesRegex(ReleaseEvidenceError, "size or digest"):
            self.build()

    def test_rejects_oci_image_revision_and_platform_drift(self):
        cases = (
            ("revision", "b" * 40),
            ("image", "ghcr.io/charleslzp/mycomesh-provider-codex@sha256:" + "9" * 64),
        )
        for field, value in cases:
            with self.subTest(field=field):
                changed = json.loads(json.dumps(self.oci_value))
                changed[field] = value
                write_json(self.oci_path, changed)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()
        changed = json.loads(json.dumps(self.oci_value))
        changed["platforms"][1]["revision"] = "b" * 40
        write_json(self.oci_path, changed)
        with self.assertRaisesRegex(ReleaseEvidenceError, "platform"):
            self.build()

    def test_rejects_deployment_identity_runtime_and_manifest_hash_drift(self):
        mutations = {
            "address": "0x" + "9" * 40,
            "runtime_code_sha256": "0" * 64,
            "deployment_manifest_sha256": "0" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                write_json(self.oci_path, self.oci_value)
                changed = dict(self.deployed_value)
                changed[field] = value
                write_json(self.deployed_path, changed)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()

    def test_rejects_confirmed_state_and_capacity_evidence_tampering(self):
        mutations = (
            (("provider_network_manifest_sha256",), "0" * 64),
            (("deployer",), "0x" + "9" * 40),
            (("state_block_timestamp",),
             self.deployed_value["capacity_channels"][0]["admit_until"]),
            (("contract_state", "governance"), "0x" + "9" * 40),
            (("contract_state", "stablecoin_balance"), 1),
            (("capacity_channels", 0, "pricing_version"), True),
            (("capacity_channels", 0, "open_block_timestamp"),
             self.deployed_value["capacity_channels"][0]["valid_from"]),
            (("capacity_channels", 0, "consumer_nonce"), 999),
            (
                ("capacity_channels", 0, "settled_max_fee"),
                self.deployed_value["capacity_channels"][0]["capacity"],
            ),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.deployed_value)
                cursor = changed
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                write_json(self.deployed_path, changed)
                with self.assertRaises(ReleaseEvidenceError):
                    self.build()

    def test_rejects_unknown_schema_fields(self):
        self.npm_value["unexpected"] = True
        write_json(self.npm_path, self.npm_value)
        with self.assertRaisesRegex(ReleaseEvidenceError, "unexpected"):
            self.build()

    def test_cli_exclusive_create_never_overwrites(self):
        output = self.directory / "release.json"
        args = [
            "--root", str(self.root),
            "--source-commit", SOURCE_COMMIT,
            "--npm-metadata", str(self.npm_path),
            "--provider-tgz", str(self.provider_tgz),
            "--consumer-tgz", str(self.consumer_tgz),
            "--oci-metadata", str(self.oci_path),
            "--deployed-code-evidence", str(self.deployed_path),
            "--foundry-artifact", str(self.artifact_path),
            "--output", str(output),
        ]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 0)
        original = output.read_bytes()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 1)
        self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
