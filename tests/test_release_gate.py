import base64
import hashlib
import copy
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts.release_gate import (
    ARTIFACT_SCHEMA,
    DEPLOYED_CODE_SCHEMA,
    DYNAMIC_JURY_MODE,
    DYNAMIC_JURY_RANDOMNESS,
    EMPTY_CODE_KECCAK256,
    JURY_TRANSACTION_GAS_CAP_FIELD,
    REPUTATION_HISTORY_FIELD,
    REPUTATION_HISTORY_SCHEMA,
    OCI_METADATA_SCHEMA,
    REQUIRED_RELEASE_FILES,
    _canonical_abi,
    _deployment_source_status,
    _expected_immutable_values,
    _jury_policy_declaration,
    _keccak256,
    _package_source_files,
    _strict_git_source_status,
    _tarball_files,
    check,
    check_artifacts,
)


ROOT = Path(__file__).parents[1]
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
FIXTURE_FILES = (
    "package.json",
    "package-lock.json",
    "packages/mycomesh-cli/package.json",
    "packages/mycomesh-cli/package-lock.json",
    "packages/mycomesh-cli/src/provider.mjs",
    "packages/mycomesh-cli/src/release.mjs",
    "packages/mycomesh-cli/src/consumer.mjs",
    "packages/mycomesh-cli/src/cli.mjs",
    "Makefile",
    *REQUIRED_RELEASE_FILES,
)


def failed(report, name):
    return not next(item for item in report["checks"] if item["name"] == name)["ok"]


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return path.read_bytes()


def write_tgz(path, files):
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(raw))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dynamic_jury_providers():
    return [
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


class ReleaseGateTest(unittest.TestCase):
    def test_dynamic_release_workflow_wires_registry_artifact(self):
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "--jury-registry-artifact out/ProviderJuryRegistryV1.sol/ProviderJuryRegistryV1.json",
            workflow,
        )
        self.assertIn(
            "--jury-registry-abi-artifact out/ProviderJuryRegistryV1.sol/ProviderJuryRegistryV1.json",
            workflow,
        )
        self.assertIn(
            "ProviderJuryRegistryV1.json\"",
            workflow,
        )

    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in FIXTURE_FILES:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            for relative in (
                "bin", "packages/mycomesh-cli/bin", "packages/mycomesh-cli/src",
                "packages/mycomesh-cli/networks",
            ):
                shutil.copytree(ROOT / relative, root / relative, dirs_exist_ok=True)
            for relative in (
                "deployments/sepolia-myco-v10-dynamic-20260926.json",
                "deployments/sepolia-provider-network-v10-dynamic-20260926.json",
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            for relative in ("README.md", "packages/mycomesh-cli/README.md"):
                shutil.copyfile(ROOT / relative, root / relative)
            tracked = sorted(
                path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
            )
            with patch("scripts.release_gate._tracked", return_value=tracked), patch(
                "scripts.release_gate._strict_git_source_status",
                return_value=(True, {"fixture": "clean tracked HEAD"}),
            ), patch(
                "scripts.release_gate._deployment_source_status",
                return_value=(True, {"fixture": "deployment source verified"}),
            ):
                yield root, tracked

    def make_dynamic_jury_manifest(self, root):
        deployment_path = root / "deployments/sepolia-myco-v10.json"
        deployment = json.loads(deployment_path.read_text())
        provider_path = root / "deployments/sepolia-provider-network-v10.json"
        provider = json.loads(provider_path.read_text())
        jury_policy = json.loads(
            (root / "deployments/provider-jury-policy-v1.json").read_text()
        )
        executable_policy = {
            **jury_policy,
            "verdict_fields": [
                "confirmed", "confidence_bps", "reason_code", "reasoning",
            ],
        }
        jury_policy_hash = "0x" + hashlib.sha256(json.dumps(
            executable_policy, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode()).hexdigest()
        consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
        network_id = "mycomesh-v10-dynamic-provider-ai-controlled-test"
        deployment.update({
            "network_id": network_id,
            "source_commit": "b" * 40,
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
            "max_channel_duration_seconds": 2_592_000,
            "deployment_block_hash": "0x" + "4" * 64,
            REPUTATION_HISTORY_FIELD: copy.deepcopy(REPUTATION_HISTORY),
        })
        settlement_immutables = list(_expected_immutable_values(deployment).values())
        settlement_starts = tuple(
            8 + 40 * index for index in range(len(settlement_immutables))
        )
        settlement_runtime = bytearray(b"\x60" * (settlement_starts[-1] + 40))
        for start, immutable in zip(settlement_starts, settlement_immutables):
            settlement_runtime[start:start + 32] = immutable
        deployment["settlement_runtime_code_keccak256"] = _keccak256(
            bytes(settlement_runtime)
        )
        for name in (
            "adjudicators", "adjudicator_operators", "independence_attested",
            "monetary_policy",
        ):
            deployment.pop(name, None)
        provider["network_id"] = network_id
        provider["source_commit"] = deployment["source_commit"]
        provider["jury_relay_public_keys"] = [JURY_RELAY_KEY]
        provider["jury_transaction_senders"] = {
            JURY_RELAY_KEY: JURY_TRANSACTION_SENDER,
        }
        provider[JURY_TRANSACTION_GAS_CAP_FIELD] = (
            JURY_TRANSACTION_GAS_CAP_WEI
        )
        provider[REPUTATION_HISTORY_FIELD] = copy.deepcopy(
            deployment[REPUTATION_HISTORY_FIELD]
        )
        for field in (
            "deployment_block", "deployment_block_hash",
            "settlement_runtime_code_keccak256",
        ):
            provider[field] = deployment[field]
        consumer = {
            **deployment,
            **{
                key: value for key, value in provider.items()
                if key not in {"deployment", "tls_ca_file"}
            },
            "tls_ca_file": "v10-controlled-test.ca.crt",
        }
        write_json(deployment_path, deployment)
        write_json(provider_path, provider)
        write_json(consumer_path, consumer)
        return deployment

    def artifact_fixture(self, root, *, promotable=True, dynamic=True):
        source_commit = "a" * 40
        index_digest = "sha256:" + "1" * 64
        image = "ghcr.io/charleslzp/mycomesh-provider-codex@" + index_digest
        artifacts = root / "release-inputs"
        artifacts.mkdir()

        if promotable:
            deployment_path = root / "deployments/sepolia-myco-v10.json"
            deployment = json.loads(deployment_path.read_text())
            provider_network_path = root / "deployments/sepolia-provider-network-v10.json"
            provider_network = json.loads(provider_network_path.read_text())
            consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            consumer = json.loads(consumer_path.read_text())
            network_id = "mycomesh-v10-fixed-budget"
            operators = {
                judge: f"independent-operator-{index}"
                for index, judge in enumerate(deployment["adjudicators"], start=1)
            }
            deployment.update({
                "network_id": network_id,
                "max_channel_duration_seconds": 2_592_000,
                "committee_mode": "independent_users",
                "independence_attested": True,
                "adjudicator_operators": operators,
                "monetary_policy": {
                    "schema": "mycomesh.v10.monetary-policy.v1",
                    "network_id": network_id,
                    "chain_id": deployment["chain_id"],
                    "settlement_contract": deployment["settlement"],
                    "required_reputation": 80,
                    "required_votes": deployment["adjudication_threshold"],
                    "signers": [
                        {
                            "public_key": f"{index:02x}" * 32,
                            "evm_address": judge,
                            "operator_id": operators[judge],
                            "reputation": 99,
                        }
                        for index, judge in enumerate(deployment["adjudicators"], start=1)
                    ],
                },
            })
            provider_network["network_id"] = network_id
            consumer.update(deployment)
            consumer.update({
                key: value for key, value in provider_network.items()
                if key not in {"deployment", "tls_ca_file"}
            })
            write_json(deployment_path, deployment)
            write_json(provider_network_path, provider_network)
            write_json(consumer_path, consumer)

        if dynamic:
            self.make_dynamic_jury_manifest(root)

        release_source = (root / "packages/mycomesh-cli/src/release.mjs").read_text()
        release_source = release_source.replace(
            "export const PROVIDER_RELEASE_SOURCE_COMMIT = null;",
            f'export const PROVIDER_RELEASE_SOURCE_COMMIT = "{source_commit}";',
        ).replace(
            "export const PROVIDER_RELEASE_IMAGE = null;",
            f'export const PROVIDER_RELEASE_IMAGE = "{image}";',
        ).encode()
        provider_tgz = artifacts / "provider.tgz"
        provider_files = _package_source_files(root, "provider")
        provider_files["package/packages/mycomesh-cli/src/release.mjs"] = release_source
        write_tgz(provider_tgz, provider_files)
        consumer_tgz = artifacts / "consumer.tgz"
        write_tgz(consumer_tgz, _package_source_files(root, "consumer"))

        oci_metadata = artifacts / "oci.json"
        oci_value = {
            "schema": OCI_METADATA_SCHEMA,
            "image": image,
            "index_digest": index_digest,
            "revision": source_commit,
            "platforms": [
                {"os": "linux", "architecture": "amd64", "digest": "sha256:" + "2" * 64,
                 "revision": source_commit},
                {"os": "linux", "architecture": "arm64", "digest": "sha256:" + "3" * 64,
                 "revision": source_commit},
            ],
        }
        write_json(oci_metadata, oci_value)

        deployment_path = root / "deployments/sepolia-myco-v10.json"
        deployment = json.loads(deployment_path.read_text())
        provider_network_path = root / "deployments/sepolia-provider-network-v10.json"
        provider_network = json.loads(provider_network_path.read_text())
        immutable_values = list(_expected_immutable_values(deployment).values())
        starts = tuple(8 + 40 * index for index in range(len(immutable_values)))
        runtime_template = bytearray(b"\x60" * (starts[-1] + 40))
        runtime = bytearray(runtime_template)
        immutable_references = {}
        for index, (start, value) in enumerate(zip(starts, immutable_values)):
            runtime_template[start:start + 32] = b"\0" * 32
            runtime[start:start + 32] = value
            immutable_references[str(index)] = [{"start": start, "length": 32}]

        abi_artifact = artifacts / "MycoSettlementV10.json"
        abi_value = {
            "abi": [
                {
                    "type": "function", "name": "MAX_CHANNEL_DURATION",
                    "inputs": [], "outputs": [],
                },
                {"type": "function", "name": "openCapacityChannels", "inputs": [], "outputs": []},
                {"type": "function", "name": "settleReservedReceipt", "inputs": [], "outputs": []},
                {"type": "function", "name": "voteDisputeBySig", "inputs": [], "outputs": []},
                *([{"type": "function", "name": "juryRegistry", "inputs": [], "outputs": []}]
                  if dynamic else []),
            ],
            "deployedBytecode": {
                "object": "0x" + runtime_template.hex(),
                "immutableReferences": immutable_references,
            },
        }
        write_json(abi_artifact, abi_value)
        abi_artifact_hash, abi_hash, _ = _canonical_abi(abi_artifact.read_bytes())

        registry_abi_artifact = None
        registry_runtime = None
        registry_runtime_sha256 = None
        registry_runtime_keccak = None
        if dynamic:
            registry_values = (
                bytes.fromhex(deployment["policy"]["bond_penalty_recipient"][2:]).rjust(32, b"\0"),
                deployment["minimum_provider_reputation"],
                deployment["jury_size"],
                deployment["adjudication_threshold"],
                deployment["jury_selection_delay_blocks"],
            )
            registry_starts = (8, 48, 88, 128, 168)
            registry_template = bytearray(b"\x61" * 208)
            registry_runtime_value = bytearray(registry_template)
            registry_references = {}
            for index, (start, value) in enumerate(zip(registry_starts, registry_values)):
                registry_template[start:start + 32] = b"\0" * 32
                registry_runtime_value[start:start + 32] = (
                    value if isinstance(value, bytes) else value.to_bytes(32, "big")
                )
                registry_references[str(index)] = [{"start": start, "length": 32}]
            registry_abi_artifact = artifacts / "ProviderJuryRegistryV1.json"
            registry_abi_value = {
                "abi": registry_abi_items(),
                "deployedBytecode": {
                    "object": "0x" + registry_template.hex(),
                    "immutableReferences": registry_references,
                },
            }
            write_json(registry_abi_artifact, registry_abi_value)
            registry_runtime = bytes(registry_runtime_value)
            registry_runtime_sha256 = hashlib.sha256(registry_runtime).hexdigest()
            registry_runtime_keccak = _keccak256(registry_runtime)

        runtime = bytes(runtime)
        runtime_sha256 = hashlib.sha256(runtime).hexdigest()
        runtime_keccak = _keccak256(runtime)
        if dynamic:
            deployment["settlement_runtime_code_keccak256"] = runtime_keccak
            provider_network["settlement_runtime_code_keccak256"] = runtime_keccak
            consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            consumer_network = json.loads(consumer_path.read_text())
            consumer_network["settlement_runtime_code_keccak256"] = runtime_keccak
            write_json(deployment_path, deployment)
            write_json(provider_network_path, provider_network)
            write_json(consumer_path, consumer_network)
        deployed_code = artifacts / "deployed-code.json"
        state_block_number = deployment["deployment_block"] + 100
        pricing_state = {
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
        deployed_value = {
            "schema": DEPLOYED_CODE_SCHEMA,
            "source_commit": source_commit,
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
                "domain_separator": "0x" + _expected_immutable_values(deployment)[
                    "initial_domain_separator"
                ].hex(),
                "max_channel_duration_seconds": deployment[
                    "max_channel_duration_seconds"
                ],
                ("jury_registry" if dynamic else "adjudicators"): deployment[
                    "jury_registry" if dynamic else "adjudicators"
                ],
                "policy": deployment["policy"],
                "stablecoin_runtime_code_sha256": deployment[
                    "stablecoin_runtime_code_sha256"
                ],
                "stablecoin_runtime_code_keccak256": deployment[
                    "stablecoin_runtime_code_keccak256"
                ],
                "stablecoin_balance": 2_000_000,
                "stable_liabilities": 1_500_000,
                "channel": pricing_state,
            },
            "capacity_channels": capacity_channels,
            "confirmations": 6,
            "rpc_quorum": 2,
            "deployment_manifest_sha256": sha256(deployment_path),
            "provider_network_manifest_sha256": sha256(provider_network_path),
            "consumer_network_manifest_sha256": sha256(
                root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            ),
            "runtime_code": "0x" + runtime.hex(),
            "runtime_code_sha256": runtime_sha256,
            "runtime_code_keccak256": runtime_keccak,
        }
        if dynamic:
            deployed_value["source_commit"] = deployment["source_commit"]
            providers = dynamic_jury_providers()
            for channel in deployed_value["capacity_channels"]:
                channel["jury_ready"] = True
            deployed_value["jury_decision_policy_hash"] = deployment[
                "jury_decision_policy_hash"
            ]
            deployed_value["jury_registry_state"] = {
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
                "runtime_code_sha256": registry_runtime_sha256,
                "runtime_code_keccak256": registry_runtime_keccak,
            }
            deployed_value["jury_transaction_senders"] = {
                JURY_RELAY_KEY: {
                    "relay_public_key": JURY_RELAY_KEY,
                    "address": JURY_TRANSACTION_SENDER,
                    "block_number": state_block_number,
                    "block_hash": deployed_value["state_block_hash"],
                    "confirmed_nonce": 6,
                    "latest_nonce": 7,
                    "pending_nonce": 7,
                    "pending_transaction": False,
                    "balance_wei": JURY_TRANSACTION_GAS_CAP_WEI * 2,
                    "code_keccak256": EMPTY_CODE_KECCAK256,
                    "gas_cap_wei": JURY_TRANSACTION_GAS_CAP_WEI,
                },
            }
            deployed_value[REPUTATION_HISTORY_FIELD] = copy.deepcopy(
                deployment[REPUTATION_HISTORY_FIELD]
            )
        write_json(deployed_code, deployed_value)

        root_package = json.loads((root / "package.json").read_text())
        consumer_package = json.loads((root / "packages/mycomesh-cli/package.json").read_text())
        npm_metadata = artifacts / "npm-release-candidate.json"
        npm_packages = {}
        for role, package, tarball in (
            ("provider", root_package, provider_tgz),
            ("consumer", consumer_package, consumer_tgz),
        ):
            raw = tarball.read_bytes()
            npm_packages[role] = {
                "name": package["name"],
                "version": package["version"],
                "filename": tarball.name,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "npm_shasum": hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
                "npm_integrity": "sha512-" + base64.b64encode(
                    hashlib.sha512(raw).digest()
                ).decode("ascii"),
            }
        write_json(npm_metadata, {
            "schema": "mycomesh.npm-release-candidate.v1",
            "source_commit": source_commit,
            "provider_image": image,
            "packages": npm_packages,
        })
        release_evidence = artifacts / "release.json"
        release_value = {
            "schema": ARTIFACT_SCHEMA,
            "source_commit": source_commit,
            "packages": {
                "provider": {"name": root_package["name"], "version": root_package["version"],
                             "sha256": sha256(provider_tgz)},
                "consumer": {"name": consumer_package["name"], "version": consumer_package["version"],
                             "sha256": sha256(consumer_tgz)},
            },
            "oci": {
                "image": image,
                "index_digest": index_digest,
                "metadata_sha256": sha256(oci_metadata),
            },
            "contract": {
                "chain_id": deployment["chain_id"],
                "address": deployment["settlement"],
                "transaction_hash": deployment["tx_hash"],
                "deployment_block": deployment["deployment_block"],
                "abi_artifact_sha256": abi_artifact_hash,
                "abi_sha256": abi_hash,
                "deployment_manifest_sha256": sha256(deployment_path),
                "provider_network_manifest_sha256": sha256(root / "deployments/sepolia-provider-network-v10.json"),
                "consumer_network_manifest_sha256": sha256(root / "packages/mycomesh-cli/networks/v10-controlled-test.json"),
                "deployed_code_evidence_sha256": sha256(deployed_code),
                "runtime_code_sha256": runtime_sha256,
                "runtime_code_keccak256": runtime_keccak,
            },
        }
        if dynamic:
            release_value["contract"]["jury_decision_policy_hash"] = deployment[
                "jury_decision_policy_hash"
            ]
            release_value["contract"]["jury_policy"] = _jury_policy_declaration(
                root, deployment,
            )
            registry_artifact_hash, registry_abi_hash, _ = _canonical_abi(
                registry_abi_artifact.read_bytes()
            )
            release_value["contract"]["jury_registry"] = {
                "address": deployment["jury_registry"],
                "abi_artifact_sha256": registry_artifact_hash,
                "abi_sha256": registry_abi_hash,
                "runtime_code_sha256": registry_runtime_sha256,
                "runtime_code_keccak256": registry_runtime_keccak,
            }
            release_value["contract"]["jury_transaction_senders"] = {
                JURY_RELAY_KEY: {
                    "address": JURY_TRANSACTION_SENDER,
                    "confirmed_nonce": 6,
                    "latest_nonce": 7,
                    "balance_wei": JURY_TRANSACTION_GAS_CAP_WEI * 2,
                    "code_keccak256": EMPTY_CODE_KECCAK256,
                    "gas_cap_wei": JURY_TRANSACTION_GAS_CAP_WEI,
                },
            }
            release_value["contract"][REPUTATION_HISTORY_FIELD] = copy.deepcopy(
                deployment[REPUTATION_HISTORY_FIELD]
            )
        write_json(release_evidence, release_value)
        result = {
            "artifact_evidence": release_evidence,
            "npm_metadata": npm_metadata,
            "provider_tgz": provider_tgz,
            "consumer_tgz": consumer_tgz,
            "oci_metadata": oci_metadata,
            "deployed_code_evidence": deployed_code,
            "abi_artifact": abi_artifact,
            "expected_source_commit": source_commit,
            "release_value": release_value,
            "oci_value": oci_value,
            "deployed_value": deployed_value,
        }
        if dynamic:
            result["jury_registry_abi_artifact"] = registry_abi_artifact
        return result

    def test_repository_accepts_ancestor_deployment_source(self):
        report = check(ROOT)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["scope"], "source")
        self.assertFalse(failed(report, "active-v10-manifest-source-commit"), report)
        self.assertIn("OCI image digest/revision/signature not verified", report["limitations"])

    def test_deployment_source_commit_is_ancestor_with_unchanged_build_inputs(self):
        path = ROOT / "deployments/sepolia-myco-v10-dynamic-20260926.json"
        source_commit = json.loads(path.read_text())["source_commit"]
        ok, detail = _deployment_source_status(ROOT, source_commit)
        self.assertTrue(ok, detail)
        self.assertTrue(detail["is_ancestor"])
        self.assertTrue(detail["committed_build_inputs_unchanged"])
        self.assertTrue(detail["working_tree_build_inputs_unchanged"])

    def test_deployment_source_rejects_non_ancestor(self):
        ok, detail = _deployment_source_status(ROOT, "0" * 40)
        self.assertFalse(ok, detail)
        self.assertFalse(detail["is_ancestor"])

    def test_deployment_source_rejects_contract_input_drift(self):
        responses = [
            subprocess.CompletedProcess([], 0, "c" * 40 + "\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 1, "", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        with patch("scripts.release_gate.subprocess.run", side_effect=responses):
            ok, detail = _deployment_source_status(ROOT, "a" * 40)
        self.assertFalse(ok, detail)
        self.assertFalse(detail["committed_build_inputs_unchanged"])

    def test_manifest_source_commit_rejects_stale_head(self):
        with self.fixture() as (root, _):
            paths = (
                root / "deployments/sepolia-myco-v10.json",
                root / "deployments/sepolia-provider-network-v10.json",
                root / "packages/mycomesh-cli/networks/v10-controlled-test.json",
            )
            for path in paths:
                value = json.loads(path.read_text())
                value["source_commit"] = "a" * 40
                write_json(path, value)
            with patch("scripts.release_gate._deployment_source_status", return_value=(False, {"is_ancestor": False})):
                report = check(root)
        self.assertTrue(failed(report, "v10-manifest-source-commit"), report)

    def test_manifest_source_commit_accepts_deployment_commit_distinct_from_release_head(self):
        with self.fixture() as (root, _):
            paths = (
                root / "deployments/sepolia-myco-v10.json",
                root / "deployments/sepolia-provider-network-v10.json",
                root / "packages/mycomesh-cli/networks/v10-controlled-test.json",
            )
            for path in paths:
                value = json.loads(path.read_text())
                value["source_commit"] = "a" * 40
                write_json(path, value)
            with patch("scripts.release_gate._git_head", return_value="b" * 40), patch(
                "scripts.release_gate._deployment_source_status",
                return_value=(True, {"is_ancestor": True}),
            ):
                report = check(root)
        self.assertFalse(failed(report, "v10-manifest-source-commit"), report)

    def test_dynamic_manifest_requires_source_commit(self):
        with self.fixture() as (root, _):
            self.make_dynamic_jury_manifest(root)
            paths = (
                root / "deployments/sepolia-myco-v10.json",
                root / "deployments/sepolia-provider-network-v10.json",
                root / "packages/mycomesh-cli/networks/v10-controlled-test.json",
            )
            for path in paths:
                value = json.loads(path.read_text())
                value.pop("source_commit", None)
                write_json(path, value)
            report = check(root)
        self.assertTrue(failed(report, "v10-manifest-source-commit"), report)

    def test_source_gate_rejects_symlinked_release_manifest(self):
        with self.fixture() as (root, _):
            manifest = root / "deployments/sepolia-myco-v10.json"
            target = root / "deployment-copy.json"
            target.write_bytes(manifest.read_bytes())
            manifest.unlink()
            manifest.symlink_to(target)
            report = check(root)
        self.assertTrue(failed(report, "json:deployments/sepolia-myco-v10.json"), report)

    def test_active_dynamic_profile_rejects_stale_head_even_with_legacy_profile(self):
        with self.fixture() as (root, _):
            active_paths = (
                ("deployments/sepolia-myco-v10-dynamic-20260926.json", "deployment"),
                (
                    "deployments/sepolia-provider-network-v10-dynamic-20260926.json",
                    "provider_network",
                ),
                ("packages/mycomesh-cli/networks/v10-dynamic-20260926.json", "consumer_network"),
            )
            for relative, _ in active_paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            with patch("scripts.release_gate._deployment_source_status", return_value=(False, {"is_ancestor": False})):
                report = check(root)
        self.assertTrue(failed(report, "active-v10-manifest-source-commit"), report)

    def test_active_dynamic_profile_rejects_partial_manifest_set(self):
        with self.fixture() as (root, _):
            for relative in (
                "deployments/sepolia-myco-v10-dynamic-20260926.json",
                "deployments/sepolia-provider-network-v10-dynamic-20260926.json",
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            (root / "packages/mycomesh-cli/networks/v10-dynamic-20260926.json").unlink()
            report = check(root)
        self.assertTrue(failed(report, "active-v10-manifest-source-commit"), report)

    def test_source_gate_requires_jury_runtime_and_policy_in_oci_context(self):
        with self.fixture() as (root, _):
            dockerfile = root / "Dockerfile"
            dockerfile.write_text(
                dockerfile.read_text().replace(
                    "COPY deployments ./deployments\n", "# deployments omitted\n",
                )
            )
            report = check(root)
        self.assertTrue(
            failed(report, "oci-source-includes-provider-jury-runtime"), report,
        )

    def test_oci_source_requires_reputation_import_and_event_verifier(self):
        for relative in (
            "gateway/provider_reputation_import.py",
            "gateway/v10_reputation.py",
        ):
            with self.subTest(relative=relative), self.fixture() as (root, _):
                (root / relative).unlink()
                report = check(root)
            self.assertTrue(
                failed(report, "oci-source-includes-provider-jury-runtime"), report,
            )
            self.assertTrue(failed(report, f"release-file:{relative}"), report)

    def test_dynamic_jury_source_manifest_needs_no_static_adjudicators(self):
        with self.fixture() as (root, _):
            deployment = self.make_dynamic_jury_manifest(root)
            self.assertNotIn("adjudicators", deployment)
            self.assertNotIn("independence_attested", deployment)
            self.assertNotIn("monetary_policy", deployment)
            report = check(root)
        self.assertTrue(report["ok"], report)
        self.assertFalse(failed(report, "v10-dynamic-jury-config"))
        self.assertFalse(failed(report, "v10-dynamic-jury-provider-pool-policy"))
        self.assertFalse(failed(report, "v10-dynamic-jury-can-form"))
        self.assertTrue(any("not production-grade" in item for item in report["limitations"]))

    def test_dynamic_jury_manifest_rejects_a_pinned_provider_pool(self):
        with self.fixture() as (root, _):
            deployment = self.make_dynamic_jury_manifest(root)
            deployment["jury_provider_evidence"] = dynamic_jury_providers()
            deployment_path = root / "deployments/sepolia-myco-v10.json"
            write_json(deployment_path, deployment)
            consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            consumer = json.loads(consumer_path.read_text())
            consumer["jury_provider_evidence"] = deployment["jury_provider_evidence"]
            write_json(consumer_path, consumer)
            report = check(root)
        self.assertTrue(failed(report, "v10-dynamic-jury-provider-pool-policy"), report)

    def test_dynamic_reputation_history_lineage_is_required_exact_and_shared(self):
        mutations = (
            "missing", "null", "extra", "provider-drift", "consumer-drift",
            "high-confirmations", "invalid-history-range", "wrong-genesis",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.fixture() as (root, _):
                self.make_dynamic_jury_manifest(root)
                deployment_path = root / "deployments/sepolia-myco-v10.json"
                provider_path = root / "deployments/sepolia-provider-network-v10.json"
                consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
                deployment = json.loads(deployment_path.read_text())
                provider = json.loads(provider_path.read_text())
                consumer = json.loads(consumer_path.read_text())
                if mutation == "missing":
                    deployment.pop(REPUTATION_HISTORY_FIELD)
                elif mutation == "null":
                    deployment[REPUTATION_HISTORY_FIELD] = None
                elif mutation == "extra":
                    deployment[REPUTATION_HISTORY_FIELD]["unexpected"] = True
                elif mutation == "provider-drift":
                    provider[REPUTATION_HISTORY_FIELD]["artifact_root"] = (
                        "0x" + "65" * 32
                    )
                elif mutation == "consumer-drift":
                    consumer[REPUTATION_HISTORY_FIELD]["artifact_sha256"] = "66" * 32
                elif mutation == "high-confirmations":
                    deployment[REPUTATION_HISTORY_FIELD]["confirmations"] = 257
                elif mutation == "wrong-genesis":
                    wrong = "0x" + "67" * 32
                    for manifest in (deployment, provider, consumer):
                        manifest[REPUTATION_HISTORY_FIELD][
                            "source_genesis_hash"
                        ] = wrong
                else:
                    deployment[REPUTATION_HISTORY_FIELD][
                        "source_history_through_block"
                    ] = 89
                write_json(deployment_path, deployment)
                write_json(provider_path, provider)
                write_json(consumer_path, consumer)
                report = check(root)
            self.assertTrue(
                failed(report, "v10-reputation-history-import"), report,
            )

    def test_dynamic_settlement_deployment_boundary_is_required_exact_and_shared(self):
        mutations = (
            "missing-block", "zero-block", "missing-block-hash",
            "provider-block-hash-drift", "consumer-runtime-hash-drift",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.fixture() as (root, _):
                self.make_dynamic_jury_manifest(root)
                deployment_path = root / "deployments/sepolia-myco-v10.json"
                provider_path = root / "deployments/sepolia-provider-network-v10.json"
                consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
                deployment = json.loads(deployment_path.read_text())
                provider = json.loads(provider_path.read_text())
                consumer = json.loads(consumer_path.read_text())
                if mutation == "missing-block":
                    deployment.pop("deployment_block")
                elif mutation == "zero-block":
                    deployment["deployment_block"] = 0
                elif mutation == "missing-block-hash":
                    deployment.pop("deployment_block_hash")
                elif mutation == "provider-block-hash-drift":
                    provider["deployment_block_hash"] = "0x" + "7" * 64
                else:
                    consumer["settlement_runtime_code_keccak256"] = (
                        "0x" + "8" * 64
                    )
                write_json(deployment_path, deployment)
                write_json(provider_path, provider)
                write_json(consumer_path, consumer)
                report = check(root)
            self.assertTrue(
                failed(report, "v10-dynamic-settlement-deployment-boundary"),
                report,
            )

    def test_dynamic_jury_manifests_reject_every_static_committee_field(self):
        prohibited = {
            "adjudicators": [],
            "adjudicator_operators": {},
            "independence_attested": False,
            "jury_provider_evidence": [],
        }
        for location in ("deployment", "provider_network", "consumer_network"):
            for field, value in prohibited.items():
                with self.subTest(location=location, field=field), self.fixture() as (root, _):
                    self.make_dynamic_jury_manifest(root)
                    deployment_path = root / "deployments/sepolia-myco-v10.json"
                    provider_path = root / "deployments/sepolia-provider-network-v10.json"
                    consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
                    deployment = json.loads(deployment_path.read_text())
                    provider = json.loads(provider_path.read_text())
                    consumer = json.loads(consumer_path.read_text())
                    target = {
                        "deployment": deployment,
                        "provider_network": provider,
                        "consumer_network": consumer,
                    }[location]
                    target[field] = value
                    # Keep the semantic-union check valid when the injected field
                    # originates in either source manifest, so this test isolates
                    # the dynamic/static schema boundary.
                    if location in {"deployment", "provider_network"}:
                        consumer[field] = value
                    write_json(deployment_path, deployment)
                    write_json(provider_path, provider)
                    write_json(consumer_path, consumer)
                    report = check(root)
                self.assertTrue(failed(report, "v10-dynamic-jury-schema"), report)

    def test_dynamic_future_blockhash_mode_is_sepolia_controlled_only(self):
        with self.fixture() as (root, _):
            deployment = self.make_dynamic_jury_manifest(root)
            deployment["network_id"] = "mycomesh-v10-production"
            deployment_path = root / "deployments/sepolia-myco-v10.json"
            write_json(deployment_path, deployment)
            provider_path = root / "deployments/sepolia-provider-network-v10.json"
            provider = json.loads(provider_path.read_text())
            provider["network_id"] = deployment["network_id"]
            write_json(provider_path, provider)
            consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            consumer = json.loads(consumer_path.read_text())
            consumer["network_id"] = deployment["network_id"]
            write_json(consumer_path, consumer)
            report = check(root)
        self.assertTrue(failed(report, "v10-dynamic-jury-config"), report)

    def test_dynamic_jury_config_validates_authority_reputation_quorum_and_delay(self):
        mutations = (
            ("jury_registry", "0x" + "0" * 40),
            ("jury_registry_governance", "0x" + "33" * 20),
            ("reputation_authority", "0x" + "0" * 40),
            ("minimum_provider_reputation", 0),
            ("jury_size", 2),
            ("adjudication_threshold", 1),
            ("jury_selection_delay_blocks", 0),
            ("jury_randomness", "uncommitted_blockhash"),
            ("jury_decision_policy_hash", "0x" + "0" * 64),
            ("jury_decision_policy_hash", "0x" + "AB" * 32),
        )
        for field, value in mutations:
            with self.subTest(field=field), self.fixture() as (root, _):
                deployment = self.make_dynamic_jury_manifest(root)
                deployment[field] = value
                deployment_path = root / "deployments/sepolia-myco-v10.json"
                write_json(deployment_path, deployment)
                consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
                consumer = json.loads(consumer_path.read_text())
                consumer[field] = value
                write_json(consumer_path, consumer)
                report = check(root)
            self.assertTrue(failed(report, "v10-dynamic-jury-config"), report)

    def test_noncontrolled_committee_requires_real_independence(self):
        with self.fixture() as (root, _):
            path = root / "deployments/sepolia-myco-v10.json"
            deployment = json.loads(path.read_text())
            deployment["committee_mode"] = "independent_users"
            deployment["independence_attested"] = False
            path.write_text(json.dumps(deployment))
            report = check(root)
        self.assertTrue(failed(report, "v10-committee-declaration"))

    def test_bad_provider_version_is_reported(self):
        with self.fixture() as (root, _):
            package = json.loads((root / "package.json").read_text())
            package["version"] = "0.0.0"
            (root / "package.json").write_text(json.dumps(package))
            report = check(root)
        self.assertFalse(report["ok"])
        self.assertTrue(failed(report, "provider-version"))

    def test_npm_provenance_requires_matching_repository_for_both_packages(self):
        for path in ("package.json", "packages/mycomesh-cli/package.json"):
            with self.subTest(path=path), self.fixture() as (root, _):
                package_path = root / path
                package = json.loads(package_path.read_text())
                package["repository"] = {"type": "git", "url": ""}
                package_path.write_text(json.dumps(package))
                report = check(root)
                self.assertTrue(failed(report, "npm-provenance-repository"))

    def test_nested_consumer_lock_version_is_checked(self):
        with self.fixture() as (root, _):
            path = root / "packages/mycomesh-cli/package-lock.json"
            lock = json.loads(path.read_text())
            lock["packages"][""]["version"] = "0.0.0"
            path.write_text(json.dumps(lock))
            report = check(root)
        self.assertTrue(failed(report, "consumer-version"))

    def test_malformed_json_is_a_structured_failure(self):
        with self.fixture() as (root, _):
            (root / "package.json").write_text('{"version":"1", "version":"2"}')
            report = check(root)
        self.assertFalse(report["ok"])
        self.assertTrue(failed(report, "json:package.json"))

    def test_provider_image_must_use_official_digest_pinned_repository(self):
        with self.fixture() as (root, _):
            path = root / "packages/mycomesh-cli/src/release.mjs"
            path.write_text(path.read_text().replace(
                "export const PROVIDER_RELEASE_IMAGE = null;",
                'export const PROVIDER_RELEASE_IMAGE = "example.invalid/provider@sha256:' + "1" * 64 + '";',
            ))
            report = check(root)
        self.assertTrue(failed(report, "provider-image-pin"))

    def test_consumer_manifest_drift_is_rejected(self):
        with self.fixture() as (root, _):
            path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            manifest = json.loads(path.read_text())
            manifest["pricing_version"] += 1
            path.write_text(json.dumps(manifest))
            report = check(root)
        self.assertTrue(failed(report, "v10-consumer-manifest-merge"))

    def test_provider_and_deployment_binding_drift_is_rejected(self):
        with self.fixture() as (root, _):
            path = root / "deployments/sepolia-provider-network-v10.json"
            manifest = json.loads(path.read_text())
            manifest["network_id"] = "wrong-network"
            path.write_text(json.dumps(manifest))
            report = check(root)
        self.assertTrue(failed(report, "v10-provider-deployment-bindings"))

    def test_ca_is_compared_by_content_not_package_relative_name(self):
        with self.fixture() as (root, _):
            path = root / "packages/mycomesh-cli/networks/v10-controlled-test.ca.crt"
            path.write_bytes(path.read_bytes() + b"tampered")
            report = check(root)
        self.assertTrue(failed(report, "v10-ca-bundle"))

    def test_invalid_fresh_channel_window_is_rejected(self):
        with self.fixture() as (root, _):
            deployment_path = root / "deployments/sepolia-myco-v10.json"
            deployment = json.loads(deployment_path.read_text())
            deployment["fresh_channel_claim_until"] = deployment["fresh_channel_admit_until"]
            deployment_path.write_text(json.dumps(deployment))
            consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            consumer = json.loads(consumer_path.read_text())
            consumer["fresh_channel_claim_until"] = deployment["fresh_channel_claim_until"]
            consumer_path.write_text(json.dumps(consumer))
            report = check(root)
        self.assertTrue(failed(report, "v10-fresh-channel-window"))

    def test_channel_duration_is_bound_to_open_block_timestamps(self):
        with self.fixture() as (root, _):
            deployment_path = root / "deployments/sepolia-myco-v10.json"
            deployment = json.loads(deployment_path.read_text())
            deployment["fresh_channel_open_block_timestamps"][0] = (
                deployment["fresh_channel_valid_from"]
            )
            deployment_path.write_text(json.dumps(deployment))
            consumer_path = root / "packages/mycomesh-cli/networks/v10-controlled-test.json"
            consumer = json.loads(consumer_path.read_text())
            consumer["fresh_channel_open_block_timestamps"] = deployment[
                "fresh_channel_open_block_timestamps"
            ]
            consumer_path.write_text(json.dumps(consumer))
            report = check(root)
        self.assertTrue(failed(report, "v10-channel-duration"))

    def test_required_release_file_must_be_tracked(self):
        with self.fixture() as (root, tracked):
            missing = REQUIRED_RELEASE_FILES[0]
            with patch("scripts.release_gate._tracked", return_value=[p for p in tracked if p != missing]):
                report = check(root)
        self.assertTrue(failed(report, "release-files-tracked"))

    def test_tracked_generated_output_is_rejected(self):
        with self.fixture() as (root, tracked):
            with patch("scripts.release_gate._tracked", return_value=[*tracked, "out/build.json"]):
                report = check(root)
        self.assertTrue(failed(report, "tracked-generated-files"))

    def test_strict_artifact_evidence_round_trip(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["scope"], "artifacts")

    def test_npm_candidate_metadata_binds_head_and_tarball_hashes(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(report["ok"], report)
        self.assertFalse(failed(report, "artifact-npm-candidate-binding"), report)

    def test_npm_candidate_metadata_rejects_source_commit_drift(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            metadata = json.loads(inputs["npm_metadata"].read_text())
            metadata["source_commit"] = "b" * 40
            write_json(inputs["npm_metadata"], metadata)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-npm-source-commit"), report)
        self.assertTrue(failed(report, "artifact-npm-candidate-binding"), report)

    def test_npm_candidate_metadata_rejects_tarball_hash_drift(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            metadata = json.loads(inputs["npm_metadata"].read_text())
            metadata["packages"]["consumer"]["sha256"] = "f" * 64
            write_json(inputs["npm_metadata"], metadata)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-npm-candidate-binding"), report)

    def test_dynamic_jury_strict_gate_verifies_both_contract_runtimes(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(report["ok"], report)
        self.assertFalse(failed(report, "artifact-deployed-runtime"))
        self.assertFalse(failed(report, "artifact-jury-registry-runtime"))
        self.assertFalse(failed(report, "artifact-promotion-policy"))
        self.assertTrue(any("not production-grade" in item for item in report["limitations"]))

    def test_static_independent_committee_cannot_be_promoted(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=False)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-promotion-policy"), report)

    def test_strict_gate_rejects_uncommitted_source_boundary(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            with patch(
                "scripts.release_gate._strict_git_source_status",
                return_value=(False, {"dirty_entries": [" M gateway/provider_jury.py"]}),
            ):
                report = check_artifacts(root, **{
                    key: value for key, value in inputs.items()
                    if key not in {"release_value", "oci_value", "deployed_value"}
                })
        self.assertTrue(failed(report, "artifact-git-source-boundary"), report)

    def test_strict_git_source_status_requires_clean_tracked_head(self):
        with self.fixture() as (root, _):
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run([
                "git", "-C", str(root), "-c", "user.name=Release Test",
                "-c", "user.email=release@example.invalid", "commit", "-qm", "fixture",
            ], check=True)
            head = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            ok, detail = _strict_git_source_status(root, head)
            self.assertTrue(ok, detail)
            target = root / "contracts/ProviderJuryRegistryV1.sol"
            target.write_text(target.read_text() + "\n// dirty\n")
            ok, detail = _strict_git_source_status(root, head)
            self.assertFalse(ok, detail)
            self.assertTrue(detail["dirty_entries"])

    def test_dynamic_jury_strict_gate_requires_registry_compiler_artifact(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            inputs["jury_registry_abi_artifact"] = None
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-input:jury-registry-abi-artifact"), report)
        self.assertTrue(failed(report, "artifact-jury-registry-runtime"), report)

    def test_dynamic_jury_strict_gate_binds_decision_policy_hash(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            inputs["deployed_value"]["jury_decision_policy_hash"] = "0x" + "42" * 32
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                inputs["deployed_code_evidence"]
            )
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-deployed-state"), report)
        self.assertTrue(failed(report, "artifact-jury-decision-policy-hash"), report)

    def test_dynamic_jury_strict_gate_binds_settlement_deployment_boundary(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            inputs["deployed_value"]["block_hash"] = "0x" + "42" * 32
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            inputs["release_value"]["contract"][
                "deployed_code_evidence_sha256"
            ] = sha256(inputs["deployed_code_evidence"])
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-deployed-state"), report)

    def test_dynamic_jury_strict_gate_binds_policy_preimage(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            policy_path = root / "deployments/provider-jury-policy-v1.json"
            changed = json.loads(policy_path.read_text())
            changed["system_prompt"] += " Changed after release evidence."
            write_json(policy_path, changed)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "v10-dynamic-jury-policy-preimage"), report)
        self.assertTrue(failed(report, "artifact-jury-policy-preimage"), report)

    def test_dynamic_jury_strict_gate_rejects_false_onchain_can_form(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            inputs["deployed_value"]["jury_registry_state"]["can_form_jury"] = False
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                inputs["deployed_code_evidence"]
            )
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-deployed-state"), report)

    def test_dynamic_jury_strict_gate_recomputes_live_operator_independence(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            providers = inputs["deployed_value"]["jury_registry_state"]["providers"]
            providers[1]["operator_id_hash"] = providers[0]["operator_id_hash"]
            providers[2]["operator_id_hash"] = providers[0]["operator_id_hash"]
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                inputs["deployed_code_evidence"]
            )
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-deployed-state"), report)

    def test_dynamic_jury_registry_runtime_must_match_compiler(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, dynamic=True)
            registry_state = inputs["deployed_value"]["jury_registry_state"]
            runtime = bytearray.fromhex(registry_state["runtime_code"][2:])
            runtime[-1] ^= 1
            registry_state["runtime_code"] = "0x" + bytes(runtime).hex()
            registry_state["runtime_code_sha256"] = hashlib.sha256(runtime).hexdigest()
            registry_state["runtime_code_keccak256"] = _keccak256(runtime)
            registry_declared = inputs["release_value"]["contract"]["jury_registry"]
            registry_declared["runtime_code_sha256"] = registry_state["runtime_code_sha256"]
            registry_declared["runtime_code_keccak256"] = registry_state[
                "runtime_code_keccak256"
            ]
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                inputs["deployed_code_evidence"]
            )
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-jury-registry-runtime"), report)

    def test_dynamic_registry_abi_requires_replay_fence_and_canonical_event(self):
        for mutation in ("old-set-provider", "bad-provider-updated-event"):
            with self.subTest(mutation=mutation), self.fixture() as (root, _):
                inputs = self.artifact_fixture(root)
                artifact = json.loads(inputs["jury_registry_abi_artifact"].read_text())
                if mutation == "old-set-provider":
                    item = next(value for value in artifact["abi"] if value.get("name") == "setProvider")
                    item["inputs"] = item["inputs"][:1]
                else:
                    item = next(value for value in artifact["abi"] if value.get("name") == "ProviderUpdated")
                    item["inputs"][5]["indexed"] = True
                write_json(inputs["jury_registry_abi_artifact"], artifact)
                artifact_hash, abi_hash, _ = _canonical_abi(
                    inputs["jury_registry_abi_artifact"].read_bytes()
                )
                declaration = inputs["release_value"]["contract"]["jury_registry"]
                declaration["abi_artifact_sha256"] = artifact_hash
                declaration["abi_sha256"] = abi_hash
                write_json(inputs["artifact_evidence"], inputs["release_value"])
                report = check_artifacts(root, **{
                    key: value for key, value in inputs.items()
                    if key not in {"release_value", "oci_value", "deployed_value"}
                })
            self.assertTrue(failed(report, "artifact-jury-registry-abi"), report)

    def test_dynamic_evidence_requires_source_commitments_and_channel_jury(self):
        mutations = (
            (("jury_registry_state", "providers", 0, "source_sequence"), 0),
            (("jury_registry_state", "providers", 0, "source_digest"), "0x" + "0" * 64),
            (("capacity_channels", 0, "jury_ready"), False),
        )
        for path, value in mutations:
            with self.subTest(path=path), self.fixture() as (root, _):
                inputs = self.artifact_fixture(root)
                cursor = inputs["deployed_value"]
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
                inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                    inputs["deployed_code_evidence"]
                )
                write_json(inputs["artifact_evidence"], inputs["release_value"])
                report = check_artifacts(root, **{
                    key: item for key, item in inputs.items()
                    if key not in {"release_value", "oci_value", "deployed_value"}
                })
            self.assertTrue(failed(report, "artifact-deployed-state"), report)

    def test_controlled_test_cannot_be_attested_as_promotable(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, promotable=False, dynamic=False)
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-promotion-policy"), report)

    def test_promotion_requires_explicit_independent_committee_mode(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            path = root / "deployments/sepolia-myco-v10.json"
            deployment = json.loads(path.read_text())
            deployment.pop("committee_mode")
            path.write_text(json.dumps(deployment))
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "v10-committee-declaration"), report)
        self.assertTrue(failed(report, "artifact-promotion-policy"), report)

    def test_strict_mode_fails_closed_when_inputs_are_missing(self):
        with self.fixture() as (root, _):
            report = check_artifacts(
                root,
                artifact_evidence=None,
                provider_tgz=None,
                consumer_tgz=None,
                oci_metadata=None,
                deployed_code_evidence=None,
                abi_artifact=None,
                expected_source_commit="a" * 40,
                require_npm_metadata=True,
            )
        self.assertFalse(report["ok"])
        self.assertTrue(failed(report, "artifact-input:release-evidence"))
        self.assertTrue(failed(report, "artifact-input:npm-metadata"))
        self.assertTrue(failed(report, "artifact-input:provider-tgz"))
        self.assertTrue(failed(report, "artifact-input:deployed-code"))

    def test_every_oci_platform_must_match_source_commit(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            inputs["oci_value"]["platforms"][1]["revision"] = "b" * 40
            write_json(inputs["oci_metadata"], inputs["oci_value"])
            inputs["release_value"]["oci"]["metadata_sha256"] = sha256(inputs["oci_metadata"])
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-oci-platforms"))

    def test_tarball_cannot_change_unchecked_runtime_source(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            files = _tarball_files(inputs["consumer_tgz"])
            member = "package/src/consumer-runtime.mjs"
            files[member] += b"\n// tampered after source review\n"
            write_tgz(inputs["consumer_tgz"], files)
            inputs["release_value"]["packages"]["consumer"]["sha256"] = sha256(
                inputs["consumer_tgz"]
            )
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-consumer-tgz-layout"))

    def test_runtime_template_cannot_replace_raw_deployed_code(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            inputs["deployed_value"]["runtime_template"] = inputs["deployed_value"].pop("runtime_code")
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                inputs["deployed_code_evidence"]
            )
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-deployed-runtime"))

    def test_deployed_code_requires_multi_rpc_confirmed_capture(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            inputs["deployed_value"]["rpc_quorum"] = 1
            inputs["deployed_value"]["confirmations"] = 1
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                inputs["deployed_code_evidence"]
            )
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-deployed-code-quorum"))

    def test_strict_gate_revalidates_state_and_channel_identity(self):
        mutations = (
            (("contract_state", "governance"), "0x" + "9" * 40),
            (("contract_state", "stablecoin_balance"), 1),
            (("capacity_channels", 0, "pricing_version"), True),
            (("capacity_channels", 0, "open_block_timestamp"),
             9_999_999_999),
            (("capacity_channels", 0, "consumer_nonce"), 999),
            (("capacity_channels", 0, "closed"), True),
        )
        for path, value in mutations:
            with self.subTest(path=path), self.fixture() as (root, _):
                inputs = self.artifact_fixture(root)
                changed = copy.deepcopy(inputs["deployed_value"])
                cursor = changed
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                write_json(inputs["deployed_code_evidence"], changed)
                inputs["release_value"]["contract"]["deployed_code_evidence_sha256"] = sha256(
                    inputs["deployed_code_evidence"]
                )
                write_json(inputs["artifact_evidence"], inputs["release_value"])
                report = check_artifacts(root, **{
                    key: item for key, item in inputs.items()
                    if key not in {"release_value", "oci_value", "deployed_value"}
                })
            self.assertTrue(failed(report, "artifact-deployed-state"), report)

    def test_deployed_runtime_must_match_compiler_output_outside_immutables(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root)
            runtime = bytes.fromhex("61ff6001")
            inputs["deployed_value"]["runtime_code"] = "0x" + runtime.hex()
            inputs["deployed_value"]["runtime_code_sha256"] = hashlib.sha256(runtime).hexdigest()
            inputs["deployed_value"]["runtime_code_keccak256"] = _keccak256(runtime)
            write_json(inputs["deployed_code_evidence"], inputs["deployed_value"])
            contract = inputs["release_value"]["contract"]
            contract["runtime_code_sha256"] = inputs["deployed_value"]["runtime_code_sha256"]
            contract["runtime_code_keccak256"] = inputs["deployed_value"]["runtime_code_keccak256"]
            contract["deployed_code_evidence_sha256"] = sha256(inputs["deployed_code_evidence"])
            write_json(inputs["artifact_evidence"], inputs["release_value"])
            report = check_artifacts(root, **{
                key: value for key, value in inputs.items()
                if key not in {"release_value", "oci_value", "deployed_value"}
            })
        self.assertTrue(failed(report, "artifact-deployed-runtime"))


if __name__ == "__main__":
    unittest.main()
