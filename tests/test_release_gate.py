import hashlib
import copy
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts.release_gate import (
    ARTIFACT_SCHEMA,
    DEPLOYED_CODE_SCHEMA,
    OCI_METADATA_SCHEMA,
    REQUIRED_RELEASE_FILES,
    _canonical_abi,
    _expected_immutable_values,
    _keccak256,
    _package_source_files,
    _tarball_files,
    check,
    check_artifacts,
)


ROOT = Path(__file__).parents[1]
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


class ReleaseGateTest(unittest.TestCase):
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
            for relative in ("README.md", "packages/mycomesh-cli/README.md"):
                shutil.copyfile(ROOT / relative, root / relative)
            tracked = sorted(
                path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
            )
            with patch("scripts.release_gate._tracked", return_value=tracked):
                yield root, tracked

    def artifact_fixture(self, root, *, promotable=True):
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
        starts = (8, 48, 88, 128, 168)
        runtime_template = bytearray(b"\x60" * 208)
        runtime = bytearray(runtime_template)
        immutable_references = {}
        for index, (start, value) in enumerate(zip(starts, immutable_values)):
            runtime_template[start:start + 32] = b"\0" * 32
            runtime[start:start + 32] = value
            immutable_references[str(index)] = [{"start": start, "length": 32}]

        abi_artifact = artifacts / "MycoSettlementV10.json"
        abi_value = {
            "abi": [
                {"type": "function", "name": "openCapacityChannels", "inputs": [], "outputs": []},
                {"type": "function", "name": "settleReservedReceipt", "inputs": [], "outputs": []},
                {"type": "function", "name": "voteDisputeBySig", "inputs": [], "outputs": []},
            ],
            "deployedBytecode": {
                "object": "0x" + runtime_template.hex(),
                "immutableReferences": immutable_references,
            },
        }
        write_json(abi_artifact, abi_value)
        abi_artifact_hash, abi_hash, _ = _canonical_abi(abi_artifact.read_bytes())

        runtime = bytes(runtime)
        runtime_sha256 = hashlib.sha256(runtime).hexdigest()
        runtime_keccak = _keccak256(runtime)
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
        for index, (channel_id, transaction_hash, config) in enumerate(zip(
            deployment["capacity_channel_ids"],
            deployment["fresh_channel_open_tx_hashes"],
            channel_configs,
        )):
            capacity_channels.append({
                "channel_id": channel_id,
                "transaction_hash": transaction_hash,
                "block_number": deployment["deployment_block"] + index + 1,
                "block_hash": "0x" + f"{index + 5:x}" * 64,
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
                "channel": pricing_state,
            },
            "capacity_channels": capacity_channels,
            "confirmations": 6,
            "rpc_quorum": 2,
            "deployment_manifest_sha256": sha256(deployment_path),
            "provider_network_manifest_sha256": sha256(provider_network_path),
            "runtime_code": "0x" + runtime.hex(),
            "runtime_code_sha256": runtime_sha256,
            "runtime_code_keccak256": runtime_keccak,
        }
        write_json(deployed_code, deployed_value)

        root_package = json.loads((root / "package.json").read_text())
        consumer_package = json.loads((root / "packages/mycomesh-cli/package.json").read_text())
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
        write_json(release_evidence, release_value)
        return {
            "artifact_evidence": release_evidence,
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

    def test_repository_passes_release_gate(self):
        report = check(ROOT)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["scope"], "source")
        self.assertIn("OCI image digest/revision/signature not verified", report["limitations"])

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

    def test_controlled_test_cannot_be_attested_as_promotable(self):
        with self.fixture() as (root, _):
            inputs = self.artifact_fixture(root, promotable=False)
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
            )
        self.assertFalse(report["ok"])
        self.assertTrue(failed(report, "artifact-input:release-evidence"))
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
