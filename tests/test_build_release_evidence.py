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
    NPM_SCHEMA,
    OCI_SCHEMA,
    RELEASE_SCHEMA,
    ReleaseEvidenceError,
    _expected_domain_separator,
    _keccak256,
    build_release_evidence,
    main,
)


ROOT = Path(__file__).parents[1]
SOURCE_COMMIT = "a" * 40
INDEX_DIGEST = "sha256:" + "1" * 64
PROVIDER_IMAGE = "ghcr.io/charleslzp/mycomesh-provider-codex@" + INDEX_DIGEST


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
        }
        self.deployed_path = self.directory / "deployed-code.json"
        write_json(self.deployed_path, self.deployed_value)

    def tearDown(self):
        self.temporary.cleanup()

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
            value["contract"]["deployed_code_evidence_sha256"],
            hashlib.sha256(self.deployed_path.read_bytes()).hexdigest(),
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
