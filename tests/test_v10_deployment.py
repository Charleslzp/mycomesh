"""Offline safety tests for the staged V10 deployment outbox."""
import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from gateway import chain, chain_v10
from gateway import v10_deployment as deploy
from tests.test_chain_v9 import address, digest, key, signer


def policy_fixture():
    runtime_hash = "0x" + chain.keccak256(bytes.fromhex("00" * 40)).hex()
    return {
        "deployment_class": "controlled_test",
        "network_id": "mycomesh-v10-dynamic-provider-ai-controlled-test",
        "chain_id": 31337,
        "genesis_hash": digest(90),
        "jury_decision_policy_hash": digest(92),
        "reputation_history_import": {
            "schema": chain_v10.REPUTATION_HISTORY_SCHEMA,
            "source_network_id": "mycomesh-v9-prior-controlled-test",
            "source_protocol_version": 9,
            "source_chain_id": 31337,
            "source_genesis_hash": digest(90),
            "source_settlement_contract": address(26),
            "source_runtime_code_hash": digest(93),
            "source_deployment_block": 10,
            "source_deployment_block_hash": digest(94),
            "source_history_through_block": 80,
            "source_history_through_block_hash": digest(95),
            "confirmations": 2,
            "artifact_sha256": "d" * 64,
            "artifact_root": digest(96),
        },
        "confirmations": 2,
        "deployer": signer(20),
        "stablecoin": address(21),
        "reward_token": chain.ZERO_ADDRESS,
        "source_commit": "c" * 40,
        "artifact_pins": {
            "registry": {
                "source_sha256": "a" * 64,
                "creation_keccak256": "0x" + chain.keccak256(bytes.fromhex("60016000")).hex(),
                "runtime_template_keccak256": runtime_hash,
            },
            "settlement": {
                "source_sha256": "b" * 64,
                "creation_keccak256": "0x" + chain.keccak256(bytes.fromhex("60026000")).hex(),
                "runtime_template_keccak256": runtime_hash,
            },
        },
        "treasury": address(22),
        "governance": signer(20),
        "initial_channel": digest(91),
        "initial_config": dict(zip(deploy.CONFIG_FIELDS, [1000, 4000, 2000, 8500, 300, 200, 1000, True])),
        "dispute_policy": dict(zip(deploy.DISPUTE_POLICY_FIELDS,
            [300, 600, 300, 10_000, 10_000, 100_000, 2000, 20_000, 0, 0, 0, 0, address(24)])),
        "registry": {
            "reputation_authority": address(25),
            "bond_penalty_recipient": address(24),
            "minimum_reputation": 100,
            "jury_size": 3,
            "threshold": 2,
            "selection_delay_blocks": 4,
        },
        "fee_policy": {
            "gas_price_wei": 10,
            "gas_limits": {"registry": 5_000_000, "settlement": 8_000_000, "bind": 200_000},
            "max_total_gas_cost_wei": 132_000_000,
        },
    }


def artifact_fixture(contract):
    creation = "0x60016000" if contract == "ProviderJuryRegistryV1" else "0x60026000"
    runtime = "0x" + "00" * 40
    result = {
        "contract": contract,
        "creation_bytecode": creation,
        "runtime_template": runtime,
        "immutable_references": {"fixture": [{"start": 1, "length": 32}]},
        "source_sha256": ("a" if contract.startswith("Provider") else "b") * 64,
    }
    result["creation_keccak256"] = "0x" + chain.keccak256(bytes.fromhex(creation[2:])).hex()
    result["runtime_template_keccak256"] = "0x" + chain.keccak256(bytes.fromhex(runtime[2:])).hex()
    return result


def artifacts_fixture():
    return {
        "registry": artifact_fixture("ProviderJuryRegistryV1"),
        "settlement": artifact_fixture("MycoSettlementV10"),
    }


class FakeRPC(deploy.V10DeploymentClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:1", allow_single_test_rpc=True)
        self.policy = policy_fixture()
        self.plan_value = None
        self.timestamp = int(time.time())
        self.head = 100
        self.nonce = 0
        self.pending_nonce = None
        self.price = 10
        self.receipts = {}
        self.deployed = set()
        self.binding = False
        self.bad_getter = None
        self.reorg_blocks = set()
        self.broadcasts = []
        self.unknown_broadcast = False
        self.stablecoin_code = "0x6000"
        self.code = "0x" + "00" + "12" * 32 + "00" * 7
        self.calls = []

    def _block(self, number):
        block_hash = digest(number + (1000 if number in self.reorg_blocks else 0))
        return {"number": hex(number), "hash": block_hash, "timestamp": hex(self.timestamp)}

    def rpc(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return hex(self.policy["chain_id"])
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            if params[0] == "0x0":
                return {"hash": self.policy["genesis_hash"]}
            return self._block(self.head if params[0] == "latest" else int(params[0], 16))
        if method == "eth_getTransactionCount":
            return hex(self.pending_nonce if params[1] == "pending" and self.pending_nonce is not None else self.nonce)
        if method == "eth_gasPrice":
            return hex(self.price)
        if method == "eth_estimateGas":
            request = params[0]
            if request.get("to") == self.plan_value["addresses"]["registry"]:
                return hex(80_000)
            if request["data"].startswith("0x6001"):
                return hex(3_200_000)
            if request["data"].startswith("0x6002"):
                return hex(5_250_000)
            raise AssertionError((method, params))
        if method == "eth_getBalance":
            return hex(10**20)
        if method == "eth_getCode":
            target = params[0].lower()
            if target == self.policy["stablecoin"]:
                return self.stablecoin_code
            return self.code if target in self.deployed else "0x"
        if method == "eth_sendRawTransaction":
            self.broadcasts.append(params[0])
            if self.unknown_broadcast:
                raise TimeoutError("accepted but response lost")
            return "0x" + chain.keccak256(bytes.fromhex(params[0][2:])).hex()
        if method == "eth_getTransactionReceipt":
            return self.receipts.get(params[0])
        if method == "eth_call":
            return self._eth_call(params)
        raise AssertionError((method, params))

    def _eth_call(self, params):
        plan, call, tag = self.plan_value, params[0], params[1]
        p, target, selector = plan["policy"], call["to"].lower(), call["data"][:10]
        historical = isinstance(tag, dict) and tag.get("blockHash") in {digest(100), digest(102)}
        if target == plan["addresses"]["registry"]:
            r = p["registry"]
            values = {
                "governance()": [p["governance"]],
                "reputationAuthority()": [r["reputation_authority"]],
                "bondPenaltyRecipient()": [r["bond_penalty_recipient"]],
                "minimumReputation()": [r["minimum_reputation"]],
                "jurySize()": [r["jury_size"]],
                "threshold()": [r["threshold"]],
                "selectionDelayBlocks()": [r["selection_delay_blocks"]],
                "MAX_JURY_SIZE()": [7],
                "settlement()": [chain.ZERO_ADDRESS if historical or not self.binding else plan["addresses"]["settlement"]],
            }
        else:
            pricing = deploy._words([p["initial_channel"], 1, p["treasury"],
                                     *[p["initial_config"][name] for name in deploy.CONFIG_FIELDS]])
            values = {
                "stablecoin()": [p["stablecoin"]], "rewardToken()": [p["reward_token"]],
                "treasury()": [p["treasury"]], "governance()": [p["governance"]],
                "juryRegistry()": [plan["addresses"]["registry"]],
                "adjudicationThreshold()": [p["registry"]["threshold"]],
                "MAX_AUTHORIZATION_TTL()": [10_800],
                "MAX_CHANNEL_DURATION()": [30 * 86400],
                "DOMAIN_SEPARATOR()": [chain_v10.domain_separator(
                    chain_id=p["chain_id"], verifying_contract=plan["addresses"]["settlement"])],
                "policy()": [p["dispute_policy"][name] for name in deploy.DISPUTE_POLICY_FIELDS],
                "latestChannelVersion(bytes32)": [1],
                "channelPricingHash(bytes32,uint64)": ["0x" + chain.keccak256(pricing).hex()],
            }
        for signature, result in values.items():
            if selector == "0x" + chain.keccak256(signature.encode())[:4].hex():
                if self.bad_getter == signature:
                    result = [0] * len(result)
                return "0x" + deploy._words(result).hex()
        raise AssertionError(("eth_call", params))


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key_file = self.root / "synthetic.key"
        self.key_file.write_text(key(20))
        self.key_file.chmod(0o600)
        self.client = FakeRPC()
        self.plan = self.client.plan(policy_fixture(), artifacts_fixture())
        self.client.plan_value = self.plan
        self.outbox = deploy.V10DeploymentOutbox(self.root / "outbox.sqlite")
        self.addCleanup(self.outbox.close)
        self.send = dict(allow_send=True, approved_plan_hash=self.plan["plan_hash"], key_file=self.key_file,
                         max_gas_price_wei=10, max_total_gas_cost_wei=132_000_000)

    def execute(self):
        return self.outbox.execute_next(self.client, self.plan, **self.send)

    def signed_raw(self, step="registry", *, key_number=20, **overrides):
        tx = self.plan["transactions"][step]
        fields = {
            "nonce": tx["nonce"],
            "gas_price_wei": tx["gas_price_wei"],
            "gas_units": tx["gas_units"],
            "to": tx["to"],
            "value": int(tx["value"], 16),
            "data": bytes.fromhex(tx["data"][2:]),
            "chain_id": tx["chain_id"],
        }
        fields.update(overrides)
        raw = chain.sign_legacy_transaction(
            chain.parse_private_key(key(key_number)),
            fields["nonce"], fields["gas_price_wei"], fields["gas_units"],
            fields["to"], fields["value"], fields["data"], fields["chain_id"],
        )
        raw_hex = "0x" + raw.hex()
        return raw_hex, "0x" + chain.keccak256(raw).hex()

    def mine_latest(self, status=1):
        state = self.outbox.status(self.plan["plan_hash"])
        step = next(name for name in deploy.STEPS if state["steps"].get(name, {}).get("state") in ("submitted", "uncertain"))
        item = state["steps"][step]
        number = {"registry": 100, "settlement": 102, "bind": 104}[step]
        self.head = max(self.client.head, number + 1)
        self.client.head = self.head
        if status:
            if step in ("registry", "settlement"):
                self.client.deployed.add(self.plan["addresses"][step])
            else:
                self.client.binding = True
        self.client.receipts[item["tx_hash"]] = {
            "transactionHash": item["tx_hash"], "blockHash": digest(number), "blockNumber": hex(number),
            "status": hex(status), "contractAddress": self.plan["addresses"].get(step),
        }
        self.client.nonce = item["nonce"] + 1
        return step

    def test_plan_fixes_three_transactions_artifacts_policy_and_addresses(self):
        self.assertEqual(self.plan["policy_hash"], deploy._hash(deploy.validate_policy(policy_fixture())))
        self.assertEqual(
            self.plan["policy"]["network_id"],
            "mycomesh-v10-dynamic-provider-ai-controlled-test",
        )
        self.assertEqual(self.plan["policy"]["jury_decision_policy_hash"], digest(92))
        self.assertEqual(
            self.plan["policy"]["reputation_history_import"],
            policy_fixture()["reputation_history_import"],
        )
        self.assertEqual(self.plan["addresses"]["registry"], chain.derive_contract_address(signer(20), 0))
        self.assertEqual(self.plan["addresses"]["settlement"], chain.derive_contract_address(signer(20), 1))
        self.assertEqual([self.plan["transactions"][s]["nonce"] for s in deploy.STEPS], [0, 1, 2])
        self.assertEqual(self.plan["transactions"]["bind"]["to"], self.plan["addresses"]["registry"])
        self.assertEqual(self.plan["transactions"]["bind"]["data"], deploy.bind_calldata(self.plan["addresses"]["settlement"]))
        self.assertEqual(len(deploy.registry_constructor_data(policy_fixture())), 7 * 32)
        self.assertEqual(len(deploy.settlement_constructor_data(policy_fixture(), self.plan["addresses"]["registry"])), 27 * 32)
        self.assertEqual(self.client.broadcasts, [])

    def test_dynamic_operating_policy_is_exact_canonical_and_plan_hashed(self):
        history_mutations = (
            lambda value: value.update(unexpected=True),
            lambda value: value.update(source_network_id=policy_fixture()["network_id"]),
            lambda value: value.update(source_protocol_version=8),
            lambda value: value.update(source_chain_id=1),
            lambda value: value.update(source_genesis_hash=digest(99)),
            lambda value: value.update(source_settlement_contract=chain.ZERO_ADDRESS),
            lambda value: value.update(source_runtime_code_hash=chain.ZERO_BYTES32),
            lambda value: value.update(source_deployment_block=0),
            lambda value: value.update(source_deployment_block_hash=chain.ZERO_BYTES32),
            lambda value: value.update(source_history_through_block=9),
            lambda value: value.update(source_history_through_block_hash=chain.ZERO_BYTES32),
            lambda value: value.update(confirmations=1),
            lambda value: value.update(confirmations=257),
            lambda value: value.update(artifact_sha256="D" * 64),
            lambda value: value.update(artifact_root=chain.ZERO_BYTES32),
        )
        for mutate in history_mutations:
            with self.subTest(mutate=mutate):
                policy = policy_fixture()
                mutate(policy["reputation_history_import"])
                with self.assertRaises(chain.ChainError):
                    deploy.validate_policy(policy)

        for field in ("network_id", "jury_decision_policy_hash", "reputation_history_import"):
            with self.subTest(missing=field):
                policy = policy_fixture()
                policy.pop(field)
                with self.assertRaises(chain.ChainError):
                    deploy.validate_policy(policy)
        for network_id in (
            "mycomesh-v10", "MycoMesh-v10-controlled-test",
            "mycomesh--v10-controlled-test", "-mycomesh-controlled-test",
        ):
            with self.subTest(network_id=network_id):
                policy = policy_fixture()
                policy["network_id"] = network_id
                with self.assertRaisesRegex(chain.ChainError, "network_id"):
                    deploy.validate_policy(policy)
        for decision_hash in (chain.ZERO_BYTES32, digest(92).upper()):
            with self.subTest(decision_hash=decision_hash):
                policy = policy_fixture()
                policy["jury_decision_policy_hash"] = decision_hash
                with self.assertRaisesRegex(chain.ChainError, "jury decision policy hash"):
                    deploy.validate_policy(policy)

        changed = policy_fixture()
        changed["reputation_history_import"]["artifact_root"] = digest(97)
        changed_plan = self.client.plan(changed, artifacts_fixture())
        self.assertNotEqual(changed_plan["policy_hash"], self.plan["policy_hash"])
        self.assertNotEqual(changed_plan["plan_hash"], self.plan["plan_hash"])

    def test_history_source_cannot_alias_predicted_new_settlement(self):
        predicted_settlement = self.plan["addresses"]["settlement"]
        policy = policy_fixture()
        policy["reputation_history_import"][
            "source_settlement_contract"
        ] = predicted_settlement
        with self.assertRaisesRegex(chain.ChainError, "predicted new Settlement"):
            self.client.plan(policy, artifacts_fixture())

        changed = copy.deepcopy(self.plan)
        changed["policy"]["reputation_history_import"][
            "source_settlement_contract"
        ] = predicted_settlement
        changed["policy_hash"] = deploy._hash(deploy.validate_policy(changed["policy"]))
        unsigned = {key: value for key, value in changed.items() if key != "plan_hash"}
        changed["plan_hash"] = deploy._hash(unsigned)
        with self.assertRaisesRegex(chain.ChainError, "predicted new Settlement"):
            deploy.validate_plan(changed)

    def test_policy_and_artifact_mismatches_fail_closed(self):
        mutations = (
            lambda p: p["registry"].update(bond_penalty_recipient=address(30)),
            lambda p: p["registry"].update(threshold=1),
            lambda p: p["registry"].update(jury_size=8, threshold=5),
            lambda p: p.update(governance=address(31)),
            lambda p: (
                p["registry"].update(bond_penalty_recipient=p["governance"]),
                p["dispute_policy"].update(bond_penalty_recipient=p["governance"]),
            ),
            lambda p: (
                p["registry"].update(
                    reputation_authority=p["registry"]["bond_penalty_recipient"]
                ),
            ),
            lambda p: p["fee_policy"].update(max_total_gas_cost_wei=1),
            lambda p: p["dispute_policy"].update(token_reward=1),
            lambda p: p.update(deployment_class="production"),
            lambda p: p.update(network_id="not-controlled"),
            lambda p: p.update(jury_decision_policy_hash=chain.ZERO_BYTES32),
            lambda p: p.update(source_commit="C" * 40),
            lambda p: p.update(extra=True),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                policy = policy_fixture()
                mutate(policy)
                with self.assertRaises(chain.ChainError):
                    deploy.validate_policy(policy)
        artifacts = artifacts_fixture()
        artifacts["registry"]["creation_bytecode"] = "0x6003"
        with self.assertRaisesRegex(chain.ChainError, "modified registry"):
            deploy.validate_artifacts(artifacts)

        policy = policy_fixture()
        policy["artifact_pins"]["registry"]["source_sha256"] = "d" * 64
        with self.assertRaisesRegex(chain.ChainError, "independently approved policy pin"):
            self.client.plan(policy, artifacts_fixture())

    def test_json_inputs_reject_duplicate_fields_nonfinite_values_and_invalid_utf8(self):
        path = self.root / "input.json"
        for raw, message in (
            (b'{"chain_id":1,"chain_id":2}', "repeats field 'chain_id'"),
            (b'{"chain_id":NaN}', "non-finite value 'NaN'"),
            (b'{"chain_id":"\xff"}', "must be UTF-8"),
            (b'{"chain_id":', "must be strict JSON"),
        ):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaisesRegex(chain.ChainError, message):
                    deploy._read_json(str(path))

    def test_compiler_artifact_rejects_ambiguous_or_nonobject_json(self):
        path = self.root / "artifact.json"
        for raw, message in (
            (b'{"metadata":{},"metadata":{}}', "repeats field 'metadata'"),
            (b'{"metadata":NaN}', "non-finite value 'NaN'"),
            (b'[]', "must be a JSON object"),
        ):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaisesRegex(chain.ChainError, message):
                    deploy.load_artifact(path, "ProviderJuryRegistryV1")

    @unittest.skipIf(os.name == "nt", "hard links use different Windows semantics")
    def test_deployment_outbox_rejects_hard_links(self):
        original = self.root / "linked.sqlite"
        original.touch(mode=0o600)
        alias = self.root / "linked-alias.sqlite"
        os.link(original, alias)
        with self.assertRaisesRegex(chain.ChainError, "unlinked regular file"):
            deploy.V10DeploymentOutbox(alias)

    def test_rpc_quantities_must_use_canonical_json_rpc_encoding(self):
        self.assertEqual(deploy._rpc_quantity("0x0", "quantity"), 0)
        self.assertEqual(deploy._rpc_quantity("0x1", "quantity"), 1)
        for value in ("0x00", "0x01", "0X1", "0xA", "1", "-0x1", 1, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(chain.ChainError, "invalid|noncanonical"):
                    deploy._rpc_quantity(value, "quantity")

    def test_three_rpc_quorum_requires_two_matching_results_and_safe_quantities(self):
        urls = ["https://rpc-a.example", "https://rpc-b.example", "https://rpc-c.example"]
        client = deploy.V10DeploymentClient(urls)
        responses = {
            "eth_chainId": {urls[0]: "0xaa", urls[1]: "0xaa", urls[2]: "0xbb"},
            "eth_gasPrice": {urls[0]: "0x5", urls[1]: "0x7", urls[2]: "0x6"},
            "eth_estimateGas": {urls[0]: "0x64", urls[1]: "0x66", urls[2]: "0x65"},
            "eth_getBalance": {urls[0]: "0x9", urls[1]: "0x7", urls[2]: "0x8"},
            "eth_blockNumber": {urls[0]: "0x64", urls[1]: "0x66", urls[2]: "0x65"},
            "eth_sendRawTransaction": {
                urls[0]: digest(10), urls[1]: digest(10), urls[2]: digest(11),
            },
        }

        def rpc(endpoint, method, params, timeout):
            return responses[method][endpoint]

        with mock.patch.object(deploy.chain, "rpc_call", side_effect=rpc) as call:
            self.assertEqual(client.rpc("eth_chainId", []), "0xaa")
            self.assertEqual(client.rpc("eth_gasPrice", []), "0x7")
            self.assertEqual(client.rpc("eth_estimateGas", []), "0x66")
            self.assertEqual(client.rpc("eth_getBalance", []), "0x7")
            self.assertEqual(client.rpc("eth_blockNumber", []), "0x65")
            self.assertEqual(client.rpc("eth_sendRawTransaction", ["0x01"]), digest(10))
        self.assertEqual(call.call_count, 18)

        responses["eth_chainId"] = {
            urls[0]: "0xaa", urls[1]: "0xbb", urls[2]: "0xcc",
        }
        with mock.patch.object(deploy.chain, "rpc_call", side_effect=rpc):
            with self.assertRaisesRegex(chain.ChainError, "disagree"):
                client.rpc("eth_chainId", [])

    def test_live_rpc_urls_require_credential_free_https_and_distinct_hosts(self):
        valid = [
            "https://rpc-a.example/v1", "https://rpc-b.example/v1",
            "https://rpc-c.example/v1",
        ]
        deploy.V10DeploymentClient(valid).require_quorum()
        invalid = (
            ["http://rpc-a.example", valid[1], valid[2]],
            ["https://user:secret@rpc-a.example", valid[1], valid[2]],
            ["https://rpc-a.example?token=secret", valid[1], valid[2]],
            ["https://rpc-a.example?", valid[1], valid[2]],
            ["https://rpc-a.example#fragment", valid[1], valid[2]],
            [" https://rpc-a.example", valid[1], valid[2]],
            ["https://localhost", valid[1], valid[2]],
            [
                "https://rpc-a.example/one", "https://RPC-A.example:443/two",
                "https://rpc-a.example./three",
            ],
        )
        for urls in invalid:
            with self.subTest(urls=urls):
                with self.assertRaises(chain.ChainError):
                    deploy.V10DeploymentClient(urls)

    def test_single_rpc_is_explicit_loopback_only_test_mode(self):
        with self.assertRaisesRegex(chain.ChainError, "single RPC is test-only"):
            deploy.V10DeploymentClient("https://rpc.example")
        for endpoint in (
            "http://127.0.0.1:8545", "http://localhost:8545",
            "https://[::1]:8545",
        ):
            with self.subTest(endpoint=endpoint):
                deploy.V10DeploymentClient(
                    endpoint, allow_single_test_rpc=True,
                ).require_quorum()
        for endpoint in (
            "http://rpc.example", "https://rpc.example",
            "http://user:secret@localhost:8545", "http://localhost:8545?token=x",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(chain.ChainError):
                    deploy.V10DeploymentClient(
                        endpoint, allow_single_test_rpc=True,
                    )

    def test_controlled_test_send_requires_acknowledgement_and_pinned_sepolia(self):
        policy = policy_fixture()
        policy["chain_id"] = deploy.SEPOLIA_CHAIN_ID
        policy["genesis_hash"] = deploy.SEPOLIA_GENESIS_HASH
        policy["reputation_history_import"]["source_chain_id"] = deploy.SEPOLIA_CHAIN_ID
        policy["reputation_history_import"][
            "source_genesis_hash"
        ] = deploy.SEPOLIA_GENESIS_HASH
        with self.assertRaisesRegex(chain.ChainError, "explicit --allow-controlled-test"):
            deploy._require_controlled_sepolia_send(
                policy, allow_controlled_test=False,
            )
        deploy._require_controlled_sepolia_send(policy, allow_controlled_test=True)
        policy["genesis_hash"] = digest(123)
        policy["reputation_history_import"]["source_genesis_hash"] = digest(123)
        with self.assertRaisesRegex(chain.ChainError, "pinned Sepolia"):
            deploy._require_controlled_sepolia_send(
                policy, allow_controlled_test=True,
            )

    def test_sender_lock_prevents_same_identity_across_outboxes(self):
        with deploy._deployment_sender_lock(
            self.key_file, self.plan["policy"]["deployer"],
        ):
            with self.assertRaisesRegex(chain.ChainError, "another V10 deployment process"):
                self.execute()
        self.assertEqual(self.client.broadcasts, [])

    def test_sender_lock_rejects_symlink_ancestor_and_key_hard_link(self):
        if os.getuid() != 0:
            real_parent = self.root / "real-key-parent"
            real_parent.mkdir(mode=0o700)
            aliased_key = real_parent / "key"
            aliased_key.write_text(key(20))
            aliased_key.chmod(0o600)
            alias_parent = self.root / "key-parent-alias"
            alias_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(chain.ChainError, "user-controlled symbolic link"):
                with deploy._deployment_sender_lock(
                    alias_parent / "key", self.plan["policy"]["deployer"],
                ):
                    self.fail("user-owned symlink ancestor must not acquire a lock")

        hard_link = self.root / "key-hard-link"
        os.link(self.key_file, hard_link)
        with self.assertRaisesRegex(chain.ChainError, "exactly one link"):
            with deploy._deployment_sender_lock(
                self.key_file, self.plan["policy"]["deployer"],
            ):
                self.fail("multiply linked key must not acquire a lock")

    def test_sender_lock_binds_open_key_inode_against_path_swap(self):
        displaced = self.root / "displaced.key"
        real_open = deploy.os.open
        canonical_key = Path(os.path.realpath(self.key_file))
        swapped = False

        def open_then_swap(path, flags, mode=0o777):
            nonlocal swapped
            descriptor = real_open(path, flags, mode)
            if not swapped and Path(path) == canonical_key:
                swapped = True
                self.key_file.rename(displaced)
                self.key_file.write_text(key(20))
                self.key_file.chmod(0o600)
            return descriptor

        with mock.patch.object(deploy.os, "open", side_effect=open_then_swap):
            with self.assertRaisesRegex(chain.ChainError, "changed after its protected open"):
                with deploy._deployment_sender_lock(
                    self.key_file, self.plan["policy"]["deployer"],
                ):
                    self.fail("swapped key path must not acquire a lock")

    def test_outbox_rejects_unsafe_parent_and_user_owned_symlink(self):
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        try:
            with self.assertRaisesRegex(chain.ChainError, "parent must be owned"):
                deploy.V10DeploymentOutbox(unsafe / "outbox.sqlite")
        finally:
            unsafe.chmod(0o700)

        if os.getuid() != 0:
            target = self.root / "safe-target"
            target.mkdir(mode=0o700)
            alias = self.root / "symlink-parent"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(chain.ChainError, "symbolic link"):
                deploy.V10DeploymentOutbox(alias / "outbox.sqlite")

    def test_outbox_detects_main_file_path_swap_during_sqlite_open(self):
        path = self.root / "swapped.sqlite"
        displaced = self.root / "displaced.sqlite"
        real_connect = deploy.sqlite3.connect

        def swap_then_connect(database, *args, **kwargs):
            Path(database).rename(displaced)
            Path(database).touch(mode=0o600)
            Path(database).chmod(0o600)
            return real_connect(database, *args, **kwargs)

        with mock.patch.object(
            deploy.sqlite3, "connect", side_effect=swap_then_connect,
        ):
            with self.assertRaisesRegex(chain.ChainError, "changed after its protected open"):
                deploy.V10DeploymentOutbox(path)

    def test_predicted_contract_addresses_cannot_capture_operational_roles(self):
        registry = chain.derive_contract_address(signer(20), 0)
        settlement = chain.derive_contract_address(signer(20), 1)
        mutations = (
            lambda p: p["registry"].update(reputation_authority=registry),
            lambda p: p.update(treasury=registry),
            lambda p: (
                p["registry"].update(bond_penalty_recipient=settlement),
                p["dispute_policy"].update(bond_penalty_recipient=settlement),
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                policy = policy_fixture()
                mutate(policy)
                with self.assertRaisesRegex(chain.ChainError, "predicted V10 contract address"):
                    self.client.plan(policy, artifacts_fixture())

    def test_jury_size_matches_registry_contract_boundary(self):
        policy = policy_fixture()
        policy["registry"].update(jury_size=7, threshold=4)
        self.assertEqual(deploy.validate_policy(policy)["registry"]["jury_size"], 7)
        policy["registry"].update(jury_size=8, threshold=5)
        with self.assertRaisesRegex(chain.ChainError, "jury threshold"):
            deploy.validate_policy(policy)

    def test_arbitration_timeout_covers_controlled_sepolia_jury_liveness_budget(self):
        policy = policy_fixture()
        minimum = deploy.controlled_sepolia_min_arbitration_timeout_seconds(
            selection_delay_blocks=policy["registry"]["selection_delay_blocks"],
            confirmations=policy["confirmations"],
        )
        self.assertEqual(minimum, 585)
        policy["dispute_policy"]["arbitration_timeout"] = minimum
        self.assertEqual(
            deploy.validate_policy(policy)["dispute_policy"]["arbitration_timeout"],
            minimum,
        )
        policy["dispute_policy"]["arbitration_timeout"] = minimum - 1
        with self.assertRaisesRegex(chain.ChainError, "controlled-Sepolia jury liveness budget"):
            deploy.validate_policy(policy)

    def test_self_rehashed_plan_cannot_change_derived_transaction(self):
        changed = copy.deepcopy(self.plan)
        changed["transactions"]["bind"]["data"] = deploy.bind_calldata(address(99))
        changed["plan_hash"] = deploy._hash({key: value for key, value in changed.items() if key != "plan_hash"})
        with self.assertRaisesRegex(chain.ChainError, "transactions differ"):
            deploy.validate_plan(changed)

    def test_pending_nonce_stale_head_and_fee_cap_prevent_plan(self):
        for attribute, value in (("pending_nonce", 1), ("timestamp", int(time.time()) - 301), ("price", 11)):
            with self.subTest(attribute=attribute):
                client = FakeRPC()
                setattr(client, attribute, value)
                with self.assertRaises(chain.ChainError):
                    client.plan(policy_fixture(), artifacts_fixture())

    def test_default_execute_is_read_only(self):
        self.client.calls.clear()
        result = self.outbox.execute_next(self.client, self.plan)
        self.assertFalse(result["sent"])
        self.assertEqual(self.client.calls, [])
        self.assertEqual(self.client.broadcasts, [])

    def test_modified_plan_and_wrong_approval_are_rejected(self):
        changed = copy.deepcopy(self.plan)
        changed["transactions"]["bind"]["nonce"] += 1
        with self.assertRaisesRegex(chain.ChainError, "modified"):
            self.outbox.execute_next(self.client, changed)
        self.send["approved_plan_hash"] = digest(1)
        with self.assertRaisesRegex(chain.ChainError, "exact approved"):
            self.execute()

    def test_each_next_nonce_waits_for_verified_confirmation(self):
        first = self.execute()
        self.assertEqual(first["next_step"], "registry")
        self.assertEqual(len(self.client.broadcasts), 1)
        # Unknown receipt neither signs nor sends the settlement transaction.
        self.assertEqual(self.execute()["next_step"], "registry")
        self.assertEqual(len(self.client.broadcasts), 1)
        self.mine_latest()
        second = self.execute()
        self.assertEqual(second["next_step"], "settlement")
        self.assertEqual(len(self.client.broadcasts), 2)
        self.mine_latest()
        third = self.execute()
        self.assertEqual(third["next_step"], "bind")
        self.assertEqual(len(self.client.broadcasts), 3)
        self.mine_latest()
        final = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertTrue(final["complete"])
        self.assertEqual(final["state"], "confirmed")
        self.assertEqual(final["deployment_block"], 102)
        self.assertEqual(final["deployment_block_hash"], digest(102))
        self.assertEqual(
            final["settlement_runtime_code_keccak256"],
            final["steps"]["settlement"]["verification"]["runtime_code_hash"],
        )
        self.assertTrue(self.client.binding)

    def test_incomplete_other_plan_reserves_its_future_contract_addresses(self):
        self.execute()
        self.mine_latest()
        self.assertEqual(
            self.outbox.reconcile(self.client, self.plan["plan_hash"])["steps"]["registry"]["state"],
            "confirmed",
        )
        replacement_policy = policy_fixture()
        replacement_policy["initial_channel"] = digest(92)
        replacement = self.client.plan(replacement_policy, artifacts_fixture())
        self.client.plan_value = replacement
        replacement_send = {
            **self.send,
            "approved_plan_hash": replacement["plan_hash"],
        }
        with self.assertRaisesRegex(chain.ChainError, "incomplete V10 deployment"):
            self.outbox.execute_next(
                self.client, replacement, **replacement_send,
            )
        self.assertEqual(len(self.client.broadcasts), 1)

    def test_preflight_requires_canonical_estimate_and_safety_margin(self):
        policy = policy_fixture()
        policy["fee_policy"]["gas_limits"]["registry"] = 3_849_999
        policy["fee_policy"]["max_total_gas_cost_wei"] = 120_499_990
        plan = self.client.plan(policy, artifacts_fixture())
        self.client.plan_value = plan
        with self.assertRaisesRegex(chain.ChainError, "gas limit does not cover"):
            self.outbox.execute_next(
                self.client, plan, allow_send=True,
                approved_plan_hash=plan["plan_hash"], key_file=self.key_file,
                max_gas_price_wei=10,
                max_total_gas_cost_wei=120_499_990,
            )
        self.assertEqual(self.client.broadcasts, [])

        self.client.rpc = lambda method, params: (
            "0x030d40" if method == "eth_estimateGas"
            else FakeRPC.rpc(self.client, method, params)
        )
        self.client.plan_value = self.plan
        with self.assertRaisesRegex(chain.ChainError, "noncanonical V10 gas estimate"):
            self.execute()
        self.assertEqual(self.client.broadcasts, [])

    def test_unknown_send_survives_restart_and_rebroadcasts_exact_bytes(self):
        self.client.unknown_broadcast = True
        uncertain = self.execute()
        raw = self.client.broadcasts[0]
        self.assertEqual(uncertain["state"], "uncertain")
        self.outbox.close()
        self.outbox = deploy.V10DeploymentOutbox(self.root / "outbox.sqlite")
        self.client.unknown_broadcast = False
        result = self.outbox.rebroadcast(
            self.client, self.plan["plan_hash"], "registry",
            allow_send=True, key_file=self.key_file,
        )
        self.assertEqual(result["steps"]["registry"]["state"], "submitted")
        self.assertEqual(self.client.broadcasts, [raw, raw])

    def test_stored_raw_transaction_is_bound_to_every_approved_field_and_sender(self):
        raw, tx_hash = self.signed_raw()
        deploy._verify_stored_raw_transaction(self.plan, "registry", raw, tx_hash)
        mutations = (
            ("chain id", {"chain_id": self.plan["policy"]["chain_id"] + 1}),
            ("sender", {"key_number": 21}),
            ("nonce", {"nonce": 1}),
            ("gas price", {"gas_price_wei": 11}),
            ("gas limit", {"gas_units": 4_999_999}),
            ("destination", {"to": address(99)}),
            ("value", {"value": 1}),
            ("data", {"data": b"\x60\x03"}),
        )
        for label, mutation in mutations:
            with self.subTest(field=label):
                key_number = mutation.get("key_number", 20)
                overrides = {
                    name: value for name, value in mutation.items()
                    if name != "key_number"
                }
                changed_raw, changed_hash = self.signed_raw(
                    key_number=key_number, **overrides,
                )
                with self.assertRaisesRegex(
                    chain.ChainError, "differs from its approved plan",
                ):
                    deploy._verify_stored_raw_transaction(
                        self.plan, "registry", changed_raw, changed_hash,
                    )

    def test_paired_raw_and_hash_outbox_tampering_cannot_rebroadcast(self):
        self.execute()
        changed_raw, changed_hash = self.signed_raw(data=b"\x60\x03")
        self.outbox.db.execute(
            "UPDATE v10_deployment_steps SET raw_tx=?,tx_hash=? "
            "WHERE plan_hash=? AND step='registry'",
            (changed_raw, changed_hash, self.plan["plan_hash"]),
        )
        with self.assertRaisesRegex(
            chain.ChainError, "differs from its approved plan",
        ):
            self.outbox.rebroadcast(
                self.client, self.plan["plan_hash"], "registry",
                allow_send=True, key_file=self.key_file,
            )
        self.assertEqual(len(self.client.broadcasts), 1)

    def test_rebroadcast_rejects_later_step_after_prior_confirmation_reorg(self):
        self.execute()
        self.mine_latest()
        self.execute()
        self.assertEqual(len(self.client.broadcasts), 2)
        self.client.reorg_blocks.add(100)
        with self.assertRaisesRegex(
            chain.ChainError, "every prior stage to remain confirmed",
        ):
            self.outbox.rebroadcast(
                self.client, self.plan["plan_hash"], "settlement",
                allow_send=True, key_file=self.key_file,
            )
        self.assertEqual(len(self.client.broadcasts), 2)

    def test_revert_is_terminal_and_never_advances_nonce(self):
        self.execute()
        self.mine_latest(status=0)
        result = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(result["state"], "reverted")
        with self.assertRaisesRegex(chain.ChainError, "reverted"):
            self.execute()
        self.assertEqual(len(self.client.broadcasts), 1)

    def test_reorg_or_getter_mismatch_clears_prior_confirmation(self):
        self.execute()
        self.mine_latest()
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["steps"]["registry"]["state"], "confirmed")
        self.client.reorg_blocks.add(100)
        result = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(result["steps"]["registry"]["state"], "uncertain")
        self.client.reorg_blocks.clear()
        self.client.bad_getter = "threshold()"
        with self.assertRaisesRegex(chain.ChainError, "threshold"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(self.outbox.status(self.plan["plan_hash"])["steps"]["registry"]["state"], "uncertain")

    def test_receipt_confirmation_rechecks_pinned_stablecoin_runtime(self):
        self.execute()
        self.mine_latest()
        self.client.stablecoin_code = "0x6001"
        with self.assertRaisesRegex(chain.ChainError, "stablecoin runtime"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(
            self.outbox.status(self.plan["plan_hash"])["steps"]["registry"]["state"],
            "uncertain",
        )


if __name__ == "__main__":
    unittest.main()
