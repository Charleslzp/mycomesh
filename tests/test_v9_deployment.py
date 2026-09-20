"""Deployment safety checks use synthetic keys and RPC, never an external chain."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from gateway import chain, chain_v9
from gateway import v9_deployment as deploy
from tests.test_chain_v9 import address, digest, key, signer, deployment_manifest


def policy_fixture():
    manifest = deployment_manifest()
    result = {key: manifest[key] for key in deploy.MANIFEST_INPUTS}
    result.update(deployer=signer(20), reward_token=chain.ZERO_ADDRESS, genesis_hash=digest(40), confirmations=2,
                  initial_config=dict(zip(deploy.CONFIG_FIELDS, [1000, 4000, 2000, 8500, 300, 200, 1000, True])))
    for name in ("token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty"):
        result["policy"][name] = 0
    return result


def artifact_fixture():
    return {"creation_bytecode": "0x60016000", "runtime_template": "0x" + "00" * 40,
            "immutable_references": {"fixture": [{"start": 1, "length": 32}]}, "sha256": "a" * 64}


class FakeRPC(deploy.V9DeploymentClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:1")
        self.calls = []
        self.nonce = 0
        self.pending_nonce = None
        self.price = 10
        self.policy = policy_fixture()
        self.timestamp = int(time.time())
        self.code = "0x" + "00" + "12" * 32 + "00" * 7
        self.chain_id = 31337
        self.genesis = digest(40)
        self.receipt = None
        self.unknown_broadcast = False
        self.broadcasts = []
        self.outbox = None
        self.plan_value = None
        self.bad_getter = None
        self.head = 101

    def rpc(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            if params[0] == "0x0":
                return {"hash": self.genesis}
            return {"number": hex(100), "hash": digest(100), "timestamp": hex(self.timestamp)}
        if method == "eth_getTransactionCount":
            return hex(self.pending_nonce if params[1] == "pending" and self.pending_nonce is not None else self.nonce)
        if method == "eth_getCode":
            if params[0] == self.policy["stablecoin"]:
                return "0x6000"
            return self.code if self.receipt else "0x"
        if method == "eth_estimateGas":
            return hex(100000)
        if method == "eth_gasPrice":
            return hex(self.price)
        if method == "eth_getBalance":
            return hex(10**20)
        if method == "eth_sendRawTransaction":
            self.broadcasts.append(params[0])
            # Persistence must precede even the first, possibly uncertain send.
            if self.outbox:
                assert self.outbox._row(self.plan_value["plan_hash"])["raw_tx"] == params[0]
            if self.unknown_broadcast:
                raise TimeoutError("accepted transaction, response lost")
            return "0x" + chain.keccak256(bytes.fromhex(params[0][2:])).hex()
        if method == "eth_getTransactionReceipt":
            return self.receipt
        if method == "eth_call":
            p, m = self.plan_value["policy"], self.plan_value["manifest_candidate"]
            calls = {
                "MAX_AUTHORIZATION_TTL()": [m.get("max_authorization_ttl_seconds", 3600)],
                "stablecoin()": [m["stablecoin"]], "rewardToken()": [m["reward_token"]],
                "governance()": [m["governance"]], "treasury()": [m["treasury"]],
                "adjudicationThreshold()": [m["adjudication_threshold"]],
                "policy()": [m["policy"][k] for k in chain_v9.POLICY_FIELDS],
                "adjudicators()": [32, len(m["adjudicators"]), *m["adjudicators"]],
                "DOMAIN_SEPARATOR()": [chain_v9.domain_separator(chain_id=m["chain_id"], verifying_contract=m["settlement"])],
                "latestChannelVersion(bytes32)": [1], "channelPricingHash(bytes32,uint64)": [m["pricing_hash"]],
            }
            for signature, values in calls.items():
                if params[0]["data"].startswith("0x" + chain.keccak256(signature.encode())[:4].hex()):
                    return "0x" + deploy._words([0] if self.bad_getter == signature else values).hex()
        raise AssertionError((method, params))


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.keyfile = self.root / "synthetic-only.key"
        self.keyfile.write_text(key(20))
        self.keyfile.chmod(0o600)
        self.client = FakeRPC()
        self.plan = self.client.plan(policy_fixture(), artifact_fixture())
        self.client.plan_value = self.plan
        self.outbox = deploy.V9DeploymentOutbox(self.root / "outbox.sqlite")
        self.addCleanup(lambda: self.outbox.close())
        self.client.outbox = self.outbox
        self.send_args = dict(allow_send=True, approved_plan_hash=self.plan["plan_hash"], key_file=self.keyfile,
                              max_gas_price_wei=10, max_gas_units=130000, max_total_gas_cost_wei=1300000)

    def execute(self):
        return self.outbox.execute(self.client, self.plan, **self.send_args)

    def mine(self, status=1):
        result = self.execute()
        self.client.receipt = {"transactionHash": result["tx_hash"], "blockHash": digest(100),
                               "blockNumber": hex(100), "status": hex(status),
                               "contractAddress": self.plan["manifest_candidate"]["settlement"]}
        return result

    def test_plan_is_read_only_and_constructor_array_offset_is_correct(self):
        self.assertFalse(self.client.broadcasts)
        self.assertEqual(self.plan["estimate"]["total_gas_cost_wei"], 1300000)
        data = deploy.constructor_data(policy_fixture())
        self.assertEqual(len(data), 32 * 32)
        self.assertEqual(int.from_bytes(data[26 * 32:27 * 32], "big"), 28 * 32)
        self.assertEqual(int.from_bytes(data[28 * 32:29 * 32], "big"), 3)
        self.assertEqual(self.plan["manifest_candidate"]["settlement"], chain.derive_contract_address(signer(20), 0))
        chain_v9.validate_deployment(self.plan["manifest_candidate"])

    def test_explicit_policy_and_disabled_rewards(self):
        for mutate in (lambda p: p.pop("adjudicator_operators"),
                       lambda p: p.update(independence_attested=False),
                       lambda p: p["policy"].update(token_reward=1),
                       lambda p: p["initial_config"].update(provider_bps=0),
                       lambda p: p.update(unknown=1)):
            with self.subTest(mutate=mutate):
                policy = policy_fixture()
                mutate(policy)
                with self.assertRaises(chain.ChainError):
                    deploy.validate_policy(policy)

    def test_chain_genesis_staleness_and_pending_nonce_fail_closed(self):
        for attr, value in (("chain_id", 1), ("genesis", digest(999)),
                            ("timestamp", int(time.time()) - 301), ("pending_nonce", 2)):
            with self.subTest(attr=attr):
                client = FakeRPC()
                setattr(client, attr, value)
                with self.assertRaises(chain.ChainError):
                    client.plan(policy_fixture(), artifact_fixture())

    def test_rpc_fallback_lists_are_forbidden(self):
        with self.assertRaisesRegex(chain.ChainError, "one explicit"):
            deploy.V9DeploymentClient("https://one.invalid,https://two.invalid")

    def test_default_execute_does_not_read_key_or_send(self):
        self.client.calls.clear()
        self.assertEqual(self.outbox.execute(self.client, self.plan)["sent"], False)
        self.assertEqual(self.client.calls, [])
        self.assertIsNone(self.outbox.get(self.plan["plan_hash"]))

    def test_modified_plan_or_wrong_approval_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan["transaction"]["nonce"] += 1
        with self.assertRaisesRegex(chain.ChainError, "modified"):
            self.outbox.execute(self.client, plan)
        self.send_args["approved_plan_hash"] = digest(1)
        with self.assertRaisesRegex(chain.ChainError, "exact approved"):
            self.execute()

    def test_caps_and_key_protection_prevent_send(self):
        self.client.price = 11
        with self.assertRaisesRegex(chain.ChainError, "caps"):
            self.execute()
        self.client.price = 10
        self.keyfile.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0400/0600"):
            self.execute()
        self.keyfile.chmod(0o600)
        self.keyfile.write_text(key(21))
        with self.assertRaisesRegex(chain.ChainError, "key does not match"):
            self.execute()
        self.assertEqual(self.client.broadcasts, [])
        self.assertIsNone(self.outbox.get(self.plan["plan_hash"]))

    def test_nonce_change_requires_new_plan(self):
        self.client.nonce = 1
        with self.assertRaisesRegex(chain.ChainError, "changed"):
            self.execute()

    def test_unknown_send_is_durable_and_restart_reuses_exact_bytes(self):
        self.client.unknown_broadcast = True
        result = self.execute()
        self.assertEqual(result["state"], "uncertain")
        self.outbox.close()
        self.outbox = deploy.V9DeploymentOutbox(self.root / "outbox.sqlite")
        self.client.outbox = self.outbox
        self.client.calls.clear()
        self.assertEqual(self.execute()["tx_hash"], result["tx_hash"])
        self.assertEqual(self.client.calls, [])
        self.client.nonce = 99  # No nonce lookup or signing during rebroadcast.
        self.client.unknown_broadcast = False
        retried = self.outbox.rebroadcast(self.client, self.plan["plan_hash"], allow_send=True)
        self.assertEqual(retried["tx_hash"], result["tx_hash"])
        self.assertEqual(self.client.broadcasts[0], self.client.broadcasts[1])
        self.assertFalse(any(m == "eth_getTransactionCount" for m, _ in self.client.calls))

    def test_unresolved_outbox_blocks_other_deployment(self):
        self.execute()
        self.client.nonce = 1
        other = self.client.plan(policy_fixture(), artifact_fixture())
        with self.assertRaisesRegex(chain.ChainError, "unresolved"):
            self.outbox.execute(self.client, other, **{**self.send_args, "approved_plan_hash": other["plan_hash"]})

    def test_confirmed_deployment_outputs_valid_manifest_and_runtime_hash(self):
        result = self.mine()
        confirmed = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(confirmed["state"], "confirmed")
        manifest = confirmed["verification"]["manifest"]
        self.assertEqual(chain_v9.validate_deployment(manifest).tx_hash, result["tx_hash"])
        self.assertEqual(manifest["deployment_block"], 100)
        self.assertEqual(confirmed["verification"]["runtime_code_hash"], "0x" + chain.keccak256(bytes.fromhex(self.client.code[2:])).hex())
        self.outbox.rebroadcast(self.client, self.plan["plan_hash"], allow_send=True)
        self.assertEqual(len(self.client.broadcasts), 1)

    def test_confirmations_and_revert_do_not_produce_manifest(self):
        self.mine()
        self.client.head = 100
        result = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(result["state"], "submitted")
        self.assertNotIn("verification", result)
        self.client.head = 101
        self.client.receipt["status"] = "0x0"
        result = self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(result["state"], "reverted")
        self.assertNotIn("verification", result)

    def test_wrong_runtime_or_policy_rejected(self):
        self.mine()
        self.client.code = "0xff" + self.client.code[4:]
        with self.assertRaisesRegex(chain.ChainError, "runtime differs"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.client.code = "0x00" + self.client.code[4:]
        self.client.bad_getter = "policy()"
        with self.assertRaisesRegex(chain.ChainError, "policy.*differs"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertNotEqual(self.outbox.get(self.plan["plan_hash"])["state"], "confirmed")

    def test_wrong_authorization_ttl_never_produces_a_verified_manifest(self):
        self.mine()
        self.client.bad_getter = "MAX_AUTHORIZATION_TTL()"
        with self.assertRaisesRegex(chain.ChainError, "MAX_AUTHORIZATION_TTL.*differs"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertNotEqual(self.outbox.get(self.plan["plan_hash"])["state"], "confirmed")

    def test_failed_recheck_clears_prior_confirmation_and_manifest(self):
        self.mine()
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["state"], "confirmed")
        self.client.chain_id = 1
        with self.assertRaisesRegex(chain.ChainError, "genesis differs"):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        result = self.outbox.get(self.plan["plan_hash"])
        self.assertEqual(result["state"], "uncertain")
        self.assertNotIn("verification", result)
        self.client.chain_id = 31337
        self.assertEqual(self.outbox.reconcile(self.client, self.plan["plan_hash"])["state"], "confirmed")
        self.client.bad_getter = "policy()"
        with self.assertRaises(chain.ChainError):
            self.outbox.reconcile(self.client, self.plan["plan_hash"])
        self.assertEqual(self.outbox.get(self.plan["plan_hash"])["state"], "uncertain")

    def test_runtime_mask_rejects_overlapping_or_out_of_bounds_ranges(self):
        artifact = artifact_fixture()
        for entries in ([{"start": 10, "length": 32}], [{"start": 0, "length": 32}, {"start": 1, "length": 32}]):
            artifact["immutable_references"] = {"bad": entries}
            with self.assertRaises(chain.ChainError):
                deploy._masked_runtime(artifact["runtime_template"], artifact)


@unittest.skipUnless(os.environ.get("RUN_MYCO_V9_LOCAL_CHAIN") == "1", "opt-in localhost deployment integration")
class LocalChainDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests import test_v9_local_chain
        cls.fixture = test_v9_local_chain.V9LocalChainTests
        cls.fixture.setUpClass()
        cls.addClassCleanup(cls.fixture.doClassCleanups)

    def test_deploy_and_verify_compiler_runtime_and_constructor_state(self):
        fixture = self.fixture
        policy = policy_fixture()
        policy.update(max_authorization_ttl_seconds=10800, authorization_deadline_seconds=9000)
        policy.update(stablecoin=fixture.stable, genesis_hash=chain.rpc_call(fixture.rpc, "eth_getBlockByNumber", ["0x0", False], 5)["hash"], confirmations=1)
        artifact_root = Path(os.environ.get("MYCOMESH_TEST_V9_ARTIFACT_ROOT", str(Path(__file__).resolve().parents[1] / "out")))
        artifact = deploy.load_artifact(artifact_root / "MycoSettlementV9.sol/MycoSettlementV9.json")
        client = deploy.V9DeploymentClient(fixture.rpc)
        plan = client.plan(policy, artifact)
        with tempfile.TemporaryDirectory() as directory:
            keyfile = Path(directory) / "synthetic-only.key"
            keyfile.write_text(key(20))
            keyfile.chmod(0o600)
            outbox = deploy.V9DeploymentOutbox(Path(directory) / "outbox.sqlite")
            self.addCleanup(outbox.close)
            result = outbox.execute(client, plan, allow_send=True, approved_plan_hash=plan["plan_hash"], key_file=keyfile,
                                    max_gas_price_wei=10**12, max_gas_units=20_000_000, max_total_gas_cost_wei=20 * 10**18)
            self.assertIn(result["state"], ("submitted", "uncertain"))
            fixture.receipt(result["tx_hash"])
            result = outbox.reconcile(client, plan["plan_hash"])
            self.assertEqual(result["state"], "confirmed")
            verified = chain_v9.validate_deployment(result["verification"]["manifest"])
            self.assertEqual(verified.reward_token, chain.ZERO_ADDRESS)
            self.assertEqual(verified.pricing_hash, plan["manifest_candidate"]["pricing_hash"])

    def test_controlled_committee_deploys_only_with_explicit_opt_in_and_honest_manifest(self):
        fixture = self.fixture
        policy = policy_fixture()
        policy.update(max_authorization_ttl_seconds=10800, authorization_deadline_seconds=9000)
        policy.update(stablecoin=fixture.stable,
                      genesis_hash=chain.rpc_call(fixture.rpc, "eth_getBlockByNumber", ["0x0", False], 5)["hash"],
                      confirmations=1, committee_mode="controlled_test", independence_attested=False,
                      network_id="mycomesh-v9-controlled-test",
                      adjudicator_operators={address: "synthetic-single-test-controller"
                                             for address in policy["adjudicators"]})
        artifact_root = Path(os.environ.get("MYCOMESH_TEST_V9_ARTIFACT_ROOT", str(Path(__file__).resolve().parents[1] / "out")))
        artifact = deploy.load_artifact(artifact_root / "MycoSettlementV9.sol/MycoSettlementV9.json")
        default_client = deploy.V9DeploymentClient(fixture.rpc)
        with self.assertRaisesRegex(chain.ChainError, "explicit local opt-in"):
            default_client.plan(policy, artifact)
        client = deploy.V9DeploymentClient(fixture.rpc, allow_controlled_test=True)
        plan = client.plan(policy, artifact)
        with tempfile.TemporaryDirectory() as directory:
            keyfile = Path(directory) / "synthetic-only.key"
            keyfile.write_text(key(20))
            keyfile.chmod(0o600)
            outbox = deploy.V9DeploymentOutbox(Path(directory) / "outbox.sqlite")
            self.addCleanup(outbox.close)
            result = outbox.execute(client, plan, allow_send=True, approved_plan_hash=plan["plan_hash"], key_file=keyfile,
                                    max_gas_price_wei=10**12, max_gas_units=20_000_000, max_total_gas_cost_wei=20 * 10**18)
            fixture.receipt(result["tx_hash"])
            with self.assertRaisesRegex(chain.ChainError, "explicit local opt-in"):
                outbox.reconcile(default_client, plan["plan_hash"])
            self.assertNotEqual(outbox.get(plan["plan_hash"])["state"], "confirmed")
            result = outbox.reconcile(client, plan["plan_hash"])
            self.assertEqual(result["state"], "confirmed")
            manifest = result["verification"]["manifest"]
            with self.assertRaisesRegex(chain.ChainError, "explicit local opt-in"):
                chain_v9.validate_deployment(manifest)
            verified = chain_v9.validate_deployment(manifest, allow_controlled_test=True)
            self.assertEqual(verified.committee_mode, "controlled_test")
            self.assertFalse(verified.independence_attested)
            self.assertEqual(set(verified.adjudicator_operators.values()), {"synthetic-single-test-controller"})
            self.assertEqual(len(set(verified.adjudicators)), 3)
            self.assertEqual(verified.reward_token, chain.ZERO_ADDRESS)
            self.assertEqual(verified.pricing_hash, plan["manifest_candidate"]["pricing_hash"])
            for field in ("token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty"):
                self.assertEqual(verified.policy[field], 0)


if __name__ == "__main__":
    unittest.main()
