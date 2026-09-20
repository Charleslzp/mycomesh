"""Opt-in real EVM tests. Only an ephemeral localhost EVM, never an external RPC.

Run: RUN_MYCO_V9_LOCAL_CHAIN=1 python3 -B -m unittest tests.test_v9_local_chain
Requires prebuilt offline Forge artifacts; fixtures have no production authority.
Hardhat can be supplied through MYCOMESH_TEST_HARDHAT_BIN and
MYCOMESH_TEST_HARDHAT_CONFIG (network name v9local, chainId 31337, initialDate
approximately two minutes ago). Its EIP-1898 support is required by the operator
test. Ganache's incomplete EIP-1898 support intentionally fails that test.
MYCOMESH_TEST_V9_ARTIFACT_ROOT can point to separate Shanghai test artifacts.
Installing a test EVM is explicit and never changes project/global dependencies.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from gateway import chain_v8, chain_v9 as v9
from gateway.chain import (ChainError, abi_encode_arg, call_contract, deploy_contract_transaction, keccak256,
                           load_artifact_bytecode, rpc_call, send_contract_data_transaction,
                           send_contract_transaction)
from tests.test_chain_v9 import address, digest, key, signer
from gateway.relay_adjudication_v9 import V9AdjudicationClient, V9OperatorConfig, V9TransactionOutbox
from gateway.relay_incidents import evidence_hash


ROOT = Path(__file__).resolve().parents[1]
ANVIL = shutil.which("anvil") or str(Path.home() / ".foundry" / "bin" / "anvil")


@unittest.skipUnless(os.environ.get("RUN_MYCO_V9_ANVIL_TESTS") == "1" or os.environ.get("RUN_MYCO_V9_LOCAL_CHAIN") == "1", "opt-in localhost EVM test")
class V9LocalChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ganache = os.environ.get("MYCOMESH_TEST_GANACHE_BIN")
        cls.hardhat = os.environ.get("MYCOMESH_TEST_HARDHAT_BIN")
        if not cls.ganache and not cls.hardhat and not Path(ANVIL).is_file():
            raise unittest.SkipTest("no installed or explicit localhost EVM fixture binary")
        artifact_root = Path(os.environ.get("MYCOMESH_TEST_V9_ARTIFACT_ROOT", str(ROOT / "out")))
        artifacts = [artifact_root / "MycoSettlementV9.sol/MycoSettlementV9.json", artifact_root / "MycoSettlementV9.t.sol/MockExactTokenV9.json"]
        if not all(path.is_file() for path in artifacts):
            raise unittest.SkipTest("build V9 contracts with offline Forge first")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cls.rpc = f"http://127.0.0.1:{port}"
        if cls.hardhat:
            command = [cls.hardhat, "node", "--hostname", "127.0.0.1", "--port", str(port), "--network", "v9local",
                       "--config", os.environ["MYCOMESH_TEST_HARDHAT_CONFIG"]]
        elif cls.ganache:
            command = [cls.ganache, "--server.host", "127.0.0.1", "--server.port", str(port), "--chain.chainId", "31337", "--logging.quiet"]
            command.extend(["--chain.time", datetime.fromtimestamp(time.time() - 120, timezone.utc).isoformat()])
            for number in (1, 2, 3, 10, 11, 12, 20, 21, 22, 23):
                command.extend(["--wallet.accounts", f"{key(number)},{10**22}"])
        else:
            command = [ANVIL, "--host", "127.0.0.1", "--port", str(port), "--chain-id", "31337", "--silent"]
        cls.process = subprocess.Popen(command, cwd=Path(os.environ["MYCOMESH_TEST_HARDHAT_CONFIG"]).parent if cls.hardhat else ROOT,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.addClassCleanup(cls._shutdown)
        for attempt in range(1500):
            try:
                if rpc_call(cls.rpc, "eth_chainId", [], 1) == "0x7a69":
                    break
            except (ChainError, OSError):
                time.sleep(0.02)
        else:
            raise RuntimeError("local EVM HTTP RPC did not start within 30 seconds")
        if not cls.ganache:
            for number in (1, 2, 3, 10, 11, 12, 20, 21, 22, 23):
                rpc_call(cls.rpc, "hardhat_setBalance" if cls.hardhat else "anvil_setBalance", [signer(number), hex(10**22)], 2)
        cls.stable, _ = deploy_contract_transaction(cls.rpc, key(20), 31337, load_artifact_bytecode(artifacts[1]), 5)
        cls.reward, _ = deploy_contract_transaction(cls.rpc, key(20), 31337, load_artifact_bytecode(artifacts[1]), 5)
        cls.channel = digest(101)
        config = [1000, 4000, 2000, 8500, 300, 200, 1000, "true"]
        policy = [60, 120, 60, 100, 5000, 10000, 2000, 1000, 10, 1000, 100, 10, address(99)]
        constructor = [cls.stable, cls.reward, address(90), signer(20), cls.channel, *config, *policy, 28 * 32, 2,
                       3, signer(10), signer(11), signer(12)]
        data = b"".join(abi_encode_arg(str(item)) for item in constructor)
        cls.contract, _ = deploy_contract_transaction(cls.rpc, key(20), 31337, load_artifact_bytecode(artifacts[0]) + data, 10)
        cls.pricing_hash = call_contract(cls.rpc, cls.contract, "channelPricingHash(bytes32,uint64)", [cls.channel, "1"])
        for number, amount in ((21, 50000), (22, 50000), (23, 1000)):
            cls.send(20, cls.stable, "mint(address,uint256)", [signer(number), str(amount)])
            cls.send(number, cls.stable, "approve(address,uint256)", [cls.contract, str(amount)])
        cls.send(21, cls.contract, "deposit(uint256)", ["50000"])
        cls.send(21, cls.contract, "registerKey(address,uint256,uint64)", [signer(1), "10000", "0"])
        cls.send(22, cls.contract, "depositStake(uint256)", ["50000"])
        cls.send(22, cls.contract, "authorizeProviderSigner(address)", [signer(2)])
        cls.send(20, cls.reward, "mint(address,uint256)", [signer(20), "1000"])
        cls.send(20, cls.reward, "approve(address,uint256)", [cls.contract, "1000"])
        cls.send_data(20, v9.encode_fund_token_rewards(1000))
        cls.snapshot = rpc_call(cls.rpc, "evm_snapshot", [], 2)

    @classmethod
    def _shutdown(cls):
        if getattr(cls, "process", None) is not None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=2)

    def setUp(self):
        rpc_call(self.rpc, "evm_revert", [self.snapshot], 2)
        type(self).snapshot = rpc_call(self.rpc, "evm_snapshot", [], 2)

    @classmethod
    def receipt(cls, tx):
        for _ in range(100):
            value = rpc_call(cls.rpc, "eth_getTransactionReceipt", [tx], 2)
            if value:
                if value.get("status") != "0x1":
                    raise AssertionError("local transaction reverted")
                return value
            time.sleep(0.01)
        raise AssertionError("local transaction not mined")

    @classmethod
    def send(cls, number, contract, signature, args):
        tx = send_contract_transaction(cls.rpc, key(number), 31337, contract, signature, args, 5)
        return cls.receipt(tx)

    @classmethod
    def send_data(cls, number, data):
        tx = send_contract_data_transaction(cls.rpc, key(number), 31337, cls.contract, data, 5)
        return cls.receipt(tx)

    def signed(self, module=v9, *, node=False):
        block = rpc_call(self.rpc, "eth_getBlockByNumber", ["latest", False], 2)
        issued = min(int(block["timestamp"], 16), int(time.time()))
        if node:
            script = "import {buildAuthorization} from './packages/mycomesh-cli/src/consumer-runtime.mjs'; let input=''; for await (const chunk of process.stdin) input+=chunk; console.log(JSON.stringify(buildAuthorization(JSON.parse(input))));"
            params = {"protocolVersion": 9, "paymentKey": key(1), "chainId": 31337, "settlementContract": self.contract,
                      "requestId": digest(201), "requestHash": digest(202), "relay": signer(3), "relaySigner": signer(3),
                      "channelHash": self.channel, "pricingVersion": 1, "pricingHash": self.pricing_hash,
                      "maxFee": 10000, "issuedAt": issued, "deadline": issued + 3600}
            result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=ROOT, input=json.dumps(params),
                                    text=True, capture_output=True, check=True, timeout=15)
            auth = json.loads(result.stdout)
            module.verify_authorization(auth)
        else:
            auth = module.build_authorization(payment_key=key(1), chain_id=31337, settlement_contract=self.contract,
                                              request_id=digest(201), request_hash=digest(202), relay=signer(3), relay_signer=signer(3),
                                              channel_hash=self.channel, pricing_version=1, pricing_hash=self.pricing_hash,
                                              max_fee=10000, issued_at=issued, deadline=issued + 3600)
        provider = module.build_provider_receipt(provider=signer(22), provider_private_key=key(2), authorization_payload=auth,
                                                response_hash=digest(203), relay=signer(3), input_tokens=100, output_tokens=100,
                                                actual_fee=2000)
        return module.finalize_relay_receipt(provider, relay_private_key=key(3))

    def stake(self):
        # Ordinary balance assertions exercise the explicit pinned-number API
        # on every backend. The operator test below independently exercises
        # production's EIP-1898 hash-pinned path without any compatibility shim.
        block = rpc_call(self.rpc, "eth_blockNumber", [], 2)
        return v9.provider_stake_status(self.rpc, self.contract, signer(22), block_tag=block)

    def settle(self, *, node=False):
        tx = self.send_data(3, v9.encode_signed_receipt(self.signed(node=node)))
        events = [log for log in tx["logs"] if log["topics"] and log["topics"][0] == v9.RECEIPT_ESCROWED_TOPIC]
        self.assertEqual(len(events), 1)
        event = v9.parse_receipt_escrowed(events[0], expected_contract=self.contract)
        expected = v9.settlement_key_for(signer(21), signer(1), digest(201))
        self.assertEqual(event["settlement_key"], expected)
        self.assertEqual(event["gross_fee"], 2000)
        self.assertEqual(self.stake()["locked"], 2000)
        return event

    def warp(self, timestamp):
        if self.ganache:
            rpc_call(self.rpc, "evm_setTime", [timestamp * 1000], 2)
        else:
            rpc_call(self.rpc, "evm_setNextBlockTimestamp", [timestamp], 2)
        rpc_call(self.rpc, "evm_mine", [], 2)

    def test_verified_long_authorization_reaches_escrow_after_two_hours(self):
        now = int(time.time())
        window = v9.verified_authorization_window(
            self.rpc, chain_id=31337, settlement=self.contract, key=signer(1), now=now,
            deadline_seconds=9000, expected_max_ttl=10800, max_fee=10000,
        )
        auth = v9.build_authorization(
            payment_key=key(1), chain_id=31337, settlement_contract=self.contract,
            request_id=digest(201), request_hash=digest(202), relay=signer(3), relay_signer=signer(3),
            channel_hash=self.channel, pricing_version=1, pricing_hash=self.pricing_hash, max_fee=10000,
            issued_at=window["issued_at"], deadline=window["deadline"],
            max_authorization_ttl=window["max_authorization_ttl"],
        )
        provider = v9.build_provider_receipt(provider=signer(22), provider_private_key=key(2),
            authorization_payload=auth, response_hash=digest(203), relay=signer(3),
            input_tokens=100, output_tokens=100, actual_fee=2000)
        signed = v9.finalize_relay_receipt(provider, relay_private_key=key(3))
        self.warp(now + 7200)
        self.send_data(3, v9.encode_signed_receipt(signed))
        identifier = v9.settlement_key_for(signer(21), signer(1), digest(201))
        self.assertEqual(v9.settlement_info(self.rpc, self.contract, identifier)["status_name"], "pending")

    def test_real_eip712_matches_contract_and_v8_cannot_settle(self):
        self.assertEqual(call_contract(self.rpc, self.contract, "DOMAIN_SEPARATOR()", []),
                         v9.domain_separator(chain_id=31337, verifying_contract=self.contract))
        with self.assertRaises(ChainError):
            self.send_data(3, chain_v8.encode_signed_receipt(self.signed(chain_v8)))
        self.assertEqual(v9.account_balance(self.rpc, self.contract, signer(21)), 50000)
        event = self.settle()
        self.assertEqual(v9.settlement_info(self.rpc, self.contract, event["settlement_key"])["status_name"], "pending")

    def test_escrow_is_not_immediate_payout_and_release_unlocks_stake(self):
        event = self.settle()
        self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(22)), 0)
        with self.assertRaises(ChainError):
            self.send_data(3, v9.encode_release(event["settlement_key"]))
        self.warp(event["release_at"])
        self.send_data(3, v9.encode_release(event["settlement_key"]))
        self.assertEqual(v9.settlement_info(self.rpc, self.contract, event["settlement_key"])["status_name"], "released")
        self.assertEqual(self.stake()["locked"], 0)
        self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(22)), 1700)
        self.send_data(22, v9.encode_claim_payout())
        self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(22)), 0)

    def test_report_independent_quorum_refund_slash_and_both_rewards(self):
        event = self.settle(node=True)
        settlement_key = event["settlement_key"]
        report_id = v9.report_id_for(settlement_key, signer(23), digest(301))
        self.send_data(23, v9.encode_open_dispute(settlement_key, digest(301)))
        self.assertEqual(v9.report_info(self.rpc, self.contract, settlement_key, report_id)["reporter"], signer(23))
        self.assertTrue(v9.has_reported(self.rpc, self.contract, settlement_key, signer(23)))
        with self.assertRaises(ChainError):
            self.send_data(10, v9.encode_vote_dispute(settlement_key, confirmed=True, report_id=report_id, decision_hash=digest(302)))
        self.warp(event["release_at"])
        with self.assertRaises(ChainError):
            self.send_data(23, v9.encode_vote_dispute(settlement_key, confirmed=True, report_id=report_id, decision_hash=digest(302)))
        self.send_data(10, v9.encode_vote_dispute(settlement_key, confirmed=True, report_id=report_id, decision_hash=digest(302)))
        self.assertEqual(v9.settlement_info(self.rpc, self.contract, settlement_key)["status_name"], "disputed")
        self.send_data(11, v9.encode_vote_dispute(settlement_key, confirmed=True, report_id=report_id, decision_hash=digest(303)))
        self.assertEqual(v9.settlement_info(self.rpc, self.contract, settlement_key)["status_name"], "confirmed")
        self.assertEqual(v9.account_balance(self.rpc, self.contract, signer(21)), 50000)
        self.assertEqual(self.stake(), {"stake": 49000, "locked": 0, "available": 49000})
        self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(23)), 200)
        self.assertEqual(v9.token_claimable_balance(self.rpc, self.contract, signer(23)), 10)
        self.send_data(3, v9.encode_claim_dispute_bond(settlement_key, report_id))
        self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(23)), 300)
        self.send_data(23, v9.encode_claim_payout())
        self.send_data(23, v9.encode_claim_token_reward())
        self.assertEqual(v9.token_claimable_balance(self.rpc, self.contract, signer(23)), 0)
        self.assertTrue(v9.report_info(self.rpc, self.contract, settlement_key, report_id)["bond_claimed"])
        with self.assertRaises(ChainError):
            self.send_data(3, v9.encode_claim_dispute_bond(settlement_key, report_id))

    def test_user_jury_real_evidence_two_independent_votes_refund_and_slash(self):
        """Actual signed evidence, user selection, plans and two EVM senders.

        The fixture Relay intentionally co-signs a receipt whose committed
        response contradicts its usage. The contract escrows the valid priced
        receipt; the real offline verifier establishes the separate mismatch.
        No evidence verifier, chain snapshot, signer or model is mocked.
        """
        from dataclasses import replace

        from gateway.identity import create_identity, sign_document
        from gateway.provider_identity_binding import build_provider_identity_binding
        from gateway.relay_evidence import OBSERVATION_PURPOSE, verify_relay_incident
        from gateway.relay_integrity import PROVIDER_RESPONSE_PURPOSE, provider_response_hash
        from gateway.user_jury_agent import JuryError, ROSTER_PURPOSE, UserJuryAgent

        observer, provider_identity, reputation_authority = (create_identity() for _ in range(3))
        payment = self.signed()["authorization"]
        auth = payment["authorization"]
        observed_at = auth["issued_at"]
        observation_source = "isolated-localhost-fixture-observation:" + auth["request_id"]
        registration_audience = "isolated-fixture-relay:9801"
        peer = {
            "peer_id": provider_identity.peer_id, "public_key": provider_identity.public_key,
            "model": "fixture-model", "models": ["fixture-model"], "channel": "codex-standard-v1",
            "payment_address": signer(22), "challenge": "isolated-registration-challenge",
            "settlement": {"version": 9, "chain_id": 31337, "contract": self.contract,
                           "pricing_version": 1, "pricing_hash": self.pricing_hash,
                           "provider_signer": signer(2)},
        }
        peer["settlement_identity_binding"] = build_provider_identity_binding(
            peer, audience=registration_audience, private_key=key(2))
        registration = sign_document(peer, provider_identity.private_key, "mycomesh.relay.provider.v1",
                                     audience=registration_audience, timestamp=observed_at)
        usage = {"input_tokens": 200, "output_tokens": 100, "total_tokens": 300}
        response = {
            "type": "infer_result", "ok": True, "peer": peer, "request_id": auth["request_id"],
            "endpoint": "responses", "model": "fixture-model", "output_text": "signed fixture answer",
            "usage": usage, "raw": {"output_text": "signed fixture answer", "usage": usage},
        }
        provider_receipt = v9.build_provider_receipt(
            provider=signer(22), provider_private_key=key(2), authorization_payload=payment,
            response_hash=provider_response_hash(response), relay=signer(3),
            input_tokens=100, output_tokens=100, actual_fee=2000)
        response["mycomesh_v9_settlement"] = provider_receipt
        response = sign_document(response, provider_identity.private_key, PROVIDER_RESPONSE_PURPOSE,
                                 audience=observer.public_key, timestamp=observed_at)
        evidence = {
            "schema": "mycomesh.relay.protocol-observation.v1", "code": "usage_receipt_mismatch",
            "settlement_version": 9, "expected_authorization": payment,
            "provider_response": response, "provider_registration": registration,
            "request_constraints": {"request_id": auth["request_id"], "request_hash": auth["request_hash"],
                                    "chain_id": 31337, "contract": self.contract, "model": "fixture-model",
                                    "endpoint": "responses", "max_output_tokens": 500, "channel": self.channel},
            "response_signature_verified": True, "observer_public_key": observer.public_key,
            "signature_time_semantics": "authorization_issued_at", "economic_identity_verified": True,
            "monetary_verdict": False,
        }
        evidence = sign_document(evidence, observer.private_key, OBSERVATION_PURPOSE,
                                 audience=f"31337:{self.contract}", timestamp=observed_at)
        record = {
            "provider_id": provider_identity.peer_id, "provider_signer": signer(2),
            "request_id": auth["request_id"], "request_hash": auth["request_hash"],
            "kind": "protocol:usage_receipt_mismatch", "severity": "high", "evidence": evidence,
        }
        incident = {**record, "evidence_hash": evidence_hash(evidence), "record_hash": evidence_hash(record)}
        verified = verify_relay_incident(incident, expected_observer_public_key=observer.public_key,
                                         observed_at=observed_at)
        self.assertEqual(verified["code"], "usage_receipt_mismatch")
        self.assertEqual(verified["classification"], "protocol_contradiction")
        self.assertFalse(verified["monetary_verdict"])

        signed_receipt = v9.finalize_relay_receipt(provider_receipt, relay_private_key=key(3))
        tx = self.send_data(3, v9.encode_signed_receipt(signed_receipt))
        escrow_logs = [log for log in tx["logs"] if log["topics"] and log["topics"][0] == v9.RECEIPT_ESCROWED_TOPIC]
        self.assertEqual(len(escrow_logs), 1)
        event = v9.parse_receipt_escrowed(escrow_logs[0], expected_contract=self.contract)
        settlement_key = event["settlement_key"]
        self.assertEqual(v9.account_balance(self.rpc, self.contract, signer(21)), 48000)
        self.assertEqual(self.stake(), {"stake": 50000, "locked": 2000, "available": 48000})
        self.send_data(23, v9.encode_open_dispute(settlement_key, incident["record_hash"]))
        report_id = v9.report_id_for(settlement_key, signer(23), incident["record_hash"])
        self.assertEqual(v9.report_info(self.rpc, self.contract, settlement_key, report_id)["evidence_hash"],
                         incident["record_hash"])
        self.warp(event["release_at"])

        # Local EVM time can be ahead of wall time after warping. Only its test
        # clock follows that advance; every hash-pinned RPC read remains real.
        block = rpc_call(self.rpc, "eth_getBlockByNumber", ["latest", False], 2)
        jury_now = int(block["timestamp"], 16)
        with patch("gateway.user_jury_agent.time.time", return_value=jury_now):
            client = V9AdjudicationClient(replace(self.operator_client().config,
                                                 observer_public_key=observer.public_key))
            roster = {
                "schema": ROSTER_PURPOSE, "domain": client.config.domain,
                "issued_at": jury_now, "expires_at": jury_now + 3600,
                "users": [{"address": signer(number), "operator_id": client.config.adjudicator_operators[signer(number)],
                           "score": 100 - index, "score_source_hash": digest(700 + index),
                           "affiliated_addresses": [], "opt_in": True}
                          for index, number in enumerate((10, 11, 12))],
            }
            roster = sign_document(roster, reputation_authority.private_key, ROSTER_PURPOSE,
                                   audience=evidence_hash(client.config.domain), timestamp=jury_now)
            agent = UserJuryAgent(client, reputation_public_key=reputation_authority.public_key, minimum_score=90)
            tasks = agent.assign(incident=incident, observed_at=observed_at, observation_source_ref=observation_source,
                                 settlement_key=settlement_key, signed_roster=roster)
            self.assertEqual([task["reviewer"] for task in tasks], [signer(10), signer(11), signer(12)])
            task_by_user = {task["reviewer"]: task for task in tasks}
            tx_hashes = []
            with tempfile.TemporaryDirectory(prefix="mycomesh-user-jury-local-evm-") as directory:
                for number in (10, 11):
                    reviewer, task = signer(number), task_by_user[signer(number)]
                    review = agent.review(task, reviewer=reviewer, observed_at=observed_at,
                                          observation_source_ref=observation_source)
                    self.assertTrue(review["eligible_for_confirming_vote_review"])
                    self.assertEqual(review["facts"][2]["value"], "protocol_contradiction")
                    self.assertEqual([fact["value"] for fact in review["facts"][4:]],
                                     ["matched", "matched", "eligible", "open"])
                    self.assertFalse(review["monetary_verdict"])
                    self.assertFalse(review["transaction_authorized"])
                    self.assertEqual(review["codex_status"], "not_requested")
                    approved = {"task_hash": task["task_hash"], "reviewer": reviewer,
                                "incident_record_hash": incident["record_hash"], "outcome": "confirmed",
                                "reason": "I independently replayed the signed usage mismatch and verified this settled receipt."}
                    plan = agent.plan_user_vote(task, reviewer=reviewer, observed_at=observed_at,
                                                observation_source_ref=observation_source, approved_review=approved)
                    self.assertEqual(plan["transaction"]["from"], reviewer)
                    fixture_key = Path(directory) / f"fixture-user-{number}.key"
                    fixture_key.write_text(key(number), encoding="utf-8")
                    fixture_key.chmod(0o600)
                    outbox = V9TransactionOutbox(Path(directory) / f"user-{number}-outbox.sqlite3")
                    try:
                        sent = outbox.execute(client, plan, allow_send=True, approved_plan_hash=plan["plan_hash"],
                                              key_file=fixture_key, max_gas_price_wei=10**12,
                                              max_gas_units=1000000, max_total_gas_cost_wei=10**18)
                        self.assertEqual(sent["state"], "submitted")
                        self.assertEqual(outbox.reconcile(client, plan["plan_hash"])["state"], "confirmed")
                        tx_hashes.append(sent["tx_hash"])
                    finally:
                        outbox.close()
                    self.assertNotEqual(v9.dispute_vote(self.rpc, self.contract, settlement_key, reviewer), 0)
                    if number == 10:
                        self.assertEqual(v9.settlement_info(self.rpc, self.contract, settlement_key)["status_name"], "disputed")
                        self.assertEqual(v9.account_balance(self.rpc, self.contract, signer(21)), 48000)
                        self.assertEqual(self.stake(), {"stake": 50000, "locked": 2000, "available": 48000})
                        with self.assertRaisesRegex(JuryError, "already voted"):
                            agent.review(task, reviewer=reviewer, observed_at=observed_at,
                                         observation_source_ref=observation_source)
                        remaining = agent.assign(incident=incident, observed_at=observed_at,
                                                 observation_source_ref=observation_source,
                                                 settlement_key=settlement_key, signed_roster=roster)
                        self.assertEqual([task["reviewer"] for task in remaining], [signer(11), signer(12)])
            self.assertEqual(len(set(tx_hashes)), 2)
            self.assertEqual(v9.settlement_info(self.rpc, self.contract, settlement_key)["status_name"], "confirmed")
            self.assertEqual(v9.account_balance(self.rpc, self.contract, signer(21)), 50000)
            self.assertEqual(self.stake(), {"stake": 49000, "locked": 0, "available": 49000})
            self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(22)), 0)
            self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(23)), 200)

    def test_timeout_is_nonpunitive_and_returns_report_bond(self):
        event = self.settle()
        settlement_key = event["settlement_key"]
        self.send_data(23, v9.encode_open_dispute(settlement_key, digest(401)))
        report_id = v9.report_id_for(settlement_key, signer(23), digest(401))
        case = v9.dispute_info(self.rpc, self.contract, settlement_key)
        self.warp(case["resolve_at"])
        self.send_data(3, v9.encode_resolve_timed_out_dispute(settlement_key))
        self.send_data(3, v9.encode_claim_dispute_bond(settlement_key, report_id))
        self.assertEqual(v9.settlement_info(self.rpc, self.contract, settlement_key)["status_name"], "timed_out")
        self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(23)), 100)
        self.assertEqual(v9.token_claimable_balance(self.rpc, self.contract, signer(23)), 0)
        self.assertEqual(self.stake()["stake"], 50000)

    def operator_client(self):
        block = rpc_call(self.rpc, "eth_blockNumber", [], 2)
        policy = v9.dispute_policy(self.rpc, self.contract, block_tag=block)
        judges = tuple(v9.adjudicators(self.rpc, self.contract, block_tag=block))
        code = rpc_call(self.rpc, "eth_getCode", [self.contract, block], 2)
        config = V9OperatorConfig(rpc_url=self.rpc, chain_id=31337, settlement_contract=self.contract,
            runtime_code_hash="0x" + keccak256(bytes.fromhex(code[2:])).hex(),
            genesis_hash=rpc_call(self.rpc, "eth_getBlockByNumber", ["0x0", False], 2)["hash"],
            policy_hash=evidence_hash(policy), adjudicators=judges,
            adjudicator_operators={judge: f"isolated-fixture-{i}" for i, judge in enumerate(judges)},
            independence_attested=True, threshold=2, observer_public_key="11" * 32,
            reporter_address=signer(23), confirmations=1)
        return V9AdjudicationClient(config)

    def test_operator_pinned_snapshot_exact_approved_claim_and_reconcile(self):
        event = self.settle()
        self.warp(event["release_at"])
        self.send_data(3, v9.encode_release(event["settlement_key"]))
        client = self.operator_client()
        plan = client.plan_claim(actor=signer(22), settlement_key=event["settlement_key"], kind="stable")
        self.assertEqual(plan["amounts"]["claim_units"], 1700)
        with tempfile.TemporaryDirectory(prefix="mycomesh-v9-operator-fixture-") as directory:
            key_file = Path(directory) / "fixture-key"
            key_file.write_text(key(22), encoding="utf-8")
            key_file.chmod(0o600)
            outbox = V9TransactionOutbox(Path(directory) / "outbox.sqlite3")
            try:
                result = outbox.execute(client, plan, allow_send=True, approved_plan_hash=plan["plan_hash"],
                    key_file=key_file, max_gas_price_wei=10**12, max_gas_units=500000, max_total_gas_cost_wei=10**18)
                self.assertEqual(result["state"], "submitted")
                self.assertEqual(outbox.reconcile(client, plan["plan_hash"])["state"], "confirmed")
                self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(22)), 0)
                repeated = outbox.execute(client, plan, allow_send=True, approved_plan_hash=plan["plan_hash"],
                    key_file=key_file, max_gas_price_wei=10**12, max_gas_units=500000, max_total_gas_cost_wei=10**18)
                self.assertEqual(repeated["tx_hash"], result["tx_hash"])
            finally:
                outbox.close()

    def check_operator_lifecycle(self, action):
        event = self.settle()
        settlement_key = event["settlement_key"]
        if action == "timeout":
            self.send_data(23, v9.encode_open_dispute(settlement_key, digest(501)))
            self.warp(v9.dispute_info(self.rpc, self.contract, settlement_key)["resolve_at"])
        else:
            self.warp(event["release_at"])
        # Advancing an isolated EVM through arbitration can move it ahead of
        # wall time. Advance this test's observer clock by the same amount;
        # production snapshot freshness/future checks remain unchanged.
        block = rpc_call(self.rpc, "eth_getBlockByNumber", ["latest", False], 2)
        observer_clock = patch("gateway.relay_adjudication_v9.time.time", return_value=int(block["timestamp"], 16))
        observer_clock.start()
        self.addCleanup(observer_clock.stop)
        self.assertGreater(self.stake()["locked"], 0)
        client = self.operator_client()
        plan = getattr(client, "plan_" + action)(actor=signer(3), settlement_key=settlement_key)
        with tempfile.TemporaryDirectory(prefix="mycomesh-v9-maintenance-fixture-") as directory:
            key_file = Path(directory) / "fixture-key"
            key_file.write_text(key(3), encoding="utf-8")
            key_file.chmod(0o600)
            path = Path(directory) / "outbox.sqlite3"
            outbox = V9TransactionOutbox(path)
            options = dict(allow_send=True, approved_plan_hash=plan["plan_hash"], key_file=key_file,
                           max_gas_price_wei=10**12, max_gas_units=500000, max_total_gas_cost_wei=10**18)
            try:
                self.assertFalse(outbox.execute(client, plan)["sent"])
                first = outbox.execute(client, plan, **options)
                result = outbox.reconcile(client, plan["plan_hash"])
                self.assertEqual(result["state"], "confirmed")
                self.assertEqual(result["settlement_outcome"]["status"], "released" if action == "release" else "timed_out")
                self.assertFalse(result["settlement_outcome"]["wallet_payout_verified"])
                self.assertEqual(self.stake()["locked"], 0)
                self.assertEqual(v9.claimable_balance(self.rpc, self.contract, signer(22)), 1700)
            finally:
                outbox.close()
            reopened = V9TransactionOutbox(path)
            try:
                repeated = reopened.execute(client, plan, **options)
                self.assertEqual(repeated["tx_hash"], first["tx_hash"])
                self.assertEqual(repeated["settlement_outcome"], result["settlement_outcome"])
            finally:
                reopened.close()

    def test_operator_matured_release_verified_after_restart(self):
        self.check_operator_lifecycle("release")

    def test_operator_dispute_timeout_verified_after_restart(self):
        self.check_operator_lifecycle("timeout")


if __name__ == "__main__":
    unittest.main()
