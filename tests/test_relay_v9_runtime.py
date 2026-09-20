"""V9 runtime regression: real signatures, local fake RPC/transport only."""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway import chain_v8, chain_v9, relay
from gateway.chain import ChainError
from gateway.identity import sign_document
from gateway.p2p import INFERENCE_REQUEST_PURPOSE, P2PError, _preverify_inference_request, handle_infer, provider_runtime_capabilities
from gateway.relay_integrity import provider_response_hash
from gateway.relay_evidence import verify_relay_incident
from gateway.session_relayer import RelaySettlementOutbox, RelaySettlementSubmitter, RelaySettlementError
from gateway.v9_relayer import prepare_v9_relay_settlement
from tests import test_relay_security_integration, test_p2p_v8, test_relay_probe_runtime


class V9ProbeRuntimeTests(test_relay_probe_runtime.RelayProbeRuntimeTests):
    version = 9
    protocol = chain_v9


class RelayV9SecurityTests(test_relay_security_integration.RelaySecurityIntegrationTests):
    version = 9
    protocol = chain_v9

    def test_v9_pre_settlement_evidence_reproduces_but_is_not_a_monetary_verdict(self):
        self.mode = "body_mismatch"
        with self.assertRaises(relay.RelaySchedulingError):
            self.run_request()
        evidence = verify_relay_incident(
            self.incident(), expected_observer_public_key=self.state._scheduler_identity.public_key,
            observed_at=int(time.time()),
        )
        self.assertEqual(evidence["classification"], "protocol_contradiction")
        self.assertFalse(evidence["monetary_verdict"])
        self.submitter.enqueue.assert_not_called()

    def test_v8_authorization_is_not_accepted_by_v9_relay(self):
        self.payment["schema"] = chain_v8.AUTH_SCHEMA
        with self.assertRaises(ChainError):
            self.run_request()
        self.submitter.enqueue.assert_not_called()

    def test_stake_check_blocks_before_provider_dispatch(self):
        with patch("gateway.chain_v9.key_grant", return_value={"active": True, "owner": self.key_address, "max_per_request": 10000, "valid_until": 0}), \
                patch("gateway.chain_v9.account_balance", return_value=100000), \
                patch("gateway.chain_v9.provider_stake_status", return_value={"stake": 10000, "locked": 1, "available": 9999}), \
                patch("gateway.relay.relay_infer") as dispatch:
            with self.assertRaisesRegex(relay.RelayNotDispatchedError, "insufficient available stake"):
                relay.relay_v7_openai(self.state, "/v1/responses", self.body, self.payment)
        dispatch.assert_not_called()
        self.submitter.enqueue.assert_not_called()
        self.assertEqual(self.session.reserved_jobs, 0)

    def test_stake_rpc_failure_cannot_be_used_as_available_collateral(self):
        with patch("gateway.chain_v9.key_grant", return_value={"active": True, "owner": self.key_address, "max_per_request": 10000, "valid_until": 0}), \
                patch("gateway.chain_v9.account_balance", return_value=100000), \
                patch("gateway.chain_v9.provider_stake_status", side_effect=ChainError("unavailable")), \
                patch("gateway.relay.relay_infer") as dispatch:
            with self.assertRaisesRegex(relay.RelayNotDispatchedError, "could not be verified"):
                relay.relay_v7_openai(self.state, "/v1/responses", self.body, self.payment)
        dispatch.assert_not_called()

    def long_authorization(self):
        args = dict(self.payment["authorization"])
        args.pop("key")
        args["channel_hash"] = args.pop("channel")
        args["deadline"] = args["issued_at"] + 9000
        self.payment = chain_v9.build_authorization(payment_key=self.key_private,
            chain_id=11155111, settlement_contract=self.contract,
            max_authorization_ttl=10800, **args)
        self.state.settlement_rpc_url = "http://offline.invalid"
        self.state.settlement_contract = self.contract

    def test_long_authorization_is_rejected_on_legacy_contract_before_dispatch(self):
        self.long_authorization()
        with patch("gateway.chain_v9.max_authorization_ttl", return_value=3600) as ttl:
            with self.assertRaisesRegex(relay.RelayNotDispatchedError, "deployment's TTL"):
                self.run_request()
        ttl.assert_called_once()
        self.assertEqual(ttl.call_args.args, ("http://offline.invalid", self.contract))
        self.transport_mock.assert_not_called()
        self.submitter.enqueue.assert_not_called()
        self.submitter.release_admission.assert_called_once_with("lease")

    def test_long_authorization_cap_rpc_failure_is_not_permission_to_execute(self):
        self.long_authorization()
        with patch("gateway.chain_v9.max_authorization_ttl", side_effect=ChainError("unavailable")):
            with self.assertRaisesRegex(relay.RelayNotDispatchedError, "could not be verified"):
                self.run_request()
        self.transport_mock.assert_not_called()

    def test_three_hour_contract_accepts_long_authorization_and_short_path_needs_no_ttl_rpc(self):
        with patch("gateway.chain_v9.max_authorization_ttl", side_effect=AssertionError("legacy authorization needs no TTL query")) as ttl:
            self.run_request()
        ttl.assert_not_called()
        self.long_authorization()
        with patch("gateway.chain_v9.max_authorization_ttl", return_value=10800) as ttl:
            _, envelope = self.run_request()
        ttl.assert_called_once()
        self.assertEqual(envelope["signed_receipt"]["authorization"]["authorization"]["deadline"],
            self.payment["authorization"]["deadline"])

    def test_key_grant_must_cover_the_whole_authorization_deadline(self):
        grant = {"active": True, "owner": self.key_address, "max_per_request": 10000,
                 "valid_until": self.payment["authorization"]["deadline"] - 1}
        with patch("gateway.chain_v9.key_grant", return_value=grant), \
                patch("gateway.relay.relay_infer") as dispatch, \
                patch("gateway.chain_v9.account_balance") as balance:
            with self.assertRaisesRegex(relay.RelayNotDispatchedError, "expires before"):
                relay.relay_v7_openai(self.state, "/v1/responses", self.body, self.payment)
        dispatch.assert_not_called()
        balance.assert_not_called()


class ProviderV9Tests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_p2p_v8.ProviderV8Test()
        self.fixture.setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = self.fixture.config(self.temp.name)
        self.config.settlement_version = 9
        self.grant = {"active": True, "owner": self.fixture.provider_address,
                      "max_per_request": 100000, "valid_until": 0}
        grant_patch = patch("gateway.chain_v9.key_grant", side_effect=lambda *_args, **_kwargs: dict(self.grant))
        self.grant_rpc = grant_patch.start()
        self.addCleanup(grant_patch.stop)

    def message(self, *, ttl=900):
        message = self.fixture.message(self.config)
        auth = message.pop("payment_v8")["authorization"]
        message.pop("signature")
        args = {name: value for name, value in auth.items() if name != "key"}
        args["channel_hash"] = args.pop("channel")
        args["deadline"] = args["issued_at"] + ttl
        message["payment_v9"] = chain_v9.build_authorization(
            payment_key=self.fixture.payment_key, chain_id=self.config.settlement_chain_id,
            settlement_contract=self.config.settlement_contract,
            max_authorization_ttl=10800 if ttl > 3600 else 3600, **args,
        )
        return sign_document(message, self.fixture.relay_identity.private_key, INFERENCE_REQUEST_PURPOSE,
                             audience=self.config.peer_id)

    def test_v9_replay_has_its_own_domain_and_descriptor(self):
        checked = _preverify_inference_request(self.config, self.message())
        self.assertTrue(checked["request_key"].startswith("v9:"))
        caps = provider_runtime_capabilities(self.config)
        self.assertEqual(caps["payment_key_settlement"]["schema"], chain_v9.AUTH_SCHEMA)
        self.assertTrue(caps["payment_key_settlement"]["provider_stake_required"])

    def test_v8_cannot_be_downgraded_into_v9_provider(self):
        with self.assertRaises(P2PError):
            _preverify_inference_request(self.config, self.fixture.message(self.config))

    def test_v9_provider_response_and_retry_are_real_signed_and_cached(self):
        message = self.message()
        with patch("gateway.chain_v9.provider_stake_status", return_value={"available": 100000}), \
                patch("gateway.p2p.ensure_gateway_readiness"), \
                patch("gateway.p2p.call_gateway", return_value={"output_text": "world", "usage": {"input_tokens": 5, "output_tokens": 3}}) as backend:
            first = handle_infer(self.config, message)
            second = handle_infer(self.config, message)
        self.assertTrue(first["ok"], first)
        self.assertTrue(second["ok"], second)
        _, receipt, _, _, _ = chain_v9.verify_provider_receipt(first["mycomesh_v9_settlement"])
        self.assertEqual(receipt.response_hash, provider_response_hash(first))
        self.assertEqual(receipt.provider, self.fixture.provider_address)
        self.assertEqual(first["raw"], second["raw"])
        self.assertEqual(backend.call_count, 1)

    def test_provider_rejects_missing_stake_before_backend_work(self):
        with patch("gateway.chain_v9.provider_stake_status", return_value={"available": 0}), \
                patch("gateway.p2p.ensure_gateway_readiness"), patch("gateway.p2p.call_gateway") as backend:
            result = handle_infer(self.config, self.message())
        self.assertFalse(result["ok"])
        self.assertIn("stake", result["error"])
        backend.assert_not_called()

    def test_provider_rejects_long_authorization_on_legacy_contract_before_backend(self):
        with patch("gateway.chain_v9.max_authorization_ttl", return_value=3600) as ttl, \
                patch("gateway.p2p.ensure_gateway_readiness"), patch("gateway.p2p.call_gateway") as backend:
            result = handle_infer(self.config, self.message(ttl=9000))
        self.assertFalse(result["ok"])
        self.assertIn("deployment's TTL", result["error"])
        ttl.assert_called_once()
        self.assertEqual(ttl.call_args.args, (self.config.settlement_rpc_url, self.config.settlement_contract))
        backend.assert_not_called()

    def test_provider_long_cap_rpc_failure_fails_closed(self):
        with patch("gateway.chain_v9.max_authorization_ttl", side_effect=ChainError("unavailable")), \
                patch("gateway.p2p.ensure_gateway_readiness"), patch("gateway.p2p.call_gateway") as backend:
            result = handle_infer(self.config, self.message(ttl=9000))
        self.assertFalse(result["ok"])
        self.assertIn("could not be verified", result["error"])
        backend.assert_not_called()

    def test_provider_long_authorization_on_three_hour_contract(self):
        message = self.message(ttl=9000)
        self.grant["valid_until"] = message["payment_v9"]["authorization"]["deadline"]
        with patch("gateway.chain_v9.max_authorization_ttl", return_value=10800) as ttl, \
                patch("gateway.chain_v9.provider_stake_status", return_value={"available": 100000}), \
                patch("gateway.p2p.ensure_gateway_readiness"), \
                patch("gateway.p2p.call_gateway", return_value={"output_text": "world", "usage": {"input_tokens": 5, "output_tokens": 3}}) as backend:
            result = handle_infer(self.config, message)
        self.assertTrue(result["ok"], result)
        ttl.assert_called_once()
        backend.assert_called_once()

    def test_provider_rechecks_grant_coverage_even_for_short_authorizations(self):
        message = self.message()
        original = dict(self.grant)
        for change in ({"active": False}, {"owner": "0x" + "00" * 20}, {"max_per_request": 99999},
                       {"valid_until": message["payment_v9"]["authorization"]["deadline"] - 1}):
            self.grant = {**original, **change}
            with self.subTest(change=change), \
                    patch("gateway.chain_v9.max_authorization_ttl") as ttl, \
                    patch("gateway.p2p.ensure_gateway_readiness"), patch("gateway.p2p.call_gateway") as backend:
                result = handle_infer(self.config, message)
                self.assertFalse(result["ok"])
                self.assertIn("payment key", result["error"])
                backend.assert_not_called()
                ttl.assert_not_called()

    def test_provider_grant_rpc_failure_is_not_an_unlimited_grant(self):
        self.grant_rpc.side_effect = ChainError("unavailable")
        with patch("gateway.p2p.ensure_gateway_readiness"), patch("gateway.p2p.call_gateway") as backend:
            result = handle_infer(self.config, self.message())
        self.assertFalse(result["ok"])
        self.assertIn("could not be verified", result["error"])
        backend.assert_not_called()


class V9SubmitterTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RelayV9SecurityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        _, envelope = self.fixture.run_request()
        self.prepared = prepare_v9_relay_settlement(
            envelope["signed_receipt"], owner=self.fixture.key_address, expected_chain_id=11155111,
            expected_contract=self.fixture.contract, expected_relay=self.fixture.relay_payout,
            expected_relay_signer=self.fixture.relay_signer,
        )
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.outbox = RelaySettlementOutbox(Path(temp.name) / "outbox.sqlite3")
        self.submitter = RelaySettlementSubmitter(
            outbox=self.outbox, rpc_url="http://offline.invalid", private_key="0x" + "44" * 32,
            expected_chain_id=11155111, expected_contract=self.fixture.contract, settlement_version=9,
            batch_encoder=chain_v9.encode_signed_batch_tuples,
        )
        self.outbox.enqueue(self.prepared)
        self.tx_hash = "0x" + "bc" * 32
        self.outbox.mark_submitted(self.prepared.key, self.tx_hash)
        self.receipt = {
            "status": "0x1", "transactionHash": self.tx_hash,
            "logs": [{"address": self.fixture.contract, "topics": [chain_v9.RECEIPT_ESCROWED_TOPIC,
                self.prepared.payload["settlement_key"], self.prepared.session_id,
                "0x" + self.fixture.key_address[2:].rjust(64, "0")],
                "data": "0x" + self.fixture.provider_payout[2:].rjust(64, "0") + f"{2200:064x}" + f"{int(time.time()) + 600:064x}"}],
        }

    def reconcile(self):
        with patch("gateway.session_relayer.rpc_call", return_value=self.receipt):
            self.submitter._wait_for_receipt([self.prepared.key], self.tx_hash)

    def test_confirmed_transaction_is_escrowed_never_earned(self):
        self.reconcile()
        self.assertEqual(self.outbox.status(self.prepared.key), "escrowed")
        status = self.submitter.public_status(self.prepared.session_id, key_address=self.fixture.key_address)
        self.assertEqual(status["status"], "escrowed")
        self.assertNotIn("claimable", status)
        self.assertIsNone(self.submitter.public_status(self.prepared.session_id, key_address=self.fixture.provider_payout))

    def test_missing_wrong_contract_or_wrong_fee_event_cannot_confirm(self):
        original = copy.deepcopy(self.receipt)
        for change in ("missing", "contract", "fee", "owner", "tx"):
            self.receipt = copy.deepcopy(original)
            if change == "missing":
                self.receipt["logs"] = []
            elif change == "contract":
                self.receipt["logs"][0]["address"] = "0x" + "01" * 20
            elif change == "fee":
                self.receipt["logs"][0]["data"] = "0x" + self.fixture.provider_payout[2:].rjust(64, "0") + f"{2201:064x}" + f"{1234:064x}"
            elif change == "owner":
                self.receipt["logs"][0]["topics"][3] = "0x" + "00" * 12 + "01" * 20
            else:
                self.receipt["transactionHash"] = "0x" + "00" * 32
            with self.subTest(change=change), self.assertRaises(RelaySettlementError):
                self.reconcile()
            self.assertEqual(self.outbox.status(self.prepared.key), "submitted")

    def test_v8_worker_cannot_process_v9_durable_rows(self):
        self.submitter.settlement_version = 8
        with patch("gateway.session_relayer.rpc_call") as rpc, self.assertRaises(RelaySettlementError):
            self.submitter._process(self.outbox.next_batch())
        rpc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
