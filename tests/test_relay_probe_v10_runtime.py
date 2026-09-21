from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway import chain_v10 as v, relay
from gateway.chain import channel_to_hash
from gateway.identity import create_identity
from gateway.relay_incidents import RelayIncidentStore
from gateway.relay_integrity import provider_response_hash
from gateway.relay_probe import RelayProbeStore, VerifiedProbeResponse
from gateway.relay_probe_runtime import (
    ProbeBudgetStore, RelayProbeRuntime, RelayProbeRuntimeError, _v10_channel_map,
)
from tests.test_chain_v9 import address, digest, key, signer
from tests.test_v10_relay_runtime import config


class V10FundedProbeRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.now = int(time.time())
        self.contract = address(50)
        self.channel_config = config(self.now)
        self.channel_config["channel"] = channel_to_hash("codex")
        self.channel_id = v.channel_id_for(self.channel_config, chain_id=31337, verifying_contract=self.contract)
        self.channel = {
            **self.channel_config, "channel_id": self.channel_id, "closed": False,
            "settled_max_fee": 0, "credit_remaining": 20_000, "stake_remaining": 20_000,
            "block_hash": digest(99), "block_number": 500, "head_timestamp": self.now,
        }
        identity = create_identity()
        peer = {
            "peer_id": "provider-v10", "public_key": "", "payment_address": signer(22),
            "model": "gpt-5.6-sol", "models": ["gpt-5.6-sol"], "channel": "codex",
            "settlement": {"version": 10, "chain_id": 31337, "contract": self.contract,
                "pricing_version": 1, "pricing_hash": self.channel_config["pricing_hash"],
                "provider_signer": signer(2)},
        }
        session = relay.RelayProviderSession(peer_id=peer["peer_id"], peer=peer, last_seen=self.now)
        probes = RelayProbeStore(str(root / "probes.sqlite3"))
        incidents = RelayIncidentStore(str(root / "incidents.sqlite3"))
        self.addCleanup(probes.close)
        self.addCleanup(incidents.close)
        self.state = SimpleNamespace(
            settlement_version=10, settlement_chain_id=31337, settlement_contract=self.contract,
            settlement_rpc_url="https://rpc.invalid", payment_address=signer(3),
            attestation_address=signer(3), attestation_private_keys={signer(3): key(3)},
            settlement_private_key=None, _settlement_submitter=SimpleNamespace(address=signer(8)),
            _probe_store=probes, _incident_store=incidents, _scheduler_identity=identity,
            providers={session.peer_id: session}, lock=threading.RLock(), _risk_lock=threading.RLock(),
            _risk_storage_failed=False, _emergency_quarantine=set(), _provider_affinity={},
        )
        self.budget = ProbeBudgetStore(str(root / "budget.sqlite3"))
        self.addCleanup(self.budget.close)
        self.runtime = RelayProbeRuntime(
            self.state, sponsor_key=key(1), max_fee_units=100, daily_budget_units=200,
            budget=self.budget, interval_seconds=60, timeout_seconds=20,
            v10_channels={"provider-v10": self.channel_id},
        )
        self.addCleanup(self.runtime.close)

    def _response(self, _state, _path, body, payment, **kwargs):
        response = {
            "ok": True, "request_id": payment["authorization"]["request_id"],
            "endpoint": "responses", "model": body["model"], "output_text": "{\"ok\":true}",
            "usage": {"input_tokens": 2, "output_tokens": 2},
            "raw": {"output_text": "{\"ok\":true}", "usage": {"input_tokens": 2, "output_tokens": 2}},
        }
        dispatch = v.build_relay_dispatch(authorization_payload=payment, relay_private_key=key(3))
        signed = v.build_provider_receipt(
            provider_private_key=key(2), dispatch_payload=dispatch,
            response_hash=provider_response_hash(response), input_tokens=2, output_tokens=2,
            actual_fee=100, channel=self.channel,
        )
        response["settlement_v10"] = signed
        return response["raw"], {"signed_receipt": signed, "audit_provider_response": response,
                                "audit_provider_id": kwargs["audit_provider_id"]}

    def test_v10_probe_uses_preapproved_channel_and_persists_verified_receipt(self):
        envelope = {"input": "Return JSON", "max_output_tokens": 32, "nonce": "a" * 48}
        with patch("gateway.reserved_execution.confirmed_channel_snapshot", return_value=self.channel), \
                patch("gateway.relay.relay_v7_openai", side_effect=self._response) as dispatch:
            result = self.runtime.dispatch("provider-v10", envelope, 10)
        self.assertIsInstance(result, VerifiedProbeResponse)
        self.assertEqual(dispatch.call_count, 1)
        saved = self.budget.get_receipt(result.receipt_hash)
        self.assertEqual(saved["channel_id"], self.channel_id)
        self.assertEqual(saved["payment"]["protocol_version"], 10)

    def test_v10_probe_fails_closed_on_channel_binding_and_does_not_dispatch(self):
        envelope = {"input": "Return JSON", "max_output_tokens": 32, "nonce": "b" * 48}
        wrong = {**self.channel, "provider_signer": signer(4)}
        with patch("gateway.reserved_execution.confirmed_channel_snapshot", return_value=wrong), \
                patch("gateway.relay.relay_v7_openai") as dispatch, \
                self.assertRaisesRegex(RelayProbeRuntimeError, "bound to another"):
            self.runtime.dispatch("provider-v10", envelope, 10)
        dispatch.assert_not_called()
        self.assertEqual(self.budget.reserved_units(self.runtime.scope), 0)

    def test_v10_map_rejects_duplicate_or_noncanonical_channels(self):
        path = Path(self.directory.name) / "channels.json"
        path.write_text('{"schema":"mycomesh.v10.probe-channels.v1","channels":{"a":"0x' + '11' * 32 + '","b":"0x' + '11' * 32 + '"}}')
        path.chmod(0o600)
        with self.assertRaisesRegex(RelayProbeRuntimeError, "duplicate"):
            _v10_channel_map(str(path))
        path.write_text('{"schema":"mycomesh.v10.probe-channels.v1","channels":{"a":"' + '11' * 32 + '"}}')
        with self.assertRaises(RelayProbeRuntimeError):
            _v10_channel_map(str(path))


if __name__ == "__main__":
    unittest.main()
