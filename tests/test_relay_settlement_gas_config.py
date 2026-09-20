"""Settlement admission must retain its configured gas floor after recreation."""
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gateway.chain import parse_private_key, private_key_to_address
from gateway.relay import RelayError, RelayState
from gateway.session_relayer import RelaySettlementError


class RelaySettlementGasConfigTests(unittest.TestCase):
    setting = "MYCOMESH_RELAY_SETTLEMENT_GAS_PER_RECEIPT"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        # Explicit fixture environment keeps deployment-only paths/allowlists out.
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def state(self, **options):
        attestation_key = "0x" + "22" * 32
        attestation_address = private_key_to_address(parse_private_key(attestation_key))
        return RelayState(
            settlement_version=9,
            payment_address="0x" + "bb" * 20,
            attestation_address=attestation_address,
            attestation_private_keys={attestation_address: attestation_key},
            settlement_private_key="0x" + "44" * 32,
            settlement_rpc_url="http://offline.invalid",
            settlement_chain_id=11155111,
            settlement_contract="0x" + "cc" * 20,
            settlement_db_path=str(self.directory / "outbox.sqlite3"),
            usage_state_path=str(self.directory / "usage.json"),
            **options,
        )

    def healthy(self, submitter):
        def rpc(_url, method, _params, _timeout):
            if method == "eth_chainId":
                return hex(11155111)
            if method == "eth_getBalance":
                return hex(2_500_000_000_000_000)
            if method == "eth_gasPrice":
                return hex(2_000_000_000)
            if method == "eth_getBlockByNumber":
                return {"baseFeePerGas": "0x0", "timestamp": hex(int(time.time()))}
            raise AssertionError(f"unexpected RPC method: {method}")

        submitter._thread = SimpleNamespace(is_alive=lambda: True)
        with patch("gateway.session_relayer.rpc_call", side_effect=rpc):
            submitter.refresh_health()

    def test_default_keeps_existing_admission_budget(self):
        state = self.state()
        self.assertEqual(state.settlement_gas_per_receipt, 250_000)
        submitter = state._settlement_submitter
        self.assertIsNotNone(submitter)
        self.healthy(submitter)
        self.assertEqual(submitter.snapshot()["gas_per_receipt"], 250_000)
        self.assertEqual(submitter.snapshot()["gas_capacity_remaining"], 3)

    def test_configured_floor_survives_new_instance_and_limits_admission(self):
        with patch.dict(os.environ, {self.setting: "750000"}):
            first = self.state()._settlement_submitter
            self.assertEqual(first.gas_per_receipt, 750_000)
            first.gas_per_receipt = 950_000  # A previous worker learned a higher estimate.
            restarted = self.state()._settlement_submitter
        self.assertIsNot(first, restarted)
        self.healthy(restarted)
        self.assertEqual(restarted.snapshot()["gas_per_receipt"], 750_000)
        self.assertEqual(restarted.snapshot()["gas_capacity_remaining"], 1)
        reservation = restarted.reserve_admission()
        self.assertTrue(reservation)
        self.assertEqual(restarted.snapshot()["gas_capacity_remaining"], 0)
        with self.assertRaises(RelaySettlementError):
            restarted.reserve_admission()

    def test_invalid_environment_is_rejected_before_outbox_creation(self):
        for value in ("", "garbage", "750000.0", "true", "1e6", "-1", "0", "20999", "5000001", "1" * 100):
            with self.subTest(value=value), patch.dict(os.environ, {self.setting: value}):
                with self.assertRaisesRegex(RelayError, "integer between 21000 and 5000000"):
                    self.state()
                self.assertFalse((self.directory / "outbox.sqlite3").exists())

    def test_direct_configuration_rejects_coercions_and_out_of_range_values(self):
        for value in (None, True, False, "750000", 750000.0, 0, 20_999, 5_000_001):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RelayError, "settlement_gas_per_receipt"):
                    self.state(settlement_gas_per_receipt=value)

    def test_configured_bounds_are_accepted_by_real_submitter(self):
        for value in (21_000, 5_000_000):
            with self.subTest(value=value), patch.dict(os.environ, {self.setting: str(value)}):
                self.assertEqual(self.state()._settlement_submitter.gas_per_receipt, value)


if __name__ == "__main__":
    unittest.main()
