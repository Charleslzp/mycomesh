from __future__ import annotations

import unittest
from unittest.mock import patch

from gateway import chain


class RpcTransportRetryTest(unittest.TestCase):
    def test_transport_failure_is_retried_within_the_deadline(self) -> None:
        calls = []

        def once(endpoint, *, method, params, deadline):
            calls.append(endpoint)
            if len(calls) == 1:
                raise chain._RetryableRPCError(f"RPC request failed for {method}: connection failed")
            return "0x10"

        with patch("gateway.chain._rpc_call_once", side_effect=once):
            self.assertEqual(
                chain.rpc_call_retrying_transport("https://rpc.example", "eth_blockNumber", [], 5),
                "0x10",
            )
        self.assertEqual(len(calls), 2)

    def test_json_rpc_errors_are_never_retried(self) -> None:
        calls = []

        def once(endpoint, *, method, params, deadline):
            calls.append(endpoint)
            raise chain.ChainError("RPC error for eth_call: execution reverted")

        with patch("gateway.chain._rpc_call_once", side_effect=once):
            with self.assertRaisesRegex(chain.ChainError, "execution reverted"):
                chain.rpc_call_retrying_transport("https://rpc.example", "eth_call", [], 5)
        self.assertEqual(len(calls), 1)

    def test_persistent_transport_failure_is_raised_after_bounded_attempts(self) -> None:
        calls = []

        def once(endpoint, *, method, params, deadline):
            calls.append(endpoint)
            raise chain._RetryableRPCError(f"RPC request failed for {method}: connection failed")

        with patch("gateway.chain._rpc_call_once", side_effect=once):
            with self.assertRaises(chain.ChainError):
                chain.rpc_call_retrying_transport("https://rpc.example", "eth_chainId", [], 5)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
