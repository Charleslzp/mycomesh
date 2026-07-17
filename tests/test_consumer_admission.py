from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from gateway.chain import channel_to_hash, parse_private_key, private_key_to_address
from gateway.consumer_admission import (
    ConsumerAdmissionError,
    RELAY_V3_ADMISSION_SCHEMA,
    RelayV3AdmissionConfig,
    verify_relay_v3_admission,
)
from gateway.identity import create_identity
from gateway.reservation import build_evm_session_authorization


class RelayConsumerAdmissionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.session = create_identity()
        self.wallet_private_key = "0x" + "11" * 32
        self.consumer = private_key_to_address(parse_private_key(self.wallet_private_key))
        self.provider = create_identity()
        self.provider_address = "0x" + "22" * 20
        self.settlement = "0x" + "33" * 20
        self.pricing_hash = "0x" + "44" * 32
        self.request_hash = "0x" + "55" * 32
        self.reservation_id = "0x" + "66" * 32
        self.expires_at = self.now + 900
        self.amount = 250_000
        self.authorization = build_evm_session_authorization(
            chain_id=11155111,
            settlement_contract=self.settlement,
            onchain_reservation_id=self.reservation_id,
            consumer_payment_address=self.consumer,
            provider_id=self.provider.peer_id,
            provider_payment_address=self.provider_address,
            channel="codex-standard-v1",
            pricing_hash=self.pricing_hash,
            pricing_version=7,
            request_hash=self.request_hash,
            max_fee_units=self.amount,
            expires_at=self.expires_at,
            settlement_deadline=self.expires_at,
            provider_fallback_allowed=False,
            session_public_key=self.session.public_key,
            wallet_private_key=self.wallet_private_key,
            now=self.now,
        )
        self.admission = {
            "schema": RELAY_V3_ADMISSION_SCHEMA,
            "authorization": self.authorization,
        }
        self.peer = {
            "peer_id": self.provider.peer_id,
            "public_key": self.provider.public_key,
            "payment_address": self.provider_address,
            "network_id": "mycomesh-testnet",
            "channel_id": "codex",
            "channel": "codex-standard-v1",
            "backend_policy": "codex-app-server-postvalidated-v1",
            "settlement": {
                "version": 3,
                "chain_id": 11155111,
                "contract": self.settlement,
                "pricing_version": 7,
                "pricing_hash": self.pricing_hash,
            },
        }
        self.config = RelayV3AdmissionConfig(
            rpc_url="https://rpc.example",
            chain_id=11155111,
            settlement_contract=self.settlement,
            confirmations=6,
        )

    def test_wallet_session_and_confirmed_reservation_are_accepted(self) -> None:
        with self._rpc(self._reservation_words()):
            verified = verify_relay_v3_admission(
                self.admission,
                sender_public_key=self.session.public_key,
                provider_peer=self.peer,
                config=self.config,
                now=self.now,
            )

        self.assertEqual(verified["session_public_key"], self.session.public_key)
        self.assertEqual(verified["onchain_reservation_id"], self.reservation_id)

    def test_envelope_sender_must_match_wallet_authorized_session(self) -> None:
        other = create_identity()
        with self.assertRaisesRegex(ConsumerAdmissionError, "session_public_key mismatch"):
            verify_relay_v3_admission(
                self.admission,
                sender_public_key=other.public_key,
                provider_peer=self.peer,
                config=self.config,
                now=self.now,
            )

    def test_closed_or_mismatched_reservation_is_rejected(self) -> None:
        with self._rpc(self._reservation_words(closed=True)):
            with self.assertRaisesRegex(ConsumerAdmissionError, "closed mismatch"):
                verify_relay_v3_admission(
                    self.admission,
                    sender_public_key=self.session.public_key,
                    provider_peer=self.peer,
                    config=self.config,
                    now=self.now,
                )

    def test_rpc_chain_must_match_the_channel_deployment(self) -> None:
        with patch("gateway.consumer_admission.rpc_int", return_value=1):
            with self.assertRaisesRegex(ConsumerAdmissionError, "chain_id mismatch"):
                verify_relay_v3_admission(
                    self.admission,
                    sender_public_key=self.session.public_key,
                    provider_peer=self.peer,
                    config=self.config,
                    now=self.now,
                )

    def test_rpc_url_must_use_https_without_credentials(self) -> None:
        for rpc_url in (
            "http://rpc.example",
            "https://user:secret@rpc.example",
            "https://rpc.example#fragment",
            " https://rpc.example",
        ):
            with self.subTest(rpc_url=rpc_url), self.assertRaisesRegex(
                ConsumerAdmissionError, "RPC URL"
            ):
                RelayV3AdmissionConfig(
                    rpc_url=rpc_url,
                    chain_id=11155111,
                    settlement_contract=self.settlement,
                )

    def test_provider_must_match_enabled_codex_channel_binding(self) -> None:
        peer = {**self.peer, "channel_id": "claude"}
        with self.assertRaisesRegex(ConsumerAdmissionError, "reserved and not enabled"):
            verify_relay_v3_admission(
                self.admission,
                sender_public_key=self.session.public_key,
                provider_peer=peer,
                config=self.config,
                now=self.now,
            )

    def _rpc(self, reservation: str):
        def rpc_int(_url: str, method: str, _params: list[object], _timeout: float) -> int:
            return 11155111 if method == "eth_chainId" else 10_000

        return _Patches(
            patch("gateway.consumer_admission.rpc_int", side_effect=rpc_int),
            patch("gateway.consumer_admission.rpc_call", return_value="0x"),
            patch("gateway.consumer_admission.call_contract", return_value=reservation),
        )

    def _reservation_words(self, *, closed: bool = False) -> str:
        return "0x" + "".join(
            [
                _word(self.consumer),
                _word(self.provider_address),
                channel_to_hash("codex-standard-v1")[2:],
                self.request_hash[2:],
                _word(7),
                _word(self.expires_at),
                _word(self.amount),
                _word(1 if closed else 0),
                _word(0),
            ]
        )


class _Patches:
    def __init__(self, *patches: object) -> None:
        self.patches = patches

    def __enter__(self) -> None:
        for item in self.patches:
            item.start()

    def __exit__(self, *_args: object) -> None:
        for item in reversed(self.patches):
            item.stop()


def _word(value: str | int) -> str:
    if isinstance(value, int):
        return value.to_bytes(32, "big").hex()
    return value.removeprefix("0x").rjust(64, "0")


if __name__ == "__main__":
    unittest.main()
