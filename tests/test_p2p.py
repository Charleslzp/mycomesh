from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
import unittest
import tempfile
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import gateway.p2p
from gateway.attestation import verify_provider_settlement_attestation
from gateway.identity import create_identity, sign_document, verify_document
from gateway.ledger import stable_hash
from gateway.p2p import (
    ADDRESS_PROOF_PURPOSE,
    DEFAULT_CHANNEL,
    INFERENCE_REQUEST_PURPOSE,
    P2PError,
    ProviderConfig,
    build_gateway_request_body,
    handle_message,
    parse_peer_address,
    remember_peer,
    send_secure_message,
    serve_provider,
    verify_v3_onchain_reservation,
)
from gateway.chain import channel_to_hash, parse_private_key, private_key_to_address
from gateway.pricing import DEFAULT_PRICING
from gateway.reservation import (
    PAYMENT_RESERVATION_PURPOSE,
    build_payment_reservation,
    inference_request_hash,
)


class P2PProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.v3_replay_db = str(Path(self._temporary_directory.name) / "v3-replay.sqlite3")

    def test_serve_provider_preserves_explicit_advertise_port(self) -> None:
        config = SimpleNamespace(advertise_port=19700)
        observed_ports: list[int] = []
        with patch("gateway.p2p.ProviderTCPServer") as server_class:
            server = server_class.return_value.__enter__.return_value
            serve_provider(
                "0.0.0.0",
                9700,
                config,
                on_started=lambda value: observed_ports.append(value.advertise_port),
            )

        self.assertEqual(config.advertise_port, 19700)
        self.assertEqual(observed_ports, [19700])

    def test_v3_provider_requires_chain_configuration(self) -> None:
        common = {
            "peer_id": "peer-test",
            "channel": DEFAULT_CHANNEL,
            "agent_id": "coder",
            "agent_key": "coder-key",
            "gateway_url": "http://127.0.0.1:8000/v1",
            "model": "gpt-5.5",
            "advertise_host": "127.0.0.1",
            "advertise_port": 9700,
            "settlement_version": 3,
        }
        with self.assertRaisesRegex(P2PError, "requires settlement_rpc_url"):
            ProviderConfig(**common)
        with self.assertRaisesRegex(P2PError, "settlement_confirmations"):
            ProviderConfig(
                **common,
                settlement_rpc_url="http://127.0.0.1:8545",
                settlement_contract="0x" + "3" * 40,
                settlement_confirmations=-1,
            )

    def test_v3_provider_rejects_unsafe_authentication_configuration(self) -> None:
        identity = create_identity()
        common = {
            "peer_id": identity.peer_id,
            "channel": DEFAULT_CHANNEL,
            "agent_id": "coder",
            "agent_key": "coder-key",
            "gateway_url": "http://127.0.0.1:8000/v1",
            "model": "gpt-5.5",
            "advertise_host": "127.0.0.1",
            "advertise_port": 9700,
            "identity": identity,
            "payment_address": "0x" + "2" * 40,
            "settlement_rpc_url": "http://127.0.0.1:8545",
            "settlement_contract": "0x" + "3" * 40,
            "settlement_chain_id": 11155111,
            "settlement_version": 3,
            "replay_store_path": self.v3_replay_db,
        }
        for override, error in (
            ({"require_signed_requests": False}, "signed inference requests"),
            ({"require_payment_reservation": False}, "payment reservations"),
            ({"identity": None}, "provider identity"),
            ({"payment_address": None}, "payment_address"),
        ):
            with self.subTest(override=override):
                with self.assertRaisesRegex(P2PError, error):
                    ProviderConfig(**(common | override))

    def test_v3_reservation_is_read_from_confirmed_pinned_chain_block(self) -> None:
        provider_identity = create_identity()
        provider_address = "0x" + "2" * 40
        consumer_address = "0x" + "1" * 40
        contract = "0x" + "3" * 40
        config = ProviderConfig(
            peer_id=provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=provider_identity,
            payment_address=provider_address,
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract=contract,
            settlement_chain_id=11155111,
            settlement_version=3,
            pricing_version=7,
            settlement_confirmations=6,
            replay_store_path=self.v3_replay_db,
        )
        now = int(time.time())
        request_hash = "0x" + stable_hash("request")
        reservation = {
            "onchain_reservation_id": "0x" + "b" * 64,
            "consumer_payment_address": consumer_address,
            "provider_payment_address": provider_address,
            "channel": DEFAULT_CHANNEL,
            "pricing_version": 7,
            "expires_at": now + 120,
            "settlement_deadline": now + 90,
            "max_fee_units": 10_000,
            "request_hash": request_hash,
            "provider_fallback_allowed": False,
        }
        encoded = "0x" + "".join(
            [
                _abi_word(consumer_address),
                _abi_word(provider_address),
                channel_to_hash(DEFAULT_CHANNEL)[2:],
                request_hash[2:],
                _abi_word(7),
                _abi_word(now + 120),
                _abi_word(10_000),
                _abi_word(0),
                _abi_word(0),
            ]
        )

        def fake_rpc_int(_url: str, method: str, _params: list[Any], _timeout: float) -> int:
            return 11155111 if method == "eth_chainId" else 100

        with patch("gateway.chain.rpc_int", side_effect=fake_rpc_int), patch(
            "gateway.chain.call_contract", return_value=encoded
        ) as call:
            onchain = verify_v3_onchain_reservation(config, reservation, now=now)

        self.assertEqual(onchain["amount_units"], 10_000)
        self.assertEqual(call.call_args.kwargs["block_tag"], 94)

        wrong_request = encoded[: 2 + 3 * 64] + ("f" * 64) + encoded[2 + 4 * 64 :]
        with patch("gateway.chain.call_contract", return_value=wrong_request):
            with self.assertRaisesRegex(P2PError, "request_hash mismatch"):
                verify_v3_onchain_reservation(config, reservation, now=now, block_tag=94)
        wrong_fallback_policy = encoded[:-64] + _abi_word(1)
        with patch("gateway.chain.call_contract", return_value=wrong_fallback_policy):
            with self.assertRaisesRegex(P2PError, "provider_fallback_allowed mismatch"):
                verify_v3_onchain_reservation(config, reservation, now=now, block_tag=94)

    def test_v3_reservation_fails_closed_on_chain_or_amount_mismatch(self) -> None:
        provider_identity = create_identity()
        provider_address = "0x" + "2" * 40
        config = ProviderConfig(
            peer_id=provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=provider_identity,
            payment_address=provider_address,
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract="0x" + "3" * 40,
            settlement_chain_id=11155111,
            settlement_version=3,
            replay_store_path=self.v3_replay_db,
        )
        now = int(time.time())
        request_hash = "0x" + stable_hash("request")
        reservation = {
            "onchain_reservation_id": "0x" + "b" * 64,
            "consumer_payment_address": "0x" + "1" * 40,
            "provider_payment_address": provider_address,
            "channel": DEFAULT_CHANNEL,
            "pricing_version": 7,
            "expires_at": now + 120,
            "settlement_deadline": now + 90,
            "max_fee_units": 10_000,
            "request_hash": request_hash,
            "provider_fallback_allowed": False,
        }
        insufficient = "0x" + "".join(
            [
                _abi_word(reservation["consumer_payment_address"]),
                _abi_word(provider_address),
                channel_to_hash(DEFAULT_CHANNEL)[2:],
                request_hash[2:],
                _abi_word(7),
                _abi_word(now + 120),
                _abi_word(9_999),
                _abi_word(0),
                _abi_word(0),
            ]
        )
        with patch("gateway.chain.rpc_int", side_effect=[1, 100]):
            with self.assertRaisesRegex(P2PError, "chain id mismatch"):
                verify_v3_onchain_reservation(config, reservation, now=now)
        with patch("gateway.chain.rpc_int", side_effect=[11155111, 100]), patch(
            "gateway.chain.call_contract", return_value=insufficient
        ):
            with self.assertRaisesRegex(P2PError, "amount is insufficient"):
                verify_v3_onchain_reservation(config, reservation, now=now)

    def test_v3_inference_returns_provider_signed_settlement_evidence(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        consumer_wallet_private_key = "0x" + "1".zfill(64)
        consumer_address = private_key_to_address(parse_private_key(consumer_wallet_private_key))
        provider_address = "0x" + "2" * 40
        pricing_hash = "0x" + "a" * 64
        now = int(time.time())
        expires_at = now + 300
        config = ProviderConfig(
            peer_id=provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=provider_identity,
            authorized_consumers={consumer_identity.public_key},
            payment_address=provider_address,
            pricing_hash=pricing_hash,
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract="0x" + "3" * 40,
            settlement_chain_id=11155111,
            settlement_version=3,
            pricing_version=7,
            settlement_confirmations=6,
            reserve_input_tokens=8,
            reserve_output_tokens=1,
            replay_store_path=self.v3_replay_db,
        )
        request_id = "req-v3-evidence"
        reservation_id = "0x" + "b" * 64
        request_hash = "0x" + inference_request_hash(
            endpoint="responses",
            model="gpt-5.5",
            input_value="Say OK",
            max_output_tokens=1,
        )
        message = {
            "type": "infer",
            "request_id": request_id,
            "channel": DEFAULT_CHANNEL,
            "endpoint": "responses",
            "model": "gpt-5.5",
            "input": "Say OK",
            "payment_reservation": build_payment_reservation(
                request_id=request_id,
                consumer_id="consumer-v3",
                consumer_payment_address=consumer_address,
                provider_id=provider_identity.peer_id,
                provider_payment_address=provider_address,
                channel=DEFAULT_CHANNEL,
                pricing_hash=pricing_hash,
                max_fee_units=100_000,
                signer=consumer_identity,
                expires_at=expires_at,
                settlement_version=3,
                pricing_version=7,
                onchain_reservation_id=reservation_id,
                request_hash=request_hash,
                settlement_deadline=now + 240,
                settlement_chain_id=11155111,
                settlement_contract="0x" + "3" * 40,
                consumer_wallet_private_key=consumer_wallet_private_key,
            ),
        }
        message = sign_document(
            message,
            consumer_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=provider_identity.peer_id,
        )
        encoded = "0x" + "".join(
            [
                _abi_word(consumer_address),
                _abi_word(provider_address),
                channel_to_hash(DEFAULT_CHANNEL)[2:],
                request_hash[2:],
                _abi_word(7),
                _abi_word(expires_at),
                _abi_word(100_000),
                _abi_word(0),
                _abi_word(0),
            ]
        )
        quote_calls: list[list[str]] = []

        def fake_call_contract(
            _rpc_url: str,
            _contract: str,
            signature: str,
            _args: list[str],
            **_kwargs: Any,
        ) -> str:
            if signature == "channelPricingHash(bytes32,uint64)":
                return pricing_hash
            if signature == "reservations(bytes32)":
                return encoded
            if signature == "quote(bytes32,uint64,uint256,uint256)":
                quote_calls.append(_args)
                return "0x" + _abi_word(2_000)
            raise AssertionError(signature)

        with patch("gateway.chain.rpc_int", side_effect=[11155111, 100]), patch(
            "gateway.chain.call_contract", side_effect=fake_call_contract
        ), patch("gateway.chain.rpc_call", return_value="0x"
        ), patch.object(
            gateway.p2p,
            "call_gateway",
            return_value={"output_text": "OK", "usage": {"input_tokens": 1, "output_tokens": 1}},
        ) as gateway_call:
            response = handle_message(config, message)

        self.assertTrue(response["ok"])
        self.assertEqual(gateway_call.call_args.kwargs["body"]["max_output_tokens"], 1)
        self.assertEqual(quote_calls[0][-2:], ["8", "1"])
        unsigned_response = verify_document(
            response,
            purpose=gateway.p2p.PROVIDER_RESPONSE_PURPOSE,
            audience=consumer_identity.public_key,
        )
        evidence = verify_provider_settlement_attestation(
            unsigned_response["provider_settlement_attestation"],
            provider_public_key=provider_identity.public_key,
            consumer_public_key=consumer_identity.public_key,
        )
        self.assertEqual(evidence["onchain_reservation_id"], reservation_id)
        self.assertEqual(evidence["pricing_version"], 7)
        self.assertEqual(evidence["settlement_version"], 3)

    def test_v3_inference_rejects_short_settlement_window_before_execution(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        consumer_wallet_private_key = "0x" + "1".zfill(64)
        consumer_address = private_key_to_address(parse_private_key(consumer_wallet_private_key))
        provider_address = "0x" + "2" * 40
        pricing_hash = "0x" + "a" * 64
        now = int(time.time())
        expires_at = now + 300
        request_id = "req-v3-short-deadline"
        request_hash = "0x" + inference_request_hash(
            endpoint="responses",
            model="gpt-5.5",
            input_value="Say OK",
            max_output_tokens=1,
        )
        config = ProviderConfig(
            peer_id=provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=provider_identity,
            authorized_consumers={consumer_identity.public_key},
            payment_address=provider_address,
            pricing_hash=pricing_hash,
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract="0x" + "3" * 40,
            settlement_chain_id=11155111,
            settlement_version=3,
            pricing_version=7,
            reserve_input_tokens=8,
            reserve_output_tokens=1,
            replay_store_path=self.v3_replay_db,
        )
        message = sign_document(
            {
                "type": "infer",
                "request_id": request_id,
                "channel": DEFAULT_CHANNEL,
                "endpoint": "responses",
                "model": "gpt-5.5",
                "input": "Say OK",
                "payment_reservation": build_payment_reservation(
                    request_id=request_id,
                    consumer_id="consumer-v3",
                    consumer_payment_address=consumer_address,
                    provider_id=provider_identity.peer_id,
                    provider_payment_address=provider_address,
                    channel=DEFAULT_CHANNEL,
                    pricing_hash=pricing_hash,
                    max_fee_units=100_000,
                    signer=consumer_identity,
                    expires_at=expires_at,
                    settlement_version=3,
                    pricing_version=7,
                    onchain_reservation_id="0x" + "c" * 64,
                    request_hash=request_hash,
                    settlement_deadline=now + 120,
                    settlement_chain_id=11155111,
                    settlement_contract="0x" + "3" * 40,
                    consumer_wallet_private_key=consumer_wallet_private_key,
                ),
            },
            consumer_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=provider_identity.peer_id,
        )

        def fake_call_contract(
            _rpc_url: str,
            _contract: str,
            signature: str,
            _args: list[str],
            **_kwargs: Any,
        ) -> str:
            if signature == "channelPricingHash(bytes32,uint64)":
                return pricing_hash
            if signature == "quote(bytes32,uint64,uint256,uint256)":
                return "0x" + _abi_word(2_000)
            raise AssertionError(signature)

        with patch("gateway.chain.rpc_int", side_effect=[11155111, 100]), patch(
            "gateway.chain.call_contract", side_effect=fake_call_contract
        ), patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("transaction inclusion buffer", response["error"])
        gateway_call.assert_not_called()

    def test_v3_defaults_to_persistent_replay_store(self) -> None:
        provider_identity = create_identity()
        default_path = str(Path(self._temporary_directory.name) / "default-v3-replay.sqlite3")
        with patch("gateway.p2p.DEFAULT_REPLAY_DB", default_path):
            config = ProviderConfig(
                peer_id=provider_identity.peer_id,
                channel=DEFAULT_CHANNEL,
                agent_id="coder",
                agent_key="coder-key",
                gateway_url="http://127.0.0.1:8000/v1",
                model="gpt-5.5",
                advertise_host="127.0.0.1",
                advertise_port=9700,
                identity=provider_identity,
                payment_address="0x" + "2" * 40,
                settlement_rpc_url="http://127.0.0.1:8545",
                settlement_contract="0x" + "3" * 40,
                settlement_chain_id=11155111,
                settlement_version=3,
            )

        self.assertEqual(config.replay_store_path, default_path)
        self.assertIsNotNone(config._replay_store)
        self.assertTrue(Path(default_path).is_file())

    def test_v3_eip1271_authorization_uses_confirmed_block_and_strict_magic_word(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        consumer_contract = "0x" + "1" * 40
        provider_address = "0x" + "2" * 40
        settlement_contract = "0x" + "3" * 40
        pricing_hash = "0x" + "a" * 64
        now = int(time.time())
        expires_at = now + 900
        request_hash = "0x" + inference_request_hash(
            endpoint="responses",
            model="gpt-5.5",
            input_value="Say OK",
            max_output_tokens=1,
        )
        config = ProviderConfig(
            peer_id=provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=provider_identity,
            payment_address=provider_address,
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract=settlement_contract,
            settlement_chain_id=11155111,
            settlement_version=3,
            pricing_version=7,
            replay_store_path=self.v3_replay_db,
        )
        reservation = build_payment_reservation(
            request_id="req-eip1271",
            consumer_id="consumer-contract",
            consumer_payment_address=consumer_contract,
            provider_id=provider_identity.peer_id,
            provider_payment_address=provider_address,
            channel=DEFAULT_CHANNEL,
            pricing_hash=pricing_hash,
            max_fee_units=100_000,
            signer=consumer_identity,
            expires_at=expires_at,
            settlement_version=3,
            pricing_version=7,
            onchain_reservation_id="0x" + "b" * 64,
            request_hash=request_hash,
            settlement_deadline=now + 600,
            settlement_chain_id=11155111,
            settlement_contract=settlement_contract,
            session_authorization_signature="0x1234",
            session_authorization_nonce="0x" + "9" * 64,
        )
        calls: list[tuple[str, list[Any]]] = []

        def accepted_rpc_call(
            _url: str,
            method: str,
            params: list[Any],
            _timeout: float,
        ) -> str:
            calls.append((method, params))
            if method == "eth_getCode":
                return "0x6000"
            if method == "eth_call":
                return "0x1626ba7e" + "0" * 56
            raise AssertionError(method)

        with patch("gateway.chain.rpc_call", side_effect=accepted_rpc_call):
            gateway.p2p._verify_v3_session_wallet_authorization(
                config,
                reservation,
                block_tag=94,
                now=now,
            )

        self.assertEqual([method for method, _params in calls], ["eth_getCode", "eth_call"])
        self.assertEqual(calls[0][1], [consumer_contract, "0x5e"])
        self.assertEqual(calls[1][1][1], "0x5e")
        self.assertEqual(calls[1][1][0]["from"], settlement_contract)
        self.assertEqual(calls[1][1][0]["to"], consumer_contract)
        self.assertTrue(calls[1][1][0]["data"].startswith("0x1626ba7e"))
        self.assertIn("1234", calls[1][1][0]["data"])

        with patch("gateway.chain.rpc_call", side_effect=["0x6000", "0x1626ba7e"]):
            with self.assertRaisesRegex(P2PError, "rejected"):
                gateway.p2p._verify_v3_session_wallet_authorization(
                    config,
                    reservation,
                    block_tag=94,
                    now=now,
                )

        for malformed_code in (None, "6000", "0X6000", "0x0", "0xzz", "0x60 00"):
            with self.subTest(malformed_code=malformed_code), patch(
                "gateway.chain.rpc_call", return_value=malformed_code
            ) as rpc:
                with self.assertRaisesRegex(P2PError, "malformed hex data"):
                    gateway.p2p._verify_v3_session_wallet_authorization(
                        config,
                        reservation,
                        block_tag=94,
                        now=now,
                    )
                self.assertEqual(rpc.call_count, 1)

        with patch("gateway.chain.rpc_call", return_value="0x00") as rpc:
            with self.assertRaisesRegex(P2PError, "EOA session authorization signature"):
                gateway.p2p._verify_v3_session_wallet_authorization(
                    config,
                    reservation,
                    block_tag=94,
                    now=now,
                )
        self.assertEqual(rpc.call_count, 1)

    def test_v3_dual_replay_claim_rolls_back_when_session_nonce_is_consumed(self) -> None:
        provider_identity = create_identity()
        config = ProviderConfig(
            peer_id=provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=provider_identity,
            payment_address="0x" + "2" * 40,
            settlement_rpc_url="http://127.0.0.1:8545",
            settlement_contract="0x" + "3" * 40,
            settlement_chain_id=11155111,
            settlement_version=3,
            replay_store_path=self.v3_replay_db,
        )
        now = int(time.time())
        consumer = "0x" + "1" * 40
        first_nonce = "0x" + "9" * 64
        session_key = f"11155111:{config.settlement_contract}:{consumer}:{first_nonce}"
        assert config._replay_store is not None
        config._replay_store.remember(
            "p2p.v3.session.authorization",
            session_key,
            300,
            now=now,
        )
        reservation = {
            "settlement_chain_id": 11155111,
            "settlement_contract": config.settlement_contract,
            "onchain_reservation_id": "0x" + "b" * 64,
            "consumer_payment_address": consumer,
            "expires_at": now + 300,
            "evm_session_authorization": {"nonce": first_nonce},
        }

        request_key = "consumer-public-key:req-atomic-rollback"
        payment_nonce_key = "consumer-public-key:" + "a" * 32
        with self.assertRaisesRegex(P2PError, "already been consumed"):
            gateway.p2p._claim_v3_authorization(
                config,
                reservation,
                now=now,
                request_key=request_key,
                payment_nonce_key=payment_nonce_key,
                replay_ttl=300,
            )

        config._replay_store.remember("p2p.infer.request", request_key, 300, now=now)
        config._replay_store.remember("p2p.payment.reservation", payment_nonce_key, 300, now=now)

        reservation["evm_session_authorization"] = {"nonce": "0x" + "8" * 64}
        gateway.p2p._claim_v3_authorization(config, reservation, now=now)
        with self.assertRaisesRegex(P2PError, "already been consumed"):
            gateway.p2p._claim_v3_authorization(config, reservation, now=now)

    def test_v3_concurrent_same_reservation_enters_upstream_once(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        wallet_private_key = "0x" + "1".zfill(64)
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        provider_address = "0x" + "2" * 40
        contract = "0x" + "3" * 40
        pricing_hash = "0x" + "a" * 64
        expires_at = int(time.time()) + 900
        reservation_id = "0x" + "b" * 64
        configs = [
            _v3_provider_config(
                provider_identity,
                consumer_identity,
                replay_store_path=self.v3_replay_db,
                provider_address=provider_address,
                pricing_hash=pricing_hash,
                settlement_contract=contract,
            )
            for _index in range(2)
        ]
        first_message = _signed_v3_infer(
            consumer_identity,
            configs[0],
            wallet_private_key=wallet_private_key,
            request_id="req-v3-race-a",
            reservation_id=reservation_id,
            expires_at=expires_at,
        )
        authorization = first_message["payment_reservation"]["evm_session_authorization"]
        second_message = _signed_v3_infer(
            consumer_identity,
            configs[1],
            wallet_private_key=wallet_private_key,
            request_id="req-v3-race-b",
            reservation_id=reservation_id,
            expires_at=expires_at,
            evm_session_authorization=authorization,
        )
        encoded = _v3_reservation_words(
            consumer_address=consumer_address,
            provider_address=provider_address,
            request_hash=first_message["payment_reservation"]["request_hash"],
            pricing_version=7,
            expires_at=expires_at,
            amount_units=100_000,
        )

        with patch("gateway.chain.rpc_int", side_effect=_v3_rpc_int), patch(
            "gateway.chain.call_contract",
            side_effect=_v3_call_contract(pricing_hash, encoded),
        ), patch("gateway.chain.rpc_call", return_value="0x"), patch.object(
            gateway.p2p,
            "call_gateway",
            return_value={"output_text": "OK", "usage": {"input_tokens": 1, "output_tokens": 1}},
        ) as gateway_call:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(handle_message, configs[0], first_message),
                    executor.submit(handle_message, configs[1], second_message),
                ]
                responses = [future.result(timeout=10) for future in futures]

        self.assertEqual(sum(bool(response["ok"]) for response in responses), 1)
        rejected = next(response for response in responses if not response["ok"])
        self.assertIn("already been consumed", rejected["error"])
        self.assertEqual(gateway_call.call_count, 1)

    def test_v3_upstream_failure_remains_consumed_after_restart(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        wallet_private_key = "0x" + "1".zfill(64)
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        provider_address = "0x" + "2" * 40
        contract = "0x" + "3" * 40
        pricing_hash = "0x" + "a" * 64
        expires_at = int(time.time()) + 900
        reservation_id = "0x" + "c" * 64
        first_config = _v3_provider_config(
            provider_identity,
            consumer_identity,
            replay_store_path=self.v3_replay_db,
            provider_address=provider_address,
            pricing_hash=pricing_hash,
            settlement_contract=contract,
        )
        first_message = _signed_v3_infer(
            consumer_identity,
            first_config,
            wallet_private_key=wallet_private_key,
            request_id="req-v3-upstream-a",
            reservation_id=reservation_id,
            expires_at=expires_at,
        )
        second_config = _v3_provider_config(
            provider_identity,
            consumer_identity,
            replay_store_path=self.v3_replay_db,
            provider_address=provider_address,
            pricing_hash=pricing_hash,
            settlement_contract=contract,
        )
        second_message = _signed_v3_infer(
            consumer_identity,
            second_config,
            wallet_private_key=wallet_private_key,
            request_id="req-v3-upstream-b",
            reservation_id=reservation_id,
            expires_at=expires_at,
        )
        encoded = _v3_reservation_words(
            consumer_address=consumer_address,
            provider_address=provider_address,
            request_hash=first_message["payment_reservation"]["request_hash"],
            pricing_version=7,
            expires_at=expires_at,
            amount_units=100_000,
        )

        with patch("gateway.chain.rpc_int", side_effect=_v3_rpc_int), patch(
            "gateway.chain.call_contract",
            side_effect=_v3_call_contract(pricing_hash, encoded),
        ), patch("gateway.chain.rpc_call", return_value="0x"), patch.object(
            gateway.p2p,
            "call_gateway",
            side_effect=RuntimeError("upstream failed"),
        ) as gateway_call:
            first_response = handle_message(first_config, first_message)
            second_response = handle_message(second_config, second_message)

        self.assertFalse(first_response["ok"])
        self.assertFalse(first_response["retryable"])
        self.assertIn("upstream failed", first_response["error"])
        self.assertFalse(second_response["ok"])
        self.assertIn("already been consumed", second_response["error"])
        self.assertEqual(gateway_call.call_count, 1)

    def test_v3_reservation_signature_is_prechecked_before_capacity_or_rpc(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        config = _v3_provider_config(
            provider_identity,
            consumer_identity,
            replay_store_path=self.v3_replay_db,
            provider_address="0x" + "2" * 40,
            pricing_hash="0x" + "a" * 64,
            settlement_contract="0x" + "3" * 40,
        )
        message = _signed_v3_infer(
            consumer_identity,
            config,
            wallet_private_key="0x" + "1".zfill(64),
            request_id="req-v3-offline-precheck",
            reservation_id="0x" + "d" * 64,
            expires_at=int(time.time()) + 900,
        )
        unsigned = {key: value for key, value in message.items() if key != "signature"}
        reservation = dict(unsigned["payment_reservation"])
        reservation_signature = dict(reservation["signature"])
        reservation_signature["signature"] = "00" * 64
        reservation["signature"] = reservation_signature
        unsigned["payment_reservation"] = reservation
        forged = sign_document(
            unsigned,
            consumer_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=config.peer_id,
        )

        self.assertTrue(config._semaphore.acquire(blocking=False))
        try:
            with patch("gateway.chain.rpc_int") as rpc_int, patch(
                "gateway.chain.call_contract"
            ) as call_contract, patch("gateway.chain.rpc_call") as rpc_call:
                response = handle_message(config, forged)
        finally:
            config._semaphore.release()

        self.assertFalse(response["ok"])
        self.assertIn("invalid payment reservation signature", response["error"])
        self.assertNotIn("concurrency", response["error"])
        rpc_int.assert_not_called()
        call_contract.assert_not_called()
        rpc_call.assert_not_called()

    def test_v3_latest_state_rejects_reservation_closed_after_confirmed_block(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        wallet_private_key = "0x" + "1".zfill(64)
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        provider_address = "0x" + "2" * 40
        pricing_hash = "0x" + "a" * 64
        config = _v3_provider_config(
            provider_identity,
            consumer_identity,
            replay_store_path=self.v3_replay_db,
            provider_address=provider_address,
            pricing_hash=pricing_hash,
            settlement_contract="0x" + "3" * 40,
        )
        expires_at = int(time.time()) + 900
        message = _signed_v3_infer(
            consumer_identity,
            config,
            wallet_private_key=wallet_private_key,
            request_id="req-v3-latest-closed",
            reservation_id="0x" + "e" * 64,
            expires_at=expires_at,
        )
        confirmed = _v3_reservation_words(
            consumer_address=consumer_address,
            provider_address=provider_address,
            request_hash=message["payment_reservation"]["request_hash"],
            pricing_version=7,
            expires_at=expires_at,
            amount_units=100_000,
        )
        latest_closed = confirmed[: 2 + 7 * 64] + _abi_word(1) + confirmed[2 + 8 * 64 :]

        def fake_call_contract(
            _rpc_url: str,
            _contract: str,
            signature: str,
            _args: list[str],
            **kwargs: Any,
        ) -> str:
            if signature == "channelPricingHash(bytes32,uint64)":
                return pricing_hash
            if signature == "quote(bytes32,uint64,uint256,uint256)":
                return "0x" + _abi_word(2_000)
            if signature == "reservations(bytes32)":
                return latest_closed if kwargs.get("block_tag") == "latest" else confirmed
            raise AssertionError(signature)

        with patch("gateway.chain.rpc_int", side_effect=_v3_rpc_int), patch(
            "gateway.chain.call_contract", side_effect=fake_call_contract
        ), patch("gateway.chain.rpc_call") as wallet_rpc, patch.object(
            gateway.p2p, "call_gateway"
        ) as gateway_call:
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("closed at latest block", response["error"])
        wallet_rpc.assert_not_called()
        gateway_call.assert_not_called()

    def test_v3_rechecks_deadline_after_wallet_rpc_before_claim(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        wallet_private_key = "0x" + "1".zfill(64)
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        provider_address = "0x" + "2" * 40
        pricing_hash = "0x" + "a" * 64
        config = _v3_provider_config(
            provider_identity,
            consumer_identity,
            replay_store_path=self.v3_replay_db,
            provider_address=provider_address,
            pricing_hash=pricing_hash,
            settlement_contract="0x" + "3" * 40,
        )
        expires_at = int(time.time()) + 900
        message = _signed_v3_infer(
            consumer_identity,
            config,
            wallet_private_key=wallet_private_key,
            request_id="req-v3-final-deadline",
            reservation_id="0x" + "f" * 64,
            expires_at=expires_at,
        )
        encoded = _v3_reservation_words(
            consumer_address=consumer_address,
            provider_address=provider_address,
            request_hash=message["payment_reservation"]["request_hash"],
            pricing_version=7,
            expires_at=expires_at,
            amount_units=100_000,
        )
        events: list[str] = []

        def validate_deadline(_config: ProviderConfig, _reservation: dict[str, Any]) -> None:
            events.append("deadline")
            if events.count("deadline") == 2:
                raise P2PError("deadline became unsafe after wallet RPC")

        def verify_wallet(*_args: Any, **_kwargs: Any) -> None:
            events.append("wallet")

        with patch("gateway.chain.rpc_int", side_effect=_v3_rpc_int), patch(
            "gateway.chain.call_contract", side_effect=_v3_call_contract(pricing_hash, encoded)
        ), patch.object(
            gateway.p2p, "_validate_settlement_window", side_effect=validate_deadline
        ), patch.object(
            gateway.p2p, "_verify_v3_session_wallet_authorization", side_effect=verify_wallet
        ), patch.object(gateway.p2p, "_claim_v3_authorization") as claim, patch.object(
            gateway.p2p, "call_gateway"
        ) as gateway_call:
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("deadline became unsafe", response["error"])
        self.assertEqual(events, ["deadline", "wallet", "deadline"])
        claim.assert_not_called()
        gateway_call.assert_not_called()

    def test_v3_capacity_rejection_does_not_consume_authorization(self) -> None:
        consumer_identity = create_identity()
        provider_identity = create_identity()
        wallet_private_key = "0x" + "1".zfill(64)
        consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
        provider_address = "0x" + "2" * 40
        pricing_hash = "0x" + "a" * 64
        expires_at = int(time.time()) + 900
        config = _v3_provider_config(
            provider_identity,
            consumer_identity,
            replay_store_path=self.v3_replay_db,
            provider_address=provider_address,
            pricing_hash=pricing_hash,
            settlement_contract="0x" + "3" * 40,
        )
        message = _signed_v3_infer(
            consumer_identity,
            config,
            wallet_private_key=wallet_private_key,
            request_id="req-v3-capacity",
            reservation_id="0x" + "d" * 64,
            expires_at=expires_at,
        )
        encoded = _v3_reservation_words(
            consumer_address=consumer_address,
            provider_address=provider_address,
            request_hash=message["payment_reservation"]["request_hash"],
            pricing_version=7,
            expires_at=expires_at,
            amount_units=100_000,
        )
        self.assertTrue(config._semaphore.acquire(blocking=False))
        try:
            rejected = handle_message(config, message)
        finally:
            config._semaphore.release()

        self.assertFalse(rejected["ok"])
        self.assertTrue(rejected["retryable"])
        self.assertIn("concurrency", rejected["error"])

        with patch("gateway.chain.rpc_int", side_effect=_v3_rpc_int), patch(
            "gateway.chain.call_contract",
            side_effect=_v3_call_contract(pricing_hash, encoded),
        ), patch("gateway.chain.rpc_call", return_value="0x"), patch.object(
            gateway.p2p,
            "call_gateway",
            return_value={"output_text": "OK", "usage": {"input_tokens": 1, "output_tokens": 1}},
        ) as gateway_call:
            accepted = handle_message(config, message)

        self.assertTrue(accepted["ok"])
        self.assertEqual(gateway_call.call_count, 1)

    def test_unexpected_verification_exception_releases_capacity(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            require_signed_requests=False,
            require_payment_reservation=False,
        )
        message = {
            "type": "infer",
            "request_id": "req-unexpected-verification",
            "channel": DEFAULT_CHANNEL,
            "endpoint": "responses",
            "model": "gpt-5.5",
            "input": "Say OK",
        }
        with patch.object(
            gateway.p2p,
            "verify_inference_request",
            side_effect=RuntimeError("unexpected verification failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected verification failure"):
                handle_message(config, message)

        self.assertTrue(config._semaphore.acquire(blocking=False))
        config._semaphore.release()

    def test_parse_peer_address_accepts_tcp_uri_and_host_port(self) -> None:
        first = parse_peer_address("tcp://127.0.0.1:9700")
        second = parse_peer_address("localhost:9701")

        self.assertEqual(first.host, "127.0.0.1")
        self.assertEqual(first.port, 9700)
        self.assertEqual(second.uri, "tcp://localhost:9701")

    def test_provider_config_normalizes_payment_address(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            payment_address="0x00000000000000000000000000000000000000A2",
        )

        self.assertEqual(config.payment_address, "0x00000000000000000000000000000000000000a2")

    def test_provider_config_rejects_invalid_token_reserve_limits(self) -> None:
        common = {
            "peer_id": "peer-test",
            "channel": DEFAULT_CHANNEL,
            "agent_id": "coder",
            "agent_key": "coder-key",
            "gateway_url": "http://127.0.0.1:8000/v1",
            "model": "gpt-5.5",
            "advertise_host": "127.0.0.1",
            "advertise_port": 9700,
        }
        for field, value in (
            ("reserve_input_tokens", 0),
            ("reserve_input_tokens", True),
            ("reserve_input_tokens", gateway.p2p.MAX_RESERVE_INPUT_TOKENS + 1),
            ("reserve_output_tokens", -1),
            ("reserve_output_tokens", 1.5),
            ("reserve_output_tokens", gateway.p2p.MAX_RESERVE_OUTPUT_TOKENS + 1),
            ("max_connections", 0),
            ("request_read_deadline_seconds", float("inf")),
            ("timeout_seconds", gateway.p2p.MAX_P2P_NETWORK_TIMEOUT_SECONDS + 1),
            ("socket_timeout_seconds", float("nan")),
        ):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(P2PError, field):
                ProviderConfig(**common, **{field: value})

    def test_provider_gateway_defaults_to_loopback_and_remote_requires_https_opt_in(self) -> None:
        common = {
            "peer_id": "peer-test",
            "channel": DEFAULT_CHANNEL,
            "agent_id": "coder",
            "agent_key": "coder-key",
            "model": "gpt-5.5",
            "advertise_host": "127.0.0.1",
            "advertise_port": 9700,
        }
        with self.assertRaisesRegex(P2PError, "loopback"):
            ProviderConfig(gateway_url="https://10.0.0.8/v1", **common)
        with self.assertRaisesRegex(P2PError, "https"):
            ProviderConfig(
                gateway_url="http://10.0.0.8/v1",
                allow_remote_gateway_https=True,
                **common,
            )

        config = ProviderConfig(
            gateway_url="https://10.0.0.8/v1",
            allow_remote_gateway_https=True,
            **common,
        )
        self.assertTrue(config.allow_remote_gateway_https)
        with self.assertRaisesRegex(P2PError, "provider identity"):
            ProviderConfig(
                gateway_url="http://127.0.0.1:8000/v1",
                network_profile="testnet",
                **common,
            )

        identity = create_identity()
        secure_config = ProviderConfig(
            gateway_url="http://127.0.0.1:8000/v1",
            network_profile="testnet",
            identity=identity,
            replay_store_path=self.v3_replay_db,
            **(common | {"peer_id": identity.peer_id}),
        )
        descriptor = gateway.p2p.provider_descriptor(secure_config)
        self.assertTrue(descriptor["address"].startswith("myco+tcp://"))
        self.assertIsInstance(descriptor.get("transport_key"), dict)

    def test_secure_provider_socket_round_trip_uses_signed_transport_binding(self) -> None:
        provider_identity = create_identity()
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id=provider_identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=0,
            identity=provider_identity,
            network_profile="testnet",
            replay_store_path=self.v3_replay_db,
        )

        try:
            server = gateway.p2p.ProviderTCPServer(("127.0.0.1", 0), config)
        except PermissionError:
            self.skipTest("runtime sandbox does not permit local socket listeners")
        with server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                descriptor = gateway.p2p.provider_descriptor(config)
                response = send_secure_message(
                    parse_peer_address(descriptor["address"]),
                    {"type": "ping", "request_id": "secure-round-trip"},
                    timeout=2,
                    sender=consumer_identity,
                    recipient_binding=descriptor["transport_key"],
                    expected_recipient_peer_id=provider_identity.peer_id,
                    expected_recipient_public_key=provider_identity.public_key,
                )
            finally:
                server.shutdown()
                thread.join(timeout=2)

        self.assertEqual(response["type"], "pong")
        self.assertEqual(response["request_id"], "secure-round-trip")
        self.assertEqual(response["peer"]["peer_id"], provider_identity.peer_id)

    def test_provider_transport_key_rotates_with_overlap_before_expiry(self) -> None:
        identity = create_identity()
        with patch("gateway.p2p.time.time", return_value=100), patch(
            "gateway.secure_transport.time.time", return_value=100
        ):
            config = ProviderConfig(
                peer_id=identity.peer_id,
                channel=DEFAULT_CHANNEL,
                agent_id="coder",
                agent_key="coder-key",
                gateway_url="http://127.0.0.1:8000/v1",
                model="gpt-5.5",
                advertise_host="127.0.0.1",
                advertise_port=9700,
                identity=identity,
                transport_key_lifetime_seconds=300,
            )
            first_key_id = str(config.ensure_transport_key().binding["key_id"])

        with patch("gateway.p2p.time.time", return_value=350), patch(
            "gateway.secure_transport.time.time", return_value=350
        ):
            second_key_id = str(config.ensure_transport_key().binding["key_id"])
            accepted = config.accepted_transport_bindings(rotate=False)

        self.assertNotEqual(first_key_id, second_key_id)
        self.assertEqual(str(accepted[0]["key_id"]), second_key_id)
        self.assertIn(first_key_id, {str(binding["key_id"]) for binding in accepted})

    def test_ping_address_proof_is_signed_by_provider_identity(self) -> None:
        identity = create_identity()
        config = ProviderConfig(
            peer_id=identity.peer_id,
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            identity=identity,
        )

        response = handle_message(
            config,
            {"type": "ping", "request_id": "challenge-1", "audience": "https://pool.example"},
        )
        unsigned = verify_document(
            response,
            purpose=ADDRESS_PROOF_PURPOSE,
            audience="https://pool.example",
        )

        self.assertEqual(unsigned["request_id"], "challenge-1")
        self.assertEqual(unsigned["peer"]["peer_id"], identity.peer_id)
        self.assertEqual(response["signature"]["public_key"], identity.public_key)

    def test_peer_book_is_bounded_and_rejects_key_id_mismatch(self) -> None:
        config = ProviderConfig(
            peer_id="peer-local",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            max_peer_book_size=2,
        )
        for peer_id, port in (("peer-a", 9701), ("peer-b", 9702), ("peer-c", 9703)):
            remember_peer(config, {"peer_id": peer_id, "address": f"tcp://127.0.0.1:{port}"})

        self.assertEqual(len(config.peer_book), 2)
        self.assertIn("peer-c", config.peer_book)

        identity = create_identity()
        with self.assertRaisesRegex(P2PError, "does not match"):
            remember_peer(
                config,
                {
                    "peer_id": "peer-not-the-key-owner",
                    "public_key": identity.public_key,
                    "address": "tcp://127.0.0.1:9704",
                },
            )

    def test_gateway_redirect_is_not_followed_with_agent_authorization(self) -> None:
        request = urllib.request.Request(
            "http://127.0.0.1:8000/v1/responses",
            headers={"authorization": "Bearer top-secret-agent-key"},
            method="POST",
        )
        redirected = gateway.p2p._NoGatewayRedirectHandler().redirect_request(
            request,
            None,
            307,
            "temporary redirect",
            {},
            "http://127.0.0.1:9000/stolen",
        )

        self.assertIsNone(redirected)

    def test_build_gateway_request_body_for_responses(self) -> None:
        body = build_gateway_request_body(
            endpoint="responses",
            model="gpt-5.5",
            input_value="hello",
            metadata={"task_id": "task-1"},
        )

        self.assertEqual(body["model"], "gpt-5.5")
        self.assertEqual(body["input"], "hello")
        self.assertFalse(body["gateway_stateful"])
        self.assertEqual(body["metadata"], {"task_id": "task-1"})
        limited = build_gateway_request_body(endpoint="responses", model="gpt-5.5", input_value="hello", max_output_tokens=128)
        self.assertEqual(limited["max_output_tokens"], 128)

    def test_build_gateway_request_body_for_chat(self) -> None:
        body = build_gateway_request_body(
            endpoint="chat",
            model="gpt-5.5",
            input_value="hello",
        )

        self.assertEqual(
            body["messages"],
            [{"role": "user", "content": "hello"}],
        )
        self.assertFalse(body["gateway_stateful"])
        limited = build_gateway_request_body(endpoint="chat", model="gpt-5.5", input_value="hello", max_output_tokens=64)
        self.assertEqual(limited["max_tokens"], 64)

    def test_handle_infer_calls_local_gateway(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        calls: list[dict[str, Any]] = []

        def fake_call_gateway(**kwargs: Any) -> dict[str, Any]:
            calls.append(kwargs)
            return {
                "id": "resp-test",
                "object": "response",
                "output_text": "provider ok",
                "usage": {"total_tokens": 2},
            }

        with (
            patch.object(
                gateway.p2p,
                "provider_min_reservation_units",
                wraps=gateway.p2p.provider_min_reservation_units,
            ) as minimum_quote,
            patch.object(gateway.p2p, "call_gateway", side_effect=fake_call_gateway),
        ):
            response = handle_message(
                config,
                _signed_infer(
                    consumer_identity,
                    config,
                    request_id="req-1",
                    endpoint="responses",
                    model="gpt-5.5",
                    input_value="Say OK",
                ),
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["request_id"], "req-1")
        self.assertEqual(response["output_text"], "provider ok")
        self.assertEqual(calls[0]["gateway_url"], "http://127.0.0.1:8000/v1")
        self.assertEqual(calls[0]["agent_key"], "coder-key")
        self.assertEqual(calls[0]["endpoint"], "responses")
        self.assertEqual(calls[0]["body"]["input"], "Say OK")
        self.assertEqual(calls[0]["body"]["max_output_tokens"], config.reserve_output_tokens)
        self.assertEqual(minimum_quote.call_args.kwargs["input_tokens"], config.reserve_input_tokens)

    def test_handle_infer_rejects_model_outside_provider_descriptor(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        message = _signed_infer(
            consumer_identity,
            config,
            request_id="req-wrong-model",
            model="more-expensive-model",
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("model does not match provider descriptor", response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_forwards_max_output_tokens(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        calls: list[dict[str, Any]] = []

        def fake_call_gateway(**kwargs: Any) -> dict[str, Any]:
            calls.append(kwargs)
            return {"output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}}

        message = _signed_infer(consumer_identity, config, request_id="req-limited", max_output_tokens=77)
        with patch.object(gateway.p2p, "call_gateway", side_effect=fake_call_gateway):
            response = handle_message(config, message)

        self.assertTrue(response["ok"])
        self.assertEqual(calls[0]["body"]["max_output_tokens"], 77)
        expected_hash = inference_request_hash(
            endpoint="responses",
            model="gpt-5.5",
            input_value="Say OK",
            max_output_tokens=77,
        )
        self.assertEqual(response["quality"]["request_hash"], expected_hash)

    def test_request_commitment_changes_with_input_and_output_cap(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        responses: list[dict[str, Any]] = []
        with patch.object(
            gateway.p2p,
            "call_gateway",
            return_value={"output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}},
        ):
            responses.append(
                handle_message(
                    config,
                    _signed_infer(
                        consumer_identity,
                        config,
                        request_id="req-input-a",
                        model="gpt-5.5",
                        input_value="Say OK",
                        max_output_tokens=32,
                    ),
                )
            )
            responses.append(
                handle_message(
                    config,
                    _signed_infer(
                        consumer_identity,
                        config,
                        request_id="req-input-b",
                        model="gpt-5.5",
                        input_value="Say something else",
                        max_output_tokens=32,
                    ),
                )
            )
            responses.append(
                handle_message(
                    config,
                    _signed_infer(
                        consumer_identity,
                        config,
                        request_id="req-output",
                        model="gpt-5.5",
                        max_output_tokens=33,
                    ),
                )
            )

        hashes = [response["quality"]["request_hash"] for response in responses]
        self.assertEqual(len(set(hashes)), 3)

    def test_handle_infer_rejects_input_above_canonical_byte_bound_before_execution(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
            reserve_input_tokens=7,
        )
        message = _signed_infer(
            consumer_identity,
            config,
            request_id="req-oversized-input",
            input_value="你好",
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("canonical JSON UTF-8 bytes", response["error"])
        gateway_call.assert_not_called()

        hidden_input = _signed_infer(
            consumer_identity,
            config,
            request_id="req-hidden-oversized-input",
            input_value="x" * 20,
            messages=[],
        )
        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            hidden_response = handle_message(config, hidden_input)

        self.assertFalse(hidden_response["ok"])
        self.assertIn("canonical JSON UTF-8 bytes", hidden_response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_rejects_parameterized_case_insensitive_inline_pdf(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        message = _signed_infer(
            consumer_identity,
            config,
            request_id="req-inline-pdf",
            input_value=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_file",
                            "filename": "compressed.pdf",
                            "file_data": "DATA:Application/PDF;name=x;base64,JVBERi0xLjQ=",
                        }
                    ],
                }
            ],
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call, patch.object(
            gateway.p2p, "_claim_v3_authorization"
        ) as v3_claim:
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("inline PDF file_data is unsupported", response["error"])
        gateway_call.assert_not_called()
        v3_claim.assert_not_called()

    def test_handle_infer_rejects_invalid_or_excessive_output_cap_before_execution(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
            reserve_output_tokens=32,
        )
        for request_id, output_cap in (
            ("req-zero-output", 0),
            ("req-float-output", 1.5),
            ("req-excessive-output", 33),
        ):
            with self.subTest(output_cap=output_cap):
                message = _signed_infer(
                    consumer_identity,
                    config,
                    request_id=request_id,
                    max_output_tokens=output_cap,
                )
                with patch.object(gateway.p2p, "call_gateway") as gateway_call:
                    response = handle_message(config, message)

                self.assertFalse(response["ok"])
                self.assertIn("output", response["error"])
                gateway_call.assert_not_called()

    def test_handle_infer_rejects_wrong_channel(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:1/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(
                config,
                _signed_infer(
                    consumer_identity,
                    config,
                    request_id="req-1",
                    channel="other-channel",
                    input_value="Say OK",
                ),
            )

        self.assertFalse(response["ok"])
        self.assertIn("channel mismatch", response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_rejects_unsigned_request_by_default(self) -> None:
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:1/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(
                config,
                {
                    "type": "infer",
                    "request_id": "req-1",
                    "channel": DEFAULT_CHANNEL,
                    "input": "Say OK",
                },
            )

        self.assertFalse(response["ok"])
        self.assertIn("signature", response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_rejects_signed_request_without_consumer_policy(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:1/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(
                config,
                sign_document(
                    {
                        "type": "infer",
                        "request_id": "req-1",
                        "channel": DEFAULT_CHANNEL,
                        "input": "Say OK",
                    },
                    consumer_identity.private_key,
                    purpose=INFERENCE_REQUEST_PURPOSE,
                    audience=config.peer_id,
                ),
            )

        self.assertFalse(response["ok"])
        self.assertIn("allowlist", response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_rejects_duplicate_signed_request(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        message = _signed_infer(
            consumer_identity,
            config,
            request_id="req-1",
            endpoint="responses",
            model="gpt-5.5",
            input_value="Say OK",
        )

        with patch.object(
            gateway.p2p,
            "call_gateway",
            return_value={"output_text": "ok", "usage": {}},
        ) as gateway_call:
            first = handle_message(config, message)
            second = handle_message(config, message)

        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])
        self.assertIn("duplicate", second["error"])
        self.assertEqual(gateway_call.call_count, 1)

    def test_handle_infer_rejects_missing_payment_reservation(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(
                config,
                sign_document(
                    {
                        "type": "infer",
                        "request_id": "req-no-reservation",
                        "channel": DEFAULT_CHANNEL,
                        "endpoint": "responses",
                        "model": "gpt-5.5",
                        "input": "Say OK",
                    },
                    consumer_identity.private_key,
                    purpose=INFERENCE_REQUEST_PURPOSE,
                    audience=config.peer_id,
                ),
            )

        self.assertFalse(response["ok"])
        self.assertIn("payment reservation", response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_enforces_canonical_request_and_signature_nonces(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )
        oversized = _signed_infer(
            consumer_identity,
            config,
            request_id="r" * (gateway.p2p.MAX_REQUEST_ID_BYTES + 1),
        )
        valid_outer = _signed_infer(
            consumer_identity,
            config,
            request_id="req-bad-outer-nonce",
        )
        unsigned_outer = {key: value for key, value in valid_outer.items() if key != "signature"}
        bad_outer_nonce = sign_document(
            unsigned_outer,
            consumer_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=config.peer_id,
            nonce="A" * 32,
        )
        valid_payment = _signed_infer(
            consumer_identity,
            config,
            request_id="req-bad-payment-nonce",
        )
        unsigned_payment_message = {
            key: value for key, value in valid_payment.items() if key != "signature"
        }
        unsigned_reservation = {
            key: value
            for key, value in unsigned_payment_message["payment_reservation"].items()
            if key != "signature"
        }
        unsigned_payment_message["payment_reservation"] = sign_document(
            unsigned_reservation,
            consumer_identity.private_key,
            purpose=PAYMENT_RESERVATION_PURPOSE,
            nonce="a" * 31,
        )
        bad_payment_nonce = sign_document(
            unsigned_payment_message,
            consumer_identity.private_key,
            purpose=INFERENCE_REQUEST_PURPOSE,
            audience=config.peer_id,
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            oversized_response = handle_message(config, oversized)
            outer_response = handle_message(config, bad_outer_nonce)
            payment_response = handle_message(config, bad_payment_nonce)

        self.assertIn("request_id must be 1-128", oversized_response["error"])
        self.assertIn("inference request signature nonce", outer_response["error"])
        self.assertIn("payment reservation signature nonce", payment_response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_rejects_wrong_audience(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(
                config,
                sign_document(
                    {
                        "type": "infer",
                        "request_id": "req-wrong-audience",
                        "channel": DEFAULT_CHANNEL,
                        "endpoint": "responses",
                        "model": "gpt-5.5",
                        "input": "Say OK",
                    },
                    consumer_identity.private_key,
                    purpose=INFERENCE_REQUEST_PURPOSE,
                    audience="other-peer",
                ),
            )

        self.assertFalse(response["ok"])
        self.assertIn("audience", response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_rejects_under_reserved_payment(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(
                config,
                _signed_infer(
                    consumer_identity,
                    config,
                    request_id="req-low-reservation",
                    max_fee_units=1,
                ),
            )

        self.assertFalse(response["ok"])
        self.assertIn("max_fee_units", response["error"])
        gateway_call.assert_not_called()

    def test_handle_infer_rejects_cost_bound_above_reservation_before_execution(self) -> None:
        consumer_identity = create_identity()
        config = ProviderConfig(
            peer_id="peer-test",
            channel=DEFAULT_CHANNEL,
            agent_id="coder",
            agent_key="coder-key",
            gateway_url="http://127.0.0.1:8000/v1",
            model="gpt-5.5",
            advertise_host="127.0.0.1",
            advertise_port=9700,
            authorized_consumers={consumer_identity.public_key},
            reserve_input_tokens=100,
            reserve_output_tokens=100_000,
        )
        message = _signed_infer(
            consumer_identity,
            config,
            request_id="req-over-cost",
            max_fee_units=10_000,
            max_output_tokens=100_000,
        )

        with patch.object(gateway.p2p, "call_gateway") as gateway_call:
            response = handle_message(config, message)

        self.assertFalse(response["ok"])
        self.assertIn("max_fee_units", response["error"])
        gateway_call.assert_not_called()

    def test_persistent_replay_store_rejects_duplicate_after_restart(self) -> None:
        consumer_identity = create_identity()
        with tempfile.TemporaryDirectory() as tmp:
            replay_db = str(Path(tmp) / "replay.sqlite3")
            first_config = ProviderConfig(
                peer_id="peer-test",
                channel=DEFAULT_CHANNEL,
                agent_id="coder",
                agent_key="coder-key",
                gateway_url="http://127.0.0.1:8000/v1",
                model="gpt-5.5",
                advertise_host="127.0.0.1",
                advertise_port=9700,
                authorized_consumers={consumer_identity.public_key},
                replay_store_path=replay_db,
            )
            second_config = ProviderConfig(
                peer_id="peer-test",
                channel=DEFAULT_CHANNEL,
                agent_id="coder",
                agent_key="coder-key",
                gateway_url="http://127.0.0.1:8000/v1",
                model="gpt-5.5",
                advertise_host="127.0.0.1",
                advertise_port=9700,
                authorized_consumers={consumer_identity.public_key},
                replay_store_path=replay_db,
            )
            message = _signed_infer(consumer_identity, first_config, request_id="req-persistent")

            with patch.object(
                gateway.p2p,
                "call_gateway",
                return_value={"output_text": "ok", "usage": {}},
            ) as gateway_call:
                first = handle_message(first_config, message)
                second = handle_message(second_config, message)

        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])
        self.assertIn("duplicate", second["error"])
        self.assertEqual(gateway_call.call_count, 1)

def _signed_infer(
    identity: Any,
    config: ProviderConfig,
    *,
    request_id: str,
    channel: str = DEFAULT_CHANNEL,
    endpoint: str = "responses",
    model: str = "gpt-5.5",
    input_value: Any = "Say OK",
    messages: Any = None,
    max_fee_units: int = 100000,
    max_output_tokens: Any = None,
) -> dict[str, Any]:
    message = {
        "type": "infer",
        "request_id": request_id,
        "channel": channel,
        "endpoint": endpoint,
        "model": model,
        "input": input_value,
        "payment_reservation": build_payment_reservation(
            request_id=request_id,
            consumer_id="test-consumer",
            consumer_payment_address=None,
            provider_id=config.peer_id,
            provider_payment_address=config.payment_address,
            channel=channel,
            pricing_hash=DEFAULT_PRICING[DEFAULT_CHANNEL].config_hash(),
            max_fee_units=max_fee_units,
            signer=identity,
        ),
    }
    if messages is not None:
        message["messages"] = messages
    if max_output_tokens is not None:
        message["max_output_tokens"] = max_output_tokens
    return sign_document(message, identity.private_key, purpose=INFERENCE_REQUEST_PURPOSE, audience=config.peer_id)


def _v3_provider_config(
    provider_identity: Any,
    consumer_identity: Any,
    *,
    replay_store_path: str,
    provider_address: str,
    pricing_hash: str,
    settlement_contract: str,
) -> ProviderConfig:
    return ProviderConfig(
        peer_id=provider_identity.peer_id,
        channel=DEFAULT_CHANNEL,
        agent_id="coder",
        agent_key="coder-key",
        gateway_url="http://127.0.0.1:8000/v1",
        model="gpt-5.5",
        advertise_host="127.0.0.1",
        advertise_port=9700,
        identity=provider_identity,
        authorized_consumers={consumer_identity.public_key},
        payment_address=provider_address,
        pricing_hash=pricing_hash,
        settlement_rpc_url="http://127.0.0.1:8545",
        settlement_contract=settlement_contract,
        settlement_chain_id=11155111,
        settlement_version=3,
        pricing_version=7,
        settlement_confirmations=6,
        reserve_input_tokens=8,
        reserve_output_tokens=1,
        replay_store_path=replay_store_path,
    )


def _signed_v3_infer(
    identity: Any,
    config: ProviderConfig,
    *,
    wallet_private_key: str,
    request_id: str,
    reservation_id: str,
    expires_at: int,
    evm_session_authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    consumer_address = private_key_to_address(parse_private_key(wallet_private_key))
    request_hash = "0x" + inference_request_hash(
        endpoint="responses",
        model=config.model,
        input_value="Say OK",
        max_output_tokens=1,
    )
    wallet_options: dict[str, Any]
    if evm_session_authorization is None:
        wallet_options = {"consumer_wallet_private_key": wallet_private_key}
    else:
        wallet_options = {"evm_session_authorization": evm_session_authorization}
    reservation = build_payment_reservation(
        request_id=request_id,
        consumer_id="consumer-v3",
        consumer_payment_address=consumer_address,
        provider_id=config.peer_id,
        provider_payment_address=config.payment_address,
        channel=DEFAULT_CHANNEL,
        pricing_hash=str(config.pricing_hash),
        max_fee_units=100_000,
        signer=identity,
        expires_at=expires_at,
        settlement_version=3,
        pricing_version=int(config.pricing_version or 0),
        onchain_reservation_id=reservation_id,
        request_hash=request_hash,
        settlement_deadline=expires_at - 300,
        settlement_chain_id=int(config.settlement_chain_id or 0),
        settlement_contract=config.settlement_contract,
        **wallet_options,
    )
    return sign_document(
        {
            "type": "infer",
            "request_id": request_id,
            "channel": DEFAULT_CHANNEL,
            "endpoint": "responses",
            "model": config.model,
            "input": "Say OK",
            "max_output_tokens": 1,
            "payment_reservation": reservation,
        },
        identity.private_key,
        purpose=INFERENCE_REQUEST_PURPOSE,
        audience=config.peer_id,
    )


def _v3_reservation_words(
    *,
    consumer_address: str,
    provider_address: str,
    request_hash: str,
    pricing_version: int,
    expires_at: int,
    amount_units: int,
) -> str:
    return "0x" + "".join(
        [
            _abi_word(consumer_address),
            _abi_word(provider_address),
            channel_to_hash(DEFAULT_CHANNEL)[2:],
            request_hash[2:],
            _abi_word(pricing_version),
            _abi_word(expires_at),
            _abi_word(amount_units),
            _abi_word(0),
            _abi_word(0),
        ]
    )


def _v3_rpc_int(_url: str, method: str, _params: list[Any], _timeout: float) -> int:
    if method == "eth_chainId":
        return 11155111
    if method == "eth_blockNumber":
        return 100
    raise AssertionError(method)


def _v3_call_contract(pricing_hash: str, encoded_reservation: str) -> Any:
    def call(
        _rpc_url: str,
        _contract: str,
        signature: str,
        _args: list[str],
        **_kwargs: Any,
    ) -> str:
        if signature == "channelPricingHash(bytes32,uint64)":
            return pricing_hash
        if signature == "reservations(bytes32)":
            return encoded_reservation
        if signature == "quote(bytes32,uint64,uint256,uint256)":
            return "0x" + _abi_word(2_000)
        raise AssertionError(signature)

    return call


def _abi_word(value: Any) -> str:
    if isinstance(value, str) and value.startswith("0x"):
        return value[2:].lower().rjust(64, "0")
    return int(value).to_bytes(32, "big").hex()


if __name__ == "__main__":
    unittest.main()
