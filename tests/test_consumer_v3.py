from __future__ import annotations

import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

import gateway.mycomesh as mycomesh
from gateway.attestation import build_provider_settlement_attestation, settlement_response_hash
from gateway.billing import usdc_to_units
from gateway.chain import (
    ZERO_ADDRESS,
    channel_to_hash,
    parse_private_key,
    private_key_to_address,
    sign_evm_digest,
)
from gateway.chain_v3 import build_provider_settlement_payload
from gateway.identity import create_identity
from gateway.pricing import DEFAULT_CHANNEL, quote_usage
from gateway.reservation import (
    build_evm_session_authorization,
    evm_session_authorization_digest,
)


class ConsumerV3AuthorizationTest(unittest.TestCase):
    wallet_private_key = "0x" + "11" * 32
    other_private_key = "0x" + "22" * 32
    provider_payment_address = "0x" + "33" * 20
    other_provider_payment_address = "0x" + "44" * 20
    settlement = "0x" + "55" * 20
    pricing_hash = "0x" + "66" * 32
    reservation_id = "0x" + "77" * 32

    def setUp(self) -> None:
        self.consumer = private_key_to_address(parse_private_key(self.wallet_private_key))
        self.deployment = SimpleNamespace(
            protocol_version=3,
            chain_id=11155111,
            settlement=self.settlement,
            channel="codex-standard-v1",
            channel_hash="0x" + "88" * 32,
            pricing_version=1,
            pricing_hash=self.pricing_hash,
        )
        self.context = {
            "deployment": self.deployment,
            "rpc_url": "https://rpc.invalid",
            "timeout": 1.0,
            "confirmations": 6,
            "latest_block": 106,
            "confirmed_block": 100,
        }
        self.account = SimpleNamespace(account_id=self.consumer, payment_address=self.consumer)
        self.peer = self._peer(
            "peer-provider-a",
            self.provider_payment_address,
        )

    def _peer(self, peer_id: str, payment_address: str) -> dict[str, object]:
        return {
            "peer_id": peer_id,
            "public_key": "ab" * 32,
            "payment_address": payment_address,
            "address": "myco+tcp://provider.example:9700",
            "channel": "codex-standard-v1",
            "model": "mycomesh-codex-standard-v1",
            "capacity": {
                "max_concurrency": 1,
                "reserve_input_bytes": 8000,
                "reserve_output_tokens": 2000,
            },
            "settlement": {
                "version": 3,
                "chain_id": 11155111,
                "contract": self.settlement,
                "pricing_version": 1,
                "pricing_hash": self.pricing_hash,
            },
        }

    def _authorization(self) -> dict[str, object]:
        expires_at = int(time.time()) + 900
        return build_evm_session_authorization(
            chain_id=11155111,
            settlement_contract=self.settlement,
            onchain_reservation_id=self.reservation_id,
            consumer_payment_address=self.consumer,
            provider_id="peer-provider-a",
            provider_payment_address=self.provider_payment_address,
            channel="codex-standard-v1",
            pricing_hash=self.pricing_hash,
            pricing_version=1,
            request_hash="0x"
            + mycomesh._public_request_hash(
                endpoint="responses",
                model="mycomesh-codex-standard-v1",
                input_value="hello",
                max_output_tokens=128,
            ),
            max_fee_units=100_000,
            expires_at=expires_at,
            settlement_deadline=expires_at,
            provider_fallback_allowed=False,
            session_public_key=mycomesh.request_identity.public_key,
            wallet_private_key=self.wallet_private_key,
        )

    def _validate(
        self,
        authorization: dict[str, object],
        *,
        input_value: str = "hello",
        provider_id: str = "peer-provider-a",
        peers: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        with patch.object(mycomesh, "_consumer_v3_context", return_value=self.context), patch.object(
            mycomesh,
            "_consumer_v3_quote",
            return_value=100_000,
        ), patch.object(
            mycomesh,
            "rpc_call",
            return_value="0x",
        ), patch.object(
            mycomesh,
            "_verify_consumer_v3_onchain",
        ):
            return mycomesh._validate_consumer_v3_envelope(
                account=self.account,
                envelope={
                    "provider_id": provider_id,
                    "authorization": authorization,
                },
                input_value=input_value,
                model="mycomesh-codex-standard-v1",
                endpoint="responses",
                max_output_tokens=128,
                peers=peers or [self.peer],
            )

    def test_rejects_eoa_signature_from_a_different_wallet(self) -> None:
        authorization = self._authorization()
        unsigned = {key: value for key, value in authorization.items() if key != "wallet_signature"}
        signature = sign_evm_digest(
            self.other_private_key,
            evm_session_authorization_digest(unsigned),
        )
        authorization["wallet_signature"] = (
            "0x"
            + int(signature.r, 16).to_bytes(32, "big").hex()
            + int(signature.s, 16).to_bytes(32, "big").hex()
            + int(signature.v).to_bytes(1, "big").hex()
        )

        with self.assertRaises(HTTPException) as raised:
            self._validate(authorization)

        self.assertEqual(raised.exception.status_code, 403)

    def test_rejects_switching_provider_after_wallet_authorization(self) -> None:
        other_peer = self._peer(
            "peer-provider-b",
            self.other_provider_payment_address,
        )

        with self.assertRaises(HTTPException) as raised:
            self._validate(
                self._authorization(),
                provider_id="peer-provider-b",
                peers=[self.peer, other_peer],
            )

        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("provider_id mismatch", str(raised.exception.detail))

    def test_rejects_request_changed_after_wallet_authorization(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            self._validate(self._authorization(), input_value="tampered")

        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("request_hash mismatch", str(raised.exception.detail))

    def test_peer_binding_rejects_internal_model_or_missing_execution_limits(self) -> None:
        wrong_model = dict(self.peer)
        wrong_model["model"] = "gpt-5.5"
        missing_limits = dict(self.peer)
        missing_limits["capacity"] = {"max_concurrency": 1}

        for label, peer in (("model", wrong_model), ("capacity", missing_limits)):
            with self.subTest(label=label), self.assertRaises(mycomesh.P2PError):
                mycomesh._consumer_v3_peer_binding(
                    peer,
                    deployment=self.deployment,
                    channel="codex-standard-v1",
                    model="mycomesh-codex-standard-v1",
                )

    def test_rejects_reservation_missing_from_confirmed_snapshot(self) -> None:
        authorization = self._authorization()
        with patch.object(
            mycomesh,
            "call_contract",
            return_value="0x" + "0" * (9 * 64),
        ) as contract_call:
            with self.assertRaises(HTTPException) as raised:
                mycomesh._verify_consumer_v3_onchain(self.context, authorization)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("absent at confirmed state", str(raised.exception.detail))
        self.assertEqual(contract_call.call_args.kwargs["block_tag"], 100)

    def test_validate_requotes_with_signed_provider_input_reserve(self) -> None:
        with patch.object(mycomesh, "_consumer_v3_context", return_value=self.context), patch.object(
            mycomesh,
            "_consumer_v3_quote",
            return_value=100_000,
        ) as quote, patch.object(
            mycomesh,
            "rpc_call",
            return_value="0x",
        ), patch.object(
            mycomesh,
            "_verify_consumer_v3_onchain",
        ):
            mycomesh._validate_consumer_v3_envelope(
                account=self.account,
                envelope={
                    "provider_id": "peer-provider-a",
                    "authorization": self._authorization(),
                },
                input_value="hello",
                model="mycomesh-codex-standard-v1",
                endpoint="responses",
                max_output_tokens=128,
                peers=[self.peer],
            )

        self.assertEqual(quote.call_args.kwargs["reserve_input_bytes"], 8000)

    def test_prepare_binds_signed_provider_execution_limits(self) -> None:
        binding = mycomesh._consumer_v3_peer_binding(
            self.peer,
            deployment=self.deployment,
            channel="codex-standard-v1",
            model="mycomesh-codex-standard-v1",
        )
        with patch.object(mycomesh, "_consumer_v3_context", return_value=self.context), patch.object(
            mycomesh,
            "_consumer_v3_peers",
            return_value=[(self.peer, binding)],
        ), patch.object(
            mycomesh,
            "_consumer_v3_quote",
            return_value=100_000,
        ) as quote:
            plan = mycomesh._prepare_consumer_v3_plan(
                account=self.account,
                input_value="hello",
                model="mycomesh-codex-standard-v1",
                endpoint="responses",
                max_output_tokens=128,
            )

        self.assertEqual(plan["input_size_bytes"], 7)
        self.assertEqual(plan["reserve_input_bytes"], 8000)
        self.assertEqual(plan["reserve_output_tokens"], 2000)
        self.assertEqual(quote.call_args.kwargs["reserve_input_bytes"], 8000)

    def test_prepare_rejects_provider_execution_limit_overflow_before_quote(self) -> None:
        binding = mycomesh._consumer_v3_peer_binding(
            self.peer,
            deployment=self.deployment,
            channel="codex-standard-v1",
            model="mycomesh-codex-standard-v1",
        )
        binding["reserve_input_bytes"] = 7
        binding["reserve_output_tokens"] = 127
        with patch.object(mycomesh, "_consumer_v3_context", return_value=self.context), patch.object(
            mycomesh,
            "_consumer_v3_peers",
            return_value=[(self.peer, binding)],
        ), patch.object(
            mycomesh,
            "_consumer_v3_quote",
        ) as quote:
            with self.assertRaises(HTTPException) as input_error:
                mycomesh._prepare_consumer_v3_plan(
                    account=self.account,
                    input_value="\u4f60\u597d",
                    model="mycomesh-codex-standard-v1",
                    endpoint="responses",
                    max_output_tokens=127,
                )
            with self.assertRaises(HTTPException) as output_error:
                mycomesh._prepare_consumer_v3_plan(
                    account=self.account,
                    input_value="ok",
                    model="mycomesh-codex-standard-v1",
                    endpoint="responses",
                    max_output_tokens=128,
                )

        self.assertEqual(input_error.exception.status_code, 422)
        self.assertEqual(output_error.exception.status_code, 422)
        quote.assert_not_called()

    def test_validate_rejects_request_above_current_provider_limits_before_quote(self) -> None:
        limited_peer = dict(self.peer)
        limited_peer["capacity"] = {
            "max_concurrency": 1,
            "reserve_input_bytes": 7,
            "reserve_output_tokens": 127,
        }
        with patch.object(mycomesh, "_consumer_v3_context", return_value=self.context), patch.object(
            mycomesh,
            "_consumer_v3_quote",
        ) as quote:
            with self.assertRaises(HTTPException) as input_error:
                mycomesh._validate_consumer_v3_envelope(
                    account=self.account,
                    envelope={
                        "provider_id": "peer-provider-a",
                        "authorization": self._authorization(),
                    },
                    input_value="\u4f60\u597d",
                    model="mycomesh-codex-standard-v1",
                    endpoint="responses",
                    max_output_tokens=127,
                    peers=[limited_peer],
                )
            with self.assertRaises(HTTPException) as output_error:
                mycomesh._validate_consumer_v3_envelope(
                    account=self.account,
                    envelope={
                        "provider_id": "peer-provider-a",
                        "authorization": self._authorization(),
                    },
                    input_value="ok",
                    model="mycomesh-codex-standard-v1",
                    endpoint="responses",
                    max_output_tokens=128,
                    peers=[limited_peer],
                )

        self.assertEqual(input_error.exception.status_code, 422)
        self.assertIn("canonical JSON UTF-8 bytes", str(input_error.exception.detail))
        self.assertEqual(output_error.exception.status_code, 422)
        self.assertIn("reserve_output_tokens", str(output_error.exception.detail))
        quote.assert_not_called()


class ConsumerV3RuntimeSettlementTest(unittest.TestCase):
    consumer_private_key = "0x" + "31" * 32
    provider_private_key = "0x" + "32" * 32
    other_provider_private_key = "0x" + "33" * 32
    settlement = "0x" + "41" * 20
    pricing_hash = "0x" + "42" * 32
    reservation_id = "0x" + "43" * 32
    request_hash = "44" * 32

    def setUp(self) -> None:
        self.consumer = private_key_to_address(parse_private_key(self.consumer_private_key))
        self.provider = private_key_to_address(parse_private_key(self.provider_private_key))
        self.provider_identity = create_identity()
        self.deadline = int(time.time()) + 900
        self.usage = {"input_tokens": 1000, "output_tokens": 100, "total_tokens": 1100}
        self.quote = quote_usage(DEFAULT_CHANNEL, self.usage)
        self.amount_units = usdc_to_units(self.quote.to_dict()["gross_fee"])
        self.deployment = SimpleNamespace(
            protocol_version=3,
            chain_id=11155111,
            settlement=self.settlement,
            channel=DEFAULT_CHANNEL,
            channel_hash=channel_to_hash(DEFAULT_CHANNEL),
            pricing_version=1,
            pricing_hash=self.pricing_hash,
        )
        self.context = {
            "deployment": self.deployment,
            "rpc_url": "https://rpc.invalid",
            "timeout": 1.0,
            "confirmations": 6,
            "latest_block": 106,
            "confirmed_block": 100,
        }
        self.account = SimpleNamespace(account_id=self.consumer, payment_address=self.consumer)
        self.peer = {
            "peer_id": self.provider_identity.peer_id,
            "public_key": self.provider_identity.public_key,
            "payment_address": self.provider,
        }
        self.authorization = {
            "onchain_reservation_id": self.reservation_id,
            "consumer_payment_address": self.consumer,
            "provider_payment_address": self.provider,
            "channel": DEFAULT_CHANNEL,
            "request_hash": "0x" + self.request_hash,
            "pricing_version": 1,
            "pricing_hash": self.pricing_hash,
            "max_fee_units": self.amount_units * 2,
            "expires_at": self.deadline,
            "settlement_deadline": self.deadline,
            "provider_fallback_allowed": False,
        }
        self.consumer_v3 = {
            "settlement_chain_id": self.deployment.chain_id,
            "settlement_contract": self.settlement,
            "reserve_input_bytes": 8000,
            "reserve_output_tokens": 2000,
            "max_output_tokens": 2000,
        }

    def _response(
        self,
        *,
        chain_id: int | None = None,
        settlement_contract: str | None = None,
        provider_private_key: str | None = None,
        provider_address: str | None = None,
        request_hash: str | None = None,
        input_tokens: int | None = None,
        relay: str = ZERO_ADDRESS,
        pool: str = ZERO_ADDRESS,
    ) -> dict[str, object]:
        signer_key = provider_private_key or self.provider_private_key
        signer_address = provider_address or private_key_to_address(parse_private_key(signer_key))
        response: dict[str, object] = {
            "type": "infer_result",
            "ok": True,
            "request_id": "req-runtime-v3",
            "channel": DEFAULT_CHANNEL,
            "model": "mycomesh-codex-standard-v1",
            "endpoint": "responses",
            "output_text": "verified answer",
            "usage": dict(self.usage),
        }
        response["mycomesh_v3_settlement"] = build_provider_settlement_payload(
            provider_private_key=signer_key,
            chain_id=chain_id or self.deployment.chain_id,
            settlement_contract=settlement_contract or self.settlement,
            reservation_id=self.reservation_id,
            request_hash=request_hash or ("0x" + self.request_hash),
            response_hash="0x" + settlement_response_hash(response),
            channel_hash=channel_to_hash(DEFAULT_CHANNEL),
            pricing_version=1,
            pricing_hash=self.pricing_hash,
            consumer=self.consumer,
            provider=signer_address,
            relay=relay,
            pool=pool,
            input_tokens=input_tokens if input_tokens is not None else self.quote.input_tokens,
            output_tokens=self.quote.output_tokens,
            deadline=self.deadline,
        )
        reservation = {
            "consumer_id": self.account.account_id,
            "consumer_public_key": mycomesh.request_identity.public_key,
            "consumer_payment_address": self.consumer,
            "provider_id": self.provider_identity.peer_id,
            "provider_payment_address": self.provider,
            "pricing_hash": self.pricing_hash,
            "settlement_version": 3,
            "pricing_version": 1,
            "onchain_reservation_id": self.reservation_id,
            "request_hash": "0x" + self.request_hash,
            "settlement_deadline": self.deadline,
            "expires_at": self.deadline,
        }
        response["provider_settlement_attestation"] = build_provider_settlement_attestation(
            request_id="req-runtime-v3",
            request_hash=self.request_hash,
            response=response,
            channel=DEFAULT_CHANNEL,
            model="mycomesh-codex-standard-v1",
            endpoint="responses",
            reservation=reservation,
            quote=self.quote,
            provider_id=self.provider_identity.peer_id,
            provider_payment_address=self.provider,
            signer=self.provider_identity,
        )
        return response

    def _verify(self, response: dict[str, object], *, onchain_quote: int | None = None) -> dict[str, object]:
        with patch.object(mycomesh, "_consumer_v3_context", return_value=self.context), patch.object(
            mycomesh,
            "_verify_consumer_v3_onchain",
        ) as onchain_reservation, patch.object(
            mycomesh,
            "call_uint256",
            return_value=self.amount_units if onchain_quote is None else onchain_quote,
        ) as contract_quote:
            verified = mycomesh._verify_runtime_v3_settlement(
                response=response,
                account=self.account,
                peer_info=self.peer,
                consumer_v3=self.consumer_v3,
                authorization=self.authorization,
                channel=DEFAULT_CHANNEL,
                model="mycomesh-codex-standard-v1",
                endpoint="responses",
                request_hash=self.request_hash,
                quote=self.quote,
                amount_units=self.amount_units,
            )
        onchain_reservation.assert_called_once_with(self.context, self.authorization)
        self.assertEqual(contract_quote.call_args.kwargs["block_tag"], 100)
        return verified

    def test_accepts_fully_bound_provider_settlement(self) -> None:
        response = self._response()

        verified = self._verify(response)

        self.assertEqual(verified, response["mycomesh_v3_settlement"])

    def test_rejects_missing_provider_settlement(self) -> None:
        response = self._response()
        response.pop("mycomesh_v3_settlement")

        with self.assertRaises(HTTPException) as raised:
            self._verify(response)

        self.assertEqual(raised.exception.status_code, 502)

    def test_rejects_request_or_usage_tampering(self) -> None:
        cases = {
            "request_hash": self._response(request_hash="0x" + "45" * 32),
            "input_tokens": self._response(input_tokens=self.quote.input_tokens + 1),
        }
        for label, response in cases.items():
            with self.subTest(label=label), self.assertRaises(HTTPException) as raised:
                self._verify(response)
            self.assertEqual(raised.exception.status_code, 502)

    def test_rejects_usage_above_consumer_cap_or_provider_reserve(self) -> None:
        cases = {
            "consumer output cap": {"max_output_tokens": self.quote.output_tokens - 1},
            "provider input reserve": {"reserve_input_bytes": self.quote.input_tokens - 1},
            "provider output reserve": {"reserve_output_tokens": self.quote.output_tokens - 1},
        }
        for label, limits in cases.items():
            with self.subTest(label=label):
                original = dict(self.consumer_v3)
                self.consumer_v3.update(limits)
                try:
                    with self.assertRaises(HTTPException) as raised:
                        self._verify(self._response())
                    self.assertEqual(raised.exception.status_code, 502)
                    self.assertIn("exceeds", str(raised.exception.detail))
                finally:
                    self.consumer_v3 = original

    def test_rejects_a_different_provider_evm_signer(self) -> None:
        response = self._response(provider_private_key=self.other_provider_private_key)

        with self.assertRaises(HTTPException) as raised:
            self._verify(response)

        self.assertEqual(raised.exception.status_code, 502)
        self.assertIn("provider mismatch", str(raised.exception.detail))

    def test_rejects_wrong_chain_contract_or_nonzero_route_payees(self) -> None:
        cases = {
            "chain": self._response(chain_id=self.deployment.chain_id + 1),
            "contract": self._response(settlement_contract="0x" + "46" * 20),
            "relay": self._response(relay="0x" + "47" * 20),
            "pool": self._response(pool="0x" + "48" * 20),
        }
        for label, response in cases.items():
            with self.subTest(label=label), self.assertRaises(HTTPException) as raised:
                self._verify(response)
            self.assertEqual(raised.exception.status_code, 502)

    def test_rejects_local_price_that_differs_from_confirmed_chain_quote(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            self._verify(self._response(), onchain_quote=self.amount_units + 1)

        self.assertEqual(raised.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
