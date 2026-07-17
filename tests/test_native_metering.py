from __future__ import annotations

import asyncio
import hashlib
import json
import time
import unittest

from gateway.identity import canonical_json, create_identity, sign_document
from gateway.native_metering import (
    CAPABILITIES_PURPOSE,
    CAPABILITIES_SCHEMA,
    INFERENCE_RESULT_SCHEMA,
    METERING_PURPOSE,
    METERING_SCHEMA,
    NativeMeteredBackend,
    NativeMeteringError,
    build_native_inference_envelope,
    canonicalize_native_request,
    native_inference_request_hash,
    NativeMeteringRequestError,
)
from gateway.upstream import UpstreamError


NOW = int(time.time())
AUDIENCE = "mycomesh-sepolia:provider-a"
MODEL = "engine-model"
REVISION = "sha256:immutable-engine-image"
CAPABILITIES_DIGEST = "ab" * 32
P2P_REQUEST_HASH = "cd" * 32


class NativeMeteringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = create_identity()
        self.backend = NativeMeteredBackend(
            base_url="http://127.0.0.1:9000/v1",
            api_key="k" * 32,
            expected_model=MODEL,
            expected_model_revision=REVISION,
            metering_public_key=self.identity.public_key,
            capabilities_sha256=CAPABILITIES_DIGEST,
            audience=AUDIENCE,
            default_output_token_cap=64,
        )
        self.backend.accept_capabilities(
            self._capabilities("challenge-a"),
            challenge="challenge-a",
            now=NOW,
        )

    def _capabilities(self, challenge: str, **overrides: object) -> dict[str, object]:
        document: dict[str, object] = {
            "schema": CAPABILITIES_SCHEMA,
            "challenge": challenge,
            "backend_id": "engine-a",
            "model": MODEL,
            "model_revision": REVISION,
            "capabilities_sha256": CAPABILITIES_DIGEST,
            "native_output_token_cap": True,
            "trusted_native_usage": True,
            "supports_streaming": False,
            "maximum_output_token_cap": 128,
            "issued_at": NOW,
            "expires_at": NOW + 60,
        }
        document.update(overrides)
        return sign_document(
            document,
            self.identity.private_key,
            purpose=CAPABILITIES_PURPOSE,
            audience=AUDIENCE,
            timestamp=NOW,
        )

    def _result(
        self,
        prepared,
        *,
        input_tokens: object = 7,
        output_tokens: object = 5,
        total_tokens: object = 12,
        result_overrides: dict[str, object] | None = None,
        proof_overrides: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if prepared.endpoint == "chat":
            result: dict[str, object] = {
                "id": "response-a",
                "model": MODEL,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "verified output"},
                    }
                ],
                "usage": {"input_tokens": 999, "output_tokens": 999, "total_tokens": 1998},
            }
        else:
            result = {
                "id": "response-a",
                "model": MODEL,
                "output_text": "verified output",
                "usage": {"input_tokens": 999, "output_tokens": 999, "total_tokens": 1998},
            }
        result.update(result_overrides or {})
        proof: dict[str, object] = {
            "schema": METERING_SCHEMA,
            "request_id": prepared.request_id,
            "nonce": prepared.nonce,
            "request_hash": prepared.request_hash,
            "response_hash": _result_hash(result),
            "endpoint": prepared.endpoint,
            "model": MODEL,
            "model_revision": REVISION,
            "capabilities_sha256": CAPABILITIES_DIGEST,
            "output_token_cap": prepared.output_token_cap,
            "p2p_request_hash": P2P_REQUEST_HASH,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "issued_at": NOW,
            "expires_at": NOW + 60,
        }
        proof.update(proof_overrides or {})
        return {
            "schema": INFERENCE_RESULT_SCHEMA,
            "request_id": prepared.request_id,
            "result": result,
            "metering": sign_document(
                proof,
                self.identity.private_key,
                purpose=METERING_PURPOSE,
                audience=AUDIENCE,
                timestamp=NOW,
            ),
        }

    def test_verified_proof_replaces_untrusted_usage(self) -> None:
        prepared = self.backend.prepare_request(
            "responses",
            {"model": MODEL, "input": "hello", "max_output_tokens": 10, "mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
        )
        verified = self.backend.verify_result(
            prepared,
            self._result(prepared),
            now=NOW,
        )

        self.assertEqual(
            verified["usage"],
            {"input_tokens": 7, "output_tokens": 5, "total_tokens": 12},
        )
        self.assertIn("_mycomesh_metering", verified)
        self.assertEqual(prepared.envelope["max_output_tokens"], 10)
        self.assertNotIn("max_output_tokens", prepared.envelope["payload"])

    def test_provider_can_rebuild_exact_native_envelope_hash(self) -> None:
        body = {
            "model": MODEL,
            "input": "hello",
            "max_output_tokens": 10,
            "mycomesh_p2p_request_hash": P2P_REQUEST_HASH,
        }
        prepared = self.backend.prepare_request("responses", body)
        canonical = canonicalize_native_request(
            "responses",
            body,
            expected_model=MODEL,
            default_output_token_cap=64,
            maximum_output_token_cap=128,
        )
        rebuilt = build_native_inference_envelope(
            canonical,
            request_id=prepared.request_id,
            nonce=prepared.nonce,
            audience=AUDIENCE,
            model_revision=REVISION,
        )
        self.assertEqual(rebuilt, prepared.envelope)
        self.assertEqual(
            native_inference_request_hash(
                canonical,
                request_id=prepared.request_id,
                nonce=prepared.nonce,
                audience=AUDIENCE,
                model_revision=REVISION,
            ),
            prepared.request_hash,
        )
        altered = canonicalize_native_request(
            "responses",
            {**body, "input": "changed"},
            expected_model=MODEL,
            default_output_token_cap=64,
            maximum_output_token_cap=128,
        )
        self.assertNotEqual(
            native_inference_request_hash(
                altered,
                request_id=prepared.request_id,
                nonce=prepared.nonce,
                audience=AUDIENCE,
                model_revision=REVISION,
            ),
            prepared.request_hash,
        )

    def test_chat_usage_is_normalized_for_existing_pricing(self) -> None:
        prepared = self.backend.prepare_request(
            "chat",
            {"model": MODEL, "messages": [{"role": "user", "content": "hello"}], "mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
        )
        verified = self.backend.verify_result(
            prepared,
            self._result(prepared),
            now=NOW,
        )

        self.assertEqual(prepared.output_token_cap, 64)
        self.assertEqual(
            verified["usage"],
            {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
        )

    def test_capability_handshake_is_pinned_and_fresh(self) -> None:
        other = create_identity()
        wrong_key_document = sign_document(
            {
                key: value
                for key, value in self._capabilities("challenge-b").items()
                if key != "signature"
            },
            other.private_key,
            purpose=CAPABILITIES_PURPOSE,
            audience=AUDIENCE,
            timestamp=NOW,
        )
        with self.assertRaisesRegex(NativeMeteringError, "unpinned"):
            self.backend.accept_capabilities(
                wrong_key_document,
                challenge="challenge-b",
                now=NOW,
            )
        with self.assertRaisesRegex(NativeMeteringError, "challenge"):
            self.backend.accept_capabilities(
                self._capabilities("wrong"),
                challenge="expected",
                now=NOW,
            )
        with self.assertRaisesRegex(NativeMeteringError, "expired"):
            self.backend.accept_capabilities(
                self._capabilities("challenge-c"),
                challenge="challenge-c",
                now=NOW + 121,
            )

    def test_request_rejects_bypass_fields_and_ambiguous_caps(self) -> None:
        invalid_bodies = [
            {"model": MODEL, "input": "x", "stream": True} | {"mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
            {"model": MODEL, "input": "x", "tools": []} | {"mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
            {"model": MODEL, "input": "x", "metadata": {"task": "x"}} | {"mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
            {"model": MODEL, "input": "x", "max_tokens": 1, "max_output_tokens": 1} | {"mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
            {"model": MODEL, "input": "x", "max_output_tokens": True} | {"mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
            {"model": MODEL, "input": "x", "max_output_tokens": 129} | {"mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
            {"model": "wrong-model", "input": "x", "max_output_tokens": 1},
        ]
        for body in invalid_bodies:
            with self.subTest(body=body), self.assertRaises(
                (NativeMeteringRequestError, NativeMeteringError)
            ):
                self.backend.prepare_request("responses", body)

    def test_positive_schema_rejects_nested_tools_and_nonfinite_json(self) -> None:
        invalid = [
            {
                "model": MODEL,
                "messages": [
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"id": "call-a"}],
                    }
                ],
                "mycomesh_p2p_request_hash": P2P_REQUEST_HASH,
            },
            {
                "model": MODEL,
                "messages": [{"role": "tool", "content": "result"}],
                "mycomesh_p2p_request_hash": P2P_REQUEST_HASH,
            },
            {
                "model": MODEL,
                "input": "x",
                "metadata": {"not_finite": float("nan")},
                "mycomesh_p2p_request_hash": P2P_REQUEST_HASH,
            },
            {
                "model": MODEL,
                "input": "x",
                "extra_body": {"max_new_tokens": 999},
                "mycomesh_p2p_request_hash": P2P_REQUEST_HASH,
            },
        ]
        for endpoint, body in [
            ("chat", invalid[0]),
            ("chat", invalid[1]),
            ("responses", invalid[2]),
            ("responses", invalid[3]),
        ]:
            with self.subTest(endpoint=endpoint, body=body), self.assertRaises(
                NativeMeteringRequestError
            ):
                self.backend.prepare_request(endpoint, body)

    def test_result_shape_and_reserved_fields_are_rejected(self) -> None:
        chat_prepared = self.backend.prepare_request(
            "chat",
            {
                "model": MODEL,
                "messages": [{"role": "user", "content": "hello"}],
                "mycomesh_p2p_request_hash": P2P_REQUEST_HASH,
            },
        )
        with self.assertRaisesRegex(NativeMeteringError, "exactly one choice"):
            self.backend.verify_result(
                chat_prepared,
                self._result(chat_prepared, result_overrides={"choices": []}),
                now=NOW,
            )

        response_prepared = self.backend.prepare_request(
            "responses",
            {
                "model": MODEL,
                "input": "hello",
                "mycomesh_p2p_request_hash": P2P_REQUEST_HASH,
            },
        )
        with self.assertRaisesRegex(NativeMeteringError, "reserved"):
            self.backend.verify_result(
                response_prepared,
                self._result(
                    response_prepared,
                    result_overrides={"_mycomesh_untrusted": "value"},
                ),
                now=NOW,
            )

    def test_proof_rejects_tampering_bad_usage_and_cap_overrun(self) -> None:
        prepared = self.backend.prepare_request(
            "responses",
            {"model": MODEL, "input": "hello", "max_output_tokens": 5, "mycomesh_p2p_request_hash": P2P_REQUEST_HASH},
        )
        cases = [
            self._result(prepared, total_tokens=13),
            self._result(prepared, output_tokens=6, total_tokens=13),
            self._result(prepared, input_tokens=True, total_tokens=6),
            self._result(prepared, proof_overrides={"nonce": "replayed"}),
            self._result(
                prepared,
                proof_overrides={"p2p_request_hash": "ef" * 32},
            ),
            self._result(prepared, result_overrides={"model": "wrong"}),
        ]
        for document in cases:
            with self.subTest(document=document), self.assertRaises(NativeMeteringError):
                self.backend.verify_result(prepared, document, now=NOW)

        tampered = self._result(prepared)
        tampered["result"]["output_text"] = "changed after signing"
        with self.assertRaisesRegex(NativeMeteringError, "response_hash"):
            self.backend.verify_result(prepared, tampered, now=NOW)

    def test_remote_plaintext_and_missing_trust_pins_are_rejected(self) -> None:
        kwargs = {
            "api_key": "k" * 32,
            "expected_model": MODEL,
            "expected_model_revision": REVISION,
            "metering_public_key": self.identity.public_key,
            "capabilities_sha256": CAPABILITIES_DIGEST,
            "audience": AUDIENCE,
            "default_output_token_cap": 64,
        }
        with self.assertRaisesRegex(ValueError, "requires HTTPS"):
            NativeMeteredBackend(base_url="http://provider.example/v1", **kwargs)
        with self.assertRaisesRegex(ValueError, "UPSTREAM_API_KEY"):
            NativeMeteredBackend(
                base_url="https://provider.example/v1",
                **{**kwargs, "api_key": "short"},
            )


class NativeMeteringRefreshTest(unittest.IsolatedAsyncioTestCase):
    async def test_failed_concurrent_refresh_is_single_flight_and_backed_off(self) -> None:
        identity = create_identity()
        backend = NativeMeteredBackend(
            base_url="http://127.0.0.1:9000/v1",
            api_key="k" * 32,
            expected_model=MODEL,
            expected_model_revision=REVISION,
            metering_public_key=identity.public_key,
            capabilities_sha256=CAPABILITIES_DIGEST,
            audience=AUDIENCE,
            default_output_token_cap=64,
        )

        class FailingUpstream:
            def __init__(self) -> None:
                self.calls = 0

            async def post_json(self, _path, _body):
                self.calls += 1
                await asyncio.sleep(0.01)
                raise UpstreamError("offline")

        upstream = FailingUpstream()
        results = await asyncio.gather(
            *(backend.ensure_ready(upstream) for _ in range(8)),
            return_exceptions=True,
        )
        self.assertEqual(upstream.calls, 1)
        self.assertTrue(all(isinstance(result, NativeMeteringError) for result in results))
        with self.assertRaisesRegex(NativeMeteringError, "backoff"):
            await backend.ensure_ready(upstream)
        self.assertEqual(upstream.calls, 1)
        self.assertFalse(backend.capabilities["production_ready"])


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _result_hash(value: dict[str, object]) -> str:
    return _hash({key: item for key, item in value.items() if key != "usage"})


if __name__ == "__main__":
    unittest.main()
