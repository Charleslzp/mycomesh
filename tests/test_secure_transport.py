from __future__ import annotations

import io
import json
import struct
import unittest

from gateway.identity import canonical_json, create_identity
from gateway.secure_transport import (
    MemoryReplayStore,
    SecureEnvelopeError,
    SecureEnvelopeReplayError,
    TransportKeyError,
    TransportKeyPair,
    generate_transport_key,
    open_frame,
    read_secure_frame,
    seal_frame,
    seal_json_frame,
    verify_transport_key_binding,
)


PURPOSE = "mycomesh.p2p.infer.v1"


class SecureTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_800_000_000
        self.consumer = create_identity()
        self.provider = create_identity()
        self.provider_transport = generate_transport_key(self.provider, now=self.now)

    def test_json_round_trip_is_confidential_and_identity_bound(self) -> None:
        document = {"type": "infer", "prompt": "the relay must not see this secret"}
        frame = self._seal_json(document)

        self.assertNotIn(b"relay must not see", frame)
        opened = self._open(frame)

        self.assertEqual(opened.json_payload(), document)
        self.assertEqual(opened.sender_peer_id, self.consumer.peer_id)
        self.assertEqual(opened.sender_public_key, self.consumer.public_key)
        self.assertEqual(opened.recipient_peer_id, self.provider.peer_id)

    def test_transport_key_binding_detects_substitution(self) -> None:
        binding = json.loads(json.dumps(self.provider_transport.binding))
        binding["encryption_public_key"] = generate_transport_key(
            self.consumer, now=self.now
        ).binding["encryption_public_key"]

        with self.assertRaisesRegex(TransportKeyError, "key_id does not match"):
            verify_transport_key_binding(binding, expected_peer_id=self.provider.peer_id, now=self.now)

    def test_transport_key_binding_rejects_wrong_expected_identity(self) -> None:
        with self.assertRaisesRegex(TransportKeyError, "peer_id mismatch"):
            verify_transport_key_binding(
                self.provider_transport.binding,
                expected_peer_id=self.consumer.peer_id,
                now=self.now,
            )

        with self.assertRaisesRegex(TransportKeyError, "identity public key mismatch"):
            self._seal(
                b"hello",
                expected_recipient_public_key=self.consumer.public_key,
            )

    def test_transport_key_binding_expires(self) -> None:
        key = generate_transport_key(self.provider, lifetime_seconds=60, now=self.now)

        with self.assertRaisesRegex(TransportKeyError, "expired"):
            verify_transport_key_binding(key.binding, now=self.now + 60)

    def test_private_key_must_match_signed_binding(self) -> None:
        unrelated = generate_transport_key(self.provider, now=self.now)
        mismatched = TransportKeyPair(
            binding=self.provider_transport.binding,
            private_key=unrelated.private_key,
        )
        frame = self._seal(b"hello")

        with self.assertRaisesRegex(TransportKeyError, "does not match"):
            self._open(frame, recipient_key=mismatched)

    def test_wrong_recipient_cannot_open_frame(self) -> None:
        other_identity = create_identity()
        other_key = generate_transport_key(other_identity, now=self.now)
        frame = self._seal(b"hello")

        with self.assertRaisesRegex(SecureEnvelopeError, "audience peer_id mismatch"):
            self._open(frame, recipient_key=other_key)

    def test_wrong_sender_is_rejected(self) -> None:
        frame = self._seal(b"hello")

        with self.assertRaisesRegex(SecureEnvelopeError, "sender peer_id mismatch"):
            self._open(frame, expected_sender_peer_id=create_identity().peer_id)

    def test_wrong_purpose_is_rejected(self) -> None:
        frame = self._seal(b"hello")

        with self.assertRaisesRegex(SecureEnvelopeError, "purpose mismatch"):
            self._open(frame, expected_purpose="mycomesh.p2p.control.v1")

    def test_ciphertext_tampering_is_rejected_before_replay_claim(self) -> None:
        frame = self._seal(b"hello")
        envelope = self._envelope(frame)
        ciphertext = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        tampered = self._frame(envelope)
        replay = MemoryReplayStore()

        with self.assertRaisesRegex(SecureEnvelopeError, "signature"):
            self._open(tampered, replay_store=replay)
        self._open(frame, replay_store=replay)

    def test_replay_is_rejected_atomically(self) -> None:
        frame = self._seal(b"hello")
        replay = MemoryReplayStore()
        self._open(frame, replay_store=replay)

        with self.assertRaisesRegex(SecureEnvelopeReplayError, "already accepted"):
            self._open(frame, replay_store=replay)

    def test_expired_envelope_is_rejected(self) -> None:
        frame = self._seal(b"hello", ttl_seconds=60)

        with self.assertRaisesRegex(SecureEnvelopeError, "expired"):
            self._open(frame, now=self.now + 60)

    def test_far_future_envelope_is_rejected(self) -> None:
        future_frame = self._seal(b"hello", now=self.now + 120)

        with self.assertRaisesRegex(SecureEnvelopeError, "issued in the future"):
            self._open(future_frame, now=self.now)

    def test_plaintext_size_is_checked_before_encryption_and_after_decryption(self) -> None:
        with self.assertRaisesRegex(SecureEnvelopeError, "plaintext exceeds 4 bytes"):
            self._seal(b"12345", maximum_plaintext_bytes=4)

        frame = self._seal(b"12345")
        with self.assertRaisesRegex(SecureEnvelopeError, "plaintext exceeds 4 bytes"):
            self._open(frame, maximum_plaintext_bytes=4)

    def test_frame_rejects_length_mismatch_and_trailing_bytes(self) -> None:
        frame = self._seal(b"hello")

        with self.assertRaisesRegex(SecureEnvelopeError, "length mismatch"):
            self._open(frame + b"x")
        with self.assertRaisesRegex(SecureEnvelopeError, "length mismatch"):
            self._open(frame[:-1])

    def test_frame_rejects_noncanonical_json(self) -> None:
        frame = self._seal(b"hello")
        envelope = self._envelope(frame)
        raw = json.dumps(envelope, indent=2).encode("utf-8")
        noncanonical = struct.pack("!I", len(raw)) + raw

        with self.assertRaisesRegex(SecureEnvelopeError, "not canonical"):
            self._open(noncanonical)

    def test_read_secure_frame_handles_partial_reads_without_consuming_next_frame(self) -> None:
        first = self._seal(b"first")
        second = self._seal(b"second")
        stream = _ShortReadStream(first + second)

        self.assertEqual(read_secure_frame(stream), first)
        self.assertEqual(read_secure_frame(stream), second)

    def test_read_secure_frame_rejects_declared_oversize_before_body_read(self) -> None:
        stream = io.BytesIO(struct.pack("!I", 10_000))

        with self.assertRaisesRegex(SecureEnvelopeError, "exceeds 100 bytes"):
            read_secure_frame(stream, maximum_frame_bytes=100)

    def test_json_payload_rejects_duplicate_keys(self) -> None:
        frame = self._seal(b'{"type":"infer","type":"admin"}')
        opened = self._open(frame)

        with self.assertRaisesRegex(SecureEnvelopeError, "strict JSON"):
            opened.json_payload()

    def test_memory_replay_store_fails_closed_at_capacity(self) -> None:
        replay = MemoryReplayStore(maximum_entries=1)
        replay.remember("scope", "one", 60, now=self.now)

        with self.assertRaisesRegex(Exception, "capacity exceeded"):
            replay.remember("scope", "two", 60, now=self.now)

    def _seal_json(self, document: dict, **overrides: object) -> bytes:
        options = {
            "sender": self.consumer,
            "recipient_binding": self.provider_transport.binding,
            "expected_recipient_peer_id": self.provider.peer_id,
            "expected_recipient_public_key": self.provider.public_key,
            "purpose": PURPOSE,
            "now": self.now,
        }
        options.update(overrides)
        return seal_json_frame(document, **options)  # type: ignore[arg-type]

    def _seal(self, payload: bytes, **overrides: object) -> bytes:
        options = {
            "sender": self.consumer,
            "recipient_binding": self.provider_transport.binding,
            "expected_recipient_peer_id": self.provider.peer_id,
            "expected_recipient_public_key": self.provider.public_key,
            "purpose": PURPOSE,
            "now": self.now,
        }
        options.update(overrides)
        return seal_frame(payload, **options)  # type: ignore[arg-type]

    def _open(self, frame: bytes, **overrides: object):
        options = {
            "recipient_key": self.provider_transport,
            "expected_purpose": PURPOSE,
            "expected_sender_peer_id": self.consumer.peer_id,
            "expected_sender_public_key": self.consumer.public_key,
            "replay_store": MemoryReplayStore(),
            "now": self.now,
        }
        options.update(overrides)
        return open_frame(frame, **options)  # type: ignore[arg-type]

    @staticmethod
    def _envelope(frame: bytes) -> dict:
        return json.loads(frame[4:].decode("utf-8"))

    @staticmethod
    def _frame(envelope: dict) -> bytes:
        raw = canonical_json(envelope).encode("utf-8")
        return struct.pack("!I", len(raw)) + raw


class _ShortReadStream(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(min(size, 7) if size >= 0 else 7)


if __name__ == "__main__":
    unittest.main()
