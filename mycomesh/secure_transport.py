from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .identity import (
    IdentityError,
    NodeIdentity,
    canonical_json,
    peer_id_from_public_key,
    public_key_from_private_key,
    sign_document,
    verify_document,
)
from .replay import ReplayError


SECURE_ENVELOPE_VERSION = "mycomesh-secure-envelope-v1"
TRANSPORT_KEY_VERSION = "mycomesh-transport-key-v1"
TRANSPORT_KEY_PURPOSE = "mycomesh.transport.key_binding.v1"
ENVELOPE_SIGNATURE_PURPOSE = "mycomesh.transport.envelope.v1"
TRANSPORT_KEY_ALGORITHM = "X25519"
ENVELOPE_ALGORITHM = "X25519-HKDF-SHA256-CHACHA20POLY1305"
REPLAY_SCOPE = "mycomesh.transport.envelope.v1"

MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024
MAX_SECURE_FRAME_BYTES = 12 * 1024 * 1024
MAX_ENVELOPE_TTL_SECONDS = 5 * 60
MAX_TRANSPORT_KEY_LIFETIME_SECONDS = 30 * 24 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 30
MAX_REPLAY_ENTRIES = 100_000

_FRAME_PREFIX_BYTES = 4
_AEAD_NONCE_BYTES = 12
_AEAD_TAG_BYTES = 16
_HEX_32_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_16_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_HEX_NONCE_PATTERN = re.compile(r"^[0-9a-f]{24}$")
_SIGNATURE_PATTERN = re.compile(r"^[0-9a-f]{128}$")
_KEY_ID_PATTERN = re.compile(r"^x25519_[0-9a-f]{64}$")
_PURPOSE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_KDF_INFO = b"mycomesh-secure-envelope-v1\x00X25519-HKDF-SHA256-CHACHA20POLY1305"

_KEY_BINDING_FIELDS = {
    "version",
    "algorithm",
    "peer_id",
    "identity_public_key",
    "encryption_public_key",
    "key_id",
    "not_before",
    "expires_at",
    "signature",
}
_ENVELOPE_FIELDS = {
    "version",
    "algorithm",
    "message_id",
    "purpose",
    "sender_peer_id",
    "sender_public_key",
    "recipient_peer_id",
    "recipient_public_key",
    "recipient_key_id",
    "ephemeral_public_key",
    "nonce",
    "issued_at",
    "expires_at",
    "ciphertext",
    "signature",
}
_BINDING_SIGNATURE_FIELDS = {"nonce", "public_key", "purpose", "timestamp", "signature"}
_ENVELOPE_SIGNATURE_FIELDS = _BINDING_SIGNATURE_FIELDS | {"audience"}


class SecureTransportError(RuntimeError):
    pass


class TransportKeyError(SecureTransportError):
    pass


class SecureEnvelopeError(SecureTransportError):
    pass


class SecureEnvelopeReplayError(SecureEnvelopeError):
    pass


class ReplayStoreLike(Protocol):
    def remember(self, scope: str, replay_key: str, ttl_seconds: int, now: int | None = None) -> None: ...


@dataclass(frozen=True)
class VerifiedTransportKey:
    peer_id: str
    identity_public_key: str
    encryption_public_key: str
    key_id: str
    not_before: int
    expires_at: int


@dataclass(frozen=True)
class TransportKeyPair:
    binding: dict[str, Any]
    private_key: str = field(repr=False)


@dataclass(frozen=True)
class OpenedEnvelope:
    payload: bytes
    message_id: str
    purpose: str
    sender_peer_id: str
    sender_public_key: str
    recipient_peer_id: str
    recipient_public_key: str
    recipient_key_id: str
    issued_at: int
    expires_at: int

    def json_payload(self) -> dict[str, Any]:
        value = _load_json(self.payload, "secure envelope payload")
        if not isinstance(value, dict):
            raise SecureEnvelopeError("secure envelope JSON payload must be an object")
        return value


@dataclass(frozen=True)
class VerifiedEnvelopeMetadata:
    message_id: str
    purpose: str
    sender_peer_id: str
    sender_public_key: str
    recipient_peer_id: str
    recipient_public_key: str
    recipient_key_id: str
    issued_at: int
    expires_at: int


class MemoryReplayStore:
    """Process-local replay protection for tests and single-process deployments."""

    def __init__(self, maximum_entries: int = MAX_REPLAY_ENTRIES) -> None:
        if isinstance(maximum_entries, bool) or not isinstance(maximum_entries, int) or maximum_entries <= 0:
            raise ValueError("maximum_entries must be a positive integer")
        self.maximum_entries = maximum_entries
        self._entries: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def remember(self, scope: str, replay_key: str, ttl_seconds: int, now: int | None = None) -> None:
        resolved_scope = str(scope or "").strip()
        resolved_key = str(replay_key or "").strip()
        if not resolved_scope or not resolved_key:
            raise SecureTransportError("replay scope and key are required")
        current_time = _timestamp(now, "replay time")
        ttl = _positive_integer(ttl_seconds, "replay TTL", maximum=MAX_ENVELOPE_TTL_SECONDS)
        with self._lock:
            expired = [key for key, expires_at in self._entries.items() if expires_at < current_time]
            for key in expired:
                del self._entries[key]
            entry_key = (resolved_scope, resolved_key)
            if self._entries.get(entry_key, -1) >= current_time:
                raise SecureEnvelopeReplayError("secure envelope was already accepted")
            if len(self._entries) >= self.maximum_entries:
                raise SecureTransportError("replay store capacity exceeded")
            self._entries[entry_key] = current_time + ttl


def generate_transport_key(
    identity: NodeIdentity,
    *,
    lifetime_seconds: int = 24 * 60 * 60,
    now: int | None = None,
) -> TransportKeyPair:
    current_time = _timestamp(now, "current time")
    lifetime = _positive_integer(
        lifetime_seconds,
        "transport key lifetime",
        maximum=MAX_TRANSPORT_KEY_LIFETIME_SECONDS,
    )
    _verify_node_identity(identity)
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key = public_bytes.hex()
    document = {
        "version": TRANSPORT_KEY_VERSION,
        "algorithm": TRANSPORT_KEY_ALGORITHM,
        "peer_id": identity.peer_id,
        "identity_public_key": identity.public_key,
        "encryption_public_key": public_key,
        "key_id": _transport_key_id(public_bytes),
        "not_before": current_time,
        "expires_at": current_time + lifetime,
    }
    binding = sign_document(
        document,
        identity.private_key,
        purpose=TRANSPORT_KEY_PURPOSE,
        timestamp=current_time,
    )
    return TransportKeyPair(binding=binding, private_key=private_bytes.hex())


def verify_transport_key_binding(
    binding: Any,
    *,
    expected_peer_id: str | None = None,
    expected_identity_public_key: str | None = None,
    now: int | None = None,
) -> VerifiedTransportKey:
    current_time = _timestamp(now, "current time")
    if not isinstance(binding, dict):
        raise TransportKeyError("transport key binding must be an object")
    _require_exact_fields(binding, _KEY_BINDING_FIELDS, "transport key binding", TransportKeyError)
    if binding.get("version") != TRANSPORT_KEY_VERSION:
        raise TransportKeyError("unsupported transport key binding version")
    if binding.get("algorithm") != TRANSPORT_KEY_ALGORITHM:
        raise TransportKeyError("unsupported transport key algorithm")

    peer_id = _text(binding.get("peer_id"), "transport peer_id", maximum=160, error=TransportKeyError)
    identity_public_key = _lower_hex_32(
        binding.get("identity_public_key"), "transport identity public key", TransportKeyError
    )
    encryption_public_key = _lower_hex_32(
        binding.get("encryption_public_key"), "transport encryption public key", TransportKeyError
    )
    key_id = _text(binding.get("key_id"), "transport key_id", maximum=80, error=TransportKeyError)
    if _KEY_ID_PATTERN.fullmatch(key_id) is None:
        raise TransportKeyError("transport key_id is malformed")
    if key_id != _transport_key_id(bytes.fromhex(encryption_public_key)):
        raise TransportKeyError("transport key_id does not match encryption public key")
    try:
        derived_peer_id = peer_id_from_public_key(identity_public_key)
    except (IdentityError, TypeError, ValueError) as exc:
        raise TransportKeyError("transport identity public key is invalid") from exc
    if peer_id != derived_peer_id:
        raise TransportKeyError("transport peer_id does not match identity public key")
    if expected_peer_id is not None and peer_id != str(expected_peer_id):
        raise TransportKeyError("transport key binding peer_id mismatch")
    if expected_identity_public_key is not None and identity_public_key != str(expected_identity_public_key).lower():
        raise TransportKeyError("transport key binding identity public key mismatch")

    not_before = _integer(binding.get("not_before"), "transport key not_before", TransportKeyError)
    expires_at = _integer(binding.get("expires_at"), "transport key expires_at", TransportKeyError)
    if expires_at <= not_before:
        raise TransportKeyError("transport key expiry must follow not_before")
    if expires_at - not_before > MAX_TRANSPORT_KEY_LIFETIME_SECONDS:
        raise TransportKeyError("transport key lifetime exceeds the maximum")

    signature = binding.get("signature")
    _validate_signature(
        signature,
        fields=_BINDING_SIGNATURE_FIELDS,
        purpose=TRANSPORT_KEY_PURPOSE,
        audience=None,
        error=TransportKeyError,
    )
    assert isinstance(signature, dict)
    signature_timestamp = _integer(signature.get("timestamp"), "transport key signature timestamp", TransportKeyError)
    if signature_timestamp < not_before - MAX_CLOCK_SKEW_SECONDS:
        raise TransportKeyError("transport key was signed too early")
    if signature_timestamp > not_before + MAX_CLOCK_SKEW_SECONDS:
        raise TransportKeyError("transport key signature timestamp does not match not_before")
    if signature_timestamp > current_time + MAX_CLOCK_SKEW_SECONDS:
        raise TransportKeyError("transport key signature timestamp is in the future")
    if not_before > current_time + MAX_CLOCK_SKEW_SECONDS:
        raise TransportKeyError("transport key is not active yet")
    if expires_at <= current_time:
        raise TransportKeyError("transport key has expired")
    if signature.get("public_key") != identity_public_key:
        raise TransportKeyError("transport key signer does not match identity public key")
    try:
        verify_document(binding, purpose=TRANSPORT_KEY_PURPOSE, max_age_seconds=0)
    except (IdentityError, TypeError, ValueError) as exc:
        raise TransportKeyError(f"invalid transport key binding signature: {exc}") from exc
    return VerifiedTransportKey(
        peer_id=peer_id,
        identity_public_key=identity_public_key,
        encryption_public_key=encryption_public_key,
        key_id=key_id,
        not_before=not_before,
        expires_at=expires_at,
    )


def seal_frame(
    payload: bytes,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_peer_id: str,
    expected_recipient_public_key: str | None = None,
    purpose: str,
    ttl_seconds: int = 60,
    now: int | None = None,
    maximum_plaintext_bytes: int = MAX_PLAINTEXT_BYTES,
) -> bytes:
    current_time = _timestamp(now, "current time")
    ttl = _positive_integer(ttl_seconds, "secure envelope TTL", maximum=MAX_ENVELOPE_TTL_SECONDS)
    maximum_plaintext = _positive_integer(
        maximum_plaintext_bytes,
        "maximum plaintext size",
        maximum=MAX_PLAINTEXT_BYTES,
    )
    if not isinstance(payload, bytes):
        raise SecureEnvelopeError("secure envelope payload must be bytes")
    if len(payload) > maximum_plaintext:
        raise SecureEnvelopeError(f"secure envelope plaintext exceeds {maximum_plaintext} bytes")
    resolved_purpose = _purpose(purpose)
    _verify_node_identity(sender)
    recipient = verify_transport_key_binding(
        recipient_binding,
        expected_peer_id=expected_recipient_peer_id,
        expected_identity_public_key=expected_recipient_public_key,
        now=current_time,
    )
    expires_at = current_time + ttl
    if expires_at > recipient.expires_at:
        raise SecureEnvelopeError("secure envelope outlives the recipient transport key")

    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    message_id = secrets.token_hex(16)
    nonce = secrets.token_bytes(_AEAD_NONCE_BYTES)
    header = {
        "version": SECURE_ENVELOPE_VERSION,
        "algorithm": ENVELOPE_ALGORITHM,
        "message_id": message_id,
        "purpose": resolved_purpose,
        "sender_peer_id": sender.peer_id,
        "sender_public_key": sender.public_key,
        "recipient_peer_id": recipient.peer_id,
        "recipient_public_key": recipient.identity_public_key,
        "recipient_key_id": recipient.key_id,
        "ephemeral_public_key": ephemeral_public.hex(),
        "nonce": nonce.hex(),
        "issued_at": current_time,
        "expires_at": expires_at,
    }
    aad = canonical_json(header).encode("utf-8")
    try:
        shared_secret = ephemeral_private.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(recipient.encryption_public_key))
        )
    except ValueError as exc:
        raise SecureEnvelopeError("recipient transport public key is invalid") from exc
    content_key = _derive_content_key(shared_secret, aad)
    ciphertext = ChaCha20Poly1305(content_key).encrypt(nonce, payload, aad)
    envelope = dict(header)
    envelope["ciphertext"] = _base64url_encode(ciphertext)
    signed = sign_document(
        envelope,
        sender.private_key,
        purpose=ENVELOPE_SIGNATURE_PURPOSE,
        timestamp=current_time,
        nonce=message_id,
        audience=recipient.identity_public_key,
    )
    return _encode_frame(signed)


def seal_json_frame(
    document: dict[str, Any],
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_peer_id: str,
    expected_recipient_public_key: str | None = None,
    purpose: str,
    ttl_seconds: int = 60,
    now: int | None = None,
    maximum_plaintext_bytes: int = MAX_PLAINTEXT_BYTES,
) -> bytes:
    if not isinstance(document, dict):
        raise SecureEnvelopeError("secure envelope JSON document must be an object")
    return seal_frame(
        canonical_json(document).encode("utf-8"),
        sender=sender,
        recipient_binding=recipient_binding,
        expected_recipient_peer_id=expected_recipient_peer_id,
        expected_recipient_public_key=expected_recipient_public_key,
        purpose=purpose,
        ttl_seconds=ttl_seconds,
        now=now,
        maximum_plaintext_bytes=maximum_plaintext_bytes,
    )


def open_frame(
    frame: bytes,
    *,
    recipient_key: TransportKeyPair,
    expected_purpose: str,
    replay_store: ReplayStoreLike,
    expected_sender_peer_id: str | None = None,
    expected_sender_public_key: str | None = None,
    now: int | None = None,
    maximum_plaintext_bytes: int = MAX_PLAINTEXT_BYTES,
    maximum_frame_bytes: int = MAX_SECURE_FRAME_BYTES,
) -> OpenedEnvelope:
    current_time = _timestamp(now, "current time")
    maximum_plaintext = _positive_integer(
        maximum_plaintext_bytes,
        "maximum plaintext size",
        maximum=MAX_PLAINTEXT_BYTES,
    )
    maximum_frame = _positive_integer(
        maximum_frame_bytes,
        "maximum secure frame size",
        maximum=MAX_SECURE_FRAME_BYTES,
    )
    resolved_purpose = _purpose(expected_purpose)
    if not callable(getattr(replay_store, "remember", None)):
        raise SecureTransportError("an atomic replay store is required")
    recipient = _verified_private_transport_key(recipient_key, now=current_time)
    envelope = _decode_frame(frame, maximum_frame_bytes=maximum_frame)
    _require_exact_fields(envelope, _ENVELOPE_FIELDS, "secure envelope", SecureEnvelopeError)
    if envelope.get("version") != SECURE_ENVELOPE_VERSION:
        raise SecureEnvelopeError("unsupported secure envelope version")
    if envelope.get("algorithm") != ENVELOPE_ALGORITHM:
        raise SecureEnvelopeError("unsupported secure envelope algorithm")

    message_id = _text(envelope.get("message_id"), "secure envelope message_id", maximum=32)
    if _HEX_16_PATTERN.fullmatch(message_id) is None:
        raise SecureEnvelopeError("secure envelope message_id must be 16 bytes of lowercase hex")
    purpose = _purpose(envelope.get("purpose"))
    if purpose != resolved_purpose:
        raise SecureEnvelopeError("secure envelope purpose mismatch")
    sender_peer_id = _text(envelope.get("sender_peer_id"), "secure envelope sender peer_id", maximum=160)
    sender_public_key = _lower_hex_32(envelope.get("sender_public_key"), "secure envelope sender public key")
    try:
        derived_sender_peer_id = peer_id_from_public_key(sender_public_key)
    except (IdentityError, TypeError, ValueError) as exc:
        raise SecureEnvelopeError("secure envelope sender public key is invalid") from exc
    if sender_peer_id != derived_sender_peer_id:
        raise SecureEnvelopeError("secure envelope sender peer_id does not match public key")
    if expected_sender_peer_id is not None and sender_peer_id != str(expected_sender_peer_id):
        raise SecureEnvelopeError("secure envelope sender peer_id mismatch")
    if expected_sender_public_key is not None and sender_public_key != str(expected_sender_public_key).lower():
        raise SecureEnvelopeError("secure envelope sender public key mismatch")

    if envelope.get("recipient_peer_id") != recipient.peer_id:
        raise SecureEnvelopeError("secure envelope audience peer_id mismatch")
    if envelope.get("recipient_public_key") != recipient.identity_public_key:
        raise SecureEnvelopeError("secure envelope audience public key mismatch")
    if envelope.get("recipient_key_id") != recipient.key_id:
        raise SecureEnvelopeError("secure envelope recipient key_id mismatch")
    ephemeral_public_key = _lower_hex_32(
        envelope.get("ephemeral_public_key"), "secure envelope ephemeral public key"
    )
    nonce_hex = _text(envelope.get("nonce"), "secure envelope nonce", maximum=24)
    if _HEX_NONCE_PATTERN.fullmatch(nonce_hex) is None:
        raise SecureEnvelopeError("secure envelope nonce must be 12 bytes of lowercase hex")

    issued_at = _integer(envelope.get("issued_at"), "secure envelope issued_at")
    expires_at = _integer(envelope.get("expires_at"), "secure envelope expires_at")
    if expires_at <= issued_at:
        raise SecureEnvelopeError("secure envelope expiry must follow issued_at")
    if expires_at - issued_at > MAX_ENVELOPE_TTL_SECONDS:
        raise SecureEnvelopeError("secure envelope TTL exceeds the maximum")
    if issued_at > current_time + MAX_CLOCK_SKEW_SECONDS:
        raise SecureEnvelopeError("secure envelope was issued in the future")
    if expires_at <= current_time:
        raise SecureEnvelopeError("secure envelope has expired")
    if issued_at < recipient.not_before - MAX_CLOCK_SKEW_SECONDS:
        raise SecureEnvelopeError("secure envelope predates the recipient transport key")
    if expires_at > recipient.expires_at:
        raise SecureEnvelopeError("secure envelope outlives the recipient transport key")

    signature = envelope.get("signature")
    _validate_signature(
        signature,
        fields=_ENVELOPE_SIGNATURE_FIELDS,
        purpose=ENVELOPE_SIGNATURE_PURPOSE,
        audience=recipient.identity_public_key,
        error=SecureEnvelopeError,
    )
    assert isinstance(signature, dict)
    if signature.get("public_key") != sender_public_key:
        raise SecureEnvelopeError("secure envelope signer does not match sender public key")
    if signature.get("nonce") != message_id:
        raise SecureEnvelopeError("secure envelope signature nonce does not match message_id")
    if signature.get("timestamp") != issued_at:
        raise SecureEnvelopeError("secure envelope signature timestamp does not match issued_at")
    try:
        verify_document(
            envelope,
            purpose=ENVELOPE_SIGNATURE_PURPOSE,
            audience=recipient.identity_public_key,
            max_age_seconds=0,
        )
    except (IdentityError, TypeError, ValueError) as exc:
        raise SecureEnvelopeError(f"invalid secure envelope signature: {exc}") from exc

    ciphertext = _base64url_decode(envelope.get("ciphertext"), "secure envelope ciphertext")
    if len(ciphertext) < _AEAD_TAG_BYTES:
        raise SecureEnvelopeError("secure envelope ciphertext is too short")
    if len(ciphertext) > maximum_plaintext + _AEAD_TAG_BYTES:
        raise SecureEnvelopeError(f"secure envelope plaintext exceeds {maximum_plaintext} bytes")
    header = {key: envelope[key] for key in _ENVELOPE_FIELDS if key not in {"ciphertext", "signature"}}
    aad = canonical_json(header).encode("utf-8")
    try:
        recipient_private = X25519PrivateKey.from_private_bytes(bytes.fromhex(recipient_key.private_key))
        shared_secret = recipient_private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(ephemeral_public_key)))
        plaintext = ChaCha20Poly1305(_derive_content_key(shared_secret, aad)).decrypt(
            bytes.fromhex(nonce_hex), ciphertext, aad
        )
    except (InvalidTag, ValueError) as exc:
        raise SecureEnvelopeError("secure envelope authentication failed") from exc
    if len(plaintext) > maximum_plaintext:
        raise SecureEnvelopeError(f"secure envelope plaintext exceeds {maximum_plaintext} bytes")

    replay_key = f"{sender_public_key}:{recipient.key_id}:{message_id}"
    replay_ttl = max(1, expires_at - current_time)
    try:
        replay_store.remember(REPLAY_SCOPE, replay_key, replay_ttl, now=current_time)
    except SecureEnvelopeReplayError:
        raise
    except ReplayError as exc:
        raise SecureEnvelopeReplayError("secure envelope was already accepted") from exc

    return OpenedEnvelope(
        payload=plaintext,
        message_id=message_id,
        purpose=purpose,
        sender_peer_id=sender_peer_id,
        sender_public_key=sender_public_key,
        recipient_peer_id=recipient.peer_id,
        recipient_public_key=recipient.identity_public_key,
        recipient_key_id=recipient.key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def verify_frame_metadata(
    frame: bytes,
    *,
    expected_purpose: str,
    expected_recipient_peer_id: str | None = None,
    expected_recipient_public_key: str | None = None,
    expected_recipient_binding: dict[str, Any] | None = None,
    now: int | None = None,
    maximum_plaintext_bytes: int = MAX_PLAINTEXT_BYTES,
    maximum_frame_bytes: int = MAX_SECURE_FRAME_BYTES,
) -> VerifiedEnvelopeMetadata:
    """Authenticate envelope routing metadata without decrypting its payload."""
    current_time = _timestamp(now, "current time")
    maximum_plaintext = _positive_integer(
        maximum_plaintext_bytes,
        "maximum plaintext size",
        maximum=MAX_PLAINTEXT_BYTES,
    )
    maximum_frame = _positive_integer(
        maximum_frame_bytes,
        "maximum secure frame size",
        maximum=MAX_SECURE_FRAME_BYTES,
    )
    purpose = _purpose(expected_purpose)
    envelope = _decode_frame(frame, maximum_frame_bytes=maximum_frame)
    _require_exact_fields(envelope, _ENVELOPE_FIELDS, "secure envelope", SecureEnvelopeError)
    if envelope.get("version") != SECURE_ENVELOPE_VERSION:
        raise SecureEnvelopeError("unsupported secure envelope version")
    if envelope.get("algorithm") != ENVELOPE_ALGORITHM:
        raise SecureEnvelopeError("unsupported secure envelope algorithm")

    message_id = _text(envelope.get("message_id"), "secure envelope message_id", maximum=32)
    if _HEX_16_PATTERN.fullmatch(message_id) is None:
        raise SecureEnvelopeError("secure envelope message_id must be 16 bytes of lowercase hex")
    envelope_purpose = _purpose(envelope.get("purpose"))
    if envelope_purpose != purpose:
        raise SecureEnvelopeError("secure envelope purpose mismatch")

    sender_peer_id = _text(envelope.get("sender_peer_id"), "secure envelope sender peer_id", maximum=160)
    sender_public_key = _lower_hex_32(envelope.get("sender_public_key"), "secure envelope sender public key")
    recipient_peer_id = _text(
        envelope.get("recipient_peer_id"), "secure envelope recipient peer_id", maximum=160
    )
    recipient_public_key = _lower_hex_32(
        envelope.get("recipient_public_key"), "secure envelope recipient public key"
    )
    try:
        if peer_id_from_public_key(sender_public_key) != sender_peer_id:
            raise SecureEnvelopeError("secure envelope sender peer_id does not match public key")
        if peer_id_from_public_key(recipient_public_key) != recipient_peer_id:
            raise SecureEnvelopeError("secure envelope recipient peer_id does not match public key")
    except (IdentityError, TypeError, ValueError) as exc:
        raise SecureEnvelopeError("secure envelope identity public key is invalid") from exc
    if expected_recipient_peer_id is not None and recipient_peer_id != str(expected_recipient_peer_id):
        raise SecureEnvelopeError("secure envelope audience peer_id mismatch")
    if (
        expected_recipient_public_key is not None
        and recipient_public_key != str(expected_recipient_public_key).lower()
    ):
        raise SecureEnvelopeError("secure envelope audience public key mismatch")

    recipient_key_id = _text(
        envelope.get("recipient_key_id"), "secure envelope recipient key_id", maximum=80
    )
    if _KEY_ID_PATTERN.fullmatch(recipient_key_id) is None:
        raise SecureEnvelopeError("secure envelope recipient key_id is malformed")
    if expected_recipient_binding is not None:
        try:
            recipient = verify_transport_key_binding(
                expected_recipient_binding,
                expected_peer_id=recipient_peer_id,
                expected_identity_public_key=recipient_public_key,
                now=current_time,
            )
        except TransportKeyError as exc:
            raise SecureEnvelopeError(f"invalid secure envelope recipient binding: {exc}") from exc
        if recipient.key_id != recipient_key_id:
            raise SecureEnvelopeError("secure envelope recipient key_id mismatch")

    _lower_hex_32(envelope.get("ephemeral_public_key"), "secure envelope ephemeral public key")
    nonce_hex = _text(envelope.get("nonce"), "secure envelope nonce", maximum=24)
    if _HEX_NONCE_PATTERN.fullmatch(nonce_hex) is None:
        raise SecureEnvelopeError("secure envelope nonce must be 12 bytes of lowercase hex")
    issued_at = _integer(envelope.get("issued_at"), "secure envelope issued_at")
    expires_at = _integer(envelope.get("expires_at"), "secure envelope expires_at")
    if expires_at <= issued_at:
        raise SecureEnvelopeError("secure envelope expiry must follow issued_at")
    if expires_at - issued_at > MAX_ENVELOPE_TTL_SECONDS:
        raise SecureEnvelopeError("secure envelope TTL exceeds the maximum")
    if issued_at > current_time + MAX_CLOCK_SKEW_SECONDS:
        raise SecureEnvelopeError("secure envelope was issued in the future")
    if expires_at <= current_time:
        raise SecureEnvelopeError("secure envelope has expired")

    signature = envelope.get("signature")
    _validate_signature(
        signature,
        fields=_ENVELOPE_SIGNATURE_FIELDS,
        purpose=ENVELOPE_SIGNATURE_PURPOSE,
        audience=recipient_public_key,
        error=SecureEnvelopeError,
    )
    assert isinstance(signature, dict)
    if signature.get("public_key") != sender_public_key:
        raise SecureEnvelopeError("secure envelope signer does not match sender public key")
    if signature.get("nonce") != message_id:
        raise SecureEnvelopeError("secure envelope signature nonce does not match message_id")
    if signature.get("timestamp") != issued_at:
        raise SecureEnvelopeError("secure envelope signature timestamp does not match issued_at")
    try:
        verify_document(
            envelope,
            purpose=ENVELOPE_SIGNATURE_PURPOSE,
            audience=recipient_public_key,
            max_age_seconds=0,
        )
    except (IdentityError, TypeError, ValueError) as exc:
        raise SecureEnvelopeError(f"invalid secure envelope signature: {exc}") from exc
    ciphertext = _base64url_decode(envelope.get("ciphertext"), "secure envelope ciphertext")
    if len(ciphertext) < _AEAD_TAG_BYTES:
        raise SecureEnvelopeError("secure envelope ciphertext is too short")
    if len(ciphertext) > maximum_plaintext + _AEAD_TAG_BYTES:
        raise SecureEnvelopeError(f"secure envelope plaintext exceeds {maximum_plaintext} bytes")

    return VerifiedEnvelopeMetadata(
        message_id=message_id,
        purpose=envelope_purpose,
        sender_peer_id=sender_peer_id,
        sender_public_key=sender_public_key,
        recipient_peer_id=recipient_peer_id,
        recipient_public_key=recipient_public_key,
        recipient_key_id=recipient_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def read_secure_frame(stream: BinaryIO, *, maximum_frame_bytes: int = MAX_SECURE_FRAME_BYTES) -> bytes:
    maximum = _positive_integer(
        maximum_frame_bytes,
        "maximum secure frame size",
        maximum=MAX_SECURE_FRAME_BYTES,
    )
    prefix = _read_exact(stream, _FRAME_PREFIX_BYTES)
    declared_length = struct.unpack("!I", prefix)[0]
    if declared_length == 0:
        raise SecureEnvelopeError("secure frame payload is empty")
    if declared_length + _FRAME_PREFIX_BYTES > maximum:
        raise SecureEnvelopeError(f"secure frame exceeds {maximum} bytes")
    return prefix + _read_exact(stream, declared_length)


def _verified_private_transport_key(key_pair: TransportKeyPair, *, now: int) -> VerifiedTransportKey:
    if not isinstance(key_pair, TransportKeyPair):
        raise TransportKeyError("recipient transport key pair is required")
    try:
        private_bytes = bytes.fromhex(key_pair.private_key)
    except (TypeError, ValueError) as exc:
        raise TransportKeyError("transport private key must be lowercase hex") from exc
    if len(private_bytes) != 32 or key_pair.private_key != private_bytes.hex():
        raise TransportKeyError("transport private key must be 32 bytes of lowercase hex")
    try:
        public_bytes = X25519PrivateKey.from_private_bytes(private_bytes).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
    except ValueError as exc:
        raise TransportKeyError("transport private key is invalid") from exc
    verified = verify_transport_key_binding(key_pair.binding, now=now)
    if public_bytes.hex() != verified.encryption_public_key:
        raise TransportKeyError("transport private key does not match its signed binding")
    return verified


def _verify_node_identity(identity: NodeIdentity) -> None:
    if not isinstance(identity, NodeIdentity):
        raise SecureTransportError("node identity is required")
    try:
        public_key = public_key_from_private_key(identity.private_key)
        peer_id = peer_id_from_public_key(public_key)
    except (IdentityError, TypeError, ValueError) as exc:
        raise SecureTransportError("node identity is invalid") from exc
    if identity.public_key != public_key or identity.peer_id != peer_id:
        raise SecureTransportError("node identity fields do not match its private key")


def _transport_key_id(public_key: bytes) -> str:
    digest = hashlib.sha256(b"mycomesh-transport-key-v1\x00" + public_key).hexdigest()
    return "x25519_" + digest


def _derive_content_key(shared_secret: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=_KDF_INFO,
    ).derive(shared_secret)


def _encode_frame(envelope: dict[str, Any]) -> bytes:
    raw = canonical_json(envelope).encode("utf-8")
    if len(raw) + _FRAME_PREFIX_BYTES > MAX_SECURE_FRAME_BYTES:
        raise SecureEnvelopeError(f"secure frame exceeds {MAX_SECURE_FRAME_BYTES} bytes")
    return struct.pack("!I", len(raw)) + raw


def _decode_frame(frame: bytes, *, maximum_frame_bytes: int) -> dict[str, Any]:
    if not isinstance(frame, bytes):
        raise SecureEnvelopeError("secure frame must be bytes")
    if len(frame) < _FRAME_PREFIX_BYTES:
        raise SecureEnvelopeError("secure frame is truncated")
    if len(frame) > maximum_frame_bytes:
        raise SecureEnvelopeError(f"secure frame exceeds {maximum_frame_bytes} bytes")
    declared_length = struct.unpack("!I", frame[:_FRAME_PREFIX_BYTES])[0]
    if declared_length == 0:
        raise SecureEnvelopeError("secure frame payload is empty")
    if declared_length != len(frame) - _FRAME_PREFIX_BYTES:
        raise SecureEnvelopeError("secure frame length mismatch")
    raw = frame[_FRAME_PREFIX_BYTES:]
    value = _load_json(raw, "secure frame")
    if not isinstance(value, dict):
        raise SecureEnvelopeError("secure frame payload must be an object")
    if raw != canonical_json(value).encode("utf-8"):
        raise SecureEnvelopeError("secure frame JSON is not canonical")
    return value


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not isinstance(chunk, bytes):
            raise SecureEnvelopeError("secure frame stream must return bytes")
        if not chunk:
            raise SecureEnvelopeError("secure frame is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _load_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SecureEnvelopeError(f"{label} is not valid strict JSON") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: Any, label: str) -> bytes:
    text = _text(value, label, maximum=(MAX_PLAINTEXT_BYTES + _AEAD_TAG_BYTES) * 2)
    if _BASE64URL_PATTERN.fullmatch(text) is None or "=" in text:
        raise SecureEnvelopeError(f"{label} must be canonical base64url without padding")
    try:
        decoded = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecureEnvelopeError(f"{label} is invalid base64url") from exc
    if _base64url_encode(decoded) != text:
        raise SecureEnvelopeError(f"{label} is not canonical base64url")
    return decoded


def _validate_signature(
    signature: Any,
    *,
    fields: set[str],
    purpose: str,
    audience: str | None,
    error: type[SecureTransportError],
) -> None:
    if not isinstance(signature, dict):
        raise error("missing secure transport signature")
    _require_exact_fields(signature, fields, "secure transport signature", error)
    nonce = signature.get("nonce")
    if not isinstance(nonce, str) or _HEX_16_PATTERN.fullmatch(nonce) is None:
        raise error("secure transport signature nonce must be 16 bytes of lowercase hex")
    _lower_hex_32(signature.get("public_key"), "secure transport signer public key", error)
    if signature.get("purpose") != purpose:
        raise error("secure transport signature purpose mismatch")
    _integer(signature.get("timestamp"), "secure transport signature timestamp", error)
    if audience is not None and signature.get("audience") != audience:
        raise error("secure transport signature audience mismatch")
    signature_hex = signature.get("signature")
    if not isinstance(signature_hex, str) or _SIGNATURE_PATTERN.fullmatch(signature_hex) is None:
        raise error("secure transport signature must be 64 bytes of lowercase hex")


def _require_exact_fields(
    value: dict[str, Any],
    expected: set[str],
    label: str,
    error: type[SecureTransportError],
) -> None:
    missing = sorted(expected - value.keys())
    unknown = sorted(value.keys() - expected)
    if missing:
        raise error(f"{label} is missing fields: {', '.join(missing)}")
    if unknown:
        raise error(f"{label} contains unsupported fields: {', '.join(unknown)}")


def _timestamp(value: Any, label: str) -> int:
    if value is None:
        return int(time.time())
    return _integer(value, label)


def _integer(
    value: Any,
    label: str,
    error: type[SecureTransportError] = SecureEnvelopeError,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise error(f"{label} must be an integer")
    if value < 0 or value > (1 << 63) - 1:
        raise error(f"{label} is out of range")
    return value


def _positive_integer(value: Any, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SecureTransportError(f"{label} must be a positive integer")
    if value > maximum:
        raise SecureTransportError(f"{label} must not exceed {maximum}")
    return value


def _text(
    value: Any,
    label: str,
    *,
    maximum: int,
    error: type[SecureTransportError] = SecureEnvelopeError,
) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise error(f"{label} must be non-empty text no longer than {maximum} bytes")
    return value


def _lower_hex_32(
    value: Any,
    label: str,
    error: type[SecureTransportError] = SecureEnvelopeError,
) -> str:
    if not isinstance(value, str) or _HEX_32_PATTERN.fullmatch(value) is None:
        raise error(f"{label} must be 32 bytes of lowercase hex")
    return value


def _purpose(value: Any) -> str:
    if not isinstance(value, str) or _PURPOSE_PATTERN.fullmatch(value) is None:
        raise SecureEnvelopeError("secure envelope purpose is malformed")
    return value
