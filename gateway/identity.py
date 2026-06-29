from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


DEFAULT_NODE_IDENTITY_PATH = ".codex-run/node-identity.json"
DEFAULT_REQUEST_IDENTITY_PATH = ".codex-run/request-identity.json"
SIGNATURE_MAX_AGE_SECONDS = 300


class IdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class NodeIdentity:
    private_key: str
    public_key: str
    peer_id: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def create_identity() -> NodeIdentity:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    public_key = public_bytes.hex()
    return NodeIdentity(
        private_key=private_bytes.hex(),
        public_key=public_key,
        peer_id=peer_id_from_public_key(public_key),
    )


def load_or_create_identity(path: Path | str = DEFAULT_NODE_IDENTITY_PATH) -> NodeIdentity:
    resolved = Path(path)
    if resolved.exists():
        return load_identity(resolved)
    identity = create_identity()
    save_identity(resolved, identity)
    return identity


def load_identity(path: Path | str) -> NodeIdentity:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    private_key = str(payload.get("private_key") or "")
    public_key = str(payload.get("public_key") or public_key_from_private_key(private_key))
    expected_peer_id = peer_id_from_public_key(public_key)
    peer_id = str(payload.get("peer_id") or expected_peer_id)
    if peer_id != expected_peer_id:
        raise IdentityError("identity peer_id does not match public_key")
    _private_key(private_key)
    _public_key(public_key)
    return NodeIdentity(private_key=private_key, public_key=public_key, peer_id=peer_id)


def save_identity(path: Path | str, identity: NodeIdentity) -> None:
    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(identity.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        resolved.chmod(0o600)
    except OSError:
        pass


def public_key_from_private_key(private_key_hex: str) -> str:
    private_key = _private_key(private_key_hex)
    public_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return public_bytes.hex()


def peer_id_from_public_key(public_key_hex: str) -> str:
    public_bytes = bytes.fromhex(public_key_hex)
    if len(public_bytes) != 32:
        raise IdentityError("public key must be 32 bytes hex")
    return "peer_" + hashlib.sha256(public_bytes).hexdigest()[:24]


def sign_document(
    document: dict[str, Any],
    private_key_hex: str,
    purpose: str,
    timestamp: int | None = None,
    nonce: str | None = None,
    audience: str | None = None,
) -> dict[str, Any]:
    if "signature" in document:
        raise IdentityError("document is already signed")
    public_key = public_key_from_private_key(private_key_hex)
    signed = dict(document)
    signature_payload = {
        "nonce": nonce or secrets.token_hex(16),
        "public_key": public_key,
        "purpose": purpose,
        "timestamp": int(timestamp if timestamp is not None else time.time()),
    }
    if audience:
        signature_payload["audience"] = str(audience)
    message = _signature_message(document, signature_payload)
    signature_payload["signature"] = _private_key(private_key_hex).sign(message).hex()
    signed["signature"] = signature_payload
    return signed


def verify_document(
    document: dict[str, Any],
    purpose: str,
    audience: str | None = None,
    max_age_seconds: int = SIGNATURE_MAX_AGE_SECONDS,
    now: int | None = None,
) -> dict[str, Any]:
    signature_payload = document.get("signature")
    if not isinstance(signature_payload, dict):
        raise IdentityError("missing signature")
    if str(signature_payload.get("purpose") or "") != purpose:
        raise IdentityError("bad signature purpose")
    if audience is not None and str(signature_payload.get("audience") or "") != str(audience):
        raise IdentityError("bad signature audience")

    public_key = str(signature_payload.get("public_key") or "")
    signature_hex = str(signature_payload.get("signature") or "")
    try:
        timestamp = int(signature_payload.get("timestamp"))
    except (TypeError, ValueError) as exc:
        raise IdentityError("bad signature timestamp") from exc

    current_time = int(now if now is not None else time.time())
    if max_age_seconds > 0 and timestamp > current_time + 30:
        raise IdentityError("signature timestamp is in the future")
    if max_age_seconds > 0 and current_time - timestamp > max_age_seconds:
        raise IdentityError("signature expired")

    unsigned = {key: value for key, value in document.items() if key != "signature"}
    message = _signature_message(unsigned, {key: value for key, value in signature_payload.items() if key != "signature"})
    try:
        _public_key(public_key).verify(bytes.fromhex(signature_hex), message)
    except (ValueError, InvalidSignature) as exc:
        raise IdentityError("bad signature") from exc
    return unsigned


def auth_token_from_secret(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:24]).decode("ascii").rstrip("=")


def _signature_message(document: dict[str, Any], signature_payload: dict[str, Any]) -> bytes:
    payload = {
        "document": document,
        "signature": signature_payload,
    }
    return canonical_json(payload).encode("utf-8")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _private_key(private_key_hex: str) -> Ed25519PrivateKey:
    try:
        raw = bytes.fromhex(private_key_hex)
    except ValueError as exc:
        raise IdentityError("private key must be hex") from exc
    if len(raw) != 32:
        raise IdentityError("private key must be 32 bytes hex")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_key(public_key_hex: str) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise IdentityError("public key must be hex") from exc
    if len(raw) != 32:
        raise IdentityError("public key must be 32 bytes hex")
    return Ed25519PublicKey.from_public_bytes(raw)
