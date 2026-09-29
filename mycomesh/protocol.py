"""V11 wire formats: sealed requests/responses, Provider transport attestations, pricing.

A Consumer seals the canonical JSON of its request to the Provider's transport
key. ``request_hash`` is the SHA-256 of exactly those plaintext bytes, so the
Provider hashes what it decrypts and no party ever re-serializes the request.
The request names the Consumer's reply key id, so a Relay cannot substitute a
reply key to read the response. A Relay therefore sees only pricing and routing
fields plus ciphertext.
"""
from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .evm import abi_encode, keccak256, normalize_address, normalize_bytes32, recover_address, sign_digest
from .identity import canonical_json
from .settlement import Deployment

REQUEST_SCHEMA = "mycomesh.v11.request.v1"
RESPONSE_SCHEMA = "mycomesh.v11.response.v1"
SEALED_REQUEST_PURPOSE = "mycomesh.v11.sealed-request"
SEALED_RESPONSE_PURPOSE = "mycomesh.v11.sealed-response"
# Streamed text before the final response; each is {"seq": n, "delta": text}, sealed to the reply key.
SEALED_DELTA_PURPOSE = "mycomesh.v11.sealed-delta"
ENDPOINTS = ("responses", "chat")
MAX_REQUEST_BYTES = 8 * 1024 * 1024

PROVIDER_TRANSPORT_TYPE = (
    "ProviderTransport(address providerSigner,bytes32 identityPublicKey,bytes32 transportKeyId,uint64 expiresAt)"
)
PROVIDER_TRANSPORT_TYPEHASH = keccak256(PROVIDER_TRANSPORT_TYPE.encode())


class ProtocolError(ValueError):
    pass


def sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(value: Any, *, maximum: int = 12 * 1024 * 1024) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 4 // 3 + 4:
        raise ProtocolError("invalid base64 payload")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except ValueError as exc:
        raise ProtocolError("invalid base64 payload") from exc


# ---------------- requests ----------------

def build_request(*, endpoint: str, model: str, content: Any, max_output_tokens: int,
                  reply_key_id: str, options: Mapping[str, Any] | None = None) -> bytes:
    """Canonical plaintext request bytes; their SHA-256 is the request hash."""
    document = {
        "schema": REQUEST_SCHEMA, "endpoint": endpoint, "model": model,
        ("messages" if endpoint == "chat" else "input"): content,
        "max_output_tokens": max_output_tokens, "options": dict(options or {}),
        "reply_key_id": reply_key_id,
    }
    validate_request(document)
    return canonical_json(document).encode("utf-8")


def validate_request(document: Any) -> dict[str, Any]:
    if not isinstance(document, Mapping) or document.get("schema") != REQUEST_SCHEMA:
        raise ProtocolError("unsupported request schema")
    endpoint = document.get("endpoint")
    if endpoint not in ENDPOINTS:
        raise ProtocolError("unsupported endpoint")
    content_field = "messages" if endpoint == "chat" else "input"
    expected = {"schema", "endpoint", "model", content_field, "max_output_tokens", "options", "reply_key_id"}
    if set(document) != expected:
        raise ProtocolError("request fields are invalid")
    if not isinstance(document["model"], str) or not document["model"] or len(document["model"]) > 160:
        raise ProtocolError("invalid model")
    tokens = document["max_output_tokens"]
    if type(tokens) is not int or not 1 <= tokens <= 1_000_000:
        raise ProtocolError("invalid max_output_tokens")
    if not isinstance(document["options"], Mapping):
        raise ProtocolError("options must be an object")
    if not isinstance(document["reply_key_id"], str) or not document["reply_key_id"].startswith("x25519_"):
        raise ProtocolError("invalid reply key id")
    return dict(document)


def output_text(output: Any) -> str:
    """The assistant text in an OpenAI Responses, Chat Completions or Anthropic Messages payload."""
    if isinstance(output, Mapping):
        if isinstance(output.get("output_text"), str):
            return output["output_text"]
        if output.get("choices"):
            return str((output["choices"][0].get("message") or {}).get("content") or "")
        if isinstance(output.get("content"), list):
            return "".join(str(part.get("text", "")) for part in output["content"] if isinstance(part, Mapping))
        return "".join(str(part.get("text", "")) for item in output.get("output", []) if isinstance(item, Mapping)
                       for part in item.get("content", []) if isinstance(part, Mapping))
    return "" if output is None else str(output)


def build_response(*, request_hash: str, output: Any, input_tokens: int, output_tokens: int) -> bytes:
    return canonical_json({
        "schema": RESPONSE_SCHEMA, "request_hash": request_hash, "output": output,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }).encode("utf-8")


# ---------------- Provider transport attestation ----------------

def _transport_struct_hash(provider_signer: str, identity_public_key: str, transport_key_id: str, expires_at: int) -> bytes:
    key_id = transport_key_id.removeprefix("x25519_")
    return keccak256(abi_encode(
        ["bytes32", "address", "bytes32", "bytes32", "uint64"],
        ["0x" + PROVIDER_TRANSPORT_TYPEHASH.hex(), provider_signer, "0x" + identity_public_key,
         "0x" + key_id, expires_at],
    ))


def attest_transport(provider_private: str, *, identity_public_key: str, transport_key_id: str,
                     expires_at: int, deployment: Deployment) -> dict[str, Any]:
    from .evm import address_of

    signer = address_of(provider_private)
    digest = deployment.digest(_transport_struct_hash(signer, identity_public_key, transport_key_id, expires_at))
    return {"provider_signer": signer, "expires_at": expires_at, "signature": sign_digest(provider_private, digest)}


def verify_transport_attestation(attestation: Any, *, identity_public_key: str, transport_key_id: str,
                                 deployment: Deployment, now: int) -> str:
    """Return the attested Provider signer; a Relay cannot forge this binding."""
    if not isinstance(attestation, Mapping) or set(attestation) != {"provider_signer", "expires_at", "signature"}:
        raise ProtocolError("invalid transport attestation")
    signer = normalize_address(attestation["provider_signer"])
    expires_at = attestation["expires_at"]
    if type(expires_at) is not int or expires_at <= now:
        raise ProtocolError("transport attestation expired")
    digest = deployment.digest(_transport_struct_hash(signer, identity_public_key, transport_key_id, expires_at))
    if recover_address(digest, str(attestation["signature"])) != signer:
        raise ProtocolError("transport attestation signature is invalid")
    return signer


# ---------------- pricing ----------------

@dataclass(frozen=True)
class Prices:
    """Provider-set prices in stablecoin base units; a Consumer caps each fee."""

    input_per_1k: int
    output_per_1k: int
    minimum_fee: int

    def __post_init__(self) -> None:
        for name in ("input_per_1k", "output_per_1k", "minimum_fee"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ProtocolError(f"{name} must be a non-negative integer")

    def quote(self, input_tokens: int, output_tokens: int) -> int:
        cost = -(-(input_tokens * self.input_per_1k + output_tokens * self.output_per_1k) // 1000)
        return max(cost, self.minimum_fee, 1)

    def to_payload(self) -> dict[str, int]:
        return {"input_per_1k": self.input_per_1k, "output_per_1k": self.output_per_1k, "minimum_fee": self.minimum_fee}

    @classmethod
    def from_payload(cls, value: Any) -> "Prices":
        if not isinstance(value, Mapping) or set(value) != {"input_per_1k", "output_per_1k", "minimum_fee"}:
            raise ProtocolError("invalid prices")
        return cls(value["input_per_1k"], value["output_per_1k"], value["minimum_fee"])


def check_bytes32(value: Any, label: str) -> str:
    try:
        return normalize_bytes32(value)
    except ValueError as exc:
        raise ProtocolError(f"invalid {label}") from exc
