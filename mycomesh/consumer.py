"""Consumer-side V11 request building and response verification (Python client).

The Node Consumer in packages/mycomesh-cli implements the same protocol; this
module is the reference used by tests and Python tooling.
"""
from __future__ import annotations

import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .evm import address_of
from .identity import NodeIdentity, create_identity
from .protocol import (
    RESPONSE_SCHEMA, SEALED_REQUEST_PURPOSE, SEALED_RESPONSE_PURPOSE, ProtocolError, b64decode, b64encode,
    build_request, sha256_hex, verify_transport_attestation,
)
from .replay import MemoryReplayStore
from .secure_transport import TransportKeyPair, generate_transport_key, open_frame, seal_frame, verify_transport_key_binding
from .settlement import Authorization, Deployment, SignedReceipt, request_id_for, sign_authorization


@dataclass
class PreparedRequest:
    payload: dict[str, Any]
    authorization: Authorization
    reply_key: TransportKeyPair
    provider_peer_id: str
    # Kept so the Consumer alone can later reveal both sides in a dispute.
    request_plaintext: bytes = b""
    response_plaintext: bytes = field(default=b"", repr=False)


def verified_provider(descriptor: Mapping[str, Any], deployment: Deployment, *, now: int) -> tuple[str, dict[str, Any]]:
    """Return (provider signer, transport binding) after checking the Provider's own attestation."""
    binding = verify_transport_key_binding(descriptor["transport_key"], now=now)
    signer = verify_transport_attestation(
        descriptor["transport_attestation"], identity_public_key=binding.identity_public_key,
        transport_key_id=binding.key_id, deployment=deployment, now=now,
    )
    return signer, dict(descriptor["transport_key"])


def prepare_request(
    *, descriptor: Mapping[str, Any], deployment: Deployment, key_private: str, relay_signer: str,
    endpoint: str, model: str, content: Any, max_output_tokens: int, max_fee: int,
    options: Mapping[str, Any] | None = None, sender: NodeIdentity | None = None, now: int | None = None,
) -> PreparedRequest:
    current = int(time.time() if now is None else now)
    provider_signer, binding = verified_provider(descriptor, deployment, now=current)
    identity = sender or create_identity()
    reply_key = generate_transport_key(identity, lifetime_seconds=3600, now=current)
    plaintext = build_request(endpoint=endpoint, model=model, content=content, max_output_tokens=max_output_tokens,
                              reply_key_id=reply_key.binding["key_id"], options=options)
    key = address_of(key_private)
    authorization = Authorization(
        request_id=request_id_for(key, "0x" + secrets.token_hex(32)), request_hash=sha256_hex(plaintext),
        key=key, provider_signer=provider_signer, relay_signer=relay_signer, max_fee=max_fee,
        issued_at=current, execute_by=current + 300, deadline=current + 7_200,
    )
    sealed = seal_frame(plaintext, sender=identity, recipient_binding=binding,
                        expected_recipient_peer_id=binding["peer_id"], purpose=SEALED_REQUEST_PURPOSE,
                        ttl_seconds=300, now=current)
    payload = {
        "authorization": authorization.to_payload(),
        "key_signature": sign_authorization(key_private, authorization, deployment),
        "sealed_request": b64encode(sealed),
        "reply_transport_key": reply_key.binding,
    }
    return PreparedRequest(payload, authorization, reply_key, binding["peer_id"], plaintext)


def open_response(prepared: PreparedRequest, result: Mapping[str, Any], deployment: Deployment,
                  *, now: int | None = None) -> tuple[dict[str, Any], SignedReceipt]:
    """Decrypt the response and prove it is exactly what the Provider signed for."""
    current = int(time.time() if now is None else now)
    signed = SignedReceipt.from_payload(result["receipt"])
    if signed.authorization != prepared.authorization:
        raise ProtocolError("receipt is for a different authorization")
    signed.verify(deployment)
    opened = open_frame(b64decode(result["sealed_response"]), recipient_key=prepared.reply_key,
                        expected_purpose=SEALED_RESPONSE_PURPOSE, replay_store=MemoryReplayStore(),
                        expected_sender_peer_id=prepared.provider_peer_id, now=current)
    if sha256_hex(opened.payload) != signed.receipt.response_hash:
        raise ProtocolError("response differs from the Provider-signed receipt")
    response = json.loads(opened.payload)
    prepared.response_plaintext = opened.payload
    if response.get("schema") != RESPONSE_SCHEMA or response.get("request_hash") != prepared.authorization.request_hash:
        raise ProtocolError("response is not bound to this request")
    return response, signed


def dispute_evidence(prepared: PreparedRequest, signed: SignedReceipt, *, reason_code: str, statement: str) -> dict[str, Any]:
    """Evidence for openDispute: both plaintexts, bound to the Provider-signed receipt."""
    from .jury import build_evidence

    if not prepared.response_plaintext:
        raise ProtocolError("open the response before disputing it")
    return build_evidence(signed, prepared.request_plaintext, prepared.response_plaintext,
                          reason_code=reason_code, statement=statement)
