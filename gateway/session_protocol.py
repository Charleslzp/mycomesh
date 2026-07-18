"""Session V4 authorization, request, and receipt primitives.

Settlement V3 authorizes each reservation independently.  Session V4 adds a
bounded, signed off-chain sequence for consumers that want to submit several
requests without sending a wallet transaction for every request.  The module
is deliberately transport agnostic: Relay, Provider, and a local Consumer can
all use the same canonical JSON and signature checks.

The outer signatures use :mod:`gateway.identity` (Ed25519).  An optional
``session_signature`` field carries an EVM/ECDSA signature and is verified
independently against ``consumer_payment_address``.  Keeping the two signatures
separate lets a browser or a local signer use either one without weakening the
identity binding.

V3 code continues to live in :mod:`gateway.reservation`; this module never
changes or silently upgrades a V3 reservation.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Mapping

from .channel_policy import (
    CODEX_BACKEND_POLICY,
    CODEX_CHANNEL_ID,
    MYCOMESH_TESTNET_NETWORK_ID,
)
from .identity import (
    IdentityError,
    NodeIdentity,
    peer_id_from_public_key,
    sign_document,
    verify_document,
)


SESSION_V4_AUTHORIZATION_SCHEMA = "mycomesh.session.authorization.v4"
SESSION_V4_REQUEST_SCHEMA = "mycomesh.session.request.v4"
SESSION_V4_RECEIPT_SCHEMA = "mycomesh.session.receipt.v4"
SESSION_AUTHORIZATION_PURPOSE = "mycomesh.session.authorization.v4"
SESSION_REQUEST_PURPOSE = "mycomesh.session.request.v4"
SESSION_RECEIPT_PURPOSE = "mycomesh.session.receipt.v4"
SESSION_AUTHORIZATION_VERSION = SESSION_V4_AUTHORIZATION_SCHEMA
SESSION_REQUEST_VERSION = SESSION_V4_REQUEST_SCHEMA
SESSION_RECEIPT_VERSION = SESSION_V4_RECEIPT_SCHEMA

UINT256_MAX = (1 << 256) - 1
MAX_SESSION_LIFETIME_SECONDS = 30 * 24 * 60 * 60
MAX_SESSION_ID_BYTES = 32
MAX_REQUEST_ID_LENGTH = 256
ZERO_BYTES32 = "0x" + "0" * 64
BYTES32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
HEX32_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
PUBLIC_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


class SessionProtocolError(ValueError):
    """Raised when a Session V4 document is malformed or unauthorized."""


class SessionSignatureError(SessionProtocolError):
    """Raised when an optional EVM signature cannot be verified."""


# The core fields intentionally use the names shared by the browser and
# Python clients.  Optional deployment fields are included in every document
# produced by the builders, but normalizers accept their absence so that a
# V4 session can be used before a chain deployment is selected.
_AUTH_REQUIRED = frozenset(
    {
        "schema",
        "session_id",
        "session_key",
        "consumer_payment_address",
        "provider_id",
        "provider_payment_address",
        "channel",
        "pricing_version",
        "pricing_hash",
        "max_amount_units",
        "expires_at",
        "sequence",
        "request_hash",
        "max_fee_units",
        "deadline",
        "cumulative_spend_units",
    }
)
_AUTH_OPTIONAL = frozenset(
    {
        "consumer_id",
        "consumer_public_key",
        "session_public_key",
        "network_id",
        "channel_id",
        "backend_policy",
        "nonce",
        "settlement_chain_id",
        "settlement_contract",
        "provider_fallback_allowed",
        "session_signature",
        "signature",
    }
)
_REQUEST_REQUIRED = frozenset(
    {
        "schema",
        "request_id",
        "session_id",
        "session_key",
        "session_public_key",
        "session_public_key",
        "consumer_payment_address",
        "provider_id",
        "provider_payment_address",
        "channel",
        "pricing_version",
        "pricing_hash",
        "sequence",
        "request_hash",
        "max_fee_units",
        "deadline",
        "cumulative_spend_units",
        "authorization_hash",
    }
)
_REQUEST_OPTIONAL = frozenset(
    {
        "consumer_id",
        "consumer_public_key",
        "network_id",
        "channel_id",
        "backend_policy",
        "nonce",
        "session_signature",
        "signature",
    }
)
_RECEIPT_REQUIRED = frozenset(
    {
        "schema",
        "request_id",
        "session_id",
        "session_key",
        "session_public_key",
        "consumer_payment_address",
        "provider_id",
        "provider_payment_address",
        "channel",
        "pricing_version",
        "pricing_hash",
        "sequence",
        "request_hash",
        "max_fee_units",
        "amount_units",
        "deadline",
        "cumulative_spend_units",
        "authorization_hash",
        "response_hash",
        "status",
    }
)
_RECEIPT_OPTIONAL = frozenset(
    {
        "consumer_id",
        "consumer_public_key",
        "provider_public_key",
        "network_id",
        "channel_id",
        "backend_policy",
        "nonce",
        "provider_signature",
        "session_signature",
        "signature",
    }
)


def normalize_session_authorization(
    value: Mapping[str, Any],
    *,
    require_signature: bool = False,
    require_canonical: bool = False,
) -> dict[str, Any]:
    """Normalize and validate a Session V4 authorization.

    ``signature`` is the outer Ed25519 signature added by
    :func:`build_session_authorization`; it is not part of the authorization
    digest.  ``session_signature`` is optional EVM proof and *is* part of the
    outer Ed25519 signed document.
    """

    raw = _object(value, "session authorization")
    _check_schema(raw, SESSION_V4_AUTHORIZATION_SCHEMA, "session authorization")
    _check_fields(raw, _AUTH_REQUIRED, _AUTH_OPTIONAL, "session authorization")
    normalized: dict[str, Any] = {
        "schema": SESSION_V4_AUTHORIZATION_SCHEMA,
        "session_id": _bytes32(raw["session_id"], "session_id"),
        # The on-chain V4 session key is an EVM address.  The independent
        # outer transport identity is carried by session_public_key below.
        "session_key": _address(raw["session_key"], "session_key"),
        "consumer_payment_address": _address(
            raw["consumer_payment_address"], "consumer_payment_address"
        ),
        "provider_id": _text(raw["provider_id"], "provider_id"),
        "provider_payment_address": _address(
            raw["provider_payment_address"], "provider_payment_address"
        ),
        "channel": _text(raw["channel"], "channel"),
        "pricing_version": _uint(raw["pricing_version"], "pricing_version", minimum=1),
        "pricing_hash": _bytes32(raw["pricing_hash"], "pricing_hash"),
        "max_amount_units": _uint(
            raw["max_amount_units"], "max_amount_units", minimum=1
        ),
        "expires_at": _uint(raw["expires_at"], "expires_at", minimum=1),
        "sequence": _uint(raw["sequence"], "sequence", minimum=0),
        "request_hash": _bytes32(
            raw["request_hash"], "request_hash", allow_zero=True
        ),
        "max_fee_units": _uint(raw["max_fee_units"], "max_fee_units", minimum=1),
        "deadline": _uint(raw["deadline"], "deadline", minimum=1),
        "cumulative_spend_units": _uint(
            raw["cumulative_spend_units"],
            "cumulative_spend_units",
            minimum=0,
        ),
    }
    if normalized["deadline"] > normalized["expires_at"]:
        raise SessionProtocolError("session authorization deadline exceeds expires_at")
    if normalized["cumulative_spend_units"] > normalized["max_amount_units"]:
        raise SessionProtocolError(
            "session authorization cumulative_spend_units exceeds max_amount_units"
        )

    # Deployment fields have deterministic defaults so a caller cannot omit
    # the network domain accidentally.  A deployment-aware caller should pass
    # the real values and the verifier will compare them.
    normalized["consumer_id"] = _optional_text(
        raw.get("consumer_id"), "consumer_id"
    )
    raw_session_public_key = raw.get("session_public_key")
    raw_consumer_public_key = raw.get("consumer_public_key")
    normalized["session_public_key"] = _optional_public_key(
        raw_session_public_key or raw_consumer_public_key,
        "session_public_key",
    )
    normalized["consumer_public_key"] = _optional_public_key(
        raw_consumer_public_key or raw_session_public_key,
        "consumer_public_key",
    )
    if (
        normalized["session_public_key"]
        and normalized["consumer_public_key"]
        and normalized["session_public_key"] != normalized["consumer_public_key"]
    ):
        raise SessionProtocolError("session_public_key and consumer_public_key mismatch")
    normalized["network_id"] = _optional_text(raw.get("network_id"), "network_id") or MYCOMESH_TESTNET_NETWORK_ID
    normalized["channel_id"] = _optional_text(raw.get("channel_id"), "channel_id") or CODEX_CHANNEL_ID
    normalized["backend_policy"] = _optional_text(raw.get("backend_policy"), "backend_policy") or CODEX_BACKEND_POLICY
    normalized["nonce"] = _bytes32(raw.get("nonce") or normalized["session_id"], "nonce")
    chain_id = raw.get("settlement_chain_id")
    contract = raw.get("settlement_contract")
    if chain_id is None and contract is None:
        normalized["settlement_chain_id"] = None
        normalized["settlement_contract"] = None
    elif chain_id is None or contract is None:
        raise SessionProtocolError(
            "settlement_chain_id and settlement_contract must be provided together"
        )
    else:
        normalized["settlement_chain_id"] = _uint(
            chain_id, "settlement_chain_id", minimum=1
        )
        normalized["settlement_contract"] = _address(contract, "settlement_contract")
    fallback = raw.get("provider_fallback_allowed", False)
    if type(fallback) is not bool:
        raise SessionProtocolError("provider_fallback_allowed must be a boolean")
    normalized["provider_fallback_allowed"] = fallback
    if raw.get("session_signature") is not None:
        normalized["session_signature"] = normalize_evm_signature(
            raw["session_signature"], label="session authorization"
        )
    else:
        normalized["session_signature"] = None
    if raw.get("signature") is not None:
        if not isinstance(raw["signature"], dict):
            raise SessionProtocolError("session authorization signature must be an object")
        normalized["signature"] = dict(raw["signature"])
    elif require_signature:
        raise SessionProtocolError("session authorization signature is required")
    else:
        normalized["signature"] = None
    if normalized["session_public_key"] is None and normalized["signature"]:
        public_key = str(normalized["signature"].get("public_key") or "")
        if PUBLIC_KEY_RE.fullmatch(public_key):
            normalized["session_public_key"] = public_key.lower()
            normalized["consumer_public_key"] = public_key.lower()
    elif normalized["consumer_public_key"] is None:
        normalized["consumer_public_key"] = normalized["session_public_key"]
    if normalized["consumer_id"] is None and normalized["session_public_key"]:
        normalized["consumer_id"] = peer_id_from_public_key(
            normalized["session_public_key"]
        )
    if require_canonical:
        _assert_canonical_document(raw, normalized, "session authorization")
    return normalized


def normalize_session_request(
    value: Mapping[str, Any],
    *,
    require_signature: bool = False,
    require_canonical: bool = False,
) -> dict[str, Any]:
    """Normalize a signed or unsigned Session V4 inference request."""

    raw = _object(value, "session request")
    _check_schema(raw, SESSION_V4_REQUEST_SCHEMA, "session request")
    _check_fields(raw, _REQUEST_REQUIRED, _REQUEST_OPTIONAL, "session request")
    normalized: dict[str, Any] = {
        "schema": SESSION_V4_REQUEST_SCHEMA,
        "request_id": _text(raw["request_id"], "request_id", maximum=MAX_REQUEST_ID_LENGTH),
        "session_id": _bytes32(raw["session_id"], "session_id"),
        "session_key": _address(raw["session_key"], "session_key"),
        "session_public_key": _public_key(
            raw["session_public_key"], "session_public_key"
        ),
        "consumer_payment_address": _address(
            raw["consumer_payment_address"], "consumer_payment_address"
        ),
        "provider_id": _text(raw["provider_id"], "provider_id"),
        "provider_payment_address": _address(
            raw["provider_payment_address"], "provider_payment_address"
        ),
        "channel": _text(raw["channel"], "channel"),
        "pricing_version": _uint(raw["pricing_version"], "pricing_version", minimum=1),
        "pricing_hash": _bytes32(raw["pricing_hash"], "pricing_hash"),
        "sequence": _uint(raw["sequence"], "sequence", minimum=1),
        "request_hash": _bytes32(raw["request_hash"], "request_hash"),
        "max_fee_units": _uint(raw["max_fee_units"], "max_fee_units", minimum=1),
        "deadline": _uint(raw["deadline"], "deadline", minimum=1),
        "cumulative_spend_units": _uint(
            raw["cumulative_spend_units"], "cumulative_spend_units", minimum=1
        ),
        "authorization_hash": _bytes32(raw["authorization_hash"], "authorization_hash"),
        "consumer_id": _optional_text(raw.get("consumer_id"), "consumer_id"),
        "consumer_public_key": _optional_public_key(
            raw.get("consumer_public_key"), "consumer_public_key"
        ),
        "network_id": _optional_text(raw.get("network_id"), "network_id") or MYCOMESH_TESTNET_NETWORK_ID,
        "channel_id": _optional_text(raw.get("channel_id"), "channel_id") or CODEX_CHANNEL_ID,
        "backend_policy": _optional_text(raw.get("backend_policy"), "backend_policy") or CODEX_BACKEND_POLICY,
        "nonce": _bytes32(raw.get("nonce") or raw["session_id"], "nonce"),
    }
    signature = raw.get("session_signature")
    normalized["session_signature"] = (
        normalize_evm_signature(signature, label="session request")
        if signature is not None
        else None
    )
    if raw.get("signature") is not None:
        if not isinstance(raw["signature"], dict):
            raise SessionProtocolError("session request signature must be an object")
        normalized["signature"] = dict(raw["signature"])
    elif require_signature:
        raise SessionProtocolError("session request signature is required")
    else:
        normalized["signature"] = None
    if require_canonical:
        _assert_canonical_document(raw, normalized, "session request")
    return normalized


def normalize_session_receipt(
    value: Mapping[str, Any],
    *,
    require_signature: bool = False,
    require_canonical: bool = False,
) -> dict[str, Any]:
    """Normalize a signed or unsigned Session V4 provider receipt."""

    raw = _object(value, "session receipt")
    _check_schema(raw, SESSION_V4_RECEIPT_SCHEMA, "session receipt")
    _check_fields(raw, _RECEIPT_REQUIRED, _RECEIPT_OPTIONAL, "session receipt")
    normalized: dict[str, Any] = {
        "schema": SESSION_V4_RECEIPT_SCHEMA,
        "request_id": _text(raw["request_id"], "request_id", maximum=MAX_REQUEST_ID_LENGTH),
        "session_id": _bytes32(raw["session_id"], "session_id"),
        "session_key": _address(raw["session_key"], "session_key"),
        "session_public_key": _public_key(
            raw["session_public_key"], "session_public_key"
        ),
        "consumer_payment_address": _address(
            raw["consumer_payment_address"], "consumer_payment_address"
        ),
        "provider_id": _text(raw["provider_id"], "provider_id"),
        "provider_payment_address": _address(
            raw["provider_payment_address"], "provider_payment_address"
        ),
        "channel": _text(raw["channel"], "channel"),
        "pricing_version": _uint(raw["pricing_version"], "pricing_version", minimum=1),
        "pricing_hash": _bytes32(raw["pricing_hash"], "pricing_hash"),
        "sequence": _uint(raw["sequence"], "sequence", minimum=1),
        "request_hash": _bytes32(raw["request_hash"], "request_hash"),
        "max_fee_units": _uint(raw["max_fee_units"], "max_fee_units", minimum=1),
        "amount_units": _uint(raw["amount_units"], "amount_units", minimum=0),
        "deadline": _uint(raw["deadline"], "deadline", minimum=1),
        "cumulative_spend_units": _uint(
            raw["cumulative_spend_units"], "cumulative_spend_units", minimum=0
        ),
        "authorization_hash": _bytes32(raw["authorization_hash"], "authorization_hash"),
        "response_hash": _bytes32(raw["response_hash"], "response_hash"),
        "status": _status(raw["status"]),
        "consumer_id": _optional_text(raw.get("consumer_id"), "consumer_id"),
        "consumer_public_key": _optional_public_key(
            raw.get("consumer_public_key"), "consumer_public_key"
        ),
        "provider_public_key": _optional_public_key(
            raw.get("provider_public_key"), "provider_public_key"
        ),
        "network_id": _optional_text(raw.get("network_id"), "network_id") or MYCOMESH_TESTNET_NETWORK_ID,
        "channel_id": _optional_text(raw.get("channel_id"), "channel_id") or CODEX_CHANNEL_ID,
        "backend_policy": _optional_text(raw.get("backend_policy"), "backend_policy") or CODEX_BACKEND_POLICY,
        "nonce": _bytes32(raw.get("nonce") or raw["session_id"], "nonce"),
    }
    provider_signature = raw.get("provider_signature")
    normalized["provider_signature"] = (
        normalize_evm_signature(provider_signature, label="provider receipt")
        if provider_signature is not None
        else None
    )
    session_signature = raw.get("session_signature")
    normalized["session_signature"] = (
        normalize_evm_signature(session_signature, label="session receipt")
        if session_signature is not None
        else None
    )
    if raw.get("signature") is not None:
        if not isinstance(raw["signature"], dict):
            raise SessionProtocolError("session receipt signature must be an object")
        normalized["signature"] = dict(raw["signature"])
    elif require_signature:
        raise SessionProtocolError("session receipt signature is required")
    else:
        normalized["signature"] = None
    if require_canonical:
        _assert_canonical_document(raw, normalized, "session receipt")
    return normalized


def session_authorization_unsigned(authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Return canonical unsigned authorization fields for hashing/signing."""

    normalized = normalize_session_authorization(authorization)
    return {key: value for key, value in normalized.items() if key != "signature"}


def session_authorization_hash(authorization: Mapping[str, Any]) -> str:
    """Hash the exact authorization fields bound into each request/receipt."""

    payload = session_authorization_unsigned(authorization)
    return "0x" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def session_authorization_message(authorization: Mapping[str, Any]) -> bytes:
    """Return the bytes signed by the optional EVM session signature."""

    payload = session_authorization_unsigned(authorization)
    payload.pop("session_signature", None)
    return _canonical_bytes(payload)


def session_authorization_digest(authorization: Mapping[str, Any]) -> bytes:
    """Return an EIP-191 personal-sign digest for a session authorization."""

    from .chain import keccak256

    message = session_authorization_message(authorization)
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii") + message)


def build_session_authorization(
    *,
    session_id: str,
    session_key: str,
    consumer_payment_address: str,
    provider_id: str,
    provider_payment_address: str,
    channel: str,
    pricing_version: int,
    pricing_hash: str,
    max_amount_units: int,
    expires_at: int,
    sequence: int = 0,
    request_hash: str = ZERO_BYTES32,
    max_fee_units: int | None = None,
    deadline: int | None = None,
    cumulative_spend_units: int = 0,
    signer: NodeIdentity | None = None,
    consumer_id: str | None = None,
    consumer_public_key: str | None = None,
    network_id: str = MYCOMESH_TESTNET_NETWORK_ID,
    channel_id: str = CODEX_CHANNEL_ID,
    backend_policy: str = CODEX_BACKEND_POLICY,
    nonce: str | None = None,
    settlement_chain_id: int | None = None,
    settlement_contract: str | None = None,
    provider_fallback_allowed: bool = False,
    session_public_key: str | None = None,
    wallet_private_key: str | None = None,
    session_private_key: str | None = None,
    session_signature: Mapping[str, Any] | str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Build and optionally sign a bounded Session V4 authorization.

    ``signer`` signs the outer Ed25519 document.  Set ``wallet_private_key``
    or ``session_signature`` to add the independent ECDSA proof.  At least one
    outer signer is required for a production authorization.
    """

    current = int(time.time() if now is None else now)
    expiry = _uint(expires_at, "expires_at", minimum=1)
    if expiry <= current or expiry > current + MAX_SESSION_LIFETIME_SECONDS:
        raise SessionProtocolError("expires_at must be within the next 30 days")
    resolved_deadline = expiry if deadline is None else _uint(deadline, "deadline", minimum=1)
    if resolved_deadline <= current or resolved_deadline > expiry:
        raise SessionProtocolError("deadline must be active and no later than expires_at")
    resolved_max_fee = (
        _uint(max_amount_units, "max_amount_units", minimum=1)
        if max_fee_units is None
        else _uint(max_fee_units, "max_fee_units", minimum=1)
    )
    if resolved_max_fee > int(max_amount_units):
        raise SessionProtocolError("max_fee_units exceeds max_amount_units")
    resolved_session_key = _address(session_key, "session_key")
    if wallet_private_key and session_private_key:
        raise SessionProtocolError("provide only one of wallet_private_key or session_private_key")
    resolved_session_private_key = session_private_key or wallet_private_key
    resolved_session_public_key = (
        _public_key(session_public_key, "session_public_key")
        if session_public_key is not None
        else (signer.public_key if signer is not None else None)
    )
    resolved_consumer_public_key = (
        _public_key(consumer_public_key, "consumer_public_key")
        if consumer_public_key is not None
        else resolved_session_public_key
    )
    if resolved_session_public_key is None:
        raise SessionProtocolError("session_public_key or outer signer is required")
    if resolved_consumer_public_key != resolved_session_public_key:
        raise SessionProtocolError("session_public_key and consumer_public_key mismatch")
    if signer is not None and resolved_session_public_key != signer.public_key:
        raise SessionProtocolError("outer signer does not match session_public_key")
    if consumer_id is None:
        consumer_id = peer_id_from_public_key(resolved_session_public_key)
    unsigned: dict[str, Any] = {
        "schema": SESSION_V4_AUTHORIZATION_SCHEMA,
        "session_id": _bytes32(session_id, "session_id"),
        "session_key": resolved_session_key,
        "consumer_payment_address": _address(consumer_payment_address, "consumer_payment_address"),
        "provider_id": _text(provider_id, "provider_id"),
        "provider_payment_address": _address(provider_payment_address, "provider_payment_address"),
        "channel": _text(channel, "channel"),
        "pricing_version": _uint(pricing_version, "pricing_version", minimum=1),
        "pricing_hash": _bytes32(pricing_hash, "pricing_hash"),
        "max_amount_units": _uint(max_amount_units, "max_amount_units", minimum=1),
        "expires_at": expiry,
        "sequence": _uint(sequence, "sequence", minimum=0),
        "request_hash": _bytes32(request_hash, "request_hash", allow_zero=True),
        "max_fee_units": resolved_max_fee,
        "deadline": resolved_deadline,
        "cumulative_spend_units": _uint(cumulative_spend_units, "cumulative_spend_units", minimum=0),
        "consumer_id": consumer_id,
        "session_public_key": resolved_session_public_key,
        "consumer_public_key": resolved_consumer_public_key,
        "network_id": _text(network_id, "network_id"),
        "channel_id": _text(channel_id, "channel_id"),
        "backend_policy": _text(backend_policy, "backend_policy"),
        "nonce": _bytes32(nonce or session_id, "nonce"),
        "settlement_chain_id": (
            None if settlement_chain_id is None else _uint(settlement_chain_id, "settlement_chain_id", minimum=1)
        ),
        "settlement_contract": (
            None if settlement_contract is None else _address(settlement_contract, "settlement_contract")
        ),
        "provider_fallback_allowed": provider_fallback_allowed,
    }
    if (unsigned["settlement_chain_id"] is None) != (unsigned["settlement_contract"] is None):
        raise SessionProtocolError("settlement_chain_id and settlement_contract must be provided together")
    if type(provider_fallback_allowed) is not bool:
        raise SessionProtocolError("provider_fallback_allowed must be a boolean")
    if resolved_session_private_key and session_signature is not None:
        raise SessionProtocolError("provide only one EVM session signature source")
    if resolved_session_private_key:
        _assert_private_key_address(resolved_session_private_key, unsigned["session_key"], "session_key")
        session_signature = sign_session_authorization(resolved_session_private_key, unsigned)
    if session_signature is not None:
        unsigned["session_signature"] = normalize_evm_signature(
            session_signature, label="session authorization"
        )
    if signer is None:
        return normalize_session_authorization(unsigned)
    signed = sign_document(
        _without_signature(normalize_session_authorization(unsigned)),
        signer.private_key,
        purpose=SESSION_AUTHORIZATION_PURPOSE,
        audience=provider_id,
        timestamp=current,
    )
    return normalize_session_authorization(signed, require_signature=True)


def verify_session_authorization(
    authorization: Mapping[str, Any],
    *,
    provider_id: str | None = None,
    expected_channel: str | None = None,
    expected_pricing_version: int | None = None,
    expected_pricing_hash: str | None = None,
    expected_consumer_payment_address: str | None = None,
    expected_session_key: str | None = None,
    expected_session_public_key: str | None = None,
    now: int | None = None,
    require_outer_signature: bool = True,
    require_evm_signature: bool = False,
) -> dict[str, Any]:
    """Verify an authorization and all configured domain bindings."""

    raw = _object(authorization, "session authorization")
    normalized = normalize_session_authorization(
        raw,
        require_signature=require_outer_signature,
        require_canonical=require_outer_signature,
    )
    current = int(time.time() if now is None else now)
    if normalized["expires_at"] <= current or normalized["deadline"] <= current:
        raise SessionProtocolError("session authorization has expired")
    if normalized["expires_at"] > current + MAX_SESSION_LIFETIME_SECONDS:
        raise SessionProtocolError("session authorization lifetime exceeds 30 days")
    _match("provider_id", provider_id, normalized["provider_id"])
    _match("channel", expected_channel, normalized["channel"])
    _match_int("pricing_version", expected_pricing_version, normalized["pricing_version"])
    if expected_pricing_hash is not None:
        _match("pricing_hash", expected_pricing_hash, normalized["pricing_hash"])
    if expected_consumer_payment_address is not None:
        _match("consumer_payment_address", expected_consumer_payment_address, normalized["consumer_payment_address"])
    if expected_session_key is not None:
        _match("session_key", expected_session_key, normalized["session_key"])
    if expected_session_public_key is not None:
        _match("session_public_key", expected_session_public_key, normalized["session_public_key"])
    if require_outer_signature:
        signature = normalized.get("signature")
        assert isinstance(signature, dict)
        expected_key = normalized.get("session_public_key") or normalized.get("consumer_public_key")
        if not expected_key or str(signature.get("public_key") or "").lower() != str(expected_key).lower():
            raise SessionProtocolError("authorization outer signer does not match session_public_key")
        try:
            verify_document(
                raw,
                purpose=SESSION_AUTHORIZATION_PURPOSE,
                audience=normalized["provider_id"],
                max_age_seconds=MAX_SESSION_LIFETIME_SECONDS,
                now=current,
            )
        except IdentityError as exc:
            raise SessionProtocolError(f"invalid session authorization outer signature: {exc}") from exc
    if require_evm_signature or normalized.get("session_signature") is not None:
        verify_session_evm_signature(
            normalized,
            field="session_signature",
            expected_address=normalized["session_key"],
        )
    return normalized


def build_session_request(
    *,
    authorization: Mapping[str, Any],
    request_id: str,
    request_hash: str,
    max_fee_units: int,
    deadline: int,
    sequence: int | None = None,
    previous_cumulative_spend_units: int | None = None,
    cumulative_spend_units: int | None = None,
    signer: NodeIdentity | None = None,
    session_signature: Mapping[str, Any] | str | None = None,
    wallet_private_key: str | None = None,
    session_private_key: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Build a request and compute its next sequence/cumulative spend."""

    auth = normalize_session_authorization(authorization)
    resolved_sequence = auth["sequence"] + 1 if sequence is None else _uint(sequence, "sequence", minimum=1)
    previous = (
        auth["cumulative_spend_units"]
        if previous_cumulative_spend_units is None
        else _uint(previous_cumulative_spend_units, "previous_cumulative_spend_units", minimum=0)
    )
    fee = _uint(max_fee_units, "max_fee_units", minimum=1)
    resolved_cumulative = previous + fee if cumulative_spend_units is None else _uint(
        cumulative_spend_units, "cumulative_spend_units", minimum=1
    )
    validate_session_sequence_and_spend(
        authorization=auth,
        sequence=resolved_sequence,
        cumulative_spend_units=resolved_cumulative,
        previous_sequence=resolved_sequence - 1,
        previous_cumulative_spend_units=previous,
        amount_units=fee,
    )
    resolved_deadline = _uint(deadline, "deadline", minimum=1)
    current = int(time.time() if now is None else now)
    if resolved_deadline <= current or resolved_deadline > auth["deadline"]:
        raise SessionProtocolError("request deadline is outside authorization window")
    if fee > auth["max_fee_units"]:
        raise SessionProtocolError("request max_fee_units exceeds authorization cap")
    normalized: dict[str, Any] = {
        "schema": SESSION_V4_REQUEST_SCHEMA,
        "request_id": _text(request_id, "request_id", maximum=MAX_REQUEST_ID_LENGTH),
        "session_id": auth["session_id"],
        "session_key": auth["session_key"],
        "session_public_key": auth["session_public_key"],
        "consumer_payment_address": auth["consumer_payment_address"],
        "provider_id": auth["provider_id"],
        "provider_payment_address": auth["provider_payment_address"],
        "channel": auth["channel"],
        "pricing_version": auth["pricing_version"],
        "pricing_hash": auth["pricing_hash"],
        "sequence": resolved_sequence,
        "request_hash": _bytes32(request_hash, "request_hash"),
        "max_fee_units": fee,
        "deadline": resolved_deadline,
        "cumulative_spend_units": resolved_cumulative,
        "authorization_hash": session_authorization_hash(auth),
        "consumer_id": auth.get("consumer_id"),
        "session_public_key": auth["session_public_key"],
        "consumer_public_key": auth.get("consumer_public_key"),
        "network_id": auth["network_id"],
        "channel_id": auth["channel_id"],
        "backend_policy": auth["backend_policy"],
        "nonce": auth["nonce"],
    }
    if wallet_private_key and session_private_key:
        raise SessionProtocolError("provide only one of wallet_private_key or session_private_key")
    resolved_session_private_key = session_private_key or wallet_private_key
    if resolved_session_private_key and session_signature is not None:
        raise SessionProtocolError("provide only one EVM request signature source")
    if resolved_session_private_key:
        _assert_private_key_address(resolved_session_private_key, normalized["session_key"], "session_key")
        session_signature = sign_session_request(resolved_session_private_key, normalized)
    if session_signature is not None:
        normalized["session_signature"] = normalize_evm_signature(
            session_signature, label="session request"
        )
    if signer is None:
        return normalize_session_request(normalized)
    if signer.public_key != auth["session_public_key"]:
        raise SessionProtocolError("request signer does not match authorization session_public_key")
    signed = sign_document(
        _without_signature(normalize_session_request(normalized)),
        signer.private_key,
        purpose=SESSION_REQUEST_PURPOSE,
        audience=auth["provider_id"],
        timestamp=current,
    )
    return normalize_session_request(signed, require_signature=True)


def verify_session_request(
    request: Mapping[str, Any],
    authorization: Mapping[str, Any],
    *,
    previous_sequence: int | None = None,
    previous_cumulative_spend_units: int | None = None,
    now: int | None = None,
    require_outer_signature: bool = True,
    require_evm_signature: bool = False,
) -> dict[str, Any]:
    """Verify request binding, sequence progression, spend cap, and signatures."""

    auth = verify_session_authorization(
        authorization,
        provider_id=str(authorization.get("provider_id") or ""),
        now=now,
        require_outer_signature=require_outer_signature,
    )
    raw = _object(request, "session request")
    normalized = normalize_session_request(
        raw,
        require_signature=require_outer_signature,
        require_canonical=require_outer_signature,
    )
    _bind_request_to_authorization(normalized, auth)
    current = int(time.time() if now is None else now)
    if normalized["deadline"] <= current:
        raise SessionProtocolError("session request deadline has expired")
    previous_seq = auth["sequence"] if previous_sequence is None else _uint(previous_sequence, "previous_sequence", minimum=0)
    previous_spend = (
        auth["cumulative_spend_units"]
        if previous_cumulative_spend_units is None
        else _uint(previous_cumulative_spend_units, "previous_cumulative_spend_units", minimum=0)
    )
    validate_session_sequence_and_spend(
        authorization=auth,
        sequence=normalized["sequence"],
        cumulative_spend_units=normalized["cumulative_spend_units"],
        previous_sequence=previous_seq,
        previous_cumulative_spend_units=previous_spend,
        amount_units=normalized["max_fee_units"],
    )
    if require_outer_signature:
        signature = normalized.get("signature")
        assert isinstance(signature, dict)
        if str(signature.get("public_key") or "").lower() != auth["session_public_key"]:
            raise SessionProtocolError("request outer signer does not match session_public_key")
        try:
            verify_document(
                raw,
                purpose=SESSION_REQUEST_PURPOSE,
                audience=auth["provider_id"],
                now=current,
            )
        except IdentityError as exc:
            raise SessionProtocolError(f"invalid session request outer signature: {exc}") from exc
    if require_evm_signature or normalized.get("session_signature") is not None:
        verify_session_evm_signature(
            normalized,
            field="session_signature",
            expected_address=auth["session_key"],
        )
    return normalized


def build_session_receipt(
    *,
    request: Mapping[str, Any],
    response_hash: str,
    amount_units: int,
    status: str = "accepted",
    previous_cumulative_spend_units: int | None = None,
    signer: NodeIdentity | None = None,
    provider_public_key: str | None = None,
    session_signature: Mapping[str, Any] | str | None = None,
    provider_signature: Mapping[str, Any] | str | None = None,
    session_private_key: str | None = None,
    provider_private_key: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Build a provider receipt with cumulative *actual* spend accounting."""

    req = normalize_session_request(request)
    amount = _uint(amount_units, "amount_units", minimum=0)
    if amount > req["max_fee_units"]:
        raise SessionProtocolError("receipt amount_units exceeds request max_fee_units")
    previous = (
        req["cumulative_spend_units"] - req["max_fee_units"]
        if previous_cumulative_spend_units is None
        else _uint(previous_cumulative_spend_units, "previous_cumulative_spend_units", minimum=0)
    )
    cumulative = previous + amount
    if cumulative > req["cumulative_spend_units"]:
        raise SessionProtocolError("receipt cumulative spend exceeds request authorization")
    normalized: dict[str, Any] = {
        "schema": SESSION_V4_RECEIPT_SCHEMA,
        "request_id": req["request_id"],
        "session_id": req["session_id"],
        "session_key": req["session_key"],
        "session_public_key": req["session_public_key"],
        "consumer_payment_address": req["consumer_payment_address"],
        "provider_id": req["provider_id"],
        "provider_payment_address": req["provider_payment_address"],
        "channel": req["channel"],
        "pricing_version": req["pricing_version"],
        "pricing_hash": req["pricing_hash"],
        "sequence": req["sequence"],
        "request_hash": req["request_hash"],
        "max_fee_units": req["max_fee_units"],
        "amount_units": amount,
        "deadline": req["deadline"],
        "cumulative_spend_units": cumulative,
        "authorization_hash": req["authorization_hash"],
        "response_hash": _bytes32(response_hash, "response_hash"),
        "status": _status(status),
        "consumer_id": req.get("consumer_id"),
        "consumer_public_key": req.get("consumer_public_key"),
        "provider_public_key": provider_public_key,
        "network_id": req["network_id"],
        "channel_id": req["channel_id"],
        "backend_policy": req["backend_policy"],
        "nonce": req["nonce"],
    }
    if signer is not None:
        if provider_public_key is not None and provider_public_key.lower() != signer.public_key:
            raise SessionProtocolError("receipt signer does not match provider_public_key")
        normalized["provider_public_key"] = signer.public_key
    if session_private_key and session_signature is not None:
        raise SessionProtocolError("provide only one session ECDSA signature source")
    if provider_private_key and provider_signature is not None:
        raise SessionProtocolError("provide only one provider ECDSA signature source")
    if session_private_key:
        _assert_private_key_address(session_private_key, normalized["session_key"], "session_key")
        session_signature = sign_session_receipt(session_private_key, normalized)
    if session_signature is not None:
        normalized["session_signature"] = normalize_evm_signature(
            session_signature, label="session receipt"
        )
    if provider_private_key:
        _assert_private_key_address(provider_private_key, normalized["provider_payment_address"], "provider_payment_address")
        provider_signature = sign_session_receipt(provider_private_key, normalized)
    if provider_signature is not None:
        normalized["provider_signature"] = normalize_evm_signature(
            provider_signature, label="provider receipt"
        )
    if signer is None:
        return normalize_session_receipt(normalized)
    if provider_public_key is not None and signer is not None and provider_public_key.lower() != signer.public_key:
        raise SessionProtocolError("receipt signer does not match provider_public_key")
    current = int(time.time() if now is None else now)
    signed = sign_document(
        _without_signature(normalize_session_receipt(normalized)),
        signer.private_key,
        purpose=SESSION_RECEIPT_PURPOSE,
        audience=req.get("consumer_id") or req["consumer_payment_address"],
        timestamp=current,
    )
    return normalize_session_receipt(signed, require_signature=True)


def verify_session_receipt(
    receipt: Mapping[str, Any],
    authorization: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    previous_cumulative_spend_units: int | None = None,
    expected_provider_public_key: str | None = None,
    now: int | None = None,
    require_outer_signature: bool = True,
    require_evm_signature: bool = False,
) -> dict[str, Any]:
    """Verify a provider receipt and its monotonic cumulative spend."""

    req = verify_session_request(
        request,
        authorization,
        now=now,
        require_outer_signature=require_outer_signature,
    )
    raw = _object(receipt, "session receipt")
    normalized = normalize_session_receipt(
        raw,
        require_signature=require_outer_signature,
        require_canonical=require_outer_signature,
    )
    for field in (
        "request_id",
        "session_id",
        "session_key",
        "consumer_payment_address",
        "provider_id",
        "provider_payment_address",
        "channel",
        "pricing_version",
        "pricing_hash",
        "sequence",
        "request_hash",
        "max_fee_units",
        "deadline",
        "authorization_hash",
    ):
        if normalized[field] != req[field]:
            raise SessionProtocolError(f"receipt {field} does not match request")
    if normalized["amount_units"] > normalized["max_fee_units"]:
        raise SessionProtocolError("receipt amount_units exceeds max_fee_units")
    previous = (
        req["cumulative_spend_units"] - req["max_fee_units"]
        if previous_cumulative_spend_units is None
        else _uint(previous_cumulative_spend_units, "previous_cumulative_spend_units", minimum=0)
    )
    expected_cumulative = previous + normalized["amount_units"]
    if normalized["cumulative_spend_units"] != expected_cumulative:
        raise SessionProtocolError("receipt cumulative_spend_units is not monotonic")
    if normalized["cumulative_spend_units"] > req["cumulative_spend_units"]:
        raise SessionProtocolError("receipt cumulative spend exceeds request cap")
    current = int(time.time() if now is None else now)
    if normalized["deadline"] <= current:
        raise SessionProtocolError("session receipt deadline has expired")
    if require_outer_signature:
        signature = normalized.get("signature")
        assert isinstance(signature, dict)
        provider_key = normalized.get("provider_public_key") or str(signature.get("public_key") or "")
        if str(signature.get("public_key") or "").lower() != str(provider_key).lower():
            raise SessionProtocolError("receipt outer signer does not match provider_public_key")
        if expected_provider_public_key is not None and provider_key.lower() != _public_key(
            expected_provider_public_key, "expected provider public key"
        ):
            raise SessionProtocolError("receipt provider public key does not match selected provider")
        try:
            if peer_id_from_public_key(provider_key) != normalized["provider_id"]:
                raise SessionProtocolError("receipt provider_id does not match provider public key")
        except IdentityError as exc:
            raise SessionProtocolError("receipt provider public key is invalid") from exc
        audience = req.get("consumer_id") or req["consumer_payment_address"]
        try:
            verify_document(
                raw,
                purpose=SESSION_RECEIPT_PURPOSE,
                audience=audience,
                now=current,
            )
        except IdentityError as exc:
            raise SessionProtocolError(f"invalid session receipt outer signature: {exc}") from exc
    if require_evm_signature or normalized.get("provider_signature") is not None:
        verify_session_evm_signature(
            normalized,
            field="provider_signature",
            expected_address=normalized["provider_payment_address"],
        )
    if normalized.get("session_signature") is not None:
        verify_session_evm_signature(
            normalized,
            field="session_signature",
            expected_address=normalized["session_key"],
        )
    return normalized


def validate_session_sequence_and_spend(
    *,
    authorization: Mapping[str, Any],
    sequence: int,
    cumulative_spend_units: int,
    previous_sequence: int,
    previous_cumulative_spend_units: int,
    amount_units: int,
) -> None:
    """Enforce one-step sequence progression and cumulative spend bounds."""

    auth = normalize_session_authorization(authorization)
    resolved_sequence = _uint(sequence, "sequence", minimum=1)
    resolved_previous_sequence = _uint(previous_sequence, "previous_sequence", minimum=0)
    previous_spend = _uint(
        previous_cumulative_spend_units,
        "previous_cumulative_spend_units",
        minimum=0,
    )
    amount = _uint(amount_units, "amount_units", minimum=0)
    cumulative = _uint(cumulative_spend_units, "cumulative_spend_units", minimum=0)
    if resolved_sequence != resolved_previous_sequence + 1:
        raise SessionProtocolError("session sequence must increase exactly by one")
    if resolved_previous_sequence < auth["sequence"]:
        raise SessionProtocolError("previous sequence is below authorization baseline")
    if previous_spend < auth["cumulative_spend_units"]:
        raise SessionProtocolError("previous cumulative spend is below authorization baseline")
    if cumulative != previous_spend + amount:
        raise SessionProtocolError("cumulative_spend_units does not equal previous spend plus amount")
    if cumulative > auth["max_amount_units"]:
        raise SessionProtocolError("cumulative spend exceeds session max_amount_units")


# Concise aliases used by callers that do not need the explicit V4 prefix.
normalize_authorization = normalize_session_authorization
normalize_request = normalize_session_request
normalize_receipt = normalize_session_receipt
verify_authorization = verify_session_authorization
verify_request = verify_session_request
verify_receipt = verify_session_receipt
build_authorization = build_session_authorization
build_request = build_session_request
build_receipt = build_session_receipt
validate_sequence = validate_session_sequence_and_spend


def sign_session_authorization(private_key: str, authorization: Mapping[str, Any]) -> dict[str, Any]:
    """Sign an authorization with an EVM private key (EIP-191)."""

    from .chain import sign_evm_digest

    signature = sign_evm_digest(private_key, session_authorization_digest(authorization))
    return {"r": signature.r, "s": signature.s, "v": signature.v}


def sign_session_request(private_key: str, request: Mapping[str, Any]) -> dict[str, Any]:
    """Sign a request with an EVM private key (EIP-191)."""

    from .chain import sign_evm_digest

    signature = sign_evm_digest(private_key, session_request_digest(request))
    return {"r": signature.r, "s": signature.s, "v": signature.v}


def sign_session_receipt(private_key: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Sign a provider receipt with an EVM private key (EIP-191)."""

    from .chain import sign_evm_digest

    signature = sign_evm_digest(private_key, session_receipt_digest(receipt))
    return {"r": signature.r, "s": signature.s, "v": signature.v}


# Explicit names make the two independent signature layers easy to discover.
sign_session_authorization_evm = sign_session_authorization
sign_session_request_evm = sign_session_request
sign_session_receipt_evm = sign_session_receipt


def verify_session_evm_signature(
    document: Mapping[str, Any],
    *,
    field: str | None = None,
    expected_address: str | None = None,
) -> str:
    """Verify ``session_signature`` on an authorization/request/receipt."""

    field = field or ("session_signature" if "session_signature" in document else "provider_signature")
    signature_value = document.get(field)
    if signature_value is None:
        raise SessionSignatureError(f"{field} is required")
    normalized = normalize_evm_signature(signature_value, label=field)
    digest = (
        session_authorization_digest(document)
        if str(document.get("schema")) == SESSION_V4_AUTHORIZATION_SCHEMA
        else session_request_digest(document)
        if str(document.get("schema")) == SESSION_V4_REQUEST_SCHEMA
        else session_receipt_digest(document)
    )
    from .chain import EvmSignature, SECP256K1_N, recover_evm_address

    r = int(normalized["r"], 16)
    s = int(normalized["s"], 16)
    v = int(normalized["v"])
    if not 0 < r < SECP256K1_N or not 0 < s <= SECP256K1_N // 2:
        raise SessionSignatureError("ECDSA signature scalar is out of range or not low-s")
    if v not in {0, 1, 27, 28}:
        raise SessionSignatureError("ECDSA signature v must be 0, 1, 27, or 28")
    try:
        recovered = recover_evm_address(
            digest,
            EvmSignature(r=normalized["r"], s=normalized["s"], v=v),
        )
    except Exception as exc:  # ChainError is intentionally translated at this boundary.
        raise SessionSignatureError(f"invalid ECDSA signature: {exc}") from exc
    wanted = expected_address
    if wanted is None:
        if field == "session_signature":
            wanted = document.get("session_key")
        else:
            wanted = document.get("consumer_payment_address")
        if field in {"provider_signature", "provider_evm_signature"}:
            wanted = document.get("provider_payment_address")
    if wanted is not None and recovered.lower() != _address(wanted, "expected signer").lower():
        raise SessionSignatureError("ECDSA signer does not match bound payment address")
    return recovered


def normalize_evm_signature(value: Mapping[str, Any] | str, *, label: str = "signature") -> dict[str, Any]:
    """Normalize either ``{r,s,v}`` or a 65-byte ``0x`` signature."""

    if isinstance(value, str):
        if not HEX_RE.fullmatch(value) or len(value[2:]) != 130:
            raise SessionSignatureError(f"{label} ECDSA signature must be 65-byte hex")
        raw = bytes.fromhex(value[2:])
        candidate: Mapping[str, Any] = {
            "r": "0x" + raw[:32].hex(),
            "s": "0x" + raw[32:64].hex(),
            "v": raw[64],
        }
    elif isinstance(value, Mapping):
        candidate = value
    else:
        raise SessionSignatureError(f"{label} ECDSA signature must be an object or hex")
    actual = set(candidate)
    if actual != {"r", "s", "v"}:
        raise SessionSignatureError(f"{label} ECDSA signature must contain exactly r, s, v")
    try:
        r = _bytes32(candidate["r"], f"{label} signature r")
        s = _bytes32(candidate["s"], f"{label} signature s")
        v = int(candidate["v"])
    except (TypeError, ValueError, SessionProtocolError) as exc:
        raise SessionSignatureError(f"{label} ECDSA signature is malformed") from exc
    if v not in {0, 1, 27, 28}:
        raise SessionSignatureError(f"{label} ECDSA signature v must be 0, 1, 27, or 28")
    return {"r": r, "s": s, "v": v}


def session_request_unsigned(request: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_session_request(request)
    return {key: value for key, value in normalized.items() if key != "signature"}


def session_request_message(request: Mapping[str, Any]) -> bytes:
    payload = session_request_unsigned(request)
    payload.pop("session_signature", None)
    return _canonical_bytes(payload)


def session_request_digest(request: Mapping[str, Any]) -> bytes:
    from .chain import keccak256

    message = session_request_message(request)
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii") + message)


def session_receipt_unsigned(receipt: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_session_receipt(receipt)
    return {key: value for key, value in normalized.items() if key != "signature"}


def session_receipt_message(receipt: Mapping[str, Any]) -> bytes:
    payload = session_receipt_unsigned(receipt)
    payload.pop("session_signature", None)
    payload.pop("provider_signature", None)
    return _canonical_bytes(payload)


def session_receipt_digest(receipt: Mapping[str, Any]) -> bytes:
    from .chain import keccak256

    message = session_receipt_message(receipt)
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii") + message)


def _bind_request_to_authorization(request: Mapping[str, Any], authorization: Mapping[str, Any]) -> None:
    auth = normalize_session_authorization(authorization)
    for field in (
        "session_id",
        "session_key",
        "session_public_key",
        "consumer_payment_address",
        "provider_id",
        "provider_payment_address",
        "channel",
        "pricing_version",
        "pricing_hash",
        "network_id",
        "channel_id",
        "backend_policy",
    ):
        if request[field] != auth[field]:
            raise SessionProtocolError(f"request {field} does not match session authorization")
    if request["authorization_hash"] != session_authorization_hash(auth):
        raise SessionProtocolError("request authorization_hash mismatch")
    if auth["request_hash"] != ZERO_BYTES32 and request["request_hash"] != auth["request_hash"]:
        raise SessionProtocolError("request_hash does not match session authorization")
    if request["max_fee_units"] > auth["max_fee_units"]:
        raise SessionProtocolError("request max_fee_units exceeds session authorization")
    if request["deadline"] > auth["deadline"]:
        raise SessionProtocolError("request deadline exceeds session authorization")


def _assert_canonical_document(raw: Mapping[str, Any], normalized: Mapping[str, Any], label: str) -> None:
    # Signature metadata is produced by sign_document and is intentionally not
    # normalized here.  Compare all protocol fields exactly to prevent hex and
    # integer aliases from creating two different signed meanings.
    for key, value in normalized.items():
        if key == "signature":
            continue
        if key not in raw:
            # Optional defaults are allowed for unsigned compatibility.  A
            # signed document must include the canonical fields produced by the
            # builders, so this path is rejected by the caller's exact check.
            if not (
                value is None
                or value is False
                or value == MYCOMESH_TESTNET_NETWORK_ID
                or value == CODEX_CHANNEL_ID
                or value == CODEX_BACKEND_POLICY
            ):
                raise SessionProtocolError(f"{label} missing canonical field {key}")
            continue
        if raw[key] != value:
            raise SessionProtocolError(f"{label} field {key} is not canonical")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SessionProtocolError(f"{label} must be an object")
    return dict(value)


def _check_schema(value: Mapping[str, Any], expected: str, label: str) -> None:
    if value.get("schema") != expected:
        raise SessionProtocolError(f"unsupported {label} schema")


def _check_fields(
    value: Mapping[str, Any],
    required: frozenset[str],
    optional: frozenset[str],
    label: str,
) -> None:
    keys = set(value)
    missing = sorted(required - keys)
    unknown = sorted(keys - required - optional)
    if missing:
        raise SessionProtocolError(f"{label} missing fields: {', '.join(missing)}")
    if unknown:
        raise SessionProtocolError(f"{label} unknown fields: {', '.join(unknown)}")


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SessionProtocolError(f"{label} must be 1-{maximum} characters")
    if not value.isascii() or value != value.strip() or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise SessionProtocolError(f"{label} must be printable ASCII without surrounding whitespace")
    return value


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _uint(value: Any, label: str, *, minimum: int) -> int:
    if type(value) is not int or value < minimum or value > UINT256_MAX:
        raise SessionProtocolError(f"{label} must be an integer in [{minimum}, 2^256-1]")
    return value


def _bytes32(value: Any, label: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str):
        raise SessionProtocolError(f"{label} must be 0x-prefixed bytes32")
    candidate = value if value.startswith("0x") else "0x" + value
    if not BYTES32_RE.fullmatch(candidate):
        raise SessionProtocolError(f"{label} must be 0x-prefixed bytes32")
    normalized = candidate.lower()
    if not allow_zero and normalized == ZERO_BYTES32:
        raise SessionProtocolError(f"{label} must be non-zero bytes32")
    return normalized


def _address(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        raise SessionProtocolError(f"{label} must be a 0x-prefixed EVM address")
    normalized = value.lower()
    if normalized == "0x" + "0" * 40:
        raise SessionProtocolError(f"{label} must be non-zero")
    return normalized


def _public_key(value: Any, label: str) -> str:
    if not isinstance(value, str) or not PUBLIC_KEY_RE.fullmatch(value):
        raise SessionProtocolError(f"{label} must be a 32-byte Ed25519 public key")
    return value.lower()


def _optional_public_key(value: Any, label: str) -> str | None:
    return None if value is None else _public_key(value, label)


def _status(value: Any) -> str:
    if value not in {"accepted", "rejected", "failed"}:
        raise SessionProtocolError("status must be accepted, rejected, or failed")
    return str(value)


def _match(label: str, expected: Any, actual: Any) -> None:
    if expected is None:
        return
    if isinstance(expected, str) and isinstance(actual, str):
        if expected.lower() != actual.lower():
            raise SessionProtocolError(f"{label} mismatch")
    elif expected != actual:
        raise SessionProtocolError(f"{label} mismatch")


def _match_int(label: str, expected: int | None, actual: int) -> None:
    if expected is not None and int(expected) != actual:
        raise SessionProtocolError(f"{label} mismatch")


def _assert_private_key_address(private_key: str, expected: str, label: str) -> None:
    try:
        from .chain import parse_private_key, private_key_to_address

        actual = private_key_to_address(parse_private_key(private_key))
    except Exception as exc:
        raise SessionProtocolError(f"{label} private key is invalid") from exc
    if actual != _address(expected, label):
        raise SessionProtocolError(f"{label} private key does not match bound address")


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SessionProtocolError(f"session document is not canonical JSON: {exc}") from exc


def _without_signature(value: Mapping[str, Any]) -> dict[str, Any]:
    """Remove only the normalizer's explicit ``signature`` placeholder.

    ``None`` optional fields remain part of the signed object.  Dropping them
    after signing would let an attacker append a different representation and
    make the Ed25519 verification fail for every valid builder output.
    """

    return {key: item for key, item in value.items() if key != "signature"}


__all__ = [
    "SESSION_V4_AUTHORIZATION_SCHEMA",
    "SESSION_V4_REQUEST_SCHEMA",
    "SESSION_V4_RECEIPT_SCHEMA",
    "SESSION_AUTHORIZATION_PURPOSE",
    "SESSION_REQUEST_PURPOSE",
    "SESSION_RECEIPT_PURPOSE",
    "SESSION_AUTHORIZATION_VERSION",
    "SESSION_REQUEST_VERSION",
    "SESSION_RECEIPT_VERSION",
    "SessionProtocolError",
    "SessionSignatureError",
    "normalize_session_authorization",
    "normalize_session_request",
    "normalize_session_receipt",
    "session_authorization_hash",
    "session_authorization_message",
    "session_authorization_digest",
    "session_request_message",
    "session_request_digest",
    "session_receipt_message",
    "session_receipt_digest",
    "build_session_authorization",
    "build_session_request",
    "build_session_receipt",
    "verify_session_authorization",
    "verify_session_request",
    "verify_session_receipt",
    "validate_session_sequence_and_spend",
    "normalize_evm_signature",
    "sign_session_authorization",
    "sign_session_request",
    "verify_session_evm_signature",
    "normalize_authorization",
    "normalize_request",
    "normalize_receipt",
    "verify_authorization",
    "verify_request",
    "verify_receipt",
    "build_authorization",
    "build_request",
    "build_receipt",
    "validate_sequence",
]
