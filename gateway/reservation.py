from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from typing import Any

from .identity import IdentityError, NodeIdentity, sign_document, verify_document


PAYMENT_RESERVATION_PURPOSE = "mycomesh.payment.reservation.v1"
INFERENCE_REQUEST_HASH_VERSION = "mycomesh.inference.request.v2"
EVM_SESSION_AUTHORIZATION_VERSION = "mycomesh.evm.session.v1"
DEFAULT_RESERVATION_TTL_SECONDS = 300
MAX_RESERVATION_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_EVM_WALLET_SIGNATURE_BYTES = 16 * 1024
BYTES32_PATTERN = re.compile(r"^0x[a-fA-F0-9]{64}$")
ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
HEX_PATTERN = re.compile(r"^0x[0-9a-f]+$")
_SESSION_AUTHORIZATION_FIELDS = (
    "authorization_version",
    "chain_id",
    "settlement_contract",
    "onchain_reservation_id",
    "consumer_payment_address",
    "provider_id",
    "provider_payment_address",
    "channel",
    "pricing_hash",
    "pricing_version",
    "request_hash",
    "max_fee_units",
    "expires_at",
    "settlement_deadline",
    "provider_fallback_allowed",
    "nonce",
    "session_public_key",
)


class ReservationError(RuntimeError):
    pass


def validate_v3_time_window(
    *,
    expires_at: Any,
    settlement_deadline: Any | None = None,
    now: int | None = None,
) -> tuple[int, int]:
    """Validate the common lifetime constraints for a Settlement V3 authorization."""
    current_time = int(now if now is not None else time.time())
    resolved_expiry = _positive_int(expires_at, "expires_at")
    resolved_deadline = _positive_int(
        settlement_deadline if settlement_deadline is not None else resolved_expiry,
        "Settlement V3 deadline",
    )
    if resolved_expiry <= current_time or resolved_expiry > current_time + MAX_RESERVATION_TTL_SECONDS:
        raise ReservationError("expires_at must be within the next 30 days")
    if resolved_deadline <= current_time or resolved_deadline > resolved_expiry:
        raise ReservationError("Settlement V3 deadline must be active and no later than expires_at")
    return resolved_expiry, resolved_deadline


def evm_session_authorization_payload(
    *,
    chain_id: int,
    settlement_contract: str,
    onchain_reservation_id: str,
    consumer_payment_address: str,
    provider_id: str,
    provider_payment_address: str,
    channel: str,
    pricing_hash: str,
    pricing_version: int,
    request_hash: str,
    max_fee_units: int,
    expires_at: int,
    settlement_deadline: int,
    provider_fallback_allowed: bool,
    nonce: str,
    session_public_key: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Build the canonical fields an EVM wallet authorizes for one V3 session."""
    resolved_expiry, resolved_deadline = validate_v3_time_window(
        expires_at=expires_at,
        settlement_deadline=settlement_deadline,
        now=now,
    )
    payload = {
        "authorization_version": EVM_SESSION_AUTHORIZATION_VERSION,
        "chain_id": chain_id,
        "settlement_contract": str(settlement_contract or "").lower(),
        "onchain_reservation_id": str(onchain_reservation_id or "").lower(),
        "consumer_payment_address": str(consumer_payment_address or "").lower(),
        "provider_id": provider_id,
        "provider_payment_address": str(provider_payment_address or "").lower(),
        "channel": channel,
        "pricing_hash": str(pricing_hash or "").lower(),
        "pricing_version": pricing_version,
        "request_hash": str(request_hash or "").lower(),
        "max_fee_units": max_fee_units,
        "expires_at": resolved_expiry,
        "settlement_deadline": resolved_deadline,
        "provider_fallback_allowed": provider_fallback_allowed,
        "nonce": str(nonce or "").lower(),
        "session_public_key": str(session_public_key or "").lower(),
    }
    return _normalize_session_authorization(payload, signed=False)


def evm_session_authorization_message(authorization: Any) -> bytes:
    payload = _normalize_session_authorization(authorization, signed=None)
    payload.pop("wallet_signature", None)
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def evm_session_authorization_digest(authorization: Any) -> bytes:
    from .chain import keccak256

    message = evm_session_authorization_message(authorization)
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii")
    return keccak256(prefix + message)


def build_evm_session_authorization(
    *,
    chain_id: int,
    settlement_contract: str,
    onchain_reservation_id: str,
    consumer_payment_address: str,
    provider_id: str,
    provider_payment_address: str,
    channel: str,
    pricing_hash: str,
    pricing_version: int,
    request_hash: str,
    max_fee_units: int,
    expires_at: int,
    settlement_deadline: int,
    provider_fallback_allowed: bool,
    session_public_key: str,
    nonce: str | None = None,
    wallet_private_key: str | None = None,
    wallet_signature: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if bool(wallet_private_key) == bool(wallet_signature):
        raise ReservationError("provide exactly one of wallet_private_key or wallet_signature")
    if wallet_signature and nonce is None:
        raise ReservationError("an external wallet_signature requires its signed nonce")
    payload = evm_session_authorization_payload(
        chain_id=chain_id,
        settlement_contract=settlement_contract,
        onchain_reservation_id=onchain_reservation_id,
        consumer_payment_address=consumer_payment_address,
        provider_id=provider_id,
        provider_payment_address=provider_payment_address,
        channel=channel,
        pricing_hash=pricing_hash,
        pricing_version=pricing_version,
        request_hash=request_hash,
        max_fee_units=max_fee_units,
        expires_at=expires_at,
        settlement_deadline=settlement_deadline,
        provider_fallback_allowed=provider_fallback_allowed,
        nonce=nonce or ("0x" + secrets.token_hex(32)),
        session_public_key=session_public_key,
        now=now,
    )
    if wallet_private_key:
        try:
            from .chain import parse_private_key, private_key_to_address, sign_evm_digest

            wallet_address = private_key_to_address(parse_private_key(wallet_private_key))
            if wallet_address != payload["consumer_payment_address"]:
                raise ReservationError(
                    "consumer wallet private key does not match consumer_payment_address"
                )
            signature = sign_evm_digest(wallet_private_key, evm_session_authorization_digest(payload))
        except ReservationError:
            raise
        except (RuntimeError, TypeError, ValueError) as exc:
            raise ReservationError(f"invalid consumer wallet private key: {exc}") from exc
        wallet_signature = (
            "0x"
            + int(signature.r, 16).to_bytes(32, "big").hex()
            + int(signature.s, 16).to_bytes(32, "big").hex()
            + int(signature.v).to_bytes(1, "big").hex()
        )
    signed = dict(payload)
    signed["wallet_signature"] = wallet_signature
    return _normalize_session_authorization(signed, signed=True)


def validate_evm_session_authorization(
    authorization: Any,
    *,
    chain_id: int | None = None,
    settlement_contract: str | None = None,
    onchain_reservation_id: str | None = None,
    consumer_payment_address: str | None = None,
    provider_id: str | None = None,
    provider_payment_address: str | None = None,
    channel: str | None = None,
    pricing_hash: str | None = None,
    pricing_version: int | None = None,
    request_hash: str | None = None,
    max_fee_units: int | None = None,
    expires_at: int | None = None,
    settlement_deadline: int | None = None,
    provider_fallback_allowed: bool | None = None,
    session_public_key: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    normalized = _normalize_session_authorization(authorization, signed=True)
    expected_values: tuple[tuple[str, Any], ...] = (
        ("chain_id", chain_id),
        ("settlement_contract", settlement_contract.lower() if settlement_contract else None),
        ("onchain_reservation_id", onchain_reservation_id.lower() if onchain_reservation_id else None),
        ("consumer_payment_address", consumer_payment_address.lower() if consumer_payment_address else None),
        ("provider_id", provider_id),
        ("provider_payment_address", provider_payment_address.lower() if provider_payment_address else None),
        ("channel", channel),
        ("pricing_hash", pricing_hash.lower() if pricing_hash else None),
        ("pricing_version", pricing_version),
        ("request_hash", request_hash.lower() if request_hash else None),
        ("max_fee_units", max_fee_units),
        ("expires_at", expires_at),
        ("settlement_deadline", settlement_deadline),
        ("provider_fallback_allowed", provider_fallback_allowed),
        ("session_public_key", session_public_key.lower() if session_public_key else None),
    )
    for label, expected in expected_values:
        if expected is not None and normalized[label] != expected:
            raise ReservationError(f"EVM session authorization {label} mismatch")
    validate_v3_time_window(
        expires_at=normalized["expires_at"],
        settlement_deadline=normalized["settlement_deadline"],
        now=now,
    )
    return normalized


def verify_eoa_session_authorization(authorization: Any, **expected: Any) -> dict[str, Any]:
    normalized = validate_evm_session_authorization(authorization, **expected)
    signature_bytes = bytes.fromhex(normalized["wallet_signature"][2:])
    if len(signature_bytes) != 65:
        raise ReservationError("EOA session authorization signature must be exactly 65 bytes")
    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:64], "big")
    v = signature_bytes[64]
    try:
        from .chain import EvmSignature, SECP256K1_N, normalize_address, recover_evm_address

        if r <= 0 or r >= SECP256K1_N:
            raise ReservationError("EOA session authorization signature r is out of range")
        if s <= 0 or s > SECP256K1_N // 2:
            raise ReservationError("EOA session authorization signature s is not canonical low-s")
        if v not in {0, 1, 27, 28}:
            raise ReservationError("EOA session authorization signature v must be 0, 1, 27, or 28")
        recovered = recover_evm_address(
            evm_session_authorization_digest(normalized),
            EvmSignature(
                r="0x" + signature_bytes[:32].hex(),
                s="0x" + signature_bytes[32:64].hex(),
                v=v,
            ),
        )
        if recovered != normalize_address(normalized["consumer_payment_address"]):
            raise ReservationError("EVM session authorization signer does not match consumer wallet")
    except ReservationError:
        raise
    except (RuntimeError, TypeError, ValueError) as exc:
        raise ReservationError(f"invalid EOA session authorization signature: {exc}") from exc
    return normalized


def inference_request_hash(
    *,
    endpoint: str,
    model: str,
    input_value: Any = None,
    messages: Any = None,
    max_output_tokens: Any,
) -> str:
    """Hash the billable inference envelope, excluding transport and routing metadata."""
    normalized_endpoint = str(endpoint or "").strip().lower()
    if normalized_endpoint not in {"responses", "chat"}:
        raise ReservationError("inference request endpoint must be responses or chat")
    normalized_model = str(model or "")
    if not normalized_model:
        raise ReservationError("inference request model is required")
    output_limit = _positive_int(max_output_tokens, "max_output_tokens")
    if normalized_endpoint == "chat":
        request_field = "messages"
        request_value = messages
        if request_value is None:
            request_value = [{"role": "user", "content": str(input_value or "")}]
    else:
        request_field = "input"
        request_value = input_value if input_value is not None else ""
    envelope = {
        "request_hash_version": INFERENCE_REQUEST_HASH_VERSION,
        "endpoint": normalized_endpoint,
        "model": normalized_model,
        request_field: request_value,
        "max_output_tokens": output_limit,
    }
    try:
        payload = json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReservationError(f"inference request must contain canonical JSON data: {exc}") from exc
    return hashlib.sha256(payload).hexdigest()


def build_payment_reservation(
    *,
    request_id: str,
    consumer_id: str,
    consumer_payment_address: str | None,
    provider_id: str,
    provider_payment_address: str | None,
    channel: str,
    pricing_hash: str,
    max_fee_units: int,
    signer: NodeIdentity,
    expires_at: int | None = None,
    nonce: str | None = None,
    settlement_version: int = 2,
    pricing_version: int | None = None,
    onchain_reservation_id: str | None = None,
    request_hash: str | None = None,
    settlement_deadline: int | None = None,
    provider_fallback_allowed: bool = False,
    settlement_chain_id: int | None = None,
    settlement_contract: str | None = None,
    evm_session_authorization: dict[str, Any] | None = None,
    consumer_wallet_private_key: str | None = None,
    session_authorization_signature: str | None = None,
    session_authorization_nonce: str | None = None,
) -> dict[str, Any]:
    if not request_id:
        raise ReservationError("request_id is required")
    if not consumer_id:
        raise ReservationError("consumer_id is required")
    if not provider_id:
        raise ReservationError("provider_id is required")
    resolved_max_fee_units = _positive_int(max_fee_units, "max_fee_units")
    if resolved_max_fee_units > (1 << 256) - 1:
        raise ReservationError("max_fee_units exceeds uint256")
    current_time = int(time.time())
    resolved_expiry = _positive_int(
        expires_at if expires_at is not None else current_time + DEFAULT_RESERVATION_TTL_SECONDS,
        "expires_at",
    )
    if resolved_expiry <= current_time or resolved_expiry > current_time + MAX_RESERVATION_TTL_SECONDS:
        raise ReservationError("expires_at must be within the next 30 days")
    resolved_settlement_version = _positive_int(settlement_version, "settlement_version")
    if resolved_settlement_version not in {2, 3}:
        raise ReservationError("settlement_version must be 2 or 3")
    document = {
        "reservation_version": "mycomesh-reservation-v2" if resolved_settlement_version == 3 else "mycomesh-reservation-v1",
        "settlement_version": resolved_settlement_version,
        "request_id": request_id,
        "consumer_id": consumer_id,
        "consumer_public_key": signer.public_key,
        "consumer_payment_address": consumer_payment_address,
        "provider_id": provider_id,
        "provider_payment_address": provider_payment_address,
        "channel": channel,
        "pricing_hash": pricing_hash,
        "max_fee_units": resolved_max_fee_units,
        "expires_at": resolved_expiry,
    }
    if resolved_settlement_version == 3:
        resolved_chain_id = _strict_positive_int(settlement_chain_id, "Settlement V3 settlement_chain_id")
        if resolved_chain_id > (1 << 256) - 1:
            raise ReservationError("Settlement V3 settlement_chain_id exceeds uint256")
        normalized_contract = _normalize_address(settlement_contract, "Settlement V3 settlement_contract")
        resolved_pricing_version = _positive_int(pricing_version, "Settlement V3 pricing_version")
        if resolved_pricing_version > (1 << 64) - 1:
            raise ReservationError("Settlement V3 pricing_version must be a positive uint64")
        if not isinstance(onchain_reservation_id, str) or not BYTES32_PATTERN.fullmatch(onchain_reservation_id):
            raise ReservationError("Settlement V3 onchain_reservation_id must be bytes32")
        normalized_request_hash = _normalize_bytes32(request_hash, "Settlement V3 request_hash")
        if not isinstance(consumer_payment_address, str) or not ADDRESS_PATTERN.fullmatch(consumer_payment_address):
            raise ReservationError("Settlement V3 consumer_payment_address is required")
        if not isinstance(provider_payment_address, str) or not ADDRESS_PATTERN.fullmatch(provider_payment_address):
            raise ReservationError("Settlement V3 provider_payment_address is required")
        normalized_consumer_address = _normalize_address(
            consumer_payment_address,
            "Settlement V3 consumer_payment_address",
        )
        normalized_provider_address = _normalize_address(
            provider_payment_address,
            "Settlement V3 provider_payment_address",
        )
        resolved_expiry, resolved_deadline = validate_v3_time_window(
            expires_at=resolved_expiry,
            settlement_deadline=settlement_deadline,
            now=current_time,
        )
        if not isinstance(provider_fallback_allowed, bool):
            raise ReservationError("Settlement V3 provider_fallback_allowed must be a boolean")
        authorization_expected = {
            "chain_id": resolved_chain_id,
            "settlement_contract": normalized_contract,
            "onchain_reservation_id": onchain_reservation_id.lower(),
            "consumer_payment_address": normalized_consumer_address,
            "provider_id": provider_id,
            "provider_payment_address": normalized_provider_address,
            "channel": channel,
            "pricing_hash": str(pricing_hash or "").lower(),
            "pricing_version": resolved_pricing_version,
            "request_hash": normalized_request_hash,
            "max_fee_units": resolved_max_fee_units,
            "expires_at": resolved_expiry,
            "settlement_deadline": resolved_deadline,
            "provider_fallback_allowed": provider_fallback_allowed,
            "session_public_key": signer.public_key,
        }
        if evm_session_authorization is not None:
            if any(
                value is not None
                for value in (
                    consumer_wallet_private_key,
                    session_authorization_signature,
                    session_authorization_nonce,
                )
            ):
                raise ReservationError(
                    "evm_session_authorization cannot be combined with wallet signing arguments"
                )
            authorization = validate_evm_session_authorization(
                evm_session_authorization,
                **authorization_expected,
                now=current_time,
            )
        else:
            authorization = build_evm_session_authorization(
                **authorization_expected,
                nonce=session_authorization_nonce,
                wallet_private_key=consumer_wallet_private_key,
                wallet_signature=session_authorization_signature,
                now=current_time,
            )
        document.update(
            {
                "settlement_chain_id": resolved_chain_id,
                "settlement_contract": normalized_contract,
                "pricing_version": resolved_pricing_version,
                "onchain_reservation_id": onchain_reservation_id.lower(),
                "request_hash": normalized_request_hash,
                "settlement_deadline": resolved_deadline,
                "provider_fallback_allowed": provider_fallback_allowed,
                "consumer_payment_address": normalized_consumer_address,
                "provider_payment_address": normalized_provider_address,
                "evm_session_authorization": authorization,
            }
        )
    return sign_document(document, signer.private_key, purpose=PAYMENT_RESERVATION_PURPOSE, nonce=nonce)


def verify_payment_reservation(
    reservation: Any,
    *,
    request_id: str,
    channel: str,
    provider_id: str | None = None,
    provider_payment_address: str | None = None,
    consumer_public_key: str | None = None,
    min_fee_units: int = 0,
    pricing_hash: str | None = None,
    settlement_version: int | None = None,
    pricing_version: int | None = None,
    onchain_reservation_id: str | None = None,
    request_hash: str | None = None,
    provider_fallback_allowed: bool | None = None,
    settlement_chain_id: int | None = None,
    settlement_contract: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(reservation, dict):
        raise ReservationError("payment reservation is required")
    try:
        verified = verify_document(reservation, purpose=PAYMENT_RESERVATION_PURPOSE, now=now)
    except IdentityError as exc:
        raise ReservationError(f"invalid payment reservation signature: {exc}") from exc

    signature = reservation.get("signature")
    signer_public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if consumer_public_key and signer_public_key != consumer_public_key:
        raise ReservationError("reservation signer does not match consumer request")
    declared_reservation_version = str(verified.get("reservation_version") or "")
    declared_settlement_version = _positive_int(verified.get("settlement_version", 2), "settlement_version")
    if declared_settlement_version not in {2, 3}:
        raise ReservationError("unsupported settlement_version")
    expected_document_version = "mycomesh-reservation-v2" if declared_settlement_version == 3 else "mycomesh-reservation-v1"
    if declared_reservation_version != expected_document_version:
        raise ReservationError("reservation_version does not match settlement_version")
    if settlement_version is not None and int(settlement_version) != declared_settlement_version:
        raise ReservationError("settlement_version mismatch")
    _require_equal("request_id", request_id, verified.get("request_id"))
    _require_equal("channel", channel, verified.get("channel"))
    if provider_id:
        _require_equal("provider_id", provider_id, verified.get("provider_id"))
    if provider_payment_address:
        _require_equal("provider_payment_address", provider_payment_address, verified.get("provider_payment_address"))
    expires_at = _positive_int(verified.get("expires_at"), "expires_at")
    current_time = int(now if now is not None else time.time())
    if expires_at <= current_time:
        raise ReservationError("payment reservation expired")
    max_fee_units = _positive_int(verified.get("max_fee_units"), "max_fee_units")
    if min_fee_units > 0 and max_fee_units < min_fee_units:
        raise ReservationError("payment reservation max_fee_units is too low")
    actual_pricing_hash = str(verified.get("pricing_hash") or "")
    if not actual_pricing_hash:
        raise ReservationError("payment reservation pricing_hash is required")
    expected_pricing_hash = str(pricing_hash or "")
    if expected_pricing_hash and expected_pricing_hash.lower() != actual_pricing_hash.lower():
        raise ReservationError("payment reservation pricing_hash mismatch")
    if declared_settlement_version == 3:
        reservation_session_key = str(verified.get("consumer_public_key") or "")
        if signer_public_key != reservation_session_key:
            raise ReservationError("reservation signer does not match its consumer_public_key")
        actual_chain_id = _strict_positive_int(verified.get("settlement_chain_id"), "settlement_chain_id")
        if settlement_chain_id is not None and actual_chain_id != int(settlement_chain_id):
            raise ReservationError("settlement_chain_id mismatch")
        actual_contract = _normalize_address(verified.get("settlement_contract"), "settlement_contract")
        if settlement_contract is not None:
            expected_contract = _normalize_address(settlement_contract, "expected settlement_contract")
            if actual_contract != expected_contract:
                raise ReservationError("settlement_contract mismatch")
        actual_pricing_version = _positive_int(verified.get("pricing_version"), "pricing_version")
        if actual_pricing_version > (1 << 64) - 1:
            raise ReservationError("pricing_version exceeds uint64")
        if pricing_version is not None and int(pricing_version) != actual_pricing_version:
            raise ReservationError("pricing_version mismatch")
        actual_reservation_id = str(verified.get("onchain_reservation_id") or "")
        if not BYTES32_PATTERN.fullmatch(actual_reservation_id):
            raise ReservationError("onchain_reservation_id must be bytes32")
        if onchain_reservation_id and onchain_reservation_id.lower() != actual_reservation_id.lower():
            raise ReservationError("onchain_reservation_id mismatch")
        actual_request_hash = _normalize_bytes32(verified.get("request_hash"), "Settlement V3 request_hash")
        if request_hash is not None:
            expected_request_hash = _normalize_bytes32(request_hash, "expected request_hash")
            if expected_request_hash != actual_request_hash:
                raise ReservationError("request_hash mismatch")
        if not ADDRESS_PATTERN.fullmatch(str(verified.get("consumer_payment_address") or "")):
            raise ReservationError("consumer_payment_address is required for Settlement V3")
        if not ADDRESS_PATTERN.fullmatch(str(verified.get("provider_payment_address") or "")):
            raise ReservationError("provider_payment_address is required for Settlement V3")
        deadline = _positive_int(verified.get("settlement_deadline"), "settlement_deadline")
        if deadline <= current_time:
            raise ReservationError("settlement deadline expired")
        if deadline > expires_at:
            raise ReservationError("settlement deadline exceeds reservation expiry")
        actual_fallback_allowed = verified.get("provider_fallback_allowed")
        if not isinstance(actual_fallback_allowed, bool):
            raise ReservationError("Settlement V3 provider_fallback_allowed must be a boolean")
        if provider_fallback_allowed is not None:
            if not isinstance(provider_fallback_allowed, bool):
                raise ReservationError("expected provider_fallback_allowed must be a boolean")
            if actual_fallback_allowed != provider_fallback_allowed:
                raise ReservationError("provider_fallback_allowed mismatch")
        authorization = validate_evm_session_authorization(
            verified.get("evm_session_authorization"),
            chain_id=actual_chain_id,
            settlement_contract=actual_contract,
            onchain_reservation_id=actual_reservation_id,
            consumer_payment_address=str(verified.get("consumer_payment_address") or ""),
            provider_id=str(verified.get("provider_id") or ""),
            provider_payment_address=str(verified.get("provider_payment_address") or ""),
            channel=str(verified.get("channel") or ""),
            pricing_hash=actual_pricing_hash,
            pricing_version=actual_pricing_version,
            request_hash=actual_request_hash,
            max_fee_units=max_fee_units,
            expires_at=expires_at,
            settlement_deadline=deadline,
            provider_fallback_allowed=actual_fallback_allowed,
            session_public_key=signer_public_key,
            now=current_time,
        )
        verified["evm_session_authorization"] = authorization
    return verified


def _require_equal(label: str, expected: Any, actual: Any) -> None:
    if str(expected or "").lower() != str(actual or "").lower():
        raise ReservationError(f"{label} mismatch")


def _positive_int(value: Any, label: str) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        parsed = int(value)
    else:
        raise ReservationError(f"{label} must be an integer")
    if parsed <= 0:
        raise ReservationError(f"{label} must be positive")
    return parsed


def _strict_positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReservationError(f"{label} must be a positive integer")
    return value


def _normalize_bytes32(value: Any, label: str) -> str:
    text = str(value or "")
    if len(text) == 64:
        text = "0x" + text
    if not BYTES32_PATTERN.fullmatch(text) or int(text[2:], 16) == 0:
        raise ReservationError(f"{label} must be a non-zero bytes32 value")
    return text.lower()


def _normalize_address(value: Any, label: str) -> str:
    text = str(value or "")
    if not ADDRESS_PATTERN.fullmatch(text) or int(text[2:], 16) == 0:
        raise ReservationError(f"{label} must be a non-zero EVM address")
    return text.lower()


def _normalize_session_authorization(value: Any, *, signed: bool | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReservationError("EVM session authorization must be an object")
    expected_fields = set(_SESSION_AUTHORIZATION_FIELDS)
    if signed is not False:
        expected_fields.add("wallet_signature")
    if signed is None and "wallet_signature" not in value:
        expected_fields.remove("wallet_signature")
    actual_fields = set(value)
    if actual_fields != expected_fields:
        missing = sorted(expected_fields - actual_fields)
        unexpected = sorted(actual_fields - expected_fields)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ReservationError("invalid EVM session authorization fields: " + "; ".join(details))
    if value.get("authorization_version") != EVM_SESSION_AUTHORIZATION_VERSION:
        raise ReservationError("unsupported EVM session authorization version")
    normalized = {
        "authorization_version": EVM_SESSION_AUTHORIZATION_VERSION,
        "chain_id": _strict_positive_int(value.get("chain_id"), "EVM session authorization chain_id"),
        "settlement_contract": _canonical_address(
            value.get("settlement_contract"), "EVM session authorization settlement_contract"
        ),
        "onchain_reservation_id": _canonical_bytes32(
            value.get("onchain_reservation_id"), "EVM session authorization onchain_reservation_id"
        ),
        "consumer_payment_address": _canonical_address(
            value.get("consumer_payment_address"), "EVM session authorization consumer_payment_address"
        ),
        "provider_id": _strict_ascii_text(value.get("provider_id"), "EVM session authorization provider_id", 256),
        "provider_payment_address": _canonical_address(
            value.get("provider_payment_address"), "EVM session authorization provider_payment_address"
        ),
        "channel": _strict_ascii_text(value.get("channel"), "EVM session authorization channel", 256),
        "pricing_hash": _canonical_bytes32(
            value.get("pricing_hash"), "EVM session authorization pricing_hash"
        ),
        "pricing_version": _strict_positive_int(
            value.get("pricing_version"), "EVM session authorization pricing_version"
        ),
        "request_hash": _canonical_bytes32(
            value.get("request_hash"), "EVM session authorization request_hash"
        ),
        "max_fee_units": _strict_positive_int(
            value.get("max_fee_units"), "EVM session authorization max_fee_units"
        ),
        "expires_at": _strict_positive_int(value.get("expires_at"), "EVM session authorization expires_at"),
        "settlement_deadline": _strict_positive_int(
            value.get("settlement_deadline"), "EVM session authorization settlement_deadline"
        ),
        "provider_fallback_allowed": value.get("provider_fallback_allowed"),
        "nonce": _canonical_bytes32(value.get("nonce"), "EVM session authorization nonce"),
        "session_public_key": _canonical_public_key(value.get("session_public_key")),
    }
    if normalized["chain_id"] > (1 << 256) - 1:
        raise ReservationError("EVM session authorization chain_id exceeds uint256")
    if normalized["pricing_version"] > (1 << 64) - 1:
        raise ReservationError("EVM session authorization pricing_version exceeds uint64")
    if normalized["max_fee_units"] > (1 << 256) - 1:
        raise ReservationError("EVM session authorization max_fee_units exceeds uint256")
    if normalized["settlement_deadline"] > normalized["expires_at"]:
        raise ReservationError("EVM session authorization deadline exceeds expiry")
    if type(normalized["provider_fallback_allowed"]) is not bool:
        raise ReservationError("EVM session authorization provider_fallback_allowed must be a boolean")
    if "wallet_signature" in expected_fields:
        normalized["wallet_signature"] = _canonical_wallet_signature(value.get("wallet_signature"))
    return normalized


def _strict_ascii_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReservationError(f"{label} must be between 1 and {maximum} characters")
    if not value.isascii() or value.strip() != value or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ReservationError(f"{label} must use printable ASCII without whitespace")
    return value


def _canonical_address(value: Any, label: str) -> str:
    normalized = _normalize_address(value, label)
    if value != normalized:
        raise ReservationError(f"{label} must use canonical lowercase hex")
    return normalized


def _canonical_bytes32(value: Any, label: str) -> str:
    normalized = _normalize_bytes32(value, label)
    if value != normalized:
        raise ReservationError(f"{label} must use canonical lowercase 0x-prefixed hex")
    return normalized


def _canonical_public_key(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ReservationError("EVM session authorization session_public_key must be a canonical Ed25519 public key")
    return value


def _canonical_wallet_signature(value: Any) -> str:
    if not isinstance(value, str) or not HEX_PATTERN.fullmatch(value) or len(value[2:]) % 2:
        raise ReservationError("EVM session authorization wallet_signature must be canonical 0x-prefixed hex")
    size = len(value[2:]) // 2
    if size < 1 or size > MAX_EVM_WALLET_SIGNATURE_BYTES:
        raise ReservationError(
            f"EVM session authorization wallet_signature must be between 1 and {MAX_EVM_WALLET_SIGNATURE_BYTES} bytes"
        )
    return value
