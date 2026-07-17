from __future__ import annotations

import re
import time
from typing import Any

from .identity import IdentityError, NodeIdentity, peer_id_from_public_key, sign_document, verify_document
from .ledger import stable_hash
from .pricing import PriceQuote, usage_tokens
from .channel_policy import require_enabled_channel_binding


PROVIDER_SETTLEMENT_PURPOSE = "mycomesh.settlement.provider_attestation.v1"
PROVIDER_ATTESTATION_VERSION = "mycomesh-provider-attestation-v1"
BYTES32_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")
DIGEST_PATTERN = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
PUBLIC_KEY_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
UINT64_MAX = (1 << 64) - 1
UINT256_MAX = (1 << 256) - 1


class AttestationError(RuntimeError):
    pass


def build_provider_settlement_attestation(
    *,
    request_id: str,
    request_hash: str,
    response: dict[str, Any],
    channel: str,
    network_id: str | None = None,
    channel_id: str | None = None,
    backend_policy: str | None = None,
    model: str,
    endpoint: str,
    reservation: dict[str, Any],
    quote: PriceQuote,
    provider_id: str,
    provider_payment_address: str | None,
    signer: NodeIdentity,
) -> dict[str, Any]:
    if int(reservation.get("settlement_version") or 2) == 3:
        reserved_request_hash = _normalized_digest(reservation.get("request_hash"), "reservation request_hash")
        if reserved_request_hash != _normalized_digest(request_hash, "request_hash"):
            raise AttestationError("provider attestation request_hash does not match the Settlement V3 reservation")
    input_tokens, output_tokens = usage_tokens(response.get("usage") if isinstance(response.get("usage"), dict) else None)
    pricing = quote.to_dict()
    document = {
        "attestation_version": PROVIDER_ATTESTATION_VERSION,
        "request_id": str(request_id),
        "request_hash": str(request_hash),
        "response_hash": settlement_response_hash(response),
        "channel": str(channel),
        "model": str(model),
        "endpoint": str(endpoint),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "gross_fee_units": _usdc_units(pricing.get("gross_fee")),
        "consumer_id": str(reservation.get("consumer_id") or ""),
        "consumer_public_key": str(reservation.get("consumer_public_key") or ""),
        "consumer_payment_address": reservation.get("consumer_payment_address"),
        "provider_id": str(provider_id),
        "provider_payment_address": provider_payment_address,
        "pricing_hash": str(reservation.get("pricing_hash") or ""),
        "settlement_version": int(reservation.get("settlement_version") or 2),
        "pricing_version": reservation.get("pricing_version"),
        "onchain_reservation_id": reservation.get("onchain_reservation_id"),
        "settlement_deadline": int(reservation.get("settlement_deadline") or reservation.get("expires_at") or 0),
    }
    if network_id is not None:
        document["network_id"] = network_id
    if channel_id is not None:
        document["channel_id"] = channel_id
    if backend_policy is not None:
        document["backend_policy"] = backend_policy
    _validate_document_shape(document)
    return sign_document(
        document,
        signer.private_key,
        purpose=PROVIDER_SETTLEMENT_PURPOSE,
        audience=document["consumer_public_key"],
    )


def verify_provider_settlement_attestation(
    attestation: Any,
    *,
    provider_public_key: str,
    consumer_public_key: str,
    expected: dict[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(attestation, dict):
        raise AttestationError("provider settlement attestation is required")
    try:
        verified = verify_document(
            attestation,
            purpose=PROVIDER_SETTLEMENT_PURPOSE,
            audience=consumer_public_key,
            max_age_seconds=0,
        )
    except (IdentityError, TypeError, ValueError) as exc:
        raise AttestationError(f"invalid provider settlement attestation: {exc}") from exc
    signature = attestation.get("signature")
    signer_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if signer_key != provider_public_key:
        raise AttestationError("provider attestation public_key mismatch")
    _validate_document_shape(verified)
    if str(verified.get("consumer_public_key") or "") != consumer_public_key:
        raise AttestationError("provider attestation consumer_public_key mismatch")
    try:
        expected_provider_id = peer_id_from_public_key(provider_public_key)
    except (IdentityError, TypeError, ValueError) as exc:
        raise AttestationError("provider attestation public_key is invalid") from exc
    if expected_provider_id != str(verified.get("provider_id") or ""):
        raise AttestationError("provider attestation peer_id mismatch")
    signature_timestamp = _integer(signature.get("timestamp") if isinstance(signature, dict) else None, "signature timestamp")
    if signature_timestamp < 0:
        raise AttestationError("provider attestation signature timestamp must be non-negative")
    current_time = int(now if now is not None else time.time())
    if signature_timestamp > current_time + 30:
        raise AttestationError("provider attestation timestamp is in the future")
    deadline = _integer(verified.get("settlement_deadline"), "settlement_deadline")
    if deadline and signature_timestamp > deadline:
        raise AttestationError("provider attestation was signed after settlement deadline")
    for field, expected_value in (expected or {}).items():
        if expected_value is None:
            continue
        actual = verified.get(field)
        if str(actual).lower() != str(expected_value).lower():
            raise AttestationError(f"provider attestation {field} mismatch")
    return verified


def settlement_response_hash(response: dict[str, Any]) -> str:
    return stable_hash(response.get("output_text") or response.get("raw") or response)


def _validate_document_shape(document: dict[str, Any]) -> None:
    if str(document.get("attestation_version") or "") != PROVIDER_ATTESTATION_VERSION:
        raise AttestationError("unsupported provider attestation version")
    for field in (
        "request_id",
        "request_hash",
        "response_hash",
        "channel",
        "model",
        "endpoint",
        "consumer_id",
        "consumer_public_key",
        "provider_id",
    ):
        _required_text(document.get(field), field)
    if not DIGEST_PATTERN.fullmatch(_required_text(document.get("request_hash"), "request_hash")):
        raise AttestationError("provider attestation request_hash must be a 32-byte hex digest")
    if not DIGEST_PATTERN.fullmatch(_required_text(document.get("response_hash"), "response_hash")):
        raise AttestationError("provider attestation response_hash must be a 32-byte hex digest")
    if not BYTES32_PATTERN.fullmatch(_required_text(document.get("pricing_hash"), "pricing_hash")):
        raise AttestationError("provider attestation pricing_hash must be bytes32")
    if not PUBLIC_KEY_PATTERN.fullmatch(_required_text(document.get("consumer_public_key"), "consumer_public_key")):
        raise AttestationError("provider attestation consumer_public_key must be a 32-byte hex key")
    for field in ("input_tokens", "output_tokens", "gross_fee_units"):
        value = _integer(document.get(field), field)
        if value < 0:
            raise AttestationError(f"provider attestation {field} must be non-negative")
        if value > UINT256_MAX:
            raise AttestationError(f"provider attestation {field} exceeds uint256")
    settlement_version = _integer(document.get("settlement_version"), "settlement_version")
    if settlement_version not in {2, 3}:
        raise AttestationError("unsupported provider attestation settlement_version")
    _address(document.get("consumer_payment_address"), "consumer_payment_address", required=settlement_version == 3)
    _address(document.get("provider_payment_address"), "provider_payment_address", required=settlement_version == 3)
    deadline = _integer(document.get("settlement_deadline"), "settlement_deadline")
    if deadline < 0 or deadline > UINT256_MAX:
        raise AttestationError("provider attestation settlement_deadline is out of range")
    if settlement_version == 3:
        try:
            require_enabled_channel_binding(
                network_id=document.get("network_id"),
                channel_id=document.get("channel_id"),
                channel=document.get("channel"),
                backend_policy=document.get("backend_policy"),
                label="provider attestation",
            )
        except ValueError as exc:
            raise AttestationError(str(exc)) from exc
        pricing_version = _integer(document.get("pricing_version"), "pricing_version")
        if pricing_version <= 0 or pricing_version > UINT64_MAX:
            raise AttestationError("Settlement V3 provider attestation requires pricing_version")
        reservation_id = str(document.get("onchain_reservation_id") or "")
        if not BYTES32_PATTERN.fullmatch(reservation_id):
            raise AttestationError("Settlement V3 provider attestation requires onchain_reservation_id")
        if deadline <= 0:
            raise AttestationError("Settlement V3 provider attestation requires settlement_deadline")
    elif document.get("pricing_version") is not None or document.get("onchain_reservation_id") is not None:
        raise AttestationError("Settlement V2 provider attestation cannot contain V3 reservation fields")


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise AttestationError(f"provider attestation {label} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and len(value) <= 80 and re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        return int(value)
    raise AttestationError(f"provider attestation {label} must be an integer")


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttestationError(f"provider attestation {label} is required")
    return value


def _address(value: Any, label: str, *, required: bool) -> None:
    if value is None or value == "":
        if required:
            raise AttestationError(f"Settlement V3 provider attestation requires {label}")
        return
    if not isinstance(value, str) or not ADDRESS_PATTERN.fullmatch(value) or int(value[2:], 16) == 0:
        raise AttestationError(f"provider attestation {label} must be a non-zero address")


def _usdc_units(value: Any) -> int:
    from decimal import Decimal

    return int(Decimal(str(value or "0")) * Decimal("1000000"))


def _normalized_digest(value: Any, label: str) -> str:
    text = str(value or "")
    if not DIGEST_PATTERN.fullmatch(text) or int(text.removeprefix("0x"), 16) == 0:
        raise AttestationError(f"provider attestation {label} must be a non-zero 32-byte hex digest")
    return text.removeprefix("0x").lower()
