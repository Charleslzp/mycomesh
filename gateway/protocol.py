from __future__ import annotations

from decimal import Decimal, InvalidOperation
import re
from typing import Any

from .attestation import AttestationError, verify_provider_settlement_attestation
from .identity import IdentityError, peer_id_from_public_key, verify_document
from .ledger import (
    ACCEPTANCE_VERSION,
    LEGACY_RECEIPT_VERSION,
    RECEIPT_VERSION,
    verify_acceptance,
    verify_receipt_signature,
)
from .p2p import PROVIDER_RESPONSE_PURPOSE
from .channel_policy import require_enabled_channel_binding


class ProtocolValidationError(RuntimeError):
    pass


BYTES32_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")
DIGEST_PATTERN = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
UINT64_MAX = (1 << 64) - 1
UINT256_MAX = (1 << 256) - 1


def verify_provider_response(
    response: dict[str, Any],
    peer: dict[str, Any] | None = None,
    audience: str | None = None,
    expected_request_id: str | None = None,
    expected_request_hash: str | None = None,
    expected_channel: str | None = None,
    expected_network_id: str | None = None,
    expected_channel_id: str | None = None,
    expected_backend_policy: str | None = None,
    expected_model: str | None = None,
    expected_endpoint: str | None = None,
) -> dict[str, Any]:
    try:
        unsigned = verify_document(response, purpose=PROVIDER_RESPONSE_PURPOSE, audience=audience)
    except IdentityError as exc:
        raise ProtocolValidationError(f"invalid provider response signature: {exc}") from exc
    signature = response.get("signature")
    public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if not public_key:
        raise ProtocolValidationError("provider response signature missing public_key")
    if peer is not None:
        expected_public_key = str(peer.get("public_key") or "")
        if expected_public_key and public_key != expected_public_key:
            raise ProtocolValidationError("provider response public_key does not match pool descriptor")
        expected_peer_id = str(peer.get("peer_id") or "")
        if expected_peer_id and peer_id_from_public_key(public_key) != expected_peer_id:
            raise ProtocolValidationError("provider response peer_id does not match public_key")
    _require_match("provider response request_id", expected_request_id, unsigned.get("request_id"))
    _require_match("provider response channel", expected_channel, unsigned.get("channel"))
    _require_match("provider response network_id", expected_network_id, unsigned.get("network_id"))
    _require_match("provider response channel_id", expected_channel_id, unsigned.get("channel_id"))
    _require_match(
        "provider response backend_policy",
        expected_backend_policy,
        unsigned.get("backend_policy"),
    )
    _require_match("provider response model", expected_model, unsigned.get("model"))
    _require_match("provider response endpoint", expected_endpoint, unsigned.get("endpoint"))
    if expected_request_hash is not None:
        quality = unsigned.get("quality")
        actual_request_hash = quality.get("request_hash") if isinstance(quality, dict) else None
        _require_match("provider response request hash", expected_request_hash, actual_request_hash)
    return unsigned


def validate_settlement_receipt(
    receipt: dict[str, Any],
    consumer_address: str | None = None,
    provider_address: str | None = None,
    consumer_public_key: str | None = None,
    provider_public_key: str | None = None,
    *,
    allow_legacy_receipts: bool = True,
    required_settlement_version: int | None = None,
) -> dict[str, Any]:
    try:
        if not isinstance(receipt, dict):
            raise ValueError("receipt must be an object")
        declared_consumer_key = str(receipt.get("consumer_public_key") or "")
        declared_provider_key = str(receipt.get("provider_public_key") or "")
        if not declared_consumer_key or not declared_provider_key:
            raise ValueError("consumer_public_key and provider_public_key are required")
        peer_id_from_public_key(declared_consumer_key)
        peer_id_from_public_key(declared_provider_key)
        receipt_version, settlement_version = _validate_receipt_shape(receipt)
        if required_settlement_version is not None:
            required_version = _integer(required_settlement_version, "required_settlement_version")
            if required_version not in {2, 3, 4}:
                raise ValueError("required_settlement_version must be 2, 3, or 4")
            if settlement_version != required_version:
                raise ValueError("settlement_version mismatch")
        if receipt_version == LEGACY_RECEIPT_VERSION and not allow_legacy_receipts:
            raise ValueError("legacy settlement receipts are disabled")
        if settlement_version in {3, 4} and receipt_version != RECEIPT_VERSION:
            raise ValueError(f"Settlement V{settlement_version} requires a v2 receipt with provider evidence")
        verified_receipt = verify_receipt_signature(receipt, expected_public_key=declared_consumer_key)
        acceptance = verify_acceptance(receipt, expected_public_key=declared_consumer_key)
    except Exception as exc:
        raise ProtocolValidationError(f"invalid settlement receipt: {exc}") from exc

    if str(acceptance.get("acceptance_version") or "") != ACCEPTANCE_VERSION:
        raise ProtocolValidationError("unsupported receipt acceptance version")
    if str(acceptance.get("job_id") or "") != str(receipt.get("job_id") or ""):
        raise ProtocolValidationError("acceptance job_id mismatch")
    if str(acceptance.get("status") or "") != "accepted":
        raise ProtocolValidationError("receipt was not accepted")
    if str(acceptance.get("consumer_id") or "") != str(receipt.get("consumer_id") or ""):
        raise ProtocolValidationError("acceptance consumer_id mismatch")
    if str(acceptance.get("provider_id") or "") != str(receipt.get("provider_id") or ""):
        raise ProtocolValidationError("acceptance provider_id mismatch")
    if str(acceptance.get("accepted_by") or "") != str(receipt.get("consumer_id") or ""):
        raise ProtocolValidationError("acceptance accepted_by must be the receipt consumer")

    _require_match("consumer payment address", consumer_address, receipt.get("consumer_payment_address"))
    _require_match("provider payment address", provider_address, receipt.get("provider_payment_address"))
    _require_match("consumer public key", consumer_public_key, receipt.get("consumer_public_key"))
    _require_match("provider public key", provider_public_key, receipt.get("provider_public_key"))
    expected_peer_id = peer_id_from_public_key(declared_provider_key)
    if str(receipt.get("provider_id") or "") != expected_peer_id:
        raise ProtocolValidationError("receipt provider_id does not match provider public key")
    if receipt_version == RECEIPT_VERSION:
        _validate_provider_attestation(receipt, declared_consumer_key, declared_provider_key)
    return {
        "receipt": verified_receipt,
        "acceptance": acceptance,
    }


def _require_match(label: str, expected: str | None, actual: Any) -> None:
    if expected is None:
        return
    if str(expected).lower() != str(actual or "").lower():
        raise ProtocolValidationError(f"{label} mismatch")


def _validate_provider_attestation(
    receipt: dict[str, Any],
    consumer_public_key: str,
    provider_public_key: str,
) -> None:
    try:
        pricing = receipt.get("pricing")
        if not isinstance(pricing, dict):
            raise ValueError("receipt pricing is required")
        expected: dict[str, Any] = {
            "request_id": str(receipt.get("job_id") or ""),
            "request_hash": str(receipt.get("request_hash") or ""),
            "response_hash": str(receipt.get("response_hash") or ""),
            "channel": str(receipt.get("channel") or ""),
            "network_id": receipt.get("network_id"),
            "channel_id": receipt.get("channel_id"),
            "backend_policy": receipt.get("backend_policy"),
            "model": str(receipt.get("model") or ""),
            "endpoint": str(receipt.get("endpoint") or ""),
            "input_tokens": _non_negative_integer(pricing.get("input_tokens"), "pricing input_tokens"),
            "output_tokens": _non_negative_integer(pricing.get("output_tokens"), "pricing output_tokens"),
            "gross_fee_units": _gross_fee_units(pricing.get("gross_fee")),
            "consumer_id": str(receipt.get("consumer_id") or ""),
            "consumer_payment_address": receipt.get("consumer_payment_address"),
            "provider_id": str(receipt.get("provider_id") or ""),
            "provider_payment_address": receipt.get("provider_payment_address"),
            "pricing_hash": str(receipt.get("channel_pricing_hash") or ""),
            "settlement_version": _integer(receipt.get("settlement_version", 2), "settlement_version"),
        }
        for field in ("pricing_version", "onchain_reservation_id", "session_id", "session_sequence", "authorization_hash"):
            if receipt.get(field) is not None:
                expected[field] = receipt.get(field)
        if int(expected["settlement_version"]) == 4:
            v4_payload = receipt.get("mycomesh_v4_settlement")
            v4_receipt = v4_payload.get("receipt") if isinstance(v4_payload, dict) else None
            if not isinstance(v4_receipt, dict):
                raise ValueError("Settlement V4 receipt must include mycomesh_v4_settlement")
            expected["session_id"] = v4_receipt.get("session_id")
            expected["session_sequence"] = int(v4_receipt.get("sequence")) + 1
        settlement_deadline = _integer(receipt.get("settlement_deadline", 0), "settlement_deadline")
        if settlement_deadline > 0:
            expected["settlement_deadline"] = settlement_deadline
        verified = verify_provider_settlement_attestation(
            receipt.get("provider_settlement_attestation"),
            provider_public_key=provider_public_key,
            consumer_public_key=consumer_public_key,
            expected=expected,
        )
    except (AttestationError, TypeError, ValueError) as exc:
        raise ProtocolValidationError(f"invalid provider settlement evidence: {exc}") from exc
    signature = receipt.get("provider_settlement_attestation", {}).get("signature")
    try:
        signature_timestamp = _integer(signature.get("timestamp"), "provider signature timestamp") if isinstance(signature, dict) else 0
        started_at = _integer(receipt.get("started_at", 0), "started_at")
        finished_at = _integer(receipt.get("finished_at", 0), "finished_at")
    except ValueError as exc:
        raise ProtocolValidationError(f"invalid provider settlement evidence: {exc}") from exc
    if started_at and signature_timestamp < started_at - 30:
        raise ProtocolValidationError("provider settlement evidence predates inference")
    if finished_at and signature_timestamp > finished_at + 30:
        raise ProtocolValidationError("provider settlement evidence postdates inference")
    if str(verified.get("consumer_public_key") or "") != consumer_public_key:
        raise ProtocolValidationError("provider settlement evidence consumer key mismatch")


def _validate_receipt_shape(receipt: dict[str, Any]) -> tuple[str, int]:
    for field in ("job_id", "consumer_id", "provider_id", "channel", "model", "endpoint"):
        _required_text(receipt.get(field), field)
    if not DIGEST_PATTERN.fullmatch(_required_text(receipt.get("request_hash"), "request_hash")):
        raise ValueError("request_hash must be a 32-byte hex digest")
    if not DIGEST_PATTERN.fullmatch(_required_text(receipt.get("response_hash"), "response_hash")):
        raise ValueError("response_hash must be a 32-byte hex digest")
    if not BYTES32_PATTERN.fullmatch(_required_text(receipt.get("channel_pricing_hash"), "channel_pricing_hash")):
        raise ValueError("channel_pricing_hash must be bytes32")
    if not BYTES32_PATTERN.fullmatch(_required_text(receipt.get("accepted_hash"), "accepted_hash")):
        raise ValueError("accepted_hash must be bytes32")
    _address(receipt.get("consumer_payment_address"), "consumer_payment_address", required=False)
    _address(receipt.get("provider_payment_address"), "provider_payment_address", required=False)

    receipt_version = str(receipt.get("receipt_version") or LEGACY_RECEIPT_VERSION)
    if receipt_version not in {LEGACY_RECEIPT_VERSION, RECEIPT_VERSION}:
        raise ValueError("unsupported settlement receipt version")
    settlement_version = _integer(receipt.get("settlement_version", 2), "settlement_version")
    if settlement_version not in {2, 3, 4}:
        raise ValueError("unsupported settlement_version")
    if receipt_version == LEGACY_RECEIPT_VERSION and receipt.get("provider_settlement_attestation") is not None:
        raise ValueError("legacy receipt cannot contain provider settlement evidence")
    if settlement_version in {3, 4}:
        require_enabled_channel_binding(
            network_id=receipt.get("network_id"),
            channel_id=receipt.get("channel_id"),
            channel=receipt.get("channel"),
            backend_policy=receipt.get("backend_policy"),
            label=f"Settlement V{settlement_version} receipt",
        )
        _address(receipt.get("consumer_payment_address"), "consumer_payment_address", required=True)
        _address(receipt.get("provider_payment_address"), "provider_payment_address", required=True)
        pricing_version = _integer(receipt.get("pricing_version"), "pricing_version")
        if pricing_version <= 0 or pricing_version > UINT64_MAX:
            raise ValueError("pricing_version must be a positive uint64")
        if settlement_version == 3:
            if not BYTES32_PATTERN.fullmatch(_required_text(receipt.get("onchain_reservation_id"), "onchain_reservation_id")):
                raise ValueError("onchain_reservation_id must be bytes32")
        else:
            v4_payload = receipt.get("mycomesh_v4_settlement")
            v4_receipt = v4_payload.get("receipt") if isinstance(v4_payload, dict) else None
            session_id = receipt.get("session_id") or (v4_receipt.get("session_id") if isinstance(v4_receipt, dict) else None)
            if not BYTES32_PATTERN.fullmatch(_required_text(session_id, "session_id")):
                raise ValueError("session_id must be bytes32")
            sequence_value = receipt.get("session_sequence")
            if sequence_value is None and isinstance(v4_receipt, dict):
                try:
                    sequence_value = int(v4_receipt.get("sequence")) + 1
                except (TypeError, ValueError):
                    sequence_value = None
            sequence = _integer(sequence_value, "session_sequence")
            if sequence <= 0 or sequence > UINT256_MAX:
                raise ValueError("session_sequence must be a positive uint256")
        if _integer(receipt.get("settlement_deadline"), "settlement_deadline") <= 0:
            raise ValueError(f"Settlement V{settlement_version} settlement_deadline must be positive")
    return receipt_version, settlement_version


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and len(value) <= 80 and re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        return int(value)
    raise ValueError(f"{label} must be an integer")


def _non_negative_integer(value: Any, label: str) -> int:
    parsed = _integer(value, label)
    if parsed < 0 or parsed > UINT256_MAX:
        raise ValueError(f"{label} is out of range")
    return parsed


def _gross_fee_units(value: Any) -> int:
    text = str(value) if not isinstance(value, bool) else ""
    if not text or len(text) > 80:
        raise ValueError("pricing gross_fee must be a decimal with at most 6 places")
    try:
        amount = Decimal(text)
        if not amount.is_finite() or amount < 0:
            raise ValueError("pricing gross_fee must be a decimal with at most 6 places")
        scaled = amount * Decimal("1000000")
    except InvalidOperation as exc:
        raise ValueError("pricing gross_fee must be a decimal with at most 6 places") from exc
    if scaled != scaled.to_integral_value():
        raise ValueError("pricing gross_fee must be a decimal with at most 6 places")
    if scaled > Decimal(UINT256_MAX):
        raise ValueError("pricing gross_fee exceeds uint256")
    return int(scaled)


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    return value


def _address(value: Any, label: str, *, required: bool) -> None:
    if value is None or value == "":
        if required:
            raise ValueError(f"{label} is required")
        return
    if not isinstance(value, str) or not ADDRESS_PATTERN.fullmatch(value) or int(value[2:], 16) == 0:
        raise ValueError(f"{label} must be a non-zero address")
