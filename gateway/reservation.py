from __future__ import annotations

import time
from typing import Any

from .identity import IdentityError, NodeIdentity, sign_document, verify_document


PAYMENT_RESERVATION_PURPOSE = "mycomesh.payment.reservation.v1"
DEFAULT_RESERVATION_TTL_SECONDS = 300


class ReservationError(RuntimeError):
    pass


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
) -> dict[str, Any]:
    if not request_id:
        raise ReservationError("request_id is required")
    if not consumer_id:
        raise ReservationError("consumer_id is required")
    if not provider_id:
        raise ReservationError("provider_id is required")
    if max_fee_units <= 0:
        raise ReservationError("max_fee_units must be positive")
    document = {
        "reservation_version": "mycomesh-reservation-v1",
        "request_id": request_id,
        "consumer_id": consumer_id,
        "consumer_public_key": signer.public_key,
        "consumer_payment_address": consumer_payment_address,
        "provider_id": provider_id,
        "provider_payment_address": provider_payment_address,
        "channel": channel,
        "pricing_hash": pricing_hash,
        "max_fee_units": int(max_fee_units),
        "expires_at": int(expires_at if expires_at is not None else time.time() + DEFAULT_RESERVATION_TTL_SECONDS),
    }
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
    _require_equal("request_id", request_id, verified.get("request_id"))
    _require_equal("channel", channel, verified.get("channel"))
    if provider_id:
        _require_equal("provider_id", provider_id, verified.get("provider_id"))
    if provider_payment_address:
        _require_equal("provider_payment_address", provider_payment_address, verified.get("provider_payment_address"))
    expires_at = _positive_int(verified.get("expires_at"), "expires_at")
    current_time = int(now if now is not None else time.time())
    if expires_at < current_time:
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
    return verified


def _require_equal(label: str, expected: Any, actual: Any) -> None:
    if str(expected or "").lower() != str(actual or "").lower():
        raise ReservationError(f"{label} mismatch")


def _positive_int(value: Any, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ReservationError(f"{label} must be an integer") from exc
    if parsed <= 0:
        raise ReservationError(f"{label} must be positive")
    return parsed
