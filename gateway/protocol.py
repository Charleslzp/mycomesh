from __future__ import annotations

from typing import Any

from .identity import IdentityError, peer_id_from_public_key, verify_document
from .ledger import verify_acceptance, verify_receipt_signature
from .p2p import PROVIDER_RESPONSE_PURPOSE


class ProtocolValidationError(RuntimeError):
    pass


def verify_provider_response(
    response: dict[str, Any],
    peer: dict[str, Any] | None = None,
    audience: str | None = None,
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
    return unsigned


def validate_settlement_receipt(
    receipt: dict[str, Any],
    consumer_address: str | None = None,
    provider_address: str | None = None,
    consumer_public_key: str | None = None,
    provider_public_key: str | None = None,
) -> dict[str, Any]:
    try:
        verified_receipt = verify_receipt_signature(receipt)
        acceptance = verify_acceptance(receipt)
    except Exception as exc:
        raise ProtocolValidationError(f"invalid settlement receipt: {exc}") from exc

    if str(acceptance.get("status") or "") != "accepted":
        raise ProtocolValidationError("receipt was not accepted")
    if str(acceptance.get("consumer_id") or "") != str(receipt.get("consumer_id") or ""):
        raise ProtocolValidationError("acceptance consumer_id mismatch")
    if str(acceptance.get("provider_id") or "") != str(receipt.get("provider_id") or ""):
        raise ProtocolValidationError("acceptance provider_id mismatch")

    _require_match("consumer payment address", consumer_address, receipt.get("consumer_payment_address"))
    _require_match("provider payment address", provider_address, receipt.get("provider_payment_address"))
    _require_match("consumer public key", consumer_public_key, receipt.get("consumer_public_key"))
    _require_match("provider public key", provider_public_key, receipt.get("provider_public_key"))
    if provider_public_key:
        expected_peer_id = peer_id_from_public_key(provider_public_key)
        if str(receipt.get("provider_id") or "") != expected_peer_id:
            raise ProtocolValidationError("receipt provider_id does not match provider public key")
    return {
        "receipt": verified_receipt,
        "acceptance": acceptance,
    }


def _require_match(label: str, expected: str | None, actual: Any) -> None:
    if expected is None:
        return
    if str(expected).lower() != str(actual or "").lower():
        raise ProtocolValidationError(f"{label} mismatch")
