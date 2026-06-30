from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identity import NodeIdentity, sign_document, verify_document
from .pricing import PriceQuote


DEFAULT_LEDGER_PATH = ".codex-run/receipts.jsonl"
RECEIPT_VERSION = "mycomesh-receipt-v1"
RECEIPT_PURPOSE = "mycomesh.receipt.v1"
ACCEPTANCE_VERSION = "mycomesh-acceptance-v1"
ACCEPTANCE_PURPOSE = "mycomesh.receipt.acceptance.v1"


@dataclass(frozen=True)
class InferenceReceipt:
    job_id: str
    consumer_id: str
    provider_id: str
    relay_id: str | None
    pool_url: str
    selected_address: str
    channel: str
    model: str
    endpoint: str
    request_hash: str
    response_hash: str
    started_at: int
    finished_at: int
    elapsed_ms: int
    usage: dict[str, Any] | None
    quote: PriceQuote
    pricing_config_hash: str | None = None
    channel_pricing_hash: str | None = None
    settlement_deadline: int = 0
    consumer_public_key: str | None = None
    provider_public_key: str | None = None
    consumer_payment_address: str | None = None
    provider_payment_address: str | None = None
    bridge_usage: list[dict[str, Any]] | None = None
    quality: dict[str, Any] | None = None
    signatures: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": RECEIPT_VERSION,
            "job_id": self.job_id,
            "consumer_id": self.consumer_id,
            "provider_id": self.provider_id,
            "consumer_public_key": self.consumer_public_key,
            "provider_public_key": self.provider_public_key,
            "consumer_payment_address": self.consumer_payment_address,
            "provider_payment_address": self.provider_payment_address,
            "bridge_usage": self.bridge_usage or [],
            "quality": self.quality or {},
            "relay_id": self.relay_id,
            "pool_url": self.pool_url,
            "selected_address": self.selected_address,
            "channel": self.channel,
            "model": self.model,
            "endpoint": self.endpoint,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ms": self.elapsed_ms,
            "usage": self.usage,
            "pricing": self.quote.to_dict(),
            "pricing_config_hash": self.pricing_config_hash,
            "channel_pricing_hash": self.channel_pricing_hash,
            "settlement_deadline": self.settlement_deadline,
            "signatures": self.signatures or {},
        }


def build_receipt(
    consumer_id: str,
    provider_id: str,
    relay_id: str | None,
    pool_url: str,
    selected_address: str,
    channel: str,
    model: str,
    endpoint: str,
    input_value: Any,
    response: dict[str, Any],
    quote: PriceQuote,
    started_at: float,
    finished_at: float,
    consumer_public_key: str | None = None,
    provider_public_key: str | None = None,
    consumer_payment_address: str | None = None,
    provider_payment_address: str | None = None,
    bridge_usage: list[dict[str, Any]] | None = None,
    quality: dict[str, Any] | None = None,
    channel_pricing_hash: str | None = None,
    settlement_deadline: int = 0,
    signer: NodeIdentity | None = None,
) -> InferenceReceipt:
    response_signature = response.get("signature") if isinstance(response.get("signature"), dict) else None
    signatures = {"provider_response": response_signature} if response_signature else None
    receipt = InferenceReceipt(
        job_id=str(response.get("request_id") or uuid.uuid4().hex),
        consumer_id=consumer_id,
        provider_id=provider_id,
        consumer_public_key=consumer_public_key or response.get("consumer_public_key"),
        provider_public_key=provider_public_key or _response_provider_public_key(response),
        consumer_payment_address=consumer_payment_address,
        provider_payment_address=provider_payment_address or _response_provider_payment_address(response),
        bridge_usage=bridge_usage or [],
        quality=quality or _response_quality(response),
        relay_id=relay_id,
        pool_url=pool_url,
        selected_address=selected_address,
        channel=channel,
        model=model,
        endpoint=endpoint,
        request_hash=stable_hash(input_value),
        response_hash=stable_hash(response.get("output_text") or response.get("raw") or response),
        started_at=int(started_at),
        finished_at=int(finished_at),
        elapsed_ms=int((finished_at - started_at) * 1000),
        usage=response.get("usage") if isinstance(response.get("usage"), dict) else None,
        quote=quote,
        pricing_config_hash=quote.to_dict().get("pricing_config_hash"),
        channel_pricing_hash=channel_pricing_hash or quote.to_dict().get("pricing_config_hash"),
        settlement_deadline=int(settlement_deadline),
        signatures=signatures,
    )
    if signer is None:
        return receipt
    signed = sign_receipt(receipt.to_dict(), signer)
    return InferenceReceipt(
        **{
            **receipt.__dict__,
            "signatures": signed.get("signatures", {}),
        }
    )


def append_receipt(path: Path, receipt: InferenceReceipt) -> None:
    append_receipt_payload(path, receipt.to_dict())


def append_receipt_payload(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sign_receipt(receipt: dict[str, Any], signer: NodeIdentity, role: str = "operator") -> dict[str, Any]:
    unsigned = dict(receipt)
    signatures = dict(unsigned.pop("signatures", {}) or {})
    signed = sign_document(unsigned, signer.private_key, purpose=f"{RECEIPT_PURPOSE}.{role}")
    signatures[role] = signed["signature"]
    unsigned["signatures"] = signatures
    return unsigned


def build_acceptance(receipt: dict[str, Any], accepted_by: str, status: str = "accepted") -> dict[str, Any]:
    return {
        "acceptance_version": ACCEPTANCE_VERSION,
        "receipt_hash": receipt_hash(receipt),
        "job_id": str(receipt.get("job_id") or ""),
        "consumer_id": str(receipt.get("consumer_id") or ""),
        "provider_id": str(receipt.get("provider_id") or ""),
        "accepted_by": accepted_by,
        "status": status,
    }


def sign_acceptance(receipt: dict[str, Any], signer: NodeIdentity, accepted_by: str | None = None) -> dict[str, Any]:
    acceptance = build_acceptance(receipt, accepted_by=accepted_by or signer.peer_id)
    signed = sign_document(acceptance, signer.private_key, purpose=ACCEPTANCE_PURPOSE)
    receipt_with_acceptance = dict(receipt)
    receipt_with_acceptance["acceptance"] = {key: value for key, value in signed.items() if key != "signature"}
    receipt_with_acceptance["acceptance_signature"] = signed["signature"]
    receipt_with_acceptance["accepted_hash"] = acceptance_hash(receipt_with_acceptance["acceptance"])
    return receipt_with_acceptance


def verify_acceptance(receipt: dict[str, Any]) -> dict[str, Any]:
    acceptance = receipt.get("acceptance")
    signature = receipt.get("acceptance_signature")
    if not isinstance(acceptance, dict):
        raise ValueError("missing receipt acceptance")
    if not isinstance(signature, dict):
        raise ValueError("missing receipt acceptance signature")
    signed = dict(acceptance)
    signed["signature"] = signature
    verified = verify_document(signed, purpose=ACCEPTANCE_PURPOSE)
    if str(verified.get("receipt_hash") or "") != receipt_hash(_receipt_without_acceptance(receipt)):
        raise ValueError("acceptance receipt hash mismatch")
    expected_hash = acceptance_hash(verified)
    if str(receipt.get("accepted_hash") or "") not in {"", expected_hash}:
        raise ValueError("accepted_hash mismatch")
    return verified


def receipt_hash(receipt: dict[str, Any]) -> str:
    return "0x" + stable_hash(_receipt_without_acceptance(receipt))


def acceptance_hash(acceptance: dict[str, Any]) -> str:
    return "0x" + stable_hash(acceptance)


def verify_receipt_signature(receipt: dict[str, Any], role: str = "operator") -> dict[str, Any]:
    unsigned_receipt = _receipt_without_acceptance(receipt)
    signatures = unsigned_receipt.get("signatures")
    if not isinstance(signatures, dict) or role not in signatures:
        raise ValueError(f"missing {role} receipt signature")
    signed = {key: value for key, value in unsigned_receipt.items() if key != "signatures"}
    signed["signature"] = signatures[role]
    return verify_document(signed, purpose=f"{RECEIPT_PURPOSE}.{role}")


def _receipt_without_acceptance(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"acceptance", "acceptance_signature", "accepted_hash"}
    }


def _response_provider_public_key(response: dict[str, Any]) -> str | None:
    provider_signature = response.get("provider_signature")
    if isinstance(provider_signature, dict):
        return provider_signature.get("public_key")
    return None


def _response_provider_payment_address(response: dict[str, Any]) -> str | None:
    peer = response.get("peer")
    if isinstance(peer, dict):
        payment_address = peer.get("payment_address")
        if payment_address:
            return str(payment_address)
    return None


def _response_quality(response: dict[str, Any]) -> dict[str, Any] | None:
    quality = response.get("quality")
    if isinstance(quality, dict):
        return dict(quality)
    raw = response.get("raw")
    if isinstance(raw, dict) and isinstance(raw.get("mycomesh_quality"), dict):
        return dict(raw["mycomesh_quality"])
    return None
