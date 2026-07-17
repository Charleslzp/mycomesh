from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .chain import ChainError, call_contract, channel_to_hash, normalize_address, normalize_bytes32, rpc_call, rpc_int
from .chain_v3 import EIP1271SignatureRejected, verify_eip1271_signature
from .channel_policy import require_enabled_channel_binding
from .reservation import (
    ReservationError,
    evm_session_authorization_digest,
    validate_evm_session_authorization,
    verify_eoa_session_authorization,
)


RELAY_V3_ADMISSION_SCHEMA = "mycomesh.relay.consumer-admission.v1"
MAX_EIP1271_SIGNATURE_BYTES = 16 * 1024


class ConsumerAdmissionError(RuntimeError):
    pass


@dataclass(frozen=True)
class RelayV3AdmissionConfig:
    rpc_url: str
    chain_id: int
    settlement_contract: str
    confirmations: int = 6
    timeout_seconds: float = 20.0

    def __post_init__(self) -> None:
        raw_rpc_url = str(self.rpc_url or "")
        if not raw_rpc_url or raw_rpc_url != raw_rpc_url.strip():
            raise ConsumerAdmissionError(
                "Relay V3 admission RPC URL must be non-empty without whitespace"
            )
        try:
            parsed_rpc_url = urlsplit(raw_rpc_url)
            parsed_rpc_url.port
        except ValueError as exc:
            raise ConsumerAdmissionError("Relay V3 admission RPC URL is invalid") from exc
        if (
            parsed_rpc_url.scheme != "https"
            or not parsed_rpc_url.hostname
            or parsed_rpc_url.username is not None
            or parsed_rpc_url.password is not None
            or parsed_rpc_url.fragment
        ):
            raise ConsumerAdmissionError(
                "Relay V3 admission RPC URL must use HTTPS without credentials or fragments"
            )
        if type(self.chain_id) is not int or self.chain_id <= 0:
            raise ConsumerAdmissionError("Relay V3 admission chain_id must be positive")
        try:
            normalize_address(self.settlement_contract)
        except ChainError as exc:
            raise ConsumerAdmissionError(f"Relay V3 admission settlement contract is invalid: {exc}") from exc
        if type(self.confirmations) is not int or self.confirmations < 1:
            raise ConsumerAdmissionError("Relay V3 admission confirmations must be positive")
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise ConsumerAdmissionError("Relay V3 admission timeout must be positive")


def verify_relay_v3_admission(
    admission: Any,
    *,
    sender_public_key: str,
    provider_peer: dict[str, Any],
    config: RelayV3AdmissionConfig,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(admission, dict) or set(admission) != {"schema", "authorization"}:
        raise ConsumerAdmissionError("Relay V3 admission must contain schema and authorization")
    if admission.get("schema") != RELAY_V3_ADMISSION_SCHEMA:
        raise ConsumerAdmissionError("unsupported Relay V3 admission schema")
    current_time = int(now if now is not None else time.time())
    peer = _provider_binding(provider_peer, config)
    try:
        authorization = validate_evm_session_authorization(
            admission.get("authorization"),
            chain_id=config.chain_id,
            settlement_contract=normalize_address(config.settlement_contract),
            provider_id=peer["peer_id"],
            provider_payment_address=peer["payment_address"],
            channel=peer["channel"],
            pricing_hash=peer["pricing_hash"],
            pricing_version=peer["pricing_version"],
            provider_fallback_allowed=False,
            session_public_key=str(sender_public_key or "").lower(),
            now=current_time,
        )
    except (ReservationError, TypeError, ValueError) as exc:
        raise ConsumerAdmissionError(f"invalid Relay V3 session authorization: {exc}") from exc

    confirmed_block = _confirmed_block(config)
    _verify_wallet_authorization(authorization, config=config, block_tag=confirmed_block)
    for label, block_tag in (("confirmed", confirmed_block), ("latest", "latest")):
        reservation = _read_reservation(
            config,
            str(authorization["onchain_reservation_id"]),
            block_tag=block_tag,
        )
        _assert_reservation(reservation, authorization, label=label, now=current_time)
    return authorization


def _provider_binding(peer: Any, config: RelayV3AdmissionConfig) -> dict[str, Any]:
    if not isinstance(peer, dict):
        raise ConsumerAdmissionError("Relay Provider descriptor is required")
    settlement = peer.get("settlement")
    if not isinstance(settlement, dict):
        raise ConsumerAdmissionError("Relay Provider is missing Settlement V3 capabilities")
    try:
        version = int(settlement.get("version"))
        chain_id = int(settlement.get("chain_id"))
        contract = normalize_address(str(settlement.get("contract") or ""))
        pricing_version = int(settlement.get("pricing_version"))
        pricing_hash = normalize_bytes32(str(settlement.get("pricing_hash") or ""))
        payment_address = normalize_address(str(peer.get("payment_address") or ""))
    except (ChainError, TypeError, ValueError) as exc:
        raise ConsumerAdmissionError(f"Relay Provider Settlement V3 capabilities are invalid: {exc}") from exc
    peer_id = str(peer.get("peer_id") or "").strip()
    channel = str(peer.get("channel") or "").strip()
    if not peer_id or not channel:
        raise ConsumerAdmissionError("Relay Provider peer_id and channel are required")
    try:
        require_enabled_channel_binding(
            network_id=peer.get("network_id"),
            channel_id=peer.get("channel_id"),
            channel=channel,
            backend_policy=peer.get("backend_policy"),
            label="Relay Provider",
        )
    except ValueError as exc:
        raise ConsumerAdmissionError(str(exc)) from exc
    if (
        version != 3
        or chain_id != config.chain_id
        or contract != normalize_address(config.settlement_contract)
        or pricing_version <= 0
    ):
        raise ConsumerAdmissionError("Relay Provider does not match the configured V3 deployment")
    return {
        "peer_id": peer_id,
        "channel": channel,
        "payment_address": payment_address,
        "pricing_version": pricing_version,
        "pricing_hash": pricing_hash,
    }


def _confirmed_block(config: RelayV3AdmissionConfig) -> int:
    try:
        actual_chain_id = rpc_int(config.rpc_url, "eth_chainId", [], config.timeout_seconds)
        if actual_chain_id != config.chain_id:
            raise ConsumerAdmissionError("Relay V3 admission RPC chain_id mismatch")
        latest = rpc_int(config.rpc_url, "eth_blockNumber", [], config.timeout_seconds)
    except ConsumerAdmissionError:
        raise
    except (ChainError, TypeError, ValueError) as exc:
        raise ConsumerAdmissionError(f"failed to read Relay V3 admission chain state: {exc}") from exc
    if latest < config.confirmations:
        raise ConsumerAdmissionError("Relay V3 admission chain is below the confirmation depth")
    return latest - config.confirmations


def _verify_wallet_authorization(
    authorization: dict[str, Any],
    *,
    config: RelayV3AdmissionConfig,
    block_tag: int,
) -> None:
    consumer = str(authorization["consumer_payment_address"])
    try:
        code = rpc_call(
            config.rpc_url,
            "eth_getCode",
            [consumer, hex(block_tag)],
            config.timeout_seconds,
        )
    except ChainError as exc:
        raise ConsumerAdmissionError(f"failed to identify Relay Consumer wallet type: {exc}") from exc
    if not _has_contract_code(code):
        try:
            verify_eoa_session_authorization(authorization)
        except ReservationError as exc:
            raise ConsumerAdmissionError(f"Relay Consumer wallet signature was rejected: {exc}") from exc
        return

    signature = str(authorization.get("wallet_signature") or "")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", signature) or len(signature[2:]) % 2:
        raise ConsumerAdmissionError("Relay Consumer contract-wallet signature is malformed")
    signature_bytes = bytes.fromhex(signature[2:])
    if not signature_bytes or len(signature_bytes) > MAX_EIP1271_SIGNATURE_BYTES:
        raise ConsumerAdmissionError("Relay Consumer contract-wallet signature size is invalid")
    try:
        verify_eip1271_signature(
            rpc_url=config.rpc_url,
            signer=consumer,
            digest=evm_session_authorization_digest(authorization),
            signature=signature_bytes,
            caller=config.settlement_contract,
            timeout=config.timeout_seconds,
        )
    except EIP1271SignatureRejected as exc:
        raise ConsumerAdmissionError(f"Relay Consumer contract-wallet signature was rejected: {exc}") from exc
    except ChainError as exc:
        raise ConsumerAdmissionError(f"Relay Consumer contract-wallet verification failed: {exc}") from exc


def _has_contract_code(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ConsumerAdmissionError(f"unexpected eth_getCode response: {value!r}")
    encoded = value[2:]
    if len(encoded) % 2 or re.fullmatch(r"[0-9a-fA-F]*", encoded) is None:
        raise ConsumerAdmissionError(f"unexpected eth_getCode response: {value!r}")
    code = bytes.fromhex(encoded)
    return bool(code and any(code))


def _read_reservation(
    config: RelayV3AdmissionConfig,
    reservation_id: str,
    *,
    block_tag: int | str,
) -> dict[str, Any]:
    try:
        output = call_contract(
            config.rpc_url,
            config.settlement_contract,
            "reservations(bytes32)",
            [normalize_bytes32(reservation_id)],
            timeout=config.timeout_seconds,
            block_tag=block_tag,
        )
        return _decode_reservation(output)
    except (ChainError, TypeError, ValueError) as exc:
        raise ConsumerAdmissionError(f"failed to read Relay V3 reservation: {exc}") from exc


def _decode_reservation(output: Any) -> dict[str, Any]:
    raw = str(output or "")
    if not raw.startswith("0x") or len(raw) != 2 + 9 * 64:
        raise ConsumerAdmissionError("Settlement V3 reservation response is malformed")
    words = [raw[2 + index * 64 : 2 + (index + 1) * 64] for index in range(9)]
    closed = int(words[7], 16)
    fallback = int(words[8], 16)
    if closed not in {0, 1} or fallback not in {0, 1}:
        raise ConsumerAdmissionError("Settlement V3 reservation booleans are malformed")
    return {
        "consumer_payment_address": normalize_address("0x" + words[0][-40:]),
        "provider_payment_address": normalize_address("0x" + words[1][-40:]),
        "channel_hash": normalize_bytes32("0x" + words[2]),
        "request_hash": normalize_bytes32("0x" + words[3]),
        "pricing_version": int(words[4], 16),
        "expires_at": int(words[5], 16),
        "amount_units": int(words[6], 16),
        "closed": bool(closed),
        "provider_fallback_allowed": bool(fallback),
    }


def _assert_reservation(
    reservation: dict[str, Any],
    authorization: dict[str, Any],
    *,
    label: str,
    now: int,
) -> None:
    expected = {
        "consumer_payment_address": normalize_address(str(authorization["consumer_payment_address"])),
        "provider_payment_address": normalize_address(str(authorization["provider_payment_address"])),
        "channel_hash": normalize_bytes32(channel_to_hash(str(authorization["channel"]))),
        "request_hash": normalize_bytes32(str(authorization["request_hash"])),
        "pricing_version": int(authorization["pricing_version"]),
        "expires_at": int(authorization["expires_at"]),
        "amount_units": int(authorization["max_fee_units"]),
        "closed": False,
        "provider_fallback_allowed": False,
    }
    if reservation["consumer_payment_address"] == "0x" + "0" * 40:
        raise ConsumerAdmissionError(f"Relay V3 reservation is absent at {label} state")
    for field, expected_value in expected.items():
        if reservation[field] != expected_value:
            raise ConsumerAdmissionError(f"Relay V3 reservation {field} mismatch at {label} state")
    if reservation["amount_units"] <= 0:
        raise ConsumerAdmissionError(f"Relay V3 reservation amount is not positive at {label} state")
    if reservation["expires_at"] <= now:
        raise ConsumerAdmissionError(f"Relay V3 reservation expired at {label} state")
