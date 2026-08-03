from __future__ import annotations

from typing import Any, Mapping

from .chain import ChainError, normalize_address
from .chain_v7 import (
    encode_signed_receipt,
    encode_signed_receipt_tuple,
    verify_signed_receipt,
)
from .session_relayer import PreparedRelaySettlement, RelaySettlementError


def prepare_v7_relay_settlement(
    value: Mapping[str, Any],
    *,
    expected_chain_id: int,
    expected_contract: str,
    expected_relay: str,
    expected_relay_signer: str,
) -> PreparedRelaySettlement:
    try:
        authorization, receipt, _ = verify_signed_receipt(value)
        chain_id = int(authorization["chain_id"])
        contract = normalize_address(str(authorization["settlement_contract"]))
        raw = authorization["authorization"]
        if chain_id != int(expected_chain_id):
            raise RelaySettlementError("V7 settlement chain does not match this Relay")
        if contract != normalize_address(expected_contract):
            raise RelaySettlementError("V7 settlement contract does not match this Relay")
        if receipt.relay != normalize_address(expected_relay):
            raise RelaySettlementError("V7 receipt payout does not match this Relay")
        if normalize_address(str(raw["relay_signer"])) != normalize_address(expected_relay_signer):
            raise RelaySettlementError("V7 receipt signer does not match this Relay")
        tuple_data = encode_signed_receipt_tuple(value)
        request_id = str(raw["request_id"])
        key_address = normalize_address(str(raw["key"]))
    except RelaySettlementError:
        raise
    except (ChainError, KeyError, TypeError, ValueError) as exc:
        raise RelaySettlementError(f"invalid V7 signed receipt: {exc}") from exc
    payload = {
        "schema": "mycomesh.relay.settlement.v7",
        "protocol_version": 7,
        "signed_receipt": dict(value),
        "tuple_data": "0x" + tuple_data.hex(),
    }
    return PreparedRelaySettlement(
        key=f"v7:{key_address}:{request_id.lower()}",
        session_id=request_id,
        receipt_hash=receipt.response_hash,
        sequence=0,
        chain_id=chain_id,
        settlement_contract=contract,
        calldata=encode_signed_receipt(value),
        payload=payload,
    )
