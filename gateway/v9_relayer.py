from __future__ import annotations

from typing import Any, Mapping

from .chain import ChainError, normalize_address
from .chain_v9 import encode_signed_receipt, encode_signed_receipt_tuple, settlement_key_for, verify_signed_receipt
from .session_relayer import PreparedRelaySettlement, RelaySettlementError


def prepare_v9_relay_settlement(
    value: Mapping[str, Any], *, owner: str, expected_chain_id: int, expected_contract: str,
    expected_relay: str, expected_relay_signer: str,
) -> PreparedRelaySettlement:
    """Prepare an escrow transaction; owner MUST come from the verified key grant.

    No RPC is performed here. The owner is absent from the signed authorization,
    so callers must not source it from untrusted response/receipt JSON.
    """
    try:
        authorization, receipt, _ = verify_signed_receipt(value)
        chain_id = int(authorization["chain_id"])
        contract = normalize_address(str(authorization["settlement_contract"]))
        raw = authorization["authorization"]
        if chain_id != expected_chain_id:
            raise RelaySettlementError("V9 settlement chain does not match this Relay")
        if contract != normalize_address(expected_contract):
            raise RelaySettlementError("V9 settlement contract does not match this Relay")
        if receipt.relay != normalize_address(expected_relay):
            raise RelaySettlementError("V9 receipt payout does not match this Relay")
        if normalize_address(str(raw["relay_signer"])) != normalize_address(expected_relay_signer):
            raise RelaySettlementError("V9 receipt signer does not match this Relay")
        request_id = str(raw["request_id"])
        key_address = normalize_address(str(raw["key"]))
        key = settlement_key_for(owner, key_address, request_id)
        tuple_data = encode_signed_receipt_tuple(value)
    except RelaySettlementError:
        raise
    except (ChainError, KeyError, TypeError, ValueError) as exc:
        raise RelaySettlementError(f"invalid V9 signed receipt: {exc}") from exc
    payload = {
        "schema": "mycomesh.relay.settlement.v9", "protocol_version": 9,
        "signed_receipt": dict(value), "tuple_data": "0x" + tuple_data.hex(),
        "settlement_key": key, "owner": normalize_address(owner),
    }
    return PreparedRelaySettlement(
        key=f"v9:{chain_id}:{contract}:{key}", session_id=request_id,
        receipt_hash=receipt.response_hash, sequence=0, chain_id=chain_id,
        settlement_contract=contract, calldata=encode_signed_receipt(value), payload=payload,
    )
