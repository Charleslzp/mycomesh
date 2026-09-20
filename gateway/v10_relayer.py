"""Reserved V10 receipts: immutable channel context, no post-execution Relay signature."""
from __future__ import annotations

from typing import Any, Mapping

from . import chain_v10
from .chain import ChainError, normalize_address
from .identity import peer_id_from_public_key, verify_document
from .relay_integrity import (RelayIntegrityError, PROVIDER_RESPONSE_PURPOSE,
    provider_response_hash, _validated_usage, _extract_output_text)
from .session_relayer import PreparedRelaySettlement, RelaySettlementError


def prepare_v10_relay_settlement(value: Mapping[str, Any], *, channel: Mapping[str, Any],
        expected_chain_id: int, expected_contract: str) -> PreparedRelaySettlement:
    """Channel MUST be obtained from canonical chain state, never receipt JSON.

    Works for a Relay or the Provider's independent gas submitter. The caller
    address does not change the pre-execution dispatch or any receipt signature.
    """
    try:
        authorization, receipt, _ = chain_v10.verify_signed_receipt(value, channel=channel)
        contract = normalize_address(authorization['settlement_contract'])
        chain_id = authorization['chain_id']
        if chain_id != expected_chain_id or contract != normalize_address(expected_contract):
            raise ChainError('V10 receipt deployment mismatch')
        raw = authorization['authorization']
        key = chain_v10.settlement_key_for(raw['channel_id'], raw['request_id'])
        tuple_data = chain_v10.encode_signed_receipt_tuple(value)
        payload = {'schema': 'mycomesh.relay.settlement.v10', 'protocol_version': 10,
            'signed_receipt': dict(value), 'tuple_data': '0x'+tuple_data.hex(),
            'settlement_key': key, 'channel_id': raw['channel_id'],
            'owner': normalize_address(channel['consumer_owner']),
            'provider': normalize_address(channel['provider_owner']),
            'channel': {name: channel[name] for name, _ in chain_v10.OPEN_FIELDS}}
        return PreparedRelaySettlement(key=f'v10:{chain_id}:{contract}:{key}',
            session_id=raw['request_id'], receipt_hash=receipt.response_hash, sequence=0,
            chain_id=chain_id, settlement_contract=contract,
            calldata=chain_v10.encode_signed_batch_tuples([tuple_data]), payload=payload)
    except (ChainError, KeyError, TypeError, ValueError) as exc:
        raise RelaySettlementError(f'invalid V10 signed receipt: {exc}', error_code='invalid_receipt') from exc


def validate_v10_response(response: Mapping[str, Any], *, authorization: Mapping[str, Any],
        dispatch: Mapping[str, Any], channel: Mapping[str, Any], request: Mapping[str, Any],
        provider_public_key: str | None, response_audience: str) -> Mapping[str, Any]:
    """Authenticate the exact Provider, request, dispatch, full body and usage."""
    try:
        if provider_public_key:
            if (response.get('signature') or {}).get('public_key') != provider_public_key:
                raise ValueError('V10 response transport signer mismatch')
            verify_document(dict(response), purpose=PROVIDER_RESPONSE_PURPOSE,
                audience=response_audience, max_age_seconds=10800)
            peer = response.get('peer') or {}
            if peer.get('public_key') != provider_public_key or peer.get('peer_id') != peer_id_from_public_key(provider_public_key):
                raise ValueError('V10 response peer binding mismatch')
        signed = response.get('settlement_v10')
        actual, receipt, _ = chain_v10.verify_signed_receipt(signed, channel=channel)
        if actual != authorization or signed['dispatch'] != dispatch:
            raise ValueError('V10 receipt does not bind dispatched authorization')
        if response.get('ok') is not True or any(response.get(k) != request[k] for k in ('request_id','endpoint','model')):
            raise ValueError('V10 response request binding mismatch')
        if receipt.response_hash != provider_response_hash(response):
            raise ValueError('V10 response commitment mismatch')
        raw, usage, text = response.get('raw'), response.get('usage'), response.get('output_text')
        if not isinstance(raw, Mapping) or not isinstance(text, str) or raw.get('usage') != usage:
            raise ValueError('V10 raw body/usage mismatch')
        if _extract_output_text(request['endpoint'], raw) != text:
            raise ValueError('V10 raw body/output mismatch')
        input_tokens, output_tokens = _validated_usage(usage)
        if (receipt.input_tokens != input_tokens or receipt.output_tokens != output_tokens
                or output_tokens > request['max_output_tokens']):
            raise ValueError('V10 receipt usage mismatch')
        return signed
    except (ChainError, KeyError, TypeError, ValueError) as exc:
        raise RelayIntegrityError('v10_response_integrity', str(exc)) from exc
