"""Receipt-signer proof of control of a registered transport identity.

This binds two keys, not a machine or upstream model, and does not establish
that a payout wallet has authorized the signer on chain.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Mapping

from .chain import ChainError, evm_signature_from_json, keccak256, normalize_address, recover_evm_address, sign_evm_digest
from .identity import peer_id_from_public_key

SCHEMA = "mycomesh.provider-identity-binding.v1"


def _payload(peer: Mapping[str, Any], audience: str) -> dict[str, Any]:
    settlement = peer.get("settlement")
    if not isinstance(settlement, Mapping) or int(settlement.get("version", 0)) not in {7, 8, 9, 10}:
        raise ValueError("identity binding requires V7/V8/V9/V10 deployment")
    public_key = str(peer.get("public_key") or "")
    if peer.get("peer_id") != peer_id_from_public_key(public_key):
        raise ValueError("identity binding peer/public key mismatch")
    if not audience or not isinstance(peer.get("challenge"), str) or not peer["challenge"]:
        raise ValueError("identity binding requires registration challenge and audience")
    signer = settlement.get("provider_signer") if int(settlement["version"]) in {8, 9, 10} else peer.get("payment_address")
    return {"schema": SCHEMA, "peer_id": peer["peer_id"], "public_key": public_key,
            "challenge": peer["challenge"], "audience": audience,
            "version": int(settlement["version"]), "chain_id": int(settlement["chain_id"]),
            "contract": normalize_address(str(settlement["contract"])),
            "provider_signer": normalize_address(str(signer)),
            "provider": normalize_address(str(peer.get("payment_address")))}


def _digest(payload: Mapping[str, Any]) -> bytes:
    return keccak256((SCHEMA + ":" + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode())


def build_provider_identity_binding(peer: Mapping[str, Any], *, audience: str, private_key: str) -> dict[str, Any]:
    payload = _payload(peer, audience)
    return {"schema": SCHEMA, "signature": asdict(sign_evm_digest(private_key, _digest(payload)))}


def verify_provider_identity_binding(peer: Mapping[str, Any], *, audience: str) -> str:
    proof = peer.get("settlement_identity_binding")
    if not isinstance(proof, Mapping) or proof.get("schema") != SCHEMA:
        raise ValueError("Provider receipt-signer identity binding is required")
    payload = _payload(peer, audience)
    try:
        signer = recover_evm_address(_digest(payload), evm_signature_from_json(proof.get("signature")))
    except (ChainError, TypeError, ValueError) as exc:
        raise ValueError("invalid Provider receipt-signer identity binding") from exc
    if signer != payload["provider_signer"]:
        raise ValueError("Provider receipt-signer identity binding signature mismatch")
    return signer
