from __future__ import annotations

"""V9 escrow settlement protocol.

V9 has its own EIP-712 domain and wire schemas. No helper in this module
deploys a contract, sends a transaction, reads a private-key file, or funds
an account. Read-only RPC calls accept an explicit pinned block identifier.
Distinct adjudicator addresses are necessary, not proof of independent owners.
"""

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .chain import (
    ChainError, ZERO_ADDRESS, abi_encode_arg, keccak256, normalize_address,
    normalize_bytes32, parse_private_key, private_key_to_address, SECP256K1_N,
    recover_evm_address, rpc_call, sign_evm_digest,
)
from .chain_v4 import _dynamic_bytes, _signature_bytes
from .chain_v8 import (
    DOMAIN_TYPE, AUTHORIZATION_TYPE, RECEIPT_TYPE, SETTLE_SIGNATURE, BATCH_SIGNATURE,
    PaymentAuthorization, UsageReceipt, payment_private_key,
    payment_key_address, _authorization_from_payload, _raw_signature as _v8_raw_signature, _evm_signature,
)

ARTIFACT = "out/MycoSettlementV9.sol/MycoSettlementV9.json"
DEFAULT_DEPLOYMENT = "deployments/sepolia-myco-v9.json"
DEFAULT_MYCO_V9_DEPLOYMENT_PATH = DEFAULT_DEPLOYMENT
AUTH_SCHEMA = "mycomesh.x402.myco-credit-v3"
PROVIDER_SCHEMA = "mycomesh.settlement.v9.provider.v1"
SIGNED_SCHEMA = "mycomesh.settlement.v9.signed.v1"
LEGACY_MAX_AUTHORIZATION_TTL = 3600
MAX_AUTHORIZATION_TTL = 10800
DEFAULT_AUTHORIZATION_DEADLINE_SECONDS = 900
AUTHORIZATION_CLOCK_SKEW_SECONDS = 300
ZERO_BYTES32 = "0x" + "00" * 32
STATUS_NAMES = ("none", "pending", "disputed", "released", "confirmed", "dismissed", "timed_out")
INDEPENDENT_COMMITTEE = "independent_users"
CONTROLLED_TEST_COMMITTEE = "controlled_test"
CONTROLLED_TEST_CHAIN_IDS = frozenset((1337, 31337, 11155111))
RECEIPT_ESCROWED_TOPIC = "0x" + keccak256(b"ReceiptEscrowed(bytes32,bytes32,address,address,uint256,uint256)").hex()

def domain_separator(*, chain_id: int, verifying_contract: str) -> str:
    encoded = b"".join(
        [
            keccak256(DOMAIN_TYPE.encode()),
            keccak256(b"MycoMesh Settlement"),
            keccak256(b"9"),
            abi_encode_arg(str(_positive_uint(chain_id, "chain_id"))),
            abi_encode_arg(normalize_address(verifying_contract)),
        ]
    )
    return "0x" + keccak256(encoded).hex()


def authorization_struct_hash(value: PaymentAuthorization) -> str:
    return "0x" + keccak256(
        keccak256(AUTHORIZATION_TYPE.encode())
        + b"".join(abi_encode_arg(item) for item in value.abi_args())
    ).hex()


def receipt_struct_hash(value: UsageReceipt) -> str:
    return "0x" + keccak256(
        keccak256(RECEIPT_TYPE.encode())
        + b"".join(abi_encode_arg(item) for item in value.abi_args())
    ).hex()


def authorization_digest(value: PaymentAuthorization, *, chain_id: int, verifying_contract: str) -> bytes:
    return _typed_digest(authorization_struct_hash(value), chain_id=chain_id, contract=verifying_contract)


def receipt_digest(value: UsageReceipt, *, chain_id: int, verifying_contract: str) -> bytes:
    return _typed_digest(receipt_struct_hash(value), chain_id=chain_id, contract=verifying_contract)


def build_authorization(
    *,
    payment_key: str,
    chain_id: int,
    settlement_contract: str,
    request_id: str,
    request_hash: str,
    relay: str,
    relay_signer: str,
    channel_hash: str,
    pricing_version: int,
    pricing_hash: str,
    max_fee: int,
    issued_at: int | None = None,
    deadline: int | None = None,
    max_authorization_ttl: int = LEGACY_MAX_AUTHORIZATION_TTL,
) -> dict[str, Any]:
    private_key = payment_private_key(payment_key)
    now = _positive_uint(int(time.time()) if issued_at is None else issued_at, "issued_at", bits=64)
    expires = _positive_uint(deadline if deadline is not None else now + 900, "deadline", bits=64)
    authorization = PaymentAuthorization(
        request_id=normalize_bytes32(request_id),
        request_hash=normalize_bytes32(request_hash),
        key=payment_key_address(private_key),
        relay=_nonzero_address(relay, "relay"),
        relay_signer=_nonzero_address(relay_signer, "relay_signer"),
        channel=normalize_bytes32(channel_hash),
        pricing_version=_positive_uint(pricing_version, "pricing_version", bits=64),
        pricing_hash=normalize_bytes32(pricing_hash),
        max_fee=_positive_uint(max_fee, "max_fee"),
        issued_at=_positive_uint(now, "issued_at", bits=64),
        deadline=_positive_uint(expires, "deadline", bits=64),
    )
    if authorization.request_id == "0x" + "0" * 64:
        raise ChainError("V9 request_id cannot be zero")
    if authorization.request_hash == "0x" + "0" * 64:
        raise ChainError("V9 request_hash cannot be zero")
    if authorization.channel == "0x" + "0" * 64:
        raise ChainError("V9 channel cannot be zero")
    if authorization.pricing_hash == "0x" + "0" * 64:
        raise ChainError("V9 pricing_hash cannot be zero")
    if type(max_authorization_ttl) is not int or max_authorization_ttl not in (LEGACY_MAX_AUTHORIZATION_TTL, MAX_AUTHORIZATION_TTL):
        raise ChainError("V9 unsupported authorization TTL limit")
    if authorization.deadline <= authorization.issued_at or authorization.deadline - authorization.issued_at > max_authorization_ttl:
        raise ChainError(f"V9 authorization lifetime must be between 1 and {max_authorization_ttl} seconds")
    digest = authorization_digest(authorization, chain_id=chain_id, verifying_contract=settlement_contract)
    signature = _signature_bytes(sign_evm_digest(private_key, digest), "payment key")
    return {
        "schema": AUTH_SCHEMA,
        "chain_id": _positive_uint(chain_id, "chain_id"),
        "settlement_contract": _nonzero_address(settlement_contract, "settlement_contract"),
        "authorization": authorization.to_payload(),
        "authorization_hash": authorization_struct_hash(authorization),
        "authorization_digest": "0x" + digest.hex(),
        "key_signature": "0x" + signature.hex(),
    }


def verify_authorization(
    value: Any,
    *,
    expected_chain_id: int | None = None,
    expected_contract: str | None = None,
    expected_relay: str | None = None,
    expected_relay_signer: str | None = None,
    expected_request_id: str | None = None,
    expected_request_hash: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema") != AUTH_SCHEMA:
        raise ChainError("unsupported V9 payment authorization")
    chain_id = _positive_uint(value.get("chain_id"), "chain_id")
    contract = _nonzero_address(value.get("settlement_contract"), "settlement_contract")
    raw = value.get("authorization")
    if not isinstance(raw, Mapping):
        raise ChainError("V9 payment authorization is missing")
    authorization = PaymentAuthorization(
        request_id=normalize_bytes32(str(raw.get("request_id") or "")),
        request_hash=normalize_bytes32(str(raw.get("request_hash") or "")),
        key=_nonzero_address(raw.get("key"), "key"),
        relay=_nonzero_address(raw.get("relay"), "relay"),
        relay_signer=_nonzero_address(raw.get("relay_signer"), "relay_signer"),
        channel=normalize_bytes32(str(raw.get("channel") or "")),
        pricing_version=_positive_uint(raw.get("pricing_version"), "pricing_version", bits=64),
        pricing_hash=normalize_bytes32(str(raw.get("pricing_hash") or "")),
        max_fee=_positive_uint(raw.get("max_fee"), "max_fee"),
        issued_at=_positive_uint(raw.get("issued_at"), "issued_at", bits=64),
        deadline=_positive_uint(raw.get("deadline"), "deadline", bits=64),
    )
    if authorization.request_id == "0x" + "0" * 64:
        raise ChainError("V9 request_id cannot be zero")
    if authorization.request_hash == "0x" + "0" * 64:
        raise ChainError("V9 request_hash cannot be zero")
    if authorization.channel == "0x" + "0" * 64:
        raise ChainError("V9 channel cannot be zero")
    if authorization.pricing_hash == "0x" + "0" * 64:
        raise ChainError("V9 pricing_hash cannot be zero")
    current = _uint(int(time.time()) if now is None else now, "now")
    if authorization.issued_at > current or authorization.deadline < current:
        raise ChainError("V9 payment authorization is outside its time window")
    if authorization.deadline <= authorization.issued_at or authorization.deadline - authorization.issued_at > MAX_AUTHORIZATION_TTL:
        raise ChainError("V9 payment authorization lifetime is invalid")
    _expect(expected_chain_id, chain_id, "chain_id")
    _expect_address(expected_contract, contract, "settlement_contract")
    _expect_address(expected_relay, authorization.relay, "relay")
    _expect_address(expected_relay_signer, authorization.relay_signer, "relay_signer")
    _expect_bytes32(expected_request_id, authorization.request_id, "request_id")
    _expect_bytes32(expected_request_hash, authorization.request_hash, "request_hash")
    struct_hash = authorization_struct_hash(authorization)
    if normalize_bytes32(str(value.get("authorization_hash") or "")) != struct_hash:
        raise ChainError("V9 authorization hash mismatch")
    digest = authorization_digest(authorization, chain_id=chain_id, verifying_contract=contract)
    if normalize_bytes32(str(value.get("authorization_digest") or "")) != "0x" + digest.hex():
        raise ChainError("V9 authorization digest mismatch")
    signature = _raw_signature(value.get("key_signature"), "payment key")
    if recover_evm_address(digest, _evm_signature(signature)) != authorization.key:
        raise ChainError("V9 payment key signature mismatch")
    return {**dict(value), "chain_id": chain_id, "settlement_contract": contract,
            "authorization": authorization.to_payload()}


def build_provider_receipt(
    *,
    provider: str,
    provider_private_key: str,
    authorization_payload: Mapping[str, Any],
    response_hash: str,
    relay: str,
    pool: str = ZERO_ADDRESS,
    input_tokens: int,
    output_tokens: int,
    actual_fee: int,
) -> dict[str, Any]:
    verified = verify_authorization(authorization_payload, expected_relay=relay)
    chain_id = int(verified["chain_id"])
    contract = str(verified["settlement_contract"])
    provider_signer = private_key_to_address(parse_private_key(provider_private_key))
    receipt = UsageReceipt(
        authorization_hash=normalize_bytes32(str(verified["authorization_hash"])),
        response_hash=normalize_bytes32(response_hash),
        provider=_nonzero_address(provider, "provider"),
        provider_signer=provider_signer,
        relay=_nonzero_address(relay, "relay"),
        pool=normalize_address(pool),
        input_tokens=_uint(input_tokens, "input_tokens"),
        output_tokens=_uint(output_tokens, "output_tokens"),
        actual_fee=_positive_uint(actual_fee, "actual_fee"),
    )
    _validate_receipt_binding(receipt, verified)
    digest = receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    signature = _signature_bytes(sign_evm_digest(provider_private_key, digest), "provider")
    return {
        "schema": PROVIDER_SCHEMA,
        "chain_id": chain_id,
        "settlement_contract": contract,
        "authorization": dict(verified),
        "receipt": receipt.to_payload(),
        "receipt_digest": "0x" + digest.hex(),
        "provider_signature": "0x" + signature.hex(),
    }


def finalize_relay_receipt(value: Mapping[str, Any], *, relay_private_key: str) -> dict[str, Any]:
    authorization, receipt, provider_signature, chain_id, contract = verify_provider_receipt(value)
    relay = private_key_to_address(parse_private_key(relay_private_key))
    relay_signer = normalize_address(str(authorization["authorization"]["relay_signer"]))
    if relay != relay_signer:
        raise ChainError("Relay key does not match V9 authorization relay signer")
    digest = receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    relay_signature = _signature_bytes(sign_evm_digest(relay_private_key, digest), "relay")
    return {
        "schema": SIGNED_SCHEMA,
        "chain_id": chain_id,
        "settlement_contract": contract,
        "authorization": authorization,
        "receipt": receipt.to_payload(),
        "key_signature": str(authorization["key_signature"]),
        "provider_signature": "0x" + provider_signature.hex(),
        "relay_signature": "0x" + relay_signature.hex(),
    }


def verify_provider_receipt(
    value: Mapping[str, Any], *, now: int | None = None,
) -> tuple[dict[str, Any], UsageReceipt, bytes, int, str]:
    if not isinstance(value, Mapping) or value.get("schema") != PROVIDER_SCHEMA:
        raise ChainError("unsupported V9 Provider receipt")
    authorization = verify_authorization(value.get("authorization"), now=now)
    chain_id = int(authorization["chain_id"])
    contract = str(authorization["settlement_contract"])
    _validate_outer_deployment(value, authorization)
    raw = value.get("receipt")
    receipt = _receipt_from_payload(raw)
    if receipt.authorization_hash != authorization_struct_hash(_authorization_from_payload(authorization["authorization"])):
        raise ChainError("V9 Provider receipt authorization mismatch")
    digest = receipt_digest(receipt, chain_id=chain_id, verifying_contract=contract)
    if normalize_bytes32(str(value.get("receipt_digest") or "")) != "0x" + digest.hex():
        raise ChainError("V9 Provider receipt digest mismatch")
    signature = _raw_signature(value.get("provider_signature"), "provider")
    if recover_evm_address(digest, _evm_signature(signature)) != receipt.provider_signer:
        raise ChainError("V9 Provider signature mismatch")
    _validate_receipt_binding(receipt, authorization)
    return authorization, receipt, signature, chain_id, contract


def encode_signed_receipt(value: Mapping[str, Any]) -> str:
    tuple_value = encode_signed_receipt_tuple(value)
    return "0x" + (keccak256(SETTLE_SIGNATURE.encode())[:4] + (32).to_bytes(32, "big") + tuple_value).hex()


def encode_signed_receipt_tuple(value: Mapping[str, Any]) -> bytes:
    authorization_payload, receipt, signatures = verify_signed_receipt(value)
    authorization = _authorization_from_payload(authorization_payload["authorization"])
    head_words = len(authorization.abi_args()) + len(receipt.abi_args()) + 3
    head_size = head_words * 32
    tails = [_dynamic_bytes(item) for item in signatures]
    offsets: list[bytes] = []
    offset = head_size
    for tail in tails:
        offsets.append(offset.to_bytes(32, "big"))
        offset += len(tail)
    return b"".join(
        [
            *(abi_encode_arg(item) for item in authorization.abi_args()),
            *(abi_encode_arg(item) for item in receipt.abi_args()),
            *offsets,
            *tails,
        ]
    )


def encode_signed_batch(values: Sequence[Mapping[str, Any]]) -> str:
    tuples = [encode_signed_receipt_tuple(item) for item in values]
    if not tuples or len(tuples) > 32:
        raise ChainError("V9 batch must contain between 1 and 32 receipts")
    body = len(tuples).to_bytes(32, "big")
    offset = len(tuples) * 32
    for item in tuples:
        body += offset.to_bytes(32, "big")
        offset += len(item)
    body += b"".join(tuples)
    return "0x" + (keccak256(BATCH_SIGNATURE.encode())[:4] + (32).to_bytes(32, "big") + body).hex()


def encode_signed_batch_tuples(tuples: Sequence[bytes]) -> str:
    if not tuples or len(tuples) > 32:
        raise ChainError("V9 batch must contain between 1 and 32 receipts")
    body = len(tuples).to_bytes(32, "big")
    offset = len(tuples) * 32
    for item in tuples:
        body += offset.to_bytes(32, "big")
        offset += len(item)
    body += b"".join(tuples)
    return "0x" + (keccak256(BATCH_SIGNATURE.encode())[:4] + (32).to_bytes(32, "big") + body).hex()


def verify_signed_receipt(
    value: Mapping[str, Any],
    *,
    now: int | None = None,
) -> tuple[dict[str, Any], UsageReceipt, list[bytes]]:
    if not isinstance(value, Mapping) or value.get("schema") != SIGNED_SCHEMA:
        raise ChainError("unsupported signed V9 receipt")
    authorization = verify_authorization(value.get("authorization"), now=now)
    _validate_outer_deployment(value, authorization)
    receipt = _receipt_from_payload(value.get("receipt"))
    _validate_receipt_binding(receipt, authorization)
    auth_struct = _authorization_from_payload(authorization["authorization"])
    if receipt.authorization_hash != authorization_struct_hash(auth_struct):
        raise ChainError("V9 signed receipt authorization mismatch")
    if receipt.relay != normalize_address(str(auth_struct.relay)):
        raise ChainError("V9 signed receipt Relay payout mismatch")
    digest = receipt_digest(
        receipt,
        chain_id=int(authorization["chain_id"]),
        verifying_contract=str(authorization["settlement_contract"]),
    )
    key_signature = _raw_signature(value.get("key_signature"), "payment key")
    if key_signature != _raw_signature(authorization.get("key_signature"), "payment key"):
        raise ChainError("V9 signed receipt payment signature mismatch")
    provider_signature = _raw_signature(value.get("provider_signature"), "provider")
    relay_signature = _raw_signature(value.get("relay_signature"), "relay")
    if recover_evm_address(digest, _evm_signature(provider_signature)) != receipt.provider_signer:
        raise ChainError("V9 Provider signature mismatch")
    if recover_evm_address(digest, _evm_signature(relay_signature)) != auth_struct.relay_signer:
        raise ChainError("V9 Relay signature mismatch")
    return authorization, receipt, [key_signature, provider_signature, relay_signature]


def _uint(value: Any, label: str, *, bits: int = 256) -> int:
    # JSON numbers must not silently truncate (int(1.5)), nor accept booleans.
    if type(value) is int:
        result = value
    elif isinstance(value, str) and len(value) <= 78 and re.fullmatch(r"[0-9]+", value):
        result = int(value)
    else:
        raise ChainError(f"V9 {label} must be an integer")
    if result < 0 or result >= 1 << bits:
        raise ChainError(f"V9 {label} is out of range")
    return result


def _raw_signature(value: Any, label: str) -> bytes:
    raw = _v8_raw_signature(value, label)
    if raw[64] not in (0, 1, 27, 28) or not 0 < int.from_bytes(raw[:32], "big") < SECP256K1_N:
        raise ChainError(f"V9 {label} signature is noncanonical")
    if not 0 < int.from_bytes(raw[32:64], "big") <= SECP256K1_N // 2:
        raise ChainError(f"V9 {label} signature must have low s")
    return raw


def _positive_uint(value: Any, label: str, *, bits: int = 256) -> int:
    result = _uint(value, label, bits=bits)
    if result == 0:
        raise ChainError(f"V9 {label} must be positive")
    return result


def _nonzero_address(value: Any, label: str) -> str:
    result = normalize_address(str(value or ""))
    if result == ZERO_ADDRESS:
        raise ChainError(f"V9 {label} cannot be zero")
    return result


def _nonzero_hash(value: Any, label: str) -> str:
    result = normalize_bytes32(str(value or ""))
    if result == ZERO_BYTES32:
        raise ChainError(f"V9 {label} cannot be zero")
    return result


def _typed_digest(struct_hash: str, *, chain_id: int, contract: str) -> bytes:
    return keccak256(b"\x19\x01" + bytes.fromhex(domain_separator(
        chain_id=chain_id, verifying_contract=contract)[2:]) + bytes.fromhex(struct_hash[2:]))


def _expect(expected: Any | None, actual: Any, label: str) -> None:
    if expected is not None and _uint(expected, label) != actual:
        raise ChainError(f"V9 {label} mismatch")


def _expect_address(expected: str | None, actual: str, label: str) -> None:
    if expected is not None and normalize_address(expected) != actual:
        raise ChainError(f"V9 {label} mismatch")


def _expect_bytes32(expected: str | None, actual: str, label: str) -> None:
    if expected is not None and normalize_bytes32(expected) != actual:
        raise ChainError(f"V9 {label} mismatch")


def _validate_outer_deployment(value: Mapping[str, Any], authorization: Mapping[str, Any]) -> None:
    if (_positive_uint(value.get("chain_id"), "chain_id") != authorization["chain_id"]
            or _nonzero_address(value.get("settlement_contract"), "settlement_contract")
            != authorization["settlement_contract"]):
        raise ChainError("V9 receipt deployment mismatch")


def _receipt_from_payload(raw: Any) -> UsageReceipt:
    if not isinstance(raw, Mapping):
        raise ChainError("V9 usage receipt is missing")
    return UsageReceipt(
        authorization_hash=_nonzero_hash(raw.get("authorization_hash"), "authorization_hash"),
        response_hash=_nonzero_hash(raw.get("response_hash"), "response_hash"),
        provider=_nonzero_address(raw.get("provider"), "provider"),
        provider_signer=_nonzero_address(raw.get("provider_signer"), "provider_signer"),
        relay=_nonzero_address(raw.get("relay"), "relay"),
        pool=normalize_address(str(raw.get("pool") or ZERO_ADDRESS)),
        input_tokens=_uint(raw.get("input_tokens"), "input_tokens"),
        output_tokens=_uint(raw.get("output_tokens"), "output_tokens"),
        actual_fee=_positive_uint(raw.get("actual_fee"), "actual_fee"),
    )


def _validate_receipt_binding(receipt: UsageReceipt, authorization: Mapping[str, Any]) -> None:
    if receipt.response_hash == ZERO_BYTES32:
        raise ChainError("V9 response_hash cannot be zero")
    if receipt.relay != authorization["authorization"]["relay"]:
        raise ChainError("V9 receipt Relay payout mismatch")
    if receipt.actual_fee > authorization["authorization"]["max_fee"]:
        raise ChainError("V9 receipt exceeds authorized max_fee")
    if authorization["settlement_contract"] in (receipt.provider, receipt.relay, receipt.pool):
        raise ChainError("V9 contract cannot be a receipt payee")


def _calldata(signature: str, args: Sequence[str] = ()) -> str:
    return "0x" + (keccak256(signature.encode())[:4] + b"".join(abi_encode_arg(a) for a in args)).hex()


def settlement_key_for(owner: str, key: str, request_id: str) -> str:
    return "0x" + keccak256(b"".join(abi_encode_arg(v) for v in (
        _nonzero_address(owner, "owner"), _nonzero_address(key, "key"),
        _nonzero_hash(request_id, "request_id")))).hex()


def report_id_for(key: str, reporter: str, evidence_hash: str) -> str:
    return "0x" + keccak256(b"".join(abi_encode_arg(v) for v in (
        _nonzero_hash(key, "settlement_key"), _nonzero_address(reporter, "reporter"),
        _nonzero_hash(evidence_hash, "evidence_hash")))).hex()


def encode_open_dispute(key: str, evidence_hash: str) -> str:
    return _calldata("openDispute(bytes32,bytes32)", [
        _nonzero_hash(key, "settlement_key"), _nonzero_hash(evidence_hash, "evidence_hash")])


def encode_submit_evidence(key: str, evidence_hash: str) -> str:
    return _calldata("submitEvidence(bytes32,bytes32)", [
        _nonzero_hash(key, "settlement_key"), _nonzero_hash(evidence_hash, "evidence_hash")])


def encode_vote_dispute(key: str, *, confirmed: bool, report_id: str, decision_hash: str) -> str:
    if type(confirmed) is not bool:
        raise ChainError("V9 confirmed must be boolean")
    report = normalize_bytes32(report_id)
    if (confirmed and report == ZERO_BYTES32) or (not confirmed and report != ZERO_BYTES32):
        raise ChainError("V9 vote report_id does not match verdict")
    return _calldata("voteDispute(bytes32,bool,bytes32,bytes32)", [
        _nonzero_hash(key, "settlement_key"), str(confirmed), report,
        _nonzero_hash(decision_hash, "decision_hash")])


def encode_release(key: str) -> str:
    return _calldata("release(bytes32)", [_nonzero_hash(key, "settlement_key")])


def encode_resolve_timed_out_dispute(key: str) -> str:
    return _calldata("resolveTimedOutDispute(bytes32)", [_nonzero_hash(key, "settlement_key")])


def encode_claim_dispute_bond(key: str, report_id: str) -> str:
    return _calldata("claimDisputeBond(bytes32,bytes32)", [
        _nonzero_hash(key, "settlement_key"), _nonzero_hash(report_id, "report_id")])


def encode_claim_token_reward() -> str:
    return _calldata("claimTokenReward()")


def encode_claim_payout() -> str:
    return _calldata("claim()")


def encode_deposit_stake(amount: int) -> str:
    return _calldata("depositStake(uint256)", [str(_positive_uint(amount, "amount"))])


def encode_fund_token_rewards(amount: int) -> str:
    return _calldata("fundTokenRewards(uint256)", [str(_positive_uint(amount, "amount"))])


def _block_tag(value: Any) -> Any:
    if isinstance(value, str) and (value in {"latest", "safe", "finalized", "earliest"}
                                  or re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value)):
        return value
    if isinstance(value, Mapping) and set(value) == {"blockHash", "requireCanonical"} and value["requireCanonical"] is True:
        return {"blockHash": _nonzero_hash(value["blockHash"], "blockHash"), "requireCanonical": True}
    raise ChainError("V9 invalid block identifier; pin a block hash for consistent snapshots")


def _pinned_block_tag(rpc_url: str, block_tag: Any, timeout: float) -> Any:
    tag = _block_tag(block_tag)
    if isinstance(tag, str) and tag in {"latest", "safe", "finalized"}:
        block = rpc_call(rpc_url, "eth_getBlockByNumber", [tag, False], timeout)
        if not isinstance(block, Mapping):
            raise ChainError("V9 cannot pin chain snapshot")
        return {"blockHash": _nonzero_hash(block.get("hash"), "block hash"), "requireCanonical": True}
    return tag


def _words(output: Any, count: int, label: str) -> list[str]:
    if not isinstance(output, str) or not re.fullmatch(r"0x[0-9a-fA-F]*", output) or len(output) != 2 + count * 64:
        raise ChainError(f"V9 {label} returned malformed ABI data")
    return [output[i:i + 64] for i in range(2, len(output), 64)]


def _read(rpc_url: str, settlement: str, signature: str, args: Sequence[str], count: int,
          *, timeout: float = 15.0, block_tag: Any = "latest") -> list[str]:
    result = rpc_call(rpc_url, "eth_call", [{"to": _nonzero_address(settlement, "settlement"),
                      "data": _calldata(signature, args)}, _block_tag(block_tag)], timeout)
    return _words(result, count, signature)


def _word_address(value: str) -> str:
    if int(value[:24], 16) != 0:
        raise ChainError("V9 noncanonical ABI address")
    return normalize_address("0x" + value[24:])


def _word_bool(value: str) -> bool:
    number = int(value, 16)
    if number not in (0, 1):
        raise ChainError("V9 noncanonical ABI boolean")
    return number == 1


def key_grant(rpc_url: str, settlement: str, key: str, **options: Any) -> dict[str, Any]:
    words = _read(rpc_url, settlement, "keyGrants(address)", [_nonzero_address(key, "key")], 4, **options)
    return {"owner": _word_address(words[0]), "max_per_request": int(words[1], 16),
            "valid_until": _uint(int(words[2], 16), "valid_until", bits=64), "active": _word_bool(words[3])}


def max_authorization_ttl(rpc_url: str, settlement: str, **options: Any) -> int:
    value = int(_read(rpc_url, settlement, "MAX_AUTHORIZATION_TTL()", [], 1, **options)[0], 16)
    if value not in (LEGACY_MAX_AUTHORIZATION_TTL, MAX_AUTHORIZATION_TTL):
        raise ChainError("V9 contract has an unsupported authorization TTL limit")
    return value


def verified_authorization_window(
    rpc_url: str, *, chain_id: int, settlement: str, key: str, now: int,
    deadline_seconds: int, expected_max_ttl: int, max_fee: int,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Read one canonical snapshot before enabling an explicitly long authorization.

    This does not reserve balance/stake or make delayed settlement safe by itself.
    Callers must use a trusted deployment's RPC/chain/contract, never Relay claims.
    """
    validate_authorization_policy(expected_max_ttl, deadline_seconds)
    now = _positive_uint(now, "now", bits=64)
    if int(rpc_call(rpc_url, "eth_chainId", [], timeout), 16) != chain_id:
        raise ChainError("V9 authorization RPC chain mismatch")
    block = rpc_call(rpc_url, "eth_getBlockByNumber", ["latest", False], timeout)
    if not isinstance(block, Mapping):
        raise ChainError("V9 authorization RPC head is unavailable")
    try:
        timestamp = int(block["timestamp"], 16)
        block_hash = _nonzero_hash(block["hash"], "block_hash")
    except (KeyError, TypeError, ValueError) as exc:
        raise ChainError("V9 authorization RPC head is malformed") from exc
    if abs(now - timestamp) > AUTHORIZATION_CLOCK_SKEW_SECONDS:
        raise ChainError("V9 authorization RPC head/local clock differ by more than 300 seconds")
    tag = {"blockHash": block_hash, "requireCanonical": True}
    actual_max = max_authorization_ttl(rpc_url, settlement, timeout=timeout, block_tag=tag)
    if actual_max != expected_max_ttl:
        raise ChainError("V9 authorization TTL differs from the pinned deployment")
    grant = key_grant(rpc_url, settlement, key, timeout=timeout, block_tag=tag)
    deadline = now + deadline_seconds
    if grant["owner"] == ZERO_ADDRESS or grant["active"] is not True:
        raise ChainError("V9 payment key is not active")
    if grant["max_per_request"] < _positive_uint(max_fee, "max_fee"):
        raise ChainError("V9 payment key limit does not cover the requested fee")
    if grant["valid_until"] != 0 and grant["valid_until"] < deadline:
        raise ChainError("V9 payment key expires before the requested authorization deadline")
    return {"issued_at": now - AUTHORIZATION_CLOCK_SKEW_SECONDS, "deadline": deadline,
            "max_authorization_ttl": actual_max, "block_hash": block_hash}


def validate_authorization_policy(max_ttl: Any, deadline_seconds: Any) -> None:
    if type(max_ttl) is not int or max_ttl not in (LEGACY_MAX_AUTHORIZATION_TTL, MAX_AUTHORIZATION_TTL):
        raise ChainError("V9 max_authorization_ttl_seconds must be 3600 or 10800")
    if (type(deadline_seconds) is not int or deadline_seconds <= 0
            or deadline_seconds + AUTHORIZATION_CLOCK_SKEW_SECONDS > max_ttl):
        raise ChainError("V9 authorization_deadline_seconds plus 300-second clock allowance exceeds the TTL limit")


def account_balance(rpc_url: str, settlement: str, owner: str, **options: Any) -> int:
    return int(_read(rpc_url, settlement, "availableBalance(address)", [normalize_address(owner)], 1, **options)[0], 16)


def claimable_balance(rpc_url: str, settlement: str, account: str, **options: Any) -> int:
    return int(_read(rpc_url, settlement, "claimableBalance(address)", [normalize_address(account)], 1, **options)[0], 16)


def token_claimable_balance(rpc_url: str, settlement: str, account: str, **options: Any) -> int:
    return int(_read(rpc_url, settlement, "tokenClaimableBalance(address)", [normalize_address(account)], 1, **options)[0], 16)


def provider_signer_authorized(rpc_url: str, settlement: str, provider: str, signer: str, **options: Any) -> bool:
    return _word_bool(_read(rpc_url, settlement, "providerSigners(address,address)",
                     [normalize_address(provider), normalize_address(signer)], 1, **options)[0])


def provider_stake_status(rpc_url: str, settlement: str, provider: str, **options: Any) -> dict[str, int]:
    options = {**options, "block_tag": _pinned_block_tag(rpc_url, options.get("block_tag", "latest"), options.get("timeout", 15.0))}
    args = [_nonzero_address(provider, "provider")]
    stake = int(_read(rpc_url, settlement, "providerStake(address)", args, 1, **options)[0], 16)
    locked = int(_read(rpc_url, settlement, "lockedStake(address)", args, 1, **options)[0], 16)
    if locked > stake:
        raise ChainError("V9 locked stake exceeds stake; inconsistent snapshot")
    return {"stake": stake, "locked": locked, "available": stake - locked}


def has_reported(rpc_url: str, settlement: str, key: str, reporter: str, **options: Any) -> bool:
    return _word_bool(_read(rpc_url, settlement, "hasReported(bytes32,address)",
                     [_nonzero_hash(key, "settlement_key"), normalize_address(reporter)], 1, **options)[0])


def dispute_vote(rpc_url: str, settlement: str, key: str, judge: str, **options: Any) -> int:
    result = int(_read(rpc_url, settlement, "disputeVotes(bytes32,address)",
                 [_nonzero_hash(key, "settlement_key"), normalize_address(judge)], 1, **options)[0], 16)
    if result not in (0, 1, 2):
        raise ChainError("V9 invalid dispute vote")
    return result


def is_adjudicator(rpc_url: str, settlement: str, judge: str, **options: Any) -> bool:
    return _word_bool(_read(rpc_url, settlement, "isAdjudicator(address)", [normalize_address(judge)], 1, **options)[0])


def adjudicators(rpc_url: str, settlement: str, *, timeout: float = 15.0, block_tag: Any = "latest") -> list[str]:
    result = rpc_call(rpc_url, "eth_call", [{"to": _nonzero_address(settlement, "settlement"),
                      "data": _calldata("adjudicators()")}, _block_tag(block_tag)], timeout)
    if not isinstance(result, str) or len(result) < 130:
        raise ChainError("V9 malformed adjudicator list")
    try:
        count = int(result[66:130], 16)
    except ValueError as exc:
        raise ChainError("V9 malformed adjudicator count") from exc
    if count < 2 or count > 16:
        raise ChainError("V9 invalid adjudicator count")
    words = _words(result, count + 2, "adjudicators")
    if int(words[0], 16) != 32:
        raise ChainError("V9 malformed adjudicator offset")
    result = [_word_address(word) for word in words[2:]]
    if ZERO_ADDRESS in result or len(set(result)) != len(result):
        raise ChainError("V9 invalid adjudicator addresses")
    return result


POLICY_FIELDS = (
    "dispute_window", "arbitration_timeout", "consumer_withdrawal_delay", "reporter_bond",
    "slash_bps", "slash_cap", "reporter_bounty_bps", "stable_bounty_cap", "token_reward",
    "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty", "bond_penalty_recipient",
)


def dispute_policy(rpc_url: str, settlement: str, **options: Any) -> dict[str, Any]:
    options = {**options, "block_tag": _pinned_block_tag(rpc_url, options.get("block_tag", "latest"), options.get("timeout", 15.0))}
    words = _read(rpc_url, settlement, "policy()", [], len(POLICY_FIELDS), **options)
    result = {name: int(word, 16) for name, word in zip(POLICY_FIELDS[:-1], words[:-1])}
    result["bond_penalty_recipient"] = _word_address(words[-1])
    result["adjudication_threshold"] = int(_read(rpc_url, settlement, "adjudicationThreshold()", [], 1, **options)[0], 16)
    result["reward_token"] = _word_address(_read(rpc_url, settlement, "rewardToken()", [], 1, **options)[0])
    result["stablecoin"] = _word_address(_read(rpc_url, settlement, "stablecoin()", [], 1, **options)[0])
    return result


def settlement_info(rpc_url: str, settlement: str, key: str, **options: Any) -> dict[str, Any]:
    words = _read(rpc_url, settlement, "settlementInfo(bytes32)", [_nonzero_hash(key, "settlement_key")], 20, **options)
    result = dict(zip(("owner", "key", "provider", "provider_signer", "relay", "relay_signer", "pool", "treasury"),
                      map(_word_address, words[:8])))
    result.update(zip(("request_id", "request_hash", "authorization_hash", "response_hash"),
                      ("0x" + word for word in words[8:12])))
    result.update(zip(("gross_fee", "provider_amount", "relay_amount", "pool_amount", "treasury_amount", "settled_at", "release_at", "status"),
                      (int(word, 16) for word in words[12:])))
    if result["status"] >= len(STATUS_NAMES):
        raise ChainError("V9 invalid settlement status")
    result["status_name"] = STATUS_NAMES[result["status"]]
    return result


def dispute_info(rpc_url: str, settlement: str, key: str, **options: Any) -> dict[str, Any]:
    words = _read(rpc_url, settlement, "disputeInfo(bytes32)", [_nonzero_hash(key, "settlement_key")], 9, **options)
    names = ("opened_at", "resolve_at", "dismiss_votes", "report_count", "total_bond", "winning_report_id", "slash_amount", "stable_bounty", "token_bounty")
    return {name: "0x" + word if name == "winning_report_id" else int(word, 16) for name, word in zip(names, words)}


def report_info(rpc_url: str, settlement: str, key: str, report_id: str, **options: Any) -> dict[str, Any]:
    words = _read(rpc_url, settlement, "reports(bytes32,bytes32)",
                  [_nonzero_hash(key, "settlement_key"), _nonzero_hash(report_id, "report_id")], 3, **options)
    return {"reporter": _word_address(words[0]), "evidence_hash": "0x" + words[1], "bond_claimed": _word_bool(words[2])}


def parse_receipt_escrowed(log: Mapping[str, Any], *, expected_contract: str) -> dict[str, Any]:
    if not isinstance(log, Mapping) or log.get("removed") not in (None, False):
        raise ChainError("V9 invalid or removed escrow event")
    if normalize_address(str(log.get("address") or "")) != _nonzero_address(expected_contract, "expected_contract"):
        raise ChainError("V9 escrow event contract mismatch")
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 4 or topics[0] != RECEIPT_ESCROWED_TOPIC:
        raise ChainError("V9 escrow event topic mismatch")
    words = _words(log.get("data"), 3, "escrow event")
    return {"settlement_key": _nonzero_hash(topics[1], "settlement_key"),
            "request_id": _nonzero_hash(topics[2], "request_id"),
            "owner": _word_address(normalize_bytes32(topics[3])[2:]),
            "provider": _word_address(words[0]), "gross_fee": int(words[1], 16),
            "release_at": _uint(int(words[2], 16), "release_at", bits=64)}


@dataclass(frozen=True)
class V9Deployment:
    protocol_version: int
    chain_id: int
    deployer: str
    stablecoin: str
    settlement: str
    treasury: str
    governance: str
    channel: str
    channel_hash: str
    pricing_version: int
    pricing_hash: str
    reward_token: str
    policy: dict[str, Any]
    adjudicators: tuple[str, ...]
    adjudication_threshold: int
    adjudicator_operators: dict[str, str]
    independence_attested: bool
    network_id: str
    channel_id: str
    backend_policy: str
    eip712_name: str = "MycoMesh Settlement"
    eip712_version: str = "9"
    tx_hash: str | None = None
    deployment_block: int | None = None
    committee_mode: str = INDEPENDENT_COMMITTEE
    max_authorization_ttl_seconds: int = LEGACY_MAX_AUTHORIZATION_TTL
    authorization_deadline_seconds: int = DEFAULT_AUTHORIZATION_DEADLINE_SECONDS

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        # Preserve the canonical form and hashes of existing independent plans.
        if self.committee_mode == INDEPENDENT_COMMITTEE:
            value.pop("committee_mode")
        # Old manifests/outbox plans retain their canonical representation.
        if self.max_authorization_ttl_seconds == LEGACY_MAX_AUTHORIZATION_TTL:
            value.pop("max_authorization_ttl_seconds")
        if self.authorization_deadline_seconds == DEFAULT_AUTHORIZATION_DEADLINE_SECONDS:
            value.pop("authorization_deadline_seconds")
        return value


def validate_deployment(value: Any, *, allow_controlled_test: bool = False) -> V9Deployment:
    """Validate explicit operator policy, never fill monetary/security defaults.

    This checks manifest syntax and declared separation, NOT on-chain deployment
    identity, code hash, real operator ownership, or that its committee is honest.
    Network activation must compare these values against a pinned chain snapshot.
    """
    if not isinstance(value, Mapping) or type(value.get("protocol_version")) is not int or value["protocol_version"] != 9:
        raise ChainError("deployment is not Myco Settlement V9")
    if value.get("eip712_name") != "MycoMesh Settlement" or value.get("eip712_version") != "9":
        raise ChainError("V9 deployment EIP712 domain must be explicit")
    fields = {field.name for field in V9Deployment.__dataclass_fields__.values()}
    required = fields - {"tx_hash", "deployment_block", "committee_mode", "max_authorization_ttl_seconds", "authorization_deadline_seconds"}
    if required - set(value):
        raise ChainError("V9 deployment missing explicit fields: " + ", ".join(sorted(required - set(value))))
    normalized = {key: value[key] for key in fields if key in value}
    validate_authorization_policy(value.get("max_authorization_ttl_seconds", LEGACY_MAX_AUTHORIZATION_TTL),
                                  value.get("authorization_deadline_seconds", DEFAULT_AUTHORIZATION_DEADLINE_SECONDS))
    for name in ("chain_id", "pricing_version"):
        normalized[name] = _positive_uint(value[name], name, bits=64 if name == "pricing_version" else 256)
    for name in ("deployer", "stablecoin", "settlement", "treasury", "governance"):
        normalized[name] = _nonzero_address(value[name], name)
    for name in ("channel_hash", "pricing_hash"):
        normalized[name] = _nonzero_hash(value[name], name)
    for name in ("channel", "network_id", "channel_id", "backend_policy"):
        if not isinstance(value[name], str) or not value[name].strip():
            raise ChainError(f"V9 {name} must be explicit")
    reward_token = normalize_address(value["reward_token"])
    normalized["reward_token"] = reward_token
    raw_policy = value["policy"]
    if not isinstance(raw_policy, Mapping) or set(raw_policy) != set(POLICY_FIELDS):
        raise ChainError("V9 policy requires every supported field, with no unknown fields")
    policy = {name: _uint(raw_policy[name], name) for name in POLICY_FIELDS[:-1]}
    policy["bond_penalty_recipient"] = _nonzero_address(raw_policy["bond_penalty_recipient"], "bond_penalty_recipient")
    for name in ("dispute_window", "arbitration_timeout", "consumer_withdrawal_delay"):
        if not 0 < policy[name] <= 30 * 86400:
            raise ChainError(f"V9 invalid {name}")
    if not 0 < policy["slash_bps"] <= 10000 or not 0 < policy["reporter_bounty_bps"] < 10000:
        raise ChainError("V9 invalid slash/bounty basis points")
    if policy["reporter_bond"] == 0 or policy["slash_cap"] == 0 or not 0 < policy["stable_bounty_cap"] <= policy["slash_cap"]:
        raise ChainError("V9 invalid bond or bounty cap")
    reward_fields = ("token_reward", "token_reward_cap", "token_minimum_exposure", "token_minimum_penalty")
    if reward_token == ZERO_ADDRESS:
        if any(policy[name] != 0 for name in reward_fields):
            raise ChainError("V9 token reward disabled but policy allocates tokens")
    elif (reward_token == normalized["stablecoin"] or not 0 < policy["token_reward"] <= policy["token_reward_cap"]
          or policy["token_minimum_exposure"] == 0 or not 0 < policy["token_minimum_penalty"] <= policy["slash_cap"]):
        raise ChainError("V9 invalid token reward policy")
    normalized["policy"] = policy
    raw_judges = value["adjudicators"]
    if not isinstance(raw_judges, (list, tuple)) or not 2 <= len(raw_judges) <= 16:
        raise ChainError("V9 requires 2 to 16 adjudicators")
    judges = tuple(_nonzero_address(judge, "adjudicator") for judge in raw_judges)
    threshold = _positive_uint(value["adjudication_threshold"], "adjudication_threshold", bits=16)
    if len(set(judges)) != len(judges) or not len(judges) // 2 < threshold <= len(judges) or threshold < 2:
        raise ChainError("V9 adjudicator quorum must be a distinct strict majority of at least two")
    prohibited = {normalized["settlement"], normalized["governance"], normalized["treasury"], policy["bond_penalty_recipient"]}
    if normalized["settlement"] in {normalized["treasury"], policy["bond_penalty_recipient"]} or prohibited.intersection(judges):
        raise ChainError("V9 adjudicators must be independent of settlement authorities")
    operators = value["adjudicator_operators"]
    if not isinstance(operators, Mapping):
        raise ChainError("V9 explicit adjudicator operator identities required")
    operator_ids: dict[str, str] = {}
    for address, operator in operators.items():
        address = _nonzero_address(address, "adjudicator operator")
        if address in operator_ids or not isinstance(operator, str) or not operator.strip():
            raise ChainError("V9 invalid adjudicator operator identity")
        operator_ids[address] = operator.strip()
    mode = value.get("committee_mode", INDEPENDENT_COMMITTEE)
    if mode not in (INDEPENDENT_COMMITTEE, CONTROLLED_TEST_COMMITTEE):
        raise ChainError("V9 unknown committee mode")
    if set(operator_ids) != set(judges):
        raise ChainError("V9 each adjudicator must declare an operator")
    distinct_operators = len({item.casefold() for item in operator_ids.values()})
    if mode == CONTROLLED_TEST_COMMITTEE:
        if allow_controlled_test is not True:
            raise ChainError("V9 controlled test committee requires explicit local opt-in")
        if (value["independence_attested"] is not False or distinct_operators != 1
                or normalized["chain_id"] not in CONTROLLED_TEST_CHAIN_IDS
                or not value["network_id"].endswith("-controlled-test")
                or reward_token != ZERO_ADDRESS):
            raise ChainError("V9 controlled test requires one declared operator, false independence, test chain, controlled-test network and disabled rewards")
    elif value["independence_attested"] is not True or distinct_operators != len(judges):
        raise ChainError("V9 independent operators must be distinct and explicitly attested")
    normalized["committee_mode"] = mode
    normalized.update(adjudicators=judges, adjudication_threshold=threshold, adjudicator_operators=operator_ids)
    if value.get("tx_hash") is not None:
        normalized["tx_hash"] = _nonzero_hash(value["tx_hash"], "tx_hash")
    if value.get("deployment_block") is not None:
        normalized["deployment_block"] = _uint(value["deployment_block"], "deployment_block")
    return V9Deployment(**normalized)


def load_deployment(path: Path = Path(DEFAULT_DEPLOYMENT), *, allow_controlled_test: bool = False) -> V9Deployment:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ChainError("cannot read V9 deployment manifest") from exc
    return validate_deployment(value, allow_controlled_test=allow_controlled_test)


def save_deployment(path: Path, deployment: V9Deployment, *, allow_controlled_test: bool = False) -> None:
    validated = validate_deployment(deployment.to_dict(), allow_controlled_test=allow_controlled_test)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(validated.to_dict(), sort_keys=True, indent=2) + "\n", encoding="utf-8")
