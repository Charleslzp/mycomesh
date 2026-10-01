"""On-chain inference: contracts ask MycoInferenceOracleV11; Relays dispatch, Providers answer, anyone fulfils.

A request is public: the oracle emits the model, prompt and limits, and the
Provider signs as the request's hash sha256(abi.encode(schema, chain, oracle,
requestId, model, prompt, maxOutputTokens)). The answer is the raw UTF-8 text,
signed through its sha256. The authorization names the oracle as its key: the
request on-chain is the payer's approval, so there is no key signature.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from . import rpc
from .evm import abi_encode, decode_words, encode_call, keccak256, recover_address, word_to_address
from .protocol import b64decode, b64encode
from .settlement import Authorization, Deployment, Receipt, SettlementError, SignedReceipt, _SIGNED_RECEIPT_ABI, _SIGNED_RECEIPT_SIGNATURE

REQUEST_SCHEMA = keccak256(b"mycomesh.v11.onchain-request.v1")
REQUESTED = "0x" + keccak256(
    b"InferenceRequested(bytes32,address,uint32,(uint32,string,bytes,uint32,uint256,address,uint32,uint8,address),bytes32,uint64)"
).hex()
ANSWERED = "0x" + keccak256(
    b"InferenceAnswered(bytes32,bytes32,uint256,bytes,((bytes32,bytes32,address,address,address,uint256,uint64,uint64,uint64),"
    b"(bytes32,bytes32,bytes32,uint256,uint256,uint256),bytes,bytes,bytes))").hex()
STATES = ("none", "open", "answered", "delivered", "expired")
FINALITY = ("immediate", "after_dispute_window")
EVIDENCE_SCHEMA = "mycomesh.v11.onchain-evidence.v1"


@dataclass(frozen=True)
class OnchainRequest:
    request_id: str
    owner: str
    tier: int
    model: str
    prompt: bytes
    max_output_tokens: int
    max_fee: int
    finality: str
    request_hash: str
    deadline: int

    def document(self) -> dict[str, Any]:
        """The request as a Provider's backend runs it."""
        return {"endpoint": "responses", "model": self.model, "input": self.prompt.decode("utf-8", "replace"),
                "max_output_tokens": self.max_output_tokens, "options": {}}


def request_hash(chain_id: int, oracle: str, request_id: str, model: str, prompt: bytes, max_output_tokens: int) -> str:
    encoded = abi_encode(["bytes32", "uint256", "address", "bytes32", "string", "bytes", "uint32"],
                         ["0x" + REQUEST_SCHEMA.hex(), chain_id, oracle, request_id, model, prompt, max_output_tokens])
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _word(data: bytes, index: int) -> int:
    return int.from_bytes(data[32 * index:32 * (index + 1)], "big")


def _dynamic(data: bytes, offset: int) -> bytes:
    length = int.from_bytes(data[offset:offset + 32], "big")
    return data[offset + 32:offset + 32 + length]


def decode_requested(entry: dict[str, Any]) -> OnchainRequest:
    """An InferenceRequested log: (Ask ask, bytes32 requestHash, uint64 deadline) with the Ask tuple dynamic."""
    data = bytes.fromhex(entry["data"][2:])
    ask = data[_word(data, 0):]
    return OnchainRequest(
        request_id=entry["topics"][1], owner=word_to_address(bytes.fromhex(entry["topics"][2][2:])),
        tier=_word(ask, 0), model=_dynamic(ask, _word(ask, 1)).decode(), prompt=_dynamic(ask, _word(ask, 2)),
        max_output_tokens=_word(ask, 3), max_fee=_word(ask, 4), finality=FINALITY[_word(ask, 7)],
        request_hash="0x" + data[32:64].hex(), deadline=_word(data, 2))


def _signed_receipt(data: bytes) -> SignedReceipt:
    """ABI-decoded SignedReceipt: (Authorization, UsageReceipt) static, then three dynamic signatures."""
    words = [data[32 * i:32 * (i + 1)] for i in range(18)]
    number = lambda i: int.from_bytes(words[i], "big")  # noqa: E731
    authorization = Authorization(
        request_id="0x" + words[0].hex(), request_hash="0x" + words[1].hex(), key=word_to_address(words[2]),
        provider_signer=word_to_address(words[3]), relay_signer=word_to_address(words[4]), max_fee=number(5),
        issued_at=number(6), execute_by=number(7), deadline=number(8))
    receipt = Receipt("0x" + words[9].hex(), "0x" + words[10].hex(), "0x" + words[11].hex(), number(12), number(13), number(14))
    key, provider, relay = ("0x" + _dynamic(data, number(i)).hex() for i in (15, 16, 17))
    return SignedReceipt(authorization, receipt, key, provider, relay)


def decode_answered(entry: dict[str, Any]) -> tuple[str, str, int, bytes, SignedReceipt]:
    data = bytes.fromhex(entry["data"][2:])
    return (entry["topics"][1], entry["topics"][2], _word(data, 0), _dynamic(data, _word(data, 1)),
            _signed_receipt(data[_word(data, 2):]))


@dataclass(frozen=True)
class OracleReader:
    rpc: Any
    oracle: str

    def info(self, request_id: str) -> dict[str, Any]:
        raw = rpc.eth_call(self.rpc, self.oracle, encode_call("requestInfo(bytes32)", ["bytes32"], [request_id]))
        words = decode_words(raw, 13)
        number = lambda i: int.from_bytes(words[i], "big")  # noqa: E731
        return {"owner": word_to_address(words[0]), "callback": word_to_address(words[1]),
                "disputer": word_to_address(words[2]), "tier": number(3), "max_output_tokens": number(4),
                "callback_gas": number(5), "finality": FINALITY[number(6)], "state": STATES[number(7)],
                "deadline": number(8), "max_fee": number(9), "request_hash": "0x" + words[10].hex(),
                "settlement_key": "0x" + words[11].hex(), "response_hash": "0x" + words[12].hex()}

    def requests(self, from_block: int, to_block: int) -> list[OnchainRequest]:
        return [decode_requested(entry) for entry in rpc.call(self.rpc, "eth_getLogs", [{
            "address": self.oracle, "topics": [REQUESTED], "fromBlock": hex(from_block), "toBlock": hex(to_block)}])]

    def request(self, request_id: str, from_block: int = 0) -> OnchainRequest:
        logs = rpc.call(self.rpc, "eth_getLogs", [{"address": self.oracle, "topics": [REQUESTED, request_id],
                                                  "fromBlock": hex(from_block), "toBlock": "latest"}])
        if not logs:
            raise SettlementError("no such on-chain request")
        return decode_requested(logs[0])

    def answer(self, request_id: str, from_block: int = 0) -> tuple[SignedReceipt, bytes]:
        """The answer and its signed receipt, from the InferenceAnswered log."""
        logs = rpc.call(self.rpc, "eth_getLogs", [{"address": self.oracle, "topics": [ANSWERED, request_id],
                                                  "fromBlock": hex(from_block), "toBlock": "latest"}])
        if not logs:
            raise SettlementError("the request has no answer")
        _, _, _, response, signed = decode_answered(logs[0])
        return signed, response


def encode_fulfill(request_id: str, signed: SignedReceipt, response: bytes) -> str:
    return encode_call(f"fulfill(bytes32,{_SIGNED_RECEIPT_SIGNATURE},bytes)", ["bytes32", _SIGNED_RECEIPT_ABI, "bytes"],
                       [request_id, signed.abi_value(), response])


def encode_deliver(request_id: str, response: bytes) -> str:
    return encode_call("deliver(bytes32,bytes)", ["bytes32", "bytes"], [request_id, response])


def encode_expire(request_id: str) -> str:
    return encode_call("expire(bytes32)", ["bytes32"], [request_id])


def verify_answer(signed: SignedReceipt, request: OnchainRequest, response: bytes, deployment: Deployment, oracle: str) -> None:
    """Everything the oracle and settlement check, except chain state: the answer is the request's, signed."""
    a, r = signed.authorization, signed.receipt
    if a.key != oracle.lower() or a.request_id != request.request_id or a.request_hash != request.request_hash:
        raise SettlementError("the receipt is not for this on-chain request")
    if r.response_hash != "0x" + hashlib.sha256(response).hexdigest():
        raise SettlementError("the answer is not the one the Provider signed")
    if r.authorization_hash != "0x" + a.struct_hash.hex() or r.dispatch_hash != "0x" + a.dispatch_hash.hex():
        raise SettlementError("receipt is not bound to its authorization")
    if recover_address(deployment.digest(a.dispatch_hash), signed.relay_signature) != a.relay_signer:
        raise SettlementError("bad relay dispatch signature")
    if recover_address(deployment.digest(r.struct_hash), signed.provider_signature) != a.provider_signer:
        raise SettlementError("bad provider signature")


# ---------------- disputes over on-chain answers ----------------

def build_evidence(request: OnchainRequest, signed: SignedReceipt, response: bytes, oracle: str, chain_id: int,
                   *, reason_code: str, statement: str) -> dict[str, Any]:
    """Everything a jury needs, all of it public on-chain already."""
    return {"schema": EVIDENCE_SCHEMA, "settlement_key": signed.authorization.settlement_key,
            "signed_receipt": signed.to_payload(), "oracle": oracle.lower(), "chain_id": chain_id,
            "request": {"request_id": request.request_id, "model": request.model, "prompt": b64encode(request.prompt),
                        "max_output_tokens": request.max_output_tokens},
            "response": b64encode(response),
            "allegation": {"reason_code": reason_code[:64], "statement": statement[:4000]}}


def verify_evidence(evidence: Any, deployment: Deployment) -> tuple[SignedReceipt, dict[str, Any], dict[str, Any]]:
    """(receipt, request document, response document) for a juror, after checking every binding."""
    if not isinstance(evidence, dict) or evidence.get("schema") != EVIDENCE_SCHEMA:
        raise SettlementError("not on-chain request evidence")
    signed = SignedReceipt.from_payload(evidence["signed_receipt"])
    item = evidence["request"]
    prompt, response = b64decode(item["prompt"]), b64decode(evidence["response"])
    oracle, chain_id = str(evidence["oracle"]), int(evidence["chain_id"])
    if chain_id != deployment.chain_id or evidence["settlement_key"] != signed.authorization.settlement_key:
        raise SettlementError("evidence names another chain or settlement")
    request = OnchainRequest(str(item["request_id"]), "", 0, str(item["model"]), prompt, int(item["max_output_tokens"]),
                             signed.authorization.max_fee, "", request_hash(chain_id, oracle, str(item["request_id"]),
                                                                            str(item["model"]), prompt,
                                                                            int(item["max_output_tokens"])), 0)
    verify_answer(signed, request, response, deployment, oracle)
    return signed, request.document(), {"output_text": response.decode("utf-8", "replace")}


def unsigned_receipt(authorization: Authorization, receipt: Receipt, provider_signature: str, relay_signature: str) -> SignedReceipt:
    return SignedReceipt(authorization, receipt, "0x", provider_signature, relay_signature)


def response_from(result: dict[str, Any]) -> bytes:
    return b64decode(result["response"])


def payload_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True)
