"""Canonical V10 terminal-event verification for Pool reputation.

The feedback signer only transports an event reference.  Reputation is derived
from the confirmed Settlement event and state read from the pinned chain; the
signer cannot choose counters or an outcome.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from . import chain


class V10ReputationError(RuntimeError):
    pass


_RPC_QUANTITY = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")


FEEDBACK_SCHEMA = "mycomesh.pool.reputation-event.v2"
FEEDBACK_PURPOSE = "mycomesh.pool.reputation.v2"
FEEDBACK_FIELDS = frozenset({
    "schema", "network_id", "chain_id", "settlement_contract",
    "settlement_key", "request_id", "provider_owner", "provider_signer",
    "peer_id", "tx_hash", "log_index", "block_number", "block_hash",
    "terminal_status", "outcome",
})

SETTLEMENT_RELEASED_TOPIC = "0x" + chain.keccak256(
    b"SettlementReleased(bytes32,uint8)"
).hex()
DISPUTE_RESOLVED_TOPIC = "0x" + chain.keccak256(
    b"DisputeResolved(bytes32,uint8,uint256,uint256)"
).hex()
V9_DISPUTE_RESOLVED_TOPIC = "0x" + chain.keccak256(
    b"DisputeResolved(bytes32,uint8,uint256,uint256,uint256)"
).hex()

# MycoSettlementV10.Status.  One canonical event is accepted per terminal case
# so Dismissed/TimedOut cannot be counted once via SettlementReleased and again
# via DisputeResolved from the same transaction.
TERMINAL_OUTCOMES: dict[int, tuple[str, str, str]] = {
    3: ("released", "positive", SETTLEMENT_RELEASED_TOPIC),
    4: ("confirmed", "negative", DISPUTE_RESOLVED_TOPIC),
    5: ("dismissed", "positive", DISPUTE_RESOLVED_TOPIC),
    6: ("timed_out", "neutral", DISPUTE_RESOLVED_TOPIC),
    7: ("jury_unavailable", "neutral", DISPUTE_RESOLVED_TOPIC),
}


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise V10ReputationError(f"invalid {label}")
    return value


def _uint(value: Any, label: str, *, positive: bool = False, bits: int = 256) -> int:
    if type(value) is not int or not int(positive) <= value < 2**bits:
        raise V10ReputationError(f"invalid {label}")
    return value


def _rpc_uint(value: Any, label: str) -> int:
    # JSON-RPC QUANTITY values are minimal lowercase hexadecimal.  Accepting
    # values such as 0x00 or 0X1 makes independent RPC responses compare under
    # a looser grammar than the chain references we persist and sign.
    if not isinstance(value, str) or _RPC_QUANTITY.fullmatch(value) is None:
        raise V10ReputationError(f"RPC returned an invalid {label}")
    try:
        result = int(value, 16)
    except ValueError:
        raise V10ReputationError(f"RPC returned an invalid {label}") from None
    if result < 0:
        raise V10ReputationError(f"RPC returned an invalid {label}")
    return result


def _hash(value: Any, label: str, *, nonzero: bool = True) -> str:
    try:
        normalized = chain.normalize_bytes32(value)
    except (chain.ChainError, TypeError, ValueError) as exc:
        raise V10ReputationError(f"invalid {label}") from exc
    if value != normalized or (nonzero and normalized == chain.ZERO_BYTES32):
        raise V10ReputationError(f"invalid {label}")
    return normalized


def _address(value: Any, label: str) -> str:
    try:
        normalized = chain.normalize_address(value)
    except (chain.ChainError, TypeError, ValueError) as exc:
        raise V10ReputationError(f"invalid {label}") from exc
    if value != normalized or normalized == chain.ZERO_ADDRESS:
        raise V10ReputationError(f"invalid {label}")
    return normalized


def _raw(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) % 2:
        raise V10ReputationError(f"RPC returned malformed {label}")
    try:
        return bytes.fromhex(value[2:])
    except ValueError:
        raise V10ReputationError(f"RPC returned malformed {label}") from None


def _word_address(word: bytes, label: str) -> str:
    if len(word) != 32 or any(word[:12]):
        raise V10ReputationError(f"RPC returned malformed {label}")
    return _address("0x" + word[12:].hex(), label)


def normalize_feedback_document(value: Any) -> dict[str, Any]:
    """Validate the exact signed v2 body without trusting its claimed outcome."""
    if not isinstance(value, Mapping) or set(value) != FEEDBACK_FIELDS:
        raise V10ReputationError(
            "reputation feedback requires exactly the signed v2 event fields"
        )
    if value.get("schema") != FEEDBACK_SCHEMA:
        raise V10ReputationError("unsupported reputation feedback schema")
    result = dict(value)
    result["network_id"] = _text(value.get("network_id"), "network_id")
    result["chain_id"] = _uint(value.get("chain_id"), "chain_id", positive=True, bits=64)
    result["settlement_contract"] = _address(
        value.get("settlement_contract"), "settlement contract",
    )
    for name in ("settlement_key", "request_id", "tx_hash", "block_hash"):
        result[name] = _hash(value.get(name), name)
    result["provider_owner"] = _address(value.get("provider_owner"), "provider owner")
    result["provider_signer"] = _address(value.get("provider_signer"), "provider signer")
    result["peer_id"] = _text(value.get("peer_id"), "peer_id", maximum=160)
    result["log_index"] = _uint(value.get("log_index"), "log_index", bits=64)
    result["block_number"] = _uint(value.get("block_number"), "block_number", bits=64)
    result["terminal_status"] = _text(value.get("terminal_status"), "terminal_status", maximum=32)
    result["outcome"] = _text(value.get("outcome"), "outcome", maximum=16)
    return result


def reputation_event_id(value: Mapping[str, Any]) -> str:
    """Return the chain-scoped replay identity for one canonical log."""
    document = normalize_feedback_document(value)
    return reputation_log_event_id(
        chain_id=document["chain_id"],
        settlement_contract=document["settlement_contract"],
        tx_hash=document["tx_hash"],
        log_index=document["log_index"],
    )


def reputation_log_event_id(
    *, chain_id: Any, settlement_contract: Any, tx_hash: Any, log_index: Any,
) -> str:
    """Return the replay identity directly from one canonical log reference."""
    identity = {
        "chain_id": _uint(chain_id, "chain_id", positive=True, bits=64),
        "settlement_contract": _address(
            settlement_contract, "settlement contract",
        ),
        "tx_hash": _hash(tx_hash, "tx_hash"),
        "log_index": _uint(log_index, "log_index", bits=64),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return "0x" + chain.keccak256(encoded).hex()


def canonical_terminal_log_reference(
    value: Any,
    *,
    chain_id: int,
    protocol_version: int,
    settlement_contract: str,
) -> dict[str, Any] | None:
    """Normalize one terminal log, ignoring non-canonical companion events.

    Dismissed and timed-out cases emit ``SettlementReleased`` as part of the
    payout path and then emit ``DisputeResolved``.  Only the latter is the
    canonical reputation event, so the companion log returns ``None``.
    """
    if protocol_version not in {9, 10}:
        raise V10ReputationError("reputation source protocol version must be V9 or V10")
    if not isinstance(value, Mapping):
        raise V10ReputationError("reputation terminal log must be an object")
    if value.get("removed") not in (None, False):
        raise V10ReputationError("reputation terminal log was removed")
    address = _address(value.get("address"), "terminal log contract")
    expected_contract = _address(settlement_contract, "settlement contract")
    topics = value.get("topics")
    if address != expected_contract or not isinstance(topics, list) or len(topics) != 2:
        raise V10ReputationError("reputation terminal log targets another contract")
    normalized_topics = [_hash(topic, "terminal log topic") for topic in topics]
    data = _raw(value.get("data"), "terminal event data")
    dispute_topic = (
        V9_DISPUTE_RESOLVED_TOPIC
        if protocol_version == 9 else DISPUTE_RESOLVED_TOPIC
    )
    if normalized_topics[0] == SETTLEMENT_RELEASED_TOPIC:
        if len(data) != 32:
            raise V10ReputationError("SettlementReleased has malformed ABI data")
    elif normalized_topics[0] == dispute_topic:
        if len(data) != (128 if protocol_version == 9 else 96):
            raise V10ReputationError("DisputeResolved has malformed ABI data")
    else:
        raise V10ReputationError("history scan returned an unexpected event topic")
    status = int.from_bytes(data[:32], "big")
    expected = TERMINAL_OUTCOMES.get(status)
    if expected is None or (protocol_version == 9 and status == 7):
        raise V10ReputationError("history scan returned an invalid terminal status")
    canonical_topic = expected[2]
    if canonical_topic == DISPUTE_RESOLVED_TOPIC and protocol_version == 9:
        canonical_topic = V9_DISPUTE_RESOLVED_TOPIC
    if normalized_topics[0] != canonical_topic:
        return None
    block_number = _rpc_uint(value.get("blockNumber"), "terminal log block number")
    log_index = _rpc_uint(value.get("logIndex"), "terminal log index")
    tx_hash = _hash(value.get("transactionHash"), "terminal log transaction hash")
    block_hash = _hash(value.get("blockHash"), "terminal log block hash")
    return {
        "address": address,
        "topics": normalized_topics,
        "data": "0x" + data.hex(),
        "transaction_hash": tx_hash,
        "block_number": block_number,
        "block_hash": block_hash,
        "log_index": log_index,
        "terminal_status_code": status,
        "terminal_status": expected[0],
        "outcome": expected[1],
        "event_id": reputation_log_event_id(
            chain_id=chain_id,
            settlement_contract=address,
            tx_hash=tx_hash,
            log_index=log_index,
        ),
    }


@dataclass(frozen=True)
class V10ReputationVerifierConfig:
    network_id: str
    rpc_url: str
    chain_id: int
    genesis_hash: str
    settlement_contract: str
    confirmations: int = 6
    timeout_seconds: float = 15.0
    runtime_code_hash: str | None = None
    protocol_version: int = 10
    require_provider_owner_match: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "network_id", _text(self.network_id, "network_id"))
        rpc_url = _text(self.rpc_url, "RPC URL", maximum=2048)
        parsed = urlsplit(rpc_url)
        if "," in rpc_url or parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise V10ReputationError("reputation verifier requires one HTTP(S) RPC URL")
        object.__setattr__(self, "rpc_url", rpc_url)
        object.__setattr__(self, "chain_id", _uint(self.chain_id, "chain_id", positive=True, bits=64))
        object.__setattr__(self, "genesis_hash", _hash(self.genesis_hash, "genesis hash"))
        object.__setattr__(
            self, "settlement_contract",
            _address(self.settlement_contract, "settlement contract"),
        )
        confirmations = _uint(self.confirmations, "confirmations", positive=True, bits=16)
        if not 2 <= confirmations <= 256:
            raise V10ReputationError("reputation confirmations must be between 2 and 256")
        object.__setattr__(self, "confirmations", confirmations)
        if self.protocol_version not in {9, 10}:
            raise V10ReputationError(
                "reputation source protocol version must be V9 or V10"
            )
        if type(self.require_provider_owner_match) is not bool:
            raise V10ReputationError(
                "provider owner matching policy must be explicit"
            )
        if self.runtime_code_hash is not None:
            object.__setattr__(
                self, "runtime_code_hash",
                _hash(self.runtime_code_hash, "settlement runtime code hash"),
            )
        if (
            type(self.timeout_seconds) not in (int, float)
            or not 0 < float(self.timeout_seconds) <= 60
        ):
            raise V10ReputationError("reputation RPC timeout must be bounded and positive")


class V10ReputationEventVerifier:
    """Verify one authority-signed reference against canonical V10 chain state."""

    def __init__(
        self, config: V10ReputationVerifierConfig,
        *, rpc: Callable[[str, list[Any]], Any] | None = None,
    ) -> None:
        if not isinstance(config, V10ReputationVerifierConfig):
            raise V10ReputationError("validated reputation verifier config is required")
        self.config = config
        self._rpc_override = rpc

    def _rpc(self, method: str, params: list[Any]) -> Any:
        if self._rpc_override is not None:
            return self._rpc_override(method, params)
        return chain.rpc_call(
            self.config.rpc_url, method, params, float(self.config.timeout_seconds),
        )

    def _verified_peer(self, document: Mapping[str, Any], peer: Any) -> None:
        if not isinstance(peer, Mapping) or peer.get("peer_id") != document["peer_id"]:
            raise V10ReputationError("reputation event is not bound to the current Provider peer")
        try:
            payment = chain.normalize_address(peer.get("payment_address"))
        except (chain.ChainError, TypeError, ValueError) as exc:
            raise V10ReputationError("current Provider descriptor has no valid payment owner") from exc
        settlement = peer.get("settlement")
        if not isinstance(settlement, Mapping):
            raise V10ReputationError("current Provider descriptor has no V10 settlement binding")
        try:
            signer = chain.normalize_address(settlement.get("provider_signer"))
            contract = chain.normalize_address(settlement.get("contract"))
        except (chain.ChainError, TypeError, ValueError) as exc:
            raise V10ReputationError("current Provider descriptor has invalid V10 identities") from exc
        if (
            (self.config.require_provider_owner_match
             and payment != document["provider_owner"])
            or signer != document["provider_signer"]
            or settlement.get("version") != self.config.protocol_version
            or settlement.get("chain_id") != document["chain_id"]
            or contract != document["settlement_contract"]
            or peer.get("network_id") != document["network_id"]
        ):
            raise V10ReputationError(
                "reputation event differs from the current signed Provider descriptor"
            )

    def _network(self) -> int:
        observed = _rpc_uint(self._rpc("eth_chainId", []), "chain id")
        genesis = self._rpc("eth_getBlockByNumber", ["0x0", False])
        if (
            observed != self.config.chain_id
            or not isinstance(genesis, Mapping)
            or _hash(genesis.get("hash"), "RPC genesis hash") != self.config.genesis_hash
        ):
            raise V10ReputationError("reputation RPC chain or genesis differs from its pin")
        return _rpc_uint(self._rpc("eth_blockNumber", []), "chain head")

    def _event(self, log: Mapping[str, Any], document: Mapping[str, Any]) -> int:
        if log.get("removed") not in (None, False):
            raise V10ReputationError("reputation event was removed")
        try:
            address = chain.normalize_address(log.get("address"))
        except (chain.ChainError, TypeError, ValueError) as exc:
            raise V10ReputationError("reputation log has an invalid contract") from exc
        topics = log.get("topics")
        if address != document["settlement_contract"] or not isinstance(topics, list) or len(topics) != 2:
            raise V10ReputationError("reputation log is not a canonical V10 terminal event")
        normalized_topics = [_hash(topic, "event topic", nonzero=False) for topic in topics]
        if normalized_topics[1] != document["settlement_key"]:
            raise V10ReputationError("reputation log targets another settlement")
        data = _raw(log.get("data"), "terminal event data")
        if normalized_topics[0] == SETTLEMENT_RELEASED_TOPIC:
            if len(data) != 32:
                raise V10ReputationError("SettlementReleased has malformed ABI data")
        elif normalized_topics[0] in {
            DISPUTE_RESOLVED_TOPIC, V9_DISPUTE_RESOLVED_TOPIC,
        }:
            expected_size = 128 if self.config.protocol_version == 9 else 96
            expected_topic = (
                V9_DISPUTE_RESOLVED_TOPIC
                if self.config.protocol_version == 9 else DISPUTE_RESOLVED_TOPIC
            )
            if normalized_topics[0] != expected_topic or len(data) != expected_size:
                raise V10ReputationError("DisputeResolved has malformed ABI data")
        else:
            raise V10ReputationError("reputation log has an unsupported event topic")
        status = int.from_bytes(data[:32], "big")
        expected = TERMINAL_OUTCOMES.get(status)
        expected_topic = expected[2] if expected is not None else None
        if expected_topic == DISPUTE_RESOLVED_TOPIC and self.config.protocol_version == 9:
            expected_topic = V9_DISPUTE_RESOLVED_TOPIC
        if (
            expected is None
            or (self.config.protocol_version == 9 and status == 7)
            or normalized_topics[0] != expected_topic
        ):
            raise V10ReputationError("reputation log is not the canonical event for its terminal status")
        if document["terminal_status"] != expected[0] or document["outcome"] != expected[1]:
            raise V10ReputationError("claimed reputation outcome differs from the terminal event")
        return status

    def _settlement(self, document: Mapping[str, Any], tag: Mapping[str, Any]) -> int:
        calldata = chain.encode_contract_call(
            "settlementInfo(bytes32)", [document["settlement_key"]],
        )
        raw = _raw(self._rpc(
            "eth_call",
            [{"to": self.config.settlement_contract, "data": calldata}, dict(tag)],
        ), "settlementInfo")
        if len(raw) != 20 * 32:
            raise V10ReputationError("settlementInfo returned malformed ABI data")
        words = [raw[index:index + 32] for index in range(0, len(raw), 32)]
        provider = _word_address(words[2], "settlement Provider owner")
        signer = _word_address(words[3], "settlement Provider signer")
        request_id = "0x" + words[8].hex()
        status = int.from_bytes(words[19], "big")
        if (
            provider != document["provider_owner"]
            or signer != document["provider_signer"]
            or request_id != document["request_id"]
        ):
            raise V10ReputationError("settlement state differs from the reputation event")
        return status

    def verify(self, feedback: Any, *, peer: Any) -> dict[str, Any]:
        document = normalize_feedback_document(feedback)
        if (
            document["network_id"] != self.config.network_id
            or document["chain_id"] != self.config.chain_id
            or document["settlement_contract"] != self.config.settlement_contract
        ):
            raise V10ReputationError("reputation feedback targets another deployment")
        self._verified_peer(document, peer)
        head = self._network()
        if head < document["block_number"] or head - document["block_number"] + 1 < self.config.confirmations:
            raise V10ReputationError("reputation event has insufficient confirmations")
        block = self._rpc("eth_getBlockByNumber", [hex(document["block_number"]), False])
        if (
            not isinstance(block, Mapping)
            or _rpc_uint(block.get("number"), "event block number") != document["block_number"]
            or _hash(block.get("hash"), "event block hash") != document["block_hash"]
        ):
            raise V10ReputationError("reputation event block is noncanonical")
        if self.config.runtime_code_hash is not None:
            code = _raw(self._rpc(
                "eth_getCode",
                [self.config.settlement_contract, {
                    "blockHash": document["block_hash"], "requireCanonical": True,
                }],
            ), "settlement runtime code")
            if not code or "0x" + chain.keccak256(code).hex() != self.config.runtime_code_hash:
                raise V10ReputationError(
                    "reputation settlement runtime code differs from its pin"
                )
        receipt = self._rpc("eth_getTransactionReceipt", [document["tx_hash"]])
        if not isinstance(receipt, Mapping):
            raise V10ReputationError("reputation transaction receipt is unavailable")
        if (
            _hash(receipt.get("transactionHash"), "receipt transaction hash") != document["tx_hash"]
            or _rpc_uint(receipt.get("status"), "receipt status") != 1
            or _rpc_uint(receipt.get("blockNumber"), "receipt block number") != document["block_number"]
            or _hash(receipt.get("blockHash"), "receipt block hash") != document["block_hash"]
        ):
            raise V10ReputationError("reputation receipt differs from its signed reference")
        logs = receipt.get("logs")
        if not isinstance(logs, list):
            raise V10ReputationError("reputation receipt has malformed logs")
        matched = [
            log for log in logs
            if isinstance(log, Mapping)
            and _rpc_uint(log.get("logIndex"), "log index") == document["log_index"]
        ]
        if len(matched) != 1:
            raise V10ReputationError("reputation receipt does not contain the unique referenced log")
        log = matched[0]
        if (
            _hash(log.get("transactionHash"), "log transaction hash") != document["tx_hash"]
            or _rpc_uint(log.get("blockNumber"), "log block number") != document["block_number"]
            or _hash(log.get("blockHash"), "log block hash") != document["block_hash"]
        ):
            raise V10ReputationError("reputation log differs from its receipt")
        event_status = self._event(log, document)
        tag = {"blockHash": document["block_hash"], "requireCanonical": True}
        state_status = self._settlement(document, tag)
        if state_status != event_status:
            raise V10ReputationError("terminal event differs from canonical settlement state")
        # Fence a reorg occurring between the state read and acceptance.
        canonical = self._rpc(
            "eth_getBlockByNumber", [hex(document["block_number"]), False],
        )
        if (
            not isinstance(canonical, Mapping)
            or _hash(canonical.get("hash"), "canonical event block hash")
            != document["block_hash"]
        ):
            raise V10ReputationError("reputation event reorganized during verification")
        final_head = _rpc_uint(self._rpc("eth_blockNumber", []), "chain head")
        if (
            final_head < document["block_number"]
            or final_head - document["block_number"] + 1 < self.config.confirmations
        ):
            raise V10ReputationError(
                "reputation event lost confirmations during verification"
            )
        return {
            **document,
            "event_id": reputation_event_id(document),
            "terminal_status_code": event_status,
        }


__all__ = [
    "DISPUTE_RESOLVED_TOPIC", "V9_DISPUTE_RESOLVED_TOPIC", "FEEDBACK_FIELDS", "FEEDBACK_PURPOSE",
    "FEEDBACK_SCHEMA", "SETTLEMENT_RELEASED_TOPIC", "TERMINAL_OUTCOMES",
    "V10ReputationError", "V10ReputationEventVerifier",
    "V10ReputationVerifierConfig", "canonical_terminal_log_reference",
    "normalize_feedback_document", "reputation_event_id",
    "reputation_log_event_id",
]
