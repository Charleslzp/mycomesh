"""Reproducible, quorum-verified V9/V10 Provider reputation history scan.

The output is a proof-carrying artifact, not a reputation opinion.  Every
included terminal event is independently accepted by every pinned RPC endpoint
against the source contract's canonical block, receipt, runtime code, and
settlement state.  Registry publication re-verifies the same proofs later.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from . import chain
from .provider_reputation_sync import HISTORY_IMPORT_SCHEMA
from .relay_incidents import evidence_hash
from .v10_reputation import (
    DISPUTE_RESOLVED_TOPIC,
    FEEDBACK_SCHEMA,
    SETTLEMENT_RELEASED_TOPIC,
    TERMINAL_OUTCOMES,
    V9_DISPUTE_RESOLVED_TOPIC,
    V10ReputationError,
    V10ReputationEventVerifier,
    V10ReputationVerifierConfig,
    reputation_event_id,
)


class ReputationImportError(ValueError):
    pass


SCAN_POLICY_SCHEMA = "mycomesh.v10.reputation-history-scan-policy.v1"
MAX_POLICY_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_RPC_HEAD_SKEW_BLOCKS = 2
DEFAULT_RPC_MIN_INTERVAL_SECONDS = 1.1
DEFAULT_RPC_ATTEMPTS = 5
_QUANTITY = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_PEER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,159}$")
_LOG_RANGE_LIMIT = re.compile(
    r"(?:limited|limit(?:ed)?)[^0-9]{0,32}(?:0\s*-\s*)?([1-9][0-9]*)\s*blocks?",
    re.IGNORECASE,
)


RPC = Callable[[str, str, list[Any], float], Any]


def _strict_json(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ReputationImportError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ReputationImportError(f"{label} contains a non-finite number")
            ),
        )
    except ReputationImportError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReputationImportError(f"{label} is not strict JSON") from exc


def _read(path: str | os.PathLike[str], maximum: int, label: str) -> bytes:
    target = Path(path)
    descriptor = -1
    try:
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_size <= 0 or info.st_size > maximum
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise ReputationImportError(
                f"{label} must be an owned, non-writable, bounded regular file"
            )
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(maximum + 1)
    except OSError as exc:
        raise ReputationImportError(f"could not read {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > maximum:
        raise ReputationImportError(f"{label} exceeds its size limit")
    return raw


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReputationImportError(f"{label} has unknown or missing fields")
    return value


def _uint(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive) or value >= 2**64:
        raise ReputationImportError(f"invalid {label}")
    return value


def _rpc_uint(value: Any, label: str) -> int:
    if not isinstance(value, str) or _QUANTITY.fullmatch(value) is None:
        raise ReputationImportError(f"RPC returned an invalid {label}")
    return int(value, 16)


def _address(value: Any, label: str) -> str:
    try:
        result = chain.normalize_address(value)
    except (chain.ChainError, TypeError, ValueError) as exc:
        raise ReputationImportError(f"invalid {label}") from exc
    if result != value or result == chain.ZERO_ADDRESS:
        raise ReputationImportError(f"invalid {label}")
    return result


def _hash(value: Any, label: str) -> str:
    try:
        result = chain.normalize_bytes32(value)
    except (chain.ChainError, TypeError, ValueError) as exc:
        raise ReputationImportError(f"invalid {label}") from exc
    if result != value or result == chain.ZERO_BYTES32:
        raise ReputationImportError(f"invalid {label}")
    return result


def _rpc_default(url: str, method: str, params: list[Any], timeout: float) -> Any:
    return chain.rpc_call(url, method, params, timeout)


def _paced_default_rpc() -> RPC:
    """Bound public-RPC load and retry transient gateway/rate-limit failures.

    History import deliberately asks every pinned endpoint for the same data.
    Public archive endpoints commonly enforce a one-request-per-second budget;
    an unpaced scan would therefore fail for operational reasons before it can
    compare the proofs.  Tests and injected RPC implementations remain
    unpaced, so this cannot hide deterministic disagreement in the verifier.
    """
    last_started: dict[str, float] = {}

    def call(url: str, method: str, params: list[Any], timeout: float) -> Any:
        last_error: BaseException | None = None
        for attempt in range(DEFAULT_RPC_ATTEMPTS):
            since = time.monotonic() - last_started.get(url, 0.0)
            if since < DEFAULT_RPC_MIN_INTERVAL_SECONDS:
                time.sleep(DEFAULT_RPC_MIN_INTERVAL_SECONDS - since)
            last_started[url] = time.monotonic()
            try:
                return _rpc_default(url, method, params, timeout)
            except chain.ChainError as exc:
                last_error = exc
                message = str(exc)
                if method == "eth_getLogs" and (
                    "-32602" in message or _LOG_RANGE_LIMIT.search(message)
                ):
                    # The scanner handles an endpoint's explicit range limit
                    # by covering the same interval with smaller pages.
                    raise
                if attempt + 1 < DEFAULT_RPC_ATTEMPTS:
                    time.sleep(min(2**attempt, 8))
        raise ReputationImportError(
            f"history RPC {method} failed after bounded retries"
        ) from last_error

    return call


def _logs_for_endpoint(
    rpc: RPC, url: str, timeout: float, request: Mapping[str, Any],
) -> list[dict[str, Any]]:
    start = int(str(request["fromBlock"]), 16)
    end = int(str(request["toBlock"]), 16)
    page_size = end - start + 1
    cursor = start
    result: list[dict[str, Any]] = []
    while cursor <= end:
        page_end = min(end, cursor + page_size - 1)
        query = dict(request)
        query["fromBlock"] = hex(cursor)
        query["toBlock"] = hex(page_end)
        try:
            value = rpc(url, "eth_getLogs", [query], timeout)
        except chain.ChainError as exc:
            match = _LOG_RANGE_LIMIT.search(str(exc))
            if match is None:
                raise ReputationImportError(
                    "history RPC failed while reading terminal logs"
                ) from exc
            supported = int(match.group(1))
            if supported >= page_size:
                raise ReputationImportError(
                    "history RPC returned an unusable terminal-log range limit"
                ) from exc
            page_size = supported
            continue
        if not isinstance(value, list):
            raise ReputationImportError("history RPC returned malformed logs")
        result.extend(value)
        cursor = page_end + 1
    return result


def _canonical_block(
    rpc: RPC, urls: list[str], timeout: float, number: int, label: str,
) -> str:
    hashes: list[str] = []
    for url in urls:
        value = rpc(url, "eth_getBlockByNumber", [hex(number), False], timeout)
        if (
            not isinstance(value, Mapping)
            or _rpc_uint(value.get("number"), f"{label} number") != number
        ):
            raise ReputationImportError(f"history RPC returned an invalid {label}")
        hashes.append(_hash(value.get("hash"), f"{label} hash"))
    if any(value != hashes[0] for value in hashes[1:]):
        raise ReputationImportError(f"pinned history RPC endpoints disagree on {label}")
    return hashes[0]


def _runtime_code_at(
    rpc: RPC, url: str, timeout: float, settlement: str, block_hash: str,
) -> bytes:
    value = rpc(
        url,
        "eth_getCode",
        [settlement, {"blockHash": block_hash, "requireCanonical": True}],
        timeout,
    )
    if (
        not isinstance(value, str) or not value.startswith("0x")
        or len(value) % 2 or re.fullmatch(r"[0-9a-f]*", value[2:]) is None
    ):
        raise ReputationImportError("history RPC returned malformed runtime code")
    return bytes.fromhex(value[2:])


def _normalized_log(value: Any) -> dict[str, Any]:
    # JSON-RPC implementations are allowed to add non-consensus metadata (for
    # example ``blockTimestamp``).  Compare the complete security-relevant
    # projection across endpoints, while neither depending on nor persisting
    # provider-specific extension fields.
    required = {
        "address", "topics", "data", "blockNumber", "transactionHash",
        "transactionIndex", "blockHash", "logIndex", "removed",
    }
    if not isinstance(value, Mapping) or not required.issubset(value):
        raise ReputationImportError(
            "terminal event log is missing required consensus fields"
        )
    log = value
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 2:
        raise ReputationImportError("terminal event log has malformed topics")
    normalized = {
        "address": _address(log.get("address"), "log address"),
        "topics": [_hash(item, "log topic") for item in topics],
        "data": log.get("data"),
        "blockNumber": hex(_rpc_uint(log.get("blockNumber"), "log block number")),
        "transactionHash": _hash(log.get("transactionHash"), "log transaction hash"),
        "transactionIndex": hex(_rpc_uint(log.get("transactionIndex"), "transaction index")),
        "blockHash": _hash(log.get("blockHash"), "log block hash"),
        "logIndex": hex(_rpc_uint(log.get("logIndex"), "log index")),
        "removed": log.get("removed"),
    }
    data = normalized["data"]
    if (
        not isinstance(data, str) or not data.startswith("0x")
        or len(data) % 2 or re.fullmatch(r"[0-9a-f]*", data[2:]) is None
        or normalized["removed"] not in (None, False)
    ):
        raise ReputationImportError("terminal event log has malformed data")
    return normalized


def _event_status(log: Mapping[str, Any], protocol_version: int) -> int | None:
    raw = bytes.fromhex(str(log["data"])[2:])
    topic = log["topics"][0]
    dispute_topic = (
        V9_DISPUTE_RESOLVED_TOPIC if protocol_version == 9
        else DISPUTE_RESOLVED_TOPIC
    )
    expected_size = 128 if protocol_version == 9 else 96
    if topic == SETTLEMENT_RELEASED_TOPIC:
        if len(raw) != 32:
            raise ReputationImportError("SettlementReleased has malformed ABI data")
    elif topic == dispute_topic:
        if len(raw) != expected_size:
            raise ReputationImportError("DisputeResolved has malformed ABI data")
    else:
        raise ReputationImportError("history scan returned an unexpected event topic")
    status = int.from_bytes(raw[:32], "big")
    expected = TERMINAL_OUTCOMES.get(status)
    if expected is None or (protocol_version == 9 and status == 7):
        raise ReputationImportError("history scan returned an invalid terminal status")
    canonical_topic = expected[2]
    if canonical_topic == DISPUTE_RESOLVED_TOPIC and protocol_version == 9:
        canonical_topic = V9_DISPUTE_RESOLVED_TOPIC
    # Dismissal/timeout transactions also emit SettlementReleased.  Ignore
    # that companion log so one terminal case can never count twice.
    return status if topic == canonical_topic else None


def _settlement_identity(
    rpc: RPC, url: str, timeout: float, settlement: str,
    settlement_key: str, block_hash: str,
) -> dict[str, Any]:
    calldata = chain.encode_contract_call("settlementInfo(bytes32)", [settlement_key])
    raw_value = rpc(
        url, "eth_call",
        [{"to": settlement, "data": calldata}, {
            "blockHash": block_hash, "requireCanonical": True,
        }],
        timeout,
    )
    if not isinstance(raw_value, str) or not raw_value.startswith("0x"):
        raise ReputationImportError("settlementInfo returned malformed ABI data")
    try:
        raw = bytes.fromhex(raw_value[2:])
    except ValueError as exc:
        raise ReputationImportError("settlementInfo returned malformed ABI data") from exc
    if len(raw) != 20 * 32:
        raise ReputationImportError("settlementInfo returned malformed ABI data")
    words = [raw[index:index + 32] for index in range(0, len(raw), 32)]

    def word_address(word: bytes) -> str:
        if any(word[:12]):
            raise ReputationImportError("settlementInfo returned malformed address")
        return _address("0x" + word[12:].hex(), "settlement identity")

    return {
        "provider_owner": word_address(words[2]),
        "provider_signer": word_address(words[3]),
        "request_id": "0x" + words[8].hex(),
        "status": int.from_bytes(words[19], "big"),
    }


def scan_history_import(
    policy_value: Any,
    *,
    rpc: RPC = _rpc_default,
) -> dict[str, Any]:
    policy = _exact(
        policy_value,
        {
            "schema", "source_network_id", "source_protocol_version",
            "source_chain_id", "source_genesis_hash", "source_settlement_contract",
            "source_runtime_code_hash", "confirmations", "rpc_urls",
            "source_deployment_block", "signer_peer_map", "timeout_seconds",
        },
        "reputation history scan policy",
    )
    if policy.get("schema") != SCAN_POLICY_SCHEMA:
        raise ReputationImportError("unsupported reputation history scan policy")
    network_id = policy.get("source_network_id")
    if not isinstance(network_id, str) or not network_id or network_id.strip() != network_id:
        raise ReputationImportError("invalid source network id")
    protocol = _uint(policy.get("source_protocol_version"), "source protocol version")
    if protocol not in {9, 10}:
        raise ReputationImportError("source protocol version must be V9 or V10")
    chain_id = _uint(policy.get("source_chain_id"), "source chain id", positive=True)
    genesis = _hash(policy.get("source_genesis_hash"), "source genesis hash")
    settlement = _address(
        policy.get("source_settlement_contract"), "source settlement contract",
    )
    runtime_hash = _hash(
        policy.get("source_runtime_code_hash"), "source runtime code hash",
    )
    confirmations = _uint(policy.get("confirmations"), "confirmations", positive=True)
    if not 2 <= confirmations <= 256:
        raise ReputationImportError(
            "history scan confirmations must be between two and 256"
        )
    urls = policy.get("rpc_urls")
    if (
        not isinstance(urls, list) or len(urls) < 2 or len(urls) != len(set(urls))
        or any(
            not isinstance(url, str) or url != url.strip() or "\x00" in url
            or urlsplit(url).scheme != "https"
            or not urlsplit(url).hostname or urlsplit(url).username is not None
            or urlsplit(url).password is not None or urlsplit(url).query
            or urlsplit(url).fragment
            for url in urls
        )
        or len({str(urlsplit(url).hostname).lower() for url in urls}) != len(urls)
    ):
        raise ReputationImportError(
            "history scan requires at least two unique credential-free HTTPS RPC URLs"
        )
    if rpc is _rpc_default:
        rpc = _paced_default_rpc()
    deployment_block = _uint(
        policy.get("source_deployment_block"),
        "source deployment block",
        positive=True,
    )
    timeout_value = policy.get("timeout_seconds")
    if type(timeout_value) not in {int, float} or not 0 < float(timeout_value) <= 60:
        raise ReputationImportError("history scan timeout must be bounded")
    timeout = float(timeout_value)
    signer_peer_map = policy.get("signer_peer_map")
    if not isinstance(signer_peer_map, Mapping) or not signer_peer_map:
        raise ReputationImportError("history signer-to-peer map is required")
    signer_peers: dict[str, str] = {}
    for signer, peer in signer_peer_map.items():
        canonical_signer = _address(signer, "historical Provider signer")
        if not isinstance(peer, str) or _PEER.fullmatch(peer) is None:
            raise ReputationImportError("historical Provider peer id is invalid")
        if peer in signer_peers.values():
            raise ReputationImportError("history peer id is assigned to multiple signers")
        signer_peers[canonical_signer] = peer

    heads: list[int] = []
    for url in urls:
        if _rpc_uint(rpc(url, "eth_chainId", [], timeout), "chain id") != chain_id:
            raise ReputationImportError("history RPC chain id differs from its pin")
        genesis_block = rpc(url, "eth_getBlockByNumber", ["0x0", False], timeout)
        if not isinstance(genesis_block, Mapping) or _hash(
            genesis_block.get("hash"), "genesis block hash",
        ) != genesis:
            raise ReputationImportError("history RPC genesis differs from its pin")
        heads.append(_rpc_uint(rpc(url, "eth_blockNumber", [], timeout), "chain head"))
    if max(heads) - min(heads) > MAX_RPC_HEAD_SKEW_BLOCKS:
        raise ReputationImportError("pinned history RPC heads are too far apart")
    end = min(heads) - confirmations + 1
    if end < deployment_block or end - deployment_block > 2_000_000:
        raise ReputationImportError(
            "confirmed history scan range is invalid or too large"
        )
    deployment_hash = _canonical_block(
        rpc, urls, timeout, deployment_block, "source deployment block",
    )
    previous_hash = _canonical_block(
        rpc, urls, timeout, deployment_block - 1, "pre-deployment block",
    )
    through_hash = _canonical_block(
        rpc, urls, timeout, end, "source history cutoff block",
    )
    for url in urls:
        code = _runtime_code_at(
            rpc, url, timeout, settlement, deployment_hash,
        )
        previous_code = _runtime_code_at(
            rpc, url, timeout, settlement, previous_hash,
        )
        if (
            not code
            or "0x" + chain.keccak256(code).hex() != runtime_hash
            or previous_code
        ):
            raise ReputationImportError(
                "source deployment boundary or runtime code differs from its pin"
            )

    topics = [
        SETTLEMENT_RELEASED_TOPIC,
        V9_DISPUTE_RESOLVED_TOPIC if protocol == 9 else DISPUTE_RESOLVED_TOPIC,
    ]
    logs: list[dict[str, Any]] = []
    # Start with a broadly interoperable window.  Some public archive RPCs
    # advertise a smaller deterministic limit (for example 50 blocks); page
    # that endpoint without excluding it from the proof quorum.
    for chunk_start in range(deployment_block, end + 1, 1_000):
        chunk_end = min(end, chunk_start + 999)
        observed: list[list[dict[str, Any]]] = []
        for url in urls:
            value = _logs_for_endpoint(rpc, url, timeout, {
                "address": settlement,
                "fromBlock": hex(chunk_start),
                "toBlock": hex(chunk_end),
                "topics": [topics],
            })
            normalized = sorted(
                (_normalized_log(item) for item in value),
                key=lambda item: (
                    _rpc_uint(item["blockNumber"], "log block number"),
                    _rpc_uint(item["logIndex"], "log index"),
                ),
            )
            observed.append(normalized)
        if any(candidate != observed[0] for candidate in observed[1:]):
            raise ReputationImportError(
                "pinned history RPC endpoints disagree on the terminal log set"
            )
        logs.extend(observed[0])

    entries: dict[str, list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for log in logs:
        status = _event_status(log, protocol)
        if status is None:
            continue
        identities = [
            _settlement_identity(
                rpc, url, timeout, settlement, log["topics"][1], log["blockHash"],
            )
            for url in urls
        ]
        if any(identity != identities[0] for identity in identities[1:]):
            raise ReputationImportError(
                "pinned history RPC endpoints disagree on settlement state"
            )
        identity = identities[0]
        if identity["status"] != status:
            raise ReputationImportError(
                "historical terminal event differs from settlement state"
            )
        signer = identity["provider_signer"]
        peer_id = signer_peers.get(signer)
        if peer_id is None:
            raise ReputationImportError(
                "historical terminal event has no explicit signer-to-peer mapping"
            )
        terminal_status, outcome, _topic = TERMINAL_OUTCOMES[status]
        event = {
            "schema": FEEDBACK_SCHEMA,
            "network_id": network_id,
            "chain_id": chain_id,
            "settlement_contract": settlement,
            "settlement_key": log["topics"][1],
            "request_id": identity["request_id"],
            "provider_owner": identity["provider_owner"],
            "provider_signer": signer,
            "peer_id": peer_id,
            "tx_hash": log["transactionHash"],
            "log_index": _rpc_uint(log["logIndex"], "log index"),
            "block_number": _rpc_uint(log["blockNumber"], "log block number"),
            "block_hash": log["blockHash"],
            "terminal_status": terminal_status,
            "outcome": outcome,
        }
        event_id = reputation_event_id(event)
        if event_id in seen:
            raise ReputationImportError("history scan produced a duplicate event")
        for url in urls:
            verifier = V10ReputationEventVerifier(
                V10ReputationVerifierConfig(
                    network_id=network_id,
                    rpc_url=url,
                    chain_id=chain_id,
                    genesis_hash=genesis,
                    settlement_contract=settlement,
                    confirmations=confirmations,
                    timeout_seconds=timeout,
                    runtime_code_hash=runtime_hash,
                    protocol_version=protocol,
                    require_provider_owner_match=False,
                ),
                rpc=lambda method, params, endpoint=url: rpc(
                    endpoint, method, params, timeout,
                ),
            )
            try:
                verified = verifier.verify(event, peer={
                    "peer_id": peer_id,
                    "network_id": network_id,
                    "payment_address": identity["provider_owner"],
                    "settlement": {
                        "version": protocol,
                        "chain_id": chain_id,
                        "contract": settlement,
                        "provider_signer": signer,
                    },
                })
            except V10ReputationError as exc:
                raise ReputationImportError(
                    f"historical event failed canonical verification: {exc}"
                ) from exc
            if verified.get("event_id") != event_id:
                raise ReputationImportError(
                    "historical verifier changed the event identity"
                )
        seen.add(event_id)
        entries.setdefault(peer_id, []).append(event)
    if not entries:
        raise ReputationImportError("history scan found no canonical terminal events")
    if _canonical_block(
        rpc, urls, timeout, deployment_block, "source deployment block",
    ) != deployment_hash or _canonical_block(
        rpc, urls, timeout, end, "source history cutoff block",
    ) != through_hash:
        raise ReputationImportError("history source reorganized during the scan")
    final_heads = [
        _rpc_uint(rpc(url, "eth_blockNumber", [], timeout), "chain head")
        for url in urls
    ]
    if (
        max(final_heads) - min(final_heads) > MAX_RPC_HEAD_SKEW_BLOCKS
        or min(final_heads) - end + 1 < confirmations
    ):
        raise ReputationImportError(
            "history cutoff lost its confirmation quorum during the scan"
        )
    artifact_entries = []
    for peer_id in sorted(entries):
        events = sorted(entries[peer_id], key=reputation_event_id)
        artifact_entries.append({
            "peer_id": peer_id,
            "provider_signer": events[0]["provider_signer"],
            "events": events,
        })
    return {
        "schema": HISTORY_IMPORT_SCHEMA,
        "source": {
            "network_id": network_id,
            "protocol_version": protocol,
            "chain_id": chain_id,
            "genesis_hash": genesis,
            "settlement_contract": settlement,
            "runtime_code_hash": runtime_hash,
            "confirmations": confirmations,
            "source_deployment_block": deployment_block,
            "source_deployment_block_hash": deployment_hash,
            "source_history_through_block": end,
            "source_history_through_block_hash": through_hash,
        },
        "entries": artifact_entries,
    }


def write_history_import(path: str | os.PathLike[str], artifact: Mapping[str, Any]) -> dict[str, Any]:
    encoded = (
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ReputationImportError("history import artifact exceeds its size limit")
    target = Path(path)
    if target.exists():
        raise ReputationImportError("history import output already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise ReputationImportError("could not write history import artifact")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "artifact_sha256": hashlib.sha256(encoded).hexdigest(),
        "artifact_root": evidence_hash(artifact),
        "path": str(target.resolve()),
        "peer_count": len(artifact["entries"]),
        "event_count": sum(len(entry["events"]) for entry in artifact["entries"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="scan canonical V9/V10 terminal events into a release-pinned reputation import",
    )
    parser.add_argument("--policy", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        policy = _strict_json(
            _read(args.policy, MAX_POLICY_BYTES, "history scan policy"),
            "history scan policy",
        )
        result = write_history_import(
            args.output, scan_history_import(policy),
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ReputationImportError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ReputationImportError", "SCAN_POLICY_SCHEMA", "scan_history_import",
    "write_history_import",
]
