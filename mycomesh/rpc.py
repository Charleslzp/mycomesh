"""JSON-RPC access with endpoint failover and transport-only retry."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any

from .evm import address_of, parse_private_key, sign_legacy_transaction

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
ENDPOINT_COOLDOWN_SECONDS = 30.0

_cooldowns: dict[str, float] = {}
_cooldown_lock = threading.Lock()


class RpcError(RuntimeError):
    """A JSON-RPC answer that must not be retried (it is an answer)."""


class RpcTransportError(RpcError):
    """No answer was obtained: connection, timeout, or retryable HTTP status."""


def endpoints_of(value: str | Sequence[str]) -> tuple[str, ...]:
    items = value.split(",") if isinstance(value, str) else list(value)
    result = tuple(dict.fromkeys(item.strip() for item in items if item and item.strip()))
    if not result or len(result) > 8:
        raise RpcError("between one and eight RPC endpoints are required")
    return result


def _call_once(endpoint: str, method: str, params: list[Any], timeout: float) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "mycomesh/11"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        if status in {403, 408, 425, 429} or 500 <= status <= 599:
            raise RpcTransportError(f"{method}: HTTP {status}") from exc
        raise RpcError(f"{method}: HTTP {status}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RpcTransportError(f"{method}: connection failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RpcError(f"{method}: response too large")
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise RpcTransportError(f"{method}: invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise RpcTransportError(f"{method}: non-object response")
    if "error" in parsed:
        message = str(parsed["error"])[:300]
        if any(marker in message.lower() for marker in ("rate limit", "too many requests", "temporarily unavailable")):
            raise RpcTransportError(f"{method}: {message}")
        raise RpcError(f"{method}: {message}")
    return parsed.get("result")


def call(rpc: str | Sequence[str], method: str, params: list[Any], *, timeout: float = 15.0, attempts: int = 2) -> Any:
    """Try each available endpoint within one deadline; retry transport failures only."""
    endpoints = endpoints_of(rpc)
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    for _ in range(max(1, attempts)):
        now = time.monotonic()
        with _cooldown_lock:
            ready = [item for item in endpoints if _cooldowns.get(item, 0.0) <= now] or list(endpoints)
        for index, endpoint in enumerate(ready):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            share = remaining if index == len(ready) - 1 else max(1.0, remaining / (len(ready) - index))
            try:
                result = _call_once(endpoint, method, params, min(share, remaining))
            except RpcTransportError as exc:
                last = exc
                with _cooldown_lock:
                    _cooldowns[endpoint] = time.monotonic() + ENDPOINT_COOLDOWN_SECONDS
                continue
            with _cooldown_lock:
                _cooldowns.pop(endpoint, None)
            return result
        if deadline - time.monotonic() <= 0:
            break
    raise RpcTransportError(str(last) if last else f"{method}: no endpoint answered")


def quantity(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RpcError(f"invalid RPC quantity: {value!r}")
    return int(value, 16)


def eth_call(rpc: str | Sequence[str], to: str, data: str, *, block: Any = "latest", timeout: float = 15.0) -> str:
    return call(rpc, "eth_call", [{"to": to, "data": data}, block], timeout=timeout)


def block_time(rpc: str | Sequence[str]) -> int:
    """Timestamp of the latest block: contract deadlines follow chain time, not the local clock."""
    return quantity(call(rpc, "eth_getBlockByNumber", ["latest", False])["timestamp"])


def send_transaction(
    rpc: str | Sequence[str], private_key: str, *, to: str | None, data: bytes | str = b"", value: int = 0,
    gas_limit: int | None = None, gas_price: int | None = None, chain_id: int | None = None, timeout: float = 30.0,
) -> str:
    """Sign and broadcast a legacy transaction; returns the transaction hash."""
    key = parse_private_key(private_key)
    sender = address_of(key)
    payload = bytes.fromhex(data[2:]) if isinstance(data, str) else data
    chain = chain_id if chain_id is not None else quantity(call(rpc, "eth_chainId", [], timeout=timeout))
    nonce = quantity(call(rpc, "eth_getTransactionCount", [sender, "pending"], timeout=timeout))
    price = gas_price if gas_price is not None else quantity(call(rpc, "eth_gasPrice", [], timeout=timeout)) * 12 // 10
    if gas_limit is None:
        estimate = {"from": sender, "data": "0x" + payload.hex(), "value": hex(value)}
        if to is not None:
            estimate["to"] = to
        gas_limit = quantity(call(rpc, "eth_estimateGas", [estimate], timeout=timeout)) * 12 // 10 + 10_000
    raw = sign_legacy_transaction(
        key, nonce=nonce, gas_price=price, gas_limit=gas_limit, to=to, value=value, data=payload, chain_id=chain,
    )
    return call(rpc, "eth_sendRawTransaction", ["0x" + raw.hex()], timeout=timeout, attempts=1)


def wait_for_receipt(rpc: str | Sequence[str], tx_hash: str, *, timeout: float = 180.0, poll: float = 1.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = call(rpc, "eth_getTransactionReceipt", [tx_hash], timeout=min(15.0, deadline - time.monotonic()))
        if receipt:
            if receipt.get("status") != "0x1":
                raise RpcError(f"transaction {tx_hash} reverted")
            return receipt
        time.sleep(poll)
    raise RpcTransportError(f"transaction {tx_hash} was not mined within {timeout:.0f}s")
