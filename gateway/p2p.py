from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
import time
import urllib.error
import urllib.request
import uuid
import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable

from .identity import IdentityError, NodeIdentity, sign_document, verify_document
from .pricing import DEFAULT_CHANNEL, ChannelPricing, load_pricing_config, quote_usage
from .pricing_source import channel_pricing_snapshot
from .reservation import ReservationError, verify_payment_reservation
from .billing import normalize_payment_address, usdc_to_units
from .replay import DEFAULT_REPLAY_DB, ReplayError, ReplayStore


PROTOCOL_VERSION = "mycomesh-p2p/0.2"
DEFAULT_P2P_PORT = 9700
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
INFERENCE_REQUEST_PURPOSE = "mycomesh.inference.request.v1"
PROVIDER_RESPONSE_PURPOSE = "mycomesh.inference.provider_response.v1"


class P2PError(RuntimeError):
    pass


@dataclass(frozen=True)
class PeerAddress:
    host: str
    port: int

    @property
    def value(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def uri(self) -> str:
        return f"tcp://{self.value}"


@dataclass
class ProviderConfig:
    peer_id: str
    channel: str
    agent_id: str
    agent_key: str
    gateway_url: str
    model: str
    advertise_host: str
    advertise_port: int
    timeout_seconds: float = 120.0
    peer_book: dict[str, dict[str, Any]] = field(default_factory=dict)
    identity: NodeIdentity | None = None
    require_signed_requests: bool = True
    allow_any_signed_consumer: bool = False
    authorized_consumers: set[str] = field(default_factory=set)
    payment_address: str | None = None
    seen_requests: dict[str, float] = field(default_factory=dict)
    require_payment_reservation: bool = True
    pricing_config_path: str | None = None
    pricing_hash: str | None = None
    reserve_input_tokens: int = 8000
    reserve_output_tokens: int = 2000
    replay_store_path: str | None = None
    replay_ttl_seconds: int = 600
    max_concurrency: int = 1
    socket_timeout_seconds: float = 10.0
    _seen_lock: threading.Lock = field(init=False, repr=False)
    _semaphore: threading.BoundedSemaphore = field(init=False, repr=False)
    _replay_store: ReplayStore | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.payment_address = normalize_payment_address(self.payment_address)
        self.max_concurrency = max(1, int(self.max_concurrency))
        self._semaphore = threading.BoundedSemaphore(self.max_concurrency)
        self._seen_lock = threading.Lock()
        if self.replay_store_path:
            self._replay_store = ReplayStore(self.replay_store_path)


class ProviderTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        config: ProviderConfig,
    ) -> None:
        super().__init__(server_address, P2PRequestHandler)
        self.config = config
        if self.config.advertise_port == 0:
            self.config.advertise_port = int(self.server_address[1])


class P2PRequestHandler(socketserver.StreamRequestHandler):
    server: ProviderTCPServer

    def handle(self) -> None:
        self.connection.settimeout(float(self.server.config.socket_timeout_seconds))
        raw = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
        if len(raw) > MAX_MESSAGE_BYTES:
            self._write({"type": "error", "ok": False, "error": "message too large"})
            return
        try:
            message = json.loads(raw.decode("utf-8"))
            response = handle_message(self.server.config, message)
        except Exception as exc:
            response = {
                "type": "error",
                "ok": False,
                "error": str(exc),
            }
        self._write(response)

    def _write(self, response: dict[str, Any]) -> None:
        payload = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
        self.wfile.write(payload)


def serve_provider(
    listen_host: str,
    listen_port: int,
    config: ProviderConfig,
    bootstrap_peers: list[PeerAddress] | None = None,
    on_started: Callable[[ProviderConfig], None] | None = None,
) -> None:
    with ProviderTCPServer((listen_host, listen_port), config) as server:
        config.advertise_port = int(server.server_address[1])
        if on_started is not None:
            on_started(config)
        for peer in bootstrap_peers or []:
            try:
                announce_to_peer(config, peer, timeout=5)
            except P2PError:
                pass
        server.serve_forever()


def handle_message(config: ProviderConfig, message: dict[str, Any]) -> dict[str, Any]:
    message_type = str(message.get("type") or "")
    request_id = str(message.get("request_id") or uuid.uuid4().hex)
    if message_type == "ping":
        return {
            "type": "pong",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
        }
    if message_type == "hello":
        return {
            "type": "hello_result",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
            "peers": list(config.peer_book.values()),
        }
    if message_type == "peers":
        return {
            "type": "peers_result",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
            "peers": list(config.peer_book.values()),
        }
    if message_type == "announce":
        peer = message.get("peer")
        if isinstance(peer, dict):
            remember_peer(config, peer)
        return {
            "type": "announce_result",
            "ok": True,
            "request_id": request_id,
            "peer": provider_descriptor(config),
            "peers": list(config.peer_book.values()),
        }
    if message_type == "infer":
        return handle_infer(config, message)
    raise P2PError(f"unsupported p2p message type: {message_type}")


def handle_infer(config: ProviderConfig, message: dict[str, Any]) -> dict[str, Any]:
    request_id = str(message.get("request_id") or uuid.uuid4().hex)
    channel = str(message.get("channel") or config.channel)
    if channel != config.channel:
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": f"channel mismatch: provider={config.channel} request={channel}",
        }
    try:
        verified = verify_inference_request(config, message)
    except P2PError as exc:
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": str(exc),
        }

    if not config._semaphore.acquire(blocking=False):
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": "provider concurrency exceeded",
            "retryable": True,
        }
    endpoint = str(message.get("endpoint") or "responses")
    model = str(message.get("model") or config.model)
    body = build_gateway_request_body(
        endpoint=endpoint,
        model=model,
        input_value=message.get("input"),
        messages=message.get("messages"),
        metadata=message.get("metadata"),
        max_output_tokens=message.get("max_output_tokens"),
    )
    started_at = time.time()
    try:
        raw = call_gateway(
            gateway_url=config.gateway_url,
            agent_key=config.agent_key,
            endpoint=endpoint,
            body=body,
            timeout=config.timeout_seconds,
        )
    except Exception as exc:
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": str(exc),
        }
    finally:
        config._semaphore.release()

    response = {
        "type": "infer_result",
        "ok": True,
        "request_id": request_id,
        "peer": provider_descriptor(config),
        "channel": config.channel,
        "endpoint": endpoint,
        "model": model,
        "output_text": extract_output_text(endpoint, raw),
        "usage": raw.get("usage"),
        "provider_signature": verified.get("provider_signature"),
        "consumer_public_key": verified.get("consumer_public_key"),
        "elapsed_ms": int((time.time() - started_at) * 1000),
        "quality": {
            "mode": "provider-attested",
            "request_hash": _stable_hash(message.get("messages") if endpoint == "chat" else message.get("input")),
            "canary": bool(message.get("metadata", {}).get("canary")) if isinstance(message.get("metadata"), dict) else False,
        },
        "raw": raw,
    }
    quote = quote_usage(config.channel, raw.get("usage") if isinstance(raw, dict) else None, pricing_table=load_pricing_config(config.pricing_config_path))
    amount_units = usdc_to_units(quote.to_dict()["gross_fee"])
    max_fee_units = int(verified.get("max_fee_units") or 0)
    if max_fee_units > 0 and amount_units > max_fee_units:
        return {
            "type": "infer_result",
            "ok": False,
            "request_id": request_id,
            "error": "inference cost exceeded payment reservation",
            "retryable": False,
        }
    if config.identity is not None:
        response = sign_document(
            response,
            config.identity.private_key,
            purpose=PROVIDER_RESPONSE_PURPOSE,
            audience=verified.get("consumer_public_key"),
        )
    return response


def verify_inference_request(config: ProviderConfig, message: dict[str, Any]) -> dict[str, Any]:
    if not config.require_signed_requests:
        return {}
    try:
        unsigned = verify_document(message, purpose=INFERENCE_REQUEST_PURPOSE, audience=config.peer_id)
    except IdentityError as exc:
        raise P2PError(f"invalid inference request signature: {exc}") from exc
    signature = message.get("signature")
    consumer_public_key = ""
    if isinstance(signature, dict):
        consumer_public_key = str(signature.get("public_key") or "")
    if not consumer_public_key:
        raise P2PError("consumer public key is required")
    if not config.authorized_consumers and not config.allow_any_signed_consumer:
        raise P2PError("consumer allowlist is required")
    if config.authorized_consumers and consumer_public_key not in config.authorized_consumers:
        raise P2PError("consumer is not authorized for this provider")
    request_id = str(unsigned.get("request_id") or "")
    if not request_id:
        raise P2PError("request_id is required")
    request_key = f"{consumer_public_key}:{request_id}"
    now = time.time()
    if config.require_payment_reservation:
        try:
            pricing_table = load_pricing_config(config.pricing_config_path)
            snapshot = channel_pricing_snapshot(
                pricing_table,
                str(message.get("channel") or config.channel),
                override=config.pricing_hash,
            )
            reservation = verify_payment_reservation(
                message.get("payment_reservation"),
                request_id=request_id,
                channel=str(message.get("channel") or config.channel),
                provider_id=config.peer_id,
                provider_payment_address=config.payment_address,
                consumer_public_key=consumer_public_key,
                min_fee_units=provider_min_reservation_units(
                    str(message.get("channel") or config.channel),
                    pricing_table,
                    input_tokens=config.reserve_input_tokens,
                    output_tokens=config.reserve_output_tokens,
                ),
                pricing_hash=snapshot.pricing_hash,
            )
        except ReservationError as exc:
            raise P2PError(str(exc)) from exc
    else:
        reservation = {}
    replay_ttl = max(1, int(config.replay_ttl_seconds))
    with config._seen_lock:
        expired = [key for key, seen_at in config.seen_requests.items() if now - seen_at > replay_ttl]
        for key in expired:
            config.seen_requests.pop(key, None)
        if request_key in config.seen_requests:
            raise P2PError("duplicate request_id")
        config.seen_requests[request_key] = now
    if config._replay_store is not None:
        try:
            config._replay_store.remember("p2p.infer.request", request_key, replay_ttl, now=int(now))
            reservation_nonce = _signature_nonce(message.get("payment_reservation"))
            if reservation_nonce:
                config._replay_store.remember(
                    "p2p.payment.reservation",
                    f"{consumer_public_key}:{reservation_nonce}",
                    replay_ttl,
                    now=int(now),
                )
        except ReplayError as exc:
            with config._seen_lock:
                config.seen_requests.pop(request_key, None)
            raise P2PError(str(exc).replace("replay key", "request_id")) from exc
    result: dict[str, Any] = {
        "consumer_public_key": consumer_public_key,
        "max_fee_units": int(reservation.get("max_fee_units") or 0),
    }
    if config.identity is not None:
        result["provider_signature"] = {
            "peer_id": config.identity.peer_id,
            "public_key": config.identity.public_key,
        }
    return result


def provider_min_reservation_units(
    channel: str,
    pricing_table: dict[str, ChannelPricing] | None = None,
    *,
    input_tokens: int = 8000,
    output_tokens: int = 2000,
) -> int:
    quote = quote_usage(
        channel,
        {
            "input_tokens": max(0, int(input_tokens)),
            "output_tokens": max(0, int(output_tokens)),
        },
        pricing_table=pricing_table,
    )
    return max(1, usdc_to_units(quote.to_dict()["gross_fee"]))


def build_gateway_request_body(
    endpoint: str,
    model: str,
    input_value: Any = None,
    messages: Any = None,
    metadata: Any = None,
    max_output_tokens: Any = None,
) -> dict[str, Any]:
    output_limit = _positive_optional_int(max_output_tokens)
    if endpoint == "chat":
        chat_messages = messages
        if chat_messages is None:
            chat_messages = [{"role": "user", "content": str(input_value or "")}]
        body = {
            "model": model,
            "messages": chat_messages,
            "gateway_stateful": False,
            "gateway_metadata": metadata or {},
        }
        if output_limit is not None:
            body["max_tokens"] = output_limit
        return body
    if endpoint == "responses":
        body = {
            "model": model,
            "input": input_value if input_value is not None else "",
            "gateway_stateful": False,
            "metadata": metadata or {},
        }
        if output_limit is not None:
            body["max_output_tokens"] = output_limit
        return body
    raise P2PError(f"unsupported inference endpoint: {endpoint}")


def _positive_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def call_gateway(
    gateway_url: str,
    agent_key: str,
    endpoint: str,
    body: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    path = "/chat/completions" if endpoint == "chat" else "/responses"
    url = gateway_url.rstrip("/") + path
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {agent_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise P2PError(f"gateway returned HTTP {exc.code}: {payload}") from exc
    return json.loads(payload)


def extract_output_text(endpoint: str, raw: dict[str, Any]) -> str:
    if endpoint == "responses":
        return str(raw.get("output_text") or "")
    try:
        return str(raw["choices"][0]["message"].get("content") or "")
    except (KeyError, IndexError, TypeError):
        return ""


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def provider_descriptor(config: ProviderConfig) -> dict[str, Any]:
    descriptor = {
        "peer_id": config.peer_id,
        "protocol": PROTOCOL_VERSION,
        "address": f"tcp://{config.advertise_host}:{config.advertise_port}",
        "channel": config.channel,
        "agent_id": config.agent_id,
        "model": config.model,
        "last_seen": int(time.time()),
        "capacity": {"max_concurrency": config.max_concurrency},
    }
    if config.identity is not None:
        descriptor["public_key"] = config.identity.public_key
    if config.payment_address:
        descriptor["payment_address"] = config.payment_address
    return descriptor


def _signature_nonce(document: Any) -> str | None:
    if not isinstance(document, dict):
        return None
    signature = document.get("signature")
    if not isinstance(signature, dict):
        return None
    nonce = str(signature.get("nonce") or "")
    return nonce or None


def remember_peer(config: ProviderConfig, peer: dict[str, Any]) -> None:
    peer_id = str(peer.get("peer_id") or "")
    address = str(peer.get("address") or "")
    if not peer_id or not address:
        return
    if peer_id == config.peer_id:
        return
    normalized = dict(peer)
    normalized["last_seen"] = int(time.time())
    config.peer_book[peer_id] = normalized


def announce_to_peer(config: ProviderConfig, peer: PeerAddress, timeout: float) -> dict[str, Any]:
    response = send_message(
        peer,
        {
            "type": "announce",
            "request_id": uuid.uuid4().hex,
            "peer": provider_descriptor(config),
        },
        timeout=timeout,
    )
    remote_peer = response.get("peer")
    if isinstance(remote_peer, dict):
        remember_peer(config, remote_peer)
    for item in response.get("peers") or []:
        if isinstance(item, dict):
            remember_peer(config, item)
    return response


def send_message(peer: PeerAddress, message: dict[str, Any], timeout: float) -> dict[str, Any]:
    payload = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
    try:
        with socket.create_connection((peer.host, peer.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            with sock.makefile("rb") as reader:
                raw = reader.readline(MAX_MESSAGE_BYTES + 1)
    except OSError as exc:
        raise P2PError(f"failed to connect to peer {peer.value}: {exc}") from exc
    if not raw:
        raise P2PError(f"peer {peer.value} returned no response")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise P2PError(f"peer {peer.value} response is too large")
    response = json.loads(raw.decode("utf-8"))
    if isinstance(response, dict) and response.get("ok") is False:
        raise P2PError(str(response.get("error") or "p2p request failed"))
    if not isinstance(response, dict):
        raise P2PError("p2p response must be a JSON object")
    return response


def parse_peer_address(value: str) -> PeerAddress:
    raw = value.strip()
    if raw.startswith("tcp://"):
        raw = raw[len("tcp://") :]
    if ":" not in raw:
        raise ValueError("peer address must look like host:port or tcp://host:port")
    host, port_text = raw.rsplit(":", 1)
    if not host:
        raise ValueError("peer host is required")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("peer port must be an integer") from exc
    if port <= 0 or port > 65535:
        raise ValueError("peer port must be between 1 and 65535")
    return PeerAddress(host=host, port=port)
