from __future__ import annotations

import json
import socket
import socketserver
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any


PROTOCOL_VERSION = "fandai-p2p/0.1"
DEFAULT_CHANNEL = "codex-standard-v1"
DEFAULT_P2P_PORT = 9700
MAX_MESSAGE_BYTES = 8 * 1024 * 1024


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
) -> None:
    with ProviderTCPServer((listen_host, listen_port), config) as server:
        config.advertise_port = int(server.server_address[1])
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

    endpoint = str(message.get("endpoint") or "responses")
    model = str(message.get("model") or config.model)
    body = build_gateway_request_body(
        endpoint=endpoint,
        model=model,
        input_value=message.get("input"),
        messages=message.get("messages"),
        metadata=message.get("metadata"),
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

    return {
        "type": "infer_result",
        "ok": True,
        "request_id": request_id,
        "peer": provider_descriptor(config),
        "channel": config.channel,
        "endpoint": endpoint,
        "model": model,
        "output_text": extract_output_text(endpoint, raw),
        "usage": raw.get("usage"),
        "elapsed_ms": int((time.time() - started_at) * 1000),
        "raw": raw,
    }


def build_gateway_request_body(
    endpoint: str,
    model: str,
    input_value: Any = None,
    messages: Any = None,
    metadata: Any = None,
) -> dict[str, Any]:
    if endpoint == "chat":
        chat_messages = messages
        if chat_messages is None:
            chat_messages = [{"role": "user", "content": str(input_value or "")}]
        return {
            "model": model,
            "messages": chat_messages,
            "gateway_stateful": False,
            "gateway_metadata": metadata or {},
        }
    if endpoint == "responses":
        return {
            "model": model,
            "input": input_value if input_value is not None else "",
            "gateway_stateful": False,
            "metadata": metadata or {},
        }
    raise P2PError(f"unsupported inference endpoint: {endpoint}")


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


def provider_descriptor(config: ProviderConfig) -> dict[str, Any]:
    return {
        "peer_id": config.peer_id,
        "protocol": PROTOCOL_VERSION,
        "address": f"tcp://{config.advertise_host}:{config.advertise_port}",
        "channel": config.channel,
        "agent_id": config.agent_id,
        "model": config.model,
        "last_seen": int(time.time()),
    }


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
