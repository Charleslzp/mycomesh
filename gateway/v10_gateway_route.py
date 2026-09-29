"""Non-custodial V10 paid route for the public OpenAI-compatible gateway.

V10 payment is per request: the Consumer signs a ``ReservedPaymentAuthorization``
for its own on-chain capacity channel and sends it as the x402
``PAYMENT-SIGNATURE`` header.  The gateway never holds a payment key.  It only
verifies that the authorization is well formed and bound to this gateway's
deployment, forwards the unmodified request to a pinned Relay, and returns the
Relay's ``PAYMENT-RESPONSE`` receipt verbatim for the Consumer to verify.

Relay failover is limited to failures before the request is written.  After a
request reaches a Relay, a different Relay has its own outbox, so a retry could
execute the same authorization twice; such outcomes are reported as unknown.
"""
from __future__ import annotations

import base64
import http.client
import json
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import chain_v10
from .chain import ChainError, normalize_address
from .provider_bootstrap import ProviderBootstrapError, load_provider_network_config


V10_ROUTE_PATHS = frozenset({"/v1/responses", "/v1/chat/completions"})
RESPONSE_PROOF_HEADER = "X-MycoMesh-Response-Proof"
REQUEST_TIMEOUT_HEADER = "X-MycoMesh-Request-Timeout-Ms"
RELAY_RESPONSE_HEADERS = ("PAYMENT-RESPONSE", "PAYMENT-REQUIRED", "Retry-After", "x-should-retry")
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_REQUEST_TIMEOUT_SECONDS = 300.0
MAX_RELAY_RESPONSE_BYTES = 32 * 1024 * 1024
RELAY_HEALTH_TTL_SECONDS = 15.0
RELAY_HEALTH_MAX_AGE_SECONDS = 60.0
RELAY_HEALTH_TIMEOUT_SECONDS = 5.0
RELAY_HEALTH_MAX_BYTES = 1024 * 1024


class V10GatewayRouteError(Exception):
    """A V10 route failure with an explicit execution status for the client."""

    def __init__(
        self, status: int, code: str, message: str, *, execution_status: str,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.execution_status = execution_status

    def payload(self) -> dict[str, Any]:
        return {
            "error": {
                "type": "mycomesh_gateway_error",
                "code": self.code,
                "message": str(self),
                "execution_status": self.execution_status,
                "retryable": self.execution_status == "not_dispatched",
            }
        }


@dataclass
class V10GatewayRoute:
    network_id: str
    chain_id: int
    settlement: str
    relay_urls: tuple[str, ...]
    relay_payment_address: str
    relay_attestation_address: str
    ssl_context: ssl.SSLContext = field(repr=False)
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    max_request_timeout_seconds: float = DEFAULT_MAX_REQUEST_TIMEOUT_SECONDS
    _health_lock: Any = field(default_factory=threading.Lock, init=False, repr=False)
    _health: dict[str, Any] | None = field(default=None, init=False, repr=False)
    _health_checked_at: float = field(default=0.0, init=False, repr=False)
    _health_refreshing: bool = field(default=False, init=False, repr=False)

    def verify_payment(self, header_value: str) -> dict[str, Any]:
        """Decode and verify one Consumer authorization before any dispatch."""
        payment = decode_payment_header(header_value)
        try:
            return chain_v10.verify_authorization(
                payment,
                expected_chain_id=self.chain_id,
                expected_contract=self.settlement,
            )
        except (ChainError, KeyError, TypeError, ValueError) as exc:
            raise V10GatewayRouteError(
                400, "invalid_payment_authorization",
                f"V10 payment authorization rejected: {exc}",
                execution_status="not_dispatched",
            ) from exc

    def request_timeout(self, requested_ms: str | None) -> float:
        timeout = self.max_request_timeout_seconds
        if requested_ms:
            try:
                value = int(requested_ms) / 1000
            except ValueError:
                value = timeout
            if value > 0:
                timeout = min(timeout, value)
        return timeout

    def forward(
        self,
        path: str,
        body: bytes,
        *,
        payment_header: str | None,
        response_proof: str | None,
        timeout_seconds: float,
    ) -> tuple[int, bytes, dict[str, str]]:
        """Forward one request to the first reachable pinned Relay."""
        if path not in V10_ROUTE_PATHS:
            raise V10GatewayRouteError(
                404, "unsupported_path", "unsupported V10 route",
                execution_status="not_dispatched",
            )
        deadline = time.monotonic() + max(0.001, float(timeout_seconds))
        last_error: Exception | None = None
        for url in self.relay_urls:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            parts = urlsplit(url)
            connection = http.client.HTTPSConnection(
                str(parts.hostname), parts.port or 443,
                timeout=min(self.connect_timeout_seconds, remaining),
                context=self.ssl_context,
            )
            try:
                connection.connect()
            except (OSError, ssl.SSLError) as exc:
                # Nothing was written: the next Relay cannot duplicate work.
                connection.close()
                last_error = exc
                continue
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("request deadline elapsed before dispatch")
                connection.sock.settimeout(remaining)
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    REQUEST_TIMEOUT_HEADER: str(max(1, int(remaining * 1000))),
                }
                if payment_header:
                    headers["PAYMENT-SIGNATURE"] = payment_header
                if response_proof:
                    headers[RESPONSE_PROOF_HEADER] = response_proof
                connection.request("POST", path, body=body, headers=headers)
                response = connection.getresponse()
                data = response.read(MAX_RELAY_RESPONSE_BYTES + 1)
                if len(data) > MAX_RELAY_RESPONSE_BYTES:
                    raise ValueError("Relay response exceeds the gateway limit")
                returned = {
                    name: value
                    for name in RELAY_RESPONSE_HEADERS
                    if (value := response.getheader(name)) is not None
                }
                return response.status, data, returned
            except (OSError, ValueError, http.client.HTTPException) as exc:
                raise V10GatewayRouteError(
                    502, "relay_outcome_unknown",
                    "The request may have reached the Relay; reconcile the "
                    "authorization's execution and payment status before retrying",
                    execution_status="unknown",
                ) from exc
            finally:
                connection.close()
        detail = f": {type(last_error).__name__}" if last_error is not None else ""
        raise V10GatewayRouteError(
            503, "relay_unavailable", f"no pinned V10 Relay is reachable{detail}",
            execution_status="not_dispatched",
        )

    def health_snapshot(self) -> dict[str, Any] | None:
        """Return the last bounded-age Relay probe; refresh it in the background.

        Readiness callers never block on Relay I/O.  Before the first probe
        completes, and whenever the last probe exceeds its hard age, callers
        receive ``None`` and must treat the route as not ready.
        """
        now = time.monotonic()
        with self._health_lock:
            age = now - self._health_checked_at
            snapshot = self._health if age < RELAY_HEALTH_MAX_AGE_SECONDS else None
            if age >= RELAY_HEALTH_TTL_SECONDS and not self._health_refreshing:
                self._health_refreshing = True
                threading.Thread(
                    target=self._refresh_health,
                    name="mycomesh-v10-gateway-relay-health",
                    daemon=True,
                ).start()
        return snapshot

    def _refresh_health(self) -> None:
        relays = []
        try:
            relays = [self._probe_relay(url) for url in self.relay_urls]
        finally:
            with self._health_lock:
                self._health = {"relays": relays}
                self._health_checked_at = time.monotonic()
                self._health_refreshing = False

    def _probe_relay(self, url: str) -> dict[str, Any]:
        result: dict[str, Any] = {"url": url, "ready": False}
        parts = urlsplit(url)
        connection = http.client.HTTPSConnection(
            str(parts.hostname), parts.port or 443,
            timeout=RELAY_HEALTH_TIMEOUT_SECONDS, context=self.ssl_context,
        )
        try:
            connection.request("GET", "/relay/health", headers={"Accept": "application/json"})
            response = connection.getresponse()
            data = response.read(RELAY_HEALTH_MAX_BYTES + 1)
            if response.status != 200 or len(data) > RELAY_HEALTH_MAX_BYTES:
                result["error_code"] = f"http_{response.status}"
                return result
            payload = json.loads(data.decode("utf-8"))
        except (OSError, ssl.SSLError, ValueError, http.client.HTTPException) as exc:
            result["error_code"] = type(exc).__name__
            return result
        finally:
            connection.close()
        return {"url": url, **relay_route_health(payload, self)}


def relay_route_health(payload: Any, route: V10GatewayRoute) -> dict[str, Any]:
    """Reduce one Relay /health document to the fields the gateway trusts."""
    if not isinstance(payload, Mapping):
        return {"ready": False, "error_code": "invalid_health"}
    v10 = payload.get("v10")
    if not isinstance(v10, Mapping):
        return {"ready": False, "error_code": "v10_disabled"}
    scheduler = v10.get("scheduler") if isinstance(v10.get("scheduler"), Mapping) else {}
    total_slots = scheduler.get("total_slots")
    total_slots = total_slots if type(total_slots) is int and total_slots >= 0 else 0
    providers = payload.get("providers")
    providers = providers if type(providers) is int and providers >= 0 else 0
    try:
        bound = (
            v10.get("enabled") is True
            and v10.get("chain_id") == route.chain_id
            and normalize_address(str(v10.get("settlement_contract"))) == route.settlement
            and normalize_address(str(v10.get("relay_payment_address"))) == route.relay_payment_address
            and normalize_address(str(v10.get("relay_signer_address"))) == route.relay_attestation_address
        )
    except (ChainError, TypeError, ValueError):
        bound = False
    ready = (
        bound
        and payload.get("inference_ready") is True
        and payload.get("settlement_ready") is True
        and providers > 0
        and total_slots > 0
    )
    result: dict[str, Any] = {
        "ready": ready,
        "deployment_bound": bound,
        "providers": providers,
        "total_slots": total_slots,
    }
    if not bound:
        result["error_code"] = "deployment_mismatch"
    return result


def decode_payment_header(value: str) -> dict[str, Any]:
    """Decode the x402 header in the same wrapped or bare forms as the Relay."""
    try:
        text = str(value)
        raw = base64.urlsafe_b64decode(text.encode("ascii") + b"=" * (-len(text) % 4))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise V10GatewayRouteError(
            400, "invalid_payment_header", "invalid x402 PAYMENT-SIGNATURE header",
            execution_status="not_dispatched",
        ) from exc
    if not isinstance(decoded, dict):
        raise V10GatewayRouteError(
            400, "invalid_payment_header", "x402 PAYMENT-SIGNATURE must contain a JSON object",
            execution_status="not_dispatched",
        )
    for wrapper in ("payload", "payment"):
        inner = decoded.get(wrapper)
        if isinstance(inner, dict) and "authorization" in inner:
            return inner
    return decoded


def load_v10_gateway_route(env: Mapping[str, str]) -> V10GatewayRoute | None:
    """Load the pinned Relay route, or ``None`` when V10 routing is not configured."""
    path = str(env.get("MYCOMESH_V10_PROVIDER_NETWORK_CONFIG") or "").strip()
    if not path:
        return None
    try:
        config = load_provider_network_config(path)
    except (ProviderBootstrapError, OSError) as exc:
        raise ChainError(f"invalid V10 gateway Relay network: {exc}") from exc
    deployment = config.deployment
    if int(getattr(deployment, "protocol_version", 0)) != 10:
        raise ChainError("V10 gateway route requires a V10 network manifest")
    if not config.relay_payment_address or not config.relay_attestation_address:
        raise ChainError("V10 gateway route requires pinned Relay identities")
    payment = normalize_address(config.relay_payment_address)
    attestation = normalize_address(config.relay_attestation_address)
    urls = [config.relay_public_url]
    for fallback in config.relay_fallbacks:
        # A V10 channel is bound to one Relay payment/signing identity, so a
        # fallback with a different identity could never admit the request.
        if (
            normalize_address(fallback["payment_address"]) != payment
            or normalize_address(fallback["attestation_address"]) != attestation
        ):
            raise ChainError("V10 fallback Relays must share the channel-bound Relay identity")
        urls.append(fallback["public_url"])
    context = ssl.create_default_context()
    ca_file = str(env.get("MYCOMESH_V10_RELAY_CA_FILE") or "").strip()
    if ca_file:
        # A private manifest CA supplements, rather than replaces, public trust.
        context.load_verify_locations(cafile=ca_file)
    return V10GatewayRoute(
        network_id=config.network_id,
        chain_id=int(deployment.chain_id),
        settlement=normalize_address(deployment.settlement),
        relay_urls=tuple(dict.fromkeys(urls)),
        relay_payment_address=payment,
        relay_attestation_address=attestation,
        ssl_context=context,
    )
