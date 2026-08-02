from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import stat
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .chain import ChainError, ZERO_ADDRESS, normalize_address, sign_evm_digest
from .chain_v5 import session_receipt_digest as session_receipt_digest_v5, verify_provider_settlement_payload as verify_provider_settlement_payload_v5
from .chain_v6 import session_receipt_digest as session_receipt_digest_v6, verify_provider_settlement_payload as verify_provider_settlement_payload_v6
from .client import (
    _peer_addresses,
    _send_infer_to_address,
    _send_session_status_to_address,
    discover_peers_from_pools,
)
from .identity import (
    IdentityError,
    NodeIdentity,
    create_identity,
    peer_id_from_public_key,
    public_key_from_private_key,
)
from .provider_bootstrap import (
    DEFAULT_PROVIDER_NETWORK_PATH,
    ProviderBootstrapError,
    ProviderNetworkConfig,
    load_provider_network_config,
)
from .pool import PoolError, verify_discovered_peer
from .pricing import load_pricing_config, quote_usage
from .protocol import ProtocolValidationError, verify_provider_response
from .reservation import (
    RESPONSES_REQUEST_OPTION_FIELDS,
    ReservationError,
    inference_request_hash,
    normalize_inference_request_options,
)
from .relay import RelayError, parse_relay_address, submit_relay_settlement
from .request_limits import BoundedRequestBodyMiddleware
from .routing import (
    RouteState,
    load_route_state,
    rank_peers,
    record_route_failure,
    record_route_success,
    release_peer,
    reserve_peer,
    save_route_state,
)
from .session_service import (
    DEFAULT_SESSION_LIFETIME_SECONDS,
    DEFAULT_SESSION_MAX_AMOUNT_UNITS,
    SessionClaim,
    SessionDeployment,
    SessionServiceError,
    SessionV4Store,
    verify_opened_session,
)


DEFAULT_LOCAL_CONSUMER_DATA_DIR = "/data"
DEFAULT_LOCAL_CONSUMER_BASE_URL = "http://127.0.0.1:8110/v1"
DEFAULT_LOCAL_CONSUMER_WEB_DIR = "/app/web"
LOCAL_API_KEY_PREFIX = "sk-myco-local-"
LOCAL_WALLET_SCHEMA = "mycomesh.local-consumer.wallet.v1"
LOCAL_STATUS_SCHEMA = "mycomesh.local-consumer.status.v1"
LOCAL_SESSION_SCHEMA = "mycomesh.consumer.v6.plan.v1"
LOCAL_SESSION_DB_NAME = "consumer-session-v6.sqlite3"
LOCAL_SESSION_SECRET_NAME = "consumer-session-secret"
LOCAL_ROUTE_STATE_NAME = "route-state.json"
LOCAL_PEER_CACHE_NAME = "provider-cache.json"
_API_KEY_PATTERN = re.compile(r"^sk-myco-local-[A-Za-z0-9_-]{43}$")
_CODEX_CLIENT_MODEL_ID = "gpt-5.5"


class LocalConsumerError(RuntimeError):
    pass


_V5_PRE_DISPATCH_ERROR_MARKERS = (
    "not connected",
    "queue is full",
    "connection refused",
    "failed to seal",
    "requires sealed",
    "requires secure",
    "relay inference deadline exceeded",
    "consumer concurrency exceeded",
    "rate limit",
    "admission",
    "before dispatch",
    "before sending",
    "pre-dispatch",
)
_V5_UNCERTAIN_ERROR_MARKERS = (
    "in progress or uncertain",
    "timed out",
    "deadline exceeded",
    "http 504",
    "disconnected",
    "connection reset",
    "already been consumed",
)
_V5_ROUTE_REFRESH_ERROR_MARKERS = (
    "secure relay request targets an unregistered provider transport key",
    "provider has not registered a signed transport key",
    "secure p2p request targets an unknown or expired transport key",
)


def _session_v5_claim_should_be_retained(error: Exception) -> bool:
    """Return whether a failed request may already have reached the Provider."""
    normalized = " ".join(str(error).lower().split())
    if isinstance(error, ValueError):
        return False
    if any(marker in normalized for marker in ("before dispatch", "before sending", "pre-dispatch")):
        return False
    if "connection reset" in normalized:
        return True
    if any(marker in normalized for marker in _V5_PRE_DISPATCH_ERROR_MARKERS):
        return False
    if "failed to reach relay" in normalized or "failed to connect" in normalized:
        return "timed out" in normalized or "deadline exceeded" in normalized
    try:
        if int(getattr(error, "status_code", getattr(error, "code", 0)) or 0) == 504:
            return True
    except (TypeError, ValueError):
        pass
    return any(marker in normalized for marker in _V5_UNCERTAIN_ERROR_MARKERS)


def _session_v5_sequence_conflict(error: Exception) -> bool:
    normalized = " ".join(str(error).lower().split())
    return "session request or sequence has already been consumed" in normalized


def _session_request_in_flight(error: Exception) -> bool:
    normalized = " ".join(str(error).lower().split())
    return "another request is already in flight for this session" in normalized


def _session_claim_requires_recovery(error: Exception) -> bool:
    """Identify a durable claim that may already have reached a Provider.

    A stale claim cannot be cleared or replayed safely: the Provider may have
    consumed the sequence while the local Consumer was offline.  Surface a
    dedicated recovery error so clients activate a fresh Session instead of
    retrying the uncertain sequence.
    """
    normalized = " ".join(str(error).lower().split())
    return "stale v4 request claim requires operator recovery" in normalized


def _session_execution_requires_recovery(error: Exception) -> bool:
    normalized = " ".join(str(error).lower().split())
    return "request execution is already in progress or uncertain" in normalized


def _provider_route_refresh_required(error: Exception) -> bool:
    normalized = " ".join(str(error).lower().split())
    return any(marker in normalized for marker in _V5_ROUTE_REFRESH_ERROR_MARKERS)


logger = logging.getLogger(__name__)

_CONSUMER_REQUEST_IN_FLIGHT_MESSAGE = (
    "The local Consumer is finishing another request. Please wait a moment."
)
_PROVIDER_UNAVAILABLE_MESSAGE = (
    "No Provider is available for this request. The local Consumer will retry discovery."
)


class LocalConsumerAPIError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers or {}


@dataclass(frozen=True)
class LocalConsumerConfig:
    data_dir: Path
    network_config_path: Path
    public_base_url: str
    max_request_bytes: int = 1024 * 1024
    request_body_timeout_seconds: float = 30.0
    web_dist_dir: Path | None = None
    discovery_urls: tuple[str, ...] = ()
    pricing_config_path: Path | None = None
    session_lifetime_seconds: int = DEFAULT_SESSION_LIFETIME_SECONDS
    session_max_amount_units: int = DEFAULT_SESSION_MAX_AMOUNT_UNITS
    request_timeout_seconds: float = 300.0

    @classmethod
    def from_env(cls) -> "LocalConsumerConfig":
        data_dir = Path(
            os.getenv("MYCOMESH_CONSUMER_DATA_DIR", DEFAULT_LOCAL_CONSUMER_DATA_DIR)
        )
        network_config_path = Path(
            os.getenv(
                "MYCOMESH_CONSUMER_NETWORK_CONFIG",
                DEFAULT_PROVIDER_NETWORK_PATH,
            )
        )
        public_base_url = _local_base_url(
            os.getenv(
                "MYCOMESH_CONSUMER_PUBLIC_BASE_URL",
                DEFAULT_LOCAL_CONSUMER_BASE_URL,
            )
        )
        try:
            max_request_bytes = int(
                os.getenv("MYCOMESH_CONSUMER_MAX_REQUEST_BYTES", str(1024 * 1024))
            )
            request_body_timeout_seconds = float(
                os.getenv("MYCOMESH_CONSUMER_REQUEST_BODY_TIMEOUT_SECONDS", "30")
            )
        except ValueError as exc:
            raise LocalConsumerError("local Consumer request limits are invalid") from exc
        if max_request_bytes <= 0 or max_request_bytes > 16 * 1024 * 1024:
            raise LocalConsumerError(
                "MYCOMESH_CONSUMER_MAX_REQUEST_BYTES must be between 1 and 16777216"
            )
        if not 0 < request_body_timeout_seconds <= 300:
            raise LocalConsumerError(
                "MYCOMESH_CONSUMER_REQUEST_BODY_TIMEOUT_SECONDS must be between 0 and 300"
            )
        return cls(
            data_dir=data_dir,
            network_config_path=network_config_path,
            public_base_url=public_base_url,
            max_request_bytes=max_request_bytes,
            request_body_timeout_seconds=request_body_timeout_seconds,
            web_dist_dir=Path(
                os.getenv(
                    "MYCOMESH_CONSUMER_WEB_DIR",
                    DEFAULT_LOCAL_CONSUMER_WEB_DIR,
                )
            ),
            discovery_urls=_split_discovery_urls(os.getenv("MYCOMESH_CONSUMER_DISCOVERY_URLS")),
            pricing_config_path=(
                Path(os.getenv("MYCOMESH_PRICING_CONFIG"))
                if os.getenv("MYCOMESH_PRICING_CONFIG")
                else None
            ),
            session_lifetime_seconds=_bounded_int_env(
                "MYCOMESH_CONSUMER_SESSION_LIFETIME_SECONDS",
                DEFAULT_SESSION_LIFETIME_SECONDS,
                minimum=60,
                maximum=30 * 24 * 60 * 60,
            ),
            session_max_amount_units=_bounded_int_env(
                "MYCOMESH_CONSUMER_SESSION_MAX_AMOUNT_UNITS",
                DEFAULT_SESSION_MAX_AMOUNT_UNITS,
                minimum=1,
                maximum=10**18,
            ),
            request_timeout_seconds=_bounded_float_env(
                "MYCOMESH_CONSUMER_REQUEST_TIMEOUT_SECONDS",
                300.0,
                minimum=1.0,
                maximum=3600.0,
            ),
        )

    @property
    def api_key_path(self) -> Path:
        return self.data_dir / "api-key"

    @property
    def identity_path(self) -> Path:
        return self.data_dir / "consumer-identity.json"

    @property
    def wallet_path(self) -> Path:
        return self.data_dir / "wallet.json"

    @property
    def session_db_path(self) -> Path:
        return self.data_dir / LOCAL_SESSION_DB_NAME

    @property
    def session_secret_path(self) -> Path:
        return self.data_dir / LOCAL_SESSION_SECRET_NAME

    @property
    def route_state_path(self) -> Path:
        return self.data_dir / LOCAL_ROUTE_STATE_NAME

    @property
    def peer_cache_path(self) -> Path:
        return self.data_dir / LOCAL_PEER_CACHE_NAME


@dataclass(frozen=True)
class LocalWallet:
    address: str
    signing_mode: str = "external"

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": LOCAL_WALLET_SCHEMA,
            "address": self.address,
            "signing_mode": self.signing_mode,
        }


@dataclass
class LocalConsumerState:
    config: LocalConsumerConfig
    network: ProviderNetworkConfig
    identity: NodeIdentity
    api_key: str = field(repr=False)
    wallet: LocalWallet | None = None
    session_store: SessionV4Store | None = field(default=None, repr=False)
    route_state: RouteState = field(default_factory=RouteState, repr=False)
    peer_cache: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    _route_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _peer_cache_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _wallet_lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    @property
    def api_key_fingerprint(self) -> str:
        return hashlib.sha256(self.api_key.encode("utf-8")).hexdigest()[:12]

    @property
    def browser_app_ready(self) -> bool:
        root = self.config.web_dist_dir
        return bool(
            root
            and root.is_dir()
            and not root.is_symlink()
            and (root / "index.html").is_file()
            and not (root / "index.html").is_symlink()
        )

    @property
    def browser_app_url(self) -> str:
        parsed = urlsplit(self.config.public_base_url)
        return f"{parsed.scheme}://{parsed.netloc}/app/playground"

    def configure_external_wallet(self, address: Any) -> LocalWallet:
        try:
            normalized = normalize_address(str(address or ""))
        except ChainError as exc:
            raise LocalConsumerError("wallet address must be a valid EVM address") from exc
        if normalized == ZERO_ADDRESS:
            raise LocalConsumerError("wallet address must be non-zero")
        candidate = LocalWallet(address=normalized)
        with self._wallet_lock:
            if self.wallet is not None:
                if self.wallet == candidate:
                    return self.wallet
                raise LocalConsumerError(
                    "a different wallet is already configured; explicit wallet rotation is not available"
                )
            try:
                _write_new_secret_json(self.config.wallet_path, candidate.to_dict())
            except FileExistsError:
                persisted = _load_wallet(self.config.wallet_path)
                if persisted != candidate:
                    raise LocalConsumerError(
                        "a different wallet was configured concurrently"
                    )
                self.wallet = persisted
                return persisted
            self.wallet = candidate
            return candidate

    @property
    def discovery_urls(self) -> tuple[str, ...]:
        configured = tuple(self.config.discovery_urls)
        return configured or tuple(self.network.bridge_urls)

    @property
    def session_deployment(self) -> SessionDeployment:
        deployment = self.network.deployment
        protocol_version = int(getattr(deployment, "protocol_version", 0))
        if protocol_version not in {5, 6}:
            raise LocalConsumerError("the local Consumer requires a Settlement V5 or V6 deployment")
        return SessionDeployment(
            chain_id=int(deployment.chain_id),
            contract=str(deployment.settlement),
            rpc_url=self.network.settlement_rpc_url,
            channel=str(deployment.channel),
            channel_hash=str(deployment.channel_hash),
            pricing_version=int(deployment.pricing_version),
            pricing_hash=str(deployment.pricing_hash),
            network_id=str(deployment.network_id),
            channel_id=str(deployment.channel_id),
            backend_policy=str(deployment.backend_policy),
            relay_payment_address=str(self.network.relay_payment_address or ZERO_ADDRESS),
            relay_attestation_address=str(self.network.relay_attestation_address or ZERO_ADDRESS),
            protocol_version=protocol_version,
        ).normalized()

    @property
    def session_ready(self) -> bool:
        """Return whether a live Session V5 has been verified locally.

        This marker is only a status hint. ``infer`` still verifies the exact
        session against the contract before every request.
        """
        if self.wallet is None or self.session_store is None:
            return False
        plan = self.session_store.latest_active(account_id=self.wallet.address)
        return bool(plan and int(plan.get("activated_at") or 0) > 0)

    def discover_peers(
        self,
        *,
        model: str | None = None,
        timeout: float = 10.0,
        allow_cached: bool = True,
    ) -> list[dict[str, Any]]:
        discovery_error: Exception | None = None
        try:
            peers = discover_peers_from_pools(
                list(self.discovery_urls),
                channel=self.session_deployment.channel,
                timeout=min(float(timeout), 30.0),
            )
        except Exception as exc:
            discovery_error = exc
            peers = []
        expected_model = str(model or self.network.public_model_id)
        accepted: list[dict[str, Any]] = []
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            if str(peer.get("model") or "") != expected_model:
                continue
            try:
                self._validate_peer_binding(peer)
            except (ChainError, LocalConsumerError, TypeError, ValueError):
                continue
            accepted.append(peer)
        if accepted:
            with self._peer_cache_lock:
                now = int(time.time())
                for peer in accepted:
                    peer_id = str(peer.get("peer_id") or "")
                    if peer_id:
                        cached = dict(peer)
                        cached["_cached_at"] = now
                        self.peer_cache[peer_id] = cached
                _save_peer_cache(self.config.peer_cache_path, self.peer_cache)
            return accepted

        if allow_cached:
            cached = self._cached_peers(expected_model)
            if cached:
                return cached
        if discovery_error is not None:
            raise LocalConsumerError(f"local Provider discovery failed: {discovery_error}") from discovery_error
        if not accepted:
            raise LocalConsumerError(
                f"no Settlement V{self.session_deployment.protocol_version} Provider is available for model {expected_model}"
            )
        return accepted

    def _cached_peers(self, model: str) -> list[dict[str, Any]]:
        now = int(time.time())
        accepted: list[dict[str, Any]] = []
        changed = False
        with self._peer_cache_lock:
            for peer_id, raw_peer in list(self.peer_cache.items()):
                if not isinstance(raw_peer, dict):
                    self.peer_cache.pop(peer_id, None)
                    changed = True
                    continue
                try:
                    cached_at = int(raw_peer.get("_cached_at") or 0)
                    expires_at = int(raw_peer.get("expires_at") or 0)
                    ttl_seconds = int(raw_peer.get("ttl_seconds") or 0)
                except (TypeError, ValueError):
                    self.peer_cache.pop(peer_id, None)
                    changed = True
                    continue
                max_age = max(60, min(ttl_seconds or 15 * 60, 24 * 60 * 60))
                if (expires_at and expires_at <= now) or (cached_at <= 0 or cached_at + max_age <= now):
                    self.peer_cache.pop(peer_id, None)
                    changed = True
                    continue
                if str(raw_peer.get("model") or "") != model:
                    continue
                peer = {key: value for key, value in raw_peer.items() if key != "_cached_at"}
                try:
                    self._validate_peer_binding(peer)
                except (ChainError, LocalConsumerError, TypeError, ValueError):
                    continue
                accepted.append(peer)
            if changed:
                _save_peer_cache(self.config.peer_cache_path, self.peer_cache)
        return rank_peers(accepted, self.route_state)

    def _validate_peer_binding(self, peer: dict[str, Any]) -> None:
        if isinstance(peer.get("descriptor"), dict) or isinstance(peer.get("signature"), dict):
            try:
                verified = verify_discovered_peer(
                    peer,
                    pool_url=str(peer.get("pool_url") or self.discovery_urls[0]),
                    require_signed=True,
                    max_signature_age_seconds=0,
                )
            except PoolError as exc:
                raise LocalConsumerError(f"stored Provider descriptor is invalid: {exc}") from exc
            peer.update(verified)
        deployment = self.session_deployment
        if str(peer.get("peer_id") or "").strip() == "":
            raise LocalConsumerError("Provider descriptor has no peer_id")
        addresses = _peer_addresses(peer)
        if not addresses:
            raise LocalConsumerError("Provider descriptor has no routable address")
        if not str(peer.get("public_key") or "").strip():
            raise LocalConsumerError("Provider descriptor has no public key")
        if str(peer.get("network_id") or deployment.network_id) != deployment.network_id:
            raise LocalConsumerError("Provider network_id does not match the local manifest")
        if str(peer.get("channel_id") or deployment.channel_id) != deployment.channel_id:
            raise LocalConsumerError("Provider channel_id does not match the local manifest")
        if str(peer.get("backend_policy") or deployment.backend_policy) != deployment.backend_policy:
            raise LocalConsumerError("Provider backend_policy does not match the local manifest")
        settlement = peer.get("session_settlement") or peer.get("settlement")
        expected_version = int(deployment.protocol_version)
        if not isinstance(settlement, dict) or int(settlement.get("version") or 0) != expected_version:
            raise LocalConsumerError(f"Provider does not advertise Settlement V{expected_version} sessions")
        if int(settlement.get("chain_id") or 0) != deployment.chain_id:
            raise LocalConsumerError(f"Provider Settlement V{expected_version} chain does not match the local manifest")
        if normalize_address(str(settlement.get("contract") or ZERO_ADDRESS)) != normalize_address(deployment.contract):
            raise LocalConsumerError(f"Provider Settlement V{expected_version} contract does not match the local manifest")
        if int(settlement.get("pricing_version") or 0) != deployment.pricing_version:
            raise LocalConsumerError(f"Provider pricing version does not match Settlement V{expected_version}")
        if str(settlement.get("pricing_hash") or "").lower() != deployment.pricing_hash.lower():
            raise LocalConsumerError(f"Provider pricing hash does not match Settlement V{expected_version}")
        payment_address = normalize_address(str(peer.get("payment_address") or ZERO_ADDRESS))
        if payment_address == ZERO_ADDRESS:
            raise LocalConsumerError("Provider payment address is zero")
        if payment_address == normalize_address(self.wallet.address if self.wallet else ZERO_ADDRESS):
            raise LocalConsumerError("Provider payment address matches the Consumer wallet")

    @staticmethod
    def _provider_route_requires_refresh(peer: dict[str, Any]) -> bool:
        binding = peer.get("transport_key")
        if not isinstance(binding, dict):
            return True
        try:
            expires_at = int(binding.get("expires_at") or 0)
        except (TypeError, ValueError):
            return True
        return expires_at <= int(time.time()) + 60

    def _refresh_session_provider(
        self,
        *,
        session_id: str,
        provider_id: str,
        provider_payment_address: str,
        model: str,
    ) -> dict[str, Any]:
        for candidate in self.discover_peers(model=model, allow_cached=False):
            if str(candidate.get("peer_id") or "") != provider_id:
                continue
            if normalize_address(str(candidate.get("payment_address") or ZERO_ADDRESS)) != normalize_address(
                provider_payment_address
            ):
                continue
            self.session_store.set_provider_route(session_id, candidate)
            return candidate
        raise LocalConsumerError("the bound Provider is not currently available")

    def _session_provider(self, plan: dict[str, Any], *, model: str) -> dict[str, Any]:
        peer = dict(plan.get("provider") or {})
        if not peer or self._provider_route_requires_refresh(peer):
            peer = self._refresh_session_provider(
                session_id=str(plan["session_id"]),
                provider_id=str(plan["provider_id"]),
                provider_payment_address=str(plan["provider_payment_address"]),
                model=model,
            )
        self._validate_peer_binding(peer)
        if str(peer.get("peer_id") or "") != str(plan["provider_id"]):
            raise LocalConsumerError("stored Provider route does not match the local Session")
        if normalize_address(str(peer.get("payment_address") or ZERO_ADDRESS)) != normalize_address(
            str(plan["provider_payment_address"])
        ):
            raise LocalConsumerError("stored Provider payment address does not match the local Session")
        return peer

    def prepare_session(
        self,
        *,
        model: str,
        max_output_tokens: int,
        provider_id: str | None = None,
        max_amount_units: int | None = None,
    ) -> dict[str, Any]:
        if self.wallet is None:
            raise LocalConsumerError("configure a wallet before preparing a local session")
        if self.session_store is None:
            raise LocalConsumerError("local Session store is not initialized")
        if max_output_tokens <= 0 or max_output_tokens > self.network.reserve_output_tokens:
            raise LocalConsumerError(
                f"max_output_tokens must be between 1 and {self.network.reserve_output_tokens}"
            )
        if max_amount_units is not None and (
            int(max_amount_units) <= 0
            or int(max_amount_units) > int(self.config.session_max_amount_units)
        ):
            raise LocalConsumerError(
                "max_amount_units must be positive and no greater than the local Consumer session cap"
            )
        peers = self.discover_peers(model=model)
        if provider_id:
            peers = [peer for peer in peers if str(peer.get("peer_id") or "") == provider_id]
            if not peers:
                raise LocalConsumerError("the requested Provider is not available")
        peer = rank_peers(peers, self.route_state)[0]
        deployment = self.session_deployment
        relay_payment = normalize_address(
            str(peer.get("relay_payment_address") or self.network.relay_payment_address or ZERO_ADDRESS)
        )
        relay_attestation = normalize_address(
            str(peer.get("relay_attestation_address") or self.network.relay_attestation_address or ZERO_ADDRESS)
        )
        addresses = {urlsplit(address).scheme.lower() for address in _peer_addresses(peer)}
        relay_schemes = {"relay", "relays", "myco+relay", "myco+relays"}
        if addresses and addresses.isdisjoint(relay_schemes):
            relay_payment = ZERO_ADDRESS
            relay_attestation = ZERO_ADDRESS
        plan = self.session_store.create_plan(
            account_id=self.wallet.address,
            consumer=self.wallet.address,
            provider_id=str(peer["peer_id"]),
            provider_payment_address=normalize_address(str(peer["payment_address"])),
            provider_route=peer,
            deployment=SessionDeployment(
                **{
                    **deployment.__dict__,
                    "relay_payment_address": relay_payment,
                    "relay_attestation_address": relay_attestation,
                }
            ).normalized(),
            relay_payment_address=relay_payment,
            relay_attestation_address=relay_attestation,
            max_amount_units=(
                int(max_amount_units)
                if max_amount_units is not None
                else self.config.session_max_amount_units
            ),
            expires_at=int(time.time()) + self.config.session_lifetime_seconds,
        )
        plan.update(
            {
                "enabled": True,
                "settlement_version": int(deployment.protocol_version),
                "protocol_version": int(deployment.protocol_version),
                "provider_addresses": _peer_addresses(peer),
                "provider": peer,
                "request_deadline": int(plan["expires_at"]),
                "activation_required": True,
            }
        )
        return plan

    def infer(
        self,
        *,
        endpoint: str,
        model: str,
        input_value: Any,
        max_output_tokens: int,
        envelope: dict[str, Any] | None,
        request_options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.wallet is None:
            raise LocalConsumerAPIError(409, "wallet_not_configured", "configure a wallet before inference")
        if self.session_store is None:
            raise LocalConsumerAPIError(503, "session_store_unavailable", "local Session store is unavailable")
        if not isinstance(envelope, dict):
            raise LocalConsumerAPIError(
                409,
                "session_required",
                "prepare and activate a local V5/V6 Session, then send its session_id",
            )
        session_id = str(envelope.get("session_id") or "").strip()
        if not session_id:
            nested = envelope.get("request")
            session_id = str(nested.get("session_id") or "").strip() if isinstance(nested, dict) else ""
        if not session_id:
            raise LocalConsumerAPIError(422, "session_id_required", "mycomesh_session.session_id is required")
        plan = self.session_store.get(session_id)
        if plan is None or str(plan.get("consumer_payment_address") or "").lower() != self.wallet.address.lower():
            raise LocalConsumerAPIError(409, "session_wallet_mismatch", "the local Session is not bound to this wallet")
        try:
            self._verify_local_session(plan)
        except (ChainError, SessionServiceError) as exc:
            raise LocalConsumerAPIError(409, "session_not_active", str(exc)) from exc
        if max_output_tokens > self.network.reserve_output_tokens:
            raise LocalConsumerAPIError(
                422,
                "invalid_request",
                f"max_output_tokens must be between 1 and {self.network.reserve_output_tokens}",
            )
        try:
            request_hash = inference_request_hash(
                endpoint=endpoint,
                model=model,
                input_value=input_value if endpoint == "responses" else None,
                messages=input_value if endpoint == "chat" else None,
                max_output_tokens=max_output_tokens,
                options=request_options,
            )
        except ReservationError as exc:
            raise LocalConsumerAPIError(422, "invalid_request", str(exc)) from exc
        request_id = str(envelope.get("request_id") or uuid.uuid4().hex)
        try:
            completed = self.session_store.completed_response(
                session_id=session_id,
                request_id=request_id,
                account_id=self.wallet.address,
                request_hash="0x" + request_hash,
            )
        except SessionServiceError as exc:
            raise LocalConsumerAPIError(409, "session_request_rejected", str(exc)) from exc
        if completed is not None:
            return completed
        pricing = load_pricing_config(str(self.config.pricing_config_path) if self.config.pricing_config_path else None)
        quote = quote_usage(
            plan["channel"],
            {"input_tokens": self.network.reserve_input_bytes, "output_tokens": max_output_tokens},
            pricing_table=pricing,
        )
        max_fee_units = max(1, int(Decimal(str(quote.gross_fee)) * Decimal("1000000") * Decimal("1.25")))
        deadline = int(envelope.get("deadline") or min(int(plan["expires_at"]), int(time.time()) + 300))
        claim: SessionClaim | None = None
        for attempt in range(2):
            try:
                claim = self.session_store.claim_request(
                    session_id=session_id,
                    account_id=self.wallet.address,
                    request_id=request_id,
                    request_hash="0x" + request_hash,
                    max_fee_units=min(max_fee_units, int(plan["max_amount_units"])),
                    deadline=deadline,
                    signer=self.identity,
                )
                break
            except SessionServiceError as exc:
                if _session_request_in_flight(exc):
                    raise LocalConsumerAPIError(
                        503,
                        "consumer_request_in_flight",
                        _CONSUMER_REQUEST_IN_FLIGHT_MESSAGE,
                        headers={"Retry-After": "5"},
                    ) from exc
                if _session_claim_requires_recovery(exc):
                    stale_claim = self.session_store.request_claim_state(session_id)
                    if (
                        attempt == 0
                        and stale_claim is not None
                        and bool(stale_claim.get("stale"))
                        and str(stale_claim.get("request_id") or "") != request_id
                    ):
                        recovered = self._recover_stale_session_claim(
                            plan=plan,
                            claim_state=stale_claim,
                            model=model,
                        )
                        if (
                            recovered is not None
                            and str(stale_claim.get("request_hash") or "").lower()
                            == ("0x" + request_hash).lower()
                        ):
                            return recovered
                        plan = self.session_store.get(session_id)
                        if plan is None:
                            raise LocalConsumerAPIError(
                                409,
                                "session_required",
                                "the local Session is no longer available",
                            )
                        continue
                    raise LocalConsumerAPIError(
                        503,
                        "consumer_request_in_flight",
                        _CONSUMER_REQUEST_IN_FLIGHT_MESSAGE,
                        headers={"Retry-After": "5"},
                    ) from exc
                raise LocalConsumerAPIError(
                    409,
                    "consumer_request_rejected",
                    "The local Consumer could not prepare this request.",
                ) from exc
        if claim is None:  # pragma: no cover - the bounded loop either returns or raises
            raise LocalConsumerAPIError(503, "consumer_request_in_flight", _CONSUMER_REQUEST_IN_FLIGHT_MESSAGE)
        try:
            peer = self._session_provider(claim.plan, model=model)
        except (ChainError, LocalConsumerError, SessionServiceError, StopIteration, TypeError, ValueError) as exc:
            self.session_store.rollback(session_id, sequence=int(claim.request["sequence"]))
            raise LocalConsumerAPIError(503, "provider_unavailable", _PROVIDER_UNAVAILABLE_MESSAGE) from exc
        request_dispatched = False
        route_refreshed = False
        started = time.monotonic()
        try:
            while True:
                try:
                    response, route_address = self._send_session_request(
                        peer=peer,
                        endpoint=endpoint,
                        model=model,
                        input_value=input_value,
                        max_output_tokens=max_output_tokens,
                        claim=claim,
                        request_options=request_options,
                    )
                    request_dispatched = True
                    break
                except LocalConsumerError as exc:
                    if route_refreshed or not _provider_route_refresh_required(exc):
                        raise
                    peer = self._refresh_session_provider(
                        session_id=session_id,
                        provider_id=str(claim.plan["provider_id"]),
                        provider_payment_address=str(claim.plan["provider_payment_address"]),
                        model=model,
                    )
                    self._validate_peer_binding(peer)
                    route_refreshed = True
            verify_provider_response(
                response,
                peer,
                audience=self.identity.public_key,
                expected_request_id=request_id,
                expected_request_hash="0x" + request_hash,
                expected_channel=str(claim.request["channel"]),
                expected_network_id=str(claim.request["network_id"]),
                expected_channel_id=str(claim.request["channel_id"]),
                expected_backend_policy=str(claim.request["backend_policy"]),
                expected_model=model,
                expected_endpoint=endpoint,
            )
            actual_quote = quote_usage(plan["channel"], response.get("usage") if isinstance(response, dict) else None, pricing_table=pricing)
            amount_units = max(1, int(Decimal(str(actual_quote.gross_fee)) * Decimal("1000000")))
            if amount_units > int(claim.request["max_fee_units"]):
                raise LocalConsumerError("Provider usage exceeded the local Session request cap")
            payload = dict(response)
            payload["mycomesh_price"] = actual_quote.to_dict()
            payload["mycomesh_session"] = {
                "session_id": session_id,
                "protocol_version": int(claim.plan.get("protocol_version") or 5),
                "sequence": int(claim.request["sequence"]),
                "cumulative_spend_units": int(claim.previous_cumulative_spend_units + amount_units),
                "settlement": "provider-signed",
            }
            settlement = payload.get(f"mycomesh_v{int(claim.plan.get('protocol_version') or 5)}_settlement")
            self.session_store.finalize(
                session_id,
                sequence=int(claim.request["sequence"]),
                amount_units=amount_units,
                request_hash="0x" + request_hash,
                response_payload=payload,
                settlement_payload=settlement if isinstance(settlement, dict) else None,
            )
            self._submit_settlement_to_relay(
                route_address=route_address,
                response=payload,
                session_private_key=claim.private_key,
            )
            with self._route_lock:
                record_route_success(self.route_state, str(peer["peer_id"]), int((time.monotonic() - started) * 1000))
                save_route_state(self.route_state, self.config.route_state_path)
            return payload
        except (ProtocolValidationError, LocalConsumerError, ChainError, SessionServiceError, ValueError) as exc:
            if not (request_dispatched or _session_v5_claim_should_be_retained(exc)):
                try:
                    self.session_store.rollback(session_id, sequence=int(claim.request["sequence"]))
                except Exception:
                    pass
            with self._route_lock:
                record_route_failure(self.route_state, str(peer.get("peer_id") or "unknown"), exc)
                save_route_state(self.route_state, self.config.route_state_path)
            if isinstance(exc, LocalConsumerAPIError):
                raise
            if _session_execution_requires_recovery(exc):
                raise LocalConsumerAPIError(
                    503,
                    "consumer_request_in_flight",
                    _CONSUMER_REQUEST_IN_FLIGHT_MESSAGE,
                    headers={"Retry-After": "5"},
                ) from exc
            if _session_v5_sequence_conflict(exc):
                raise LocalConsumerAPIError(
                    503,
                    "consumer_request_in_flight",
                    _CONSUMER_REQUEST_IN_FLIGHT_MESSAGE,
                    headers={"Retry-After": "5"},
                ) from exc
            raise LocalConsumerAPIError(502, "provider_unavailable", _PROVIDER_UNAVAILABLE_MESSAGE) from exc

    def _send_session_status(
        self,
        *,
        peer: dict[str, Any],
        claim: SessionClaim,
    ) -> tuple[dict[str, Any], str]:
        errors: list[str] = []
        lease_id: str | None = None
        try:
            with self._route_lock:
                lease_id = reserve_peer(self.route_state, peer, ttl_seconds=60)
                save_route_state(self.route_state, self.config.route_state_path)
            for address in _peer_addresses(peer):
                try:
                    return _send_session_status_to_address(
                        address=address,
                        peer_id=str(peer["peer_id"]),
                        identity=self.identity,
                        provider_public_key=str(peer["public_key"]),
                        provider_transport_key=dict(peer["transport_key"]),
                        timeout=min(self.config.request_timeout_seconds, 30.0),
                        protocol_version=int(claim.plan.get("protocol_version") or 5),
                        channel=str(claim.request["channel"]),
                        network_id=str(claim.request["network_id"]),
                        channel_id=str(claim.request["channel_id"]),
                        backend_policy=str(claim.request["backend_policy"]),
                        session_authorization=claim.authorization,
                        session_request=claim.request,
                        relay_attestation_address=str(
                            claim.plan.get("relay_attestation_address") or ZERO_ADDRESS
                        ),
                    ), address
                except Exception as exc:
                    errors.append(f"{address}: {exc}")
            raise LocalConsumerError("all Provider status routes failed: " + "; ".join(errors))
        finally:
            with self._route_lock:
                release_peer(self.route_state, lease_id)
                save_route_state(self.route_state, self.config.route_state_path)

    def _recover_stale_session_claim(
        self,
        *,
        plan: dict[str, Any],
        claim_state: dict[str, Any],
        model: str,
    ) -> dict[str, Any] | None:
        session_id = str(plan["session_id"])
        try:
            claim = self.session_store.claim_request(
                session_id=session_id,
                account_id=self.wallet.address,
                request_id=str(claim_state["request_id"]),
                request_hash=str(claim_state["request_hash"]),
                max_fee_units=int(claim_state["max_fee_units"]),
                deadline=min(int(plan["expires_at"]), int(time.time()) + 300),
                signer=self.identity,
            )
            peer = self._session_provider(claim.plan, model=model)
            status, route_address = self._send_session_status(peer=peer, claim=claim)
        except (ChainError, LocalConsumerError, SessionServiceError, StopIteration, TypeError, ValueError) as exc:
            logger.warning("Provider Session recovery query failed: %s", exc)
            raise LocalConsumerAPIError(
                503,
                "provider_unavailable",
                _PROVIDER_UNAVAILABLE_MESSAGE,
                headers={"Retry-After": "5"},
            ) from exc
        state = str(status.get("status") or "")
        if state in {"absent", "aborted"}:
            self.session_store.rollback(session_id, sequence=int(claim.request["sequence"]))
            logger.info("Recovered stale Consumer request as %s", state)
            return
        if state == "pending":
            raise LocalConsumerAPIError(
                503,
                "consumer_request_in_flight",
                _CONSUMER_REQUEST_IN_FLIGHT_MESSAGE,
                headers={"Retry-After": "5"},
            )
        response = status.get("response")
        if state != "completed" or not isinstance(response, dict):
            raise LocalConsumerAPIError(503, "provider_unavailable", _PROVIDER_UNAVAILABLE_MESSAGE)
        try:
            expected_model = str(response.get("model") or self.network.public_model_id)
            expected_endpoint = str(response.get("endpoint") or "responses")
            verify_provider_response(
                response,
                peer,
                audience=self.identity.public_key,
                expected_request_id=str(claim.request["request_id"]),
                expected_request_hash=str(claim.request["request_hash"]),
                expected_channel=str(claim.request["channel"]),
                expected_network_id=str(claim.request["network_id"]),
                expected_channel_id=str(claim.request["channel_id"]),
                expected_backend_policy=str(claim.request["backend_policy"]),
                expected_model=expected_model,
                expected_endpoint=expected_endpoint,
            )
            pricing = load_pricing_config(
                str(self.config.pricing_config_path) if self.config.pricing_config_path else None
            )
            actual_quote = quote_usage(
                plan["channel"],
                response.get("usage") if isinstance(response.get("usage"), dict) else None,
                pricing_table=pricing,
            )
            amount_units = max(1, int(Decimal(str(actual_quote.gross_fee)) * Decimal("1000000")))
            if amount_units > int(claim.request["max_fee_units"]):
                raise LocalConsumerError("Provider usage exceeded the recovered Session request cap")
            payload = dict(response)
            payload["mycomesh_price"] = actual_quote.to_dict()
            payload["mycomesh_session"] = {
                "session_id": session_id,
                "protocol_version": int(claim.plan.get("protocol_version") or 5),
                "sequence": int(claim.request["sequence"]),
                "cumulative_spend_units": int(claim.previous_cumulative_spend_units + amount_units),
                "settlement": "provider-signed",
            }
            settlement = payload.get(
                f"mycomesh_v{int(claim.plan.get('protocol_version') or 5)}_settlement"
            )
            self.session_store.finalize(
                session_id,
                sequence=int(claim.request["sequence"]),
                amount_units=amount_units,
                request_hash=str(claim.request["request_hash"]),
                response_payload=payload,
                settlement_payload=settlement if isinstance(settlement, dict) else None,
            )
            self._submit_settlement_to_relay(
                route_address=route_address,
                response=payload,
                session_private_key=claim.private_key,
            )
            logger.info("Recovered a completed Consumer request from the Provider cache")
            return payload
        except (ProtocolValidationError, LocalConsumerError, ChainError, SessionServiceError, ValueError) as exc:
            logger.warning("Provider Session recovery response was invalid: %s", exc)
            raise LocalConsumerAPIError(503, "provider_unavailable", _PROVIDER_UNAVAILABLE_MESSAGE) from exc

    def _send_session_request(
        self,
        *,
        peer: dict[str, Any],
        endpoint: str,
        model: str,
        input_value: Any,
        max_output_tokens: int,
        claim: SessionClaim,
        request_options: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str]:
        errors: list[str] = []
        lease_id: str | None = None
        try:
            with self._route_lock:
                lease_id = reserve_peer(
                    self.route_state,
                    peer,
                    ttl_seconds=max(60, min(int(self.config.request_timeout_seconds) + 30, 3600)),
                )
                save_route_state(self.route_state, self.config.route_state_path)
        except ValueError as exc:
            raise LocalConsumerError(str(exc)) from exc
        try:
            for address in _peer_addresses(peer):
                try:
                    return _send_infer_to_address(
                        address=address,
                        channel=str(claim.request["channel"]),
                        endpoint=endpoint,
                        model=model,
                        input_value=input_value,
                        pool_url=str(peer.get("pool_url") or self.discovery_urls[0]),
                        peer_id=str(peer["peer_id"]),
                        timeout=self.config.request_timeout_seconds,
                        identity=self.identity,
                        consumer_id=self.wallet.address if self.wallet else None,
                        consumer_payment_address=self.wallet.address if self.wallet else None,
                        provider_payment_address=str(peer.get("payment_address") or ""),
                        provider_public_key=str(peer.get("public_key") or "") or None,
                        provider_transport_key=peer.get("transport_key") if isinstance(peer.get("transport_key"), dict) else None,
                        max_fee_units=int(claim.request["max_fee_units"]),
                        max_output_tokens=max_output_tokens,
                        settlement_version=int(claim.plan.get("protocol_version") or 5),
                        pricing_version=int(claim.request["pricing_version"]),
                        settlement_chain_id=int(claim.authorization["settlement_chain_id"]),
                        settlement_contract=str(claim.authorization["settlement_contract"]),
                        network_id=str(claim.request["network_id"]),
                        channel_id=str(claim.request["channel_id"]),
                        backend_policy=str(claim.request["backend_policy"]),
                        request_id=str(claim.request["request_id"]),
                        session_authorization=claim.authorization,
                        session_request=claim.request,
                        session_private_key=claim.private_key,
                        relay_attestation_address=str(claim.plan.get("relay_attestation_address") or ZERO_ADDRESS),
                        request_options=request_options,
                    ), address
                except Exception as exc:
                    errors.append(f"{address}: {exc}")
            raise LocalConsumerError("all Provider routes failed: " + "; ".join(errors))
        finally:
            with self._route_lock:
                release_peer(self.route_state, lease_id)
                save_route_state(self.route_state, self.config.route_state_path)

    def _submit_settlement_to_relay(
        self,
        *,
        route_address: str,
        response: dict[str, Any],
        session_private_key: str,
    ) -> None:
        """Forward the completed, Consumer-signed V5 receipt to the Relay.

        The inference response is already durable in the local Session store
        before this best-effort network hop.  A Relay outage therefore leaves
        the signed result locally available for a later retry instead of
        failing an otherwise completed model request.
        """

        try:
            relay_address = parse_relay_address(route_address)
        except (TypeError, ValueError):
            return
        protocol_version = int(response.get("mycomesh_session", {}).get("protocol_version") or 5)
        provider_payload = response.get(f"mycomesh_v{protocol_version}_settlement")
        if not isinstance(provider_payload, dict):
            logger.warning("Relay route returned no V5/V6 Provider settlement payload")
            return
        try:
            verify_payload = verify_provider_settlement_payload_v6 if protocol_version == 6 else verify_provider_settlement_payload_v5
            digest_builder = session_receipt_digest_v6 if protocol_version == 6 else session_receipt_digest_v5
            receipt = verify_payload(provider_payload)
            digest = digest_builder(
                receipt,
                chain_id=int(provider_payload["chain_id"]),
                verifying_contract=str(provider_payload["settlement_contract"]),
            )
            signature = sign_evm_digest(session_private_key, digest)
            session_signature = (
                "0x"
                + signature.r[2:].zfill(64)
                + signature.s[2:].zfill(64)
                + f"{int(signature.v):02x}"
            )
            attestation = response.get("_mycomesh_relay_attestation") or response.get("relay_attestation")
            submission = {
                "schema": "mycomesh.relay.settlement.v1",
                "protocol_version": protocol_version,
                "chain_id": int(provider_payload["chain_id"]),
                "settlement_contract": str(provider_payload["settlement_contract"]),
                "provider_settlement": provider_payload,
                "session_signature": session_signature,
                "relay_attestation": attestation,
            }
            submit_relay_settlement(
                relay_address,
                submission,
                timeout=min(self.config.request_timeout_seconds, 30.0),
            )
        except (ChainError, RelayError, TypeError, ValueError, KeyError) as exc:
            logger.warning("Relay settlement submission deferred: %s", exc)

    def _verify_local_session(self, plan: dict[str, Any]) -> None:
        if int(plan.get("protocol_version") or 5) not in {5, 6}:
            raise SessionServiceError("local session is not Settlement V5 or V6")
        verify_opened_session(
            rpc_url=self.network.settlement_rpc_url,
            contract=str(plan["settlement_contract"]),
            plan=plan,
            timeout=min(self.config.request_timeout_seconds, 30.0),
        )
        if self.session_store is not None:
            self.session_store.mark_activated(str(plan["session_id"]))

    def status_payload(self) -> dict[str, Any]:
        if self.wallet is None:
            state = "needs_wallet"
            blockers = [
                {
                    "code": "wallet_not_configured",
                    "detail": "Connect a browser wallet or configure the public address that owns the prepaid balance.",
                },
                {
                    "code": "session_not_activated",
                    "detail": "The local Consumer will prepare and route Settlement V5/V6 sessions after the wallet is connected.",
                },
            ]
            next_action = {
                "code": "configure_external_wallet",
                "command": (
                    "docker compose --profile consumer exec consumer "
                    "python -m gateway.local_consumer init-wallet --address 0xYOUR_WALLET"
                ),
            }
        else:
            if self.session_ready:
                state = "ready"
                blockers = []
                next_action = {
                    "code": "use_local_proxy",
                        "detail": "The local Consumer is ready to route requests through an activated Settlement V5/V6 session.",
                }
            else:
                state = "needs_session"
                blockers = [
                    {
                        "code": "session_not_activated",
                        "detail": "Prepare a local V5/V6 Session, deposit prepaid funds, then confirm openSession in the wallet.",
                    },
                    {
                        "code": "provider_discovery_required",
                        "detail": "Provider discovery uses the configured Bridge/Relay list and has no fixed Gateway dependency.",
                    },
                ]
                next_action = {
                    "code": "prepare_local_session",
                    "command": (
                        "curl -sS -X POST http://127.0.0.1:8110/v1/mycomesh/session/prepare "
                        "-H 'Authorization: Bearer <local-key>' "
                        "-H 'Content-Type: application/json' "
                        "-d '{\"model\":\"mycomesh-codex-standard-v1\",\"max_output_tokens\":256}'"
                    ),
                }
        deployment = self.network.deployment
        return {
            "schema": LOCAL_STATUS_SCHEMA,
            "service": "mycomesh-local-consumer",
            "state": state,
            "inference_ready": self.session_ready,
            "browser_app_ready": self.browser_app_ready,
            "browser_app_url": self.browser_app_url,
            "gateway_dependency": False,
            "routing_mode": f"local-p2p-bridge-relay-settlement-v{int(deployment.protocol_version)}",
            "api": {
                "base_url": self.config.public_base_url,
                "key_fingerprint": self.api_key_fingerprint,
                "credentials_command": (
                    "docker compose --profile consumer exec consumer "
                    "python -m gateway.local_consumer credentials"
                ),
            },
            "identity": {
                "peer_id": self.identity.peer_id,
                "public_key": self.identity.public_key,
            },
            "wallet": {
                "configured": self.wallet is not None,
                "address": self.wallet.address if self.wallet is not None else None,
                "signing_mode": self.wallet.signing_mode if self.wallet is not None else None,
                "private_key_stored": False,
            },
            "network": {
                "network_id": self.network.network_id,
                "channel_id": self.network.channel_id,
                "channel": deployment.channel,
                "backend_policy": self.network.backend_policy,
                "model": self.network.public_model_id,
                "discovery_urls": list(self.discovery_urls),
                "bridge_urls": list(self.discovery_urls),
                "relay_url": self.network.relay_public_url,
            },
            "settlement": {
                "version": int(deployment.protocol_version),
                "chain_id": deployment.chain_id,
                "contract": deployment.settlement,
                "pricing_version": deployment.pricing_version,
                "pricing_hash": deployment.pricing_hash,
                "session_store": str(self.config.session_db_path),
                "provider_cache": str(self.config.peer_cache_path),
            },
            "blockers": blockers,
            "next_action": next_action,
        }


def bootstrap_local_consumer(
    config: LocalConsumerConfig | None = None,
) -> LocalConsumerState:
    resolved = config or LocalConsumerConfig.from_env()
    _secure_data_directory(resolved.data_dir)
    try:
        network = load_provider_network_config(resolved.network_config_path)
    except (OSError, ProviderBootstrapError, TypeError, ValueError) as exc:
        raise LocalConsumerError(f"published Consumer network config is invalid: {exc}") from exc
    api_key = _load_or_create_api_key(resolved.api_key_path)
    identity = _load_or_create_consumer_identity(resolved.identity_path)
    session_secret = _load_or_create_session_secret(resolved.session_secret_path)
    try:
        session_store = SessionV4Store(resolved.session_db_path, secret=session_secret)
    except SessionServiceError as exc:
        raise LocalConsumerError(f"local Consumer Session store is invalid: {exc}") from exc
    wallet = (
        _load_wallet(resolved.wallet_path)
        if resolved.wallet_path.exists() or resolved.wallet_path.is_symlink()
        else None
    )
    return LocalConsumerState(
        config=resolved,
        network=network,
        identity=identity,
        api_key=api_key,
        wallet=wallet,
        session_store=session_store,
        route_state=load_route_state(resolved.route_state_path),
        peer_cache=_load_peer_cache(resolved.peer_cache_path),
    )


def create_app(
    config: LocalConsumerConfig | None = None,
    *,
    state: LocalConsumerState | None = None,
) -> FastAPI:
    local_state = state or bootstrap_local_consumer(config)
    app = FastAPI(
        title="MycoMesh Local Consumer",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.local_consumer = local_state
    app.add_middleware(
        BoundedRequestBodyMiddleware,
        limit=local_state.config.max_request_bytes,
        timeout_seconds=local_state.config.request_body_timeout_seconds,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost"],
    )

    @app.exception_handler(LocalConsumerAPIError)
    async def local_api_error_handler(
        _request: Request,
        exc: LocalConsumerAPIError,
    ) -> JSONResponse:
        return _openai_error_response(
            exc.status_code,
            exc.code,
            exc.message,
            headers=exc.headers,
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        status = local_state.status_payload()
        return {
            "ok": True,
            "service": "mycomesh-local-consumer",
            "state": status["state"],
            "inference_ready": status["inference_ready"],
            "browser_app_ready": local_state.browser_app_ready,
            "gateway_dependency": False,
        }

    @app.get("/ready")
    async def ready() -> JSONResponse:
        status = local_state.status_payload()
        status_code = 200 if status["inference_ready"] else 503
        return JSONResponse(
            status_code=status_code,
            content={
                "ok": status["inference_ready"],
                "service": "mycomesh-local-consumer",
                "state": status["state"],
                "inference_ready": status["inference_ready"],
                "blockers": [str(item["code"]) for item in status["blockers"]],
            },
        )

    @app.get("/v1/models")
    async def models() -> dict[str, Any]:
        # Model metadata is intentionally public on the loopback edge so the
        # bundled Playground can initialize before a user pastes its local key.
        # Session preparation and inference remain Bearer-authenticated.
        return {
            "object": "list",
            "data": [
                {
                    "id": local_state.network.public_model_id,
                    "object": "model",
                    "created": 0,
                    "owned_by": "mycomesh",
                }
            ],
        }

    @app.get("/v1/mycomesh/local/status")
    async def local_status(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_api_key(local_state, authorization)
        return local_state.status_payload()

    @app.get("/v1/mycomesh/local/credentials")
    async def local_credentials() -> JSONResponse:
        # This endpoint is reachable only through the loopback TrustedHost
        # boundary. It lets the bundled UI bootstrap its volume-local key; it
        # is never exposed by a public Gateway and is marked non-cacheable.
        return JSONResponse(
            _credentials_payload(local_state),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @app.get("/v1/mycomesh/local/peers")
    async def local_peers() -> dict[str, Any]:
        try:
            peers = await asyncio.to_thread(local_state.discover_peers)
        except LocalConsumerError as exc:
            raise LocalConsumerAPIError(503, "provider_discovery_failed", str(exc)) from exc
        return {
            "ok": True,
            "protocol": "mycomesh-p2p/0.2",
            "source": "local-consumer-discovery",
            "discovery_urls": list(local_state.discovery_urls),
            "peers": peers,
        }

    @app.put("/v1/mycomesh/local/wallet")
    async def configure_wallet(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_api_key(local_state, authorization)
        try:
            payload = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise LocalConsumerAPIError(400, "invalid_json", "request body must be JSON") from exc
        if not isinstance(payload, dict) or set(payload) != {"address", "signing_mode"}:
            raise LocalConsumerAPIError(
                422,
                "invalid_wallet_config",
                "wallet config must contain exactly address and signing_mode",
            )
        if payload.get("signing_mode") != "external":
            raise LocalConsumerAPIError(
                422,
                "invalid_wallet_config",
                "only the external signing mode is supported; private keys are not accepted",
            )
        try:
            wallet = local_state.configure_external_wallet(payload.get("address"))
        except LocalConsumerError as exc:
            status_code = 409 if local_state.wallet is not None else 422
            raise LocalConsumerAPIError(
                status_code,
                "wallet_configuration_rejected",
                str(exc),
            ) from exc
        return {
            "wallet": {
                "address": wallet.address,
                "signing_mode": wallet.signing_mode,
                "private_key_stored": False,
            },
            "status": local_state.status_payload(),
        }

    @app.post("/v1/mycomesh/session/prepare")
    async def prepare_session(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_api_key(local_state, authorization)
        try:
            payload = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise LocalConsumerAPIError(400, "invalid_json", "request body must be JSON") from exc
        if not isinstance(payload, dict):
            raise LocalConsumerAPIError(422, "invalid_session_request", "request body must be an object")
        endpoint = str(payload.get("endpoint") or "responses").strip().lower()
        if endpoint not in {"responses", "chat"}:
            raise LocalConsumerAPIError(422, "invalid_session_request", "endpoint must be responses or chat")
        model = str(payload.get("model") or local_state.network.public_model_id).strip()
        try:
            max_output_tokens = int(
                payload.get("max_output_tokens")
                or payload.get("max_tokens")
                or payload.get("max_completion_tokens")
                or local_state.network.reserve_output_tokens
            )
        except (TypeError, ValueError) as exc:
            raise LocalConsumerAPIError(422, "invalid_session_request", "max_output_tokens must be an integer") from exc
        max_amount_units: int | None = None
        if payload.get("max_amount_units") is not None:
            try:
                max_amount_units = int(payload.get("max_amount_units"))
            except (TypeError, ValueError) as exc:
                raise LocalConsumerAPIError(422, "invalid_session_request", "max_amount_units must be an integer") from exc
        try:
            plan = await asyncio.to_thread(
                local_state.prepare_session,
                model=model,
                max_output_tokens=max_output_tokens,
                provider_id=(str(payload.get("provider_id") or "").strip() or None),
                max_amount_units=max_amount_units,
            )
        except LocalConsumerError as exc:
            raise LocalConsumerAPIError(503, "session_preparation_failed", str(exc)) from exc
        return plan

    @app.get("/v1/mycomesh/session/{session_id}")
    async def session_status(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_api_key(local_state, authorization)
        if local_state.session_store is None:
            raise LocalConsumerAPIError(503, "session_store_unavailable", "local Session store is unavailable")
        plan = local_state.session_store.get(session_id)
        if plan is None:
            raise LocalConsumerAPIError(404, "session_not_found", "local Session was not found")
        if local_state.wallet is None or str(plan.get("consumer_payment_address") or "").lower() != local_state.wallet.address.lower():
            raise LocalConsumerAPIError(403, "session_wallet_mismatch", "local Session is bound to another wallet")
        active = False
        activation_error = None
        try:
            local_state._verify_local_session(plan)
            active = True
        except (ChainError, SessionServiceError) as exc:
            activation_error = str(exc)
        return {"plan": plan, "active": active, "activation_error": activation_error}

    @app.post("/responses", response_model=None)
    @app.post("/responses/compact", response_model=None)
    @app.post("/v1/responses", response_model=None)
    @app.post("/v1/responses/compact", response_model=None)
    @app.post("/v1/v1/responses", response_model=None)
    @app.post("/v1/v1/responses/compact", response_model=None)
    async def responses(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse | StreamingResponse:
        _require_api_key(local_state, authorization)
        if local_state.wallet is None:
            return _not_ready_response(local_state)
        body = await _request_json_body(request)
        try:
            model = _network_model(local_state, body.get("model"))
            request_options = _responses_request_options(body)
            max_output_tokens = _body_output_tokens(body, local_state.network.reserve_output_tokens)
            output = await asyncio.to_thread(
                local_state.infer,
                endpoint="responses",
                model=model,
                input_value=body.get("input", ""),
                max_output_tokens=max_output_tokens,
                envelope=_openai_session_envelope(
                    local_state,
                    body,
                    max_output_tokens=max_output_tokens,
                ),
                request_options=request_options,
            )
        except LocalConsumerAPIError:
            raise
        output = _local_responses_response(output)
        if body.get("stream") is True:
            return StreamingResponse(_local_responses_sse(output), media_type="text/event-stream")
        return JSONResponse(output)

    @app.post("/v1/chat/completions", response_model=None)
    async def chat_completions(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse | StreamingResponse:
        _require_api_key(local_state, authorization)
        if local_state.wallet is None:
            return _not_ready_response(local_state)
        body = await _request_json_body(request)
        try:
            model = _network_model(local_state, body.get("model"))
            max_output_tokens = _body_output_tokens(body, local_state.network.reserve_output_tokens)
            output = await asyncio.to_thread(
                local_state.infer,
                endpoint="chat",
                model=model,
                input_value=body.get("messages", []),
                max_output_tokens=max_output_tokens,
                envelope=_openai_session_envelope(
                    local_state,
                    body,
                    max_output_tokens=max_output_tokens,
                ),
            )
        except LocalConsumerAPIError:
            raise
        if body.get("stream") is True:
            return StreamingResponse(_local_chat_sse(output, model), media_type="text/event-stream")
        return JSONResponse(_local_chat_response(output, model))

    @app.get("/assets/{asset_path:path}", include_in_schema=False)
    async def browser_asset(asset_path: str):
        root = local_state.config.web_dist_dir
        if not local_state.browser_app_ready or root is None:
            return JSONResponse(status_code=404, content={"detail": "not found"})
        asset_root = (root / "assets").resolve()
        candidate = (asset_root / asset_path).resolve()
        try:
            candidate.relative_to(asset_root)
        except ValueError:
            return JSONResponse(status_code=404, content={"detail": "not found"})
        if not candidate.is_file() or candidate.is_symlink():
            return JSONResponse(status_code=404, content={"detail": "not found"})
        return FileResponse(
            candidate,
            headers={
                **_browser_security_headers(),
                "Cache-Control": "public, max-age=31536000, immutable",
            },
        )

    @app.get("/", include_in_schema=False)
    async def browser_root() -> RedirectResponse:
        return RedirectResponse(
            "/app/playground",
            status_code=307,
            headers=_browser_security_headers(),
        )

    @app.get("/app", include_in_schema=False)
    @app.get("/app/{app_path:path}", include_in_schema=False)
    async def browser_app(app_path: str = ""):
        del app_path
        root = local_state.config.web_dist_dir
        if not local_state.browser_app_ready or root is None:
            return JSONResponse(status_code=404, content={"detail": "not found"})
        return FileResponse(
            root / "index.html",
            media_type="text/html",
            headers={
                **_browser_security_headers(),
                "Cache-Control": "no-store",
            },
        )

    return app


def _browser_security_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": (
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self' data:; connect-src 'self' https: wss:"
        ),
        "Cross-Origin-Opener-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }


async def _request_json_body(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LocalConsumerAPIError(400, "invalid_json", "request body must be JSON") from exc
    if not isinstance(payload, dict):
        raise LocalConsumerAPIError(422, "invalid_request", "request body must be a JSON object")
    return payload


def _network_model(state: LocalConsumerState, value: Any) -> str:
    requested = str(value or state.network.public_model_id)
    if requested not in {state.network.public_model_id, _CODEX_CLIENT_MODEL_ID}:
        raise LocalConsumerAPIError(
            422,
            "model_not_supported",
            f"model must be {state.network.public_model_id!r}",
        )
    return state.network.public_model_id


def _responses_request_options(payload: dict[str, Any]) -> dict[str, Any]:
    request_fields = {
        "input",
        "max_completion_tokens",
        "max_output_tokens",
        "max_tokens",
        "model",
        "mycomesh_session",
        "stream",
        "stream_options",
        *RESPONSES_REQUEST_OPTION_FIELDS,
    }
    unsupported = sorted(set(payload) - request_fields)
    if unsupported:
        raise LocalConsumerAPIError(
            422,
            "invalid_request",
            "unsupported Responses fields: " + ", ".join(unsupported),
        )
    try:
        return normalize_inference_request_options(
            "responses",
            {
                field: payload[field]
                for field in RESPONSES_REQUEST_OPTION_FIELDS
                if field in payload
            },
        )
    except ReservationError as exc:
        raise LocalConsumerAPIError(422, "invalid_request", str(exc)) from exc


def _body_output_tokens(payload: dict[str, Any], fallback: int) -> int:
    for key in ("max_output_tokens", "max_completion_tokens", "max_tokens"):
        if payload.get(key) is None:
            continue
        try:
            value = int(payload[key])
        except (TypeError, ValueError) as exc:
            raise LocalConsumerAPIError(422, "invalid_request", f"{key} must be an integer") from exc
        if value <= 0:
            raise LocalConsumerAPIError(422, "invalid_request", f"{key} must be positive")
        return value
    return int(fallback)


def _local_chat_response(payload: dict[str, Any], model: str) -> dict[str, Any]:
    if isinstance(payload.get("raw"), dict):
        return dict(payload["raw"])
    if isinstance(payload.get("choices"), list):
        return payload
    content = str(payload.get("output_text") or "")
    return {
        "id": str(payload.get("id") or "chatcmpl_" + uuid.uuid4().hex),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": payload.get("usage") or {},
        **{key: value for key, value in payload.items() if key.startswith("mycomesh_")},
    }


def _local_responses_response(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("raw")
    if not isinstance(raw, dict):
        return payload
    return {
        **raw,
        **{key: value for key, value in payload.items() if key.startswith("mycomesh_")},
    }


async def _local_responses_sse(payload: dict[str, Any]):
    response_id = str(payload.get("id") or payload.get("request_id") or "resp_" + uuid.uuid4().hex)
    completed = dict(payload)
    completed.setdefault("id", response_id)
    completed.setdefault("object", "response")
    completed["status"] = "completed"
    created = {
        "id": response_id,
        "object": "response",
        "status": "in_progress",
        "model": payload.get("model"),
        "output": [],
        "output_text": "",
        "error": None,
        "incomplete_details": None,
    }
    yield _local_sse_event("response.created", {"type": "response.created", "response": created})
    yield _local_sse_event(
        "response.in_progress",
        {"type": "response.in_progress", "response": created},
    )

    text = str(payload.get("output_text") or "")
    output = payload.get("output") if isinstance(payload.get("output"), list) else []
    message_index = next(
        (
            index
            for index, item in enumerate(output)
            if isinstance(item, dict) and item.get("type") == "message"
        ),
        len(output),
    )
    message_item = (
        output[message_index]
        if message_index < len(output) and isinstance(output[message_index], dict)
        else {
            "id": f"msg_{uuid.uuid4().hex}",
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }
    )
    for index, item in enumerate(output):
        if index == message_index or not isinstance(item, dict):
            continue
        yield _local_sse_event(
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "output_index": index,
                "item": {**item, "status": "in_progress"},
            },
        )
        yield _local_sse_event(
            "response.output_item.done",
            {"type": "response.output_item.done", "output_index": index, "item": item},
        )

    message_id = str(message_item.get("id") or f"msg_{uuid.uuid4().hex}")
    content = message_item.get("content") if isinstance(message_item.get("content"), list) else []
    text_index = next(
        (
            index
            for index, part in enumerate(content)
            if isinstance(part, dict) and part.get("type") == "output_text"
        ),
        0,
    )
    text_part = (
        content[text_index]
        if text_index < len(content) and isinstance(content[text_index], dict)
        else {"type": "output_text", "text": text, "annotations": []}
    )
    annotations = text_part.get("annotations") if isinstance(text_part.get("annotations"), list) else []
    yield _local_sse_event(
        "response.output_item.added",
        {
            "type": "response.output_item.added",
            "output_index": message_index,
            "item": {**message_item, "status": "in_progress", "content": []},
        },
    )
    yield _local_sse_event(
        "response.content_part.added",
        {
            "type": "response.content_part.added",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_index,
            "part": {"type": "output_text", "text": "", "annotations": annotations},
        },
    )
    if text:
        yield _local_sse_event(
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "item_id": message_id,
                "output_index": message_index,
                "content_index": text_index,
                "delta": text,
            },
        )
    yield _local_sse_event(
        "response.output_text.done",
        {
            "type": "response.output_text.done",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_index,
            "text": text,
        },
    )
    yield _local_sse_event(
        "response.content_part.done",
        {
            "type": "response.content_part.done",
            "item_id": message_id,
            "output_index": message_index,
            "content_index": text_index,
            "part": {"type": "output_text", "text": text, "annotations": annotations},
        },
    )
    yield _local_sse_event(
        "response.output_item.done",
        {
            "type": "response.output_item.done",
            "output_index": message_index,
            "item": message_item,
        },
    )
    yield _local_sse_event(
        "response.completed",
        {"type": "response.completed", "response": completed},
    )


def _local_sse_event(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


async def _local_chat_sse(payload: dict[str, Any], model: str):
    response = _local_chat_response(payload, model)
    chunk_id = str(response.get("id") or "chatcmpl_" + uuid.uuid4().hex)
    content = ""
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            content = str(message.get("content") or "")
    for chunk in (
        {"id": chunk_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]},
        {"id": chunk_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model, "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]},
        {"id": chunk_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ):
        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"


def _not_ready_response(state: LocalConsumerState) -> JSONResponse:
    return _openai_error_response(
        503,
        "consumer_not_ready",
        "Local Consumer is not ready. Open its local page to add funds or authorize access.",
        headers={"Retry-After": "30"},
    )


def _openai_error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    headers: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    content: dict[str, Any] = {
        "error": {
            "message": message,
            "type": "mycomesh_local_consumer_error",
            "param": None,
            "code": code,
        }
    }
    if extra:
        content.update(extra)
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers=headers,
    )


def _require_api_key(state: LocalConsumerState, authorization: str | None) -> None:
    value = str(authorization or "")
    scheme, separator, token = value.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token:
        raise LocalConsumerAPIError(
            401,
            "invalid_api_key",
            "A local Consumer Bearer API key is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not secrets.compare_digest(token, state.api_key):
        raise LocalConsumerAPIError(
            401,
            "invalid_api_key",
            "The local Consumer API key is invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _load_or_create_api_key(path: Path) -> str:
    if path.exists() or path.is_symlink():
        value = _read_secret_text(path).strip()
        if _API_KEY_PATTERN.fullmatch(value) is None:
            raise LocalConsumerError("local Consumer API key file is malformed")
        _secure_secret_file(path)
        return value
    value = LOCAL_API_KEY_PREFIX + secrets.token_urlsafe(32)
    try:
        _write_new_secret_text(path, value + "\n")
        return value
    except FileExistsError:
        return _load_or_create_api_key(path)


def _load_or_create_consumer_identity(path: Path) -> NodeIdentity:
    if path.exists() or path.is_symlink():
        return _load_consumer_identity(path)
    identity = create_identity()
    try:
        _write_new_secret_json(path, identity.to_dict())
        return identity
    except FileExistsError:
        return _load_consumer_identity(path)


def _load_consumer_identity(path: Path) -> NodeIdentity:
    try:
        payload = json.loads(_read_secret_text(path))
        if not isinstance(payload, dict) or set(payload) != {
            "private_key",
            "public_key",
            "peer_id",
        }:
            raise IdentityError("identity has an invalid shape")
        private_key = str(payload["private_key"])
        public_key = str(payload["public_key"])
        peer_id = str(payload["peer_id"])
        if public_key_from_private_key(private_key) != public_key:
            raise IdentityError("identity public key does not match private key")
        if peer_id_from_public_key(public_key) != peer_id:
            raise IdentityError("identity peer_id does not match public_key")
        identity = NodeIdentity(
            private_key=private_key,
            public_key=public_key,
            peer_id=peer_id,
        )
    except (IdentityError, json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        raise LocalConsumerError(f"local Consumer identity is invalid: {exc}") from exc
    _secure_secret_file(path)
    return identity


def _load_wallet(path: Path) -> LocalWallet:
    _reject_symlink(path, "wallet config")
    try:
        payload = json.loads(_read_secret_text(path))
    except (json.JSONDecodeError, OSError) as exc:
        raise LocalConsumerError(f"local wallet config is invalid: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema", "address", "signing_mode"}:
        raise LocalConsumerError("local wallet config has an invalid shape")
    if payload.get("schema") != LOCAL_WALLET_SCHEMA or payload.get("signing_mode") != "external":
        raise LocalConsumerError("local wallet config has an unsupported schema or signing mode")
    try:
        address = normalize_address(str(payload.get("address") or ""))
    except ChainError as exc:
        raise LocalConsumerError("local wallet config has an invalid address") from exc
    if address == ZERO_ADDRESS:
        raise LocalConsumerError("local wallet config address must be non-zero")
    _secure_secret_file(path)
    return LocalWallet(address=address)


def _load_or_create_session_secret(path: Path) -> str:
    if path.exists() or path.is_symlink():
        value = _read_secret_text(path).strip()
        if len(value) < 32:
            raise LocalConsumerError("local Consumer Session secret is too short")
        _secure_secret_file(path)
        return value
    value = secrets.token_urlsafe(48)
    try:
        _write_new_secret_text(path, value + "\n")
        return value
    except FileExistsError:
        return _load_or_create_session_secret(path)


def _load_peer_cache(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists() and not path.is_symlink():
        return {}
    _reject_symlink(path, "Provider cache")
    try:
        payload = json.loads(_read_secret_text(path))
    except (json.JSONDecodeError, OSError) as exc:
        raise LocalConsumerError(f"local Provider cache is invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise LocalConsumerError("local Provider cache must be a JSON object")
    result: dict[str, dict[str, Any]] = {}
    for peer_id, peer in payload.items():
        if isinstance(peer_id, str) and isinstance(peer, dict):
            result[peer_id] = dict(peer)
    _secure_secret_file(path)
    return result


def _save_peer_cache(path: Path, cache: dict[str, dict[str, Any]]) -> None:
    _reject_symlink(path, "Provider cache")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(cache, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        temp_name = None
    except OSError as exc:
        raise LocalConsumerError(f"could not persist local Provider cache: {exc}") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def _split_discovery_urls(value: str | None) -> tuple[str, ...]:
    entries: list[str] = []
    for raw in str(value or "").split(","):
        candidate = raw.strip().rstrip("/")
        if not candidate:
            continue
        parsed = urlsplit(candidate)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.hostname is None
        ):
            raise LocalConsumerError(
                "MYCOMESH_CONSUMER_DISCOVERY_URLS must contain bare HTTP(S) origins"
            )
        if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
            raise LocalConsumerError(
                "non-loopback Consumer discovery URLs must use HTTPS"
            )
        if candidate not in entries:
            entries.append(candidate)
    return tuple(entries[:16])


def _is_loopback_host(hostname: str) -> bool:
    value = str(hostname).lower().rstrip(".")
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _bounded_int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else int(default)
    except ValueError as exc:
        raise LocalConsumerError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise LocalConsumerError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.getenv(name)
    try:
        value = float(raw) if raw is not None else float(default)
    except ValueError as exc:
        raise LocalConsumerError(f"{name} must be a number") from exc
    if value < minimum or value > maximum:
        raise LocalConsumerError(f"{name} must be between {minimum} and {maximum}")
    return value


def _secure_data_directory(path: Path) -> None:
    if path.is_symlink():
        raise LocalConsumerError("local Consumer data directory must not be a symbolic link")
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.is_dir():
            raise LocalConsumerError("local Consumer data path must be a directory")
        path.chmod(0o700)
    except OSError as exc:
        raise LocalConsumerError(f"could not secure local Consumer data directory: {exc}") from exc


def _write_new_secret_json(path: Path, value: dict[str, Any]) -> None:
    _write_new_secret_text(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
    )


def _write_new_secret_text(path: Path, value: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def _read_secret_text(path: Path) -> str:
    _reject_symlink(path, "secret file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LocalConsumerError(f"could not read local Consumer secret file: {exc}") from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise LocalConsumerError("local Consumer secret path must be a regular file")
        if file_stat.st_size > 64 * 1024:
            raise LocalConsumerError("local Consumer secret file is too large")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read(64 * 1024 + 1)
    finally:
        if fd >= 0:
            os.close(fd)


def _secure_secret_file(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LocalConsumerError(f"could not secure local Consumer secret file: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise LocalConsumerError("local Consumer secret path must be a regular file")
        os.fchmod(fd, 0o600)
    except OSError as exc:
        raise LocalConsumerError(f"could not secure local Consumer secret file: {exc}") from exc
    finally:
        os.close(fd)


def _reject_symlink(path: Path, label: str) -> None:
    if path.is_symlink():
        raise LocalConsumerError(f"local {label} must not be a symbolic link")


def _local_base_url(value: Any) -> str:
    resolved = str(value or "").strip().rstrip("/")
    parsed = urlsplit(resolved)
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1"
        or parsed.hostname is None
    ):
        raise LocalConsumerError(
            "local Consumer public base URL must be an http:// loopback origin ending in /v1"
        )
    hostname = parsed.hostname.lower()
    if hostname != "localhost":
        try:
            if not ipaddress.ip_address(hostname).is_loopback:
                raise ValueError
        except ValueError as exc:
            raise LocalConsumerError(
                "local Consumer public base URL must use a loopback host"
            ) from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise LocalConsumerError("local Consumer public base URL has an invalid port") from exc
    if port is None:
        raise LocalConsumerError("local Consumer public base URL must include a port")
    return resolved


def _credentials_payload(state: LocalConsumerState) -> dict[str, Any]:
    return {
        "base_url": state.config.public_base_url,
        "api_key": state.api_key,
        "key_fingerprint": state.api_key_fingerprint,
        "model": state.network.public_model_id,
        "consumer_peer_id": state.identity.peer_id,
        "consumer_public_key": state.identity.public_key,
        "status_url": state.config.public_base_url + "/mycomesh/local/status",
        "warning": "Keep api_key local. Inference requires a funded and authorized Consumer wallet.",
    }


def _openai_session_envelope(
    state: LocalConsumerState,
    body: dict[str, Any],
    *,
    max_output_tokens: int,
) -> dict[str, Any] | None:
    """Attach the active local Session to unextended OpenAI clients."""
    if "mycomesh_session" in body:
        value = body.get("mycomesh_session")
        envelope = dict(value) if isinstance(value, dict) else None
    else:
        if state.wallet is None or state.session_store is None:
            return None
        session = state.session_store.latest_active(
            account_id=state.wallet.address,
            settlement_contract=state.session_deployment.contract,
        )
        if session is None or int(session.get("activated_at") or 0) <= 0:
            return None
        session_id = str(session.get("session_id") or "").strip()
        request_id = _codex_request_id(body, session_id)
        claim = state.session_store.request_claim_state(session_id)
        max_fee_units = _local_session_max_fee_units(state, max_output_tokens)
        remaining_units = int(session["max_amount_units"]) - int(session["cumulative_spend_units"])
        session_has_capacity = remaining_units >= max_fee_units
        should_fallback = (
            claim is None and not session_has_capacity
        ) or (
            request_id is not None
            and claim is not None
            and bool(claim["fallback_safe"])
            and str(claim["request_id"]) != request_id
        )
        if should_fallback:
            fallback = state.session_store.latest_active(
                account_id=state.wallet.address,
                settlement_contract=state.session_deployment.contract,
                require_unclaimed=True,
                minimum_fee_units=max_fee_units,
            )
            if fallback is not None:
                session = fallback
                session_id = str(session.get("session_id") or "").strip()
                request_id = _codex_request_id(body, session_id)
        envelope = {"session_id": session_id} if session_id else None
    if envelope is not None and "request_id" not in envelope:
        request_id = _codex_request_id(body, str(envelope.get("session_id") or ""))
        if request_id:
            envelope["request_id"] = request_id
    return envelope


def _local_session_max_fee_units(state: LocalConsumerState, max_output_tokens: int) -> int:
    pricing = load_pricing_config(
        str(state.config.pricing_config_path) if state.config.pricing_config_path else None
    )
    quote = quote_usage(
        state.session_deployment.channel,
        {
            "input_tokens": state.network.reserve_input_bytes,
            "output_tokens": max_output_tokens,
        },
        pricing_table=pricing,
    )
    return max(1, int(Decimal(str(quote.gross_fee)) * Decimal("1000000") * Decimal("1.25")))


def _codex_request_id(body: dict[str, Any], session_id: str) -> str | None:
    metadata = body.get("client_metadata")
    if not isinstance(metadata, dict) or not str(metadata.get("turn_id") or ""):
        return None
    billable_body = {
        key: value
        for key, value in body.items()
        if key not in {"mycomesh_session", "stream", "stream_options"}
    }
    try:
        encoded = json.dumps(
            {"session_id": session_id, "request": billable_body},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return "codex_" + hashlib.sha256(encoded).hexdigest()


def _codex_env_script(state: LocalConsumerState) -> str:
    """Render only the stable local edge credentials for an OpenAI client.

    Session ids, sequence numbers, and replay claims are Consumer internals.
    The local API attaches the current authorized Session for ordinary
    OpenAI-shaped requests; exporting an id here lets Codex persist and replay
    stale protocol state after a recovery or upgrade.
    """
    lines = [
        f"export OPENAI_BASE_URL={shlex.quote(state.config.public_base_url)}",
        f"export OPENAI_API_KEY={shlex.quote(state.api_key)}",
        f"export MYCOMESH_BASE_URL={shlex.quote(state.config.public_base_url)}",
        f"export MYCOMESH_API_KEY={shlex.quote(state.api_key)}",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run and initialize the MycoMesh local Consumer.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Serve the localhost OpenAI-compatible API.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8110)

    subparsers.add_parser("credentials", help="Print the volume-local URL and API key.")
    subparsers.add_parser("codex-env", help="Print shell exports for the local OpenAI-compatible edge.")
    subparsers.add_parser("status", help="Print local initialization status without the API key.")

    init_wallet = subparsers.add_parser(
        "init-wallet",
        help="Store an external wallet public address; no private key is accepted.",
    )
    init_wallet.add_argument("--address", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        state = bootstrap_local_consumer()
        if args.command == "credentials":
            print(json.dumps(_credentials_payload(state), indent=2, sort_keys=True))
            return 0
        if args.command == "codex-env":
            print(_codex_env_script(state))
            return 0
        if args.command == "status":
            print(json.dumps(state.status_payload(), indent=2, sort_keys=True))
            return 0
        if args.command == "init-wallet":
            state.configure_external_wallet(args.address)
            print(json.dumps(state.status_payload(), indent=2, sort_keys=True))
            return 0
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise LocalConsumerError("serve port must be between 1 and 65535")
            uvicorn.run(
                create_app(state=state),
                host=args.host,
                port=args.port,
                access_log=False,
                proxy_headers=False,
                server_header=False,
            )
            return 0
    except LocalConsumerError as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
