from __future__ import annotations

from .provider_admission import admitted_provider, normalize_provider_keys, provider_keys_from_env

import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import select
import secrets
import socket
import ssl
import socketserver
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .billing import BillingError, normalize_payment_address
from .chain import (ZERO_ADDRESS, ChainError, EvmSignature, channel_to_hash, keccak256,
                    normalize_address, normalize_bytes32, parse_private_key, private_key_to_address,
                    recover_evm_address)
from .chain_v7 import (
    account_balance as v7_account_balance,
    encode_signed_batch_tuples as encode_v7_signed_batch_tuples,
    finalize_relay_receipt,
    key_grant as v7_key_grant,
    verify_authorization as verify_v7_authorization,
)
from .chain_v8 import (
    account_balance as v8_account_balance,
    encode_signed_batch_tuples as encode_v8_signed_batch_tuples,
    finalize_relay_receipt as finalize_v8_relay_receipt,
    key_grant as v8_key_grant,
    verify_authorization as verify_v8_authorization,
)
from . import chain_v9, chain_v10
from .chain_v6 import encode_settle_signed_batch_tuples as encode_v6_signed_batch_tuples
from .chain_v5 import build_relay_attestation
from .browser_cors import parse_allowed_origins
from .channel_policy import require_enabled_channel_binding
from .consumer_admission import (
    ConsumerAdmissionError,
    RelayV3AdmissionConfig,
    verify_relay_v3_admission,
)
from .identity import IdentityError, NodeIdentity, create_identity, peer_id_from_public_key, sign_document, verify_document
from .netio import NetworkIOError, bounded_timeout, read_bounded, text_preview
from .operator_budget import OperatorBudget, OperatorBudgetError
from .p2p import (
    INFERENCE_REQUEST_PURPOSE,
    P2P_ADDRESS_PROBE_PURPOSE,
    P2P_SECURE_REQUEST_PURPOSE,
    P2P_SECURE_RESPONSE_PURPOSE,
    P2P_SESSION_STATUS_REQUEST_PURPOSE,
    ProviderConfig,
    handle_message,
    handle_secure_frame,
    provider_runtime_capabilities,
)
from .reservation import (
    RESPONSES_LOCAL_OPTION_FIELDS,
    RESPONSES_REQUEST_OPTION_FIELDS,
    ReservationError,
    inference_request_hash,
    normalize_inference_request_options,
)
from .replay import ReplayError, ReplayStore
from .relay_incidents import RelayIncidentStore, evidence_hash
from .relay_probe import RelayProbeStore
from .relay_discovery import MAX_RELAYS as MAX_DISCOVERED_RELAYS
from .relay_integrity import (RelayIntegrityError, validate_authorization_binding, validate_provider_response,
                             RESPONSE_PROOF_SCHEMA, provider_response_proof)
from .provider_identity_binding import build_provider_identity_binding, verify_provider_identity_binding
from .session_protocol import (
    SessionProtocolError,
    normalize_session_request,
    verify_session_authorization,
    verify_session_request,
)
from .secure_transport import (
    MAX_SECURE_FRAME_BYTES,
    MemoryReplayStore,
    SecureTransportError,
    generate_transport_key,
    open_frame,
    seal_json_frame,
    verify_frame_metadata,
    verify_transport_key_binding,
)
from .session_relayer import (
    DEFAULT_RELAY_SETTLEMENT_DB,
    DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE,
    MAX_RELAY_SETTLEMENT_BATCH_SIZE,
    RelaySettlementError,
    RelaySettlementOutbox,
    RelaySettlementSubmitter,
    prepare_relay_settlement,
)
from .v7_relayer import prepare_v7_relay_settlement
from .v8_relayer import prepare_v8_relay_settlement
from .server_limits import (
    BoundedThreadingMixIn,
    arm_socket_deadline,
    bounded_connection_count,
    close_socket,
)


RELAY_PROTOCOL_VERSION = "mycomesh-relay/0.2"
DEFAULT_RELAY_CONTROL_PORT = 9900
DEFAULT_RELAY_PROVIDER_PORT = 9901
DEFAULT_RELAY_URL = f"http://127.0.0.1:{DEFAULT_RELAY_CONTROL_PORT}"
RELAY_PROVIDER_REGISTRATION_PURPOSE = "mycomesh.relay.provider.v1"
DEFAULT_RELAY_RECONNECT_GRACE_SECONDS = 5
DEFAULT_RELAY_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_RELAY_RATE_LIMIT_MAX_REQUESTS = 120
MAX_RELAY_RATE_LIMIT_IDENTITIES = 4096
DEFAULT_RELAY_CONSUMER_MAX_IN_FLIGHT = 32
DEFAULT_RELAY_V3_ADMISSION_MAX_IN_FLIGHT = 16
DEFAULT_RELAY_PROVIDER_QUEUE_SIZE = 64
DEFAULT_RELAY_SOCKET_TIMEOUT_SECONDS = 10
MAX_RELAY_ENCODED_FRAME_BYTES = ((MAX_SECURE_FRAME_BYTES + 2) // 3) * 4
MAX_RELAY_MESSAGE_BYTES = MAX_RELAY_ENCODED_FRAME_BYTES + 64 * 1024
MAX_RELAY_RESPONSE_BYTES = MAX_RELAY_MESSAGE_BYTES
MAX_RELAY_INFERENCE_TIMEOUT_SECONDS = 300.0
MAX_RELAY_SOCKET_TIMEOUT_SECONDS = 60.0
DEFAULT_RELAY_MAX_CONNECTIONS = 128
DEFAULT_RELAY_REQUEST_READ_DEADLINE_SECONDS = 15.0
MAX_RELAY_REQUEST_READ_DEADLINE_SECONDS = 60.0
MAX_PROVIDER_AFFINITY_ENTRIES = 4096


class RelayError(RuntimeError):
    pass


def _settlement_gas_per_receipt_from_env() -> int:
    setting = "MYCOMESH_RELAY_SETTLEMENT_GAS_PER_RECEIPT"
    value = os.getenv(setting, "250000").strip()
    if not re.fullmatch(r"[0-9]{1,7}", value):
        raise RelayError(f"{setting} must be an integer between 21000 and 5000000")
    return int(value)


class V7ProviderRejected(RelayError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        status_code: int | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code
        self.payload = dict(payload) if isinstance(payload, dict) else None


class RelayTransientError(RelayError):
    """A failed post-inference operation that is safe to retry."""


class RelaySchedulingError(RelayError):
    def __init__(self, message: str, status_code: int = 503) -> None:
        super().__init__(message)
        self.status_code = status_code


class RelayNotDispatchedError(RelaySchedulingError):
    """The request did not leave the Relay and may safely be retried."""
    execution_status = "not_dispatched"


class RelayOutcomeUnknownError(RelaySchedulingError):
    """The Provider may have executed this request; never replay elsewhere."""
    execution_status = "unknown"

    def __init__(self, message: str) -> None:
        super().__init__(message, 504)


class RelaySettlementUnavailableError(RelayNotDispatchedError):
    def __init__(self, error_code: str) -> None:
        super().__init__("Relay settlement is not ready to accept paid inference")
        self.error_code = error_code


def _normalize_relay_payment_address(
    value: str | None,
    *,
    required: bool = False,
) -> str | None:
    try:
        normalized = normalize_payment_address(value)
    except BillingError as exc:
        raise RelayError(f"Relay payment address is invalid: {exc}") from exc
    if normalized is None:
        if required:
            raise RelayError("Relay payment address is required outside the local network profile")
        return None
    if int(normalized[2:], 16) == 0:
        raise RelayError("Relay payment address must be a non-zero EVM address")
    return normalized


def relay_error_http_response(error: Exception) -> tuple[int, dict[str, str]]:
    """Map transient Provider/Relay failures to retry-aware HTTP responses."""
    message = str(error).lower()
    if isinstance(error, RelaySchedulingError):
        return error.status_code, ({"Retry-After": "5"} if error.status_code == 503 else {})
    if isinstance(error, V7ProviderRejected) and error.status_code is not None:
        status = int(error.status_code)
        if 400 <= status <= 599:
            return status, ({"Retry-After": "5"} if status == 429 or status >= 500 else {})
    if isinstance(error, RelayTransientError) or "timed out" in message or "deadline exceeded" in message:
        # A Provider may still be unwinding its bounded backend call when the
        # Relay deadline fires; give callers time to inspect reservation state
        # before they submit a new paid request.
        return 504, {"Retry-After": "5"}
    if any(
        marker in message
        for marker in (
            "is not connected",
            "queue is full",
            "disconnected",
            "connection reset",
            "connection refused",
        )
    ):
        return 503, {"Retry-After": "5"}
    return 400, {}


class _NoRelayRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _build_relay_http_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler(), _NoRelayRedirectHandler())


_RELAY_HTTP_OPENER = _build_relay_http_opener()


@dataclass(frozen=True)
class RelayAddress:
    host: str
    port: int
    peer_id: str
    scheme: str = "relay"

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def value(self) -> str:
        return f"{self.scheme}://{self.authority}/{self.peer_id}"

    @property
    def http_origin(self) -> str:
        return f"{'https' if self.tls else 'http'}://{self.authority}"

    @property
    def secure(self) -> bool:
        return self.scheme in {"myco+relay", "myco+relays"}

    @property
    def tls(self) -> bool:
        return self.scheme in {"relays", "myco+relays"}


@dataclass
class RelayJob:
    job_id: str
    message: dict[str, Any]
    response_queue: queue.Queue
    load_reservation: RelayLoadReservation | None = None


@dataclass
class ProviderSessionAffinity:
    peer_id: str
    expires_at: float
    in_flight: int = 0
    provider_signer: str | None = None


@dataclass
class RelayLoadReservation:
    state: RelayState = field(repr=False)
    provider: RelayProviderSession = field(repr=False)
    affinity: ProviderSessionAffinity | None = field(default=None, repr=False)
    phase: str = "reserved"
    settlement_admission: str | None = field(default=None, repr=False)
    dispatched: bool = False


@dataclass
class RelayProviderSession:
    peer_id: str
    peer: dict[str, Any]
    jobs: queue.Queue[RelayJob] = field(default_factory=lambda: queue.Queue(maxsize=DEFAULT_RELAY_PROVIDER_QUEUE_SIZE))
    connected_at: int = field(default_factory=lambda: int(time.time()))
    last_seen: int = field(default_factory=lambda: int(time.time()))
    connection: socket.socket | None = field(default=None, repr=False)
    reserved_jobs: int = 0
    queued_jobs: int = 0
    active_jobs: int = 0
    received_jobs: int = 0
    authenticated_signer: str | None = None
    registration_document: dict[str, Any] | None = field(default=None, repr=False)


@dataclass
class RelayState:
    providers: dict[str, RelayProviderSession] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.RLock)
    require_signed_providers: bool = True
    authorized_provider_public_keys: frozenset[str] | None = field(default_factory=provider_keys_from_env)
    network_profile: str = "local"
    payment_address: str | None = None
    attestation_address: str | None = None
    attestation_private_keys: dict[str, str] = field(default_factory=dict, repr=False)
    trust_proxy_headers: bool = False
    rate_limits: dict[str, list[float]] = field(default_factory=dict)
    reconnect_grace_seconds: float = DEFAULT_RELAY_RECONNECT_GRACE_SECONDS
    rate_limit_window_seconds: int = DEFAULT_RELAY_RATE_LIMIT_WINDOW_SECONDS
    rate_limit_max_requests: int = DEFAULT_RELAY_RATE_LIMIT_MAX_REQUESTS
    authorized_consumers: set[str] = field(default_factory=set)
    allow_any_signed_consumer: bool = False
    consumer_rate_limits: dict[str, list[float]] = field(default_factory=dict)
    consumer_in_flight: dict[str, int] = field(default_factory=dict)
    consumer_max_in_flight: int = field(
        default_factory=lambda: int(
            os.getenv(
                "MYCOMESH_RELAY_CONSUMER_MAX_IN_FLIGHT",
                str(DEFAULT_RELAY_CONSUMER_MAX_IN_FLIGHT),
            )
        )
    )
    provider_queue_size: int = DEFAULT_RELAY_PROVIDER_QUEUE_SIZE
    provider_affinity_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("MYCOMESH_RELAY_PROVIDER_AFFINITY_TTL_SECONDS", "900"))
    )
    socket_timeout_seconds: float = DEFAULT_RELAY_SOCKET_TIMEOUT_SECONDS
    control_max_connections: int = field(
        default_factory=lambda: int(
            os.getenv(
                "MYCOMESH_RELAY_CONTROL_MAX_CONNECTIONS",
                str(DEFAULT_RELAY_MAX_CONNECTIONS),
            )
        )
    )
    provider_max_connections: int = DEFAULT_RELAY_MAX_CONNECTIONS
    usage_limit_units: int = field(
        default_factory=lambda: int(os.getenv("MYCOMESH_RELAY_USAGE_LIMIT_UNITS") or 0)
    )
    usage_period_seconds: int = field(
        default_factory=lambda: int(os.getenv("MYCOMESH_RELAY_USAGE_PERIOD_SECONDS") or 2_592_000)
    )
    usage_state_path: str = "/data/operator-usage.json"
    settlement_rpc_url: str | None = None
    settlement_private_key: str | None = field(default=None, repr=False)
    settlement_chain_id: int | None = None
    settlement_contract: str | None = None
    settlement_version: int = 6
    settlement_db_path: str = DEFAULT_RELAY_SETTLEMENT_DB
    settlement_batch_size: int = DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE
    settlement_interval_seconds: int = 7200
    settlement_count_threshold: int = 100
    settlement_deadline_margin_seconds: int = 300
    # A configured floor survives worker recreation; learned estimates may only
    # increase it during the lifetime of each settlement submitter.
    settlement_gas_per_receipt: int = field(default_factory=_settlement_gas_per_receipt_from_env)
    # Optional append-only evidence ledger.  It is intentionally opt-in so
    # existing local/test Relays do not create files; production deployments
    # should set MYCOMESH_RELAY_INCIDENT_DB to a durable volume.
    incident_store_path: str | None = field(
        default_factory=lambda: os.getenv("MYCOMESH_RELAY_INCIDENT_DB") or None
    )
    probe_store_path: str | None = field(
        default_factory=lambda: os.getenv("MYCOMESH_RELAY_PROBE_DB") or None
    )
    request_read_deadline_seconds: float = DEFAULT_RELAY_REQUEST_READ_DEADLINE_SECONDS
    replay_store_path: str | None = None
    replay_ttl_seconds: int = 600
    v3_admission_config: RelayV3AdmissionConfig | None = None
    v3_admission_max_in_flight: int = DEFAULT_RELAY_V3_ADMISSION_MAX_IN_FLIGHT
    cors_allowed_origins: tuple[str, ...] = field(
        default_factory=lambda: parse_allowed_origins(
            os.getenv("MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS"),
            setting="MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS",
        )
    )
    _replay_store: ReplayStore | None = field(default=None, init=False, repr=False)
    _v3_admission_slots: threading.BoundedSemaphore = field(init=False, repr=False)
    _operator_budget: OperatorBudget | None = field(default=None, init=False, repr=False)
    _settlement_outbox: RelaySettlementOutbox | None = field(default=None, init=False, repr=False)
    _settlement_submitter: RelaySettlementSubmitter | None = field(default=None, init=False, repr=False)
    _incident_store: RelayIncidentStore | None = field(default=None, init=False, repr=False)
    _probe_store: RelayProbeStore | None = field(default=None, init=False, repr=False)
    _risk_lock: Any = field(default_factory=threading.RLock, init=False, repr=False)
    _emergency_quarantine: set[str] = field(default_factory=set, init=False, repr=False)
    _risk_storage_failed: bool = field(default=False, init=False, repr=False)
    _probe_runtime: Any = field(default=None, init=False, repr=False)
    _discovery_publisher: Any = field(default=None, init=False, repr=False)
    _scheduler_identity: NodeIdentity = field(default_factory=create_identity, init=False, repr=False)
    # Idle bindings are bounded and process-local. A signed Provider signer
    # hint can restore routing after expiry/restart; this is not a durable
    # Codex conversation store.
    _provider_affinity: dict[str, ProviderSessionAffinity] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.settlement_gas_per_receipt) is not int or not 21_000 <= self.settlement_gas_per_receipt <= 5_000_000:
            raise RelayError("settlement_gas_per_receipt must be an integer between 21000 and 5000000")
        if self.authorized_provider_public_keys is not None:
            self.authorized_provider_public_keys = normalize_provider_keys(self.authorized_provider_public_keys)
            if not self.require_signed_providers:
                raise RelayError("Provider allowlist requires signed registration")
        self.network_profile = str(self.network_profile or "").strip().lower()
        if self.network_profile not in {"local", "testnet", "open"}:
            raise RelayError("Relay network_profile must be local, testnet, or open")
        self.settlement_version = int(self.settlement_version)
        if self.settlement_version not in {5, 6, 7, 8, 9, 10}:
            raise RelayError("Relay settlement_version must be 5, 6, 7, 8, 9, or 10")
        if self.network_profile != "local" and self.settlement_version in {9, 10} and self.authorized_provider_public_keys is None:
            raise RelayError("V9/V10 testnet requires an explicit Provider allowlist")
        self.payment_address = _normalize_relay_payment_address(
            self.payment_address,
            required=self.network_profile != "local",
        )
        normalized_keys: dict[str, str] = {}
        for address, private_key in self.attestation_private_keys.items():
            try:
                derived = private_key_to_address(parse_private_key(private_key))
                supplied = normalize_address(address)
            except ChainError as exc:
                raise RelayError(f"Relay attestation identity is invalid: {exc}") from exc
            if supplied != derived:
                raise RelayError("Relay attestation key does not match its address")
            normalized_keys[derived] = private_key
        self.attestation_private_keys = normalized_keys
        if self.attestation_address:
            try:
                self.attestation_address = normalize_address(self.attestation_address)
            except ChainError as exc:
                raise RelayError(f"Relay attestation address is invalid: {exc}") from exc
            if self.attestation_address == ZERO_ADDRESS:
                raise RelayError("Relay attestation address must be non-zero")
            if self.attestation_address not in normalized_keys:
                raise RelayError("Relay current attestation address has no private key")
        elif normalized_keys:
            if len(normalized_keys) != 1:
                raise RelayError("Relay current attestation address is required when multiple keys are loaded")
            self.attestation_address = next(iter(normalized_keys))
        if self.settlement_version in {7, 8, 9, 10}:
            if not self.payment_address:
                raise RelayError(f"Settlement V{self.settlement_version} Relay requires a payout address")
            if not self.attestation_address:
                raise RelayError(f"Settlement V{self.settlement_version} Relay requires an attestation address")
        self.cors_allowed_origins = parse_allowed_origins(
            self.cors_allowed_origins,
            setting="RelayState.cors_allowed_origins",
        )
        try:
            self.socket_timeout_seconds = bounded_timeout(
                self.socket_timeout_seconds,
                maximum=MAX_RELAY_SOCKET_TIMEOUT_SECONDS,
                label="relay socket timeout",
            )
            self.request_read_deadline_seconds = bounded_timeout(
                self.request_read_deadline_seconds,
                maximum=MAX_RELAY_REQUEST_READ_DEADLINE_SECONDS,
                label="relay request read deadline",
            )
        except NetworkIOError as exc:
            raise RelayError(str(exc)) from exc
        try:
            self.control_max_connections = bounded_connection_count(
                self.control_max_connections,
                label="relay control max connections",
            )
            self.provider_max_connections = bounded_connection_count(
                self.provider_max_connections,
                label="relay provider max connections",
            )
        except ValueError as exc:
            raise RelayError(str(exc)) from exc
        if (
            type(self.consumer_max_in_flight) is not int
            or self.consumer_max_in_flight < 1
            or self.consumer_max_in_flight > self.control_max_connections
        ):
            raise RelayError(
                "Relay consumer concurrency must be positive and no greater than the control connection limit"
            )
        if self.replay_store_path:
            self._replay_store = ReplayStore(self.replay_store_path)
        if self.incident_store_path:
            try:
                self._incident_store = RelayIncidentStore(self.incident_store_path)
            except (OSError, sqlite3.Error) as exc:
                raise RelayError(f"invalid Relay incident store: {exc}") from exc
        if self.probe_store_path:
            try:
                self._probe_store = RelayProbeStore(self.probe_store_path)
            except (OSError, sqlite3.Error) as exc:
                raise RelayError(f"invalid Relay probe store: {exc}") from exc
        try:
            self._operator_budget = OperatorBudget(
                limit_units=int(self.usage_limit_units),
                period_seconds=int(self.usage_period_seconds),
                state_path=self.usage_state_path,
            )
        except (OperatorBudgetError, TypeError, ValueError) as exc:
            raise RelayError(f"invalid Relay usage budget: {exc}") from exc
        settlement_values = (
            self.settlement_rpc_url,
            self.settlement_private_key,
            self.settlement_chain_id,
            self.settlement_contract,
        )
        if any(value not in {None, ""} for value in settlement_values):
            if not self.settlement_rpc_url or not self.settlement_private_key:
                raise RelayError(
                    "Relay settlement requires both settlement_rpc_url and settlement_private_key"
                )
            if self.payment_address is None:
                raise RelayError(
                    "Relay settlement requires a non-zero payment_address"
                )
            if self.settlement_chain_id is None or not self.settlement_contract:
                raise RelayError(
                    "Relay settlement requires settlement_chain_id and settlement_contract"
                )
            try:
                if type(self.settlement_batch_size) is not int or not 1 <= self.settlement_batch_size <= MAX_RELAY_SETTLEMENT_BATCH_SIZE:
                    raise ValueError(
                        f"settlement_batch_size must be between 1 and {MAX_RELAY_SETTLEMENT_BATCH_SIZE}"
                    )
                self.settlement_chain_id = int(self.settlement_chain_id)
                if self.settlement_chain_id <= 0:
                    raise ValueError("settlement_chain_id must be positive")
                self.settlement_contract = normalize_address(self.settlement_contract)
                self._settlement_outbox = RelaySettlementOutbox(self.settlement_db_path)
                submitter_options: dict[str, Any] = {"settlement_version": self.settlement_version}
                if self.settlement_version == 10:
                    submitter_options["batch_encoder"] = chain_v10.encode_signed_batch_tuples
                    submitter_options["settlement_version"] = 10
                elif self.settlement_version == 9:
                    submitter_options["batch_encoder"] = chain_v9.encode_signed_batch_tuples
                    submitter_options["settlement_version"] = 9
                elif self.settlement_version == 8:
                    if not self.attestation_address:
                        raise ValueError("Settlement V8 Relay requires an attestation identity")
                    submitter_options["batch_encoder"] = encode_v8_signed_batch_tuples
                elif self.settlement_version == 7:
                    if not self.attestation_address:
                        raise ValueError("Settlement V7 Relay requires an attestation identity")
                    submitter_options["batch_encoder"] = encode_v7_signed_batch_tuples
                elif self.settlement_version == 6:
                    submitter_options["batch_encoder"] = encode_v6_signed_batch_tuples
                self._settlement_submitter = RelaySettlementSubmitter(
                    outbox=self._settlement_outbox,
                    rpc_url=self.settlement_rpc_url,
                    private_key=self.settlement_private_key,
                    batch_size=self.settlement_batch_size,
                    settlement_interval_seconds=self.settlement_interval_seconds,
                    settlement_count_threshold=self.settlement_count_threshold,
                    settlement_deadline_margin_seconds=self.settlement_deadline_margin_seconds,
                    expected_chain_id=self.settlement_chain_id,
                    expected_contract=self.settlement_contract,
                    gas_per_receipt=self.settlement_gas_per_receipt,
                    **submitter_options,
                )
            except (ChainError, RelaySettlementError, OSError, TypeError, ValueError) as exc:
                raise RelayError(f"invalid Relay settlement configuration: {exc}") from exc
            if self.payment_address and self._settlement_submitter.address == self.payment_address:
                raise RelayError("Relay transaction relayer identity must differ from the payout address")
            if self.attestation_address and self._settlement_submitter.address == self.attestation_address:
                raise RelayError("Relay transaction relayer identity must differ from the attestation address")
        if (
            type(self.v3_admission_max_in_flight) is not int
            or self.v3_admission_max_in_flight < 1
            or self.v3_admission_max_in_flight > self.control_max_connections
        ):
            raise RelayError(
                "Relay V3 admission concurrency must be positive and no greater than the control connection limit"
            )
        self._v3_admission_slots = threading.BoundedSemaphore(
            self.v3_admission_max_in_flight
        )


class RelayProviderTCPServer(
    BoundedThreadingMixIn,
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: RelayState,
        relay_host: str,
        control_port: int,
        provider_audience_port: int | None = None,
    ) -> None:
        super().__init__(server_address, RelayProviderHandler)
        self.state = state
        self.relay_host = relay_host
        self.control_port = control_port
        self.provider_audience_port = (
            int(provider_audience_port)
            if provider_audience_port is not None
            else int(self.server_address[1])
        )
        self.configure_connection_limit(state.provider_max_connections)


class RelayProviderHandler(socketserver.StreamRequestHandler):
    server: RelayProviderTCPServer

    def handle(self) -> None:
        self.connection.settimeout(float(self.server.state.socket_timeout_seconds))
        session: RelayProviderSession | None = None
        current_job: RelayJob | None = None
        registration_deadline = arm_socket_deadline(
            self.connection,
            float(self.server.state.request_read_deadline_seconds),
        )
        try:
            audience = f"{self.server.relay_host}:{self.server.provider_audience_port}"
            challenge = secrets.token_hex(32)
            challenge_payload: dict[str, Any] = {
                "type": "provider_challenge",
                "protocol": RELAY_PROTOCOL_VERSION,
                "challenge": challenge,
                "audience": audience,
            }
            if self.server.state.payment_address:
                challenge_payload["relay_payment_address"] = self.server.state.payment_address
            if self.server.state.attestation_address:
                challenge_payload["relay_attestation_address"] = self.server.state.attestation_address
            _write_json_line(self.wfile, challenge_payload)
            register = _read_json_line(self.rfile)
            if register.get("type") != "provider_register":
                _write_json_line(self.wfile, {"ok": False, "error": "provider_register is required"})
                return
            peer = register.get("peer")
            if not isinstance(peer, dict):
                _write_json_line(self.wfile, {"ok": False, "error": "peer must be a JSON object"})
                return
            registration_document = dict(peer)
            try:
                peer = verify_relay_provider_peer(
                    peer,
                    require_signed=self.server.state.require_signed_providers,
                    audience=audience,
                    expected_challenge=challenge,
                    expected_relay_payment_address=self.server.state.payment_address,
                    expected_relay_attestation_address=self.server.state.attestation_address,
                )
            except RelayError as exc:
                _write_json_line(self.wfile, {"ok": False, "error": str(exc)})
                return
            if not admitted_provider(peer, self.server.state.authorized_provider_public_keys):
                _write_json_line(self.wfile, {"ok": False, "error": "Provider is not admitted to this network"})
                return
            peer_id = str(peer.get("peer_id") or "")
            if not peer_id:
                _write_json_line(self.wfile, {"ok": False, "error": "peer.peer_id is required"})
                return
            session = RelayProviderSession(
                peer_id=peer_id,
                peer=dict(peer),
                jobs=queue.Queue(maxsize=self.server.state.provider_queue_size),
                connection=self.connection,
                registration_document=registration_document,
            )
            if peer.get("settlement_identity_binding") is not None or (
                self.server.state.network_profile != "local" and self.server.state.settlement_version in {7, 8, 9, 10}
            ):
                try:
                    session.authenticated_signer = verify_provider_identity_binding(peer, audience=audience)
                except ValueError as exc:
                    _write_json_line(self.wfile, {"ok": False, "error": str(exc)})
                    return
            with self.server.state.lock:
                old = self.server.state.providers.get(peer_id)
                if old is not None:
                    if time.time() - old.connected_at < self.server.state.reconnect_grace_seconds:
                        _write_json_line(self.wfile, {"ok": False, "error": "peer reconnect rate limit exceeded"})
                        return
                    try:
                        old.jobs.put_nowait(
                            RelayJob(
                                job_id="disconnect",
                                message={"type": "disconnect"},
                                response_queue=queue.Queue(),
                            )
                        )
                    except queue.Full:
                        pass
                self.server.state.providers[peer_id] = session
            registered_address = RelayAddress(self.server.relay_host, self.server.control_port, peer_id)
            registered_payload: dict[str, Any] = {
                "ok": True,
                "type": "provider_registered",
                "protocol": RELAY_PROTOCOL_VERSION,
                "peer_id": peer_id,
                "challenge": challenge,
                "relay": registered_address.http_origin,
                "relay_address": registered_address.value,
            }
            if self.server.state.payment_address:
                registered_payload["relay_payment_address"] = self.server.state.payment_address
            if self.server.state.attestation_address:
                registered_payload["relay_attestation_address"] = self.server.state.attestation_address
            _write_json_line(self.wfile, registered_payload)
            registration_deadline.cancel()
            self.connection.settimeout(None)
            while True:
                try:
                    # A Provider can disappear without sending another frame
                    # (for example, a killed container behind NAT). Probe the
                    # idle socket so its session does not remain schedulable.
                    job = session.jobs.get(timeout=1.0)
                except queue.Empty:
                    if _provider_socket_closed(self.connection):
                        raise RelayError(f"provider {session.peer_id!r} disconnected")
                    continue
                if job.message.get("type") == "disconnect":
                    return
                current_job = job
                if job.load_reservation is not None and not _start_relay_job(self.server.state, session, job):
                    current_job = None
                    continue
                session.last_seen = int(time.time())
                _write_json_line(
                    self.wfile,
                    {
                        "type": "relay_job",
                        "job_id": job.job_id,
                        "message": job.message,
                    },
                )
                response = _read_json_line(self.rfile)
                if response.get("type") != "relay_job_result" or response.get("job_id") != job.job_id:
                    raise RelayOutcomeUnknownError("Provider response does not match the active job")
                session.last_seen = int(time.time())
                _transition_provider_load(job.load_reservation, "received")
                job.response_queue.put(response)
                current_job = None
        except Exception as exc:
            if current_job is not None:
                _release_provider_load(current_job.load_reservation)
                current_job.response_queue.put(RelayOutcomeUnknownError("Provider connection failed after dispatch; execution outcome is unknown"))
                current_job = None
            if session is not None:
                # Remove the session before draining its queue so an admission
                # cannot enqueue between the drain and registry removal.
                _disconnect_relay_provider(self.server.state, session)
        finally:
            if current_job is not None:
                _release_provider_load(current_job.load_reservation)
            registration_deadline.cancel()
            if session is not None:
                _disconnect_relay_provider(self.server.state, session)


def _provider_socket_closed(connection: socket.socket) -> bool:
    try:
        value = connection.recv(1, socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0))
    except BlockingIOError:
        return False
    except (ConnectionResetError, BrokenPipeError, OSError):
        return True
    return value == b""


class RelayControlHTTPServer(BoundedThreadingMixIn, ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: RelayState,
    ) -> None:
        super().__init__(server_address, RelayControlHandler)
        self.state = state
        self.configure_connection_limit(state.control_max_connections)


class RelayControlHandler(BaseHTTPRequestHandler):
    server: RelayControlHTTPServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(float(self.server.state.socket_timeout_seconds))
        self._read_deadline = arm_socket_deadline(
            self.connection,
            float(self.server.state.request_read_deadline_seconds),
        )

    def finish(self) -> None:
        self._cancel_read_deadline()
        super().finish()

    def do_GET(self) -> None:
        self._cancel_read_deadline()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/relay-announcement":
            publisher = self.server.state._discovery_publisher
            record = publisher.current() if publisher is not None else None
            if record is None:
                self._write(404, {"ok": False, "error": "no live Relay announcement"})
            else:
                self._write(200, record, headers={"Cache-Control": "no-store"})
            return
        if parsed.path == "/health":
            providers = list_relay_providers(self.server.state)
            settlement_health = _relay_settlement_health(self.server.state)
            capabilities = v7_relay_capabilities(self.server.state)
            self._write(
                200,
                {
                    "ok": True,
                    "protocol": RELAY_PROTOCOL_VERSION,
                    "providers": len(providers),
                    "provider_admission_mode": "allowlist" if self.server.state.authorized_provider_public_keys is not None else ("signed" if self.server.state.require_signed_providers else "local"),
                    "authorized_provider_count": len(self.server.state.authorized_provider_public_keys or ()),
                    "inference_ready": bool(capabilities.get("providers")),
                    "settlement_ready": settlement_health.get("settlement_ready") is True,
                    "anti_cheat": {
                        "risk_store_ready": self.server.state._incident_store is not None and not self.server.state._risk_storage_failed,
                        "active_probes_enabled": self.server.state._probe_runtime is not None,
                        "active_probes_mode": (
                            "funded_v10_channel_required"
                            if self.server.state._probe_runtime is None and self.server.state.settlement_version == 10
                            else "disabled"
                            if self.server.state._probe_runtime is None
                            else "funded_settlement_probe"
                        ),
                        # Hard protocol violations can quarantine a Provider;
                        # economic consequences remain disabled until an
                        # independent adjudicator resolves the evidence.
                        "provider_quarantine_enabled": self.server.state._incident_store is not None and not self.server.state._risk_storage_failed,
                        "monetary_enforcement_enabled": False,
                        "enforcement_mode": "quarantine_only",
                        "monetary_enforcement_mode": "manual_independent_user_quorum",
                    },
                    "relay_payment_address": self.server.state.payment_address,
                    "relay_attestation_address": self.server.state.attestation_address,
                    "consumer_max_in_flight": self.server.state.consumer_max_in_flight,
                    "usage_budget": (
                        self.server.state._operator_budget.snapshot()
                        if self.server.state._operator_budget is not None
                        else None
                    ),
                    "settlement_submitter": settlement_health,
                    f"v{self.server.state.settlement_version}": capabilities,
                },
            )
            return
        if parsed.path == "/providers":
            self._write(
                200,
                {
                    "ok": True,
                    "protocol": RELAY_PROTOCOL_VERSION,
                    "providers": list_relay_providers(self.server.state),
                },
            )
            return
        self._write(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        cors_headers: dict[str, str] = {}
        if parsed.path == "/v1/mycomesh/receipts/status":
            try:
                self._write(200, relay_receipt_status(self.server.state, self._read_json()))
            except Exception as exc:
                status, headers = relay_error_http_response(exc)
                self._write(status, {"error": {"type": "receipt_status_error", "message": str(exc)}}, headers=headers)
            return
        if parsed.path in {"/v1/responses", "/v1/responses/compact", "/v1/chat/completions"}:
            try:
                request_deadline = time.monotonic() + _relay_client_timeout(self.headers)
                body = self._read_json()
                payment = _v7_payment_header(self.headers)
                if payment is None:
                    required = v7_payment_required(self.server.state, parsed.path, body)
                    self._write(
                        402,
                        required,
                        headers={"PAYMENT-REQUIRED": _encode_payment_header(required)},
                    )
                    return
                response, settlement = relay_v7_openai(
                    self.server.state,
                    parsed.path,
                    body,
                    payment,
                    deadline=request_deadline,
                    response_proof=self.headers.get("X-MycoMesh-Response-Proof") == RESPONSE_PROOF_SCHEMA,
                )
                self._write(
                    200,
                    response,
                    headers={"PAYMENT-RESPONSE": _encode_payment_header(settlement)},
                )
            except Exception as exc:
                status, retry_headers = relay_error_http_response(exc)
                error_payload = (
                    exc.payload
                    if isinstance(exc, V7ProviderRejected) and exc.payload is not None
                    else {
                        "error": {
                            "type": "mycomesh_relay_error",
                            "message": str(exc),
                        }
                    }
                )
                if isinstance(exc, (RelayNotDispatchedError, RelayOutcomeUnknownError)):
                    error_payload = {"error": {"type": "mycomesh_relay_error", "message": str(exc),
                                               "execution_status": exc.execution_status,
                                               "code": getattr(exc, "error_code", "relay_" + exc.execution_status)}}
                self._write(
                    status,
                    error_payload,
                    headers=retry_headers,
                )
            return
        if parsed.path.startswith("/infer/"):
            cors_headers = self._browser_cors_headers()
            origin_headers = self.headers.get_all("Origin") or []
            if origin_headers and "Access-Control-Allow-Origin" not in cors_headers:
                self._cancel_read_deadline()
                self._write(
                    403,
                    {"ok": False, "error": "CORS origin is not allowed"},
                    headers=cors_headers,
                )
                return
            if origin_headers:
                if (self.headers.get_all("Cookie") or []) or (
                    self.headers.get_all("Authorization") or []
                ):
                    self._cancel_read_deadline()
                    self._write(
                        400,
                        {"ok": False, "error": "credentialed CORS requests are not accepted"},
                        headers=cors_headers,
                    )
                    return
                content_types = self.headers.get_all("Content-Type") or []
                if (
                    len(content_types) != 1
                    or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
                ):
                    self._cancel_read_deadline()
                    self._write(
                        415,
                        {"ok": False, "error": "CORS inference requests require application/json"},
                        headers=cors_headers,
                    )
                    return
        try:
            if parsed.path.startswith("/infer/"):
                self._rate_limit()
                request_started_at = time.monotonic()
                peer_id = urllib.parse.unquote(parsed.path.removeprefix("/infer/"))
                body = self._read_json()
                timeout = _coerce_timeout(body.get("timeout"), 180.0)
                deadline = request_started_at + timeout
                secure_frame = body.get("secure_frame")
                session_status_marker = body.get("session_status")
                if session_status_marker is not None and type(session_status_marker) is not bool:
                    raise RelayError("session_status must be a boolean")
                if session_status_marker is True and secure_frame is None:
                    raise RelayError("session_status requires a signed secure_frame")
                verified_admission: dict[str, Any] = {}
                if secure_frame is not None:
                    if not isinstance(secure_frame, str):
                        raise RelayError("secure_frame must be base64url text")
                    consumer_public_key = verify_relay_consumer_frame(
                        self.server.state,
                        secure_frame,
                        peer_id=peer_id,
                        admission=body.get("admission"),
                        address_probe=body.get("address_probe") is True,
                        session_status=session_status_marker is True,
                        verified_admission=verified_admission,
                    )
                    relay_message = {"secure_frame": secure_frame}
                else:
                    with self.server.state.lock:
                        session = self.server.state.providers.get(peer_id)
                    if session is not None and _relay_session_requires_secure(session):
                        raise RelayError("provider requires sealed relay frames; plaintext inference is disabled")
                    message = body.get("message")
                    if not isinstance(message, dict):
                        raise RelayError("message must be a JSON object")
                    consumer_public_key = verify_relay_consumer_request(
                        self.server.state, message, peer_id=peer_id
                    )
                    relay_message = message
                _reserve_consumer_slot(self.server.state, consumer_public_key)
                budget = self.server.state._operator_budget
                budget_reservation = 0
                try:
                    v5_request = verified_admission.get("v5_attestation_request")
                    session_status = verified_admission.get("session_status") is True
                    if budget is not None:
                        if session_status:
                            budget_reservation = 0
                        elif isinstance(v5_request, dict):
                            budget_reservation = int(v5_request.get("max_fee_units") or 0)
                        else:
                            budget_reservation = int(verified_admission.get("v3_max_fee_units") or 0)
                        if not budget.reserve(budget_reservation):
                            raise RelayError("Relay usage budget exhausted for the current period")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RelayError("relay inference deadline exceeded")
                    response = relay_infer(self.server.state, peer_id, relay_message, timeout=remaining)
                    if isinstance(v5_request, dict):
                        signer = normalize_address(str(v5_request["relay_attestation_address"]))
                        private_key = self.server.state.attestation_private_keys.get(signer)
                        if not private_key:
                            raise RelayError("Relay V5 session targets an unavailable attestation key")
                        response = dict(response)
                        build_attestation = build_relay_attestation
                        if int(v5_request.get("protocol_version") or 5) == 6:
                            from .chain_v6 import build_relay_attestation as build_attestation
                        response["relay_attestation"] = build_attestation(
                            private_key=private_key,
                            chain_id=int(v5_request["chain_id"]),
                            settlement_contract=str(v5_request["settlement_contract"]),
                            session_id=str(v5_request["session_id"]),
                            request_hash=str(v5_request["request_hash"]),
                            provider=str(v5_request["provider"]),
                            relay=str(v5_request["relay"]),
                            **({"relay_epoch": int(v5_request.get("relay_epoch") or 0)} if int(v5_request.get("protocol_version") or 5) == 6 else {}),
                            sequence=int(v5_request["sequence"]),
                            deadline=int(v5_request["deadline"]),
                        )
                    if budget is not None:
                        actual_units = 0 if session_status else _relay_response_fee_units(response)
                        if actual_units is None:
                            actual_units = budget_reservation
                        if not budget.settle(budget_reservation, actual_units):
                            raise RelayError("Relay usage budget exhausted for the current period")
                        budget_reservation = 0
                    self._write(200, response, headers=cors_headers)
                finally:
                    if budget is not None and budget_reservation:
                        budget.release(budget_reservation)
                    _release_consumer_slot(self.server.state, consumer_public_key)
                return
            if parsed.path in {"/v5/settlements", "/v6/settlements"}:
                submission = self._read_json()
                submitter = self.server.state._settlement_submitter
                if submitter is None:
                    raise RelayError("Relay settlement submitter is not configured")
                try:
                    prepare_kwargs = {
                        "expected_chain_id": self.server.state.settlement_chain_id,
                        "expected_contract": self.server.state.settlement_contract,
                        "expected_relay": self.server.state.payment_address,
                        "attestation_private_keys": self.server.state.attestation_private_keys,
                    }
                    try:
                        prepared = prepare_relay_settlement(submission, **prepare_kwargs)
                    except RelaySettlementError as exc:
                        if "attestation deadline has elapsed" not in str(exc):
                            raise
                        prepared = prepare_relay_settlement(submission, now=0, **prepare_kwargs)
                        status = submitter.outbox.status(prepared.key)
                        if status is None:
                            raise exc
                        accepted = False
                    else:
                        status, accepted = submitter.enqueue(prepared)
                except RelaySettlementError as exc:
                    raise RelayError(str(exc)) from exc
                self._write(
                    202,
                    {
                        "ok": True,
                        "schema": "mycomesh.relay.settlement.accepted.v1",
                        "settlement_key": prepared.key,
                        "status": status,
                        "accepted": bool(accepted),
                    },
                )
                return
        except Exception as exc:
            status, retry_headers = relay_error_http_response(exc)
            response_headers = {**cors_headers, **retry_headers}
            self._write(status, {"ok": False, "error": str(exc)}, headers=response_headers)
            return
        self._write(404, {"ok": False, "error": "not found"}, headers=cors_headers)

    def do_OPTIONS(self) -> None:
        self._cancel_read_deadline()
        parsed = urllib.parse.urlparse(self.path)
        cors_headers = self._browser_cors_headers(preflight=True)
        peer_id = parsed.path.removeprefix("/infer/")
        if not parsed.path.startswith("/infer/") or not peer_id:
            self._write(404, {"ok": False, "error": "not found"}, headers=cors_headers)
            return
        origin_headers = self.headers.get_all("Origin") or []
        if len(origin_headers) != 1 or "Access-Control-Allow-Origin" not in cors_headers:
            self._write(
                403,
                {"ok": False, "error": "CORS origin is not allowed"},
                headers=cors_headers,
            )
            return
        requested_methods = self.headers.get_all("Access-Control-Request-Method") or []
        if len(requested_methods) != 1 or requested_methods[0].strip().upper() != "POST":
            self._write(
                405,
                {"ok": False, "error": "CORS method is not allowed"},
                headers=cors_headers,
            )
            return
        requested_headers = self.headers.get_all("Access-Control-Request-Headers") or []
        header_names = [
            name.strip().lower()
            for value in requested_headers
            for name in value.split(",")
        ]
        if any(not name or name != "content-type" for name in header_names):
            self._write(
                400,
                {"ok": False, "error": "CORS request headers are not allowed"},
                headers=cors_headers,
            )
            return
        self._write_empty(
            204,
            headers={
                **cors_headers,
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Max-Age": "600",
            },
        )

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _rate_limit(self) -> None:
        socket_client = self.client_address[0] if self.client_address else ""
        real_ip_headers = self.headers.get_all("X-Real-IP") or []
        client = _resolve_relay_rate_limit_client_ip(
            self.server.state,
            socket_client,
            real_ip_headers,
        )
        _bounded_rate_limit(
            self.server.state,
            self.server.state.rate_limits,
            client,
            error="rate limit exceeded",
        )

    def _read_json(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("content-length") or "0")
            if content_length > MAX_RELAY_MESSAGE_BYTES:
                raise RelayError("request body too large")
            if content_length <= 0:
                return {}
            payload = self.rfile.read(content_length).decode("utf-8")
            value = json.loads(payload)
            if not isinstance(value, dict):
                raise RelayError("request body must be a JSON object")
            return value
        finally:
            self._cancel_read_deadline()

    def _cancel_read_deadline(self) -> None:
        timer = getattr(self, "_read_deadline", None)
        if timer is not None:
            timer.cancel()
            self._read_deadline = None

    def _browser_cors_headers(self, *, preflight: bool = False) -> dict[str, str]:
        allowed_origins = self.server.state.cors_allowed_origins
        origin_headers = self.headers.get_all("Origin") or []
        if not allowed_origins and not origin_headers:
            return {}
        headers = {
            "Vary": (
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
                if preflight
                else "Origin"
            )
        }
        if len(origin_headers) == 1 and origin_headers[0] in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin_headers[0]
        return headers

    def _write(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _write_empty(self, status: int, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("content-length", "0")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()


def _resolve_relay_rate_limit_client_ip(
    state: RelayState,
    socket_client: str,
    real_ip_headers: list[str],
) -> str:
    try:
        socket_ip = ipaddress.ip_address(str(socket_client).split("%", 1)[0])
    except ValueError as exc:
        raise RelayError("socket client address is not a valid IP") from exc
    if not state.trust_proxy_headers:
        return str(socket_ip)
    if not (socket_ip.is_loopback or socket_ip.is_private):
        raise RelayError("trusted proxy mode accepts Relay control traffic only from a loopback or private proxy")
    if len(real_ip_headers) != 1:
        raise RelayError("trusted proxy request requires exactly one X-Real-IP header")
    candidate = str(real_ip_headers[0]).strip()
    if not candidate or "," in candidate or "%" in candidate:
        raise RelayError("X-Real-IP must contain exactly one global IP address")
    try:
        client_ip = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise RelayError("X-Real-IP must contain exactly one global IP address") from exc
    if not client_ip.is_global:
        raise RelayError("X-Real-IP must contain exactly one global IP address")
    return str(client_ip)


def serve_relay(
    host: str,
    control_port: int = DEFAULT_RELAY_CONTROL_PORT,
    provider_port: int = DEFAULT_RELAY_PROVIDER_PORT,
    advertise_host: str | None = None,
    advertise_control_port: int | None = None,
    advertise_provider_port: int | None = None,
    authorized_consumers: set[str] | None = None,
    allow_any_signed_consumer: bool = False,
    replay_store_path: str | None = None,
    trust_proxy_headers: bool = False,
    cors_allowed_origins: tuple[str, ...] | list[str] | None = None,
    v3_admission_config: RelayV3AdmissionConfig | None = None,
    network_profile: str = "local",
    payment_address: str | None = None,
    attestation_address: str | None = None,
    attestation_private_keys: Mapping[str, str] | None = None,
    settlement_rpc_url: str | None = None,
    settlement_private_key: str | None = None,
    settlement_chain_id: int | None = None,
    settlement_contract: str | None = None,
    settlement_version: int = 6,
    settlement_db_path: str = DEFAULT_RELAY_SETTLEMENT_DB,
    settlement_batch_size: int = DEFAULT_RELAY_SETTLEMENT_BATCH_SIZE,
    settlement_interval_seconds: int = 7200,
    settlement_count_threshold: int = 100,
    settlement_deadline_margin_seconds: int = 300,
    relay_discovery: Any = None,
) -> None:
    state_options: dict[str, Any] = {}
    if cors_allowed_origins is not None:
        state_options["cors_allowed_origins"] = tuple(cors_allowed_origins)
    if network_profile != "local" and settlement_version in {7, 8, 9, 10}:
        state_options["incident_store_path"] = os.getenv("MYCOMESH_RELAY_INCIDENT_DB") or str(
            Path(settlement_db_path).with_name("relay-incidents.sqlite3"))
        state_options["probe_store_path"] = os.getenv("MYCOMESH_RELAY_PROBE_DB") or str(
            Path(settlement_db_path).with_name("relay-probes.sqlite3"))
    state = RelayState(
        authorized_consumers=authorized_consumers or set(),
        trust_proxy_headers=trust_proxy_headers,
        allow_any_signed_consumer=allow_any_signed_consumer,
        replay_store_path=replay_store_path,
        v3_admission_config=v3_admission_config,
        network_profile=network_profile,
        payment_address=payment_address,
        attestation_address=attestation_address,
        attestation_private_keys=dict(attestation_private_keys or {}),
        settlement_rpc_url=settlement_rpc_url,
        settlement_private_key=settlement_private_key,
        settlement_chain_id=settlement_chain_id,
        settlement_contract=settlement_contract,
        settlement_version=settlement_version,
        settlement_db_path=settlement_db_path,
        settlement_batch_size=settlement_batch_size,
        settlement_interval_seconds=settlement_interval_seconds,
        settlement_count_threshold=settlement_count_threshold,
        settlement_deadline_margin_seconds=settlement_deadline_margin_seconds,
        **state_options,
    )
    from .relay_probe_runtime import create_relay_probe_runtime
    state._probe_runtime = create_relay_probe_runtime(state)
    relay_host = advertise_host or host
    public_control_port = advertise_control_port or control_port
    public_provider_port = advertise_provider_port or provider_port
    if relay_discovery is not None:
        expected_bindings = {
            "network_profile": state.network_profile,
            "chain_id": state.settlement_chain_id,
            "settlement_contract": state.settlement_contract,
            "protocol_version": state.settlement_version,
        }
        for name, value in expected_bindings.items():
            if relay_discovery.config["context"].get(name) != value:
                raise RelayError(f"Relay discovery manifest does not match configured {name}")
        for name, value in {
            "host": relay_host,
            "provider_port": public_provider_port,
            "payment_address": state.payment_address,
            "attestation_address": state.attestation_address,
        }.items():
            if relay_discovery.admission.get(name) != value:
                raise RelayError(f"Relay admission does not match configured {name}")
        public_url = urllib.parse.urlsplit(relay_discovery.admission["public_url"])
        if (public_url.port or (443 if public_url.scheme == "https" else 80)) != public_control_port:
            raise RelayError("Relay admission does not match advertised control port")
        state._discovery_publisher = relay_discovery
    provider_server = RelayProviderTCPServer(
        (host, provider_port),
        state,
        relay_host,
        public_control_port,
        public_provider_port,
    )
    control_server = RelayControlHTTPServer((host, control_port), state)
    if state._settlement_submitter is not None:
        state._settlement_submitter.start()
    provider_thread = threading.Thread(target=provider_server.serve_forever, name="mycomesh-relay-provider", daemon=True)
    provider_thread.start()
    probe_thread = None
    if state._probe_runtime is not None:
        probe_thread = threading.Thread(target=state._probe_runtime.run, name="mycomesh-relay-audit", daemon=True)
        probe_thread.start()
    try:
        if state._discovery_publisher is not None:
            state._discovery_publisher.start()
        control_server.serve_forever()
    finally:
        if state._discovery_publisher is not None:
            state._discovery_publisher.close()
        if state._probe_runtime is not None:
            state._probe_runtime.stop()
        if probe_thread is not None:
            probe_thread.join(timeout=2.0)
        if state._probe_runtime is not None:
            try:
                drained = state._probe_runtime.drain(
                    timeout_seconds=min(state._probe_runtime.coordinator.timeout_seconds + 1.0, 30.0))
                if drained:
                    state._probe_runtime.close()
                else:
                    logging.getLogger(__name__).warning(
                        "Probe shutdown drain timed out; pending outcomes remain uncertain and budgets reserved")
            except Exception as exc:
                logging.getLogger(__name__).warning("Probe shutdown drain failed (%s)", type(exc).__name__)
        if state._settlement_submitter is not None:
            state._settlement_submitter.stop()
        control_server.shutdown()
        provider_server.shutdown()
        provider_server.server_close()
        control_server.server_close()


def _finish_relay_registration_callback(
    callback_thread: threading.Thread | None,
    active_socket: socket.socket | None,
    stop_event: threading.Event | None,
) -> bool:
    """Keep registration callbacks serialized across reconnects.

    A callback may be performing a Bridge join that depends on the current
    relay connection.  Waiting for it before reconnecting prevents a stale
    callback from starting a second heartbeat after a newer registration.
    During an explicit stop, wake the callback and use a bounded wait so a
    user-supplied callback cannot hold shutdown forever.
    """
    if callback_thread is None or not callback_thread.is_alive():
        return True
    if stop_event is not None and stop_event.is_set():
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except (AttributeError, OSError):
                pass
        callback_thread.join(timeout=DEFAULT_RELAY_RECONNECT_GRACE_SECONDS)
        return not callback_thread.is_alive()
    callback_thread.join(timeout=DEFAULT_RELAY_RECONNECT_GRACE_SECONDS)
    if callback_thread.is_alive() and stop_event is not None:
        stop_event.set()
    return not callback_thread.is_alive()


def run_relay_provider(
    relay_host: str,
    relay_port: int,
    config: ProviderConfig,
    on_registered: Callable[[dict[str, Any]], None] | None = None,
    stop_event: threading.Event | None = None,
    provider_tls: bool = False,
    tls_server_hostname: str | None = None,
    relay_public_url: str | None = None,
    relay_fallbacks: Sequence[Mapping[str, Any]] = (),
    on_disconnected: Callable[[], None] | None = None,
    relay_discovery: Any = None,
) -> None:
    if (
        config.network_profile != "local"
        and int(config.settlement_version) in {4, 5, 6, 7, 8, 9, 10}
        and not config.relay_payment_address
    ):
        raise RelayError(
            f"Settlement V{config.settlement_version} Relay Provider requires a pinned Relay payment address"
        )
    if (
        config.network_profile != "local"
        and int(config.settlement_version) in {5, 6, 7, 8, 9, 10}
        and not config.relay_attestation_address
    ):
        raise RelayError(f"Settlement V{config.settlement_version} Relay Provider requires a pinned Relay attestation address")
    callback_thread: threading.Thread | None = None
    callback_cleanup_ok = True
    fallback_endpoints = _normalize_relay_fallbacks(relay_fallbacks, network_profile=config.network_profile)
    endpoints = [{"host": relay_host, "provider_port": relay_port, "public_url": relay_public_url,
                  "provider_tls": provider_tls, "tls_server_hostname": tls_server_hostname or relay_host,
                  "payment_address": config.relay_payment_address,
                  "attestation_address": config.relay_attestation_address}, *fallback_endpoints]
    if fallback_endpoints:
        if not relay_public_url:
            raise RelayError("relay_public_url is required when configuring Relay fallbacks")
        _normalize_relay_fallbacks([{name: value for name, value in endpoints[0].items() if name != "tls_server_hostname"}],
                                  network_profile=config.network_profile)
        if any(item["host"] == relay_host.lower() and item["provider_port"] == relay_port for item in fallback_endpoints):
            raise RelayError("Relay fallback must not repeat the primary Provider socket")
    if relay_discovery is not None and int(config.settlement_version) not in {8, 9, 10}:
        raise RelayError("Relay discovery requires Settlement V8 or V9")
    static_endpoints = endpoints
    discovered_endpoints: dict[str, dict[str, Any]] = {}
    endpoint_index = 0
    previous_endpoint: tuple[str, int] | None = None
    advance_endpoint = False
    if relay_discovery is not None:
        relay_discovery.start_refresh()
    while stop_event is None or not stop_event.is_set():
        if relay_discovery is not None and previous_endpoint is not None:
            discovered_endpoints = {
                signer: candidate for signer, candidate in discovered_endpoints.items()
                if candidate["discovery_expires_at"] > time.time()
            }
            try:
                discovered = relay_discovery.endpoints()
                if not isinstance(discovered, list) or len(discovered) > 8:
                    raise RelayError("Relay discovery returned too many endpoints")
                for value in discovered:
                    if not isinstance(value, dict):
                        raise RelayError("Relay discovery returned an invalid endpoint")
                    expiry = value.get("discovery_expires_at")
                    if type(expiry) is not int or expiry <= time.time():
                        continue
                    candidate = _normalize_relay_fallbacks(
                        [{key: item for key, item in value.items() if key != "discovery_expires_at"}],
                        network_profile=config.network_profile,
                    )[0]
                    candidate["discovery_expires_at"] = expiry
                    signer = candidate["attestation_address"]
                    if signer in discovered_endpoints or len(discovered_endpoints) < MAX_DISCOVERED_RELAYS:
                        discovered_endpoints[signer] = candidate
            except (OSError, ValueError, RelayError, sqlite3.Error) as exc:
                print(f"relay_discovery_error: {exc}; retaining existing Relay endpoints", file=sys.stderr, flush=True)
            # Discovery probes rotate across bounded windows. Keep live results
            # from earlier windows so retries cannot starve unattempted sockets.
            endpoints = list(static_endpoints)
            seen_sockets = {(item["host"].lower(), item["provider_port"]) for item in endpoints}
            for candidate in discovered_endpoints.values():
                socket_key = (candidate["host"], candidate["provider_port"])
                if socket_key not in seen_sockets:
                    endpoints.append(candidate)
                    seen_sockets.add(socket_key)
            # Refresh can add or expire routes. Continue relative to the previous
            # socket, not an index that now refers to a different Relay.
            previous_index = next((index for index, item in enumerate(endpoints)
                                   if (item["host"].lower(), item["provider_port"]) == previous_endpoint), None)
            endpoint_index = ((previous_index + int(advance_endpoint)) % len(endpoints)
                              if previous_index is not None else endpoint_index % len(endpoints))
        if stop_event is not None and stop_event.is_set():
            break
        endpoint = endpoints[endpoint_index]
        previous_endpoint = (endpoint["host"].lower(), endpoint["provider_port"])
        advance_endpoint = False
        relay_host, relay_port = endpoint["host"], endpoint["provider_port"]
        provider_tls = endpoint["provider_tls"]
        tls_server_hostname = endpoint.get("tls_server_hostname") or relay_host
        # Only reached after the old socket, registration callback and Bridge
        # heartbeat cleanup have all finished. The Provider identity is kept.
        config.relay_payment_address = endpoint["payment_address"]
        config.relay_attestation_address = endpoint["attestation_address"]
        callback_thread = None
        callback_cleanup_ok = True
        registration_completed = False
        active_socket: socket.socket | None = None
        retry_after_connection = False
        try:
            # Re-read the deployment allowlist on every connection.  A
            # long-lived Provider must publish a fresh signed descriptor when
            # models are added or removed, while retaining its identity and
            # transport-key binding.
            config.refresh_public_models()
            if endpoint.get("discovery_expires_at", float("inf")) <= time.time():
                raise RelayError("Discovered Relay announcement expired before connection")
            raw_socket = _connect_relay_provider_socket(relay_host, relay_port, timeout=10)
            try:
                if provider_tls:
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    sock = context.wrap_socket(
                        raw_socket,
                        server_hostname=tls_server_hostname or relay_host,
                    )
                else:
                    sock = raw_socket
            except Exception:
                raw_socket.close()
                raise
            active_socket = sock
            with sock:
                sock.settimeout(10)
                try:
                    # The job loop uses select() on the socket.  A buffered
                    # reader can prefetch a job while reading the ack, making
                    # those bytes invisible to the next select() call.
                    reader = sock.makefile("rb", buffering=0)
                except TypeError:
                    # Keep compatibility with small socket doubles used by
                    # embedders and tests that expose only makefile(mode).
                    reader = sock.makefile("rb")
                writer = sock.makefile("wb")
                challenge_message = _read_json_line(reader)
                expected_audience = f"{relay_host}:{relay_port}"
                challenge = str(challenge_message.get("challenge") or "")
                if (
                    challenge_message.get("type") != "provider_challenge"
                    or challenge_message.get("protocol") != RELAY_PROTOCOL_VERSION
                    or challenge_message.get("audience") != expected_audience
                    or len(challenge) != 64
                    or any(character not in "0123456789abcdef" for character in challenge)
                ):
                    raise RelayError("invalid Relay provider challenge")
                if config.relay_payment_address:
                    challenge_payment_address = _normalize_relay_payment_address(
                        str(challenge_message.get("relay_payment_address") or ""),
                        required=True,
                    )
                    if challenge_payment_address != config.relay_payment_address:
                        raise RelayError("Relay provider challenge payment address mismatch")
                if config.relay_attestation_address:
                    challenge_attestation_address = normalize_address(
                        str(challenge_message.get("relay_attestation_address") or "")
                    )
                    if challenge_attestation_address != config.relay_attestation_address:
                        raise RelayError("Relay provider challenge attestation address mismatch")
                if endpoint.get("discovery_expires_at", float("inf")) <= time.time():
                    raise RelayError("Discovered Relay announcement expired before registration")
                _write_json_line(
                    writer,
                    {
                        "type": "provider_register",
                        "peer": _relay_provider_peer(
                            config,
                            audience=expected_audience,
                            challenge=challenge,
                        ),
                    },
                )
                registered = _read_json_line(reader)
                if (
                    registered.get("ok") is not True
                    or registered.get("type") != "provider_registered"
                    or registered.get("protocol") != RELAY_PROTOCOL_VERSION
                    or registered.get("peer_id") != config.peer_id
                    or registered.get("challenge") != challenge
                ):
                    raise RelayError(str(registered.get("error") or "invalid Relay registration acknowledgement"))
                if config.relay_payment_address:
                    registered_payment_address = _normalize_relay_payment_address(
                        str(registered.get("relay_payment_address") or ""),
                        required=True,
                    )
                    if registered_payment_address != config.relay_payment_address:
                        raise RelayError("Relay registration acknowledgement payment address mismatch")
                if config.relay_attestation_address:
                    registered_attestation_address = normalize_address(
                        str(registered.get("relay_attestation_address") or "")
                    )
                    if registered_attestation_address != config.relay_attestation_address:
                        raise RelayError("Relay registration acknowledgement attestation address mismatch")
                registration_completed = True
                # Never trust the remote ack to tell Bridge heartbeats where
                # the Provider moved. Publish the configured, pinned endpoint.
                registered["relay_host"] = relay_host
                registered["relay_provider_port"] = relay_port
                if endpoint["public_url"]:
                    registered["relay_public_url"] = endpoint["public_url"]
                    registered["relay"] = endpoint["public_url"]
                sock.settimeout(None)
                callback_errors: queue.Queue[Exception] = queue.Queue(maxsize=1)
                if on_registered is not None:
                    def run_registered_callback(
                        callback: Callable[[dict[str, Any]], None] = on_registered,
                        registration: dict[str, Any] = registered,
                        errors: queue.Queue[Exception] = callback_errors,
                        callback_socket: socket.socket = sock,
                        callback_stop_event: threading.Event | None = stop_event,
                    ) -> None:
                        if callback_stop_event is not None and callback_stop_event.is_set():
                            return
                        try:
                            callback(registration)
                        except Exception as exc:
                            try:
                                errors.put_nowait(exc)
                            except queue.Full:
                                pass
                            try:
                                callback_socket.shutdown(socket.SHUT_RDWR)
                            except (AttributeError, OSError):
                                pass

                    callback_thread = threading.Thread(
                        target=run_registered_callback,
                        name="mycomesh-relay-provider-registered",
                        daemon=True,
                    )
                    callback_thread.start()
                registered_key = config.ensure_transport_key(rotate=False)
                registered_key_id = (
                    str(registered_key.binding.get("key_id") or "")
                    if registered_key is not None
                    else ""
                )
                while stop_event is None or not stop_event.is_set():
                    if config.refresh_public_models():
                        # The registration signature covers models. Reconnect
                        # so the Relay receives a newly signed descriptor.
                        break
                    try:
                        callback_error = callback_errors.get_nowait()
                    except queue.Empty:
                        callback_error = None
                    if callback_error is not None:
                        raise RelayError(
                            f"Relay provider registration callback failed: {callback_error}"
                        ) from callback_error
                    current_key = config.ensure_transport_key()
                    current_key_id = (
                        str(current_key.binding.get("key_id") or "")
                        if current_key is not None
                        else ""
                    )
                    if current_key_id != registered_key_id:
                        break
                    readable, _, _ = select.select([sock], [], [], 1.0)
                    if not readable:
                        continue
                    try:
                        callback_error = callback_errors.get_nowait()
                    except queue.Empty:
                        callback_error = None
                    if callback_error is not None:
                        raise RelayError(
                            f"Relay provider registration callback failed: {callback_error}"
                        ) from callback_error
                    envelope = _read_json_line(reader)
                    if envelope.get("type") != "relay_job":
                        continue
                    job_id = str(envelope.get("job_id") or "")
                    message = envelope.get("message")
                    if not isinstance(message, dict):
                        response = {"ok": False, "error": "relay job message must be a JSON object"}
                    elif isinstance(message.get("secure_frame"), str):
                        try:
                            request_frame = _decode_secure_frame(message["secure_frame"])
                            response = {
                                "secure_frame": _encode_secure_frame(
                                    handle_secure_frame(config, request_frame)
                                )
                            }
                        except Exception as exc:
                            response = {"ok": False, "error": str(exc)}
                    else:
                        if config.network_profile != "local":
                            response = {
                                "ok": False,
                                "error": "plaintext relay jobs are disabled for non-local providers",
                            }
                        else:
                            response = handle_message(config, message)
                    _write_json_line(
                        writer,
                        {
                            "type": "relay_job_result",
                            "job_id": job_id,
                            "response": response,
                        },
                    )
        except (OSError, RelayError, json.JSONDecodeError) as exc:
            retry_after_connection = not (stop_event is not None and stop_event.is_set())
            if retry_after_connection:
                # A Provider remains alive while it reconnects to the Relay. Keep
                # the retry loop, but expose the reason so Docker health failures
                # can be diagnosed without attaching a debugger to the container.
                print(
                    f"relay_provider_error: {exc}; retrying in 2 seconds",
                    file=sys.stderr,
                    flush=True,
                )
        finally:
            callback_cleanup_ok = _finish_relay_registration_callback(
                callback_thread,
                active_socket,
                stop_event,
            )
            if callback_cleanup_ok and registration_completed and on_disconnected is not None:
                # Failure here deliberately stops recovery: no mixed old
                # heartbeat URL and new Relay payout/signing pins are allowed.
                on_disconnected()
        if not callback_cleanup_ok:
            raise RelayError("Relay registration callback did not finish before reconnect")
        if retry_after_connection:
            advance_endpoint = True
            endpoint_index = (endpoint_index + 1) % len(endpoints)
            time.sleep(2)


def _normalize_relay_fallbacks(values: Sequence[Mapping[str, Any]], *, network_profile: str) -> list[dict[str, Any]]:
    if not isinstance(values, (list, tuple)) or len(values) > 8:
        raise RelayError("relay_fallbacks must contain at most eight explicitly pinned endpoints")
    required = {"host", "provider_port", "public_url", "provider_tls", "payment_address", "attestation_address"}
    endpoints = []
    seen = set()
    for raw in values:
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise RelayError("Relay fallback endpoint fields are invalid")
        host, port, public_url = raw["host"], raw["provider_port"], raw["public_url"]
        try:
            literal_ip = ipaddress.ip_address(host) if isinstance(host, str) and "%" not in host else None
        except ValueError:
            literal_ip = None
        valid_dns = (isinstance(host, str) and bool(host) and len(host) <= 253 and host.isascii()
                     and all(label and len(label) <= 63 and label[0].isalnum() and label[-1].isalnum()
                             and all(char.isalnum() or char == "-" for char in label) for label in host.split(".")))
        if literal_ip is None and not valid_dns:
            raise RelayError("Relay fallback host must be a DNS hostname or literal IP address")
        if type(port) is not int or not 1 <= port <= 65535:
            raise RelayError("Relay fallback provider_port must be 1-65535")
        if type(raw["provider_tls"]) is not bool or (network_profile != "local" and not raw["provider_tls"]):
            raise RelayError("Non-local Relay fallback requires provider_tls=true")
        if not isinstance(public_url, str) or any(character.isspace() for character in public_url):
            raise RelayError("Relay fallback public_url must be a URL origin")
        try:
            parsed = urllib.parse.urlsplit(public_url)
            url_port = parsed.port
        except ValueError as exc:
            raise RelayError("Relay fallback public_url is invalid") from exc
        schemes = {"https", "http"} if network_profile == "local" else {"https"}
        if (parsed.scheme not in schemes or parsed.hostname != host.lower()
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or (url_port is not None and not 1 <= url_port <= 65535)):
            raise RelayError("Relay fallback public_url must be a TLS origin matching its host")
        pins = {}
        for name in ("payment_address", "attestation_address"):
            value = raw[name]
            try:
                if not isinstance(value, str) or len(value) != 42:
                    raise ChainError("invalid Relay fallback address")
                pins[name] = _normalize_relay_payment_address(value, required=True)
            except (ChainError, RelayError) as exc:
                raise RelayError(f"Relay fallback {name} must be a nonzero EVM address") from exc
        key = (host.lower(), port)
        if key in seen:
            raise RelayError("Relay fallback endpoints must not repeat a Provider socket")
        seen.add(key)
        endpoints.append({**raw, **pins, "host": host.lower(), "public_url": public_url.rstrip("/")})
    return endpoints


def _connect_relay_provider_socket(
    relay_host: str,
    relay_port: int,
    *,
    timeout: float,
) -> socket.socket:
    """Open the Provider's long-lived Relay socket, optionally through HTTP CONNECT.

    The sidecar's HTTP proxy settings do not affect this raw Relay connection.
    Keep the tunnel opt-in so existing direct deployments retain their current
    behavior and only providers behind a restricted egress need the extra
    setting.
    """
    proxy_url = os.getenv("MYCOMESH_PROVIDER_RELAY_PROXY", "").strip()
    if not proxy_url:
        return socket.create_connection((relay_host, relay_port), timeout=timeout)
    try:
        parsed = urllib.parse.urlsplit(proxy_url)
        proxy_port = parsed.port or (80 if parsed.scheme == "http" else 443)
    except ValueError as exc:
        raise RelayError(f"invalid MYCOMESH_PROVIDER_RELAY_PROXY: {exc}") from exc
    if parsed.scheme != "http" or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise RelayError("MYCOMESH_PROVIDER_RELAY_PROXY must be an http URL without a path")
    if not 1 <= int(proxy_port) <= 65535:
        raise RelayError("MYCOMESH_PROVIDER_RELAY_PROXY port must be between 1 and 65535")
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((parsed.hostname, int(proxy_port)), timeout=timeout)
        sock.settimeout(timeout)
        target_host = f"[{relay_host}]" if ":" in relay_host and not relay_host.startswith("[") else relay_host
        headers = [
            f"CONNECT {target_host}:{int(relay_port)} HTTP/1.1",
            f"Host: {target_host}:{int(relay_port)}",
            "Proxy-Connection: Keep-Alive",
        ]
        if parsed.username is not None:
            credentials = f"{urllib.parse.unquote(parsed.username)}:{urllib.parse.unquote(parsed.password or '')}"
            encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {encoded}")
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        reader = sock.makefile("rb", buffering=0)
        try:
            status_line = reader.readline(8192)
            parts = status_line.decode("iso-8859-1", "replace").strip().split(None, 2)
            if len(parts) < 2 or not parts[0].startswith("HTTP/"):
                raise RelayError("Relay HTTP proxy returned an invalid CONNECT response")
            try:
                status = int(parts[1])
            except ValueError as exc:
                raise RelayError("Relay HTTP proxy returned an invalid CONNECT status") from exc
            while True:
                line = reader.readline(8192)
                if not line or line in {b"\r\n", b"\n"}:
                    break
            if not 200 <= status < 300:
                raise RelayError(f"Relay HTTP proxy CONNECT failed with HTTP {status}")
        finally:
            reader.close()
        return sock
    except (OSError, RelayError):
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        raise


def relay_infer(
    state: RelayState,
    peer_id: str,
    message: dict[str, Any],
    timeout: float,
    load_reservation: RelayLoadReservation | None = None,
) -> dict[str, Any]:
    owns_reservation = load_reservation is None
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
    try:
        with state.lock:
            session = state.providers.get(peer_id)
            if session is None or (
                load_reservation is not None and load_reservation.provider is not session
            ):
                raise RelayNotDispatchedError(f"provider {peer_id!r} is not connected")
            _require_provider_admissible(state, session)
            if _relay_session_requires_secure(session) and not isinstance(message.get("secure_frame"), str):
                raise RelayError("provider requires sealed relay frames; plaintext inference is disabled")
            if load_reservation is None:
                load_reservation = _reserve_provider_load_locked(state, session)
            if load_reservation.phase != "reserved":
                raise RelayNotDispatchedError("provider load reservation is no longer available")
            job = RelayJob(
                job_id=uuid.uuid4().hex, message=message, response_queue=queue.Queue(maxsize=1),
                load_reservation=load_reservation,
            )
            try:
                session.jobs.put_nowait(job)
            except queue.Full as exc:
                raise RelayNotDispatchedError(f"provider {peer_id!r} queue is full") from exc
            _transition_provider_load_locked(load_reservation, "queued")
        try:
            envelope = job.response_queue.get(timeout=timeout)
        except queue.Empty as exc:
            if _cancel_queued_relay_job(state, session, job):
                raise RelayNotDispatchedError(f"provider {peer_id!r} queue wait timed out before dispatch") from exc
            # A response can race the waiting thread's timeout. Once received,
            # return it; never close a socket that is processing a newer job.
            try:
                envelope = job.response_queue.get_nowait()
            except queue.Empty:
                with state.lock:
                    phase = load_reservation.phase
                if phase == "received":
                    try:
                        envelope = job.response_queue.get(timeout=0.05)
                    except queue.Empty:
                        raise RelayOutcomeUnknownError("Provider response delivery did not complete before deadline") from exc
                elif phase == "released" and not load_reservation.dispatched:
                    raise RelayNotDispatchedError(f"provider {peer_id!r} request was cancelled before dispatch") from exc
                else:
                    _abort_active_relay_job(state, session, load_reservation)
                    raise RelayOutcomeUnknownError(f"provider {peer_id!r} execution timed out; outcome is unknown") from exc
        if isinstance(envelope, Exception):
            if isinstance(envelope, RelayError):
                raise envelope
            raise RelayError(str(envelope))
        if not isinstance(envelope, dict):
            raise RelayError("provider returned invalid relay response")
        if envelope.get("type") != "relay_job_result":
            raise RelayError("provider returned unexpected relay response")
        response = envelope.get("response")
        if not isinstance(response, dict):
            raise RelayError("provider result must contain a JSON response")
        if response.get("ok") is False:
            raise RelayError(str(response.get("error") or "relay inference failed"))
        return response
    finally:
        if owns_reservation:
            _release_provider_load(load_reservation)


def _relay_client_timeout(headers: Any) -> float:
    values = headers.get_all("X-MycoMesh-Request-Timeout-Ms") or []
    if not values:
        return MAX_RELAY_INFERENCE_TIMEOUT_SECONDS
    value = values[0]
    if len(values) != 1 or not isinstance(value, str) or not value.isascii() or not value.isdecimal() or len(value) > 12 or int(value) <= 0:
        raise RelayNotDispatchedError("X-MycoMesh-Request-Timeout-Ms must be a positive integer", 400)
    return min(MAX_RELAY_INFERENCE_TIMEOUT_SECONDS, int(value) / 1000)


def _remaining_relay_deadline(deadline: float, *, maximum: float = MAX_RELAY_INFERENCE_TIMEOUT_SECONDS) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RelayNotDispatchedError("Relay request total deadline exceeded before dispatch")
    return min(maximum, remaining)


def _relay_settlement_health(state: RelayState) -> dict[str, Any]:
    submitter = state._settlement_submitter
    if submitter is None:
        return {"enabled": False, "ready": False, "settlement_ready": False, "error_code": "submitter_disabled"}
    try:
        snapshot = submitter.snapshot()
        if not isinstance(snapshot, Mapping):
            raise TypeError("invalid settlement snapshot")
        return {**snapshot, "settlement_ready": snapshot.get("settlement_ready") is True}
    except Exception:
        return {"enabled": True, "ready": False, "settlement_ready": False, "error_code": "health_unavailable"}


def _verify_receipt_status_request(state: RelayState, body: Mapping[str, Any], *, now: int | None = None) -> tuple[str, str]:
    fields = {"chain_id", "settlement_contract", "key", "request_id", "issued_at", "signature"}
    if state.settlement_version == 10:
        fields.add("channel_id")
    if not isinstance(body, Mapping) or set(body) != fields:
        raise RelaySchedulingError("Receipt status request fields are invalid", 400)
    for field_name in ("chain_id", "issued_at"):
        if type(body[field_name]) is not int or not 0 < body[field_name] <= 2**53 - 1:
            raise RelaySchedulingError(f"Receipt status {field_name} must be a positive safe integer", 400)
    if abs((int(time.time()) if now is None else now) - body["issued_at"]) > 300:
        raise RelaySchedulingError("Receipt status signature has expired or is from the future", 401)
    try:
        values = {}
        for field_name, size, normalize in (("settlement_contract", 42, normalize_address),
                                             ("key", 42, normalize_address), ("request_id", 66, normalize_bytes32)):
            raw = body[field_name]
            if not isinstance(raw, str) or len(raw) != size:
                raise ChainError("invalid receipt status identifier")
            values[field_name] = normalize(raw)
            if values[field_name] != raw:
                raise ChainError("receipt status identifiers must be lowercase canonical hex")
        if values["key"] == ZERO_ADDRESS or values["settlement_contract"] == ZERO_ADDRESS:
            raise ChainError("receipt status addresses must be nonzero")
        if body["chain_id"] != state.settlement_chain_id or values["settlement_contract"] != state.settlement_contract:
            raise ChainError("receipt status deployment mismatch")
        signature = body["signature"]
        if not isinstance(signature, str) or len(signature) != 132 or not signature.startswith("0x"):
            raise ChainError("receipt status signature must be 65 bytes")
        raw_signature = bytes.fromhex(signature[2:])
        if len(raw_signature) != 65 or raw_signature[-1] not in {0, 1, 27, 28}:
            raise ChainError("receipt status signature recovery id is invalid")
    except (ChainError, ValueError) as exc:
        raise RelaySchedulingError(str(exc), 400) from exc
    channel_line = ""
    if state.settlement_version == 10:
        try:
            channel_id = normalize_bytes32(body['channel_id'])
            if channel_id != body['channel_id'] or int(channel_id, 16) == 0:
                raise ChainError('invalid receipt status channel')
        except (ChainError, TypeError, ValueError) as exc:
            raise RelaySchedulingError('Receipt status channel must be canonical nonzero bytes32', 400) from exc
        channel_line = f"\nchannel_id:{channel_id}"
    message = (f"MycoMesh receipt status v{2 if state.settlement_version == 10 else 1}\nchain_id:{body['chain_id']}"
               f"\nsettlement_contract:{values['settlement_contract']}\nkey:{values['key']}"
               f"{channel_line}\nrequest_id:{values['request_id']}\nissued_at:{body['issued_at']}").encode("ascii")
    digest = keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii") + message)
    try:
        recovered = recover_evm_address(digest, EvmSignature(
            r="0x" + raw_signature[:32].hex(), s="0x" + raw_signature[32:64].hex(), v=raw_signature[64],
        ))
    except (ChainError, ValueError) as exc:
        raise RelaySchedulingError("Receipt status signature is invalid", 401) from exc
    if recovered != values["key"]:
        raise RelaySchedulingError("Receipt status signature does not match the payment key", 401)
    return values["request_id"], values["key"]


def relay_receipt_status(state: RelayState, body: Mapping[str, Any]) -> dict[str, Any]:
    request_id, key = _verify_receipt_status_request(state, body)
    if state._settlement_submitter is None:
        raise RelaySchedulingError("Receipt status is unavailable", 503)
    result = state._settlement_submitter.public_status(request_id, key_address=key,
        **({"channel_id": body["channel_id"]} if state.settlement_version == 10 else {}))
    if not isinstance(result, Mapping):
        raise RelaySchedulingError("Receipt not found", 404)
    fields = {"request_id", "status", "error_code", "tx_hash", "updated_at", "authorization_deadline",
              "onchain_settlement_key", "escrow_release_at", "channel_id", "protocol_version"}
    return {name: result[name] for name in fields if name in result}


def v7_relay_capabilities(state: RelayState) -> dict[str, Any]:
    if state.settlement_version not in {7, 8, 9, 10}:
        return {"enabled": False}
    candidates = _v7_provider_candidates(state)
    scheduler = {
        "response_proof": RESPONSE_PROOF_SCHEMA,
        "scheduler": _scheduler_snapshot(state, candidates),
        "provider_signers": sorted({signer for item in candidates if (signer := _advertised_provider_signer(item))}),
        "protocol_version": state.settlement_version,
        **({"reservation_mode": chain_v10.RESERVATION_MODE} if state.settlement_version == 10 else {}),
        "provider_routes": [{"provider_signer": _advertised_provider_signer(item),
            "provider": item.peer.get("payment_address"), "peer_id": item.peer_id,
            "models": item.peer.get("models") or [item.peer.get("model")]} for item in candidates],
        "settlement_ready": _relay_settlement_health(state).get("settlement_ready") is True,
        "inference_ready": bool(candidates),
    } if state.settlement_version in {8, 9, 10} else {}
    if not candidates:
        return {"enabled": True, "providers": 0, **scheduler}
    peer = candidates[0].peer
    web_search_providers = sum(
        1 for candidate in candidates if _provider_supports_web_search(candidate.peer)
    )
    settlement = peer.get("settlement") if isinstance(peer.get("settlement"), dict) else {}
    return {
        "enabled": True,
        "providers": len(candidates),
        "web_search_providers": web_search_providers,
        "chain_id": int(settlement.get("chain_id") or state.settlement_chain_id or 0),
        "settlement_contract": str(settlement.get("contract") or state.settlement_contract or "").lower(),
        "relay_payment_address": state.payment_address,
        "relay_signer_address": state.attestation_address,
        "channel": str(peer.get("channel") or ""),
        "channel_hash": channel_to_hash(str(peer.get("channel") or "")),
        "pricing_version": int(settlement.get("pricing_version") or 0),
        "pricing_hash": str(settlement.get("pricing_hash") or "").lower(),
        "model": str(peer.get("model") or ""),
        "models": sorted({
            str(model_id)
            for candidate in candidates
            for model_id in (
                candidate.peer.get("models")
                if isinstance(candidate.peer.get("models"), list)
                else [candidate.peer.get("model")]
            )
            if model_id
        }),
        "payment_schema": (
            "mycomesh.x402.myco-credit-v4"
            if state.settlement_version == 10
            else "mycomesh.x402.myco-credit-v3"
            if state.settlement_version == 9
            else "mycomesh.x402.myco-credit-v2"
            if state.settlement_version == 8
            else "mycomesh.x402.myco-credit-v1"
        ),
        "session_required": False,
        **scheduler,
    }


def v7_payment_required(state: RelayState, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
    request = _v7_normalize_request(state, path, body, payment=None)
    return {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": {7: "myco-credit-v1", 8: "myco-credit-v2", 9: "myco-credit-v3", 10: "myco-credit-v4"}[state.settlement_version],
                "network": f"eip155:{request['chain_id']}",
                "asset": "USDC",
                "payTo": state.payment_address,
                "maxAmountRequired": str(request["max_fee"]),
                "maxTimeoutSeconds": 900,
                "resource": path,
                "extra": {
                    "schema": (
                        "mycomesh.x402.myco-credit-v4"
                        if state.settlement_version == 10
                        else "mycomesh.x402.myco-credit-v3"
                        if state.settlement_version == 9
                        else "mycomesh.x402.myco-credit-v2"
                        if state.settlement_version == 8
                        else "mycomesh.x402.myco-credit-v1"
                    ),
                    "settlementContract": request["contract"],
                    "relaySigner": state.attestation_address,
                    "channel": request["channel"],
                    "channelHash": request["channel_hash"],
                    "pricingVersion": request["pricing_version"],
                    "pricingHash": request["pricing_hash"],
                    "model": request["model"],
                    "maxOutputTokens": request["max_output_tokens"],
                },
            }
        ],
    }


def relay_v7_openai(
    state: RelayState,
    path: str,
    body: Mapping[str, Any],
    payment: Mapping[str, Any],
    *,
    response_proof: bool = False,
    deadline: float | None = None,
    audit_provider_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    deadline = min(deadline, time.monotonic() + MAX_RELAY_INFERENCE_TIMEOUT_SECONDS) if deadline is not None else time.monotonic() + MAX_RELAY_INFERENCE_TIMEOUT_SECONDS
    _remaining_relay_deadline(deadline)
    if state._settlement_submitter is None:
        raise RelaySettlementUnavailableError("submitter_disabled")
    if state.settlement_version == 10:
        return relay_v10_openai(state, path, body, payment, response_proof=response_proof, deadline=deadline, audit_provider_id=audit_provider_id)
    request = _v7_normalize_request(state, path, body, payment=payment)
    request["include_response_proof"] = response_proof
    if audit_provider_id is not None:
        # Internal probe adapter only; this is never copied from request JSON.
        request["audit_provider_id"] = audit_provider_id
    settlement_version = int(state.settlement_version)
    verify_authorization = {7: verify_v7_authorization, 8: verify_v8_authorization,
                            9: chain_v9.verify_authorization}[settlement_version]
    verified = verify_authorization(
        payment,
        expected_chain_id=request["chain_id"],
        expected_contract=request["contract"],
        expected_relay=state.payment_address,
        expected_relay_signer=state.attestation_address,
        expected_request_id=request["request_id"],
        expected_request_hash=request["request_hash"],
    )
    authorization = verified["authorization"]
    try:
        admission = state._settlement_submitter.reserve_admission()
    except RelaySettlementError as exc:
        raise RelaySettlementUnavailableError(str(getattr(exc, "error_code", "settlement_unavailable"))) from exc
    try:
        return _relay_admitted_v7_request(state, request, payment, authorization, deadline, admission)
    finally:
        state._settlement_submitter.release_admission(admission)


def relay_v10_openai(state: RelayState, path: str, body: Mapping[str, Any], payment: Mapping[str, Any],
        *, response_proof: bool, deadline: float, audit_provider_id: str | None = None
        ) -> tuple[dict[str, Any], dict[str, Any]]:
    from .reserved_execution import confirmed_channel_snapshot
    from .v10_relayer import prepare_v10_relay_settlement, validate_v10_response
    try:
        verified = chain_v10.verify_authorization(payment,
            expected_chain_id=state.settlement_chain_id, expected_contract=state.settlement_contract)
        channel = confirmed_channel_snapshot(str(state.settlement_rpc_url), str(state.settlement_contract),
            verified['authorization']['channel_id'], chain_id=state.settlement_chain_id,
            confirmations=6, timeout=15.0, deadline=min(deadline, time.monotonic() + 15.0))
        previous_dispatch = state._settlement_submitter.outbox.v10_dispatch(verified)
        chain_v10.validate_channel_authorization(channel, verified, for_execution=previous_dispatch is None)
        if channel['relay'] != state.payment_address or channel['relay_signer'] != state.attestation_address:
            raise ChainError('V10 channel is bound to another Relay')
        hint = _routing_provider_signer(body.get('metadata'))
        if hint != channel['provider_signer']:
            raise ChainError('V10 request must bind its channel Provider in metadata')
        request = _v7_normalize_request(state, path, body, payment=verified)
        verified = chain_v10.verify_authorization(verified,
            expected_request_id=request['request_id'], expected_request_hash=request['request_hash'])
        if (channel['channel'] != request['channel_hash'] or channel['pricing_version'] != request['pricing_version']
                or channel['pricing_hash'] != request['pricing_hash']):
            raise ChainError('V10 channel pricing does not match Provider route')
        if audit_provider_id is not None:
            request['audit_provider_id'] = audit_provider_id
        _remaining_relay_deadline(deadline)
        dispatch = state._settlement_submitter.outbox.v10_dispatch(verified, build=lambda:
            chain_v10.build_relay_dispatch(authorization_payload=verified,
                relay_private_key=state.attestation_private_keys[str(state.attestation_address)]))
        chain_v10.verify_relay_dispatch(dispatch, expected_relay_signer=state.attestation_address)
    except (ChainError, RelaySettlementError, KeyError, TypeError, ValueError) as exc:
        raise RelayNotDispatchedError(f'V10 channel admission failed: {exc}', 400) from exc
    try:
        admission = state._settlement_submitter.reserve_admission()
    except RelaySettlementError as exc:
        raise RelaySettlementUnavailableError(getattr(exc, 'error_code', 'settlement_unavailable')) from exc
    reservation = None
    try:
        # The mandatory signed routing hint fixes one Provider even across retries.
        # There is deliberately no failover loop after dispatch.
        reservation = _assign_v7_provider(state, request, _provider_affinity_key(verified['authorization']['key'], request))
        provider = reservation.provider
        if (normalize_address(str(provider.peer.get('payment_address'))) != channel['provider_owner']
                or _advertised_provider_signer(provider) != channel['provider_signer']):
            raise RelayNotDispatchedError('V10 channel Provider identity mismatch', 409)
        reservation.settlement_admission = admission
        message = {'type': 'infer', 'request_id': request['request_id'],
            'network_id': str(provider.peer.get('network_id') or 'mycomesh-testnet'),
            'channel_id': str(provider.peer.get('channel_id') or 'codex'),
            'backend_policy': str(provider.peer.get('backend_policy') or 'codex-app-server-postvalidated-v1'),
            'channel': request['channel'], 'endpoint': request['endpoint'], 'model': request['model'],
            'max_output_tokens': request['max_output_tokens'], 'payment_v10': verified, 'relay_dispatch': dispatch,
            **({'messages': request['messages']} if request['endpoint'] == 'chat' else {'input': request['input']}),
            **request['options']}
        response = _relay_v7_provider(state, provider, message,
            timeout=_remaining_relay_deadline(deadline), load_reservation=reservation)
        public_key = provider.peer.get('public_key')
        if state.network_profile != 'local' and not public_key:
            raise RelayIntegrityError('provider_identity', 'V10 Provider has no signed transport identity')
        signed = validate_v10_response(response, authorization=verified, dispatch=dispatch,
            channel=channel, request=request, provider_public_key=public_key,
            response_audience=state._scheduler_identity.public_key)
        prepared = prepare_v10_relay_settlement(signed, channel=channel,
            expected_chain_id=request['chain_id'], expected_contract=request['contract'])
        status, accepted = state._settlement_submitter.enqueue(prepared, reservation=admission)
        output = provider_response_proof(response) if response_proof else dict(response['raw'])
        return output, {'schema': 'mycomesh.x402.my-credit-receipt.v10', 'protocol_version': 10,
            'chain_id': request['chain_id'], 'settlement_contract': request['contract'],
            'channel_id': channel['channel_id'], 'settlement_key': prepared.payload['settlement_key'],
            'onchain_settlement_key': prepared.payload['settlement_key'], 'status': status,
            'accepted': bool(accepted), 'signed_receipt': signed,
            **({'audit_provider_response': dict(response), 'audit_provider_id': provider.peer_id}
               if audit_provider_id is not None else {})}
    except RelayIntegrityError as exc:
        raise RelaySchedulingError(f'V10 Provider response integrity failed: {exc}', 409) from exc
    except (ChainError, RelaySettlementError, KeyError, TypeError, ValueError) as exc:
        # Execution may already have completed: never label this not_dispatched.
        raise RelayTransientError(f'V10 receipt persistence/reconciliation failed: {exc}') from exc
    finally:
        if reservation is not None:
            _release_provider_load(reservation)
        state._settlement_submitter.release_admission(admission)


def _relay_admitted_v7_request(
    state: RelayState, request: Mapping[str, Any], payment: Mapping[str, Any],
    authorization: Mapping[str, Any], deadline: float, admission: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    settlement_version = int(state.settlement_version)
    key_grant = {7: v7_key_grant, 8: v8_key_grant, 9: chain_v9.key_grant}[settlement_version]
    account_balance = {7: v7_account_balance, 8: v8_account_balance, 9: chain_v9.account_balance}[settlement_version]
    finalize_receipt = {7: finalize_relay_receipt, 8: finalize_v8_relay_receipt,
                        9: chain_v9.finalize_relay_receipt}[settlement_version]
    grant = key_grant(
        str(state.settlement_rpc_url),
        str(state.settlement_contract),
        str(authorization["key"]),
        timeout=_remaining_relay_deadline(deadline, maximum=15.0),
    )
    if not grant["active"] or grant["owner"] == ZERO_ADDRESS:
        raise RelayError("payment key is inactive")
    if int(authorization["max_fee"]) > int(grant["max_per_request"]):
        raise RelayError("payment key max_per_request is too small")
    if settlement_version == 9:
        try:
            valid_until = int(grant["valid_until"])
            if valid_until and valid_until < int(authorization["deadline"]):
                raise RelayNotDispatchedError("V9 payment key expires before the authorization deadline", 400)
            # The generic V9 verifier supports both deployments. A longer
            # signature is executable only on a contract that actually permits
            # it; a client-selected deadline is never deployment evidence.
            if int(authorization["deadline"]) - int(authorization["issued_at"]) > chain_v9.LEGACY_MAX_AUTHORIZATION_TTL:
                actual_ttl = chain_v9.max_authorization_ttl(
                    str(state.settlement_rpc_url), str(state.settlement_contract),
                    timeout=_remaining_relay_deadline(deadline, maximum=15.0),
                )
                if int(authorization["deadline"]) - int(authorization["issued_at"]) > actual_ttl:
                    raise RelayNotDispatchedError("V9 authorization exceeds this deployment's TTL limit", 400)
        except (ChainError, KeyError, TypeError, ValueError) as exc:
            raise RelayNotDispatchedError("V9 authorization deployment/key lifetime could not be verified", 503) from exc
    if account_balance(
        str(state.settlement_rpc_url),
        str(state.settlement_contract),
        str(grant["owner"]),
        timeout=_remaining_relay_deadline(deadline, maximum=15.0),
    ) < int(authorization["max_fee"]):
        raise RelayError("payment account has insufficient prepaid balance")
    affinity_key = _provider_affinity_key(authorization.get("key"), request)
    last_error: Exception | None = None
    attempted: set[str] = set()
    while True:
        _remaining_relay_deadline(deadline)
        try:
            load_reservation = _assign_v7_provider(state, request, affinity_key, exclude=attempted)
        except RelaySchedulingError as exc:
            if last_error is not None:
                raise last_error
            raise RelayNotDispatchedError(str(exc), exc.status_code) from exc
        session = load_reservation.provider
        load_reservation.settlement_admission = admission
        attempted.add(session.peer_id)
        try:
            if settlement_version == 9:
                # A read-only admission check, not a stake reservation. The
                # contract rechecks and locks exposure when the receipt settles.
                try:
                    stake = chain_v9.provider_stake_status(
                        str(state.settlement_rpc_url), str(state.settlement_contract),
                        str(session.peer.get("payment_address") or ""),
                        timeout=_remaining_relay_deadline(deadline, maximum=15.0),
                    )
                except (ChainError, KeyError, TypeError, ValueError) as exc:
                    raise RelayNotDispatchedError("V9 Provider stake could not be verified", 503) from exc
                if int(stake["available"]) < int(authorization["max_fee"]):
                    raise RelayNotDispatchedError("V9 Provider has insufficient available stake", 503)
            message = {
                "type": "infer",
                "request_id": request["request_id"],
                "network_id": str(session.peer.get("network_id") or "mycomesh-testnet"),
                "channel_id": str(session.peer.get("channel_id") or "codex"),
                "backend_policy": str(session.peer.get("backend_policy") or "codex-app-server-postvalidated-v1"),
                "channel": request["channel"],
                "endpoint": request["endpoint"],
                "model": request["model"],
                "max_output_tokens": request["max_output_tokens"],
                f"payment_v{settlement_version}": dict(payment),
                **({"messages": request["messages"]} if request["endpoint"] == "chat" else {"input": request["input"]}),
                **request["options"],
            }
            response = _relay_v7_provider(
                state, session, message, timeout=_remaining_relay_deadline(deadline),
                load_reservation=load_reservation,
            )
        except V7ProviderRejected as exc:
            last_error = exc
            # Provider retryable may mean replay its own fenced execution, not
            # that another Provider can safely execute this authorization.
            raise
        except RelayError as exc:
            last_error = exc
            if affinity_key is None and isinstance(exc, RelayNotDispatchedError):
                continue
            raise
        else:
            # A post-inference settlement failure must not replay the work on
            # another Provider, even when its text resembles a transport error.
            return _finalize_scheduled_v7_response(
                state,
                request,
                response,
                load_reservation,
                finalize_receipt,
                expected_authorization=payment,
                account_owner=str(grant["owner"]),
            )
        finally:
            _release_provider_load(load_reservation)


def _finalize_scheduled_v7_response(
    state: RelayState, request: Mapping[str, Any], response: Mapping[str, Any],
    reservation: RelayLoadReservation, finalize_receipt: Callable,
    *, expected_authorization: Mapping[str, Any], account_owner: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    settlement_version = int(state.settlement_version)
    provider_settlement = response.get(f"mycomesh_v{settlement_version}_settlement")
    try:
        provider = reservation.provider
        expected_signer = provider.authenticated_signer or _advertised_provider_signer(provider)
        public_key = provider.peer.get("public_key")
        if state.network_profile != "local" and not public_key:
            raise RelayIntegrityError("provider_identity", "Selected Provider lacks a signed transport identity")
        validate_provider_response(
            response, expected_authorization,
            settlement_version=settlement_version, request=request,
            expected_provider=str(provider.peer.get("payment_address") or ""),
            expected_provider_signer=expected_signer,
            expected_relay=str(state.payment_address), expected_relay_signer=str(state.attestation_address),
            expected_pool=ZERO_ADDRESS,
            expected_provider_public_key=str(public_key) if public_key else None,
            expected_response_audience=state._scheduler_identity.public_key,
        )
        # Route and body checks happen BEFORE producing a Relay signature.
        if settlement_version in {8, 9, 10}:
            _validate_scheduled_provider_signer(request, reservation, provider_settlement)
        signed = finalize_receipt(
            provider_settlement,
            relay_private_key=str(state.attestation_private_keys[str(state.attestation_address)]),
        )
        if settlement_version == 9:
            from .v9_relayer import prepare_v9_relay_settlement
            prepare_settlement = prepare_v9_relay_settlement
        else:
            prepare_settlement = prepare_v8_relay_settlement if settlement_version == 8 else prepare_v7_relay_settlement
        prepared = prepare_settlement(
            signed,
            expected_chain_id=request["chain_id"],
            expected_contract=request["contract"],
            expected_relay=str(state.payment_address),
            expected_relay_signer=str(state.attestation_address),
            **({"owner": account_owner} if settlement_version == 9 else {}),
        )
        status, accepted = state._settlement_submitter.enqueue(prepared, reservation=reservation.settlement_admission)
    except RelayIntegrityError as exc:
        _record_relay_incident(state, request, response, reservation, exc,
                               expected_authorization=expected_authorization)
        raise RelaySchedulingError(f"Provider response integrity check failed: {exc}", 409) from exc
    except RelaySchedulingError as exc:
        _record_relay_incident(state, request, response, reservation, exc,
                               expected_authorization=expected_authorization)
        raise
    except (ChainError, RelaySettlementError, KeyError, TypeError, ValueError) as exc:
        raise RelayTransientError(f"failed to queue Settlement V{settlement_version} receipt: {exc}") from exc
    raw = response.get("raw")
    output = dict(raw) if isinstance(raw, dict) else {
        "output_text": response.get("output_text") or "",
        "usage": response.get("usage") or {},
        "model": request["model"],
    }
    if request.get("include_response_proof"):
        output = provider_response_proof(response)
    return output, {
        "schema": f"mycomesh.x402.my-credit-receipt.v{settlement_version}",
        "protocol_version": settlement_version,
        "chain_id": request["chain_id"],
        "settlement_contract": request["contract"],
        "settlement_key": prepared.payload["settlement_key"] if settlement_version == 9 else prepared.key,
        "status": status,
        "accepted": bool(accepted),
        **({"onchain_settlement_key": prepared.payload["settlement_key"]} if settlement_version == 9 else {}),
        # Any compatible client can verify Provider/Relay signatures and
        # persist the original Provider signer without Relay-local state.
        "signed_receipt": signed,
        **({"audit_provider_response": dict(response), "audit_provider_id": reservation.provider.peer_id}
           if request.get("audit_provider_id") is not None else {}),
    }


def _validate_scheduled_receipt_binding(
    expected_authorization: Mapping[str, Any], signed: Mapping[str, Any],
) -> None:
    """Reject a signed receipt for any request other than the admitted one.

    The on-chain contract authenticates the receipt and its authorization
    independently.  It cannot know which authorization the Relay dispatched,
    so this check must happen at the Relay boundary before enqueueing.  Keep
    this comparison deliberately structural; response/model quality is a
    separate evidence problem and must not be confused with payment binding.
    """
    outer = signed.get("authorization") if isinstance(signed, Mapping) else None
    actual = outer.get("authorization") if isinstance(outer, Mapping) else None
    if not isinstance(actual, Mapping):
        raise RelaySchedulingError("Provider receipt is missing its authorization", 409)

    try:
        validate_authorization_binding(expected_authorization, actual)
    except RelayIntegrityError as exc:
        raise RelaySchedulingError(str(exc), 409) from exc


def _record_relay_incident(
    state: RelayState,
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    reservation: RelayLoadReservation,
    error: Exception,
    *, expected_authorization: Mapping[str, Any],
) -> None:
    """Keep original signed artifacts, not merely a reporter's accusation.

    No funds move here. Invalid/expired evidence is not proof against a wallet;
    identity aliases require the independently verified registration binding.
    """
    store = state._incident_store
    code = getattr(error, "code", "route_mismatch")
    authenticated_outer = getattr(error, "response_signature_verified", False)
    soft = (not authenticated_outer or
            code in {"receipt_time_window", "admission_context_invalid", "verification_failed"})
    signer = reservation.provider.authenticated_signer if authenticated_outer else None
    if signer is None and getattr(error, "signer_identity_bound", False):
        signer = getattr(error, "verified_provider_signer", None)
    aliases = []
    if signer:
        aliases.append(_signer_risk_key(request["chain_id"], request["contract"], signer))
    keys = [reservation.provider.peer_id, *aliases]
    if not soft:
        # Memory fallback protects this process even if the disk write fails.
        with state._risk_lock:
            state._emergency_quarantine.update(keys)
            if len(state._emergency_quarantine) > MAX_RELAY_RATE_LIMIT_IDENTITIES:
                state._risk_storage_failed = True
    if store is None:
        return
    evidence = {
        "schema": "mycomesh.relay.protocol-observation.v1", "code": code,
        "settlement_version": int(state.settlement_version),
        "expected_authorization": dict(expected_authorization),
        "provider_response": dict(response),
        "provider_registration": dict(reservation.provider.registration_document or reservation.provider.peer),
        "request_constraints": {key: request.get(key) for key in (
            "request_id", "request_hash", "chain_id", "contract", "model", "endpoint", "max_output_tokens", "channel")},
        "response_signature_verified": bool(authenticated_outer),
        "observer_public_key": state._scheduler_identity.public_key,
        "signature_time_semantics": "authorization_issued_at",
        "economic_identity_verified": bool(signer),
        "monetary_verdict": False,
    }
    try:
        evidence = sign_document(
            evidence, state._scheduler_identity.private_key,
            purpose="mycomesh.relay.protocol_observation.v1",
            audience=f"{int(request['chain_id'])}:{normalize_address(str(request['contract']))}",
            timestamp=int(expected_authorization["authorization"]["issued_at"]),
            nonce=evidence_hash(evidence)[2:34],
        )
        method = store.record_incident if soft else store.record_protocol_incident
        incident = method(
            provider_id=reservation.provider.peer_id,
            provider_signer=signer,
            request_id=str(request.get("request_id") or "") or None,
            request_hash=str(request.get("request_hash") or "") or None,
            kind=f"protocol:{code}", severity="medium" if soft else "high", evidence=evidence,
            **({"risk_provider_ids": aliases} if not soft else {}),
        )
        if not soft:
            with state._risk_lock:
                state._emergency_quarantine.difference_update(keys)
    except (sqlite3.Error, OSError):
        with state._risk_lock:
            state._risk_storage_failed = True
        logging.getLogger(__name__).exception("Relay evidence persistence failed; new dispatch paused")
    except ValueError:
        logging.getLogger(__name__).exception("Relay evidence conflicts with an existing immutable observation")


def _validate_scheduled_provider_signer(
    request: Mapping[str, Any], reservation: RelayLoadReservation, signed: Mapping[str, Any],
) -> None:
    # validate_provider_response has already verified the Provider's signature. Do not
    # enqueue a validly signed receipt from a different account than selected.
    options = request.get("options")
    hint = _routing_provider_signer(options.get("metadata") if isinstance(options, Mapping) else None)
    affinity = reservation.affinity
    with reservation.state.lock:
        expected = hint or (affinity.provider_signer if affinity else None) or _advertised_provider_signer(reservation.provider)
        raw_receipt = signed.get("receipt")
        actual = raw_receipt.get("provider_signer") if isinstance(raw_receipt, Mapping) else None
        actual = normalize_address(actual) if isinstance(actual, str) else None
        if expected is not None and actual != expected:
            raise RelaySchedulingError("Provider receipt signer conflicts with the session route", 409)
        if affinity is not None and actual is not None:
            affinity.provider_signer = actual


def _relay_v7_provider(
    state: RelayState,
    session: RelayProviderSession,
    message: dict[str, Any],
    *,
    timeout: float,
    load_reservation: RelayLoadReservation | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    signed = sign_document(
        message,
        state._scheduler_identity.private_key,
        purpose=INFERENCE_REQUEST_PURPOSE,
        audience=session.peer_id,
    )
    if not _relay_session_requires_secure(session):
        response = relay_infer(
            state, session.peer_id, signed, timeout=_remaining_relay_deadline(deadline),
            **({"load_reservation": load_reservation} if load_reservation is not None else {}),
        )
    else:
        bindings = _relay_session_transport_bindings(session)
        if not bindings:
            raise RelayError("provider has no registered transport key")
        reply_key = generate_transport_key(state._scheduler_identity, lifetime_seconds=600)
        frame = seal_json_frame(
            {"message": signed, "reply_transport_key": reply_key.binding},
            sender=state._scheduler_identity,
            recipient_binding=bindings[0],
            expected_recipient_peer_id=session.peer_id,
            expected_recipient_public_key=str(session.peer.get("public_key") or "") or None,
            purpose=P2P_SECURE_REQUEST_PURPOSE,
            ttl_seconds=300,
        )
        envelope = relay_infer(
            state,
            session.peer_id,
            {"secure_frame": _encode_secure_frame(frame)},
            timeout=_remaining_relay_deadline(deadline),
            **({"load_reservation": load_reservation} if load_reservation is not None else {}),
        )
        encoded = envelope.get("secure_frame")
        if not isinstance(encoded, str):
            raise RelayError("Provider V7 secure response is missing its frame")
        try:
            opened = open_frame(
                _decode_secure_frame(encoded),
                recipient_key=reply_key,
                expected_purpose=P2P_SECURE_RESPONSE_PURPOSE,
                expected_sender_peer_id=session.peer_id,
                expected_sender_public_key=str(session.peer.get("public_key") or "") or None,
                replay_store=MemoryReplayStore(),
            )
            wrapper = opened.json_payload()
            response = wrapper.get("response") if isinstance(wrapper, dict) else None
        except SecureTransportError as exc:
            raise RelayError(f"invalid Provider V7 secure response: {exc}") from exc
        if not isinstance(response, dict):
            raise RelayError("Provider V7 secure response is invalid")
    if response.get("ok") is False:
        upstream_status = response.get("upstream_status")
        status_code = (
            int(upstream_status)
            if isinstance(upstream_status, int) and 400 <= upstream_status <= 599
            else None
        )
        upstream_error = response.get("upstream_error")
        retryable_status = status_code in {408, 409, 425, 429} or (
            status_code is not None and status_code >= 500
        )
        raise V7ProviderRejected(
            str(response.get("error") or "Provider rejected V7 inference"),
            retryable=response.get("retryable") is True or retryable_status,
            status_code=status_code,
            payload=upstream_error if isinstance(upstream_error, dict) else None,
        )
    return response


def _v7_provider_candidates(
    state: RelayState,
    *,
    model: str | None = None,
    chain_id: int | None = None,
    contract: str | None = None,
    channel: str | None = None,
    pricing_version: int | None = None,
    pricing_hash: str | None = None,
    requires_web_search: bool = False,
    affinity_key: str | None = None,
) -> list[RelayProviderSession]:
    if state.settlement_chain_id is not None:
        if chain_id is not None and int(chain_id) != int(state.settlement_chain_id):
            return []
        chain_id = int(state.settlement_chain_id)
    if state.settlement_contract:
        pinned_contract = normalize_address(state.settlement_contract)
        if contract and normalize_address(contract) != pinned_contract:
            return []
        contract = pinned_contract
    expected_contract = normalize_address(contract) if contract else None
    expected_pricing_hash = str(pricing_hash or "").lower() or None
    affinity_peer_id: str | None = None
    with state.lock:
        sessions = list(state.providers.values())
        affinity = getattr(state, "_provider_affinity", None)
        if affinity_key and isinstance(affinity, dict):
            entry = affinity.get(affinity_key)
            if entry is not None:
                if entry.in_flight or entry.expires_at > time.monotonic():
                    affinity_peer_id = entry.peer_id
                else:
                    affinity.pop(affinity_key, None)
    selected: list[RelayProviderSession] = []
    for session in sessions:
        if _provider_quarantine_reason(state, session) is not None:
            continue
        peer = session.peer
        settlement = peer.get("settlement") if isinstance(peer.get("settlement"), dict) else {}
        if int(settlement.get("version") or 0) != int(state.settlement_version):
            continue
        if model:
            advertised = peer.get("models")
            if not isinstance(advertised, list):
                advertised = [peer.get("model")]
            if model not in {str(item) for item in advertised if item}:
                continue
        if channel and str(peer.get("channel") or "") != channel:
            continue
        if chain_id is not None and int(settlement.get("chain_id") or 0) != int(chain_id):
            continue
        if expected_contract and normalize_address(str(settlement.get("contract") or "")) != expected_contract:
            continue
        if pricing_version is not None and int(settlement.get("pricing_version") or 0) != int(pricing_version):
            continue
        if expected_pricing_hash and str(settlement.get("pricing_hash") or "").lower() != expected_pricing_hash:
            continue
        if requires_web_search and not _provider_supports_web_search(peer):
            continue
        selected.append(session)
    selected.sort(
        key=lambda item: (
            0 if affinity_peer_id and item.peer_id == affinity_peer_id else 1,
            _provider_outstanding_jobs(item),
            -int(item.last_seen),
            item.peer_id,
        )
    )
    return selected


def _signer_risk_key(chain_id: Any, contract: Any, signer: str) -> str:
    return f"signer:{int(chain_id)}:{normalize_address(str(contract))}:{normalize_address(signer)}"


def _provider_risk_keys(session: RelayProviderSession, *, state: RelayState | None = None) -> tuple[str, ...]:
    # Reading a claimed identity can only block its claimant. Writing a risk
    # against that identity requires a verified signature (see incident path).
    keys = [session.peer_id]
    settlement = session.peer.get("settlement")
    signer = session.authenticated_signer or _advertised_provider_signer(session)
    if isinstance(settlement, Mapping):
        if signer is None and settlement.get("version") == 7:
            signer = session.peer.get("payment_address")
        if signer:
            try:
                keys.append(_signer_risk_key(settlement["chain_id"], settlement["contract"], signer))
            except (KeyError, ChainError, TypeError, ValueError):
                pass
    # A changed advertised deployment must not hide this Relay's existing
    # signer quarantine from direct/opaque inference paths either.
    if signer and state is not None and state.settlement_version in {7, 8, 9, 10}:
        try:
            keys.append(_signer_risk_key(state.settlement_chain_id, state.settlement_contract, signer))
        except (ChainError, TypeError, ValueError):
            pass
    return tuple(dict.fromkeys(keys))


def _provider_quarantine_reason(state: RelayState, session: RelayProviderSession) -> str | None:
    keys = _provider_risk_keys(session, state=state)
    with state._risk_lock:
        if state._risk_storage_failed:
            return "risk_store_unavailable"
        if any(key in state._emergency_quarantine for key in keys):
            return "provider_quarantined"
    if state._incident_store is not None:
        try:
            if any(state._incident_store.is_quarantined(key) for key in keys):
                return "provider_quarantined"
        except (sqlite3.Error, OSError):
            with state._risk_lock:
                state._risk_storage_failed = True
            logging.getLogger(__name__).exception("Relay risk store read failed; new dispatch paused")
            return "risk_store_unavailable"
    return None


def _require_provider_admissible(state: RelayState, session: RelayProviderSession) -> None:
    reason = _provider_quarantine_reason(state, session)
    if reason is not None:
        error = RelayNotDispatchedError(
            "Provider is quarantined" if reason == "provider_quarantined" else "Relay risk store is unavailable",
            503,
        )
        error.error_code = reason
        raise error


def _provider_affinity_key(payment_key: Any, request: Mapping[str, Any]) -> str | None:
    options = request.get("options")
    metadata = options.get("metadata") if isinstance(options, Mapping) else None
    session_id = _routing_session_id(metadata)
    if session_id is None:
        return None
    scope = json.dumps([
        str(payment_key or "").strip().lower(), int(request.get("chain_id") or 0),
        str(request.get("contract") or "").lower(), session_id,
    ], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"mycomesh-session-affinity-v1:{scope}".encode("utf-8")).hexdigest()


def _routing_session_id(metadata: Any) -> str | None:
    if metadata is None:
        return None
    if not isinstance(metadata, Mapping):
        raise RelayError("metadata must be a JSON object")
    if "mycomesh_session_id" not in metadata:
        return None
    value = metadata["mycomesh_session_id"]
    if (
        not isinstance(value, str) or not 1 <= len(value) <= 128
        or any(not 33 <= ord(char) <= 126 or char == "," for char in value)
    ):
        raise RelayError("metadata.mycomesh_session_id must be 1-128 printable ASCII characters without whitespace or commas")
    return value


def _routing_provider_signer(metadata: Any) -> str | None:
    if metadata is None:
        return None
    if not isinstance(metadata, Mapping):
        raise RelayError("metadata must be a JSON object")
    if "mycomesh_provider_signer" not in metadata:
        return None
    value = metadata["mycomesh_provider_signer"]
    # Check exact length as normalize_address's anchored pattern also accepts
    # a trailing newline. Routing markers must match the Consumer wire rules.
    if not isinstance(value, str) or len(value) != 42:
        raise RelayError("metadata.mycomesh_provider_signer must be a 0x-prefixed 40-hex address")
    try:
        return normalize_address(value)
    except ChainError as exc:
        raise RelayError("metadata.mycomesh_provider_signer must be a 0x-prefixed 40-hex address") from exc


def _advertised_provider_signer(session: RelayProviderSession) -> str | None:
    settlement = session.peer.get("settlement")
    value = settlement.get("provider_signer") if isinstance(settlement, Mapping) else None
    # This value comes from the signed Provider descriptor. A payout address
    # or an Ed25519 peer identity is never a substitute for the receipt signer.
    if not isinstance(value, str) or len(value) != 42:
        return None
    try:
        return normalize_address(value)
    except ChainError:
        return None


def _prune_provider_affinity_locked(state: RelayState, now: float) -> None:
    for key, entry in list(state._provider_affinity.items()):
        if entry.in_flight == 0 and entry.expires_at <= now:
            state._provider_affinity.pop(key, None)


def _provider_outstanding_jobs(session: RelayProviderSession) -> int:
    return session.reserved_jobs + session.queued_jobs + session.active_jobs + session.received_jobs


def _reserve_provider_load_locked(
    state: RelayState,
    session: RelayProviderSession,
    affinity: ProviderSessionAffinity | None = None,
) -> RelayLoadReservation:
    # The caller holds state.lock: selection, the initial pin and admission are
    # one operation, including the interval spent signing/sealing the request.
    session.reserved_jobs += 1
    if affinity is not None:
        affinity.in_flight += 1
    return RelayLoadReservation(state=state, provider=session, affinity=affinity)


def _transition_provider_load_locked(reservation: RelayLoadReservation, phase: str) -> bool:
    if reservation.phase == "released":
        return False
    if reservation.phase != phase:
        old_field, new_field = reservation.phase + "_jobs", phase + "_jobs"
        setattr(reservation.provider, old_field, getattr(reservation.provider, old_field) - 1)
        setattr(reservation.provider, new_field, getattr(reservation.provider, new_field) + 1)
        reservation.phase = phase
        if phase == "active":
            reservation.dispatched = True
    return True


def _transition_provider_load(reservation: RelayLoadReservation | None, phase: str) -> bool:
    if reservation is None:
        return True
    with reservation.state.lock:
        return _transition_provider_load_locked(reservation, phase)


def _release_provider_load(reservation: RelayLoadReservation | None) -> None:
    if reservation is None:
        return
    with reservation.state.lock:
        _release_provider_load_locked(reservation)


def _release_provider_load_locked(reservation: RelayLoadReservation) -> None:
    if reservation.phase == "released":
        return
    field_name = reservation.phase + "_jobs"
    setattr(reservation.provider, field_name, getattr(reservation.provider, field_name) - 1)
    reservation.phase = "released"
    if reservation.affinity is not None:
        reservation.affinity.in_flight -= 1
        reservation.affinity.expires_at = time.monotonic() + max(1, reservation.state.provider_affinity_ttl_seconds)


def _start_relay_job(state: RelayState, session: RelayProviderSession, job: RelayJob) -> bool:
    with state.lock:
        if state.providers.get(session.peer_id) is not session:
            if job.load_reservation.phase != "released":
                _release_provider_load_locked(job.load_reservation)
                job.response_queue.put_nowait(RelayNotDispatchedError("Provider disconnected before dispatch"))
            return False
        try:
            _require_provider_admissible(state, session)
        except RelayNotDispatchedError as exc:
            if job.load_reservation.phase != "released":
                _release_provider_load_locked(job.load_reservation)
                job.response_queue.put_nowait(exc)
            return False
        return _transition_provider_load_locked(job.load_reservation, "active")


def _abort_active_relay_job(state: RelayState, session: RelayProviderSession, reservation: RelayLoadReservation) -> None:
    with state.lock:
        if reservation.phase != "active":
            return
        if state.providers.get(session.peer_id) is session:
            state.providers.pop(session.peer_id, None)
    # Registry removal above fences the worker from dispatching another job.
    # Never remove or close a replacement connection for the same peer id.
    if session.connection is not None:
        close_socket(session.connection)
    _fail_pending_jobs(session, RelayNotDispatchedError("Provider active request timed out; queued request was not dispatched"))


def _assign_v7_provider(
    state: RelayState,
    request: Mapping[str, Any],
    affinity_key: str | None,
    *,
    exclude: set[str] | None = None,
) -> RelayLoadReservation:
    options = request.get("options")
    provider_hint = _routing_provider_signer(options.get("metadata") if isinstance(options, Mapping) else None)
    candidates = _v7_provider_candidates(
        state, model=request["model"], chain_id=request["chain_id"], contract=request["contract"],
        channel=request["channel"], pricing_version=request["pricing_version"],
        pricing_hash=request["pricing_hash"], requires_web_search=bool(request.get("requires_web_search")),
    )
    if request.get("audit_provider_id") is not None:
        candidates = [item for item in candidates if item.peer_id == request["audit_provider_id"]]
    with state.lock:
        now = time.monotonic()
        _prune_provider_affinity_locked(state, now)
        candidates = [item for item in candidates if state.providers.get(item.peer_id) is item]
        affinity = state._provider_affinity.get(affinity_key) if affinity_key else None
        if affinity is not None:
            if provider_hint and affinity.provider_signer and provider_hint != affinity.provider_signer:
                raise RelaySchedulingError("Provider signer hint conflicts with the session binding", 409)
            session = state.providers.get(affinity.peer_id)
            if session is None:
                raise RelaySchedulingError("Session Provider is not connected; automatic session migration is disabled")
            advertised_signer = _advertised_provider_signer(session)
            expected_signer = provider_hint or affinity.provider_signer
            if expected_signer and advertised_signer != expected_signer:
                if advertised_signer is None:
                    raise RelaySchedulingError("Session Provider does not advertise its receipt signer; automatic session migration is disabled")
                raise RelaySchedulingError("Provider signer conflicts with the session binding", 409)
            if not any(item is session for item in candidates):
                raise RelaySchedulingError("Session Provider does not support this request; automatic session migration is disabled", 409)
            if exclude and session.peer_id in exclude:
                raise RelaySchedulingError("Session Provider is unavailable; retry on the same session")
        else:
            if provider_hint:
                hinted_providers = [item for item in state.providers.values()
                                    if _advertised_provider_signer(item) == provider_hint]
                if not hinted_providers:
                    raise RelaySchedulingError("Original session Provider signer is not connected; automatic session migration is disabled")
                candidates = [item for item in candidates if _advertised_provider_signer(item) == provider_hint]
                if not candidates:
                    raise RelaySchedulingError("Original session Provider does not support this request; automatic session migration is disabled", 409)
            candidates = [item for item in candidates if not exclude or item.peer_id not in exclude]
            if not candidates:
                raise RelaySchedulingError(f"no compatible Settlement V{state.settlement_version} Provider is connected")
            bound_sessions: dict[str, int] = {}
            if affinity_key:
                for entry in state._provider_affinity.values():
                    bound_sessions[entry.peer_id] = bound_sessions.get(entry.peer_id, 0) + 1
            session = min(candidates, key=lambda item: (
                _provider_outstanding_jobs(item), bound_sessions.get(item.peer_id, 0),
                -item.last_seen, item.peer_id,
            ))
            if affinity_key:
                if len(state._provider_affinity) >= MAX_PROVIDER_AFFINITY_ENTRIES:
                    # Do not evict live or merely busy conversations to admit
                    # a new one. Only expired, idle bindings are reclaimed.
                    raise RelaySchedulingError("Session affinity capacity is exhausted")
                affinity = ProviderSessionAffinity(
                    peer_id=session.peer_id, expires_at=now + max(1, state.provider_affinity_ttl_seconds),
                    provider_signer=_advertised_provider_signer(session),
                )
                state._provider_affinity[affinity_key] = affinity
        _require_provider_admissible(state, session)
        return _reserve_provider_load_locked(state, session, affinity)


def _scheduler_snapshot(state: RelayState, candidates: list[RelayProviderSession]) -> dict[str, Any]:
    with state.lock:
        current = [item for item in candidates if state.providers.get(item.peer_id) is item]
        return {
            "version": 1, "session_affinity": True,
            "active_jobs": sum(item.active_jobs for item in current),
            "queued_jobs": sum(item.queued_jobs for item in current),
            "reserved_jobs": sum(item.reserved_jobs for item in current),
            "outstanding_jobs": sum(_provider_outstanding_jobs(item) for item in current),
            # One serial work stream per Provider socket, not a thread or HTTP
            # connection limit. Reserved or queued work already occupies it.
            "available_slots": sum(_provider_outstanding_jobs(item) == 0 for item in current),
            "total_slots": len(current),
        }


def _bind_provider_affinity(state: RelayState, affinity_key: str | None, peer_id: str) -> None:
    if not affinity_key:
        return
    with state.lock:
        now = time.monotonic()
        _prune_provider_affinity_locked(state, now)
        existing = state._provider_affinity.get(affinity_key)
        if existing is not None:
            if existing.peer_id != peer_id:
                raise RelaySchedulingError("Session Provider binding cannot be silently changed", 409)
            existing.expires_at = now + max(1, state.provider_affinity_ttl_seconds)
            return
        if len(state._provider_affinity) >= MAX_PROVIDER_AFFINITY_ENTRIES:
            raise RelaySchedulingError("Session affinity capacity is exhausted")
        state._provider_affinity[affinity_key] = ProviderSessionAffinity(
            peer_id=peer_id, expires_at=now + max(1, state.provider_affinity_ttl_seconds),
            provider_signer=_advertised_provider_signer(state.providers[peer_id]) if peer_id in state.providers else None,
        )


def _clear_provider_affinity(state: RelayState, affinity_key: str | None, peer_id: str | None = None) -> None:
    if not affinity_key:
        return
    with state.lock:
        affinity = getattr(state, "_provider_affinity", None)
        if affinity is None:
            return
        entry = affinity.get(affinity_key)
        if entry is not None and entry.in_flight == 0 and (peer_id is None or entry.peer_id == peer_id):
            affinity.pop(affinity_key, None)


def _provider_supports_web_search(peer: Mapping[str, Any]) -> bool:
    capability = peer.get("backend_capability")
    return (
        isinstance(capability, Mapping)
        and capability.get("supports_web_search") is True
        and "/v1/alpha/search" in capability.get("endpoints", [])
    )


def _is_alpha_search_input(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 1
        and isinstance(value[0], Mapping)
        and value[0].get("type") == "mycomesh_alpha_search_request"
        and isinstance(value[0].get("request"), Mapping)
    )


def _v7_normalize_request(
    state: RelayState,
    path: str,
    body: Mapping[str, Any],
    *,
    payment: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if state.settlement_version not in {7, 8, 9, 10}:
        raise RelayError("Payment-key settlement is not enabled on this Relay")
    endpoint = "chat" if path.endswith("/chat/completions") else "responses"
    if not isinstance(body, Mapping):
        raise RelayError("inference body must be a JSON object")
    explicit_session_id = _routing_session_id(body.get("metadata"))
    provider_hint = _routing_provider_signer(body.get("metadata"))
    requested_model = str(body.get("model") or "")
    candidates = _v7_provider_candidates(state, model=requested_model or None)
    if provider_hint:
        candidates = [item for item in candidates if _advertised_provider_signer(item) == provider_hint]
        if not candidates:
            with state.lock:
                connected = any(_advertised_provider_signer(item) == provider_hint for item in state.providers.values())
            raise RelaySchedulingError(
                "Original session Provider does not support this request" if connected else "Original session Provider signer is not connected",
                409 if connected else 503,
            )
    if not candidates:
        if explicit_session_id is not None:
            raise RelaySchedulingError("No connected Provider supports this session request; automatic session migration is disabled")
        raise RelayError(f"no Settlement V{state.settlement_version} Provider supports model {requested_model!r}")
    peer = candidates[0].peer
    model = requested_model or str(peer.get("model") or "")
    output_value = body.get("max_output_tokens")
    if output_value is None:
        output_value = body.get("max_tokens")
    max_output_tokens = int(output_value or 2000)
    if max_output_tokens <= 0:
        raise RelayError("max_output_tokens must be positive")
    input_value = body.get("input")
    messages = body.get("messages")
    if endpoint == "chat" and messages is None:
        raise RelayError("chat completions require messages")
    options = {
        field: body[field]
        for field in RESPONSES_REQUEST_OPTION_FIELDS | RESPONSES_LOCAL_OPTION_FIELDS
        if field in body
    }
    try:
        normalized_options = normalize_inference_request_options(endpoint, options)
        request_hash = "0x" + inference_request_hash(
            endpoint=endpoint,
            model=model,
            input_value=input_value,
            messages=messages,
            max_output_tokens=max_output_tokens,
            options=normalized_options,
        )
    except (ReservationError, TypeError, ValueError) as exc:
        raise RelayError(str(exc)) from exc
    settlement = peer.get("settlement") if isinstance(peer.get("settlement"), dict) else {}
    chain_id = int(settlement.get("chain_id") or state.settlement_chain_id or 0)
    contract = normalize_address(str(settlement.get("contract") or state.settlement_contract or ""))
    channel = str(peer.get("channel") or "")
    pricing_version = int(settlement.get("pricing_version") or 0)
    pricing_hash = str(settlement.get("pricing_hash") or "").lower()
    if not chain_id or not pricing_version or not pricing_hash:
        raise RelayError(f"Provider V{state.settlement_version} pricing deployment is incomplete")
    request_id = ""
    if payment is not None:
        raw_auth = payment.get("authorization") if isinstance(payment, Mapping) else None
        request_id = str(raw_auth.get("request_id") or "") if isinstance(raw_auth, Mapping) else ""
    normalized = {
        "endpoint": endpoint,
        "model": model,
        "max_output_tokens": max_output_tokens,
        "options": normalized_options,
        "request_hash": request_hash,
        "request_id": request_id,
        "max_fee": int(
            os.getenv(
                f"MYCOMESH_V{state.settlement_version}_DEFAULT_MAX_FEE_UNITS",
                os.getenv("MYCOMESH_V7_DEFAULT_MAX_FEE_UNITS", "100000"),
            )
        ),
        "chain_id": chain_id,
        "contract": contract,
        "channel": channel,
        "channel_hash": channel_to_hash(channel),
        "pricing_version": pricing_version,
        "pricing_hash": pricing_hash,
        "requires_web_search": _is_alpha_search_input(input_value),
    }
    normalized["messages" if endpoint == "chat" else "input"] = messages if endpoint == "chat" else input_value
    return normalized


def _v7_payment_header(headers: Any) -> dict[str, Any] | None:
    value = headers.get("PAYMENT-SIGNATURE") or headers.get("X-PAYMENT")
    if not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(str(value).encode("ascii") + b"=" * (-len(str(value)) % 4))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RelayError(f"invalid x402 PAYMENT-SIGNATURE header: {exc}") from exc
    if not isinstance(decoded, dict):
        raise RelayError("x402 PAYMENT-SIGNATURE must contain a JSON object")
    # x402 clients commonly wrap the scheme payload in `payload`; older
    # MycoMesh clients sent the payload object directly. Accept both forms so
    # the custom `myco-credit-v1` scheme remains interoperable at the HTTP edge.
    payload = decoded.get("payload")
    if isinstance(payload, dict) and "authorization" in payload:
        return payload
    payment = decoded.get("payment")
    if isinstance(payment, dict) and "authorization" in payment:
        return payment
    return decoded


def _encode_payment_header(value: Mapping[str, Any]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _disconnect_relay_provider(state: RelayState, session: RelayProviderSession) -> None:
    with state.lock:
        if state.providers.get(session.peer_id) is session:
            state.providers.pop(session.peer_id, None)
    if session.connection is not None:
        close_socket(session.connection)
    _fail_pending_jobs(session, RelayNotDispatchedError(f"provider {session.peer_id!r} disconnected before dispatch"))


def _cancel_queued_relay_job(state: RelayState, session: RelayProviderSession, job: RelayJob) -> bool:
    # Worker dispatch and cancellation use the same state lock. If the worker
    # has popped the queue but not dispatched yet, releasing the reservation
    # makes its active transition fail. Removing a queued item also frees the
    # bounded queue slot immediately instead of leaving a cancelled tombstone.
    with state.lock:
        reservation = job.load_reservation
        if reservation is None or reservation.phase != "queued":
            return False
        with session.jobs.mutex:
            try:
                session.jobs.queue.remove(job)
            except ValueError:
                pass
            else:
                session.jobs.unfinished_tasks = max(0, session.jobs.unfinished_tasks - 1)
                session.jobs.not_full.notify()
                if session.jobs.unfinished_tasks == 0:
                    session.jobs.all_tasks_done.notify_all()
        # Do not reenter state.lock: tests and callers may supply a plain Lock.
        _release_provider_load_locked(reservation)
        return True


def verify_relay_consumer_request(state: RelayState, message: dict[str, Any], peer_id: str | None = None) -> str:
    if not state.authorized_consumers and not state.allow_any_signed_consumer:
        raise RelayError("relay consumer allowlist is required")
    try:
        target_peer_id = str(peer_id or message.get("provider_peer_id") or "")
        declared_peer_id = str(message.get("provider_peer_id") or target_peer_id)
        if target_peer_id and declared_peer_id != target_peer_id:
            raise RelayError("relay target peer mismatch")
        audience = target_peer_id
        verify_document(message, purpose=INFERENCE_REQUEST_PURPOSE, audience=audience or None)
    except IdentityError as exc:
        raise RelayError(f"invalid relay control request signature: {exc}") from exc
    signature = message.get("signature")
    public_key = str(signature.get("public_key") or "") if isinstance(signature, dict) else ""
    if public_key not in state.authorized_consumers and not state.allow_any_signed_consumer:
        raise RelayError("consumer is not authorized for this relay")
    request_id = str(message.get("request_id") or "")
    if not request_id:
        raise RelayError("request_id is required")
    if state._replay_store is not None:
        try:
            state._replay_store.remember(
                "relay.infer.request",
                f"{public_key}:{target_peer_id}:{request_id}",
                int(state.replay_ttl_seconds),
            )
        except ReplayError as exc:
            raise RelayError(str(exc).replace("replay key", "request_id")) from exc
    _consumer_rate_limit(state, public_key)
    return public_key


def verify_relay_consumer_frame(
    state: RelayState,
    encoded_frame: str,
    *,
    peer_id: str,
    admission: Any = None,
    address_probe: bool = False,
    session_status: bool = False,
    verified_admission: dict[str, Any] | None = None,
) -> str:
    is_address_probe = address_probe is True
    is_session_status = session_status is True
    if is_address_probe and is_session_status:
        raise RelayError("secure relay request cannot be both an address probe and session_status")
    if (
        not is_address_probe
        and not state.authorized_consumers
        and not state.allow_any_signed_consumer
        and state.v3_admission_config is None
        and not _is_v4_admission(admission)
    ):
        raise RelayError("relay consumer allowlist is required")
    with state.lock:
        session = state.providers.get(peer_id)
    if session is None:
        raise RelayError(f"provider {peer_id!r} is not connected")
    bindings = _relay_session_transport_bindings(session)
    if not bindings:
        raise RelayError("provider has not registered a signed transport key")
    request_frame = _decode_secure_frame(encoded_frame)
    expected_purpose = (
        P2P_ADDRESS_PROBE_PURPOSE
        if is_address_probe
        else P2P_SESSION_STATUS_REQUEST_PURPOSE
        if is_session_status
        else P2P_SECURE_REQUEST_PURPOSE
    )
    try:
        metadata = verify_frame_metadata(
            request_frame,
            expected_purpose=expected_purpose,
            expected_recipient_peer_id=peer_id,
            expected_recipient_public_key=str(session.peer.get("public_key") or "") or None,
        )
        binding = next(
            (
                item
                for item in bindings
                if str(item.get("key_id") or "") == metadata.recipient_key_id
            ),
            None,
        )
        if binding is None:
            raise RelayError("secure relay request targets an unregistered provider transport key")
        verify_frame_metadata(
            request_frame,
            expected_purpose=expected_purpose,
            expected_recipient_peer_id=peer_id,
            expected_recipient_public_key=str(session.peer.get("public_key") or "") or None,
            expected_recipient_binding=binding,
        )
    except SecureTransportError as exc:
        raise RelayError(f"invalid secure relay request: {exc}") from exc
    verified_session_status = metadata.purpose == P2P_SESSION_STATUS_REQUEST_PURPOSE
    if verified_admission is not None:
        verified_admission["session_status"] = verified_session_status
    public_key = metadata.sender_public_key
    v4_admission = _is_v4_admission(admission)
    if verified_session_status and (
        not v4_admission or str(admission.get("version") or "") not in {"5", "6"}
    ):
        raise RelayError("session_status requires Settlement V5 or V6 admission")
    requires_v3_admission = (
        not is_address_probe
        and public_key not in state.authorized_consumers
        and not state.allow_any_signed_consumer
        and not v4_admission
    )
    if requires_v3_admission:
        if state.v3_admission_config is None:
            raise RelayError("consumer is not authorized for this relay")
        if not state._v3_admission_slots.acquire(blocking=False):
            raise RelayError("Relay V3 admission capacity is exhausted")
    else:
        _consumer_rate_limit(state, public_key)
    try:
        if state._replay_store is None:
            raise RelayError("secure relay requires a persistent replay store")
        try:
            state._replay_store.remember(
                "relay.secure.envelope",
                f"{public_key}:{peer_id}:{metadata.message_id}",
                max(1, metadata.expires_at - int(time.time())),
            )
        except ReplayError as exc:
            raise RelayError("secure relay request has already been forwarded") from exc
        if v4_admission:
            try:
                verified_session = _verify_relay_v4_admission(
                    admission,
                    sender_public_key=public_key,
                    provider_peer=session.peer,
                    peer_id=peer_id,
                    expected_relay_payment_address=state.payment_address,
                    require_deployment=str(admission.get("version") or "") in {"5", "6"},
                )
                if str(admission.get("version") or "") in {"5", "6"}:
                    requested_signer = normalize_address(
                        str(admission.get("relay_attestation_address") or "")
                    )
                    if requested_signer not in state.attestation_private_keys:
                        raise SessionProtocolError(
                            f"V{admission.get('version')} Relay attestation key is not available"
                        )
                    if verified_admission is not None:
                        verified_admission["v5_attestation_request"] = {
                            "chain_id": int(verified_session["settlement_chain_id"]),
                            "settlement_contract": str(verified_session["settlement_contract"]),
                            "session_id": str(verified_session["session_id"]),
                            "request_hash": str(verified_session["request_hash"]),
                            "max_fee_units": int(verified_session["max_fee_units"]),
                            "provider": str(verified_session["provider_payment_address"]),
                            "relay": str(verified_session["relay_payment_address"]),
                            "sequence": int(verified_session["sequence"]) - 1,
                            "deadline": int(verified_session["deadline"]),
                            "relay_attestation_address": requested_signer,
                            "relay_epoch": int(verified_session.get("relay_epoch") or 0),
                            "protocol_version": int(admission.get("version") or 5),
                        }
            except (ChainError, SessionProtocolError, TypeError, ValueError) as exc:
                raise RelayError(f"consumer V4 admission was rejected: {exc}") from exc
            _consumer_rate_limit(state, public_key)
        elif requires_v3_admission:
            try:
                verified_v3 = verify_relay_v3_admission(
                    admission,
                    sender_public_key=public_key,
                    provider_peer=session.peer,
                    config=state.v3_admission_config,
                )
                if verified_admission is not None:
                    verified_admission["v3_max_fee_units"] = int(verified_v3["max_fee_units"])
            except ConsumerAdmissionError as exc:
                raise RelayError(f"consumer V3 admission was rejected: {exc}") from exc
            _consumer_rate_limit(state, public_key)
    finally:
        if requires_v3_admission:
            state._v3_admission_slots.release()
    return public_key


def _is_v4_admission(value: Any) -> bool:
    return isinstance(value, dict) and str(value.get("version") or "") in {"4", "5", "6"}


def _relay_response_fee_units(response: Any) -> int | None:
    """Read a plaintext settlement fee without opening sealed Relay frames."""

    if not isinstance(response, dict):
        return None
    for key in ("mycomesh_v6_settlement", "mycomesh_v5_settlement", "mycomesh_v4_settlement", "mycomesh_v3_settlement"):
        settlement = response.get(key)
        if not isinstance(settlement, dict):
            continue
        for field_name in ("quoted_fee", "amount_units"):
            value = settlement.get(field_name)
            try:
                if value is not None:
                    return max(0, int(value))
            except (TypeError, ValueError):
                return None
    return None


def _verify_relay_v4_admission(
    admission: Any,
    *,
    sender_public_key: str,
    provider_peer: Mapping[str, Any],
    peer_id: str,
    expected_relay_payment_address: str | None = None,
    require_deployment: bool = False,
) -> dict[str, Any]:
    """Validate a signed V4 envelope without a per-request chain read.

    The Relay authenticates only the transport admission.  Provider-side
    admission remains authoritative for the on-chain session, sequence, and
    price, so this fast path cannot mint spend or bypass Settlement checks.
    """
    if not isinstance(admission, dict):
        raise SessionProtocolError("V4 admission must be an object")
    authorization = admission.get("session_authorization")
    request = admission.get("session_request")
    if not isinstance(authorization, dict) or not isinstance(request, dict):
        raise SessionProtocolError("V4 admission must contain session_authorization and session_request")
    provider_id = str(provider_peer.get("peer_id") or peer_id)
    auth = verify_session_authorization(
        authorization,
        provider_id=provider_id,
        expected_session_public_key=sender_public_key,
        now=int(time.time()),
        require_outer_signature=True,
        require_evm_signature=True,
    )
    # The Relay deliberately does not keep the Provider's durable Session
    # progress.  Validate the request against its own predecessor so a
    # multi-request prepaid session can pass this transport admission; the
    # Provider remains authoritative for the actual cross-request sequence.
    normalized_request = normalize_session_request(
        request,
        require_signature=True,
        require_canonical=True,
    )
    previous_sequence = int(normalized_request["sequence"]) - 1
    previous_spend = int(normalized_request["cumulative_spend_units"]) - int(
        normalized_request["max_fee_units"]
    )
    if previous_sequence < 0 or previous_spend < 0:
        raise SessionProtocolError("V4 request predecessor is invalid")
    verified_request = verify_session_request(
        normalized_request,
        auth,
        previous_sequence=previous_sequence,
        previous_cumulative_spend_units=previous_spend,
        now=int(time.time()),
        require_outer_signature=True,
        require_evm_signature=True,
    )
    if str(verified_request["session_public_key"]).lower() != sender_public_key.lower():
        raise SessionProtocolError("V4 request signer does not match Relay sender")
    if expected_relay_payment_address:
        try:
            expected_payment_address = _normalize_relay_payment_address(
                expected_relay_payment_address,
                required=True,
            )
        except RelayError as exc:
            raise SessionProtocolError(str(exc)) from exc
        if verified_request["relay_payment_address"].lower() != expected_payment_address:
            raise SessionProtocolError("V4 Relay payment address mismatch")
    result = dict(verified_request)
    result["settlement_chain_id"] = auth.get("settlement_chain_id")
    result["settlement_contract"] = auth.get("settlement_contract")
    if require_deployment and (
        result["settlement_chain_id"] is None or result["settlement_contract"] is None
    ):
        raise SessionProtocolError("V5 Relay admission is missing its settlement deployment")
    return result


def _consumer_rate_limit(state: RelayState, public_key: str) -> None:
    _bounded_rate_limit(
        state,
        state.consumer_rate_limits,
        public_key,
        error="consumer rate limit exceeded",
    )


def _bounded_rate_limit(
    state: RelayState,
    entries: dict[str, list[float]],
    identity: str,
    *,
    error: str,
) -> None:
    now = time.time()
    with state.lock:
        recent = [
            timestamp
            for timestamp in entries.get(identity, [])
            if now - timestamp < state.rate_limit_window_seconds
        ]
        if identity not in entries and len(entries) >= MAX_RELAY_RATE_LIMIT_IDENTITIES:
            for candidate, timestamps in list(entries.items()):
                if not any(now - timestamp < state.rate_limit_window_seconds for timestamp in timestamps):
                    entries.pop(candidate, None)
            if len(entries) >= MAX_RELAY_RATE_LIMIT_IDENTITIES:
                raise RelayError("rate limit identity capacity reached")
        if len(recent) >= state.rate_limit_max_requests:
            raise RelayError(error)
        recent.append(now)
        entries[identity] = recent


def _reserve_consumer_slot(state: RelayState, public_key: str) -> None:
    with state.lock:
        active = int(state.consumer_in_flight.get(public_key) or 0)
        if active >= state.consumer_max_in_flight:
            raise RelayError("consumer concurrency exceeded")
        state.consumer_in_flight[public_key] = active + 1


def _release_consumer_slot(state: RelayState, public_key: str) -> None:
    with state.lock:
        active = int(state.consumer_in_flight.get(public_key) or 0)
        if active <= 1:
            state.consumer_in_flight.pop(public_key, None)
        else:
            state.consumer_in_flight[public_key] = active - 1


def send_relay_message(address: RelayAddress, message: dict[str, Any], timeout: float) -> dict[str, Any]:
    if address.secure:
        raise RelayError(
            "myco+relay(s):// requires send_secure_relay_message and a signed provider transport key"
        )
    return _post_relay_message(address, {"message": message}, timeout)


def send_secure_relay_message(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None = None,
) -> dict[str, Any]:
    return _send_secure_relay_message(
        address,
        message,
        timeout,
        sender=sender,
        recipient_binding=recipient_binding,
        expected_recipient_public_key=expected_recipient_public_key,
        purpose=P2P_SECURE_REQUEST_PURPOSE,
        address_probe=False,
        session_status=False,
    )


def send_secure_relay_status(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None = None,
) -> dict[str, Any]:
    if not isinstance(message, dict) or message.get("type") != "session_status":
        raise RelayError("secure Relay status request must be a session_status message")
    return _send_secure_relay_message(
        address,
        message,
        timeout,
        sender=sender,
        recipient_binding=recipient_binding,
        expected_recipient_public_key=expected_recipient_public_key,
        purpose=P2P_SESSION_STATUS_REQUEST_PURPOSE,
        address_probe=False,
        session_status=True,
    )


def send_secure_relay_probe(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(message, dict)
        or set(message) != {"type", "request_id", "audience"}
        or message.get("type") != "ping"
        or not isinstance(message.get("request_id"), str)
        or not message["request_id"]
    ):
        raise RelayError("secure Relay address probe must contain only a ping")
    return _send_secure_relay_message(
        address,
        message,
        timeout,
        sender=sender,
        recipient_binding=recipient_binding,
        expected_recipient_public_key=expected_recipient_public_key,
        purpose=P2P_ADDRESS_PROBE_PURPOSE,
        address_probe=True,
        session_status=False,
    )


def submit_relay_settlement(
    address: RelayAddress,
    submission: Mapping[str, Any],
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Submit a Consumer-signed V5 receipt to the Relay's durable outbox."""

    if not isinstance(submission, Mapping):
        raise RelayError("Relay settlement submission must be an object")
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=60.0,
            label="Relay settlement submission timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
    version = int(submission.get("protocol_version") or 5)
    if version not in {5, 6}:
        raise RelayError("Relay settlement submission protocol_version must be 5 or 6")
    url = f"{address.http_origin}/v{version}/settlements"
    request = urllib.request.Request(
        url,
        data=json.dumps(dict(submission), separators=(",", ":")).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    deadline = time.monotonic() + timeout
    try:
        with _RELAY_HTTP_OPENER.open(request, timeout=timeout) as response:
            payload = read_bounded(
                response,
                maximum=64 * 1024,
                label="Relay settlement response",
                deadline=deadline,
            ).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            payload = read_bounded(
                exc,
                maximum=64 * 1024,
                label="Relay settlement error response",
                deadline=deadline,
            ).decode("utf-8", errors="replace")
        finally:
            exc.close()
        raise RelayError(f"Relay settlement returned HTTP {exc.code}: {text_preview(payload)}") from exc
    except (urllib.error.URLError, NetworkIOError) as exc:
        raise RelayError(f"failed to submit settlement to Relay: {exc}") from exc
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RelayError("Relay settlement response is not JSON") from exc
    if not isinstance(value, dict):
        raise RelayError("Relay settlement response must be an object")
    if value.get("ok") is not True:
        raise RelayError(text_preview(str(value.get("error") or "Relay rejected settlement")))
    return value


def _send_secure_relay_message(
    address: RelayAddress,
    message: dict[str, Any],
    timeout: float,
    *,
    sender: NodeIdentity,
    recipient_binding: dict[str, Any],
    expected_recipient_public_key: str | None,
    purpose: str,
    address_probe: bool,
    session_status: bool,
) -> dict[str, Any]:
    if not address.secure:
        raise RelayError("secure relay messages require a myco+relay:// or myco+relays:// address")
    try:
        resolved_timeout = bounded_timeout(
            timeout,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
        reply_key = generate_transport_key(sender, lifetime_seconds=600)
        request_frame = seal_json_frame(
            {"message": message, "reply_transport_key": reply_key.binding},
            sender=sender,
            recipient_binding=recipient_binding,
            expected_recipient_peer_id=address.peer_id,
            expected_recipient_public_key=expected_recipient_public_key,
            purpose=purpose,
            ttl_seconds=min(300, max(30, int(resolved_timeout) + 5)),
        )
    except (NetworkIOError, SecureTransportError, ValueError) as exc:
        raise RelayError(f"failed to seal secure relay request: {exc}") from exc
    value = _post_relay_message(
        address,
        {
            "secure_frame": _encode_secure_frame(request_frame),
            # The Relay validates this signed admission before forwarding the
            # encrypted frame.  It never receives the request plaintext; the
            # Provider repeats the full V4 checks after decryption.
            **(
                {
                    "admission": (
                        {
                            "version": str(int(message.get("session_protocol_version") or 4)),
                            "session_authorization": message.get("session_authorization"),
                            "session_request": message.get("session_request"),
                            **(
                                {"relay_attestation_address": message.get("relay_attestation_address")}
                                if int(message.get("session_protocol_version") or 4) in {5, 6}
                                else {}
                            ),
                        }
                        if message.get("session_v4") is True
                        else message.get("payment_reservation")
                    )
                }
                if message.get("session_v4") is True or message.get("payment_reservation") is not None
                else {}
            ),
            **({"address_probe": True} if address_probe else {}),
            **({"session_status": True} if session_status else {}),
        },
        resolved_timeout,
    )
    encoded_response = value.get("secure_frame")
    if not isinstance(encoded_response, str):
        raise RelayError("secure relay response is missing its sealed frame")
    try:
        opened = open_frame(
            _decode_secure_frame(encoded_response),
            recipient_key=reply_key,
            expected_purpose=P2P_SECURE_RESPONSE_PURPOSE,
            expected_sender_peer_id=address.peer_id,
            expected_sender_public_key=expected_recipient_public_key,
            replay_store=MemoryReplayStore(),
        )
        wrapper = opened.json_payload()
        if set(wrapper) != {"response"} or not isinstance(wrapper.get("response"), dict):
            raise RelayError("secure relay response wrapper is invalid")
        response = wrapper["response"]
    except SecureTransportError as exc:
        raise RelayError(f"invalid secure relay response: {exc}") from exc
    if response.get("ok") is False:
        raise RelayError(str(response.get("error") or "relay inference failed"))
    if value.get("relay_attestation") is not None:
        response["_mycomesh_relay_attestation"] = value.get("relay_attestation")
    return response


def _post_relay_message(
    address: RelayAddress,
    body: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    try:
        timeout = bounded_timeout(
            timeout,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
    url = f"{address.http_origin}/infer/{urllib.parse.quote(address.peer_id, safe='')}"
    request = urllib.request.Request(
        url,
        data=json.dumps({**body, "timeout": timeout}).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    request_timeout = timeout + 5
    deadline = time.monotonic() + request_timeout
    # Health probes and session-status queries are idempotent. Retry these
    # short control-plane calls when a mobile/unstable network drops the TCP
    # connection before a response arrives. Inference frames are never retried
    # here because the Provider may already have consumed a paid request.
    retryable_control = bool(body.get("address_probe") or body.get("session_status"))
    attempts = 3 if retryable_control else 1
    payload: str | None = None
    for attempt in range(attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RelayError("relay request deadline exceeded")
        try:
            with _RELAY_HTTP_OPENER.open(request, timeout=min(request_timeout, remaining)) as response:
                payload = read_bounded(
                    response,
                    maximum=MAX_RELAY_RESPONSE_BYTES,
                    label="relay response",
                    deadline=deadline,
                ).decode("utf-8", errors="replace")
            break
        except urllib.error.HTTPError as exc:
            try:
                payload = read_bounded(
                    exc,
                    maximum=MAX_RELAY_RESPONSE_BYTES,
                    label="relay error response",
                    deadline=deadline,
                ).decode("utf-8", errors="replace")
            except NetworkIOError as limit_exc:
                raise RelayError(str(limit_exc)) from exc
            finally:
                exc.close()
            # HTTP responses are definitive; do not replay them.
            raise RelayError(f"relay returned HTTP {exc.code}: {text_preview(payload)}") from exc
        except (NetworkIOError, urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt + 1 >= attempts:
                if isinstance(exc, NetworkIOError):
                    raise RelayError(str(exc)) from exc
                raise RelayError(f"failed to reach relay: {exc}") from exc
            time.sleep(min(0.15 * (2**attempt), max(0.0, deadline - time.monotonic())))
    if payload is None:
        raise RelayError("relay request produced no response")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RelayError("relay response must be a JSON object")
    if value.get("ok") is False:
        raise RelayError(text_preview(str(value.get("error") or "relay request failed")))
    return value


def list_relay_providers(state: RelayState) -> list[dict[str, Any]]:
    with state.lock:
        sessions = list(state.providers.values())
    providers = []
    for session in sessions:
        reason = _provider_quarantine_reason(state, session)
        risk = {"status": "healthy", "evidence_count": 0}
        if state._incident_store is not None and reason != "risk_store_unavailable":
            try:
                snapshots = [state._incident_store.risk_snapshot(key) for key in _provider_risk_keys(session, state=state)]
                risk = max(snapshots, key=lambda row: (
                    {"healthy": 0, "suspect": 1, "quarantined": 2}.get(row["status"], 2),
                    row["evidence_count"],
                ))
            except (sqlite3.Error, OSError):
                with state._risk_lock:
                    state._risk_storage_failed = True
                reason = "risk_store_unavailable"
        if reason:
            risk = {**risk, "status": "unavailable" if reason == "risk_store_unavailable" else "quarantined"}
        providers.append({**session.peer, "connected_at": session.connected_at,
                          "last_seen": session.last_seen, "risk": risk})
    providers.sort(key=lambda item: (int(item.get("last_seen") or 0), str(item.get("peer_id") or "")), reverse=True)
    return providers


def parse_relay_address(value: str) -> RelayAddress:
    raw = value.strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"relay", "relays", "myco+relay", "myco+relays"}:
        raise ValueError(
            "relay address must use relay://, relays://, myco+relay://, or myco+relays://"
        )
    if not parsed.hostname:
        raise ValueError("relay host is required")
    if parsed.port is None:
        raise ValueError("relay port is required")
    peer_id = urllib.parse.unquote(parsed.path.lstrip("/"))
    if not peer_id:
        raise ValueError("relay peer id is required")
    return RelayAddress(host=parsed.hostname, port=parsed.port, peer_id=peer_id, scheme=parsed.scheme)


def _relay_provider_peer(
    config: ProviderConfig,
    audience: str | None = None,
    challenge: str | None = None,
) -> dict[str, Any]:
    transport_keys = config.accepted_transport_bindings()
    peer = {
        "peer_id": config.peer_id,
        "protocol": RELAY_PROTOCOL_VERSION,
        "channel": config.channel,
        "agent_id": config.agent_id,
        "model": config.model,
        "models": list(getattr(config, "models", ()) or (getattr(config, "model", ""),)),
        "last_seen": int(time.time()),
        "network_profile": config.network_profile,
        "secure_transport_required": config.network_profile != "local",
    }
    if config.network_profile != "local":
        peer.update(
            {
                "network_id": config.network_id,
                "channel_id": config.channel_id,
                "backend_policy": config.backend_policy,
            }
        )
    peer.update(provider_runtime_capabilities(config))
    if challenge is not None:
        peer["challenge"] = challenge
    if config.identity is not None:
        peer["public_key"] = config.identity.public_key
    if transport_keys:
        peer["transport_key"] = transport_keys[0]
        peer["transport_keys"] = transport_keys
    if config.payment_address:
        peer["payment_address"] = config.payment_address
    relay_payment_address = getattr(config, "relay_payment_address", None)
    if relay_payment_address:
        peer["relay_payment_address"] = relay_payment_address
    relay_attestation_address = getattr(config, "relay_attestation_address", None)
    if relay_attestation_address:
        peer["relay_attestation_address"] = relay_attestation_address
    if getattr(config, "settlement_version", 0) in {7, 8, 9, 10} and getattr(config, "evm_identity_path", None) and challenge and audience:
        from .provider_bootstrap import load_provider_evm_identity
        receipt_identity = load_provider_evm_identity(config.evm_identity_path)
        peer["settlement_identity_binding"] = build_provider_identity_binding(
            peer, audience=audience, private_key=receipt_identity.private_key,
        )
    return sign_document(peer, config.identity.private_key, purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE, audience=audience)


def verify_relay_provider_peer(
    peer: dict[str, Any],
    require_signed: bool = True,
    audience: str | None = None,
    expected_challenge: str | None = None,
    expected_relay_payment_address: str | None = None,
    expected_relay_attestation_address: str | None = None,
) -> dict[str, Any]:
    if not require_signed:
        normalized = dict(peer)
        normalized = _normalize_provider_relay_payment_address(
            normalized,
            expected_relay_payment_address=expected_relay_payment_address,
        )
        return _normalize_provider_relay_attestation_address(
            normalized,
            expected_relay_attestation_address=expected_relay_attestation_address,
        )
    try:
        unsigned = verify_document(peer, purpose=RELAY_PROVIDER_REGISTRATION_PURPOSE, audience=audience)
    except IdentityError as exc:
        raise RelayError(f"invalid provider signature: {exc}") from exc
    public_key = str(unsigned.get("public_key") or "")
    if not public_key:
        signature = peer.get("signature")
        if isinstance(signature, dict):
            public_key = str(signature.get("public_key") or "")
    if not public_key:
        raise RelayError("provider public_key is required")
    if peer["signature"].get("public_key") != public_key:
        raise RelayError("provider public_key does not match registration signer")
    if str(unsigned.get("peer_id") or "") != peer_id_from_public_key(public_key):
        raise RelayError("peer_id does not match public_key")
    if expected_challenge is not None and unsigned.get("challenge") != expected_challenge:
        raise RelayError("provider registration challenge does not match this connection")
    normalized = dict(unsigned)
    normalized["public_key"] = public_key
    normalized["signature"] = peer["signature"]
    binding = normalized.get("transport_key")
    if binding is not None:
        if not isinstance(binding, dict):
            raise RelayError("provider transport_key must be an object")
        try:
            verify_transport_key_binding(
                binding,
                expected_peer_id=str(normalized.get("peer_id") or ""),
                expected_identity_public_key=public_key,
            )
        except SecureTransportError as exc:
            raise RelayError(f"invalid provider transport key: {exc}") from exc
    network_profile = str(normalized.get("network_profile") or "local").strip().lower()
    if network_profile not in {"local", "testnet", "open"}:
        raise RelayError("provider network_profile is invalid")
    secure_required = normalized.get("secure_transport_required", False)
    if type(secure_required) is not bool:
        raise RelayError("provider secure_transport_required must be a boolean")
    if network_profile != "local" and not secure_required:
        raise RelayError("non-local relay providers must require secure transport")
    if network_profile != "local":
        try:
            require_enabled_channel_binding(
                network_id=normalized.get("network_id"),
                channel_id=normalized.get("channel_id"),
                channel=normalized.get("channel"),
                backend_policy=normalized.get("backend_policy"),
                label="Relay Provider",
            )
        except ValueError as exc:
            raise RelayError(str(exc)) from exc
    if secure_required and not isinstance(binding, dict):
        raise RelayError("secure relay provider requires a signed transport key")
    raw_transport_keys = normalized.get("transport_keys", [])
    if not isinstance(raw_transport_keys, list) or len(raw_transport_keys) > 4:
        raise RelayError("provider transport_keys must be a list of at most four bindings")
    verified_key_ids: set[str] = set()
    for item in raw_transport_keys:
        if not isinstance(item, dict):
            raise RelayError("provider transport_keys entries must be objects")
        try:
            verified_key = verify_transport_key_binding(
                item,
                expected_peer_id=str(normalized.get("peer_id") or ""),
                expected_identity_public_key=public_key,
            )
        except SecureTransportError as exc:
            raise RelayError(f"invalid provider transport key: {exc}") from exc
        if verified_key.key_id in verified_key_ids:
            raise RelayError("provider transport_keys contains a duplicate key")
        verified_key_ids.add(verified_key.key_id)
    if isinstance(binding, dict) and raw_transport_keys:
        current_key_id = str(binding.get("key_id") or "")
        if current_key_id not in verified_key_ids:
            raise RelayError("provider transport_keys must include transport_key")
    try:
        payment_address = normalize_payment_address(str(normalized.get("payment_address")) if normalized.get("payment_address") else None)
    except BillingError as exc:
        raise RelayError(str(exc)) from exc
    if payment_address:
        normalized["payment_address"] = payment_address
    normalized = _normalize_provider_relay_payment_address(
        normalized,
        expected_relay_payment_address=expected_relay_payment_address,
    )
    return _normalize_provider_relay_attestation_address(
        normalized,
        expected_relay_attestation_address=expected_relay_attestation_address,
    )


def _normalize_provider_relay_payment_address(
    peer: dict[str, Any],
    *,
    expected_relay_payment_address: str | None,
) -> dict[str, Any]:
    raw_payment_address = peer.get("relay_payment_address")
    supplied_payment_address = _normalize_relay_payment_address(
        str(raw_payment_address) if raw_payment_address else None,
        required=expected_relay_payment_address is not None,
    )
    expected_payment_address = _normalize_relay_payment_address(
        expected_relay_payment_address,
        required=expected_relay_payment_address is not None,
    )
    if expected_payment_address and supplied_payment_address != expected_payment_address:
        raise RelayError("Provider registration Relay payment address mismatch")
    if supplied_payment_address:
        peer["relay_payment_address"] = supplied_payment_address
    return peer


def _normalize_provider_relay_attestation_address(
    peer: dict[str, Any],
    *,
    expected_relay_attestation_address: str | None,
) -> dict[str, Any]:
    raw = peer.get("relay_attestation_address")
    try:
        supplied = normalize_address(str(raw or ZERO_ADDRESS))
        expected = normalize_address(str(expected_relay_attestation_address or ZERO_ADDRESS))
    except ChainError as exc:
        raise RelayError(f"Provider registration Relay attestation address is invalid: {exc}") from exc
    if expected != ZERO_ADDRESS and supplied != expected:
        raise RelayError("Provider registration Relay attestation address mismatch")
    if supplied != ZERO_ADDRESS:
        peer["relay_attestation_address"] = supplied
    return peer


def _relay_session_requires_secure(session: RelayProviderSession) -> bool:
    return bool(session.peer.get("secure_transport_required"))


def _relay_session_transport_bindings(session: RelayProviderSession) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    current = session.peer.get("transport_key")
    if isinstance(current, dict):
        bindings.append(current)
    raw = session.peer.get("transport_keys")
    if isinstance(raw, list):
        bindings.extend(item for item in raw if isinstance(item, dict))
    deduplicated: dict[str, dict[str, Any]] = {}
    for binding in bindings:
        key_id = str(binding.get("key_id") or "")
        if key_id:
            deduplicated[key_id] = binding
    return list(deduplicated.values())


def _fail_pending_jobs(session: RelayProviderSession, exc: Exception) -> None:
    while True:
        try:
            job = session.jobs.get_nowait()
        except queue.Empty:
            return
        _release_provider_load(job.load_reservation)
        job.response_queue.put(exc)


def _write_json_line(writer: Any, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
    writer.write(data)
    writer.flush()


def _read_json_line(reader: Any) -> dict[str, Any]:
    raw = reader.readline(MAX_RELAY_MESSAGE_BYTES + 1)
    if not raw:
        raise RelayError("connection closed")
    if len(raw) > MAX_RELAY_MESSAGE_BYTES:
        raise RelayError("message too large")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RelayError("message must be a JSON object")
    return value


def _encode_secure_frame(frame: bytes) -> str:
    if not isinstance(frame, bytes) or not frame or len(frame) > MAX_SECURE_FRAME_BYTES:
        raise RelayError("secure relay frame size is invalid")
    return base64.urlsafe_b64encode(frame).decode("ascii").rstrip("=")


def _decode_secure_frame(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_RELAY_ENCODED_FRAME_BYTES:
        raise RelayError("secure relay frame size is invalid")
    padding = "=" * (-len(value) % 4)
    try:
        frame = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RelayError("secure relay frame is not valid base64url") from exc
    if not frame or len(frame) > MAX_SECURE_FRAME_BYTES:
        raise RelayError("secure relay frame size is invalid")
    return frame


def _coerce_timeout(value: Any, default: float) -> float:
    resolved = default if value is None else value
    try:
        return bounded_timeout(
            resolved,
            maximum=MAX_RELAY_INFERENCE_TIMEOUT_SECONDS,
            label="relay inference timeout",
        )
    except NetworkIOError as exc:
        raise RelayError(str(exc)) from exc
