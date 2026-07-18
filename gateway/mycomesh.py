from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
import json
from decimal import Decimal
import logging
import os
import re
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .attestation import (
    AttestationError,
    settlement_response_hash,
    verify_provider_settlement_attestation,
)
from .billing import (
    DEFAULT_KEY_CHALLENGE_CAPACITY,
    DEFAULT_KEY_CHALLENGE_RATE_PER_MINUTE,
    DEFAULT_KEY_CHALLENGE_VERIFICATION_ATTEMPTS,
    MAX_KEY_CHALLENGE_VERIFICATION_ATTEMPTS,
    BillingError,
    BillingStore,
    ChainBalanceUnavailable,
    ChainSyncSuperseded,
    ConsumerAccount,
    KeyChallengeVerificationInProgress,
    KeyChallengeVerificationLimitExceeded,
    normalize_api_key_hash,
    normalize_payment_address,
    usdc_to_units,
    units_to_usdc,
)
from .browser_cors import parse_allowed_origins
from .chain import (
    ZERO_ADDRESS,
    ChainError,
    EvmSignature,
    call_contract,
    call_uint256,
    channel_to_hash,
    evm_signature_from_json,
    keccak256,
    load_active_myco_deployment,
    normalize_address,
    normalize_bytes32,
    recover_evm_address,
    rpc_call,
    rpc_int,
)
from .chain_v3 import (
    EIP1271SignatureRejected,
    MAX_EIP1271_SIGNATURE_BYTES,
    reservation_id_for,
    verify_eip1271_signature,
    verify_provider_settlement_payload,
)
from .channel_policy import require_deployment_channel_binding, require_enabled_channel_binding
from .gateway_registry import (
    DEFAULT_GATEWAY_REGISTRY_DB,
    DEFAULT_GATEWAY_TTL_SECONDS,
    GATEWAY_REGISTRATION_PURPOSE,
    GatewayRegistry,
    GatewayRegistryError,
    normalize_gateway_url,
)
from .identity import DEFAULT_REQUEST_IDENTITY_PATH, load_or_create_identity, sign_document
from .ledger import DEFAULT_LEDGER_PATH, append_receipt_payload_once, build_receipt, sign_acceptance
from .netio import NetworkIOError, bounded_timeout
from .pool import DEFAULT_POOL_URL, PoolError
from .pricing import load_pricing_config, quote_usage
from .pricing_source import channel_pricing_snapshot
from .p2p import (
    DEFAULT_CHANNEL,
    DEFAULT_PUBLIC_MODEL_ID,
    MAX_RESERVE_INPUT_TOKENS,
    MAX_RESERVE_OUTPUT_TOKENS,
    P2PError,
    canonical_inference_input_bytes,
)
from .protocol import ProtocolValidationError, verify_provider_response
from .reservation import (
    ReservationError,
    evm_session_authorization_digest,
    evm_session_authorization_message,
    evm_session_authorization_payload,
    inference_request_hash,
    validate_evm_session_authorization,
    verify_eoa_session_authorization,
)
from .request_limits import BoundedRequestBodyMiddleware
from .server_limits import (
    DEFAULT_GATEWAY_MAX_CONCURRENT_REQUESTS,
    BoundedASGIConcurrencyMiddleware,
    bounded_connection_count,
)
from .relay import RelayError
from .client import build_bridge_usage, _peer_addresses, _relay_id_for_address, _send_infer_to_address, _split_urls, discover_peers_from_pools
from .routing import (
    DEFAULT_ROUTE_STATE_PATH,
    load_route_state,
    rank_peers,
    record_route_acceptance,
    record_route_failure,
    record_route_success,
    release_peer,
    reserve_peer,
    save_route_state,
)


MAX_MYCOMESH_INFERENCE_TIMEOUT_SECONDS = 300.0
DEFAULT_MYCOMESH_INFERENCE_CONCURRENCY = 8
MAX_MYCOMESH_INFERENCE_CONCURRENCY = 64
MAX_KEY_REGISTRATION_RPC_TIMEOUT_SECONDS = 30.0
DEFAULT_KEY_REGISTRATION_RPC_CONCURRENCY = 4
MAX_KEY_REGISTRATION_RPC_CONCURRENCY = 32
DEFAULT_CONSUMER_V3_RESERVATION_TTL_SECONDS = 15 * 60
MIN_CONSUMER_V3_RESERVATION_TTL_SECONDS = 5 * 60
MAX_CONSUMER_V3_RESERVATION_TTL_SECONDS = 60 * 60
logger = logging.getLogger(__name__)


mycomesh_max_concurrent_requests = bounded_connection_count(
    os.getenv("MYCOMESH_MAX_CONCURRENT_REQUESTS", str(DEFAULT_GATEWAY_MAX_CONCURRENT_REQUESTS)),
    label="MycoMesh max concurrent requests",
)
mycomesh_inference_concurrency = bounded_connection_count(
    os.getenv("MYCOMESH_INFERENCE_CONCURRENCY", str(DEFAULT_MYCOMESH_INFERENCE_CONCURRENCY)),
    label="MycoMesh inference concurrency",
    maximum=MAX_MYCOMESH_INFERENCE_CONCURRENCY,
)
_inference_slots = threading.BoundedSemaphore(mycomesh_inference_concurrency)
key_registration_rpc_concurrency = bounded_connection_count(
    os.getenv(
        "MYCOMESH_KEY_REGISTRATION_RPC_CONCURRENCY",
        str(DEFAULT_KEY_REGISTRATION_RPC_CONCURRENCY),
    ),
    label="key registration RPC concurrency",
    maximum=MAX_KEY_REGISTRATION_RPC_CONCURRENCY,
)
_key_registration_rpc_slots = threading.BoundedSemaphore(key_registration_rpc_concurrency)
_key_registration_rpc_executor = ThreadPoolExecutor(
    max_workers=key_registration_rpc_concurrency,
    thread_name_prefix="mycomesh-key-registration-rpc",
)
_key_registration_nonce_lock = threading.Lock()
_key_registration_nonces_inflight: set[str] = set()


class _KeyRegistrationNonceClaim:
    def __init__(self, nonce: str) -> None:
        self.nonce = nonce
        self._lock = threading.Lock()
        self._deferred_to_worker = False
        self._worker_finished = False
        self._released = False
        self._release_callback: Callable[[], None] | None = None

    def set_release_callback(self, callback: Callable[[], None]) -> None:
        run_now = False
        with self._lock:
            if self._released:
                run_now = True
            else:
                self._release_callback = callback
        if run_now:
            callback()

    def _finish_release(self, callback: Callable[[], None] | None) -> None:
        try:
            if callback is not None:
                callback()
        except Exception:
            logger.exception("failed to release key registration verification lease")
        finally:
            _release_inflight_key_registration_nonce(self.nonce)

    def defer_to_worker(self) -> None:
        release_now = False
        callback = None
        with self._lock:
            self._deferred_to_worker = True
            if self._worker_finished and not self._released:
                self._released = True
                release_now = True
                callback = self._release_callback
        if release_now:
            self._finish_release(callback)

    def worker_finished(self) -> None:
        release_now = False
        callback = None
        with self._lock:
            self._worker_finished = True
            if self._deferred_to_worker and not self._released:
                self._released = True
                release_now = True
                callback = self._release_callback
        if release_now:
            self._finish_release(callback)

    def release(self) -> None:
        callback = None
        with self._lock:
            if self._deferred_to_worker or self._released:
                return
            self._released = True
            callback = self._release_callback
        self._finish_release(callback)


class _InferenceControl:
    def __init__(self, deadline: float) -> None:
        self.deadline = float(deadline)
        self._cancelled = threading.Event()
        self._funds_lock = threading.Lock()
        self._committed_response: dict[str, Any] | None = None

    def remaining(self) -> float:
        if self._cancelled.is_set():
            raise HTTPException(status_code=504, detail="MycoMesh inference deadline exceeded")
        return _remaining_inference_time(self.deadline)

    def ensure_active(self) -> None:
        self.remaining()

    def run_funds_action(
        self,
        operation: Callable[[], Any],
        *,
        committed_response: dict[str, Any] | None = None,
    ) -> Any:
        with self._funds_lock:
            self.ensure_active()
            result = operation()
            if committed_response is not None:
                self._committed_response = dict(committed_response)
            return result

    def cancel(self) -> None:
        self._cancelled.set()
        # Synchronize with an in-flight reserve/capture before the outer coroutine
        # returns a timeout. New funds actions will observe the cancellation.
        with self._funds_lock:
            pass

    def committed_response(self) -> dict[str, Any] | None:
        if self._committed_response is None:
            return None
        return dict(self._committed_response)

cors_allowed_origins = parse_allowed_origins(
    os.getenv("MYCOMESH_CORS_ALLOWED_ORIGINS"),
    setting="MYCOMESH_CORS_ALLOWED_ORIGINS",
)
app = FastAPI(title="MycoMesh Consumer Proxy")
app.add_middleware(
    BoundedRequestBodyMiddleware,
    limit=lambda: int(os.getenv("MYCOMESH_MAX_REQUEST_BYTES", str(1024 * 1024))),
    timeout_seconds=lambda: float(os.getenv("MYCOMESH_REQUEST_BODY_TIMEOUT_SECONDS", "30")),
)
app.add_middleware(
    BoundedASGIConcurrencyMiddleware,
    maximum=mycomesh_max_concurrent_requests,
)
if cors_allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
store = BillingStore(os.getenv("MYCOMESH_BILLING_DB", ".codex-run/mycomesh-billing.sqlite3"))
gateway_registry = GatewayRegistry(os.getenv("MYCOMESH_GATEWAY_REGISTRY_DB", DEFAULT_GATEWAY_REGISTRY_DB))
request_identity = load_or_create_identity(os.getenv("MYCOMESH_REQUEST_IDENTITY", DEFAULT_REQUEST_IDENTITY_PATH))


@app.get("/health")
async def health() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "service": "mycomesh-proxy",
        "billing_mode": _billing_mode(),
    }
    if not _env_flag("MYCOMESH_HEALTH_PUBLIC_DETAILS", False):
        return payload
    payload.update(_detailed_health_payload())
    return payload


@app.get("/admin/health")
async def admin_health(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    payload: dict[str, Any] = {
        "ok": True,
        "service": "mycomesh-proxy",
        "billing_mode": _billing_mode(),
    }
    payload.update(_detailed_health_payload())
    return payload


@app.get("/.well-known/mycomesh.json")
async def well_known_mycomesh() -> dict[str, Any]:
    return _network_discovery_payload(limit=int(os.getenv("MYCOMESH_DISCOVERY_LIMIT", "5")))


@app.get("/v1/mycomesh/gateways")
async def public_gateways(limit: int = 5) -> dict[str, Any]:
    return _network_discovery_payload(limit=limit)


@app.post("/v1/mycomesh/keys/challenge")
async def key_registration_challenge(payload: dict[str, Any]) -> dict[str, Any]:
    _require_public_key_registration_enabled()
    try:
        context = _key_registration_context()
    except (ChainError, GatewayRegistryError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"invalid key registration configuration: {exc}") from exc
    try:
        wallet = normalize_payment_address(payload.get("wallet"))
        if wallet is None:
            raise BillingError("wallet is required")
        key_hash = normalize_api_key_hash(str(payload.get("key_hash") or ""))
        chain_id = int(payload.get("chain_id") if payload.get("chain_id") is not None else context["chain_id"])
        if chain_id != int(context["chain_id"]):
            raise BillingError("key registration chain_id does not match this gateway")
        ttl_seconds = _key_challenge_ttl(payload.get("ttl_seconds"))
        challenge = store.create_key_challenge(
            wallet=wallet,
            key_hash=key_hash,
            chain_id=chain_id,
            ttl_seconds=ttl_seconds,
            capacity=int(
                os.getenv("MYCOMESH_KEY_CHALLENGE_CAPACITY", str(DEFAULT_KEY_CHALLENGE_CAPACITY))
            ),
            rate_per_minute=int(
                os.getenv(
                    "MYCOMESH_KEY_CHALLENGE_RATE_PER_MINUTE",
                    str(DEFAULT_KEY_CHALLENGE_RATE_PER_MINUTE),
                )
            ),
        )
        signed_challenge = {**challenge, **context}
    except (BillingError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    message = _key_registration_message(signed_challenge)
    return {
        "wallet": challenge["wallet"],
        "account_id": challenge["wallet"],
        "key_hash": challenge["key_hash"],
        "key_fingerprint": str(challenge["key_hash"])[:12],
        "chain_id": challenge["chain_id"],
        "network_id": context["network_id"],
        "origin": context["origin"],
        "settlement": context["settlement"],
        "nonce": challenge["nonce"],
        "expires_at": challenge["expires_at"],
        "message": message,
        "signature_type": "personal_sign",
    }


@app.post("/v1/mycomesh/keys/register")
@app.post("/v1/mycomesh/keys/rotate")
async def register_consumer_key(payload: dict[str, Any]) -> dict[str, Any]:
    _require_public_key_registration_enabled()
    try:
        context = _key_registration_context()
    except (ChainError, GatewayRegistryError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"invalid key registration configuration: {exc}") from exc
    nonce = ""
    nonce_claim: _KeyRegistrationNonceClaim | None = None
    verification_token = ""
    try:
        wallet = normalize_payment_address(payload.get("wallet"))
        if wallet is None:
            raise BillingError("wallet is required")
        key_hash = normalize_api_key_hash(str(payload.get("key_hash") or ""))
        chain_id = int(payload.get("chain_id") if payload.get("chain_id") is not None else context["chain_id"])
        if chain_id != int(context["chain_id"]):
            raise BillingError("key registration chain_id does not match this gateway")
        nonce = str(payload.get("nonce") or "").strip()
        nonce_claim = _claim_inflight_key_registration_nonce(nonce)
        challenge = store.validate_key_challenge(
            wallet=wallet,
            key_hash=key_hash,
            chain_id=chain_id,
            nonce=nonce,
        )
        max_attempts = _configured_key_registration_max_attempts()
        expected_message = _key_registration_message({**challenge, **context})

        def claim_verification() -> Callable[[], None]:
            nonlocal verification_token
            claimed = store.claim_key_challenge_verification(
                wallet=wallet,
                key_hash=key_hash,
                chain_id=chain_id,
                nonce=nonce,
                max_attempts=max_attempts,
            )
            verification_token = str(claimed["verification_token"])
            nonce_claim.set_release_callback(
                lambda token=verification_token: store.release_key_challenge_verification(nonce, token)
            )
            return lambda token=verification_token: store.rollback_key_challenge_verification_claim(
                nonce,
                token,
            )

        await _verify_key_registration_signature_async(
            wallet=wallet,
            message=expected_message,
            signature_payload=payload.get("signature"),
            caller=str(context["settlement"]),
            nonce_claim=nonce_claim,
            before_submit=claim_verification,
        )
        if not verification_token:
            raise BillingError("key registration verification claim was not established")
        account = store.consume_key_challenge_and_register_key_hash(
            account_id=wallet,
            wallet=wallet,
            key_hash=key_hash,
            chain_id=chain_id,
            nonce=nonce,
            verification_token=verification_token,
            payment_address=wallet,
            credential_origin=str(context["origin"]),
            credential_network_id=str(context["network_id"]),
            credential_chain_id=int(context["chain_id"]),
            credential_settlement=str(context["settlement"]),
        )
    except HTTPException:
        raise
    except KeyChallengeVerificationInProgress as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except KeyChallengeVerificationLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except (BillingError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        if nonce_claim is not None:
            nonce_claim.release()
    result = _account_payload(account)
    result.update(
        {
            "account_id": account.account_id,
            "wallet": wallet,
            "api_key_material": "client_generated",
            "api_key_returned": False,
            "base_url": context["public_url"],
            "credential_audience": context["origin"],
            "credential_scope": "origin_network_chain_settlement",
        }
    )
    return result


@app.post("/gateways")
async def register_gateway(payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_signed = isinstance(payload.get("signature"), dict)
    local_compat = _is_local_profile()
    public_local_registration = (
        require_signed and local_compat and _env_flag("MYCOMESH_ALLOW_PUBLIC_GATEWAY_REGISTRATION", False)
    )
    if not public_local_registration:
        _require_admin(authorization)
    try:
        chain_id, settlement = _consumer_chain_binding()
        record = gateway_registry.register(
            payload,
            ttl_seconds=int(os.getenv("MYCOMESH_GATEWAY_TTL_SECONDS", str(DEFAULT_GATEWAY_TTL_SECONDS))),
            require_signed=require_signed,
            expected_network_id=_network_id(),
            expected_chain_id=chain_id,
            expected_settlement=settlement,
            local_compat=local_compat,
        )
    except (ChainError, GatewayRegistryError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return record.to_dict()


@app.get("/gateways")
async def list_registered_gateways(
    authorization: str | None = Header(default=None),
    include_inactive: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    _require_admin(authorization)
    return {
        "object": "list",
        "data": [record.to_dict() for record in gateway_registry.list_gateways(include_inactive=include_inactive, limit=limit)],
    }


@app.post("/gateways/{node_id}/status")
async def set_gateway_status(node_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    try:
        record = gateway_registry.set_status(node_id, str(payload.get("status") or ""))
    except GatewayRegistryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return record.to_dict()


def _detailed_health_payload() -> dict[str, Any]:
    pricing_table = load_pricing_config(os.getenv("MYCOMESH_PRICING_CONFIG"))
    snapshot = channel_pricing_snapshot(pricing_table, os.getenv("MYCOMESH_CHANNEL", DEFAULT_CHANNEL))
    return {
        "pool": os.getenv("MYCOMESH_POOL_URL", DEFAULT_POOL_URL),
        "gateways": _gateway_urls(limit=5),
        "consumer_public_key": request_identity.public_key,
        "channel_pricing_hash": snapshot.pricing_hash,
        "pricing_source": snapshot.source,
        "chain_sync": store.get_chain_sync_state(),
    }


@app.post("/accounts")
async def create_account(payload: dict[str, Any] | None = None, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    context = _credential_context_or_503()
    account = store.create_account(
        (payload or {}).get("account_id"),
        payment_address=(payload or {}).get("payment_address"),
        credential_origin=str(context["origin"]),
        credential_network_id=str(context["network_id"]),
        credential_chain_id=int(context["chain_id"]),
        credential_settlement=str(context["settlement"]),
    )
    return {
        "account_id": account.account_id,
        "api_key": account.api_key,
        "key_fingerprint": account.key_fingerprint,
        "status": account.status,
        "balance_usdc": account.balance_usdc,
        "payment_address": account.payment_address,
        "parent_account_id": account.parent_account_id,
        "discount_bps": account.discount_bps,
        "reseller_margin_bps": account.reseller_margin_bps,
        "monthly_quota_usdc": units_to_usdc(account.monthly_quota_units),
        "monthly_used_usdc": units_to_usdc(account.monthly_used_units),
        "usage_tier": account.usage_tier,
        "credential_audience": account.credential_origin,
        "credential_network_id": account.credential_network_id,
        "credential_chain_id": account.credential_chain_id,
        "credential_settlement": account.credential_settlement,
    }


@app.post("/accounts/{account_id}/deposit")
async def deposit(account_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    _require_local_billing_mode()
    try:
        account = store.deposit(account_id, str(payload.get("amount_usdc") or "0"))
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"account_id": account.account_id, "balance_usdc": account.balance_usdc}


@app.post("/accounts/{account_id}/sync-balance")
async def sync_balance(account_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    if _billing_mode() == "local":
        raise HTTPException(status_code=409, detail="sync-balance is only used outside MYCOMESH_BILLING_MODE=local")
    try:
        chain_sync = _chain_sync_state_from_payload(payload)
        if chain_sync is None:
            raise BillingError("chain sync metadata is required for direct balance publication")
        account = store.publish_direct_chain_balance(
            account_id,
            str(payload.get("balance_usdc") or "0"),
            expected_state=store.get_chain_sync_state(),
            **chain_sync,
        )
    except ChainSyncSuperseded as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid chain sync metadata: {exc}") from exc
    return {
        "account_id": account.account_id,
        "balance_usdc": account.balance_usdc,
        "payment_address": account.payment_address,
        "billing_mode": _billing_mode(),
        "chain_sync": store.get_chain_sync_state(account_id),
    }


@app.post("/accounts/{account_id}/payment-address")
async def set_payment_address(account_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    try:
        account = store.set_payment_address(account_id, payload.get("payment_address"))
    except BillingError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"account_id": account.account_id, "payment_address": account.payment_address, "balance_usdc": account.balance_usdc}


@app.post("/accounts/{account_id}/policy")
async def set_account_policy(account_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    try:
        account = store.configure_account(
            account_id,
            parent_account_id=payload.get("parent_account_id") if "parent_account_id" in payload else None,
            discount_bps=payload.get("discount_bps") if "discount_bps" in payload else None,
            reseller_margin_bps=payload.get("reseller_margin_bps") if "reseller_margin_bps" in payload else None,
            monthly_quota_usdc=str(payload.get("monthly_quota_usdc")) if "monthly_quota_usdc" in payload else None,
            usage_tier=payload.get("usage_tier") if "usage_tier" in payload else None,
        )
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _account_payload(account)


@app.post("/accounts/{account_id}/status")
async def set_account_status(account_id: str, payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    try:
        account = store.set_account_status(account_id, str(payload.get("status") or ""))
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _account_payload(account)


@app.post("/accounts/{account_id}/keys/rotate")
async def rotate_key(account_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    context = _credential_context_or_503()
    try:
        account = store.rotate_key(
            account_id,
            credential_origin=str(context["origin"]),
            credential_network_id=str(context["network_id"]),
            credential_chain_id=int(context["chain_id"]),
            credential_settlement=str(context["settlement"]),
        )
    except BillingError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    result = _account_payload(account)
    result["api_key"] = account.api_key
    return result


@app.delete("/accounts/{account_id}")
async def delete_account(account_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_admin(authorization)
    return {"account_id": account_id, "deleted": store.delete_account(account_id)}


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": os.getenv("MYCOMESH_PUBLIC_MODEL_ID", DEFAULT_PUBLIC_MODEL_ID),
                "object": "model",
                "created": 0,
                "owned_by": "mycomesh",
            }
        ],
    }


@app.get("/account")
async def account(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    consumer = _account_from_auth(authorization, request=request)
    return {
        "account_id": consumer.account_id,
        "status": consumer.status,
        "balance_usdc": consumer.balance_usdc,
        "payment_address": consumer.payment_address,
        "key_fingerprint": consumer.key_fingerprint,
        "billing_mode": _billing_mode(),
        "parent_account_id": consumer.parent_account_id,
        "discount_bps": consumer.discount_bps,
        "reseller_margin_bps": consumer.reseller_margin_bps,
        "monthly_quota_usdc": units_to_usdc(consumer.monthly_quota_units),
        "monthly_used_usdc": units_to_usdc(consumer.monthly_used_units),
        "usage_tier": consumer.usage_tier,
        "credential_audience": consumer.credential_origin,
        "credential_network_id": consumer.credential_network_id,
        "credential_chain_id": consumer.credential_chain_id,
        "credential_settlement": consumer.credential_settlement,
    }


@app.delete("/v1/mycomesh/keys/current")
async def revoke_current_key(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    consumer = _account_from_auth(authorization, request=request)
    api_key = _authorization_bearer(authorization)
    fingerprint = consumer.key_fingerprint
    try:
        store.revoke_key(consumer.account_id, api_key)
    except BillingError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "account_id": consumer.account_id,
        "key_fingerprint": fingerprint,
        "revoked": True,
    }


@app.post("/v1/mycomesh/v3/prepare")
async def prepare_consumer_v3(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    account = _account_from_auth(authorization, request=request)
    _rate_limit_account(account.account_id)
    body = await _request_json(request)
    endpoint = str(body.get("endpoint") or "responses").strip().lower()
    if endpoint not in {"responses", "chat"}:
        raise HTTPException(status_code=422, detail="endpoint must be responses or chat")
    max_output_tokens = _request_max_output_tokens(body)
    if max_output_tokens is None:
        raise HTTPException(status_code=422, detail="max_output_tokens is required for Settlement V3")
    input_value = body.get("messages", []) if endpoint == "chat" else body.get("input", "")
    model = str(body.get("model") or os.getenv("MYCOMESH_PUBLIC_MODEL_ID", DEFAULT_PUBLIC_MODEL_ID))
    provider_id = str(body.get("provider_id") or "").strip() or None
    try:
        return await asyncio.to_thread(
            _prepare_consumer_v3_plan,
            account=account,
            input_value=input_value,
            model=model,
            endpoint=endpoint,
            max_output_tokens=max_output_tokens,
            provider_id=provider_id,
        )
    except HTTPException:
        raise
    except (ChainError, P2PError, ReservationError, RuntimeError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"Settlement V3 preparation failed: {exc}") from exc


@app.post("/v1/responses")
async def responses(request: Request, authorization: str | None = Header(default=None)) -> Any:
    account = _account_from_auth(authorization, request=request)
    _rate_limit_account(account.account_id)
    body = await _request_json(request)
    output = await _run_pool_inference_async(
        account=account,
        input_value=body.get("input", ""),
        model=str(body.get("model") or os.getenv("MYCOMESH_PUBLIC_MODEL_ID", DEFAULT_PUBLIC_MODEL_ID)),
        endpoint="responses",
        max_output_tokens=_request_max_output_tokens(body),
        consumer_v3=body.get("mycomesh_v3"),
    )
    if body.get("stream") is True:
        return StreamingResponse(_responses_sse(output), media_type="text/event-stream", headers={"x-mycomesh-streaming-mode": "buffered"})
    return output


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, authorization: str | None = Header(default=None)) -> Any:
    account = _account_from_auth(authorization, request=request)
    _rate_limit_account(account.account_id)
    body = await _request_json(request)
    output = await _run_pool_inference_async(
        account=account,
        input_value=body.get("messages", []),
        model=str(body.get("model") or os.getenv("MYCOMESH_PUBLIC_MODEL_ID", DEFAULT_PUBLIC_MODEL_ID)),
        endpoint="chat",
        max_output_tokens=_request_max_output_tokens(body),
        consumer_v3=body.get("mycomesh_v3"),
    )
    raw = output.get("raw") if isinstance(output.get("raw"), dict) else output
    if body.get("stream") is True:
        return StreamingResponse(
            _chat_sse(raw, model=str(body.get("model") or "mycomesh-codex-standard-v1")),
            media_type="text/event-stream",
            headers={"x-mycomesh-streaming-mode": "buffered"},
        )
    return raw


async def _run_pool_inference_async(
    account: ConsumerAccount,
    input_value: Any,
    model: str,
    endpoint: str,
    max_output_tokens: int | None = None,
    consumer_v3: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timeout = _configured_inference_timeout()
    deadline = time.monotonic() + timeout
    control = _InferenceControl(deadline)
    if not _inference_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="MycoMesh inference concurrency limit reached",
            headers={"Retry-After": "1"},
        )

    def run() -> dict[str, Any]:
        try:
            return _run_pool_inference(
                account,
                input_value,
                model,
                endpoint,
                max_output_tokens=max_output_tokens,
                consumer_v3=consumer_v3,
                timeout=timeout,
                deadline=deadline,
                control=control,
            )
        finally:
            _inference_slots.release()

    task = asyncio.create_task(asyncio.to_thread(run))
    task.add_done_callback(_consume_background_task_exception)
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=control.remaining())
    except asyncio.TimeoutError as exc:
        control.cancel()
        committed = control.committed_response()
        if committed is not None:
            return committed
        raise HTTPException(status_code=504, detail="MycoMesh inference deadline exceeded") from exc
    except asyncio.CancelledError:
        control.cancel()
        raise
    except HTTPException:
        control.cancel()
        raise


def _consume_background_task_exception(task: asyncio.Task[Any]) -> None:
    if not task.cancelled():
        task.exception()


def _configured_inference_timeout() -> float:
    try:
        return bounded_timeout(
            os.getenv("MYCOMESH_TIMEOUT_SECONDS", "120"),
            maximum=MAX_MYCOMESH_INFERENCE_TIMEOUT_SECONDS,
            label="MYCOMESH_TIMEOUT_SECONDS",
        )
    except NetworkIOError as exc:
        raise HTTPException(status_code=503, detail=f"invalid MycoMesh inference timeout: {exc}") from exc


def _pool_route_failure(error: Exception) -> HTTPException:
    """Expose transient Provider route failures with retry-aware status codes."""
    message = str(error)
    normalized = message.lower()
    if (
        "timed out" in normalized
        or "deadline exceeded" in normalized
        or "http 504" in normalized
    ):
        return HTTPException(
            status_code=504,
            detail=f"Provider route timed out before the Relay deadline: {message}",
            headers={"Retry-After": "5"},
        )
    if (
        "not connected" in normalized
        or "queue is full" in normalized
        or "connection reset" in normalized
        or "connection refused" in normalized
        or "disconnected" in normalized
    ):
        return HTTPException(
            status_code=503,
            detail=f"Provider route is temporarily unavailable: {message}",
            headers={"Retry-After": "5"},
        )
    return HTTPException(status_code=502, detail=f"all pool peers failed: {message}")


def _remaining_inference_time(deadline: float) -> float:
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise HTTPException(status_code=504, detail="MycoMesh inference deadline exceeded")
    return remaining


def _run_pool_inference(
    account: ConsumerAccount,
    input_value: Any,
    model: str,
    endpoint: str,
    max_output_tokens: int | None = None,
    consumer_v3: dict[str, Any] | None = None,
    *,
    timeout: float | None = None,
    deadline: float | None = None,
    control: _InferenceControl | None = None,
) -> dict[str, Any]:
    if control is None:
        timeout = float(timeout if timeout is not None else _configured_inference_timeout())
        control = _InferenceControl(float(deadline) if deadline is not None else time.monotonic() + timeout)
    control.ensure_active()
    _require_serving_billing_mode(account.account_id)
    pool_url = os.getenv("MYCOMESH_POOL_URL", DEFAULT_POOL_URL)
    channel = os.getenv("MYCOMESH_CHANNEL", DEFAULT_CHANNEL)
    deadline = control.deadline
    try:
        peers = discover_peers_from_pools(
            _split_urls(pool_url),
            channel=channel,
            timeout=min(control.remaining(), 10.0),
        )
    except PoolError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    control.ensure_active()
    if not peers:
        raise HTTPException(status_code=503, detail=f"no live peers found for channel {channel}")

    route_state_path = os.getenv("MYCOMESH_ROUTE_STATE", DEFAULT_ROUTE_STATE_PATH)
    route_state = load_route_state(route_state_path)
    pricing_table = load_pricing_config(os.getenv("MYCOMESH_PRICING_CONFIG"))
    _require_consumer_payment_address(account)
    reservation_id = "res_" + uuid.uuid4().hex
    if consumer_v3 is not None and max_output_tokens is None:
        raise HTTPException(status_code=422, detail="max_output_tokens is required for Settlement V3")
    reservation_output_tokens = int(max_output_tokens or os.getenv("MYCOMESH_RESERVE_OUTPUT_TOKENS", "2000"))
    try:
        request_hash = _public_request_hash(
            endpoint=endpoint,
            model=model,
            input_value=input_value,
            max_output_tokens=reservation_output_tokens,
        )
    except ReservationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    verified_v3: dict[str, Any] | None = None
    if consumer_v3 is not None:
        verified_v3 = _validate_consumer_v3_envelope(
            account=account,
            envelope=consumer_v3,
            input_value=input_value,
            model=model,
            endpoint=endpoint,
            max_output_tokens=reservation_output_tokens,
            peers=peers,
        )
        peers = [verified_v3["peer"]]
        authorization = verified_v3["authorization"]
        channel_pricing_hash = str(authorization["pricing_hash"])
        reservation_units = int(authorization["max_fee_units"])
    else:
        channel_pricing_hash = _channel_pricing_hash(pricing_table, channel)
        reservation_units = _reservation_units(
            pricing_table,
            channel,
            output_tokens=reservation_output_tokens,
        )
    try:
        control.run_funds_action(
            lambda: _reserve_serving_funds(account.account_id, reservation_units, reservation_id)
        )
    except ChainBalanceUnavailable as exc:
        raise HTTPException(status_code=409, detail=f"on-chain prepaid cache is not fresh: {exc}") from exc
    except BillingError as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc
    try:
        return _route_reserved_inference(
            account=account,
            input_value=input_value,
            model=model,
            endpoint=endpoint,
            peers=peers,
            pool_url=pool_url,
            channel=channel,
            deadline=deadline,
            route_state=route_state,
            route_state_path=route_state_path,
            pricing_table=pricing_table,
            channel_pricing_hash=channel_pricing_hash,
            reservation_id=reservation_id,
            reservation_output_tokens=reservation_output_tokens,
            reservation_units=reservation_units,
            request_hash=request_hash,
            consumer_v3=verified_v3,
            control=control,
        )
    finally:
        # release() is conditional on status='reserved', so it is safe after capture.
        if control.committed_response() is None:
            store.release(reservation_id)
        else:
            try:
                store.release(reservation_id)
            except Exception:
                logger.exception(
                    "post-capture reservation cleanup failed; capture remains committed "
                    "(reservation_id=%s)",
                    reservation_id,
                )


def _update_route_state_best_effort(
    *,
    route_state: Any,
    route_state_path: str,
    peer_id: str,
    reservation_id: str,
    stage: str,
    update: Callable[[], None],
    capture_committed: bool = False,
) -> None:
    try:
        update()
        save_route_state(route_state, route_state_path)
    except Exception:
        logger.exception(
            "best-effort route-state update failed at %s "
            "(peer_id=%s, reservation_id=%s, capture_committed=%s)",
            stage,
            peer_id,
            reservation_id,
            capture_committed,
        )


def _route_reserved_inference(
    *,
    account: ConsumerAccount,
    input_value: Any,
    model: str,
    endpoint: str,
    peers: list[dict[str, Any]],
    pool_url: str,
    channel: str,
    deadline: float,
    route_state: Any,
    route_state_path: str,
    pricing_table: dict[str, Any],
    channel_pricing_hash: str,
    reservation_id: str,
    reservation_output_tokens: int,
    reservation_units: int,
    request_hash: str,
    consumer_v3: dict[str, Any] | None = None,
    control: _InferenceControl,
) -> dict[str, Any]:
    v3_authorization = (
        consumer_v3.get("authorization")
        if isinstance(consumer_v3, dict) and isinstance(consumer_v3.get("authorization"), dict)
        else None
    )
    last_error: Exception | None = None
    for peer_info in rank_peers(peers, route_state):
        control.ensure_active()
        peer_id = str(peer_info.get("peer_id") or "")
        if _env_flag("MYCOMESH_REQUIRE_PROVIDER_SETTLEMENT_FIELDS", True):
            try:
                _require_provider_settlement_fields(peer_info)
            except HTTPException as exc:
                last_error = RuntimeError(str(exc.detail))
                _update_route_state_best_effort(
                    route_state=route_state,
                    route_state_path=route_state_path,
                    peer_id=peer_id,
                    reservation_id=reservation_id,
                    stage="provider-settlement-validation",
                    update=lambda: record_route_failure(route_state, peer_id, last_error),
                )
                continue
        try:
            lease_id = reserve_peer(route_state, peer_info, ttl_seconds=max(1, int(control.remaining())))
            _update_route_state_best_effort(
                route_state=route_state,
                route_state_path=route_state_path,
                peer_id=peer_id,
                reservation_id=reservation_id,
                stage="lease-reserve",
                update=lambda: None,
            )
        except ValueError as exc:
            last_error = exc
            continue
        capture_committed = False
        try:
            for address in _peer_addresses(peer_info):
                selected_pool_url = str(peer_info.get("pool_url") or pool_url)
                started_at = time.time()
                try:
                    response = _send_infer_to_address(
                        address=address,
                        channel=channel,
                        endpoint=endpoint,
                        model=model,
                        input_value=input_value,
                        pool_url=selected_pool_url,
                        peer_id=peer_id,
                        timeout=control.remaining(),
                        identity=request_identity,
                        consumer_id=account.account_id,
                        consumer_payment_address=account.payment_address,
                        provider_payment_address=str(peer_info.get("payment_address") or "") or None,
                        pricing_hash=channel_pricing_hash,
                        max_fee_units=reservation_units,
                        max_output_tokens=reservation_output_tokens,
                        provider_public_key=str(peer_info.get("public_key") or "") or None,
                        provider_transport_key=(
                            peer_info.get("transport_key")
                            if isinstance(peer_info.get("transport_key"), dict)
                            else None
                        ),
                        settlement_version=3 if v3_authorization is not None else 2,
                        pricing_version=(int(v3_authorization["pricing_version"]) if v3_authorization else None),
                        onchain_reservation_id=(str(v3_authorization["onchain_reservation_id"]) if v3_authorization else None),
                        expires_at=(int(v3_authorization["expires_at"]) if v3_authorization else None),
                        settlement_deadline=(int(v3_authorization["settlement_deadline"]) if v3_authorization else None),
                        provider_fallback_allowed=(bool(v3_authorization["provider_fallback_allowed"]) if v3_authorization else False),
                        settlement_chain_id=(int(consumer_v3["settlement_chain_id"]) if consumer_v3 else None),
                        settlement_contract=(str(consumer_v3["settlement_contract"]) if consumer_v3 else None),
                        evm_session_authorization=v3_authorization,
                        network_id=(str(consumer_v3["network_id"]) if consumer_v3 else None),
                        channel_id=(str(consumer_v3["channel_id"]) if consumer_v3 else None),
                        backend_policy=(str(consumer_v3["backend_policy"]) if consumer_v3 else None),
                    )
                except (P2PError, RelayError, ValueError) as exc:
                    last_error = exc
                    _update_route_state_best_effort(
                        route_state=route_state,
                        route_state_path=route_state_path,
                        peer_id=peer_id,
                        reservation_id=reservation_id,
                        stage="provider-request",
                        update=lambda exc=exc: record_route_failure(route_state, peer_id, exc),
                    )
                    continue
                finished_at = time.time()
                control.ensure_active()
                try:
                    verify_provider_response(
                        response,
                        peer_info,
                        audience=request_identity.public_key,
                        expected_request_hash=request_hash,
                        expected_channel=channel,
                        expected_network_id=(str(consumer_v3["network_id"]) if consumer_v3 else None),
                        expected_channel_id=(str(consumer_v3["channel_id"]) if consumer_v3 else None),
                        expected_backend_policy=(str(consumer_v3["backend_policy"]) if consumer_v3 else None),
                        expected_model=model,
                        expected_endpoint=endpoint,
                    )
                except ProtocolValidationError as exc:
                    last_error = exc
                    _update_route_state_best_effort(
                        route_state=route_state,
                        route_state_path=route_state_path,
                        peer_id=peer_id,
                        reservation_id=reservation_id,
                        stage="provider-response-validation",
                        update=lambda exc=exc: record_route_failure(route_state, peer_id, exc),
                    )
                    continue
                control.ensure_active()
                quote = quote_usage(
                    channel,
                    response.get("usage") if isinstance(response, dict) else None,
                    pricing_table=pricing_table,
                )
                amount_units = usdc_to_units(quote.to_dict()["gross_fee"])
                if amount_units > reservation_units:
                    raise HTTPException(status_code=402, detail="inference cost exceeded payment reservation")
                verified_v3_settlement: dict[str, Any] | None = None
                if v3_authorization is not None:
                    try:
                        verified_v3_settlement = _verify_runtime_v3_settlement(
                            response=response,
                            account=account,
                            peer_info=peer_info,
                            consumer_v3=consumer_v3,
                            authorization=v3_authorization,
                            channel=channel,
                            model=model,
                            endpoint=endpoint,
                            request_hash=request_hash,
                            quote=quote,
                            amount_units=amount_units,
                        )
                    except HTTPException as exc:
                        _update_route_state_best_effort(
                            route_state=route_state,
                            route_state_path=route_state_path,
                            peer_id=peer_id,
                            reservation_id=reservation_id,
                            stage="provider-v3-settlement-validation",
                            update=lambda exc=exc: record_route_failure(route_state, peer_id, exc),
                        )
                        raise
                _update_route_state_best_effort(
                    route_state=route_state,
                    route_state_path=route_state_path,
                    peer_id=peer_id,
                    reservation_id=reservation_id,
                    stage="provider-success",
                    update=lambda: record_route_success(
                        route_state,
                        peer_id,
                        int((finished_at - started_at) * 1000),
                    ),
                )
                control.ensure_active()
                receipt = build_receipt(
                    consumer_id=account.account_id,
                    provider_id=peer_id,
                    relay_id=_relay_id_for_address(address),
                    pool_url=selected_pool_url,
                    selected_address=address,
                    channel=channel,
                    model=model,
                    endpoint=endpoint,
                    input_value=input_value,
                    response=response,
                    quote=quote,
                    started_at=started_at,
                    finished_at=finished_at,
                    consumer_public_key=request_identity.public_key,
                    consumer_payment_address=account.payment_address,
                    provider_public_key=str(peer_info.get("public_key") or "") or None,
                    provider_payment_address=str(peer_info.get("payment_address") or "") or None,
                    bridge_usage=build_bridge_usage(address, selected_pool_url, quote.to_dict()),
                    channel_pricing_hash=channel_pricing_hash,
                    network_id=(str(consumer_v3["network_id"]) if consumer_v3 else None),
                    channel_id=(str(consumer_v3["channel_id"]) if consumer_v3 else None),
                    backend_policy=(str(consumer_v3["backend_policy"]) if consumer_v3 else None),
                    settlement_version=3 if v3_authorization is not None else 2,
                    pricing_version=(int(v3_authorization["pricing_version"]) if v3_authorization else None),
                    onchain_reservation_id=(str(v3_authorization["onchain_reservation_id"]) if v3_authorization else None),
                    settlement_deadline=(int(v3_authorization["settlement_deadline"]) if v3_authorization else 0),
                    mycomesh_v3_settlement=verified_v3_settlement,
                    signer=request_identity,
                    request_hash=request_hash,
                )
                try:
                    accepted_receipt = sign_acceptance(receipt.to_dict(), request_identity, accepted_by=account.account_id)
                    payload = dict(response)
                    payload["mycomesh_receipt"] = accepted_receipt
                    payload["mycomesh_price"] = quote.to_dict()
                    control.run_funds_action(
                        lambda: store.capture(
                            reservation_id,
                            amount_units,
                            event_id=receipt.job_id,
                            receipt=accepted_receipt,
                            outbox_payload=accepted_receipt,
                        ),
                        committed_response=payload,
                    )
                    capture_committed = True
                except HTTPException:
                    raise
                except BillingError as exc:
                    raise HTTPException(status_code=402, detail=str(exc)) from exc
                except Exception as exc:
                    _update_route_state_best_effort(
                        route_state=route_state,
                        route_state_path=route_state_path,
                        peer_id=peer_id,
                        reservation_id=reservation_id,
                        stage="acceptance-or-capture",
                        update=lambda exc=exc: record_route_failure(route_state, peer_id, exc),
                    )
                    raise HTTPException(status_code=500, detail=str(exc)) from exc
                _update_route_state_best_effort(
                    route_state=route_state,
                    route_state_path=route_state_path,
                    peer_id=peer_id,
                    reservation_id=reservation_id,
                    stage="post-capture-acceptance",
                    update=lambda: record_route_acceptance(route_state, peer_id),
                    capture_committed=True,
                )
                try:
                    _export_pending_receipts()
                except Exception:
                    logger.exception("receipt outbox export failed; the captured receipt remains pending")
                return payload
        finally:
            _update_route_state_best_effort(
                route_state=route_state,
                route_state_path=route_state_path,
                peer_id=peer_id,
                reservation_id=reservation_id,
                stage="lease-release",
                update=lambda: release_peer(route_state, lease_id),
                capture_committed=capture_committed,
            )
    control.ensure_active()
    raise _pool_route_failure(last_error or RuntimeError("no Provider route succeeded"))


def _account_from_auth(authorization: str | None, *, request: Request):
    api_key = _authorization_bearer(authorization)
    try:
        context = _key_registration_context()
    except (BillingError, ChainError, GatewayRegistryError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"invalid credential audience configuration: {exc}") from exc
    account = store.get_by_key(
        api_key,
        credential_origin=str(context["origin"]),
        credential_network_id=str(context["network_id"]),
        credential_chain_id=int(context["chain_id"]),
        credential_settlement=str(context["settlement"]),
    )
    if account is None:
        raise HTTPException(status_code=401, detail="invalid MycoMesh API key")
    if account.credential_origin is None:
        raise HTTPException(status_code=403, detail="legacy unscoped API key must be rotated")
    _require_credential_request_authority(request, account.credential_origin)
    if account.status != "active":
        raise HTTPException(status_code=403, detail=f"account is {account.status}")
    return account


def _authorization_bearer(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization: Bearer <mycomesh_api_key> is required")
    scheme, separator, value = authorization.partition(" ")
    api_key = value.strip()
    if scheme.lower() != "bearer" or not separator or not api_key or any(character.isspace() for character in api_key):
        raise HTTPException(status_code=401, detail="Authorization: Bearer <mycomesh_api_key> is required")
    return api_key


def _credential_context_or_503() -> dict[str, object]:
    try:
        return _key_registration_context()
    except (BillingError, ChainError, GatewayRegistryError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"invalid credential audience configuration: {exc}") from exc


def _require_credential_request_authority(request: Request, credential_origin: str) -> None:
    expected = urlparse(credential_origin)
    host = str(request.headers.get("host") or "").strip()
    try:
        request_url = normalize_gateway_url(
            f"{expected.scheme}://{host}/v1",
            allow_localhost=_is_local_profile(),
        )
    except GatewayRegistryError as exc:
        raise HTTPException(status_code=401, detail="credential audience mismatch") from exc
    if _origin_from_gateway_url(request_url) != credential_origin:
        raise HTTPException(status_code=401, detail="credential audience mismatch")


def _require_admin(authorization: str | None) -> None:
    token = os.getenv("MYCOMESH_ADMIN_TOKEN")
    if not token:
        raise HTTPException(status_code=403, detail="MYCOMESH_ADMIN_TOKEN is required for account administration")
    if not _is_local_profile() and (
        len(token) < 32
        or token.lower() in {"change-me", "change-me-admin-token", "admin", "admin-token"}
    ):
        raise HTTPException(
            status_code=503,
            detail="MYCOMESH_ADMIN_TOKEN must be a strong non-placeholder secret outside the local profile",
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer <admin_token> is required")
    if not secrets.compare_digest(authorization.split(" ", 1)[1].strip(), token):
        raise HTTPException(status_code=403, detail="invalid admin token")


def _require_public_key_registration_enabled() -> None:
    if _env_flag("MYCOMESH_PUBLIC_KEY_REGISTRATION", _is_local_profile()):
        return
    raise HTTPException(status_code=403, detail="public key registration is disabled")


def _require_local_billing_mode() -> None:
    if _billing_mode() != "local":
        raise HTTPException(status_code=409, detail="local balance mutation is disabled outside MYCOMESH_BILLING_MODE=local")


def _require_serving_billing_mode(account_id: str) -> None:
    mode = _billing_mode()
    if mode == "local":
        return
    if mode == "onchain-prepaid" and _env_flag("MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE", False):
        try:
            chain_cache = _chain_cache_configuration()
            store.require_fresh_chain_sync(
                account_id=account_id,
                **chain_cache,
            )
        except (BillingError, ChainError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=f"on-chain prepaid cache is not fresh: {exc}") from exc
        return
    raise HTTPException(
        status_code=409,
        detail=(
            "on-chain prepaid serving requires a synchronized local balance cache. "
            "Set MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE=1 and feed /accounts/{account_id}/sync-balance from a chain indexer."
        ),
    )


def _reserve_serving_funds(
    account_id: str,
    amount_units: int,
    reservation_id: str,
) -> ConsumerAccount:
    mode = _billing_mode()
    if mode == "local":
        return store.reserve(account_id, amount_units, reservation_id)
    if mode == "onchain-prepaid" and _env_flag("MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE", False):
        try:
            chain_cache = _chain_cache_configuration()
        except (BillingError, ChainError, ValueError) as exc:
            raise ChainBalanceUnavailable(str(exc)) from exc
        return store.reserve_with_chain_guard(
            account_id,
            amount_units,
            reservation_id,
            **chain_cache,
        )
    raise ChainBalanceUnavailable(
        "on-chain prepaid serving requires a synchronized local balance cache"
    )


def _chain_cache_configuration() -> dict[str, int | str]:
    deployment = load_active_myco_deployment()
    return {
        "chain_id": int(os.getenv("ETH_CHAIN_ID", str(deployment.chain_id))),
        "settlement": os.getenv("MYCO_SETTLEMENT", deployment.settlement),
        "max_age_seconds": int(os.getenv("MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS", "120")),
        "max_block_lag": int(os.getenv("MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG", "12")),
        "min_confirmations": int(os.getenv("MYCOMESH_CHAIN_SYNC_MIN_CONFIRMATIONS", "6")),
    }


def _billing_mode() -> str:
    return os.getenv("MYCOMESH_BILLING_MODE", "local").strip().lower() or "local"


def _consumer_v3_context() -> dict[str, Any]:
    if os.getenv("MYCOMESH_SETTLEMENT_VERSION", "2").strip() != "3":
        raise HTTPException(status_code=409, detail="this Consumer Proxy is not configured for Settlement V3")
    try:
        deployment = load_active_myco_deployment(settlement_version=3)
        require_deployment_channel_binding(deployment)
        rpc_url = str(
            os.getenv("MYCOMESH_SETTLEMENT_RPC_URL")
            or os.getenv("ETH_RPC_URL")
            or ""
        ).strip()
        if not rpc_url:
            raise ChainError("MYCOMESH_SETTLEMENT_RPC_URL or ETH_RPC_URL is required")
        confirmations = int(os.getenv("MYCOMESH_SETTLEMENT_CONFIRMATIONS", "6"))
        if confirmations < 0:
            raise ChainError("MYCOMESH_SETTLEMENT_CONFIRMATIONS must be non-negative")
        if not _is_local_profile() and confirmations < 6:
            raise ChainError("testnet Consumer V3 requires at least 6 confirmations")
        timeout = bounded_timeout(
            os.getenv("MYCOMESH_SETTLEMENT_RPC_TIMEOUT", "20"),
            maximum=MAX_MYCOMESH_INFERENCE_TIMEOUT_SECONDS,
            label="Settlement V3 RPC timeout",
        )
        chain_id = rpc_int(rpc_url, "eth_chainId", [], timeout)
        if chain_id != int(deployment.chain_id):
            raise ChainError(
                f"settlement RPC chain id mismatch: expected {deployment.chain_id}, got {chain_id}"
            )
        latest_block = rpc_int(rpc_url, "eth_blockNumber", [], timeout)
    except HTTPException:
        raise
    except (ChainError, NetworkIOError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"invalid Settlement V3 runtime: {exc}") from exc
    return {
        "deployment": deployment,
        "rpc_url": rpc_url,
        "timeout": float(timeout),
        "confirmations": confirmations,
        "latest_block": latest_block,
        "confirmed_block": max(0, latest_block - confirmations),
    }


def _consumer_v3_peer_binding(
    peer: dict[str, Any],
    *,
    deployment: Any,
    channel: str,
    model: str,
) -> dict[str, Any]:
    peer_id = str(peer.get("peer_id") or "").strip()
    public_key = str(peer.get("public_key") or "").strip().lower()
    if not peer_id or not public_key:
        raise P2PError("provider descriptor is missing signed identity fields")
    if not _peer_addresses(peer):
        raise P2PError("provider descriptor has no routable address")
    if str(peer.get("channel") or "") != channel:
        raise P2PError("provider descriptor channel mismatch")
    try:
        peer_channel_binding = require_enabled_channel_binding(
            network_id=peer.get("network_id"),
            channel_id=peer.get("channel_id"),
            channel=peer.get("channel"),
            backend_policy=peer.get("backend_policy"),
            label="provider descriptor",
        )
        deployment_channel_binding = require_deployment_channel_binding(deployment)
    except ValueError as exc:
        raise P2PError(str(exc)) from exc
    if peer_channel_binding != deployment_channel_binding:
        raise P2PError("provider descriptor channel binding mismatch")
    if str(peer.get("model") or "") != model:
        raise P2PError("provider descriptor model mismatch")
    capacity = peer.get("capacity")
    if not isinstance(capacity, dict):
        raise P2PError("provider descriptor is missing execution capacity")
    reserve_input_bytes = capacity.get("reserve_input_bytes")
    reserve_output_tokens = capacity.get("reserve_output_tokens")
    if (
        type(reserve_input_bytes) is not int
        or reserve_input_bytes <= 0
        or reserve_input_bytes > MAX_RESERVE_INPUT_TOKENS
    ):
        raise P2PError("provider descriptor reserve_input_bytes is invalid")
    if (
        type(reserve_output_tokens) is not int
        or reserve_output_tokens <= 0
        or reserve_output_tokens > MAX_RESERVE_OUTPUT_TOKENS
    ):
        raise P2PError("provider descriptor reserve_output_tokens is invalid")
    payment_address = normalize_address(str(peer.get("payment_address") or ""))
    if int(payment_address[2:], 16) == 0:
        raise P2PError("provider descriptor payment_address is zero")
    settlement = peer.get("settlement")
    if not isinstance(settlement, dict):
        raise P2PError("provider descriptor is missing Settlement V3 capabilities")
    try:
        version = int(settlement.get("version"))
        chain_id = int(settlement.get("chain_id"))
        contract = normalize_address(str(settlement.get("contract") or ""))
        pricing_version = int(settlement.get("pricing_version"))
        pricing_hash = normalize_bytes32(str(settlement.get("pricing_hash") or ""))
    except (ChainError, TypeError, ValueError) as exc:
        raise P2PError(f"provider descriptor has malformed Settlement V3 capabilities: {exc}") from exc
    expected = (
        version == 3
        and chain_id == int(deployment.chain_id)
        and contract == normalize_address(deployment.settlement)
        and pricing_version == int(deployment.pricing_version)
        and pricing_hash == normalize_bytes32(deployment.pricing_hash)
    )
    if not expected:
        raise P2PError("provider descriptor does not match the pinned Settlement V3 deployment")
    return {
        "peer_id": peer_id,
        "network_id": peer_channel_binding.network_id,
        "channel_id": peer_channel_binding.channel_id,
        "backend_policy": peer_channel_binding.backend_policy,
        "payment_address": payment_address,
        "pricing_version": pricing_version,
        "pricing_hash": pricing_hash,
        "reserve_input_bytes": reserve_input_bytes,
        "reserve_output_tokens": reserve_output_tokens,
    }


def _consumer_v3_peers(
    *,
    deployment: Any,
    channel: str,
    model: str,
    provider_id: str | None = None,
    timeout: float = 10.0,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    peers = discover_peers_from_pools(
        _split_urls(os.getenv("MYCOMESH_POOL_URL", DEFAULT_POOL_URL)),
        channel=channel,
        timeout=timeout,
    )
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    errors: list[str] = []
    for peer in peers:
        if provider_id and str(peer.get("peer_id") or "") != provider_id:
            continue
        try:
            binding = _consumer_v3_peer_binding(
                peer,
                deployment=deployment,
                channel=channel,
                model=model,
            )
        except (ChainError, P2PError, TypeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        matches.append((peer, binding))
    if not matches:
        if provider_id:
            detail = f"requested signed V3 Provider is unavailable: {provider_id}"
        else:
            detail = "no compatible signed V3 Provider is available"
        if errors:
            detail += f" ({errors[0]})"
        raise HTTPException(status_code=503, detail=detail)
    return matches


def _consumer_v3_quote(
    context: dict[str, Any],
    *,
    channel: str,
    pricing_version: int,
    reserve_input_bytes: int,
    max_output_tokens: int,
) -> int:
    input_tokens = int(reserve_input_bytes)
    if input_tokens <= 0 or input_tokens > MAX_RESERVE_INPUT_TOKENS:
        raise HTTPException(status_code=503, detail="Provider input byte reserve is out of range")
    try:
        amount = call_uint256(
            context["rpc_url"],
            context["deployment"].settlement,
            "quote(bytes32,uint64,uint256,uint256)",
            [
                channel_to_hash(channel),
                str(pricing_version),
                str(input_tokens),
                str(max_output_tokens),
            ],
            timeout=context["timeout"],
            block_tag=context["confirmed_block"],
        )
    except (ChainError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"failed to read confirmed V3 quote: {exc}") from exc
    if amount <= 0:
        raise HTTPException(status_code=503, detail="Settlement V3 quote is not positive")
    return amount


def _consumer_v3_execution_limits(
    *,
    binding: dict[str, Any],
    input_value: Any,
    max_output_tokens: int,
) -> int:
    try:
        input_size_bytes = len(canonical_inference_input_bytes(input_value))
    except P2PError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if input_size_bytes > binding["reserve_input_bytes"]:
        raise HTTPException(
            status_code=422,
            detail=(
                "inference input exceeds Provider reserve_input_bytes: "
                f"{input_size_bytes} > {binding['reserve_input_bytes']} canonical JSON UTF-8 bytes"
            ),
        )
    if max_output_tokens > binding["reserve_output_tokens"]:
        raise HTTPException(
            status_code=422,
            detail=(
                "max_output_tokens exceeds Provider reserve_output_tokens: "
                f"{max_output_tokens} > {binding['reserve_output_tokens']}"
            ),
        )
    return input_size_bytes


def _consumer_v3_ttl_seconds() -> int:
    try:
        ttl = int(
            os.getenv(
                "MYCOMESH_CONSUMER_V3_RESERVATION_TTL_SECONDS",
                str(DEFAULT_CONSUMER_V3_RESERVATION_TTL_SECONDS),
            )
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="invalid Consumer V3 reservation TTL") from exc
    if ttl < MIN_CONSUMER_V3_RESERVATION_TTL_SECONDS or ttl > MAX_CONSUMER_V3_RESERVATION_TTL_SECONDS:
        raise HTTPException(
            status_code=503,
            detail=(
                "Consumer V3 reservation TTL must be between "
                f"{MIN_CONSUMER_V3_RESERVATION_TTL_SECONDS} and "
                f"{MAX_CONSUMER_V3_RESERVATION_TTL_SECONDS} seconds"
            ),
        )
    return ttl


def _prepare_consumer_v3_plan(
    *,
    account: ConsumerAccount,
    input_value: Any,
    model: str,
    endpoint: str,
    max_output_tokens: int,
    provider_id: str | None = None,
) -> dict[str, Any]:
    _require_consumer_payment_address(account)
    consumer = normalize_address(str(account.payment_address or ""))
    context = _consumer_v3_context()
    deployment = context["deployment"]
    channel = str(deployment.channel)
    matches = _consumer_v3_peers(
        deployment=deployment,
        channel=channel,
        model=model,
        provider_id=provider_id,
        timeout=min(float(context["timeout"]), 10.0),
    )
    peer, binding = matches[0]
    input_size_bytes = _consumer_v3_execution_limits(
        binding=binding,
        input_value=input_value,
        max_output_tokens=max_output_tokens,
    )
    request_hash = "0x" + _public_request_hash(
        endpoint=endpoint,
        model=model,
        input_value=input_value,
        max_output_tokens=max_output_tokens,
    )
    amount = _consumer_v3_quote(
        context,
        channel=channel,
        pricing_version=binding["pricing_version"],
        reserve_input_bytes=binding["reserve_input_bytes"],
        max_output_tokens=max_output_tokens,
    )
    now = int(time.time())
    expires_at = now + _consumer_v3_ttl_seconds()
    reservation_salt = "0x" + secrets.token_hex(32)
    onchain_reservation_id = reservation_id_for(
        settlement=deployment.settlement,
        chain_id=int(deployment.chain_id),
        consumer=consumer,
        reservation_salt=reservation_salt,
    )
    authorization = evm_session_authorization_payload(
        chain_id=int(deployment.chain_id),
        settlement_contract=deployment.settlement,
        onchain_reservation_id=onchain_reservation_id,
        consumer_payment_address=consumer,
        provider_id=binding["peer_id"],
        provider_payment_address=binding["payment_address"],
        channel=channel,
        pricing_hash=binding["pricing_hash"],
        pricing_version=binding["pricing_version"],
        request_hash=request_hash,
        max_fee_units=amount,
        expires_at=expires_at,
        settlement_deadline=expires_at,
        provider_fallback_allowed=False,
        nonce="0x" + secrets.token_hex(32),
        session_public_key=request_identity.public_key,
        now=now,
    )
    return {
        "schema": "mycomesh.consumer.v3.plan.v1",
        "network_id": binding["network_id"],
        "channel_id": binding["channel_id"],
        "backend_policy": binding["backend_policy"],
        "provider_id": binding["peer_id"],
        "provider_payment_address": binding["payment_address"],
        "provider_addresses": _peer_addresses(peer),
        "chain_id": int(deployment.chain_id),
        "settlement_contract": normalize_address(deployment.settlement),
        "channel": channel,
        "channel_hash": normalize_bytes32(deployment.channel_hash),
        "pricing_version": binding["pricing_version"],
        "pricing_hash": binding["pricing_hash"],
        "request_hash": request_hash,
        "input_size_bytes": input_size_bytes,
        "reserve_input_bytes": binding["reserve_input_bytes"],
        "reserve_output_tokens": binding["reserve_output_tokens"],
        "max_fee_units": amount,
        "expires_at": expires_at,
        "settlement_deadline": expires_at,
        "provider_fallback_allowed": False,
        "reservation_salt": reservation_salt,
        "onchain_reservation_id": onchain_reservation_id,
        "required_confirmations": int(context["confirmations"]),
        "authorization": authorization,
        "authorization_message": evm_session_authorization_message(authorization).decode("utf-8"),
    }


def _consumer_v3_reservation_words(output: str) -> dict[str, Any]:
    raw = str(output or "")
    if not raw.startswith("0x") or len(raw) != 2 + 9 * 64:
        raise ChainError("Settlement V3 reservation getter returned malformed ABI data")
    words = [raw[2 + index * 64 : 2 + (index + 1) * 64] for index in range(9)]
    closed = int(words[7], 16)
    fallback = int(words[8], 16)
    if closed not in {0, 1} or fallback not in {0, 1}:
        raise ChainError("Settlement V3 reservation getter returned malformed booleans")
    return {
        "consumer_payment_address": normalize_address("0x" + words[0][-40:]),
        "provider_payment_address": normalize_address("0x" + words[1][-40:]),
        "channel_hash": normalize_bytes32("0x" + words[2]),
        "request_hash": normalize_bytes32("0x" + words[3]),
        "pricing_version": int(words[4], 16),
        "expires_at": int(words[5], 16),
        "amount_units": int(words[6], 16),
        "closed": bool(closed),
        "provider_fallback_allowed": bool(fallback),
    }


def _verify_consumer_v3_wallet(
    context: dict[str, Any],
    authorization: dict[str, Any],
) -> None:
    consumer = normalize_address(str(authorization["consumer_payment_address"]))
    try:
        code = rpc_call(
            context["rpc_url"],
            "eth_getCode",
            [consumer, context["confirmed_block"]],
            context["timeout"],
        )
    except ChainError as exc:
        raise HTTPException(status_code=503, detail=f"failed to identify Consumer wallet type: {exc}") from exc
    if not _has_contract_code(code):
        try:
            verify_eoa_session_authorization(authorization)
        except ReservationError as exc:
            raise HTTPException(status_code=403, detail=f"Consumer V3 wallet signature rejected: {exc}") from exc
        return
    signature = str(authorization.get("wallet_signature") or "")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", signature) or len(signature[2:]) % 2:
        raise HTTPException(status_code=403, detail="Consumer V3 contract-wallet signature is malformed")
    signature_bytes = bytes.fromhex(signature[2:])
    if not signature_bytes or len(signature_bytes) > MAX_EIP1271_SIGNATURE_BYTES:
        raise HTTPException(status_code=403, detail="Consumer V3 contract-wallet signature size is invalid")
    try:
        verify_eip1271_signature(
            rpc_url=context["rpc_url"],
            signer=consumer,
            digest=evm_session_authorization_digest(authorization),
            signature=signature_bytes,
            caller=context["deployment"].settlement,
            timeout=context["timeout"],
        )
    except EIP1271SignatureRejected as exc:
        raise HTTPException(status_code=403, detail=f"Consumer V3 contract-wallet signature rejected: {exc}") from exc
    except ChainError as exc:
        raise HTTPException(status_code=503, detail=f"Consumer V3 contract-wallet verification failed: {exc}") from exc


def _verify_consumer_v3_onchain(
    context: dict[str, Any],
    authorization: dict[str, Any],
) -> None:
    deployment = context["deployment"]
    reservation_id = normalize_bytes32(str(authorization["onchain_reservation_id"]))
    expected = {
        "consumer_payment_address": normalize_address(str(authorization["consumer_payment_address"])),
        "provider_payment_address": normalize_address(str(authorization["provider_payment_address"])),
        "channel_hash": normalize_bytes32(channel_to_hash(str(authorization["channel"]))),
        "request_hash": normalize_bytes32(str(authorization["request_hash"])),
        "pricing_version": int(authorization["pricing_version"]),
        "expires_at": int(authorization["expires_at"]),
        "amount_units": int(authorization["max_fee_units"]),
        "closed": False,
        "provider_fallback_allowed": bool(authorization["provider_fallback_allowed"]),
    }
    try:
        for label, block_tag in (
            ("confirmed", context["confirmed_block"]),
            ("latest", "latest"),
        ):
            output = call_contract(
                context["rpc_url"],
                deployment.settlement,
                "reservations(bytes32)",
                [reservation_id],
                timeout=context["timeout"],
                block_tag=block_tag,
            )
            actual = _consumer_v3_reservation_words(output)
            if int(actual["consumer_payment_address"][2:], 16) == 0:
                raise P2PError(f"Settlement V3 reservation is absent at {label} state")
            for field, expected_value in expected.items():
                if actual[field] != expected_value:
                    raise P2PError(f"Settlement V3 reservation {field} mismatch at {label} state")
    except P2PError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ChainError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"failed to verify Settlement V3 reservation: {exc}") from exc


def _verify_runtime_v3_settlement(
    *,
    response: dict[str, Any],
    account: ConsumerAccount,
    peer_info: dict[str, Any],
    consumer_v3: dict[str, Any] | None,
    authorization: dict[str, Any],
    channel: str,
    model: str,
    endpoint: str,
    request_hash: str,
    quote: Any,
    amount_units: int,
) -> dict[str, Any]:
    context = _consumer_v3_context()
    deployment = context["deployment"]
    if not isinstance(consumer_v3, dict):
        raise HTTPException(status_code=500, detail="verified Consumer V3 context is missing")
    if (
        int(consumer_v3.get("settlement_chain_id") or 0) != int(deployment.chain_id)
        or normalize_address(str(consumer_v3.get("settlement_contract") or ""))
        != normalize_address(deployment.settlement)
        or consumer_v3.get("network_id") != deployment.network_id
        or consumer_v3.get("channel_id") != deployment.channel_id
        or consumer_v3.get("backend_policy") != deployment.backend_policy
    ):
        raise HTTPException(status_code=409, detail="Settlement V3 deployment changed during inference")

    payload = response.get("mycomesh_v3_settlement")
    try:
        receipt = verify_provider_settlement_payload(payload)
        if int(payload["chain_id"]) != int(deployment.chain_id):
            raise P2PError("Provider V3 settlement chain_id mismatch")
        if normalize_address(str(payload["settlement_contract"])) != normalize_address(deployment.settlement):
            raise P2PError("Provider V3 settlement contract mismatch")
        if str(deployment.channel) != channel:
            raise P2PError("active Settlement V3 channel mismatch")
        response_binding = require_enabled_channel_binding(
            network_id=response.get("network_id"),
            channel_id=response.get("channel_id"),
            channel=response.get("channel"),
            backend_policy=response.get("backend_policy"),
            label="provider response",
        )
        if response_binding != require_deployment_channel_binding(deployment):
            raise P2PError("provider response channel binding mismatch")

        expected_receipt = {
            "reservation_id": normalize_bytes32(str(authorization["onchain_reservation_id"])),
            "request_hash": normalize_bytes32("0x" + request_hash.removeprefix("0x")),
            "response_hash": normalize_bytes32("0x" + settlement_response_hash(response).removeprefix("0x")),
            "channel_hash": normalize_bytes32(channel_to_hash(channel)),
            "pricing_version": int(authorization["pricing_version"]),
            "pricing_hash": normalize_bytes32(str(authorization["pricing_hash"])),
            "consumer": normalize_address(str(account.payment_address or "")),
            "provider": normalize_address(str(peer_info.get("payment_address") or "")),
            "relay": ZERO_ADDRESS,
            "pool": ZERO_ADDRESS,
            "input_tokens": int(quote.input_tokens),
            "output_tokens": int(quote.output_tokens),
            "deadline": int(authorization["settlement_deadline"]),
        }
        for field, expected_value in expected_receipt.items():
            if getattr(receipt, field) != expected_value:
                raise P2PError(f"Provider V3 settlement {field} mismatch")
        if receipt.pricing_version != int(deployment.pricing_version):
            raise P2PError("Provider V3 settlement active pricing_version mismatch")
        if receipt.pricing_hash != normalize_bytes32(deployment.pricing_hash):
            raise P2PError("Provider V3 settlement active pricing_hash mismatch")
        reserve_input_bytes = int(consumer_v3.get("reserve_input_bytes") or 0)
        reserve_output_tokens = int(consumer_v3.get("reserve_output_tokens") or 0)
        requested_output_tokens = int(consumer_v3.get("max_output_tokens") or 0)
        if receipt.input_tokens > reserve_input_bytes:
            raise P2PError("Provider V3 settlement input usage exceeds the Provider reserve")
        if receipt.output_tokens > reserve_output_tokens:
            raise P2PError("Provider V3 settlement output usage exceeds the Provider reserve")
        if receipt.output_tokens > requested_output_tokens:
            raise P2PError("Provider V3 settlement output usage exceeds the Consumer request cap")
        if amount_units > int(authorization["max_fee_units"]):
            raise P2PError("Provider V3 settlement exceeds the wallet-authorized maximum")

        provider_public_key = str(peer_info.get("public_key") or "")
        peer_id = str(peer_info.get("peer_id") or "")
        request_id = str(response.get("request_id") or "")
        verify_provider_settlement_attestation(
            response.get("provider_settlement_attestation"),
            provider_public_key=provider_public_key,
            consumer_public_key=request_identity.public_key,
            expected={
                "request_id": request_id,
                "request_hash": request_hash,
                "response_hash": settlement_response_hash(response),
                "channel": channel,
                "network_id": deployment.network_id,
                "channel_id": deployment.channel_id,
                "backend_policy": deployment.backend_policy,
                "model": model,
                "endpoint": endpoint,
                "input_tokens": int(quote.input_tokens),
                "output_tokens": int(quote.output_tokens),
                "gross_fee_units": amount_units,
                "consumer_id": account.account_id,
                "consumer_payment_address": expected_receipt["consumer"],
                "provider_id": peer_id,
                "provider_payment_address": expected_receipt["provider"],
                "pricing_hash": expected_receipt["pricing_hash"],
                "settlement_version": 3,
                "pricing_version": expected_receipt["pricing_version"],
                "onchain_reservation_id": expected_receipt["reservation_id"],
                "settlement_deadline": expected_receipt["deadline"],
            },
        )
    except (AttestationError, ChainError, P2PError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"Provider V3 settlement rejected: {exc}") from exc

    if int(time.time()) > int(authorization["settlement_deadline"]):
        raise HTTPException(status_code=409, detail="Settlement V3 deadline elapsed during inference")
    _verify_consumer_v3_onchain(context, authorization)
    try:
        onchain_amount_units = call_uint256(
            context["rpc_url"],
            deployment.settlement,
            "quote(bytes32,uint64,uint256,uint256)",
            [
                receipt.channel_hash,
                str(receipt.pricing_version),
                str(receipt.input_tokens),
                str(receipt.output_tokens),
            ],
            timeout=context["timeout"],
            block_tag=context["confirmed_block"],
        )
    except (ChainError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"failed to verify confirmed V3 usage quote: {exc}") from exc
    if onchain_amount_units != amount_units:
        raise HTTPException(status_code=503, detail="confirmed Settlement V3 quote does not match actual usage")
    return dict(payload)


def _validate_consumer_v3_envelope(
    *,
    account: ConsumerAccount,
    envelope: Any,
    input_value: Any,
    model: str,
    endpoint: str,
    max_output_tokens: int,
    peers: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise HTTPException(status_code=422, detail="mycomesh_v3 must be a JSON object")
    unknown = set(envelope) - {"provider_id", "authorization", "reservation_transaction_hash"}
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown mycomesh_v3 fields: {', '.join(sorted(unknown))}")
    authorization_value = envelope.get("authorization")
    if not isinstance(authorization_value, dict):
        raise HTTPException(status_code=422, detail="mycomesh_v3.authorization is required")
    _require_consumer_payment_address(account)
    context = _consumer_v3_context()
    deployment = context["deployment"]
    provider_id = str(envelope.get("provider_id") or authorization_value.get("provider_id") or "").strip()
    candidates = [peer for peer in peers if str(peer.get("peer_id") or "") == provider_id]
    if len(candidates) != 1:
        raise HTTPException(status_code=503, detail="authorized V3 Provider is no longer available")
    peer = candidates[0]
    try:
        binding = _consumer_v3_peer_binding(
            peer,
            deployment=deployment,
            channel=str(deployment.channel),
            model=model,
        )
    except (ChainError, P2PError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=f"authorized Provider descriptor rejected: {exc}") from exc
    _consumer_v3_execution_limits(
        binding=binding,
        input_value=input_value,
        max_output_tokens=max_output_tokens,
    )
    request_hash = "0x" + _public_request_hash(
        endpoint=endpoint,
        model=model,
        input_value=input_value,
        max_output_tokens=max_output_tokens,
    )
    max_fee_units = _consumer_v3_quote(
        context,
        channel=str(deployment.channel),
        pricing_version=binding["pricing_version"],
        reserve_input_bytes=binding["reserve_input_bytes"],
        max_output_tokens=max_output_tokens,
    )
    try:
        authorization = validate_evm_session_authorization(
            authorization_value,
            chain_id=int(deployment.chain_id),
            settlement_contract=deployment.settlement,
            consumer_payment_address=normalize_address(str(account.payment_address or "")),
            provider_id=binding["peer_id"],
            provider_payment_address=binding["payment_address"],
            channel=str(deployment.channel),
            pricing_hash=binding["pricing_hash"],
            pricing_version=binding["pricing_version"],
            request_hash=request_hash,
            max_fee_units=max_fee_units,
            provider_fallback_allowed=False,
            session_public_key=request_identity.public_key,
        )
    except ReservationError as exc:
        raise HTTPException(status_code=422, detail=f"Consumer V3 authorization rejected: {exc}") from exc
    tx_hash = str(envelope.get("reservation_transaction_hash") or "")
    if tx_hash and re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash) is None:
        raise HTTPException(status_code=422, detail="reservation_transaction_hash must be bytes32")
    _verify_consumer_v3_wallet(context, authorization)
    _verify_consumer_v3_onchain(context, authorization)
    return {
        "peer": peer,
        "authorization": authorization,
        "request_hash": request_hash,
        "network_id": binding["network_id"],
        "channel_id": binding["channel_id"],
        "backend_policy": binding["backend_policy"],
        "reserve_input_bytes": binding["reserve_input_bytes"],
        "reserve_output_tokens": binding["reserve_output_tokens"],
        "max_output_tokens": max_output_tokens,
        "settlement_chain_id": int(deployment.chain_id),
        "settlement_contract": normalize_address(deployment.settlement),
    }


def _reservation_units(pricing_table: dict[str, Any], channel: str, output_tokens: int | None = None) -> int:
    input_tokens = int(os.getenv("MYCOMESH_RESERVE_INPUT_TOKENS", "8000"))
    output_tokens = int(output_tokens if output_tokens is not None else os.getenv("MYCOMESH_RESERVE_OUTPUT_TOKENS", "2000"))
    multiplier = Decimal(os.getenv("MYCOMESH_RESERVE_MULTIPLIER", "1.25"))
    quote = quote_usage(
        channel,
        {"input_tokens": input_tokens, "output_tokens": output_tokens},
        pricing_table=pricing_table,
    )
    units = usdc_to_units(str(Decimal(quote.to_dict()["gross_fee"]) * multiplier))
    return max(1, units)


def _public_request_hash(
    *,
    endpoint: str,
    model: str,
    input_value: Any,
    max_output_tokens: int,
) -> str:
    is_chat = endpoint == "chat"
    return inference_request_hash(
        endpoint=endpoint,
        model=model,
        input_value=None if is_chat else input_value,
        messages=input_value if is_chat else None,
        max_output_tokens=max_output_tokens,
    )


def _request_max_output_tokens(body: dict[str, Any]) -> int | None:
    provided: dict[str, int] = {}
    for key in ("max_output_tokens", "max_completion_tokens", "max_tokens"):
        value = body.get(key)
        if value is None:
            continue
        if type(value) is not int or value <= 0:
            raise HTTPException(status_code=422, detail=f"{key} must be a positive integer")
        provided[key] = value
    if len(set(provided.values())) > 1:
        raise HTTPException(status_code=422, detail="output token limit fields must match when provided together")
    return next(iter(provided.values()), None)


def _export_pending_receipts() -> None:
    ledger_path = Path(os.getenv("MYCOMESH_LEDGER", DEFAULT_LEDGER_PATH))
    for item in store.pending_receipts(limit=100):
        receipt_id = str(item["receipt_id"])
        claim_token = str(item["claim_token"])
        try:
            payload = json.loads(str(item["payload_json"]))
            append_receipt_payload_once(ledger_path, receipt_id, payload)
        except Exception:
            store.release_receipt_claim(receipt_id, claim_token)
            raise
        if not store.mark_receipt_exported(receipt_id, claim_token=claim_token):
            raise BillingError("receipt outbox claim was lost before export completion")


def _account_payload(account: ConsumerAccount) -> dict[str, Any]:
    return {
        "account_id": account.account_id,
        "status": account.status,
        "balance_usdc": account.balance_usdc,
        "payment_address": account.payment_address,
        "key_fingerprint": account.key_fingerprint,
        "parent_account_id": account.parent_account_id,
        "discount_bps": account.discount_bps,
        "reseller_margin_bps": account.reseller_margin_bps,
        "monthly_quota_usdc": units_to_usdc(account.monthly_quota_units),
        "monthly_used_usdc": units_to_usdc(account.monthly_used_units),
        "usage_tier": account.usage_tier,
        "credential_audience": account.credential_origin,
        "credential_network_id": account.credential_network_id,
        "credential_chain_id": account.credential_chain_id,
        "credential_settlement": account.credential_settlement,
    }


def _network_discovery_payload(limit: int = 5) -> dict[str, Any]:
    network_id = _network_id()
    chain_id, settlement = _consumer_chain_binding()
    try:
        local_public_url = _public_gateway_url()
    except GatewayRegistryError as exc:
        raise HTTPException(status_code=503, detail=f"invalid public gateway URL configuration: {exc}") from exc
    if not local_public_url:
        raise HTTPException(status_code=503, detail="MYCOMESH_PUBLIC_GATEWAY_URL is required")
    recommended_gateway = _signed_local_gateway_descriptor(
        public_url=local_public_url,
        network_id=network_id,
        chain_id=chain_id,
        settlement=settlement,
    )
    gateways: list[dict[str, Any]] = []
    for item in gateway_registry.list_gateways(limit=max(1, int(limit)) * 2):
        if (
            item.network_id != network_id
            or item.chain_id != chain_id
            or item.settlement != settlement
        ):
            continue
        record = item.to_dict()
        record["credential_audience"] = _origin_from_gateway_url(item.public_url)
        record["credential_scope"] = "origin_network_chain_settlement"
        gateways.append(record)
        if len(gateways) >= max(1, int(limit)):
            break
    return {
        "network": network_id,
        "chain_id": chain_id,
        "settlement": settlement,
        "recommended_base_url": local_public_url,
        "recommended_gateway": recommended_gateway,
        "gateways": gateways,
        "key_registration": {
            "enabled": _env_flag("MYCOMESH_PUBLIC_KEY_REGISTRATION", _is_local_profile()),
            "challenge_url": "/v1/mycomesh/keys/challenge",
            "register_url": "/v1/mycomesh/keys/register",
            "rotate_url": "/v1/mycomesh/keys/rotate",
            "revoke_url": "/v1/mycomesh/keys/current",
            "secret_storage": "client_generated_hash_only",
            "credential_scope": "origin_network_chain_settlement",
        },
        "updated_at": int(time.time()),
    }


def _gateway_urls(limit: int = 5) -> list[str]:
    payload = _network_discovery_payload(limit=limit)
    urls: list[str] = []
    recommended = payload.get("recommended_base_url")
    if recommended:
        urls.append(str(recommended))
    for gateway in payload.get("gateways", []):
        if not isinstance(gateway, dict):
            continue
        public_url = str(gateway.get("public_url") or "")
        if public_url and public_url not in urls:
            urls.append(public_url)
    return urls


def _public_gateway_url() -> str | None:
    raw = os.getenv("MYCOMESH_PUBLIC_GATEWAY_URL") or os.getenv("MYCOMESH_PUBLIC_URL")
    if not raw:
        return None
    return normalize_gateway_url(raw, allow_localhost=_is_local_profile())


def _signed_local_gateway_descriptor(
    *,
    public_url: str,
    network_id: str,
    chain_id: int,
    settlement: str,
) -> dict[str, Any]:
    now = int(time.time())
    expires_at = now + DEFAULT_GATEWAY_TTL_SECONDS
    cache_key = json.dumps(
        {
            "node_id": request_identity.peer_id,
            "public_key": request_identity.public_key,
            "public_url": public_url,
            "network_id": network_id,
            "chain_id": chain_id,
            "settlement": settlement,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    def issue(sequence: int) -> dict[str, Any]:
        unsigned = {
            "node_id": request_identity.peer_id,
            "public_key": request_identity.public_key,
            "public_url": public_url,
            "network_id": network_id,
            "chain_id": chain_id,
            "settlement": settlement,
            "sequence": sequence,
            "expires_at": expires_at,
            "ttl_seconds": DEFAULT_GATEWAY_TTL_SECONDS,
            "status": "active",
            "weight": 1,
            "capacity": 0,
            "role": "consumer_gateway",
        }
        descriptor = sign_document(
            unsigned,
            request_identity.private_key,
            purpose=GATEWAY_REGISTRATION_PURPOSE,
            timestamp=now,
        )
        return {
            **unsigned,
            "credential_audience": _origin_from_gateway_url(public_url),
            "credential_scope": "origin_network_chain_settlement",
            "descriptor": descriptor,
        }

    return gateway_registry.get_or_issue_local_descriptor(
        request_identity.peer_id,
        cache_key=cache_key,
        now=max(1, now),
        refresh_before_seconds=min(30, DEFAULT_GATEWAY_TTL_SECONDS // 3),
        factory=issue,
    )


def _key_challenge_ttl(value: Any) -> int:
    minimum = 30
    maximum = 900
    parsed = int(value if value is not None else os.getenv("MYCOMESH_KEY_CHALLENGE_TTL_SECONDS", "300"))
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"key challenge ttl_seconds must be between {minimum} and {maximum}")
    return parsed


def _key_registration_message(challenge: dict[str, object]) -> str:
    return "\n".join(
        [
            "MycoMesh API key registration",
            f"Origin: {challenge['origin']}",
            f"Network ID: {challenge['network_id']}",
            f"Wallet: {challenge['wallet']}",
            f"Key Hash: {challenge['key_hash']}",
            f"Chain ID: {challenge['chain_id']}",
            f"Settlement: {challenge['settlement']}",
            f"Nonce: {challenge['nonce']}",
            f"Expires At: {challenge['expires_at']}",
        ]
    )


def _key_registration_context() -> dict[str, object]:
    public_url = _public_gateway_url()
    if public_url is None:
        raise GatewayRegistryError("MYCOMESH_PUBLIC_GATEWAY_URL is required for public key registration")
    chain_id, settlement = _consumer_chain_binding()
    return {
        "public_url": public_url,
        "origin": _origin_from_gateway_url(public_url),
        "network_id": _network_id(),
        "chain_id": chain_id,
        "settlement": settlement,
    }


def _origin_from_gateway_url(public_url: str) -> str:
    parsed = urlparse(public_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _network_id() -> str:
    value = os.getenv("MYCOMESH_NETWORK_ID", "mycomesh-testnet").strip()
    if not value:
        raise GatewayRegistryError("MYCOMESH_NETWORK_ID must not be empty")
    return value


def _consumer_chain_binding() -> tuple[int, str]:
    deployment = _consumer_deployment_binding()
    raw_chain_id = os.getenv("ETH_CHAIN_ID")
    if raw_chain_id is not None:
        chain_id = int(raw_chain_id)
    elif deployment is not None:
        chain_id = int(deployment.chain_id)
    else:
        chain_id = 0
    if chain_id < 0:
        raise GatewayRegistryError("ETH_CHAIN_ID must be non-negative")

    configured_settlement = os.getenv("MYCO_SETTLEMENT")
    if configured_settlement:
        settlement = normalize_payment_address(configured_settlement)
        if settlement is None or int(settlement[2:], 16) == 0:
            raise BillingError("MYCO_SETTLEMENT must be a non-zero EVM address")
    elif deployment is not None:
        settlement = deployment.settlement
    else:
        raise ChainError("Myco deployment is required when MYCO_SETTLEMENT is not configured")
    return chain_id, settlement


def _consumer_deployment_binding() -> Any | None:
    try:
        return load_active_myco_deployment()
    except ChainError:
        settlement_version = os.getenv("MYCOMESH_SETTLEMENT_VERSION", "2").strip()
        if _is_local_profile() and settlement_version == "2":
            return None
        raise


def _is_local_profile() -> bool:
    return os.getenv("MYCOMESH_NETWORK_PROFILE", "testnet").strip().lower() == "local"


def _recover_personal_signer(message: str, signature_payload: Any) -> str:
    signature = _evm_signature_payload(signature_payload)
    digest = _personal_sign_digest(str(message).encode("utf-8"))
    return recover_evm_address(digest, signature)


def _verify_key_registration_signature(
    *,
    wallet: str,
    message: str,
    signature_payload: Any,
    caller: str,
    deadline: float | None = None,
) -> None:
    digest = _personal_sign_digest(str(message).encode("utf-8"))
    rpc_url = str(os.getenv("ETH_RPC_URL") or "").strip()
    if not rpc_url:
        _verify_eoa_key_registration_signature(wallet, message, signature_payload)
        return

    if deadline is None:
        deadline = time.monotonic() + _configured_key_registration_rpc_timeout()
    try:
        code = rpc_call(
            rpc_url,
            "eth_getCode",
            [wallet, "latest"],
            _remaining_key_registration_rpc_time(deadline),
        )
        is_contract = _has_contract_code(code)
    except ChainError as exc:
        raise HTTPException(status_code=503, detail=f"failed to identify wallet type: {exc}") from exc

    if not is_contract:
        _verify_eoa_key_registration_signature(wallet, message, signature_payload)
        return

    try:
        contract_signature = _eip1271_signature_payload(signature_payload)
    except (ChainError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=403, detail=f"contract wallet signature rejected: {exc}") from exc
    try:
        verify_eip1271_signature(
            rpc_url=rpc_url,
            signer=wallet,
            digest=digest,
            signature=contract_signature,
            caller=caller,
            timeout=_remaining_key_registration_rpc_time(deadline),
        )
    except EIP1271SignatureRejected as exc:
        raise HTTPException(status_code=403, detail=f"contract wallet signature rejected: {exc}") from exc
    except ChainError as exc:
        raise HTTPException(status_code=503, detail=f"contract wallet verification unavailable: {exc}") from exc


async def _verify_key_registration_signature_async(
    *,
    wallet: str,
    message: str,
    signature_payload: Any,
    caller: str,
    nonce_claim: _KeyRegistrationNonceClaim | None = None,
    before_submit: Callable[[], Callable[[], None] | None] | None = None,
) -> None:
    timeout = _configured_key_registration_rpc_timeout()
    deadline = time.monotonic() + timeout
    if not _key_registration_rpc_slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="key registration RPC capacity is exhausted")
    rollback_submission: Callable[[], None] | None = None
    try:
        if before_submit is not None:
            rollback_submission = before_submit()
    except BaseException:
        _key_registration_rpc_slots.release()
        raise

    def run() -> None:
        try:
            _verify_key_registration_signature(
                wallet=wallet,
                message=message,
                signature_payload=signature_payload,
                caller=caller,
                deadline=deadline,
            )
        finally:
            _key_registration_rpc_slots.release()
            if nonce_claim is not None:
                nonce_claim.worker_finished()

    loop = asyncio.get_running_loop()
    try:
        worker = loop.run_in_executor(_key_registration_rpc_executor, run)
    except BaseException as exc:
        _key_registration_rpc_slots.release()
        if rollback_submission is not None:
            try:
                rollback_submission()
            except Exception:
                logger.exception("failed to roll back unsubmitted key registration verification")
        if isinstance(exc, HTTPException):
            raise
        if isinstance(exc, Exception):
            raise HTTPException(
                status_code=503,
                detail="key registration RPC executor is unavailable",
            ) from exc
        raise
    worker.add_done_callback(_consume_key_registration_worker_exception)
    try:
        await asyncio.wait_for(
            asyncio.shield(worker),
            timeout=_remaining_key_registration_rpc_time(deadline),
        )
    except asyncio.TimeoutError as exc:
        if nonce_claim is not None:
            nonce_claim.defer_to_worker()
        raise HTTPException(status_code=504, detail="key registration RPC deadline exceeded") from exc
    except asyncio.CancelledError:
        if nonce_claim is not None:
            nonce_claim.defer_to_worker()
        raise
    except HTTPException as exc:
        if exc.status_code == 504 and nonce_claim is not None:
            nonce_claim.defer_to_worker()
        raise


def _configured_key_registration_rpc_timeout() -> float:
    try:
        return bounded_timeout(
            os.getenv(
                "MYCOMESH_KEY_REGISTRATION_RPC_TIMEOUT",
                os.getenv("MYCOMESH_SETTLEMENT_RPC_TIMEOUT", "20"),
            ),
            maximum=MAX_KEY_REGISTRATION_RPC_TIMEOUT_SECONDS,
            label="key registration RPC timeout",
        )
    except NetworkIOError as exc:
        raise HTTPException(status_code=503, detail=f"invalid key registration RPC configuration: {exc}") from exc


def _configured_key_registration_max_attempts() -> int:
    raw = os.getenv(
        "MYCOMESH_KEY_REGISTRATION_MAX_ATTEMPTS",
        str(DEFAULT_KEY_CHALLENGE_VERIFICATION_ATTEMPTS),
    )
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="invalid key registration max attempts configuration",
        ) from exc
    if value < 1 or value > MAX_KEY_CHALLENGE_VERIFICATION_ATTEMPTS:
        raise HTTPException(
            status_code=503,
            detail=(
                "key registration max attempts must be between 1 and "
                f"{MAX_KEY_CHALLENGE_VERIFICATION_ATTEMPTS}"
            ),
        )
    return value


def _remaining_key_registration_rpc_time(deadline: float) -> float:
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise HTTPException(status_code=504, detail="key registration RPC deadline exceeded")
    return remaining


def _consume_key_registration_worker_exception(worker: asyncio.Future[Any]) -> None:
    if not worker.cancelled():
        worker.exception()


def _claim_inflight_key_registration_nonce(nonce: str) -> _KeyRegistrationNonceClaim:
    with _key_registration_nonce_lock:
        if nonce in _key_registration_nonces_inflight:
            raise HTTPException(status_code=409, detail="key registration for this nonce is already in progress")
        _key_registration_nonces_inflight.add(nonce)
    return _KeyRegistrationNonceClaim(nonce)


def _release_inflight_key_registration_nonce(nonce: str) -> None:
    with _key_registration_nonce_lock:
        _key_registration_nonces_inflight.discard(nonce)


def _verify_eoa_key_registration_signature(wallet: str, message: str, signature_payload: Any) -> None:
    try:
        recovered = _recover_personal_signer(message, signature_payload)
    except (ChainError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=403, detail=f"invalid wallet signature: {exc}") from exc
    if recovered.lower() != wallet.lower():
        raise HTTPException(status_code=403, detail="wallet signature does not match wallet")


def _has_contract_code(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ChainError(f"unexpected eth_getCode response: {value!r}")
    encoded = value[2:]
    if len(encoded) % 2 or re.fullmatch(r"[0-9a-fA-F]*", encoded) is None:
        raise ChainError(f"unexpected eth_getCode response: {value!r}")
    code = bytes.fromhex(encoded)
    return bool(code and any(code))


def _eip1271_signature_payload(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ChainError("contract wallet signature must be 0x-prefixed hex")
    raw = value.strip()
    if not raw.startswith("0x"):
        raise ChainError("contract wallet signature must be 0x-prefixed hex")
    encoded = raw[2:]
    if not encoded or len(encoded) % 2 or re.fullmatch(r"[0-9a-fA-F]+", encoded) is None:
        raise ChainError("contract wallet signature must be non-empty even-length hex")
    if len(encoded) > MAX_EIP1271_SIGNATURE_BYTES * 2:
        raise ChainError(f"contract wallet signature exceeds {MAX_EIP1271_SIGNATURE_BYTES} bytes")
    return bytes.fromhex(encoded)


def _personal_sign_digest(message: bytes) -> bytes:
    prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode("utf-8")
    return keccak256(prefix + message)


def _evm_signature_payload(value: Any) -> EvmSignature:
    if isinstance(value, dict):
        return evm_signature_from_json(value)
    raw = str(value or "").strip()
    if raw.startswith("0x") and len(raw) == 132:
        payload = bytes.fromhex(raw[2:])
        v = payload[64]
        if v < 27:
            v += 27
        return EvmSignature(
            r="0x" + payload[:32].hex(),
            s="0x" + payload[32:64].hex(),
            v=v,
        )
    return evm_signature_from_json(raw)


def _chain_sync_state_from_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    keys = {"chain_id", "settlement", "synced_block", "synced_block_hash"}
    if keys.issubset(payload.keys()):
        supplied_source = str(payload.get("source") or "direct")
        if supplied_source != "direct":
            raise ValueError("manual sync source must be 'direct'; event state is published by the indexer")
        return {
            "chain_id": int(payload["chain_id"]),
            "settlement": str(payload["settlement"]),
            "latest_block": int(payload.get("latest_block", payload["synced_block"])),
            "synced_block": int(payload["synced_block"]),
            "confirmations": int(payload.get("confirmations", 0)),
            "synced_block_hash": str(payload["synced_block_hash"]),
        }
    if any(
        key in payload
        for key in (
            "chain_id",
            "settlement",
            "latest_block",
            "synced_block",
            "synced_block_hash",
            "confirmations",
            "source",
        )
    ):
        missing = ", ".join(sorted(keys - set(payload.keys())))
        raise ValueError(f"missing {missing}")
    return None


def _channel_pricing_hash(pricing_table: dict[str, Any], channel: str) -> str:
    snapshot = channel_pricing_snapshot(pricing_table, channel)
    if _billing_mode() != "local" and snapshot.source not in {"chain", "override"}:
        raise HTTPException(
            status_code=409,
            detail="on-chain prepaid serving requires chain or explicit channel pricing hash",
        )
    return snapshot.pricing_hash


def _require_consumer_payment_address(account: ConsumerAccount) -> None:
    if _billing_mode() == "local" and not _env_flag("MYCOMESH_REQUIRE_CONSUMER_PAYMENT_ADDRESS", False):
        return
    if not account.payment_address:
        raise HTTPException(status_code=409, detail="account payment_address is required for settlement receipts")


def _require_provider_settlement_fields(peer_info: dict[str, Any]) -> None:
    if not str(peer_info.get("public_key") or ""):
        raise HTTPException(status_code=502, detail="provider pool descriptor is missing public_key")
    if not str(peer_info.get("payment_address") or ""):
        raise HTTPException(status_code=502, detail="provider pool descriptor is missing payment_address")


_ACCOUNT_RATE_LIMITS: dict[str, list[float]] = {}
_ACCOUNT_RATE_LIMITS_LOCK = threading.Lock()


def _rate_limit_account(account_id: str) -> None:
    window = int(os.getenv("MYCOMESH_ACCOUNT_RATE_LIMIT_WINDOW_SECONDS", "60"))
    maximum = int(os.getenv("MYCOMESH_ACCOUNT_RATE_LIMIT_MAX_REQUESTS", "120"))
    if maximum <= 0:
        return
    now = time.time()
    with _ACCOUNT_RATE_LIMITS_LOCK:
        recent = [timestamp for timestamp in _ACCOUNT_RATE_LIMITS.get(account_id, []) if now - timestamp < window]
        if len(recent) >= maximum:
            raise HTTPException(status_code=429, detail="account rate limit exceeded")
        recent.append(now)
        _ACCOUNT_RATE_LIMITS[account_id] = recent


async def _request_json(request: Request) -> dict[str, Any]:
    limit = int(os.getenv("MYCOMESH_MAX_REQUEST_BYTES", str(1024 * 1024)))
    payload = bytearray()
    async for chunk in request.stream():
        if len(chunk) > limit - len(payload):
            raise HTTPException(status_code=413, detail="request body too large")
        payload.extend(chunk)
    if not payload:
        return {}
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="request body must be valid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    return value


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


async def _responses_sse(payload: dict[str, Any]):
    response_id = str(payload.get("id") or payload.get("request_id") or "resp_" + uuid.uuid4().hex)
    model = str(payload.get("model") or os.getenv("MYCOMESH_PUBLIC_MODEL_ID", DEFAULT_PUBLIC_MODEL_ID))
    text = str(payload.get("output_text") or "")
    yield _sse_event(
        "response.created",
        {
            "type": "response.created",
            "response": {"id": response_id, "object": "response", "status": "in_progress", "model": model},
        },
    )
    if text:
        yield _sse_event(
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "item_id": "item_0",
                "output_index": 0,
                "content_index": 0,
                "delta": text,
            },
        )
    completed = dict(payload)
    completed.setdefault("id", response_id)
    completed.setdefault("object", "response")
    completed["status"] = "completed"
    yield _sse_event("response.completed", {"type": "response.completed", "response": completed})
    yield "data: [DONE]\n\n"


async def _chat_sse(payload: dict[str, Any], model: str):
    chunk_id = str(payload.get("id") or "chatcmpl_" + uuid.uuid4().hex)
    content = _chat_content(payload)
    yield _sse_data(
        {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
        }
    )
    if content:
        yield _sse_data(
            {
                "id": chunk_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
            }
        )
    yield _sse_data(
        {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
    )
    yield "data: [DONE]\n\n"


def _chat_content(payload: dict[str, Any]) -> str:
    try:
        return str(payload["choices"][0]["message"].get("content") or "")
    except (KeyError, IndexError, TypeError):
        return str(payload.get("output_text") or "")


def _sse_event(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False, sort_keys=True)}\n\n"


def _sse_data(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False, sort_keys=True)}\n\n"
