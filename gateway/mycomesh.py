from __future__ import annotations

import json
from decimal import Decimal
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse

from .billing import BillingError, BillingStore, ConsumerAccount, normalize_api_key_hash, normalize_payment_address, usdc_to_units, units_to_usdc
from .chain import ChainError, EvmSignature, evm_signature_from_json, keccak256, load_myco_deployment, recover_evm_address
from .gateway_registry import DEFAULT_GATEWAY_REGISTRY_DB, GatewayRegistry, GatewayRegistryError, normalize_gateway_url
from .identity import DEFAULT_REQUEST_IDENTITY_PATH, load_or_create_identity
from .ledger import DEFAULT_LEDGER_PATH, append_receipt_payload, build_receipt, sign_acceptance
from .pool import DEFAULT_POOL_URL, PoolError
from .pricing import load_pricing_config, quote_usage
from .pricing_source import channel_pricing_snapshot
from .p2p import DEFAULT_CHANNEL, P2PError
from .protocol import ProtocolValidationError, verify_provider_response
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


app = FastAPI(title="MycoMesh Consumer Proxy")
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
        wallet = normalize_payment_address(payload.get("wallet"))
        if wallet is None:
            raise BillingError("wallet is required")
        key_hash = normalize_api_key_hash(str(payload.get("key_hash") or ""))
        chain_id = int(payload.get("chain_id") or os.getenv("ETH_CHAIN_ID", "0"))
        ttl_seconds = _key_challenge_ttl(payload.get("ttl_seconds"))
        challenge = store.create_key_challenge(wallet=wallet, key_hash=key_hash, chain_id=chain_id, ttl_seconds=ttl_seconds)
    except (BillingError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    message = _key_registration_message(challenge)
    return {
        "wallet": challenge["wallet"],
        "account_id": challenge["wallet"],
        "key_hash": challenge["key_hash"],
        "key_fingerprint": str(challenge["key_hash"])[:12],
        "chain_id": challenge["chain_id"],
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
        wallet = normalize_payment_address(payload.get("wallet"))
        if wallet is None:
            raise BillingError("wallet is required")
        key_hash = normalize_api_key_hash(str(payload.get("key_hash") or ""))
        chain_id = int(payload.get("chain_id") or os.getenv("ETH_CHAIN_ID", "0"))
        nonce = str(payload.get("nonce") or "")
        challenge = store.get_key_challenge(nonce)
        if challenge is None:
            raise BillingError("key registration challenge not found")
        expected_message = _key_registration_message(challenge)
        recovered = _recover_personal_signer(expected_message, payload.get("signature"))
        if recovered.lower() != wallet.lower():
            raise HTTPException(status_code=403, detail="wallet signature does not match wallet")
        store.consume_key_challenge(wallet=wallet, key_hash=key_hash, chain_id=chain_id, nonce=nonce)
        account = store.register_key_hash(wallet, key_hash, payment_address=wallet)
    except HTTPException:
        raise
    except (BillingError, ChainError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = _account_payload(account)
    result.update(
        {
            "account_id": account.account_id,
            "wallet": wallet,
            "api_key_material": "client_generated",
            "api_key_returned": False,
            "base_urls": _gateway_urls(limit=int(os.getenv("MYCOMESH_DISCOVERY_LIMIT", "5"))),
        }
    )
    return result


@app.post("/gateways")
async def register_gateway(payload: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_signed = isinstance(payload.get("signature"), dict)
    if require_signed and not _env_flag("MYCOMESH_ALLOW_PUBLIC_GATEWAY_REGISTRATION", True):
        _require_admin(authorization)
    if not require_signed:
        _require_admin(authorization)
    try:
        record = gateway_registry.register(
            payload,
            ttl_seconds=int(os.getenv("MYCOMESH_GATEWAY_TTL_SECONDS", "300")),
            require_signed=require_signed,
        )
    except (GatewayRegistryError, TypeError, ValueError) as exc:
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
    account = store.create_account((payload or {}).get("account_id"), payment_address=(payload or {}).get("payment_address"))
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
        account = store.set_balance(account_id, str(payload.get("balance_usdc") or "0"))
        if chain_sync is not None:
            store.set_chain_sync_state(**chain_sync)
    except BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid chain sync metadata: {exc}") from exc
    return {
        "account_id": account.account_id,
        "balance_usdc": account.balance_usdc,
        "payment_address": account.payment_address,
        "billing_mode": _billing_mode(),
        "chain_sync": store.get_chain_sync_state(),
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
    try:
        account = store.rotate_key(account_id)
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
                "id": os.getenv("MYCOMESH_PUBLIC_MODEL_ID", "mycomesh-codex-standard-v1"),
                "object": "model",
                "created": 0,
                "owned_by": "mycomesh",
            }
        ],
    }


@app.get("/account")
async def account(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    consumer = _account_from_auth(authorization)
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
    }


@app.post("/v1/responses")
async def responses(request: Request, authorization: str | None = Header(default=None)) -> Any:
    account = _account_from_auth(authorization)
    _rate_limit_account(account.account_id)
    body = await _request_json(request)
    output = _run_pool_inference(
        account=account,
        input_value=body.get("input", ""),
        model=str(body.get("model") or os.getenv("MYCOMESH_PUBLIC_MODEL_ID", "mycomesh-codex-standard-v1")),
        endpoint="responses",
        max_output_tokens=_request_max_output_tokens(body),
    )
    if body.get("stream") is True:
        return StreamingResponse(_responses_sse(output), media_type="text/event-stream", headers={"x-mycomesh-streaming-mode": "buffered"})
    return output


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, authorization: str | None = Header(default=None)) -> Any:
    account = _account_from_auth(authorization)
    _rate_limit_account(account.account_id)
    body = await _request_json(request)
    output = _run_pool_inference(
        account=account,
        input_value=body.get("messages", []),
        model=str(body.get("model") or os.getenv("MYCOMESH_PUBLIC_MODEL_ID", "mycomesh-codex-standard-v1")),
        endpoint="chat",
        max_output_tokens=_request_max_output_tokens(body),
    )
    raw = output.get("raw") if isinstance(output.get("raw"), dict) else output
    if body.get("stream") is True:
        return StreamingResponse(
            _chat_sse(raw, model=str(body.get("model") or "mycomesh-codex-standard-v1")),
            media_type="text/event-stream",
            headers={"x-mycomesh-streaming-mode": "buffered"},
        )
    return raw


def _run_pool_inference(account: ConsumerAccount, input_value: Any, model: str, endpoint: str, max_output_tokens: int | None = None) -> dict[str, Any]:
    _require_serving_billing_mode()
    pool_url = os.getenv("MYCOMESH_POOL_URL", DEFAULT_POOL_URL)
    channel = os.getenv("MYCOMESH_CHANNEL", DEFAULT_CHANNEL)
    timeout = float(os.getenv("MYCOMESH_TIMEOUT_SECONDS", "180"))
    try:
        peers = discover_peers_from_pools(_split_urls(pool_url), channel=channel, timeout=min(timeout, 10.0))
    except PoolError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not peers:
        raise HTTPException(status_code=503, detail=f"no live peers found for channel {channel}")

    last_error: Exception | None = None
    route_state_path = os.getenv("MYCOMESH_ROUTE_STATE", DEFAULT_ROUTE_STATE_PATH)
    route_state = load_route_state(route_state_path)
    pricing_table = load_pricing_config(os.getenv("MYCOMESH_PRICING_CONFIG"))
    channel_pricing_hash = _channel_pricing_hash(pricing_table, channel)
    _require_consumer_payment_address(account)
    reservation_id = "res_" + uuid.uuid4().hex
    reservation_output_tokens = int(max_output_tokens or os.getenv("MYCOMESH_RESERVE_OUTPUT_TOKENS", "2000"))
    reservation_units = _reservation_units(pricing_table, channel, output_tokens=reservation_output_tokens)
    try:
        store.reserve(account.account_id, reservation_units, reservation_id)
    except BillingError as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc
    captured = False
    for peer_info in rank_peers(peers, route_state):
        peer_id = str(peer_info.get("peer_id") or "")
        if _env_flag("MYCOMESH_REQUIRE_PROVIDER_SETTLEMENT_FIELDS", True):
            try:
                _require_provider_settlement_fields(peer_info)
            except HTTPException as exc:
                last_error = RuntimeError(str(exc.detail))
                record_route_failure(route_state, peer_id, last_error)
                save_route_state(route_state, route_state_path)
                continue
        try:
            lease_id = reserve_peer(route_state, peer_info, ttl_seconds=int(timeout))
            save_route_state(route_state, route_state_path)
        except ValueError as exc:
            last_error = exc
            continue
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
                    timeout=timeout,
                    identity=request_identity,
                    consumer_id=account.account_id,
                    consumer_payment_address=account.payment_address,
                    provider_payment_address=str(peer_info.get("payment_address") or "") or None,
                    pricing_hash=channel_pricing_hash,
                    max_fee_units=reservation_units,
                    max_output_tokens=reservation_output_tokens,
                )
            except (P2PError, RelayError, ValueError) as exc:
                last_error = exc
                record_route_failure(route_state, peer_id, exc)
                save_route_state(route_state, route_state_path)
                continue
            finished_at = time.time()
            try:
                verify_provider_response(response, peer_info, audience=request_identity.public_key)
            except ProtocolValidationError as exc:
                last_error = exc
                record_route_failure(route_state, peer_id, exc)
                save_route_state(route_state, route_state_path)
                continue
            record_route_success(route_state, peer_id, int((finished_at - started_at) * 1000))
            save_route_state(route_state, route_state_path)
            quote = quote_usage(
                channel,
                response.get("usage") if isinstance(response, dict) else None,
                pricing_table=pricing_table,
            )
            amount_units = usdc_to_units(quote.to_dict()["gross_fee"])
            if amount_units > reservation_units:
                release_peer(route_state, lease_id)
                store.release(reservation_id)
                raise HTTPException(status_code=402, detail="inference cost exceeded payment reservation")
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
                signer=request_identity,
            )
            try:
                accepted_receipt = sign_acceptance(receipt.to_dict(), request_identity, accepted_by=account.account_id)
                store.capture(
                    reservation_id,
                    amount_units,
                    event_id=receipt.job_id,
                    receipt=accepted_receipt,
                    outbox_payload=accepted_receipt,
                )
                captured = True
                record_route_acceptance(route_state, peer_id)
                save_route_state(route_state, route_state_path)
            except BillingError as exc:
                store.release(reservation_id)
                release_peer(route_state, lease_id)
                save_route_state(route_state, route_state_path)
                raise HTTPException(status_code=402, detail=str(exc)) from exc
            except Exception as exc:
                store.release(reservation_id)
                record_route_failure(route_state, peer_id, exc)
                release_peer(route_state, lease_id)
                save_route_state(route_state, route_state_path)
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            _export_pending_receipts()
            payload = dict(response)
            payload["mycomesh_receipt"] = accepted_receipt
            payload["mycomesh_price"] = quote.to_dict()
            release_peer(route_state, lease_id)
            save_route_state(route_state, route_state_path)
            return payload
        release_peer(route_state, lease_id)
        save_route_state(route_state, route_state_path)
    if not captured:
        store.release(reservation_id)
    raise HTTPException(status_code=502, detail=f"all pool peers failed: {last_error}")


def _account_from_auth(authorization: str | None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer <mycomesh_api_key> is required")
    account = store.get_by_key(authorization.split(" ", 1)[1].strip())
    if account is None:
        raise HTTPException(status_code=401, detail="invalid MycoMesh API key")
    if account.status != "active":
        raise HTTPException(status_code=403, detail=f"account is {account.status}")
    return account


def _require_admin(authorization: str | None) -> None:
    token = os.getenv("MYCOMESH_ADMIN_TOKEN")
    if not token:
        raise HTTPException(status_code=403, detail="MYCOMESH_ADMIN_TOKEN is required for account administration")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer <admin_token> is required")
    if authorization.split(" ", 1)[1].strip() != token:
        raise HTTPException(status_code=403, detail="invalid admin token")


def _require_public_key_registration_enabled() -> None:
    if _env_flag("MYCOMESH_PUBLIC_KEY_REGISTRATION", True):
        return
    raise HTTPException(status_code=403, detail="public key registration is disabled")


def _require_local_billing_mode() -> None:
    if _billing_mode() != "local":
        raise HTTPException(status_code=409, detail="local balance mutation is disabled outside MYCOMESH_BILLING_MODE=local")


def _require_serving_billing_mode() -> None:
    mode = _billing_mode()
    if mode == "local":
        return
    if mode == "onchain-prepaid" and _env_flag("MYCOMESH_ALLOW_LOCAL_BALANCE_CACHE", False):
        try:
            deployment = load_myco_deployment(Path(os.getenv("MYCO_DEPLOYMENT", "deployments/sepolia-myco-v2.json")))
            store.require_fresh_chain_sync(
                chain_id=int(os.getenv("ETH_CHAIN_ID", str(deployment.chain_id))),
                settlement=os.getenv("MYCO_SETTLEMENT", deployment.settlement),
                max_age_seconds=int(os.getenv("MYCOMESH_CHAIN_SYNC_MAX_AGE_SECONDS", "120")),
                max_block_lag=int(os.getenv("MYCOMESH_CHAIN_SYNC_MAX_BLOCK_LAG", "12")),
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


def _billing_mode() -> str:
    return os.getenv("MYCOMESH_BILLING_MODE", "local").strip().lower() or "local"


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


def _request_max_output_tokens(body: dict[str, Any]) -> int | None:
    for key in ("max_output_tokens", "max_tokens"):
        value = body.get(key)
        if value is None:
            continue
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        if parsed > 0:
            return parsed
    return None


def _export_pending_receipts() -> None:
    ledger_path = Path(os.getenv("MYCOMESH_LEDGER", DEFAULT_LEDGER_PATH))
    for item in store.pending_receipts(limit=100):
        payload = json.loads(str(item["payload_json"]))
        append_receipt_payload(ledger_path, payload)
        store.mark_receipt_exported(str(item["receipt_id"]))


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
    }


def _network_discovery_payload(limit: int = 5) -> dict[str, Any]:
    gateways = [record.to_dict() for record in gateway_registry.list_gateways(limit=max(1, int(limit)))]
    base_urls = [str(record["public_url"]) for record in gateways]
    local_public_url = _public_gateway_url()
    if local_public_url and local_public_url not in base_urls:
        base_urls.append(local_public_url)
    return {
        "network": os.getenv("MYCOMESH_NETWORK_ID", "mycomesh-testnet"),
        "recommended_base_url": base_urls[0] if base_urls else local_public_url,
        "base_urls": base_urls,
        "gateways": gateways,
        "key_registration": {
            "challenge_url": "/v1/mycomesh/keys/challenge",
            "register_url": "/v1/mycomesh/keys/register",
            "secret_storage": "client_generated_hash_only",
        },
        "updated_at": int(time.time()),
    }


def _gateway_urls(limit: int = 5) -> list[str]:
    payload = _network_discovery_payload(limit=limit)
    return [str(url) for url in payload.get("base_urls", [])]


def _public_gateway_url() -> str | None:
    raw = os.getenv("MYCOMESH_PUBLIC_GATEWAY_URL") or os.getenv("MYCOMESH_PUBLIC_URL")
    if not raw:
        return None
    try:
        return normalize_gateway_url(raw)
    except GatewayRegistryError:
        return raw.strip().rstrip("/")


def _key_challenge_ttl(value: Any) -> int:
    if value is None:
        return int(os.getenv("MYCOMESH_KEY_CHALLENGE_TTL_SECONDS", "600"))
    return max(1, int(value))


def _key_registration_message(challenge: dict[str, object]) -> str:
    return "\n".join(
        [
            "MycoMesh API key registration",
            f"Wallet: {challenge['wallet']}",
            f"Key Hash: {challenge['key_hash']}",
            f"Chain ID: {challenge['chain_id']}",
            f"Nonce: {challenge['nonce']}",
            f"Expires At: {challenge['expires_at']}",
        ]
    )


def _recover_personal_signer(message: str, signature_payload: Any) -> str:
    signature = _evm_signature_payload(signature_payload)
    digest = _personal_sign_digest(str(message).encode("utf-8"))
    return recover_evm_address(digest, signature)


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
    keys = {"chain_id", "settlement", "synced_block"}
    if keys.issubset(payload.keys()):
        return {
            "chain_id": int(payload["chain_id"]),
            "settlement": str(payload["settlement"]),
            "latest_block": int(payload.get("latest_block", payload["synced_block"])),
            "synced_block": int(payload["synced_block"]),
            "confirmations": int(payload.get("confirmations", 0)),
            "source": str(payload.get("source") or "admin-sync-balance"),
        }
    if any(key in payload for key in ("chain_id", "settlement", "latest_block", "synced_block", "confirmations", "source")):
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
        payload.extend(chunk)
        if len(payload) > limit:
            raise HTTPException(status_code=413, detail="request body too large")
    if not payload:
        return {}
    try:
        value = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
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
    model = str(payload.get("model") or os.getenv("MYCOMESH_PUBLIC_MODEL_ID", "mycomesh-codex-standard-v1"))
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
