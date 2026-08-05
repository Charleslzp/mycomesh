from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import secrets
import shlex
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import httpx
import uvicorn
from fastapi import FastAPI, Header, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .billing import BillingError, usdc_to_units
from .chain import ZERO_ADDRESS, ChainError, abi_encode_arg, call_contract, keccak256, normalize_address
from .chain_v8 import (
    account_balance,
    build_authorization,
    generate_payment_key,
    key_grant,
    payment_key_address,
    payment_private_key,
    verify_signed_receipt,
)
from .openai_protocol import chat_completion_sse, normalize_openai_error, openai_error, response_stream_events, responses_sse
from .reservation import (
    RESPONSES_LOCAL_OPTION_FIELDS,
    RESPONSES_REQUEST_OPTION_FIELDS,
    derive_prompt_cache_key,
    inference_request_hash,
    normalize_inference_request_options,
)


DEFAULT_BASE_URL = "http://127.0.0.1:8110/v1"
DEFAULT_MAX_FEE_UNITS = 100_000
# Public RPCs can lag the local clock by more than a few seconds. Keep the
# signed window below the contract's one-hour TTL while leaving settlement room.
AUTHORIZATION_CLOCK_SKEW_SECONDS = 300
RETRYABLE_RELAY_STATUS = {408, 429, 500, 502, 503, 504}


class ConsumerV8Error(RuntimeError):
    pass


@dataclass(frozen=True)
class ConsumerV8Config:
    data_dir: Path
    base_url: str = DEFAULT_BASE_URL
    relay_urls: tuple[str, ...] = ()
    max_fee_units: int = DEFAULT_MAX_FEE_UNITS
    timeout_seconds: float = 300.0
    health_timeout_seconds: float = 5.0
    network_config_path: Path | None = None

    @classmethod
    def from_env(cls) -> "ConsumerV8Config":
        data_dir = Path(os.getenv("MYCOMESH_CONSUMER_DATA_DIR", "/data"))
        raw_relays = os.getenv("MYCOMESH_V8_RELAY_URLS") or os.getenv("MYCOMESH_CONSUMER_RELAY_URL") or "https://bridge.mycomesh.xyz"
        relays = tuple(item.rstrip("/") for item in raw_relays.split(",") if item.strip())
        if not relays:
            raise ConsumerV8Error("MYCOMESH_V8_RELAY_URLS must contain at least one Relay URL")
        try:
            max_fee = int(os.getenv("MYCOMESH_V8_MAX_FEE_UNITS", str(DEFAULT_MAX_FEE_UNITS)))
        except ValueError as exc:
            raise ConsumerV8Error("MYCOMESH_V8_MAX_FEE_UNITS must be an integer") from exc
        if max_fee <= 0:
            raise ConsumerV8Error("MYCOMESH_V8_MAX_FEE_UNITS must be positive")
        return cls(
            data_dir=data_dir,
            base_url=os.getenv("MYCOMESH_CONSUMER_PUBLIC_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            relay_urls=relays,
            max_fee_units=max_fee,
            timeout_seconds=float(os.getenv("MYCOMESH_V8_REQUEST_TIMEOUT_SECONDS", "300")),
            health_timeout_seconds=float(os.getenv("MYCOMESH_V8_HEALTH_TIMEOUT_SECONDS", "5")),
            network_config_path=Path(
                os.getenv(
                    "MYCOMESH_CONSUMER_NETWORK_CONFIG",
                    "/app/deployments/sepolia-provider-network-v8.json",
                )
            ),
        )


class ConsumerV8State:
    def __init__(self, config: ConsumerV8Config | None = None) -> None:
        self.config = config or ConsumerV8Config.from_env()
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.config.data_dir.chmod(0o700)
        except OSError:
            pass
        self._payment_key_from_env = bool(os.getenv("MYCOMESH_V8_PAYMENT_KEY", "").strip())
        self.payment_key = self._load_payment_key()
        self.payment_address = payment_key_address(self.payment_key)
        self._health_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._management_lock = threading.Lock()
        self._history_path = self.config.data_dir / "receipt-history.jsonl"
        self._pending_key_path = self.config.data_dir / "pending-payment-key"
        self._settlement = self._load_settlement_config()

    def _load_payment_key(self) -> str:
        configured = os.getenv("MYCOMESH_V8_PAYMENT_KEY", "").strip()
        path = self.config.data_dir / "payment-key"
        if configured:
            payment_private_key(configured)
            return configured
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            payment_private_key(value)
            return value
        value = generate_payment_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(value + "\n")
        except BaseException:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return value

    def credentials_text(self) -> str:
        return "\n".join(
            (
                f"export OPENAI_BASE_URL={shlex.quote(self.config.base_url)}",
                f"export OPENAI_API_KEY={shlex.quote(self.payment_key)}",
            )
        )

    def _load_settlement_config(self) -> dict[str, Any] | None:
        configured = self.config.network_config_path
        candidates = [configured] if configured is not None else []
        candidates.append(
            Path(__file__).resolve().parents[1]
            / "deployments"
            / "sepolia-provider-network-v8.json"
        )
        network_path = next((path for path in candidates if path is not None and path.is_file()), None)
        if network_path is None:
            return None
        try:
            network = json.loads(network_path.read_text(encoding="utf-8"))
            deployment_path = network_path.parent / str(network["deployment"])
            deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
            if int(deployment.get("protocol_version") or 0) != 8:
                return None
            rpc_urls = [
                str(value).strip()
                for value in network.get("settlement_rpc_urls", [])
                if str(value).strip()
            ]
            if not rpc_urls and str(network.get("settlement_rpc_url") or "").strip():
                rpc_urls = [str(network["settlement_rpc_url"]).strip()]
            if not rpc_urls:
                return None
            return {
                "chain_id": int(deployment["chain_id"]),
                "network_name": "Sepolia testnet" if int(deployment["chain_id"]) == 11155111 else "EVM network",
                "settlement_contract": normalize_address(str(deployment["settlement"])),
                "stablecoin": normalize_address(str(deployment["stablecoin"])),
                "stablecoin_symbol": "tUSDC",
                "stablecoin_decimals": 6,
                "deployment_block": int(deployment.get("deployment_block") or 0),
                "rpc_urls": rpc_urls,
                "explorer_url": "https://sepolia.etherscan.io" if int(deployment["chain_id"]) == 11155111 else "",
            }
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, ChainError):
            return None

    def _rpc_value(self, callback: Any) -> Any:
        if self._settlement is None:
            raise ConsumerV8Error("Settlement V8 network configuration is unavailable")
        errors: list[str] = []
        for rpc_url in self._settlement["rpc_urls"]:
            try:
                return callback(rpc_url)
            except (ChainError, OSError, ValueError) as exc:
                errors.append(str(exc))
        raise ConsumerV8Error("all configured Settlement V8 RPC endpoints failed: " + "; ".join(errors))

    def _grant_for(self, key_address: str) -> dict[str, Any]:
        if self._settlement is None:
            raise ConsumerV8Error("Settlement V8 network configuration is unavailable")
        return self._rpc_value(
            lambda rpc: key_grant(rpc, self._settlement["settlement_contract"], key_address)
        )

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        try:
            lines = self._history_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        entries: list[dict[str, Any]] = []
        selected = lines if limit <= 0 else lines[-max(1, min(limit, 500)) :]
        for line in selected:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                entries.append(value)
        return list(reversed(entries))

    def record_receipt(
        self,
        *,
        relay_url: str,
        endpoint: str,
        model: str,
        settlement: Mapping[str, Any],
    ) -> None:
        signed = settlement.get("signed_receipt")
        receipt = signed.get("receipt") if isinstance(signed, Mapping) else None
        authorization = signed.get("authorization") if isinstance(signed, Mapping) else None
        auth_value = authorization.get("authorization") if isinstance(authorization, Mapping) else None
        if not isinstance(receipt, Mapping) or not isinstance(auth_value, Mapping):
            return
        entry = {
            "timestamp": int(time.time()),
            "request_id": str(auth_value.get("request_id") or ""),
            "settlement_key": str(settlement.get("settlement_key") or ""),
            "status": str(settlement.get("status") or "queued"),
            "accepted": bool(settlement.get("accepted")),
            "endpoint": endpoint,
            "model": model,
            "relay_url": relay_url,
            "provider": str(receipt.get("provider") or ""),
            "input_tokens": int(receipt.get("input_tokens") or 0),
            "output_tokens": int(receipt.get("output_tokens") or 0),
            "actual_fee_units": int(receipt.get("actual_fee") or 0),
        }
        encoded = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
        with self._management_lock:
            descriptor = os.open(
                self._history_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                handle.write(encoded)

    def prepare_payment_key(self) -> dict[str, str]:
        if self._payment_key_from_env:
            raise ConsumerV8Error("payment-key rotation is disabled while MYCOMESH_V8_PAYMENT_KEY is set")
        with self._management_lock:
            if self._pending_key_path.exists():
                value = self._pending_key_path.read_text(encoding="utf-8").strip()
            else:
                value = generate_payment_key()
                descriptor = os.open(
                    self._pending_key_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(value + "\n")
        return {"payment_key": value, "payment_key_address": payment_key_address(value)}

    def pending_payment_key(self) -> dict[str, str] | None:
        try:
            value = self._pending_key_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return None
        payment_private_key(value)
        return {"payment_key": value, "payment_key_address": payment_key_address(value)}

    def activate_pending_payment_key(self, wallet: str) -> dict[str, str]:
        owner = normalize_address(wallet)
        with self._management_lock:
            pending = self.pending_payment_key()
            if pending is None:
                raise ConsumerV8Error("no pending payment key exists")
            grant = self._grant_for(pending["payment_key_address"])
            if not grant["active"] or normalize_address(grant["owner"]) != owner:
                raise ConsumerV8Error("the pending payment key is not active for this wallet on-chain")
            old_address = self.payment_address
            os.replace(self._pending_key_path, self.config.data_dir / "payment-key")
            os.chmod(self.config.data_dir / "payment-key", 0o600)
            self.payment_key = pending["payment_key"]
            self.payment_address = pending["payment_key_address"]
        return {
            "payment_key": self.payment_key,
            "payment_key_address": self.payment_address,
            "previous_key_address": old_address,
        }

    def dashboard_payload(self, wallet: str | None = None) -> dict[str, Any]:
        all_history = self.history(0)
        history = all_history[:100]
        payload: dict[str, Any] = {
            "ok": True,
            "protocol_version": 8,
            "credentials": {
                "base_url": self.config.base_url,
                "api_key": self.payment_key,
                "export": self.credentials_text(),
            },
            "key": {
                "address": self.payment_address,
                "max_fee_units": self.config.max_fee_units,
                "pending": self.pending_payment_key(),
            },
            "settlement": self._settlement,
            "history": history,
            "usage": {
                "request_count": len(all_history),
                "total_spent_units": sum(int(item.get("actual_fee_units") or 0) for item in all_history),
                "input_tokens": sum(int(item.get("input_tokens") or 0) for item in all_history),
                "output_tokens": sum(int(item.get("output_tokens") or 0) for item in all_history),
            },
        }
        if self._settlement is None:
            payload["chain_error"] = "Settlement V8 network configuration is unavailable"
            return payload
        try:
            grant = self._grant_for(self.payment_address)
            payload["key"]["grant"] = grant
            if grant["owner"] != ZERO_ADDRESS:
                payload["account"] = {
                    "owner": grant["owner"],
                    "available_balance_units": self._rpc_value(
                        lambda rpc: account_balance(
                            rpc,
                            self._settlement["settlement_contract"],
                            grant["owner"],
                        )
                    ),
                }
        except ConsumerV8Error as exc:
            payload["chain_error"] = str(exc)
        if wallet:
            try:
                address = normalize_address(wallet)
                settlement = self._settlement["settlement_contract"]
                stablecoin = self._settlement["stablecoin"]
                token_balance = self._rpc_value(
                    lambda rpc: _uint_contract_call(rpc, stablecoin, "balanceOf(address)", [address])
                )
                allowance = self._rpc_value(
                    lambda rpc: _uint_contract_call(
                        rpc,
                        stablecoin,
                        "allowance(address,address)",
                        [address, settlement],
                    )
                )
                payload["wallet"] = {
                    "address": address,
                    "token_balance_units": token_balance,
                    "allowance_units": allowance,
                }
            except (ChainError, ConsumerV8Error) as exc:
                payload["wallet_error"] = str(exc)
        return payload

    def transaction_plan(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if self._settlement is None:
            raise ConsumerV8Error("Settlement V8 network configuration is unavailable")
        action = str(raw.get("action") or "")
        wallet = normalize_address(str(raw.get("wallet") or ""))
        settlement = self._settlement["settlement_contract"]
        stablecoin = self._settlement["stablecoin"]
        if action == "top_up":
            try:
                amount = usdc_to_units(str(raw.get("amount_usdc") or ""))
            except (BillingError, TypeError, ValueError) as exc:
                raise ConsumerV8Error("enter a valid positive top-up amount") from exc
            if amount <= 0:
                raise ConsumerV8Error("enter a valid positive top-up amount")
            allowance = self._rpc_value(
                lambda rpc: _uint_contract_call(
                    rpc,
                    stablecoin,
                    "allowance(address,address)",
                    [wallet, settlement],
                )
            )
            transactions = []
            if allowance < amount:
                transactions.append(
                    {
                        "label": "Approve stablecoin",
                        "to": stablecoin,
                        "data": _contract_data(
                            "approve(address,uint256)",
                            [settlement, str((1 << 256) - 1)],
                        ),
                    }
                )
            transactions.append(
                {
                    "label": "Deposit prepaid balance",
                    "to": settlement,
                    "data": _contract_data("deposit(uint256)", [str(amount)]),
                }
            )
            return {"action": action, "amount_units": amount, "transactions": transactions}
        if action == "register_key":
            pending = self.pending_payment_key()
            key_address = pending["payment_key_address"] if pending else self.payment_address
            return {
                "action": action,
                "key_address": key_address,
                "transactions": [
                    {
                        "label": "Register payment key",
                        "to": settlement,
                        "data": _contract_data(
                            "registerKey(address,uint256,uint64)",
                            [key_address, str(self.config.max_fee_units), "0"],
                        ),
                    }
                ],
            }
        if action == "revoke_key":
            key_address = normalize_address(str(raw.get("key_address") or ""))
            return {
                "action": action,
                "key_address": key_address,
                "transactions": [
                    {
                        "label": "Revoke previous payment key",
                        "to": settlement,
                        "data": _contract_data("revokeKey(address)", [key_address]),
                    }
                ],
            }
        raise ConsumerV8Error("unsupported transaction action")

    def health_payload(self) -> dict[str, Any]:
        return {
            "ok": True,
            "protocol": "mycomesh-consumer/v8",
            "browser_app_ready": True,
            "gateway_dependency": False,
            "routing_mode": "relay-scheduled-payment-key-v8",
            "relay_urls": list(self.config.relay_urls),
            "payment_key_address": self.payment_address,
            "payment_key_persisted": True,
            "responses_transports": ["http", "sse", "websocket"],
        }

    async def relay_health(self, relay_url: str, *, refresh: bool = False) -> dict[str, Any]:
        cached = self._health_cache.get(relay_url)
        if cached and not refresh and time.monotonic() - cached[0] < 5:
            return cached[1]
        try:
            async with httpx.AsyncClient(timeout=self.config.health_timeout_seconds, follow_redirects=False) as client:
                response = await client.get(relay_url.rstrip("/") + "/health")
                response.raise_for_status()
                payload = response.json()
                if isinstance(payload, dict) and not isinstance(payload.get("v8"), dict):
                    response = await client.get(relay_url.rstrip("/") + "/relay/health")
                    response.raise_for_status()
                    payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConsumerV8Error(f"Relay health failed for {relay_url}: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise ConsumerV8Error(f"Relay health is invalid for {relay_url}")
        v8 = payload.get("v8")
        if not isinstance(v8, dict) or v8.get("enabled") is not True or int(v8.get("providers") or 0) <= 0:
            raise ConsumerV8Error(f"Relay has no live Settlement V8 Provider: {relay_url}")
        self._health_cache[relay_url] = (time.monotonic(), payload)
        return payload

    async def choose_relay(self, *, exclude: set[str] | None = None) -> tuple[str, dict[str, Any]]:
        excluded = exclude or set()
        errors: list[str] = []
        for relay_url in self.config.relay_urls:
            if relay_url in excluded:
                continue
            try:
                return relay_url, await self.relay_health(relay_url)
            except ConsumerV8Error as exc:
                errors.append(str(exc))
        raise ConsumerV8Error("no healthy Settlement V8 Relay is available: " + "; ".join(errors))


def _contract_data(signature: str, args: list[str]) -> str:
    encoded = keccak256(signature.encode("ascii"))[:4] + b"".join(abi_encode_arg(value) for value in args)
    return "0x" + encoded.hex()


def _uint_contract_call(rpc_url: str, contract: str, signature: str, args: list[str]) -> int:
    value = call_contract(rpc_url, contract, signature, args)
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ChainError("contract returned an invalid integer")
    return int(value, 16)


def _management_authorized(state: ConsumerV8State, authorization: str | None) -> bool:
    prefix = "Bearer "
    return bool(
        authorization
        and authorization.startswith(prefix)
        and secrets.compare_digest(authorization[len(prefix) :], state.payment_key)
    )


def _consumer_html_page() -> str:
    return r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Consumer | MycoMesh</title>
<style>
:root{--ink:#17211d;--muted:#68736e;--line:#d9e0dc;--soft:#f3f6f4;--green:#177b57;--green-dark:#0f6044;--red:#b43b35;--amber:#9a6413;--white:#fff}*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;background:#eef2ef;color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}button,input{font:inherit;letter-spacing:0}button{cursor:pointer}.shell{min-height:100vh}.topbar{position:sticky;z-index:5;top:0;display:flex;min-height:58px;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);background:rgba(255,255,255,.96);padding:0 28px}.brand{display:flex;align-items:center;gap:10px;font-weight:750}.mark{display:grid;width:28px;height:28px;place-items:center;border-radius:6px;background:var(--ink);color:white;font-size:13px}.context{display:flex;align-items:center;gap:10px;color:var(--muted)}.status{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;background:var(--white);padding:4px 9px;font-size:12px}.status:before{width:7px;height:7px;border-radius:50%;background:#9aa39f;content:""}.status.ok:before{background:var(--green)}.status.warn:before{background:var(--amber)}.workspace{width:min(1120px,calc(100% - 40px));margin:0 auto;padding:34px 0 60px}.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:26px}.eyebrow{margin:0 0 5px;color:var(--green);font-size:12px;font-weight:750;text-transform:uppercase}.page-head h1{margin:0;font-size:28px;line-height:1.2}.page-head p:last-child{margin:7px 0 0;color:var(--muted)}.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:25px}.tabs a{padding:10px 13px;border-bottom:2px solid transparent;color:var(--muted);text-decoration:none}.tabs a:first-child{border-color:var(--green);color:var(--ink);font-weight:700}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;border:1px solid var(--line);border-radius:6px;overflow:hidden;background:var(--line);margin-bottom:24px}.metric{background:var(--white);padding:18px 20px}.metric span,.field-label{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;margin-top:5px;font-size:23px}.band{border-top:1px solid var(--line);padding:26px 0}.band:first-of-type{border-top:0}.section-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:17px}.section-head h2{margin:0;font-size:17px}.section-head p{margin:3px 0 0;color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(280px,.75fr);gap:18px}.panel{border:1px solid var(--line);border-radius:6px;background:var(--white);padding:18px}.field+.field{margin-top:14px}.field-row{display:flex;align-items:stretch;gap:8px;margin-top:6px}.value{min-width:0;flex:1;border:1px solid var(--line);border-radius:5px;background:var(--soft);padding:10px 11px;color:var(--ink);font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.value.secret{filter:none}.exports{min-height:78px;white-space:pre-wrap}.button{display:inline-flex;min-height:38px;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:5px;background:var(--white);padding:0 13px;color:var(--ink);font-weight:650}.button:hover{border-color:#9ba8a1;background:#f8faf9}.button.primary{border-color:var(--green);background:var(--green);color:white}.button.primary:hover{background:var(--green-dark)}.button.danger{border-color:#e5b7b4;color:var(--red)}.button:disabled{cursor:not-allowed;opacity:.5}.button-row{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.key-meta{display:grid;gap:0;margin:0}.key-meta div{display:grid;grid-template-columns:112px minmax(0,1fr);gap:12px;border-bottom:1px solid var(--line);padding:10px 0}.key-meta div:last-child{border-bottom:0}.key-meta dt{color:var(--muted)}.key-meta dd{overflow:hidden;margin:0;text-align:right;text-overflow:ellipsis;white-space:nowrap}.notice{border-left:3px solid var(--amber);background:#fff9ed;padding:10px 12px;color:#76511c;font-size:12px}.notice.error{border-color:var(--red);background:#fff4f3;color:#8c302c}.topup{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;margin-top:12px}.input{width:100%;min-height:40px;border:1px solid var(--line);border-radius:5px;background:white;padding:8px 10px;color:var(--ink)}.input:focus{border-color:var(--green);outline:2px solid rgba(23,123,87,.12)}.wallet-line{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.wallet-line code{overflow:hidden;text-overflow:ellipsis}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:6px;background:white}table{width:100%;border-collapse:collapse;min-width:760px}th,td{padding:11px 13px;border-bottom:1px solid var(--line);text-align:left;font-size:12px}th{background:var(--soft);color:var(--muted);font-weight:650}tbody tr:last-child td{border-bottom:0}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.empty{padding:35px;text-align:center;color:var(--muted)}#toast{position:fixed;right:20px;bottom:20px;z-index:10;max-width:min(420px,calc(100vw - 40px));border:1px solid var(--line);border-radius:6px;background:var(--ink);padding:11px 14px;color:white;box-shadow:0 8px 30px rgba(0,0,0,.16);opacity:0;transform:translateY(8px);pointer-events:none;transition:.18s}#toast.show{opacity:1;transform:none}.loading{animation:pulse 1.1s infinite}@keyframes pulse{50%{opacity:.55}}@media(max-width:760px){.topbar{padding:0 16px}.context>span:first-child{display:none}.workspace{width:min(100% - 28px,1120px);padding-top:24px}.page-head{display:block}.page-head>.button{margin-top:15px}.metrics,.grid{grid-template-columns:1fr}.field-row,.topup{display:grid}.metrics{gap:1px}.key-meta div{grid-template-columns:1fr}.key-meta dd{text-align:left}.button{min-height:42px}.tabs{overflow:auto}}
</style>
</head>
<body>
<div class="shell">
  <header class="topbar">
    <div class="brand"><span class="mark">M</span><span>MycoMesh</span></div>
    <div class="context"><span>Consumer V8</span><span class="status" id="network-status">正在连接</span></div>
  </header>
  <main class="workspace">
    <div class="page-head">
      <div><p class="eyebrow">本地 Consumer</p><h1>账户与访问</h1><p id="account-owner">正在读取链上账户</p></div>
      <button class="button" id="wallet-button" type="button">连接钱包</button>
    </div>
    <nav class="tabs" aria-label="Consumer sections"><a href="#account">账户</a><a href="#access">Key</a><a href="#funds">充值</a><a href="#activity">记录</a></nav>
    <section class="metrics" id="account">
      <div class="metric"><span>预付余额</span><strong id="balance">--</strong></div>
      <div class="metric"><span>本地累计消费</span><strong id="spent">--</strong></div>
      <div class="metric"><span>已记录请求</span><strong id="requests">--</strong></div>
    </section>
    <section class="band" id="access">
      <div class="section-head"><div><h2>访问凭据</h2><p>OpenAI 兼容本地入口</p></div><span class="status" id="key-status">读取中</span></div>
      <div class="grid">
        <div class="panel">
          <div class="field"><span class="field-label">API URL</span><div class="field-row"><div class="value" id="base-url">--</div><button class="button copy" data-copy="base-url" type="button">复制</button></div></div>
          <div class="field"><span class="field-label">API Key</span><div class="field-row"><div class="value secret" id="api-key">--</div><button class="button copy" data-copy="api-key" type="button">复制</button></div></div>
          <div class="field"><span class="field-label">Export</span><div class="field-row"><div class="value exports" id="exports">--</div><button class="button copy" data-copy="exports" type="button">复制</button></div></div>
        </div>
        <div class="panel">
          <dl class="key-meta"><div><dt>Key 地址</dt><dd class="mono" id="key-address">--</dd></div><div><dt>所属钱包</dt><dd class="mono" id="key-owner">--</dd></div><div><dt>单次上限</dt><dd id="key-limit">--</dd></div><div><dt>有效期</dt><dd id="key-validity">--</dd></div></dl>
          <div id="key-notice" class="notice" hidden></div>
          <div class="button-row"><button class="button primary" id="activate-key" type="button">激活 Key</button><button class="button danger" id="rotate-key" type="button">更换 Key</button></div>
        </div>
      </div>
    </section>
    <section class="band" id="funds">
      <div class="section-head"><div><h2>充值预付</h2><p id="wallet-balance">连接钱包后显示代币余额</p></div></div>
      <div class="panel">
        <div class="wallet-line"><span>充值账户</span><code id="wallet-address">未连接</code></div>
        <label class="field-label" for="topup-amount">充值金额（tUSDC）</label>
        <div class="topup"><input class="input" id="topup-amount" inputmode="decimal" placeholder="10.00"><button class="button primary" id="topup-button" type="button">充值</button></div>
        <p class="notice" id="funds-notice" hidden></p>
      </div>
    </section>
    <section class="band" id="activity">
      <div class="section-head"><div><h2>消费记录</h2><p>本机收到的 V8 签名收据</p></div><button class="button" id="refresh" type="button">刷新</button></div>
      <div class="table-wrap"><table><thead><tr><th>时间</th><th>模型</th><th>Token</th><th>费用</th><th>Provider</th><th>状态</th></tr></thead><tbody id="history"></tbody></table><div class="empty" id="history-empty">暂无消费记录</div></div>
    </section>
  </main>
</div>
<div id="toast" role="status"></div>
<script>
const $=(selector)=>document.querySelector(selector);let state=null,wallet=null,busy=false;
function units(value,decimals=6){try{const raw=BigInt(value||0),base=10n**BigInt(decimals),whole=raw/base,fraction=(raw%base).toString().padStart(decimals,'0').replace(/0+$/,'');return whole+(fraction?'.'+fraction:'')}catch{return '0'}}
function short(value){const text=String(value||'');return text.length>18?text.slice(0,8)+'...'+text.slice(-6):text||'--'}
function escapeHtml(value){return String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]))}
function toast(message,error=false){const node=$('#toast');node.textContent=message;node.style.background=error?'#8c302c':'#17211d';node.classList.add('show');clearTimeout(toast.timer);toast.timer=setTimeout(()=>node.classList.remove('show'),4200)}
function setBusy(value){busy=value;for(const node of document.querySelectorAll('button'))node.disabled=value}
async function api(path,options={}){const response=await fetch(path,{cache:'no-store',...options});const data=await response.json();if(!response.ok)throw new Error(data.error||'请求失败');return data}
async function load(){const query=wallet?'?wallet='+encodeURIComponent(wallet):'';state=await api('/v1/mycomesh/local/dashboard'+query);render()}
function render(){const decimals=state.settlement?.stablecoin_decimals||6,grant=state.key.grant||{},account=state.account||{};$('#base-url').textContent=state.credentials.base_url;$('#api-key').textContent=state.credentials.api_key;$('#exports').textContent=state.credentials.export;$('#key-address').textContent=state.key.address;$('#key-owner').textContent=grant.owner&&Number(BigInt(grant.owner))!==0?short(grant.owner):'未绑定';$('#key-limit').textContent=grant.max_per_request?units(grant.max_per_request,decimals)+' '+(state.settlement?.stablecoin_symbol||'USDC'):'--';$('#key-validity').textContent=grant.valid_until?new Date(grant.valid_until*1000).toLocaleString():'长期有效';$('#balance').textContent=units(account.available_balance_units,decimals)+' '+(state.settlement?.stablecoin_symbol||'USDC');$('#spent').textContent=units(state.usage.total_spent_units,decimals)+' '+(state.settlement?.stablecoin_symbol||'USDC');$('#requests').textContent=String(state.usage.request_count);$('#account-owner').textContent=account.owner?'账户 '+short(account.owner):'Key 尚未绑定钱包';const active=grant.active===true;$('#key-status').className='status '+(active?'ok':'warn');$('#key-status').textContent=active?'链上有效':'等待激活';$('#activate-key').hidden=active;$('#rotate-key').hidden=!active;const networkError=state.chain_error;$('#network-status').className='status '+(networkError?'warn':'ok');$('#network-status').textContent=networkError?'链上读取失败':(state.settlement?.network_name||'V8');const notice=$('#key-notice');notice.hidden=!networkError;notice.textContent=networkError||'';if(state.wallet){$('#wallet-balance').textContent='钱包余额 '+units(state.wallet.token_balance_units,decimals)+' '+(state.settlement?.stablecoin_symbol||'USDC')}renderHistory()}
function renderHistory(){const body=$('#history'),items=state.history||[];body.innerHTML='';$('#history-empty').hidden=items.length>0;for(const item of items){const row=document.createElement('tr');row.innerHTML='<td>'+escapeHtml(new Date(item.timestamp*1000).toLocaleString())+'</td><td>'+escapeHtml(item.model)+'</td><td>'+escapeHtml((item.input_tokens||0)+' / '+(item.output_tokens||0))+'</td><td>'+escapeHtml(units(item.actual_fee_units,state.settlement?.stablecoin_decimals||6))+'</td><td class="mono">'+escapeHtml(short(item.provider))+'</td><td>'+escapeHtml(item.accepted?'已接收':item.status)+'</td>';body.appendChild(row)}}
async function connectWallet(){if(!window.ethereum)throw new Error('未检测到浏览器钱包');const accounts=await window.ethereum.request({method:'eth_requestAccounts'});wallet=accounts[0];if(!wallet)throw new Error('钱包未连接');const chainId='0x'+Number(state.settlement.chain_id).toString(16);try{await window.ethereum.request({method:'wallet_switchEthereumChain',params:[{chainId}]})}catch(error){throw new Error('请在钱包中切换到 '+state.settlement.network_name)}$('#wallet-address').textContent=wallet;$('#wallet-button').textContent=short(wallet);await load();return wallet}
async function requireWallet(){return wallet||await connectWallet()}
async function waitReceipt(hash){for(let count=0;count<120;count++){const receipt=await window.ethereum.request({method:'eth_getTransactionReceipt',params:[hash]});if(receipt){if(receipt.status!=='0x1')throw new Error('链上交易失败');return receipt}await new Promise(resolve=>setTimeout(resolve,1500))}throw new Error('等待链上确认超时')}
async function sendPlan(plan){for(const transaction of plan.transactions){toast(transaction.label);const hash=await window.ethereum.request({method:'eth_sendTransaction',params:[{from:wallet,to:transaction.to,data:transaction.data}]});await waitReceipt(hash)}return true}
async function run(task){if(busy)return;setBusy(true);try{await task()}catch(error){toast(error?.message||String(error),true)}finally{setBusy(false)}}
document.addEventListener('click',event=>{const button=event.target.closest('.copy');if(!button)return;const text=$('#'+button.dataset.copy).textContent;navigator.clipboard.writeText(text).then(()=>toast('已复制'))});
$('#wallet-button').addEventListener('click',()=>run(connectWallet));
$('#refresh').addEventListener('click',()=>run(load));
$('#activate-key').addEventListener('click',()=>run(async()=>{await requireWallet();const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'register_key',wallet})});await sendPlan(plan);toast('Key 已激活');await load()}));
$('#topup-button').addEventListener('click',()=>run(async()=>{await requireWallet();const amount=$('#topup-amount').value.trim();const plan=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'top_up',wallet,amount_usdc:amount})});await sendPlan(plan);$('#topup-amount').value='';toast('充值已确认');await load()}));
$('#rotate-key').addEventListener('click',()=>run(async()=>{await requireWallet();const oldKey=state.credentials.api_key,oldAddress=state.key.address;await api('/v1/mycomesh/local/key/prepare',{method:'POST',headers:{authorization:'Bearer '+oldKey}});const register=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'register_key',wallet})});await sendPlan(register);let activated=null;for(let count=0;count<8&&!activated;count++){try{activated=await api('/v1/mycomesh/local/key/activate',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+oldKey},body:JSON.stringify({wallet})})}catch(error){if(count===7)throw error;await new Promise(resolve=>setTimeout(resolve,1800))}}const revoke=await api('/v1/mycomesh/local/transactions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'revoke_key',wallet,key_address:oldAddress})});await sendPlan(revoke);toast('Key 已更换，旧 Key 已撤销');await load()}));
window.ethereum?.on?.('accountsChanged',accounts=>{wallet=accounts[0]||null;$('#wallet-address').textContent=wallet||'未连接';load().catch(error=>toast(error.message,true))});
load().catch(error=>toast(error.message,true));
</script>
</body>
</html>"""


def create_app(state: ConsumerV8State | None = None) -> FastAPI:
    local = state or ConsumerV8State()
    app = FastAPI(title="MycoMesh Consumer V8", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.consumer_v8 = local
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.get("/", response_class=HTMLResponse)
    async def browser_credentials() -> HTMLResponse:
        return HTMLResponse(
            _consumer_html_page(),
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return local.health_payload()

    @app.get("/ready")
    async def ready() -> dict[str, Any]:
        try:
            relay, payload = await local.choose_relay()
        except ConsumerV8Error as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)
        return {"ok": True, "relay": relay, "model": payload["v8"].get("model")}

    @app.get("/credentials")
    async def credentials() -> str:
        return local.credentials_text() + "\n"

    @app.get("/codex-env")
    async def codex_env() -> str:
        return local.credentials_text() + "\n"

    @app.get("/v1/mycomesh/local/dashboard")
    async def dashboard(wallet: str | None = None) -> dict[str, Any]:
        return await asyncio.to_thread(local.dashboard_payload, wallet)

    @app.post("/v1/mycomesh/local/transactions")
    async def transactions(request: Request) -> Any:
        try:
            raw = await request.json()
            if not isinstance(raw, Mapping):
                raise ConsumerV8Error("transaction request must be an object")
            return await asyncio.to_thread(local.transaction_plan, raw)
        except (ConsumerV8Error, ChainError, ValueError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    @app.post("/v1/mycomesh/local/key/prepare")
    async def prepare_key(authorization: str | None = Header(default=None)) -> Any:
        if not _management_authorized(local, authorization):
            return JSONResponse({"ok": False, "error": "invalid local payment key"}, status_code=401)
        try:
            return await asyncio.to_thread(local.prepare_payment_key)
        except (ConsumerV8Error, ChainError, OSError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    @app.post("/v1/mycomesh/local/key/activate")
    async def activate_key(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> Any:
        if not _management_authorized(local, authorization):
            return JSONResponse({"ok": False, "error": "invalid local payment key"}, status_code=401)
        try:
            raw = await request.json()
            if not isinstance(raw, Mapping):
                raise ConsumerV8Error("key activation request must be an object")
            return await asyncio.to_thread(
                local.activate_pending_payment_key,
                str(raw.get("wallet") or ""),
            )
        except (ConsumerV8Error, ChainError, OSError, ValueError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    @app.get("/models")
    @app.get("/v1/models")
    @app.get("/backend-api/codex/models")
    async def models() -> dict[str, Any]:
        relay, payload = await local.choose_relay()
        model = str(payload["v8"].get("model") or "mycomesh-codex-standard-v1")
        return {"object": "list", "data": [{"id": model, "object": "model", "owned_by": "mycomesh", "relay": relay}]}

    @app.post("/responses")
    @app.post("/v1/responses")
    @app.post("/v1/v1/responses")
    @app.post("/backend-api/codex/responses")
    async def responses(request: Request, authorization: str | None = Header(default=None)) -> Any:
        return await _proxy_inference(local, "/v1/responses", request, authorization)

    @app.post("/responses/compact")
    @app.post("/v1/responses/compact")
    @app.post("/v1/v1/responses/compact")
    @app.post("/backend-api/codex/responses/compact")
    async def compact(request: Request, authorization: str | None = Header(default=None)) -> Any:
        return await _proxy_inference(local, "/v1/responses/compact", request, authorization)

    @app.post("/chat/completions")
    @app.post("/v1/chat/completions")
    async def chat(request: Request, authorization: str | None = Header(default=None)) -> Any:
        return await _proxy_inference(local, "/v1/chat/completions", request, authorization)

    @app.websocket("/responses")
    @app.websocket("/v1/responses")
    @app.websocket("/v1/v1/responses")
    @app.websocket("/backend-api/codex/responses")
    async def responses_websocket(websocket: WebSocket) -> None:
        if websocket.headers.get("authorization") != f"Bearer {local.payment_key}":
            await websocket.close(code=1008, reason="invalid MycoMesh payment key")
            return
        await websocket.accept()
        try:
            while True:
                try:
                    client_event = await websocket.receive_json()
                except (ValueError, json.JSONDecodeError):
                    await websocket.send_json(_websocket_error("request frame must be JSON"))
                    continue
                if not isinstance(client_event, dict):
                    await websocket.send_json(_websocket_error("request frame must be an object"))
                    continue
                if client_event.get("type") != "response.create":
                    await websocket.send_json(
                        _websocket_error(
                            "unsupported client event; expected response.create",
                            param="type",
                        )
                    )
                    continue
                body = {
                    key: value
                    for key, value in client_event.items()
                    if key not in {"type", "generate"}
                }
                compact_request = _has_compaction_trigger(body.get("input"))
                payload, status_code, _headers = await _relay_inference_result(
                    local,
                    "/v1/responses",
                    body,
                )
                if status_code >= 400:
                    await websocket.send_json(_websocket_error_from_payload(payload))
                    continue
                for event in response_stream_events(payload, compact=compact_request):
                    await websocket.send_json(event)
        except WebSocketDisconnect:
            return

    return app


async def _proxy_inference(
    state: ConsumerV8State,
    path: str,
    request: Request,
    authorization: str | None,
) -> Any:
    if authorization != f"Bearer {state.payment_key}":
        return JSONResponse(openai_error("invalid MycoMesh payment key", error_type="invalid_api_key"), status_code=401)
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError) as exc:
        return JSONResponse(openai_error("request body must be JSON", error_type="invalid_request_error"), status_code=400)
    if not isinstance(body, dict):
        return JSONResponse(openai_error("request body must be an object", error_type="invalid_request_error"), status_code=400)
    if path.endswith("/responses/compact") and not _has_compaction_trigger(body.get("input")):
        input_value = body.get("input")
        items = list(input_value) if isinstance(input_value, list) else []
        if input_value not in (None, "") and not isinstance(input_value, list):
            items.append(
                {"type": "message", "role": "user", "content": input_value}
                if isinstance(input_value, str)
                else input_value
            )
        items.append({"type": "compaction_trigger"})
        body["input"] = items
    payload, status_code, headers = await _relay_inference_result(state, path, body)
    if status_code >= 400:
        return JSONResponse(payload, status_code=status_code, headers=headers)
    if body.get("stream") is True:
        response = _stream_response(path, payload, body)
        for name, value in headers.items():
            response.headers[name] = value
        return response
    return JSONResponse(payload, headers=headers)


async def _relay_inference_result(
    state: ConsumerV8State,
    path: str,
    body: Mapping[str, Any],
) -> tuple[dict[str, Any], int, dict[str, str]]:
    # Keep one settlement id across Relay failover. The authorization remains
    # Relay-specific, while the on-chain settlement key prevents double charge.
    request_id = "0x" + secrets.token_hex(32)
    used: set[str] = set()
    last_error: str | None = None
    last_response: tuple[dict[str, Any], int, dict[str, str]] | None = None
    for _ in state.config.relay_urls:
        try:
            relay_url, health = await state.choose_relay(exclude=used)
        except ConsumerV8Error as exc:
            last_error = str(exc)
            break
        used.add(relay_url)
        try:
            request_body = dict(body)
            model = str(health["v8"].get("model") or request_body.get("model") or "")
            request_body["model"] = model
            if not str(request_body.get("prompt_cache_key") or "").strip():
                cache_key = derive_prompt_cache_key(
                    request_body,
                    endpoint="chat" if path.endswith("/chat/completions") else "responses",
                )
                if cache_key:
                    request_body["prompt_cache_key"] = cache_key
            payload = _build_relay_payment(state, path, request_body, health, request_id=request_id)
            relay_path = relay_url.rstrip("/") + path
            encoded = base64.urlsafe_b64encode(
                json.dumps(payload["payment"], sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            async with httpx.AsyncClient(timeout=state.config.timeout_seconds, follow_redirects=False) as client:
                response = await client.post(
                    relay_path,
                    json=request_body,
                    headers={"PAYMENT-SIGNATURE": encoded, "content-type": "application/json"},
                )
            response_headers = {}
            retry_after = response.headers.get("retry-after")
            if retry_after:
                response_headers["Retry-After"] = retry_after
            if response.status_code in RETRYABLE_RELAY_STATUS:
                last_error = response.text[:500]
                last_response = (_decode_error(response), response.status_code, response_headers)
                continue
            if response.status_code >= 400:
                return _decode_error(response), response.status_code, response_headers
            result = response.json()
            if not isinstance(result, dict):
                raise ConsumerV8Error("Relay returned a non-object response")
            payment_response = response.headers.get("PAYMENT-RESPONSE")
            if payment_response:
                settlement = _decode_payment_response(payment_response)
                state.record_receipt(
                    relay_url=relay_url,
                    endpoint=path,
                    model=model,
                    settlement=settlement,
                )
                response_headers["PAYMENT-RESPONSE"] = payment_response
            return result, 200, response_headers
        except (httpx.HTTPError, ValueError, ConsumerV8Error) as exc:
            last_error = str(exc)
            continue
    if last_response is not None:
        return last_response
    return (
        openai_error(last_error or "no Relay accepted the request", error_type="relay_unavailable"),
        503,
        {"Retry-After": "2"},
    )


def _build_relay_payment(
    state: ConsumerV8State,
    path: str,
    body: Mapping[str, Any],
    health: Mapping[str, Any],
    *,
    request_id: str | None = None,
) -> dict[str, Any]:
    endpoint = "chat" if path.endswith("/chat/completions") else "responses"
    v8 = health.get("v8")
    if not isinstance(v8, Mapping):
        raise ConsumerV8Error("Relay health has no V8 payment requirements")
    request_body = dict(body)
    model = str(v8.get("model") or request_body.get("model") or "")
    max_output = request_body.get("max_output_tokens")
    if max_output is None:
        max_output = request_body.get("max_tokens")
    max_output_tokens = int(max_output or int(v8.get("maxOutputTokens") or 2000))
    options = {
        field: request_body[field]
        for field in RESPONSES_REQUEST_OPTION_FIELDS | RESPONSES_LOCAL_OPTION_FIELDS
        if field in request_body
    }
    normalized_options = normalize_inference_request_options(endpoint, options)
    request_id = request_id or ("0x" + secrets.token_hex(32))
    request_hash = "0x" + inference_request_hash(
        endpoint=endpoint,
        model=model,
        input_value=request_body.get("input"),
        messages=request_body.get("messages"),
        max_output_tokens=max_output_tokens,
        options=normalized_options,
    )
    now = int(time.time())
    payment = build_authorization(
        payment_key=state.payment_key,
        chain_id=int(v8["chain_id"]),
        settlement_contract=str(v8["settlement_contract"]),
        request_id=request_id,
        request_hash=request_hash,
        relay=str(v8["relay_payment_address"]),
        relay_signer=str(v8["relay_signer_address"]),
        channel_hash=str(v8["channel_hash"]),
        pricing_version=int(v8["pricing_version"]),
        pricing_hash=str(v8["pricing_hash"]),
        max_fee=state.config.max_fee_units,
        issued_at=now - AUTHORIZATION_CLOCK_SKEW_SECONDS,
        deadline=now + 900,
    )
    return {"payment": payment, "request_id": request_id}


def _decode_error(response: httpx.Response) -> dict[str, Any]:
    try:
        value = response.json()
    except ValueError:
        value = None
    if isinstance(value, dict):
        return normalize_openai_error(value, fallback_type="relay_error")
    return openai_error(response.text[:1000], error_type="relay_error")


def _decode_payment_response(value: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ConsumerV8Error("Relay returned an invalid PAYMENT-RESPONSE") from exc
    if not isinstance(payload, dict):
        raise ConsumerV8Error("Relay returned an invalid PAYMENT-RESPONSE")
    signed = payload.get("signed_receipt")
    if not isinstance(signed, Mapping):
        raise ConsumerV8Error("Relay PAYMENT-RESPONSE is missing its signed receipt")
    try:
        verify_signed_receipt(signed)
    except ChainError as exc:
        raise ConsumerV8Error(f"Relay returned an invalid signed receipt: {exc}") from exc
    return payload


def _websocket_error(
    message: str,
    *,
    code: str = "invalid_request_error",
    param: str | None = None,
) -> dict[str, Any]:
    return {
        "type": "error",
        "sequence_number": 0,
        "code": code,
        "message": message,
        "param": param,
    }


def _websocket_error_from_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_openai_error(payload, fallback_type="relay_error")["error"]
    return _websocket_error(
        str(normalized["message"]),
        code=str(normalized.get("code") or normalized.get("type") or "relay_error"),
        param=(str(normalized["param"]) if normalized.get("param") is not None else None),
    )


def _has_compaction_trigger(value: Any) -> bool:
    return isinstance(value, list) and any(
        isinstance(item, Mapping) and item.get("type") == "compaction_trigger"
        for item in value
    )


def _stream_response(
    path: str,
    payload: dict[str, Any],
    request_body: Mapping[str, Any] | None = None,
) -> StreamingResponse:
    if path.endswith("/chat/completions"):
        stream_options = (request_body or {}).get("stream_options")
        include_usage = isinstance(stream_options, Mapping) and stream_options.get("include_usage") is True
        return StreamingResponse(
            chat_completion_sse(payload, include_usage=include_usage),
            media_type="text/event-stream",
            headers={"x-mycomesh-streaming-mode": "buffered"},
        )
    return StreamingResponse(
        responses_sse(
            payload,
            compact=(
                path.endswith("/responses/compact")
                or _has_compaction_trigger((request_body or {}).get("input"))
            ),
        ),
        media_type="text/event-stream",
        headers={"x-mycomesh-streaming-mode": "buffered"},
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the MycoMesh V8 payment-key Consumer edge.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8110)
    subparsers.add_parser("credentials")
    subparsers.add_parser("codex-env")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state = ConsumerV8State()
    if args.command == "credentials":
        print(state.credentials_text())
        return 0
    if args.command == "codex-env":
        print(state.credentials_text())
        return 0
    uvicorn.run(create_app(state), host=args.host, port=args.port, access_log=False, server_header=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
