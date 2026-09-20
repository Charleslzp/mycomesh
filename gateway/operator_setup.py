"""Loopback-only onboarding wizard for Provider and Relay operators.

The wizard collects public settings only. Provider signing identities are
created and persisted by the protected runtime; they are never shown in the
browser, copied into a URL, or requested from the operator.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import shlex
import stat
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .billing import BillingError, normalize_payment_address, usdc_to_units
from .chain import ChainError, encode_contract_call, keccak256, recover_evm_address, rpc_int, sign_evm_digest
from .provider_bootstrap import ProviderEvmIdentity, load_provider_network_config
from .chain_v8 import provider_signer_authorized
from .provider_authorization_state import ProviderAuthorizationState
from .provider_identity import (
    ProviderIdentityImportError,
    provider_evm_identity_from_private_key,
    provider_identity_fingerprint,
    validate_provider_evm_identity,
    write_provider_evm_identity,
)


SCHEMA = "mycomesh.operator.v1"
MAX_CONCURRENCY = 1024
MIN_PERIOD_SECONDS = 60
MAX_PERIOD_SECONDS = 366 * 24 * 60 * 60
MAX_USAGE_UNITS = 10**30
_PRIVATE_FIELD_NAMES = {
    "private_key",
    "privatekey",
    "generated_private_key",
    "seed",
    "seed_phrase",
    "mnemonic",
    "secret",
    "access_token",
    "refresh_token",
    "api_key",
}
_PROVIDER_WALLET_SOURCES = {"existing", "generated", "imported"}
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class OperatorConfigError(ValueError):
    """Raised when an onboarding configuration is invalid."""


def _reject_private_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).strip().lower() in _PRIVATE_FIELD_NAMES:
                raise OperatorConfigError(
                    "private keys and credentials are not accepted by this wizard"
                )
            _reject_private_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_private_fields(child)


def _parse_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise OperatorConfigError(f"{name} must be an integer")
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise OperatorConfigError(f"{name} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise OperatorConfigError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def normalize_operator_config(
    raw: dict[str, Any], *, role: str, configured_at: int | None = None
) -> dict[str, Any]:
    if role not in {"provider", "relay"}:
        raise OperatorConfigError("role must be provider or relay")
    if not isinstance(raw, dict):
        raise OperatorConfigError("configuration must be a JSON object")
    _reject_private_fields(raw)
    wallet_source = str(raw.get("wallet_source") or ("existing" if role == "provider" else "")).strip().lower()
    if role == "provider" and wallet_source not in _PROVIDER_WALLET_SOURCES:
        raise OperatorConfigError(
            "wallet_source must be existing, generated, or imported for Provider"
        )
    if role != "provider" and wallet_source:
        raise OperatorConfigError("wallet_source is only supported for Provider")

    address_value = raw.get("wallet_address", raw.get("payout_address", raw.get("payment_address")))
    try:
        payout_address = normalize_payment_address(address_value)
    except BillingError as exc:
        raise OperatorConfigError(f"payout_address is invalid: {exc}") from exc
    if payout_address and int(payout_address[2:], 16) == 0:
        raise OperatorConfigError("payout_address must be a non-zero EVM address")
    max_concurrency = _parse_int(
        raw.get("max_concurrency", 1),
        name="max_concurrency",
        minimum=1,
        maximum=MAX_CONCURRENCY,
    )
    period_seconds = _parse_int(
        raw.get("usage_period_seconds", 2_592_000),
        name="usage_period_seconds",
        minimum=MIN_PERIOD_SECONDS,
        maximum=MAX_PERIOD_SECONDS,
    )
    usage_value = raw.get("usage_limit_usdc", raw.get("usage_limit"))
    usage_limit_units = 0
    if usage_value is not None and str(usage_value).strip():
        try:
            usage_limit_units = usdc_to_units(str(usage_value).strip())
        except (BillingError, TypeError, ValueError) as exc:
            raise OperatorConfigError(
                "usage_limit_usdc must be a non-negative amount with at most 6 decimals"
            ) from exc
        if usage_limit_units > MAX_USAGE_UNITS:
            raise OperatorConfigError("usage_limit_usdc is too large")
    config = {
        "schema": SCHEMA,
        "role": role,
        "payout_address": payout_address,
        "max_concurrency": max_concurrency,
        "usage_limit_units": usage_limit_units,
        "usage_limit_usdc": f"{usage_limit_units / 1_000_000:.6f}",
        "usage_period_seconds": period_seconds,
        "configured_at": int(configured_at or time.time()),
    }
    if role == "provider":
        raw_version = raw.get("settlement_version")
        if raw_version is not None and str(raw_version).strip():
            config["settlement_version"] = _parse_int(
                raw_version,
                name="settlement_version",
                minimum=2,
                maximum=10,
            )
        config["wallet_source"] = wallet_source
        signer_address = raw.get("provider_signer_address")
        if signer_address:
            try:
                config["provider_signer_address"] = normalize_payment_address(signer_address)
            except BillingError as exc:
                raise OperatorConfigError(f"provider_signer_address is invalid: {exc}") from exc
        fingerprint = str(raw.get("wallet_fingerprint") or "").strip()
        if fingerprint and len(fingerprint) > 32:
            raise OperatorConfigError("wallet_fingerprint is too long")
        if fingerprint:
            config["wallet_fingerprint"] = fingerprint
        backup_confirmed_at = raw.get("backup_confirmed_at")
        if backup_confirmed_at is not None:
            try:
                config["backup_confirmed_at"] = int(backup_confirmed_at)
            except (TypeError, ValueError) as exc:
                raise OperatorConfigError("backup_confirmed_at must be an integer") from exc
    return config


def load_operator_config(path: str | Path, *, role: str) -> dict[str, Any]:
    """Load a generated config and require a private 0600 regular file."""

    target = Path(path)
    try:
        info = target.lstat()
    except OSError as exc:
        raise OperatorConfigError(f"operator config is not readable: {target}") from exc
    if not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o077):
        raise OperatorConfigError("operator config must be a regular 0600 file")
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OperatorConfigError("operator config is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise OperatorConfigError("operator config must be a JSON object")
    if raw.get("schema") != SCHEMA or raw.get("role") != role:
        raise OperatorConfigError("operator config schema or role does not match")
    return normalize_operator_config(raw, role=role, configured_at=raw.get("configured_at"))


def write_operator_config(path: str | Path, config: dict[str, Any]) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        target.parent.chmod(0o700)
    except OSError:
        pass
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(
            json.dumps(config, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return target


def _provider_backup_is_confirmed(
    config: dict[str, Any], identity: ProviderEvmIdentity | None = None
) -> bool:
    try:
        confirmed_at = int(config.get("backup_confirmed_at") or 0)
    except (TypeError, ValueError):
        return False
    address = str(
        config.get("provider_signer_address")
        if int(config.get("settlement_version") or 7) in {8, 9, 10}
        else config.get("payout_address")
        or ""
    )
    fingerprint = str(config.get("wallet_fingerprint") or "")
    if confirmed_at <= 0 or not address or not fingerprint:
        return False
    if identity is None:
        return True
    return (
        address == identity.address
        and fingerprint == provider_identity_fingerprint(identity)
    )


def load_protected_provider_profile(
    config_path: str | Path,
    identity_path: str | Path,
) -> dict[str, Any]:
    """Build the public profile only after validating the protected signer."""

    try:
        identity = validate_provider_evm_identity(identity_path)
    except ProviderIdentityImportError as exc:
        raise OperatorConfigError(str(exc)) from exc
    target = Path(config_path)
    if target.exists():
        try:
            config = load_operator_config(target, role="provider")
        except OperatorConfigError:
            config = {}
    else:
        config = {}
    raw = dict(config)
    if not _provider_backup_is_confirmed(config, identity):
        raw.pop("backup_confirmed_at", None)
    expected_address = (
        config.get("provider_signer_address")
        if int(config.get("settlement_version") or 7) in {8, 9, 10}
        else config.get("payout_address")
    )
    if expected_address != identity.address or str(
        config.get("wallet_fingerprint") or ""
    ) != provider_identity_fingerprint(identity):
        raw.pop("wallet_fingerprint", None)
    raw["wallet_source"] = "existing"
    if int(config.get("settlement_version") or 7) in {8, 9, 10}:
        raw["wallet_address"] = config.get("payout_address")
        raw["provider_signer_address"] = identity.address
    else:
        raw["wallet_address"] = identity.address
    profile = normalize_operator_config(
        raw,
        role="provider",
        configured_at=config.get("configured_at"),
    )
    # This is a fresh assertion about the protected volume, not a persisted
    # flag supplied by the browser. Missing/corrupt or mismatched profiles must
    # still visit onboarding instead of silently accepting repaired defaults.
    profile["settings_reusable"] = bool(
        config.get("settlement_version") in {8, 9, 10}
        and config.get("payout_address")
        and expected_address == identity.address
        and config.get("wallet_fingerprint") == provider_identity_fingerprint(identity)
    )
    return profile


def shell_env(config: dict[str, Any], *, role: str) -> str:
    """Emit validated shell assignments for a Compose entrypoint."""

    prefix = "MYCOMESH_PROVIDER" if role == "provider" else "MYCOMESH_RELAY"
    values = {
        f"{prefix}_PAYMENT_ADDRESS": config.get("payout_address") or "",
        f"{prefix}_CAPACITY" if role == "provider" else f"{prefix}_CONSUMER_MAX_IN_FLIGHT": config[
            "max_concurrency"
        ],
        f"{prefix}_USAGE_LIMIT_UNITS": config["usage_limit_units"],
        f"{prefix}_USAGE_PERIOD_SECONDS": config["usage_period_seconds"],
    }
    if role == "provider" and config.get("settlement_version") is not None:
        values["MYCOMESH_SETTLEMENT_VERSION"] = config["settlement_version"]
    if role == "provider" and config.get("provider_signer_address"):
        values["MYCOMESH_PROVIDER_SIGNER_ADDRESS"] = config["provider_signer_address"]
    if role == "relay":
        values[f"{prefix}_CONTROL_MAX_CONNECTIONS"] = config["max_concurrency"]
    return "\n".join(f"{key}={shlex.quote(str(value))}" for key, value in values.items())


def provider_authorization_plan(
    config_path: str | Path, identity_path: str | Path, network_config_path: str | Path
) -> dict[str, Any]:
    """Build an unsigned wallet request without RPC access or payout keys."""

    config = load_operator_config(config_path, role="provider")
    try:
        identity = validate_provider_evm_identity(identity_path)
        network = load_provider_network_config(network_config_path)
    except (ValueError, OSError) as exc:
        raise OperatorConfigError(str(exc)) from exc
    version = int(network.deployment.protocol_version)
    if version not in {8, 9, 10} or config.get("settlement_version") != version:
        raise OperatorConfigError("Provider settings must match the selected V8/V9/V10 network")
    if config.get("provider_signer_address") != identity.address:
        raise OperatorConfigError("Provider settings do not match the protected identity")
    if not config.get("payout_address"):
        raise OperatorConfigError("Configure the public payout address before authorization")
    return _authorization_plan(config, network)


def _authorization_plan(config: dict[str, Any], network: Any) -> dict[str, Any]:
    transaction = {
        "chainId": hex(network.deployment.chain_id),
        "from": config["payout_address"],
        "to": network.deployment.settlement,
        "value": "0x0",
        "data": encode_contract_call("authorizeProviderSigner(address)", [config["provider_signer_address"]]),
    }
    return {
        "schema": "mycomesh.provider-authorization-plan.v1",
        "status": "wallet_confirmation_required",
        "protocol_version": network.deployment.protocol_version,
        "chain_id": network.deployment.chain_id,
        "provider_signer": config["provider_signer_address"],
        "transaction": transaction,
        "notice": (
            "Unsigned plan only. Review the network, contract and payout account in your wallet. "
            "No transaction was sent and authorization has not been verified. "
            "Never enter a wallet private key in the launcher."
        ),
    }


def _authorization_status(config: dict[str, Any], network: Any) -> bool:
    if rpc_int(network.settlement_rpc_url, "eth_chainId", [], timeout=5) != network.deployment.chain_id:
        raise OperatorConfigError("Authorization RPC does not match the selected network")
    return provider_signer_authorized(
        network.settlement_rpc_url, network.deployment.settlement,
        config["payout_address"], config["provider_signer_address"], timeout=5,
    )


def _browser_url(host: str, port: int, token: str, role: str) -> str:
    return f"http://{host}:{port}/?role={urllib.parse.quote(role)}&token={urllib.parse.quote(token)}"


def _open_browser(url: str) -> None:
    if os.getenv("MYCOMESH_NO_BROWSER") == "1" or os.getenv("CI") == "true":
        return
    try:
        webbrowser.open(url, new=2)
    except Exception:
        pass


def _verify_provider_identity(identity: ProviderEvmIdentity, challenge: str) -> None:
    """Run a local sign/recover check before accepting a Provider key."""

    digest = keccak256(
        b"MycoMesh Provider wallet setup v1:" + str(challenge).encode("utf-8")
    )
    try:
        signature = sign_evm_digest(identity.private_key, digest)
        recovered = recover_evm_address(digest, signature)
    except ChainError as exc:
        raise OperatorConfigError(f"Provider wallet signature verification failed: {exc}") from exc
    if recovered != identity.address:
        raise OperatorConfigError("Provider wallet signature does not match its address")


def _html_page(
    *,
    role: str,
    token: str,
    current: dict[str, Any] | None = None,
    generated_identity: ProviderEvmIdentity | None = None,
    protected_identity: ProviderEvmIdentity | None = None,
    identity_locked: bool = False,
    settlement_version: int = 8,
    authorization_network: Any = None,
    authorization_only: bool = False,
) -> bytes:
    if role == "provider":
        return _provider_html_page(
            token=token,
            current=current,
            generated_identity=generated_identity,
            protected_identity=protected_identity,
            identity_locked=identity_locked,
            settlement_version=settlement_version,
            authorization_network=authorization_network,
            authorization_only=authorization_only,
        )
    config = current or {}
    title = "Relay"
    payout_label = "Public payout address"
    payout_hint = (
        "Leave blank to use the payout identity created in the protected Relay "
        "volume. To use an existing address, import its matching identity first."
    )
    concurrency_label = "Maximum concurrent Consumer requests"
    address = html.escape(str(config.get("payout_address") or ""), quote=True)
    concurrency = html.escape(str(config.get("max_concurrency") or 1), quote=True)
    period = html.escape(str(config.get("usage_period_seconds") or 2_592_000), quote=True)
    usage = ""
    if config.get("usage_limit_units"):
        usage = html.escape(str(config["usage_limit_units"] / 1_000_000), quote=True)
    return f"""<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MycoMesh {title} onboarding</title>
<style>body{{font:16px system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#202124}}label{{display:block;margin:1rem 0 .3rem;font-weight:600}}input{{box-sizing:border-box;width:100%;padding:.65rem;font:inherit}}button{{margin-top:1.5rem;padding:.7rem 1.2rem;font:inherit;cursor:pointer}}small{{color:#5f6368}}#message{{margin-top:1rem}}</style>
<h1>{title} onboarding</h1>
<p>Only a public payout address is accepted. Never paste a private key, seed phrase, or API credential here.</p>
<form id="setup">
<input type="hidden" name="token" value="{html.escape(token, quote=True)}">
<label for="payout_address">{payout_label}</label>
<input id="payout_address" name="payout_address" autocomplete="off" placeholder="0x..." value="{address}">
<small>{payout_hint}</small>
<label for="max_concurrency">{concurrency_label}</label>
<input id="max_concurrency" name="max_concurrency" type="number" min="1" max="1024" value="{concurrency}" required>
<label for="usage_limit_usdc">Maximum usage per period (USDC, blank = unlimited)</label>
<input id="usage_limit_usdc" name="usage_limit_usdc" inputmode="decimal" placeholder="100.00" value="{usage}">
<label for="usage_period_seconds">Period length (seconds)</label>
<input id="usage_period_seconds" name="usage_period_seconds" type="number" min="60" max="31622400" value="{period}" required>
<small>The usage setting is persisted with the operator profile and is exposed to the role runtime.</small>
<button type="submit">Save settings</button>
</form><p id="message" role="status"></p>
<script>
const form=document.querySelector('#setup'), message=document.querySelector('#message');
form.addEventListener('submit', async (event)=>{{event.preventDefault();message.textContent='Saving...';
const body=Object.fromEntries(new FormData(form).entries());
const response=await fetch('/api/config',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}});
const data=await response.json(); message.textContent=data.ok?'Saved. Close this window and return to the terminal.':(data.error||'Could not save configuration.');
}});
    </script>""".encode("utf-8")


def _provider_html_page(
    *,
    token: str,
    current: dict[str, Any] | None,
    generated_identity: ProviderEvmIdentity | None,
    protected_identity: ProviderEvmIdentity | None,
    identity_locked: bool,
    settlement_version: int = 8,
    authorization_network: Any = None,
    authorization_only: bool = False,
) -> bytes:
    config = current or {}
    concurrency = html.escape(str(config.get("max_concurrency") or 1), quote=True)
    period = html.escape(str(config.get("usage_period_seconds") or 2_592_000), quote=True)
    usage = ""
    if config.get("usage_limit_units"):
        usage = html.escape(str(config["usage_limit_units"] / 1_000_000), quote=True)
    configured_address = str(config.get("payout_address") or "")
    is_v8 = int(settlement_version) in {8, 9, 10}
    configured_models = getattr(authorization_network, "public_model_ids", ()) if authorization_network is not None else ()
    model_summary = ", ".join(html.escape(str(model)) for model in configured_models) or "No pinned network model list loaded"
    identity_status = "Saved in protected runtime" if identity_locked else "Will be saved with your settings"
    economics_hint = (
        "This controlled V10 test network provides the execution budget, so a Provider does not need to deposit personal collateral. "
        "Choose a public payout wallet, authorize the Provider once, and complete the Codex and network checks. "
        "Earnings are pending during the dispute window; only released, claimable earnings can be withdrawn, "
        "using the payout wallet and its network gas."
        if int(settlement_version) == 10 else
        "V9 stake must be funded from the payout wallet before paid work. "
        "The network operator can provide the verified external-wallet funding flow. "
        "This setup page does not deposit stake or transfer funds. "
        "Earnings are pending during the dispute window; only released, claimable earnings can be withdrawn, "
        "using the payout wallet and its network gas."
        if int(settlement_version) == 9 else
        "Wallet authorization requires network gas. Withdraw earnings using the payout wallet through the network's verified withdrawal flow."
    )
    payout_fields = f"""
<label for=\"payout_address\">Payout address</label>
<input id=\"payout_address\" name=\"payout_address\" autocomplete=\"off\" placeholder=\"0x...\" value=\"{html.escape(configured_address, quote=True)}\" {'required' if is_v8 else ''} {'readonly' if authorization_only else ''}>
<small>The public wallet that receives earnings. Never enter a private key or recovery phrase.</small>
""" if is_v8 else ""
    wallet_fields = """
<div class=\"notice\" role=\"status\">
  <strong>Your Provider identity is managed automatically</strong>
  <p>No extra credentials are needed on this page. Saved settings are reused on your next start.</p>
</div>
"""
    if is_v8:
        wallet_fields += """
<small>Before receiving paid work, this payout wallet must authorize the Provider once.
Saving this page does not complete that authorization or confirm the Provider is online.</small>
"""
    if int(settlement_version) == 10:
        wallet_fields += """
<div class="notice"><p><strong>Controlled V10 test network: no personal collateral is required.</strong> The network sponsors execution capacity. You only provide a public payout address and approve one wallet authorization; never paste a private key or recovery phrase.</p></div>
"""
    elif int(settlement_version) == 9:
        wallet_fields += f"""
<div class="notice"><p>V{settlement_version} uses a funded execution channel and payout-wallet authorization before paid work.
This page does not transfer funds or submit a stake transaction. Network readiness will show whether the channel is available.
Earnings stay in escrow during the dispute window; an accepted receipt is not yet withdrawable.</p></div>
"""
    wallet_script = ""
    if authorization_network is not None:
        identity = protected_identity or generated_identity
        signer = identity.address if identity is not None else config.get("provider_signer_address")
        if signer:
            pin = {
                "chainId": hex(authorization_network.deployment.chain_id),
                "contract": authorization_network.deployment.settlement,
                "data": encode_contract_call("authorizeProviderSigner(address)", [signer]),
                "persistent": bool(identity_locked),
            }
            encoded_pin = json.dumps(pin).replace("<", "\\u003c")
            wallet_label = "Connect wallet and authorize" if identity_locked else "Use my wallet and continue"
            wallet_fields += f'<p><button type="button" id="authorize-wallet">{wallet_label}</button></p><p id="authorization-message" role="status"></p>'
            wallet_script = (
                '<script id="authorization-pin" type="application/json">' + encoded_pin + '</script><script>'
                + Path(__file__).with_name("provider_onboarding_wallet.js").read_text(encoding="utf-8")
                + '</script>'
            )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="color-scheme" content="light">
<title>Provider setup | MycoMesh</title>
<style>:root{{--ink:#17211d;--muted:#68736e;--line:#d8dfdb;--soft:#f2f5f3;--green:#147553;--green-dark:#0d5b40;--amber:#9a6413;--red:#ad322a;--white:#fff}}*{{box-sizing:border-box}}html{{background:#edf1ee}}body{{min-width:320px;margin:0;background:#edf1ee;color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}}.shell{{width:min(780px,100%);min-height:100vh;margin:0 auto;background:var(--white)}}.topbar{{position:sticky;z-index:10;top:0;display:flex;min-height:60px;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);background:rgba(255,255,255,.97);padding:0 20px}}.brand{{display:flex;align-items:center;gap:10px;font-weight:780}}.mark{{display:grid;width:30px;height:30px;place-items:center;border-radius:6px;background:var(--ink);color:white;font-size:12px}}.status{{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:11px}}.status:before{{width:6px;height:6px;border-radius:50%;background:var(--green);content:""}}main{{padding:28px 24px 42px}}.eyebrow{{margin:0 0 5px;color:var(--green);font-size:11px;font-weight:750;text-transform:uppercase}}h1{{margin:0;font-size:26px;line-height:1.2}}.intro{{max-width:650px;margin:8px 0 22px;color:var(--muted)}}.steps{{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin:0 -24px 22px;padding:0 24px}}.step{{position:relative;padding:12px 4px 11px;color:var(--muted);font-size:11px;font-weight:700}}.step:after{{position:absolute;right:10px;bottom:-1px;left:0;height:2px;background:var(--green);content:""}}.step:nth-child(2):after{{background:#5c7185}}.step:nth-child(3):after{{background:var(--amber)}}label{{display:block;margin:14px 0 5px;font-weight:680}}input,select,textarea{{width:100%;min-height:42px;border:1px solid var(--line);border-radius:5px;background:white;padding:9px 11px;color:var(--ink);font:inherit;letter-spacing:0}}input:focus,select:focus,textarea:focus{{border-color:var(--green);outline:2px solid rgba(20,117,83,.13)}}textarea,code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}}fieldset{{min-width:0;border:0;border-top:1px solid var(--line);padding:22px 0 25px;margin:0}}fieldset:first-of-type{{border-top:0;padding-top:4px}}legend{{padding:0;font-size:16px;font-weight:760}}small{{display:block;margin-top:5px;color:var(--muted);font-size:12px}}.settings-grid{{display:grid;grid-template-columns:1fr 1fr;gap:0 16px;border-top:1px solid var(--line);padding:22px 0 24px}}.settings-grid:before{{grid-column:1/-1;margin-bottom:3px;font-size:16px;font-weight:760;content:"2. Capacity and limits"}}.settings-grid>div:first-of-type{{grid-column:1/-1}}button{{display:inline-flex;min-height:44px;align-items:center;justify-content:center;border:1px solid var(--green);border-radius:6px;background:var(--green);padding:0 18px;color:white;font:inherit;font-weight:720;letter-spacing:0;cursor:pointer}}button:hover{{background:var(--green-dark)}}button:disabled{{cursor:not-allowed;opacity:.55}}.notice{{border-left:3px solid var(--green);background:#eef8f3;padding:10px 12px;color:#235d48}}.savebar{{border-top:1px solid var(--line);margin-top:4px;padding-top:18px}}.savebar-inner{{display:flex;align-items:center;justify-content:space-between;gap:16px}}#message{{min-height:20px;margin:0;color:var(--green);font-size:12px;font-weight:650}}#message.error{{color:var(--red)}}@media(min-width:781px){{body{{padding:22px}}.shell{{min-height:calc(100vh - 44px);border:1px solid var(--line);border-radius:8px;overflow:hidden;box-shadow:0 18px 50px rgba(23,33,29,.08)}}.topbar{{position:relative}}}}@media(max-width:620px){{main{{padding:24px 18px 36px}}.topbar{{padding:0 18px}}.steps{{margin-right:-18px;margin-left:-18px;padding:0 18px}}.step{{font-size:10px}}.settings-grid{{grid-template-columns:1fr}}.settings-grid>div:first-of-type{{grid-column:auto}}.savebar-inner{{align-items:stretch;flex-direction:column;gap:7px}}button{{width:100%}}#message:empty{{display:none}}}}</style></head>
<body><div class="shell"><header class="topbar"><div class="brand"><span class="mark">M</span><span>MycoMesh</span></div><span class="status">Provider V{settlement_version}</span></header><main>
<p class="eyebrow">Provider setup</p><h1>{'Authorize your Provider' if authorization_only else 'Start your Provider'}</h1>
<p class="intro">{'Your settings and identity are saved. Continue with wallet authorization before login and network checks.' if authorization_only else 'Choose where earnings go. Capacity and usage settings are already filled in; change them only if needed.'}</p>
<section aria-label="Setup progress" class="notice">
<strong>Setup progress · Online status not verified</strong>
<ol>
<li>Local settings: <span id="settings-progress">{'Saved' if config else 'Waiting for save'}</span>. Provider identity: {identity_status}.</li>
<li>Wallet authorization: <span id="wallet-progress">{'Not checked on this page' if is_v8 else 'Not required by this protocol'}</span>.</li>
<li>Codex login, model access and network connection: not checked on this page. Continue in the terminal after saving.</li>
</ol>
</section>
<form id="setup">
<input type="hidden" name="token" value="{html.escape(token, quote=True)}">
<input type="hidden" name="settlement_version" value="{settlement_version}">
<fieldset><legend>Provider settings</legend>
{payout_fields}
{wallet_fields}
</fieldset>
<details {'hidden' if authorization_only else ''}><summary>Capacity and usage limits (optional)</summary>
<div class="settings-grid"><div><label for="max_concurrency">Maximum concurrent admitted requests</label>
<input id="max_concurrency" name="max_concurrency" type="number" min="1" max="1024" value="{concurrency}" required>
</div><div><label for="usage_limit_usdc">Maximum usage per period (USDC)</label>
<input id="usage_limit_usdc" name="usage_limit_usdc" inputmode="decimal" placeholder="100.00" value="{usage}">
</div><div><label for="usage_period_seconds">Period length (seconds)</label>
<input id="usage_period_seconds" name="usage_period_seconds" type="number" min="60" max="31622400" value="{period}" required>
</div></div><small>Leave the usage amount blank for no period limit.</small></details>
<div class="savebar"><div class="savebar-inner"><p id="message" role="status"></p><button id="save" type="submit">Save settings</button></div></div>
</form>
<section id="next-steps" aria-label="Next steps" hidden>
<h2>Continue setup</h2>
<p id="next-step-message">Return to the terminal to finish sign-in and connection checks. Keep the original terminal open; it will show the next step.</p>
<p>If setup was interrupted, rerun the same start command. Saved settings are reused and authorization is checked before another wallet request. A pending transaction must be verified before retrying a send.</p>
</section>
<details><summary>{'Models and earnings' if int(settlement_version) == 10 else 'Models, stake and earnings'}</summary>
<p><strong>Configured network models:</strong> {model_summary}</p>
<p><strong>Capability evidence: configuration only.</strong> This page has not probed Codex model access or run a test request. A configured model is not a verified available model.</p>
<p>{economics_hint}</p>
<p>Stake, gas, escrow and claimable balances have not been checked on this page. Provider readiness is verified by the terminal after login and network connection; saving settings is not proof of readiness.</p>
</details>
{wallet_script}
<script>
const form=document.querySelector('#setup'), message=document.querySelector('#message'), save=document.querySelector('#save');
form.addEventListener('submit', async (event)=>{{
  event.preventDefault();
  message.className=''; message.textContent='Saving...'; save.disabled=true; save.textContent='Saving';
  let saved=false;
  try {{
    const body=Object.fromEntries(new FormData(form).entries());
    const response=await fetch('/api/config',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}});
    const data=await response.json();
    if (!response.ok || data.ok !== true) throw new Error(data.error || 'Could not save configuration.');
    saved=true;
    message.textContent='Settings saved. Return to the terminal to finish sign-in and connection checks.';
    document.querySelector('#settings-progress').textContent='Saved';
    if (data.authorization_verified === true) document.querySelector('#wallet-progress').textContent='Verified by the network';
    document.querySelector('#next-steps').hidden=false;
    document.querySelector('#next-step-message').textContent=data.authorization_verified === true
      ? 'Wallet authorization is verified. Return to the terminal for Codex login, stake readiness and network connection checks.'
      : 'Return to the terminal. For V8/V9/V10, it will open the one-time wallet authorization step after preserving your Provider identity, then continue login and network checks.';
  }} catch(error) {{
    message.className='error';
    message.textContent=(error?.message || 'Could not save configuration.') + ' Check the information above and that the setup terminal is still running, then retry. If it has closed, rerun the same start command to resume.';
  }} finally {{
    save.disabled=saved; save.textContent=saved?'Settings saved':'Save settings';
  }}
}});
</script></main></div></body></html>""".encode("utf-8")


class _WizardServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        role: str,
        output: Path,
        token: str,
        identity_output: Path | None = None,
        pending_identity: ProviderEvmIdentity | None = None,
        identity_locked: bool | None = None,
        settlement_version: int = 8,
        authorization_network: Any = None,
        authorization_state_path: str | Path | None = None,
        authorization_only: bool = False,
    ):
        super().__init__(address, _WizardHandler)
        self.role = role
        self.output = output
        self.token = token
        self.identity_output = identity_output
        self.pending_identity = pending_identity
        if identity_locked is None:
            identity_locked = bool(identity_output is not None and identity_output.exists())
        self.identity_locked = identity_locked
        self.authorization_identity_persisted = bool(identity_locked)
        self.settlement_version = int(settlement_version)
        self.authorization_network = authorization_network
        self.authorization_state = ProviderAuthorizationState(authorization_state_path) if authorization_state_path else None
        self.authorization_only = authorization_only
        self.saved: dict[str, Any] | None = None
        self.save_lock = threading.Lock()


class _WizardHandler(BaseHTTPRequestHandler):
    server: _WizardServer

    def _valid_origin(self) -> bool:
        host = self.headers.get("host", "")
        try:
            parsed = urllib.parse.urlsplit("http://" + host)
            if parsed.hostname not in _LOOPBACK_HOSTS or parsed.username is not None or parsed.password is not None:
                return False
            if parsed.path or parsed.query or parsed.fragment or not parsed.port:
                return False
        except ValueError:
            return False
        origin = self.headers.get("origin")
        return origin is None or origin == "http://" + host

    def do_GET(self) -> None:
        if not self._valid_origin():
            self._json(403, {"ok": False, "error": "onboarding requires the local origin"})
            return
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/health":
            self._json(200, {"ok": True, "role": self.server.role})
            return
        if parsed.path != "/" or query.get("token", [""])[0] != self.server.token:
            self._json(404, {"ok": False, "error": "not found"})
            return
        current = None
        try:
            current = load_operator_config(self.server.output, role=self.server.role)
        except OperatorConfigError:
            pass
        if (
            self.server.role == "provider"
            and self.server.identity_output is not None
            and self.server.identity_output.exists()
        ):
            try:
                existing_identity = validate_provider_evm_identity(self.server.identity_output)
            except ProviderIdentityImportError as exc:
                self._json(500, {"ok": False, "error": str(exc)})
                return
            current = dict(current or {})
            if int(self.server.settlement_version) in {8, 9, 10}:
                current["provider_signer_address"] = existing_identity.address
            else:
                current["payout_address"] = existing_identity.address
        payload = _html_page(
            role=self.server.role,
            token=self.server.token,
            current=current,
            generated_identity=self.server.pending_identity,
            protected_identity=(
                existing_identity
                if self.server.role == "provider"
                and self.server.identity_locked
                and self.server.identity_output is not None
                and self.server.identity_output.exists()
                else None
            ),
            identity_locked=self.server.authorization_identity_persisted,
            settlement_version=self.server.settlement_version,
            authorization_network=self.server.authorization_network,
            authorization_only=self.server.authorization_only,
        )
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("content-security-policy", "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        if not self._valid_origin():
            self._json(403, {"ok": False, "error": "onboarding requires the local origin"})
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in {"/api/config", "/api/provider-authorization", "/api/provider-authorization-intent"}:
            self._json(404, {"ok": False, "error": "not found"})
            return
        try:
            length = int(self.headers.get("content-length") or "0")
            if length <= 0 or length > 32 * 1024:
                raise OperatorConfigError("configuration body is invalid")
            raw = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(raw, dict) or raw.pop("token", None) != self.server.token:
                raise OperatorConfigError("invalid onboarding token")
            authorization_verified = False
            with self.server.save_lock:
                if parsed.path in {"/api/provider-authorization", "/api/provider-authorization-intent"}:
                    if self.server.role != "provider" or self.server.authorization_network is None:
                        raise OperatorConfigError("Wallet authorization is not configured")
                    if not self.server.authorization_identity_persisted:
                        raise OperatorConfigError("Save and persist the Provider identity before wallet authorization")
                    config, _identity = self._save_provider_config(raw)
                    plan = _authorization_plan(config, self.server.authorization_network)
                    authorized = _authorization_status(config, self.server.authorization_network)
                    state = self.server.authorization_state
                    if state is None:
                        raise OperatorConfigError("Persistent wallet authorization state is unavailable")
                    if authorized:
                        state.confirmed(plan)
                    intent_id = None
                    if parsed.path == "/api/provider-authorization-intent":
                        action = raw.get("action")
                        if action == "reserve" and not authorized:
                            intent_id = state.reserve(plan)
                        elif action == "submitted":
                            tx_hash = str(raw.get("tx_hash") or "")
                            if len(tx_hash) != 66 or not tx_hash.startswith("0x") or any(char not in "0123456789abcdefABCDEF" for char in tx_hash[2:]):
                                raise OperatorConfigError("Invalid wallet transaction hash")
                            if not authorized:
                                state.submitted(plan, str(raw.get("intent_id") or ""), tx_hash)
                        elif action == "rejected" and raw.get("wallet_error_code") == 4001:
                            if not authorized:
                                state.cancel_rejected(plan, str(raw.get("intent_id") or ""))
                        elif action != "reserve":
                            raise OperatorConfigError("Invalid wallet authorization action")
                    self._json(200, {"ok": True, "plan": plan, "authorized": authorized, "pending": state.pending(plan) is not None, "intent_id": intent_id})
                    return
                if self.server.role == "provider":
                    requires_authorization = self.server.authorization_identity_persisted and self.server.authorization_network is not None
                    config, identity = self._save_provider_config(raw)
                    if requires_authorization and not _authorization_status(config, self.server.authorization_network):
                        raise OperatorConfigError("Approve the one-time wallet authorization before continuing")
                    self._commit_provider_config(config, identity)
                    authorization_verified = requires_authorization
                else:
                    config = normalize_operator_config(raw, role=self.server.role)
                    write_operator_config(self.server.output, config)
                self.server.saved = config
            self._json(200, {"ok": True, "role": self.server.role, "authorization_verified": authorization_verified})
        except (OperatorConfigError, ChainError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})
        finally:
            if self.server.saved is not None:
                threading.Thread(target=self.server.shutdown, daemon=True).start()

    def _save_provider_config(
        self, raw: dict[str, Any]
    ) -> tuple[dict[str, Any], ProviderEvmIdentity | None]:
        # The browser config surface intentionally has no wallet controls. A
        # signer is generated on first run and reused from the protected
        # volume afterwards. Keep rejecting legacy secret fields explicitly so
        # an old client cannot smuggle a key into this endpoint.
        source = str(raw.pop("wallet_source", "") or "").strip().lower()
        secret_fields = ("private_key", "generated_private_key", "backup_saved", "backup_confirmation")
        if any(str(raw.pop(field, "") or "").strip() for field in secret_fields):
            raise OperatorConfigError("Provider signing keys are managed automatically")
        if self.server.authorization_only:
            _reject_private_fields(raw)
            existing = load_operator_config(self.server.output, role="provider")
            if str(raw.get("payout_address") or "").lower() != existing.get("payout_address"):
                raise OperatorConfigError("Authorization must use the saved payout wallet; use --configure to change it")
            action_fields = {key: raw[key] for key in ("action", "intent_id", "tx_hash", "wallet_error_code") if key in raw}
            raw.clear()
            raw.update(existing)
            raw.update(action_fields)
        raw.pop("token", None)
        raw["settlement_version"] = int(self.server.settlement_version)

        identity_path = self.server.identity_output
        identity_locked = self.server.identity_locked or bool(
            identity_path is not None and identity_path.exists()
        )
        if source and source not in _PROVIDER_WALLET_SOURCES:
            raise OperatorConfigError("wallet_source is managed by the Provider runtime")

        identity: ProviderEvmIdentity | None = None
        if identity_locked:
            source = "existing"
            if identity_path is not None and identity_path.exists():
                try:
                    identity = validate_provider_evm_identity(identity_path)
                except ProviderIdentityImportError as exc:
                    raise OperatorConfigError(str(exc)) from exc
            if identity is None:
                try:
                    existing_config = load_operator_config(self.server.output, role="provider")
                except OperatorConfigError as exc:
                    raise OperatorConfigError("protected Provider settings are unavailable") from exc
                signer_address = str(
                    (
                        existing_config.get("provider_signer_address")
                        or existing_config.get("payout_address")
                    )
                    if int(self.server.settlement_version) in {8, 9, 10}
                    else existing_config.get("payout_address")
                    or ""
                )
                if not signer_address:
                    raise OperatorConfigError("protected Provider signing identity is unavailable")
                if int(self.server.settlement_version) in {8, 9, 10}:
                    raw["provider_signer_address"] = signer_address
                else:
                    raw["wallet_address"] = signer_address
        else:
            source = "generated"
            if identity_path is None or self.server.pending_identity is None:
                raise OperatorConfigError("Provider signing identity is unavailable; reopen onboarding")
            identity = self.server.pending_identity

        if int(self.server.settlement_version) in {8, 9, 10}:
            payout = str(raw.get("payout_address") or raw.get("wallet_address") or "").strip()
            if not payout:
                try:
                    existing = load_operator_config(self.server.output, role="provider")
                except OperatorConfigError:
                    existing = {}
                payout = str(existing.get("payout_address") or "").strip()
            if not payout:
                raise OperatorConfigError(f"Settlement V{self.server.settlement_version} requires a Provider payout address")
            raw["payout_address"] = payout
            raw.pop("wallet_address", None)
        if identity is not None:
            _verify_provider_identity(identity, self.server.token)
            if int(self.server.settlement_version) in {8, 9, 10}:
                raw["provider_signer_address"] = identity.address
            else:
                raw["wallet_address"] = identity.address
            raw["wallet_fingerprint"] = provider_identity_fingerprint(identity)
            raw["backup_confirmed_at"] = int(time.time())
        raw["wallet_source"] = source
        config = normalize_operator_config(raw, role="provider")
        return config, identity

    def _commit_provider_config(
        self,
        config: dict[str, Any],
        identity: ProviderEvmIdentity | None,
    ) -> None:
        identity_path = self.server.identity_output
        identity_created = False
        if identity is not None:
            if identity_path is None:
                raise OperatorConfigError("Provider identity output is not configured")
            identity_existed = identity_path.exists() or identity_path.is_symlink()
            try:
                write_provider_evm_identity(identity_path, identity)
            except ProviderIdentityImportError as exc:
                raise OperatorConfigError(str(exc)) from exc
            identity_created = not identity_existed
        try:
            write_operator_config(self.server.output, config)
        except OSError as exc:
            if identity_created and identity_path is not None:
                try:
                    identity_path.unlink()
                except OSError as rollback_exc:
                    raise OperatorConfigError(
                        "could not save Provider settings or roll back the staged wallet"
                    ) from rollback_exc
            raise OperatorConfigError("could not save Provider settings") from exc
        if identity is not None:
            self.server.identity_locked = True

    def _json(self, status: int, value: dict[str, Any]) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def _new_provider_identity() -> ProviderEvmIdentity:
    while True:
        try:
            return provider_evm_identity_from_private_key(
                "0x" + secrets.token_bytes(32).hex()
            )
        except ProviderIdentityImportError:
            continue


def run_wizard(
    *,
    role: str,
    output: str | Path,
    host: str,
    port: int,
    no_browser: bool = False,
    identity_output: str | Path | None = None,
    token: str | None = None,
    display_host: str | None = None,
    allow_container_bind: bool = False,
    protected_wallet: bool = False,
    settlement_version: int | None = None,
    network_config_path: str | Path | None = None,
    authorization_state_path: str | Path | None = None,
    authorization_only: bool = False,
) -> dict[str, Any]:
    if protected_wallet and role != "provider":
        raise OperatorConfigError("--protected-wallet is only supported for Provider")
    if settlement_version is None:
        try:
            settlement_version = int(os.getenv("MYCOMESH_SETTLEMENT_VERSION", "8"))
        except ValueError as exc:
            raise OperatorConfigError("settlement version must be an integer") from exc
    if int(settlement_version) not in {2, 3, 4, 5, 6, 7, 8, 9, 10}:
        raise OperatorConfigError("settlement version must be between 2 and 10")
    authorization_network = None
    if network_config_path is not None:
        authorization_network = load_provider_network_config(network_config_path)
        if role != "provider" or int(settlement_version) not in {8, 9, 10} or authorization_network.deployment.protocol_version != int(settlement_version):
            raise OperatorConfigError("Wallet authorization must match the selected V8/V9/V10 Provider network")
    if host not in {"127.0.0.1", "::1"} and not (
        allow_container_bind and host == "0.0.0.0"
    ):
        raise OperatorConfigError("onboarding wizard must bind to loopback")
    if not (0 <= int(port) <= 65535):
        raise OperatorConfigError("wizard port is invalid")
    url_host = display_host or ("127.0.0.1" if host == "0.0.0.0" else host)
    if url_host not in _LOOPBACK_HOSTS:
        raise OperatorConfigError("onboarding display host must be loopback")
    if token is None:
        wizard_token = secrets.token_urlsafe(32)
    elif (
        not isinstance(token, str)
        or not 32 <= len(token) <= 128
        or not token.isascii()
        or not all(character.isalnum() or character in "-_" for character in token)
    ):
        raise OperatorConfigError("onboarding token must be 32-128 URL-safe characters")
    else:
        wizard_token = token
    target = Path(output).expanduser()
    identity_target = Path(identity_output).expanduser() if identity_output else None
    if role == "provider" and identity_target is None:
        identity_target = target.with_name("provider-evm-identity.json")
    pending_identity = None
    identity_locked = bool(protected_wallet)
    protected_address = ""
    if role == "provider" and identity_target is not None:
        if protected_wallet:
            try:
                protected_config = load_operator_config(target, role="provider")
            except OperatorConfigError as exc:
                raise OperatorConfigError(
                    "protected Provider wallet settings are unavailable"
                ) from exc
            protected_address = str(
                (
                    protected_config.get("provider_signer_address")
                    if int(settlement_version) in {8, 9, 10}
                    else protected_config.get("payout_address")
                )
                or ""
            )
            if not protected_address:
                raise OperatorConfigError(
                    "protected Provider wallet address is unavailable"
                )
        if identity_target.exists():
            try:
                existing_identity = validate_provider_evm_identity(identity_target)
            except ProviderIdentityImportError as exc:
                raise OperatorConfigError(str(exc)) from exc
            if protected_address and existing_identity.address != protected_address:
                raise OperatorConfigError(
                    "local Provider identity does not match the protected Docker wallet"
                )
            identity_locked = True
        if not identity_locked:
            pending_identity = _new_provider_identity()
    server = _WizardServer(
        (host, int(port)),
        role=role,
        output=target,
        token=wizard_token,
        identity_output=identity_target,
        pending_identity=pending_identity,
        identity_locked=identity_locked,
        settlement_version=int(settlement_version),
        authorization_network=authorization_network,
        authorization_state_path=authorization_state_path,
        authorization_only=authorization_only,
    )
    url_host = "[::1]" if url_host == "::1" else url_host
    actual_port = int(server.server_address[1])
    url = _browser_url(url_host, actual_port, wizard_token, role)
    print(f"MycoMesh {role} onboarding: {url}", flush=True)
    if not no_browser:
        _open_browser(url)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
    if server.saved is None:
        raise OperatorConfigError("onboarding ended before a configuration was saved")
    return server.saved


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MycoMesh local Provider/Relay onboarding wizard")
    subparsers = parser.add_subparsers(dest="command", required=True)
    wizard = subparsers.add_parser("wizard", help="run the loopback browser wizard")
    wizard.add_argument("role", choices=["provider", "relay"])
    wizard.add_argument("--output", required=True, help="0600 operator JSON path")
    wizard.add_argument("--host", default="127.0.0.1")
    wizard.add_argument("--port", type=int, default=0)
    wizard.add_argument("--no-browser", action="store_true")
    wizard.add_argument("--network-config", help="pinned Provider manifest for optional browser-wallet authorization")
    wizard.add_argument("--authorization-state", help="persistent public wallet-send fence database")
    wizard.add_argument("--authorization-only", action="store_true", help="resume wallet approval without changing saved settings")
    wizard.add_argument("--token", help="use a caller-supplied one-time onboarding token")
    wizard.add_argument(
        "--display-host",
        choices=sorted(_LOOPBACK_HOSTS),
        help="loopback host printed in the onboarding URL",
    )
    wizard.add_argument(
        "--allow-container-bind",
        action="store_true",
        help="allow an explicit 0.0.0.0 bind inside an isolated container",
    )
    wizard.add_argument(
        "--identity-output",
        help="0600 Provider EVM identity path (Provider only)",
    )
    wizard.add_argument(
        "--protected-wallet",
        action="store_true",
        help="reuse the Provider wallet confirmed in a protected Docker volume",
    )
    wizard.add_argument(
        "--settlement-version",
        type=int,
        choices=[2, 3, 4, 5, 6, 7, 8, 9, 10],
        default=int(os.getenv("MYCOMESH_SETTLEMENT_VERSION", "8")),
        help="Provider settlement protocol version",
    )
    env = subparsers.add_parser("env", help="emit validated shell assignments for a config")
    env.add_argument("--role", choices=["provider", "relay"], required=True)
    env.add_argument("--config", required=True)
    export_profile = subparsers.add_parser(
        "export-provider-profile",
        help="export a public profile after validating the protected Provider wallet",
    )
    export_profile.add_argument("--config", required=True)
    export_profile.add_argument("--identity", required=True)
    authorization_plan = subparsers.add_parser(
        "provider-authorization-plan", help="print an unsigned Provider wallet authorization (no transaction sent)"
    )
    authorization_plan.add_argument("--config", required=True)
    authorization_plan.add_argument("--identity", required=True)
    authorization_plan.add_argument("--network-config", required=True)
    authorization_plan.add_argument("--check-authorization", action="store_true", help="read the pinned network authorization state without sending")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "env":
            print(shell_env(load_operator_config(args.config, role=args.role), role=args.role))
            return 0
        if args.command == "export-provider-profile":
            print(
                json.dumps(
                    load_protected_provider_profile(args.config, args.identity),
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "provider-authorization-plan":
            plan = provider_authorization_plan(args.config, args.identity, args.network_config)
            if args.check_authorization:
                config = load_operator_config(args.config, role="provider")
                network = load_provider_network_config(args.network_config)
                plan["authorized"] = _authorization_status(config, network)
            print(json.dumps(plan, indent=2))
            return 0
        run_wizard(
            role=args.role,
            output=args.output,
            host=args.host,
            port=args.port,
            no_browser=args.no_browser,
            identity_output=args.identity_output,
            token=args.token,
            display_host=args.display_host,
            allow_container_bind=args.allow_container_bind,
            protected_wallet=args.protected_wallet,
            settlement_version=args.settlement_version,
            network_config_path=args.network_config,
            authorization_state_path=args.authorization_state,
            authorization_only=args.authorization_only,
        )
        print(f"Saved {args.role} operator configuration to {Path(args.output).expanduser()}")
        return 0
    except (ValueError, ChainError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
