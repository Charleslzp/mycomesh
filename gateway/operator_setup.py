"""Loopback-only onboarding wizard for Provider and Relay operators.

The Relay wizard accepts only public payout addresses and bounded
capacity/budget settings.  The Provider wizard can additionally create or
import a Provider EVM identity through a one-shot loopback flow.  Private keys
are written only to a separate 0600 identity file; they are never stored in
the operator settings JSON or placed in a URL.  Compose copies that identity
into the protected Provider volume before startup.
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
from .chain import ChainError, keccak256, recover_evm_address, sign_evm_digest
from .provider_bootstrap import ProviderEvmIdentity
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
                maximum=8,
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
        if int(config.get("settlement_version") or 7) == 8
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
        if int(config.get("settlement_version") or 7) == 8
        else config.get("payout_address")
    )
    if expected_address != identity.address or str(
        config.get("wallet_fingerprint") or ""
    ) != provider_identity_fingerprint(identity):
        raw.pop("wallet_fingerprint", None)
    raw["wallet_source"] = "existing"
    if int(config.get("settlement_version") or 7) == 8:
        raw["wallet_address"] = config.get("payout_address")
        raw["provider_signer_address"] = identity.address
    else:
        raw["wallet_address"] = identity.address
    return normalize_operator_config(
        raw,
        role="provider",
        configured_at=config.get("configured_at"),
    )


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
) -> bytes:
    if role == "provider":
        return _provider_html_page(
            token=token,
            current=current,
            generated_identity=generated_identity,
            protected_identity=protected_identity,
            identity_locked=identity_locked,
            settlement_version=settlement_version,
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
) -> bytes:
    config = current or {}
    concurrency = html.escape(str(config.get("max_concurrency") or 1), quote=True)
    period = html.escape(str(config.get("usage_period_seconds") or 2_592_000), quote=True)
    usage = ""
    if config.get("usage_limit_units"):
        usage = html.escape(str(config["usage_limit_units"] / 1_000_000), quote=True)
    configured_address = str(config.get("payout_address") or "")
    is_v8 = int(settlement_version) == 8
    signer_address = str(
        config.get("provider_signer_address")
        or (protected_identity.address if protected_identity is not None else "")
    )
    payout_fields = ""
    if is_v8:
        payout_fields = f"""
<label for=\"payout_address\">1. Provider payout address</label>
<input id=\"payout_address\" name=\"payout_address\" autocomplete=\"off\" placeholder=\"0x...\" value=\"{html.escape(configured_address, quote=True)}\" required>
<small>Settlement credits are paid to this address. It is independent from the local receipt signer.</small>
<p class=\"notice\">Receipt signer: <code>{html.escape(signer_address or 'created during setup', quote=True)}</code></p>
"""
    if identity_locked:
        address = html.escape(configured_address or "Unavailable", quote=True)
        if protected_identity is not None and not _provider_backup_is_confirmed(
            config, protected_identity
        ):
            private_key = html.escape(protected_identity.private_key, quote=True)
            wallet_fields = f"""
<input type="hidden" name="wallet_source" value="existing">
<div id="protected-wallet-backup">
<p><strong>Back up this protected Provider wallet</strong></p>
<label for="protected_private_key">Provider wallet private key (shown until backup is confirmed)</label>
<textarea id="protected_private_key" readonly rows="3" spellcheck="false">{private_key}</textarea>
<p class="danger" role="alert">Warning: save this private key now. It controls Provider settlement and will be hidden after verification.</p>
<small>Use an encrypted password manager. The key is never written to settings, URLs, or logs.</small>
<p>Wallet address: <code>{address}</code></p>
<label class="backup-saved" for="backup_saved"><input id="backup_saved" name="backup_saved" type="checkbox" value="yes"><span>I have securely saved this private key</span></label>
<section id="backup-confirmation-step">
<label for="backup_confirmation">Enter the first 4 and last 8 private-key characters to verify your backup</label>
<input id="backup_confirmation" name="backup_confirmation" autocomplete="off" spellcheck="false" placeholder="abcd...12345678" disabled>
</section>
</div>
"""
            wallet_script = """<script>
const backupSaved=document.querySelector('#backup_saved'), backupStep=document.querySelector('#backup-confirmation-step'), backupConfirmation=document.querySelector('#backup_confirmation');
function updateBackupConfirmation() { const enabled=backupSaved.checked; backupStep.style.display=enabled?'block':'none'; backupConfirmation.disabled=!enabled; backupConfirmation.required=enabled; if(!enabled) backupConfirmation.value=''; }
backupSaved.addEventListener('change', updateBackupConfirmation); updateBackupConfirmation();
</script>"""
        else:
            wallet_fields = f"""
<input type="hidden" name="wallet_source" value="existing">
<p><strong>Protected Provider wallet</strong></p>
<p>Wallet address: <code>{address}</code></p>
<p class="notice" role="status">The private-key backup was verified previously. This settings page will not display or replace it.</p>
"""
            wallet_script = ""
    else:
        if generated_identity is None:
            selected_generated = ""
            selected_imported = "selected"
            private_key = ""
            address = "Unavailable until a private key is imported"
        else:
            selected_generated = "selected"
            selected_imported = ""
            private_key = html.escape(generated_identity.private_key, quote=True)
            address = html.escape(generated_identity.address, quote=True)
        wallet_fields = f"""
<label for="wallet_source">Wallet source</label>
<select id="wallet_source" name="wallet_source" required>
<option value="generated" {selected_generated}>Create a new local wallet</option>
<option value="imported" {selected_imported}>Import an existing private key</option>
</select>
<small>A new key is generated only for this initial setup. An imported key is validated locally before it is stored.</small>
<section id="generated-wallet">
<label for="generated_private_key">New wallet private key (shown once)</label>
<textarea id="generated_private_key" readonly rows="3" spellcheck="false">{private_key}</textarea>
<p class="danger" role="alert">Warning: this private key is displayed only once. Save it securely before continuing.</p>
<small>Use an encrypted password manager. The key is never written to settings, URLs, or logs.</small>
<p>Wallet address: <code>{address}</code></p>
<label class="backup-saved" for="backup_saved"><input id="backup_saved" name="backup_saved" type="checkbox" value="yes"><span>I have securely saved this private key</span></label>
<section id="backup-confirmation-step">
<label for="backup_confirmation">Enter the first 4 and last 8 private-key characters to verify your backup</label>
<input id="backup_confirmation" name="backup_confirmation" autocomplete="off" spellcheck="false" placeholder="abcd...12345678" disabled>
</section>
</section>
<section id="imported-wallet">
<label for="private_key">Existing private key</label>
<input id="private_key" name="private_key" type="password" autocomplete="off" spellcheck="false" placeholder="0x...">
<small>The key stays on this loopback request, is validated by address derivation and a sign/recover check, and is then written to a protected identity file.</small>
</section>
"""
        wallet_script = """<script>
const sourceSelect=document.querySelector('#wallet_source'), generated=document.querySelector('#generated-wallet'), imported=document.querySelector('#imported-wallet'), backupSaved=document.querySelector('#backup_saved'), backupStep=document.querySelector('#backup-confirmation-step'), backupConfirmation=document.querySelector('#backup_confirmation');
function updateBackupConfirmation() { const enabled=sourceSelect.value==='generated'&&backupSaved.checked; backupStep.style.display=enabled?'block':'none'; backupConfirmation.disabled=!enabled; backupConfirmation.required=enabled; if(!enabled) backupConfirmation.value=''; }
function updateWalletFields() { const value=sourceSelect.value, generatedSelected=value==='generated'; generated.style.display=generatedSelected?'block':'none'; imported.style.display=value==='imported'?'block':'none'; document.querySelector('#private_key').required=value==='imported'; backupSaved.disabled=!generatedSelected; if(!generatedSelected) backupSaved.checked=false; updateBackupConfirmation(); }
sourceSelect.addEventListener('change', updateWalletFields); backupSaved.addEventListener('change', updateBackupConfirmation); updateWalletFields();
</script>"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light">
<title>Provider setup | MycoMesh</title>
<style>:root{{--ink:#17211d;--muted:#68736e;--line:#d9e0dc;--soft:#f3f6f4;--green:#177b57;--red:#b43b35;--white:#fff}}*{{box-sizing:border-box}}body{{margin:0;background:#eef2ef;color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}}.topbar{{display:flex;min-height:58px;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);background:white;padding:0 28px}}.brand{{display:flex;align-items:center;gap:10px;font-weight:750}}.mark{{display:grid;width:28px;height:28px;place-items:center;border-radius:6px;background:var(--ink);color:white}}.status{{border:1px solid var(--line);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:12px}}main{{width:min(760px,calc(100% - 32px));margin:0 auto;padding:38px 0 60px}}.eyebrow{{margin:0 0 5px;color:var(--green);font-size:12px;font-weight:750;text-transform:uppercase}}h1{{margin:0;font-size:28px;line-height:1.2}}.intro{{max-width:650px;margin:9px 0 28px;color:var(--muted)}}label{{display:block;margin:14px 0 5px;font-weight:650}}input,select,textarea{{width:100%;border:1px solid var(--line);border-radius:5px;background:white;padding:10px 11px;color:var(--ink);font:inherit;letter-spacing:0}}input:focus,select:focus,textarea:focus{{border-color:var(--green);outline:2px solid rgba(23,123,87,.12)}}input[type=checkbox]{{width:auto;padding:0}}textarea,code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}}fieldset{{border:1px solid var(--line);border-radius:6px;background:white;padding:8px 18px 20px;margin:0 0 18px}}legend{{padding:0 7px;font-size:13px;font-weight:750}}section{{display:none}}small{{display:block;margin-top:5px;color:var(--muted);font-size:12px}}.settings-grid{{display:grid;grid-template-columns:1fr 1fr;gap:0 16px;border-top:1px solid var(--line);padding-top:12px}}.settings-grid>div:first-child{{grid-column:1/-1}}button{{display:inline-flex;min-height:40px;align-items:center;justify-content:center;margin-top:20px;border:1px solid var(--green);border-radius:5px;background:var(--green);padding:0 16px;color:white;font:inherit;font-weight:700;letter-spacing:0;cursor:pointer}}button:hover{{background:#0f6044}}.danger{{border-left:3px solid var(--red);background:#fff4f3;padding:9px 11px;color:#8c302c;font-weight:650}}.notice{{border-left:3px solid var(--green);background:#eef9f4;padding:9px 11px;color:#235d48}}.backup-saved{{display:flex;align-items:flex-start;gap:.6rem}}#message{{min-height:22px;margin:13px 0 0;color:var(--green);font-weight:650}}@media(max-width:620px){{.topbar{{padding:0 16px}}main{{padding-top:26px}}.settings-grid{{grid-template-columns:1fr}}.settings-grid>div:first-child{{grid-column:auto}}button{{width:100%;min-height:44px}}}}</style></head>
<body><header class="topbar"><div class="brand"><span class="mark">M</span><span>MycoMesh</span></div><span class="status">Provider V{settlement_version}</span></header><main>
<p class="eyebrow">Node setup</p><h1>Provider onboarding</h1>
<p class="intro">{('The protected Provider signer signs V8 usage receipts. The payout address is authorized to use this signer once on-chain.' if is_v8 else 'The protected Provider identity signs V7 usage receipts in the background and receives settlement credits. Its address is derived from the signing key; there is no separate payout address.')}</p>
<form id="setup">
<input type="hidden" name="token" value="{html.escape(token, quote=True)}">
<input type="hidden" name="settlement_version" value="{settlement_version}">
<fieldset><legend>1. Settlement signing identity</legend>
{payout_fields}
{wallet_fields}
</fieldset>
<div class="settings-grid"><div><label for="max_concurrency">2. Maximum concurrent admitted requests</label>
<input id="max_concurrency" name="max_concurrency" type="number" min="1" max="1024" value="{concurrency}" required>
</div><div><label for="usage_limit_usdc">3. Maximum usage per period (USDC)</label>
<input id="usage_limit_usdc" name="usage_limit_usdc" inputmode="decimal" placeholder="100.00" value="{usage}">
</div><div><label for="usage_period_seconds">Period length (seconds)</label>
<input id="usage_period_seconds" name="usage_period_seconds" type="number" min="60" max="31622400" value="{period}" required>
</div></div><small>Leave the usage amount blank for no period limit.</small>
<button type="submit">Save settings</button>
</form><p id="message" role="status"></p>
{wallet_script}
<script>
const form=document.querySelector('#setup'), message=document.querySelector('#message');
form.addEventListener('submit', async (event)=>{{event.preventDefault();message.textContent='Saving...'; const body=Object.fromEntries(new FormData(form).entries()); const response=await fetch('/api/config',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}}); const data=await response.json(); if(data.ok){{for(const key of document.querySelectorAll('#generated_private_key,#protected_private_key,#private_key,#backup_confirmation')){{key.value='';key.defaultValue='';key.textContent='';}} document.querySelector('#generated-wallet')?.remove();document.querySelector('#imported-wallet')?.remove();document.querySelector('#protected-wallet-backup')?.remove();}} message.textContent=data.ok?'Saved. Private key cleared from this page; close the window and return to the terminal.':(data.error||'Could not save configuration.');}});
</script></main></body></html>""".encode("utf-8")


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
        self.settlement_version = int(settlement_version)
        self.saved: dict[str, Any] | None = None
        self.save_lock = threading.Lock()


class _WizardHandler(BaseHTTPRequestHandler):
    server: _WizardServer

    def do_GET(self) -> None:
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
            if int(self.server.settlement_version) == 8:
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
            identity_locked=self.server.identity_locked,
            settlement_version=self.server.settlement_version,
        )
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/config":
            self._json(404, {"ok": False, "error": "not found"})
            return
        try:
            length = int(self.headers.get("content-length") or "0")
            if length <= 0 or length > 32 * 1024:
                raise OperatorConfigError("configuration body is invalid")
            raw = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(raw, dict) or raw.pop("token", None) != self.server.token:
                raise OperatorConfigError("invalid onboarding token")
            with self.server.save_lock:
                if self.server.role == "provider":
                    config, identity = self._save_provider_config(raw)
                    self._commit_provider_config(config, identity)
                else:
                    config = normalize_operator_config(raw, role=self.server.role)
                    write_operator_config(self.server.output, config)
                self.server.saved = config
            self._json(200, {"ok": True, "role": self.server.role})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        except (OperatorConfigError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})

    def _save_provider_config(
        self, raw: dict[str, Any]
    ) -> tuple[dict[str, Any], ProviderEvmIdentity | None]:
        source = str(raw.pop("wallet_source", "existing") or "existing").strip().lower()
        private_key = raw.pop("private_key", None)
        raw.pop("generated_private_key", None)
        backup_saved = raw.pop("backup_saved", None)
        backup_confirmation = raw.pop("backup_confirmation", None)
        raw.pop("token", None)
        raw["settlement_version"] = int(self.server.settlement_version)
        if source not in _PROVIDER_WALLET_SOURCES:
            raise OperatorConfigError("wallet_source must be existing, generated, or imported")

        identity_path = self.server.identity_output
        identity_locked = self.server.identity_locked or bool(
            identity_path is not None and identity_path.exists()
        )
        if identity_locked and source != "existing":
            raise OperatorConfigError(
                "Provider already has a protected settlement wallet; this settings page cannot replace it"
            )
        if not identity_locked and source == "existing":
            raise OperatorConfigError(
                "Provider has no protected settlement wallet; create a new wallet or import one"
            )

        identity: ProviderEvmIdentity | None = None
        if source == "generated":
            if identity_path is None:
                raise OperatorConfigError("Provider identity output is not configured")
            identity = self.server.pending_identity
            if identity is None:
                raise OperatorConfigError("Provider generated wallet is unavailable; reopen onboarding")
            if str(backup_saved or "").strip().lower() != "yes":
                raise OperatorConfigError(
                    "confirm that the generated private key was securely saved before verifying it"
                )
            expected = provider_identity_fingerprint(identity).replace("...", "")
            supplied = str(backup_confirmation or "").strip().lower().replace("0x", "").replace("...", "")
            if supplied != expected:
                raise OperatorConfigError(
                    "backup confirmation must match the first 4 and last 8 private-key characters"
                )
        elif source == "imported":
            if identity_path is None:
                raise OperatorConfigError("Provider identity output is not configured")
            if not isinstance(private_key, str) or not private_key.strip():
                raise OperatorConfigError("private_key is required when importing a Provider wallet")
            try:
                identity = provider_evm_identity_from_private_key(private_key)
            except ProviderIdentityImportError as exc:
                raise OperatorConfigError(f"Provider private key is invalid: {exc}") from exc
        else:
            if isinstance(private_key, str) and private_key.strip():
                raise OperatorConfigError(
                    "private key fields are only accepted for a selected Provider wallet source"
                )
            try:
                existing_config = load_operator_config(
                    self.server.output, role="provider"
                )
            except OperatorConfigError:
                existing_config = {}
            if identity_path is not None and identity_path.exists():
                try:
                    identity = validate_provider_evm_identity(identity_path)
                except ProviderIdentityImportError as exc:
                    raise OperatorConfigError(str(exc)) from exc
            else:
                try:
                    existing_config = load_operator_config(
                        self.server.output, role="provider"
                    )
                except OperatorConfigError as exc:
                    raise OperatorConfigError(
                        "protected Provider wallet address is unavailable"
                    ) from exc
                existing_address = str(
                    (
                        existing_config.get("provider_signer_address")
                        if int(self.server.settlement_version) == 8
                        else existing_config.get("payout_address")
                    )
                    or ""
                )
                if not existing_address:
                    raise OperatorConfigError(
                        "protected Provider wallet address is unavailable"
                    )
                if int(self.server.settlement_version) == 8:
                    raw["provider_signer_address"] = existing_address
                else:
                    raw["wallet_address"] = existing_address
                existing_fingerprint = existing_config.get("wallet_fingerprint")
                if existing_fingerprint:
                    raw["wallet_fingerprint"] = existing_fingerprint

            backup_confirmed_at = existing_config.get("backup_confirmed_at")
            if _provider_backup_is_confirmed(existing_config, identity):
                if isinstance(backup_confirmation, str) and backup_confirmation.strip():
                    raise OperatorConfigError(
                        "Provider wallet backup was already confirmed"
                    )
                raw["backup_confirmed_at"] = backup_confirmed_at
            else:
                if identity is None:
                    raise OperatorConfigError(
                        "protected Provider private key is unavailable for backup"
                    )
                if str(backup_saved or "").strip().lower() != "yes":
                    raise OperatorConfigError(
                        "confirm that the protected private key was securely saved before verifying it"
                    )
                expected = provider_identity_fingerprint(identity).replace("...", "")
                supplied = str(backup_confirmation or "").strip().lower().replace("0x", "").replace("...", "")
                if supplied != expected:
                    raise OperatorConfigError(
                        "backup confirmation must match the first 4 and last 8 private-key characters"
                    )
                raw["backup_confirmed_at"] = int(time.time())

        if int(self.server.settlement_version) == 8:
            payout = str(raw.get("payout_address") or raw.get("wallet_address") or "").strip()
            if not payout:
                try:
                    existing = load_operator_config(self.server.output, role="provider")
                except OperatorConfigError:
                    existing = {}
                payout = str(existing.get("payout_address") or "").strip()
            if not payout:
                raise OperatorConfigError("Settlement V8 requires a Provider payout address")
            raw["payout_address"] = payout
            raw.pop("wallet_address", None)
        if identity is not None:
            _verify_provider_identity(identity, self.server.token)
            if int(self.server.settlement_version) == 8:
                raw["provider_signer_address"] = identity.address
            else:
                raw["wallet_address"] = identity.address
            raw["wallet_fingerprint"] = provider_identity_fingerprint(identity)
            if source == "generated":
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
) -> dict[str, Any]:
    if protected_wallet and role != "provider":
        raise OperatorConfigError("--protected-wallet is only supported for Provider")
    if settlement_version is None:
        try:
            settlement_version = int(os.getenv("MYCOMESH_SETTLEMENT_VERSION", "8"))
        except ValueError as exc:
            raise OperatorConfigError("settlement version must be an integer") from exc
    if int(settlement_version) not in {2, 3, 4, 5, 6, 7, 8}:
        raise OperatorConfigError("settlement version must be between 2 and 8")
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
                    if int(settlement_version) == 8
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
        elif protected_wallet and not _provider_backup_is_confirmed(protected_config):
            raise OperatorConfigError(
                "protected Provider identity is required until its backup is verified"
            )
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
        choices=[2, 3, 4, 5, 6, 7, 8],
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
        )
        print(f"Saved {args.role} operator configuration to {Path(args.output).expanduser()}")
        return 0
    except (OperatorConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
