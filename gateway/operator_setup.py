"""Loopback-only onboarding wizard for Provider and Relay operators.

The wizard deliberately accepts only public payout addresses and bounded
capacity/budget settings.  It never handles EVM private keys or other
credentials.  ``make provider-onboard`` and ``make relay-onboard`` run this
module on the host, then Compose copies the resulting 0600 file into the
role's protected data volume.
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


SCHEMA = "mycomesh.operator.v1"
MAX_CONCURRENCY = 1024
MIN_PERIOD_SECONDS = 60
MAX_PERIOD_SECONDS = 366 * 24 * 60 * 60
MAX_USAGE_UNITS = 10**30
_PRIVATE_FIELD_NAMES = {
    "private_key",
    "privatekey",
    "seed",
    "seed_phrase",
    "mnemonic",
    "secret",
    "access_token",
    "refresh_token",
    "api_key",
}


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
    address_value = raw.get("payout_address", raw.get("payment_address"))
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
    return {
        "schema": SCHEMA,
        "role": role,
        "payout_address": payout_address,
        "max_concurrency": max_concurrency,
        "usage_limit_units": usage_limit_units,
        "usage_limit_usdc": f"{usage_limit_units / 1_000_000:.6f}",
        "usage_period_seconds": period_seconds,
        "configured_at": int(configured_at or time.time()),
    }


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
    temporary.write_text(json.dumps(config, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)
    os.chmod(target, 0o600)
    return target


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


def _html_page(*, role: str, token: str, current: dict[str, Any] | None = None) -> bytes:
    config = current or {}
    title = "Provider" if role == "provider" else "Relay"
    if role == "provider":
        payout_label = "Optional payout identity address (advanced)"
        payout_hint = (
            "Leave blank to use the payout/signing identity in the protected Provider "
            "volume. A supplied address must match an imported Provider identity."
        )
        concurrency_label = "Maximum concurrent inference requests"
    else:
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


class _WizardServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], *, role: str, output: Path, token: str):
        super().__init__(address, _WizardHandler)
        self.role = role
        self.output = output
        self.token = token
        self.saved: dict[str, Any] | None = None


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
        payload = _html_page(role=self.server.role, token=self.server.token, current=current)
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
            config = normalize_operator_config(raw, role=self.server.role)
            write_operator_config(self.server.output, config)
            self.server.saved = config
            self._json(200, {"ok": True, "role": self.server.role})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        except (OperatorConfigError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})

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


def run_wizard(*, role: str, output: str | Path, host: str, port: int, no_browser: bool = False) -> dict[str, Any]:
    if host not in {"127.0.0.1", "::1"}:
        raise OperatorConfigError("onboarding wizard must bind to loopback")
    if not (1 <= int(port) <= 65535):
        raise OperatorConfigError("wizard port is invalid")
    target = Path(output).expanduser()
    token = secrets.token_urlsafe(32)
    server = _WizardServer((host, int(port)), role=role, output=target, token=token)
    url_host = "[::1]" if host == "::1" else host
    url = _browser_url(url_host, int(port), token, role)
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
    wizard.add_argument("--port", type=int, default=8765)
    wizard.add_argument("--no-browser", action="store_true")
    env = subparsers.add_parser("env", help="emit validated shell assignments for a config")
    env.add_argument("--role", choices=["provider", "relay"], required=True)
    env.add_argument("--config", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "env":
            print(shell_env(load_operator_config(args.config, role=args.role), role=args.role))
            return 0
        run_wizard(
            role=args.role,
            output=args.output,
            host=args.host,
            port=args.port,
            no_browser=args.no_browser,
        )
        print(f"Saved {args.role} operator configuration to {Path(args.output).expanduser()}")
        return 0
    except (OperatorConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
