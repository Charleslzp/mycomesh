from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .chain import ChainError, ZERO_ADDRESS, normalize_address
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
from .request_limits import BoundedRequestBodyMiddleware


DEFAULT_LOCAL_CONSUMER_DATA_DIR = "/data"
DEFAULT_LOCAL_CONSUMER_BASE_URL = "http://127.0.0.1:8110/v1"
DEFAULT_LOCAL_CONSUMER_WEB_DIR = "/app/web"
LOCAL_API_KEY_PREFIX = "sk-myco-local-"
LOCAL_WALLET_SCHEMA = "mycomesh.local-consumer.wallet.v1"
LOCAL_STATUS_SCHEMA = "mycomesh.local-consumer.status.v1"
_API_KEY_PATTERN = re.compile(r"^sk-myco-local-[A-Za-z0-9_-]{43}$")


class LocalConsumerError(RuntimeError):
    pass


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

    def status_payload(self) -> dict[str, Any]:
        if self.wallet is None:
            state = "needs_wallet"
            blockers = [
                {
                    "code": "wallet_not_configured",
                    "detail": "Configure the public address of the wallet that will fund V3 reservations.",
                },
                {
                    "code": "v3_execution_not_enabled",
                    "detail": "The phase-one client does not submit or sign V3 transactions.",
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
            state = "needs_signer"
            blockers = [
                {
                    "code": "external_wallet_signer_not_connected",
                    "detail": "The wallet address is stored, but no private key or external signer is connected.",
                },
                {
                    "code": "v3_execution_not_enabled",
                    "detail": "The phase-one client does not submit or sign V3 transactions.",
                },
            ]
            next_action = {
                "code": "connect_external_wallet_signer",
                "detail": "Install the forthcoming local signer adapter; never send a wallet private key to this HTTP API.",
            }
        deployment = self.network.deployment
        return {
            "schema": LOCAL_STATUS_SCHEMA,
            "service": "mycomesh-local-consumer",
            "state": state,
            "inference_ready": False,
            "browser_app_ready": self.browser_app_ready,
            "browser_app_url": self.browser_app_url,
            "gateway_dependency": False,
            "routing_mode": "bridge-relay-settlement-v3",
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
                "bridge_urls": list(self.network.bridge_urls),
                "relay_url": self.network.relay_public_url,
            },
            "settlement": {
                "version": 3,
                "chain_id": deployment.chain_id,
                "contract": deployment.settlement,
                "pricing_version": deployment.pricing_version,
                "pricing_hash": deployment.pricing_hash,
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
            "inference_ready": False,
            "browser_app_ready": local_state.browser_app_ready,
            "gateway_dependency": False,
        }

    @app.get("/ready")
    async def ready() -> JSONResponse:
        status = local_state.status_payload()
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "service": "mycomesh-local-consumer",
                "state": status["state"],
                "inference_ready": False,
                "blockers": [str(item["code"]) for item in status["blockers"]],
            },
        )

    @app.get("/v1/models")
    async def models(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_api_key(local_state, authorization)
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

    @app.post("/v1/responses")
    async def responses(
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        _require_api_key(local_state, authorization)
        return _not_ready_response(local_state)

    @app.post("/v1/chat/completions")
    async def chat_completions(
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        _require_api_key(local_state, authorization)
        return _not_ready_response(local_state)

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


def _not_ready_response(state: LocalConsumerState) -> JSONResponse:
    status = state.status_payload()
    blocker_codes = [str(item["code"]) for item in status["blockers"]]
    return _openai_error_response(
        503,
        "consumer_not_ready",
        "Local Consumer inference is fail-closed until V3 wallet signing and reservation execution are configured.",
        headers={"Retry-After": "30"},
        extra={
            "mycomesh": {
                "state": status["state"],
                "status_path": "/v1/mycomesh/local/status",
                "blockers": blocker_codes,
            }
        },
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
        "warning": "Keep api_key local. This phase-one client is not inference-ready.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run and initialize the MycoMesh local Consumer.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Serve the localhost OpenAI-compatible API.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8110)

    subparsers.add_parser("credentials", help="Print the volume-local URL and API key.")
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
