#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import os
import re
import secrets
import stat
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


DEFAULT_RPC_URL = (
    "https://sepolia.drpc.org,"
    "https://rpc.sepolia.ethpandaops.io,"
    "https://sepolia.gateway.tenderly.co"
)
DEFAULT_CORS_ORIGINS = "https://mycomesh.xyz,https://app.mycomesh.xyz"
DEFAULT_SESSION_DEPLOYMENT = "/app/deployments/sepolia-myco-v5.json"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ASSIGNMENT = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)=")
PORTABLE_SECRET = re.compile(r"[A-Za-z0-9._~+/=\-]{32,}")
PLACEHOLDER_VALUES = {
    "change-me",
    "change-me-admin-token",
    "change-me-database-password",
    "replace-me",
    "postgresql://mycomesh:change-me-database-password@postgres:5432/mycomesh",
}
REQUIRED_EXISTING_KEYS = (
    "MYCOMESH_ADMIN_TOKEN",
    "MYCOMESH_POSTGRES_DB",
    "MYCOMESH_POSTGRES_USER",
    "MYCOMESH_POSTGRES_PASSWORD",
    "MYCOMESH_BILLING_DB",
    "MYCOMESH_SETTLEMENT_RPC_URL",
    "ETH_RPC_URL",
    "MYCOMESH_SESSION_V4_ENABLED",
    "MYCOMESH_SESSION_PROTOCOL_VERSION",
    "MYCOMESH_SESSION_DEPLOYMENT",
    "MYCOMESH_SESSION_RPC_URL",
    "MYCOMESH_SESSION_KEY_SECRET",
    "MYCOMESH_SESSION_RELAYER_PRIVATE_KEY",
    "MYCOMESH_CORS_ALLOWED_ORIGINS",
    "MYCOMESH_PUBLIC_KEY_REGISTRATION",
    "MYCOMESH_ALLOW_PUBLIC_GATEWAY_REGISTRATION",
    "MYCOMESH_PROXY_BIND_ADDRESS",
    "MYCOMESH_PROXY_HOST_PORT",
)
OPTIONAL_EXISTING_KEYS = (
    "MYCOMESH_SESSION_RELAY_PAYMENT_ADDRESS",
    "MYCOMESH_SESSION_RELAY_ATTESTATION_ADDRESS",
    "MYCOMESH_SESSION_POOL_PAYMENT_ADDRESS",
)
MANAGED_EXISTING_KEYS = REQUIRED_EXISTING_KEYS + OPTIONAL_EXISTING_KEYS


class ConfigurationError(ValueError):
    pass


def _is_placeholder(value: str | None) -> bool:
    normalized = str(value or "").strip().lower()
    return not normalized or normalized in PLACEHOLDER_VALUES


def _is_angle_placeholder(value: str | None) -> bool:
    normalized = str(value or "").strip()
    return normalized.startswith("<") and normalized.endswith(">")


def _strong_secret(current: str | None, *, name: str) -> str:
    if _is_placeholder(current):
        return secrets.token_urlsafe(48)
    if _is_angle_placeholder(current):
        raise ConfigurationError(
            f"{name} contains an unresolved angle-bracket placeholder"
        )
    value = str(current)
    if len(value) < 32:
        raise ConfigurationError(f"{name} must contain at least 32 characters")
    if PORTABLE_SECRET.fullmatch(value) is None:
        raise ConfigurationError(
            f"{name} must use only portable dotenv characters: "
            "letters, digits, dot, underscore, tilde, plus, slash, equals, and hyphen"
        )
    return value


def _private_key(current: str | None) -> str:
    if _is_placeholder(current):
        value = secrets.randbelow(SECP256K1_ORDER - 1) + 1
        return f"0x{value:064x}"
    value = str(current).strip()
    raw = value[2:] if value.startswith("0x") else value
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        raise ConfigurationError("MYCOMESH_SESSION_RELAYER_PRIVATE_KEY must be 32-byte hex")
    parsed = int(raw, 16)
    if not 0 < parsed < SECP256K1_ORDER:
        raise ConfigurationError("MYCOMESH_SESSION_RELAYER_PRIVATE_KEY is outside secp256k1 range")
    return "0x" + raw.lower()


def _optional_address(current: str | None, *, name: str) -> str:
    value = str(current or "").strip()
    if not value:
        return ""
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is None or int(value[2:], 16) == 0:
        raise ConfigurationError(f"{name} must be a non-zero EVM address or empty")
    return value.lower()


def _rpc_urls(current: str | None, fallback: str) -> str:
    value = str(current or fallback).strip()
    endpoints = [item.strip() for item in value.split(",") if item.strip()]
    if not endpoints or len(endpoints) > 4:
        raise ConfigurationError("RPC URL list must contain between one and four endpoints")
    for endpoint in endpoints:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ConfigurationError("RPC endpoints must be credential-free HTTPS URLs")
    return ",".join(endpoints)


def _deployment_path(current: str | None) -> str:
    value = str(current or DEFAULT_SESSION_DEPLOYMENT).strip()
    if _is_angle_placeholder(value):
        raise ConfigurationError(
            "MYCOMESH_SESSION_DEPLOYMENT contains an unresolved angle-bracket placeholder"
        )
    if (
        not value.startswith("/app/deployments/")
        or not value.endswith(".json")
        or ".." in value
    ):
        raise ConfigurationError(
            "MYCOMESH_SESSION_DEPLOYMENT must be a bundled /app/deployments/*.json path"
        )
    return value


def _cors_origins(current: str | None) -> str:
    value = str(current or DEFAULT_CORS_ORIGINS).strip()
    origins = [item.strip() for item in value.split(",") if item.strip()]
    if not origins:
        raise ConfigurationError("MYCOMESH_CORS_ALLOWED_ORIGINS must not be empty")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ConfigurationError(
                "MYCOMESH_CORS_ALLOWED_ORIGINS must contain exact credential-free HTTPS origins"
            )
    return ",".join(origin.rstrip("/") for origin in origins)


def _identifier(current: str | None, default: str, *, name: str) -> str:
    value = str(current or default).strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", value) is None:
        raise ConfigurationError(f"{name} must be a PostgreSQL identifier")
    return value


def _billing_database(
    current: str | None,
    *,
    database: str,
    username: str,
    password: str,
) -> str:
    generated = (
        f"postgresql://{quote(username, safe='')}:{quote(password, safe='')}"
        f"@postgres:5432/{quote(database, safe='')}"
    )
    if _is_placeholder(current):
        return generated
    value = str(current)
    parsed = urlsplit(value)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ConfigurationError("MYCOMESH_BILLING_DB must be a PostgreSQL DSN")
    try:
        port = parsed.port or 5432
    except ValueError as exc:
        raise ConfigurationError("MYCOMESH_BILLING_DB contains an invalid port") from exc
    if (
        parsed.hostname != "postgres"
        or port != 5432
        or unquote(parsed.username or "") != username
        or unquote(parsed.password or "") != password
        or unquote(parsed.path.lstrip("/")) != database
    ):
        raise ConfigurationError(
            "MYCOMESH_BILLING_DB must match the Compose PostgreSQL user, password, and database"
        )
    return value


def _boolean(current: str | None, default: bool, *, name: str) -> str:
    value = str(current or ("true" if default else "false")).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return "true"
    if value in {"0", "false", "no", "off"}:
        return "false"
    raise ConfigurationError(f"{name} must be true or false")


def _loopback_address(current: str | None) -> str:
    value = str(current or "127.0.0.1").strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigurationError(
            "MYCOMESH_PROXY_BIND_ADDRESS must be an IPv4 loopback address"
        ) from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_loopback:
        raise ConfigurationError(
            "MYCOMESH_PROXY_BIND_ADDRESS must be an IPv4 loopback address"
        )
    return str(address)


def _proxy_port(current: str | None) -> str:
    try:
        value = int(str(current or "8100"))
    except ValueError as exc:
        raise ConfigurationError("MYCOMESH_PROXY_HOST_PORT must be an integer") from exc
    if not 1 <= value <= 65535:
        raise ConfigurationError(
            "MYCOMESH_PROXY_HOST_PORT must be between 1 and 65535"
        )
    return str(value)


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = ASSIGNMENT.match(line)
        if match:
            key = match.group("key")
            values[key] = line[len(key) + 1 :]
    return values


def configured_values(current: dict[str, str], *, rpc_url: str) -> dict[str, str]:
    database = _identifier(
        current.get("MYCOMESH_POSTGRES_DB"),
        "mycomesh",
        name="MYCOMESH_POSTGRES_DB",
    )
    username = _identifier(
        current.get("MYCOMESH_POSTGRES_USER"),
        "mycomesh",
        name="MYCOMESH_POSTGRES_USER",
    )
    password = _strong_secret(
        current.get("MYCOMESH_POSTGRES_PASSWORD"),
        name="MYCOMESH_POSTGRES_PASSWORD",
    )
    billing_database = _billing_database(
        current.get("MYCOMESH_BILLING_DB"),
        database=database,
        username=username,
        password=password,
    )

    settlement_rpc = _rpc_urls(current.get("MYCOMESH_SETTLEMENT_RPC_URL"), rpc_url)
    eth_rpc = _rpc_urls(current.get("ETH_RPC_URL"), settlement_rpc)
    if eth_rpc != settlement_rpc:
        raise ConfigurationError(
            "ETH_RPC_URL must match MYCOMESH_SETTLEMENT_RPC_URL for the bundled Indexer"
        )
    session_rpc = _rpc_urls(current.get("MYCOMESH_SESSION_RPC_URL"), settlement_rpc)
    return {
        "MYCOMESH_ADMIN_TOKEN": _strong_secret(
            current.get("MYCOMESH_ADMIN_TOKEN"), name="MYCOMESH_ADMIN_TOKEN"
        ),
        "MYCOMESH_POSTGRES_DB": database,
        "MYCOMESH_POSTGRES_USER": username,
        "MYCOMESH_POSTGRES_PASSWORD": password,
        "MYCOMESH_BILLING_DB": str(billing_database),
        "MYCOMESH_SETTLEMENT_RPC_URL": settlement_rpc,
        "ETH_RPC_URL": eth_rpc,
        "MYCOMESH_SESSION_V4_ENABLED": "true",
        "MYCOMESH_SESSION_PROTOCOL_VERSION": "5",
        "MYCOMESH_SESSION_DEPLOYMENT": _deployment_path(
            current.get("MYCOMESH_SESSION_DEPLOYMENT")
        ),
        "MYCOMESH_SESSION_RPC_URL": session_rpc,
        "MYCOMESH_SESSION_KEY_SECRET": _strong_secret(
            current.get("MYCOMESH_SESSION_KEY_SECRET"), name="MYCOMESH_SESSION_KEY_SECRET"
        ),
        "MYCOMESH_SESSION_RELAYER_PRIVATE_KEY": _private_key(
            current.get("MYCOMESH_SESSION_RELAYER_PRIVATE_KEY")
        ),
        "MYCOMESH_SESSION_RELAY_PAYMENT_ADDRESS": _optional_address(
            current.get("MYCOMESH_SESSION_RELAY_PAYMENT_ADDRESS"),
            name="MYCOMESH_SESSION_RELAY_PAYMENT_ADDRESS",
        ),
        "MYCOMESH_SESSION_RELAY_ATTESTATION_ADDRESS": _optional_address(
            current.get("MYCOMESH_SESSION_RELAY_ATTESTATION_ADDRESS"),
            name="MYCOMESH_SESSION_RELAY_ATTESTATION_ADDRESS",
        ),
        "MYCOMESH_SESSION_POOL_PAYMENT_ADDRESS": _optional_address(
            current.get("MYCOMESH_SESSION_POOL_PAYMENT_ADDRESS"),
            name="MYCOMESH_SESSION_POOL_PAYMENT_ADDRESS",
        ),
        "MYCOMESH_CORS_ALLOWED_ORIGINS": _cors_origins(
            current.get("MYCOMESH_CORS_ALLOWED_ORIGINS")
        ),
        "MYCOMESH_PUBLIC_KEY_REGISTRATION": _boolean(
            current.get("MYCOMESH_PUBLIC_KEY_REGISTRATION"),
            False,
            name="MYCOMESH_PUBLIC_KEY_REGISTRATION",
        ),
        "MYCOMESH_ALLOW_PUBLIC_GATEWAY_REGISTRATION": _boolean(
            current.get("MYCOMESH_ALLOW_PUBLIC_GATEWAY_REGISTRATION"),
            False,
            name="MYCOMESH_ALLOW_PUBLIC_GATEWAY_REGISTRATION",
        ),
        "MYCOMESH_PROXY_BIND_ADDRESS": _loopback_address(
            current.get("MYCOMESH_PROXY_BIND_ADDRESS")
        ),
        "MYCOMESH_PROXY_HOST_PORT": _proxy_port(
            current.get("MYCOMESH_PROXY_HOST_PORT")
        ),
    }


def render_env(text: str, values: dict[str, str]) -> str:
    output: list[str] = []
    replaced: set[str] = set()
    for line in text.splitlines():
        match = ASSIGNMENT.match(line)
        key = match.group("key") if match else None
        if key in values:
            if key not in replaced:
                output.append(f"{key}={values[key]}")
                replaced.add(key)
            continue
        output.append(line)
    missing = [key for key in values if key not in replaced]
    if missing:
        if output and output[-1]:
            output.append("")
        output.append("# Consumer Proxy production configuration (managed by proxy-configure).")
        output.extend(f"{key}={values[key]}" for key in missing)
    return "\n".join(output) + "\n"


def _read_regular_file(path: Path) -> str:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ConfigurationError(
            f"{path} does not exist; create it from .env.deploy.example first"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError(f"{path} must be a regular file, not a symlink or special file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", newline="") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_write(path: Path, text: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextmanager
def _configuration_lock(path: Path):
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def configure(path: Path, *, rpc_url: str = DEFAULT_RPC_URL) -> None:
    with _configuration_lock(path):
        text = _read_regular_file(path)
        values = configured_values(parse_env(text), rpc_url=rpc_url)
        _atomic_write(path, render_env(text, values))


def check(path: Path, *, environ: Mapping[str, str] | None = None) -> None:
    text = _read_regular_file(path)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigurationError(
            f"{path} must not be readable or writable by group/others"
        )
    current = parse_env(text)
    missing = [key for key in REQUIRED_EXISTING_KEYS if _is_placeholder(current.get(key))]
    if missing:
        raise ConfigurationError(
            "Proxy configuration is missing restored production values: "
            + ", ".join(missing)
            + "; restore the environment backup or run proxy-configure only for a new deployment"
        )
    process_environment = os.environ if environ is None else environ
    overridden = sorted(
        key
        for key in MANAGED_EXISTING_KEYS
        if key in process_environment and process_environment[key] != current[key]
    )
    if overridden:
        raise ConfigurationError(
            "host environment overrides differ from the backed-up Proxy configuration: "
            + ", ".join(overridden)
            + "; unset those variables before using Proxy Make targets"
        )
    configured_values(current, rpc_url=current["MYCOMESH_SETTLEMENT_RPC_URL"])
    if (
        _boolean(
            current["MYCOMESH_SESSION_V4_ENABLED"],
            False,
            name="MYCOMESH_SESSION_V4_ENABLED",
        )
        != "true"
    ):
        raise ConfigurationError("MYCOMESH_SESSION_V4_ENABLED must be true")


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure Consumer Proxy production secrets")
    parser.add_argument("--env-file", type=Path, default=Path(".env.deploy"))
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate restored production values without changing the file",
    )
    args = parser.parse_args()
    try:
        if args.check:
            check(args.env_file)
        else:
            configure(args.env_file, rpc_url=args.rpc_url)
    except (ConfigurationError, OSError) as exc:
        parser.error(str(exc))
    if args.check:
        print(f"validated {args.env_file}; no values were changed or printed")
    else:
        print(f"configured {args.env_file} with mode 0600; secret values were not printed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
