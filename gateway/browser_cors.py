from __future__ import annotations

from collections.abc import Iterable
import ipaddress
import re
from urllib.parse import urlsplit


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class CorsConfigurationError(ValueError):
    pass


def parse_allowed_origins(
    value: str | Iterable[str] | None,
    *,
    setting: str,
) -> tuple[str, ...]:
    """Parse an explicit browser-origin allowlist into canonical exact origins."""
    if value is None:
        return ()
    if isinstance(value, str):
        if not value.strip():
            return ()
        entries = value.split(",")
    else:
        entries = list(value)

    origins: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            raise CorsConfigurationError(f"{setting} contains an empty origin")
        origin = normalize_browser_origin(entry, setting=setting)
        if origin not in seen:
            origins.append(origin)
            seen.add(origin)
    return tuple(origins)


def normalize_browser_origin(value: str, *, setting: str) -> str:
    raw = str(value).strip()
    if raw in {"*", "null"}:
        raise CorsConfigurationError(f"{setting} must contain exact origins, not {raw!r}")
    if any(character in raw for character in ("\\", "?", "#")) or any(
        ord(character) < 32 or ord(character) == 127 for character in raw
    ):
        raise CorsConfigurationError(f"{setting} contains an invalid origin: {value!r}")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise CorsConfigurationError(f"{setting} contains an invalid origin: {value!r}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"https", "http"}:
        raise CorsConfigurationError(f"{setting} origins must use https, or http on loopback")
    if parsed.username is not None or parsed.password is not None:
        raise CorsConfigurationError(f"{setting} origins must not contain userinfo")
    if parsed.path or parsed.query or parsed.fragment:
        raise CorsConfigurationError(f"{setting} entries must be origins without a path, query, or fragment")
    hostname = parsed.hostname
    if not hostname:
        raise CorsConfigurationError(f"{setting} origin host is required")
    if port is not None and not 1 <= port <= 65535:
        raise CorsConfigurationError(f"{setting} origin port is out of range")

    host, address = _normalize_origin_host(hostname, setting=setting)
    if scheme == "http" and not _is_loopback_host(host, address):
        raise CorsConfigurationError(f"{setting} permits http only for loopback origins")

    authority = f"[{host}]" if address is not None and address.version == 6 else host
    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}"


def _normalize_origin_host(
    hostname: str,
    *,
    setting: str,
) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    host = hostname.lower()
    if "%" in host:
        raise CorsConfigurationError(f"{setting} origins must not contain scoped or escaped hosts")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return address.compressed, address
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CorsConfigurationError(f"{setting} origin hosts must use ASCII/IDNA form") from exc
    if host.endswith(".") or len(host) > 253:
        raise CorsConfigurationError(f"{setting} contains an invalid origin host")
    if all(character in "0123456789." for character in host):
        raise CorsConfigurationError(f"{setting} contains an ambiguous numeric host")
    if any(not _DNS_LABEL.fullmatch(label) for label in host.split(".")):
        raise CorsConfigurationError(f"{setting} contains an invalid origin host")
    return host, None


def _is_loopback_host(
    host: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
) -> bool:
    if address is not None:
        return address.is_loopback
    return host == "localhost" or host.endswith(".localhost")
