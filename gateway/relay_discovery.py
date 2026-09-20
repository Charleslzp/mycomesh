"""Authenticated Relay discovery. Network membership is separate from payment authority."""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import queue
import re
import sqlite3
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .chain import ChainError, EvmSignature, keccak256, parse_private_key, private_key_to_address, recover_evm_address, sign_evm_digest
from .netio import read_bounded

ADMISSION_SCHEMA = "mycomesh.relay-admission.v1"
ANNOUNCEMENT_SCHEMA = "mycomesh.relay-announcement.v1"
DIRECTORY_SCHEMA = "mycomesh.relay-directory.v1"
MAX_RECORD_BYTES = 16 * 1024
MAX_DIRECTORY_BYTES = 1024 * 1024
MAX_RELAYS = 64
MAX_SAFE_INTEGER = 2**53 - 1
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BINDING_FIELDS = frozenset({"network_id", "channel_id", "chain_id", "settlement_contract", "protocol_version",
                            "host", "provider_port", "public_url", "provider_tls", "payment_address", "attestation_address"})
ENDPOINT_FIELDS = frozenset({"host", "provider_port", "public_url", "provider_tls", "payment_address", "attestation_address"})
_HTTP_SLOTS = threading.BoundedSemaphore(8)
_NONPUBLIC_V4 = tuple(ipaddress.ip_network(cidr) for cidr in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "192.88.99.0/24", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
))
_NONPUBLIC_V6 = tuple(ipaddress.ip_network(cidr) for cidr in (
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "3ffe::/16",
))
_PUBLIC_V6 = ipaddress.ip_network("2000::/3")


class DiscoveryError(ValueError):
    pass


def is_public_discovery_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Keep this admission boundary identical to the native Consumer and stable
    # across Python versions' changing special-purpose address classifications.
    if address.version == 4:
        return not any(address in network for network in _NONPUBLIC_V4)
    return address in _PUBLIC_V6 and not any(address in network for network in _NONPUBLIC_V6)


def _integer(value: Any, label: str, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DiscoveryError(f"Invalid discovery {label}")
    return value


def _address(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{40}", value) is None or int(value[2:], 16) == 0:
        raise DiscoveryError("Discovery addresses must be nonzero lowercase EVM addresses")
    return value


def canonical_json(value: Any) -> bytes:
    def check(item: Any, depth: int = 0) -> None:
        if depth > 12:
            raise DiscoveryError("Discovery JSON is too deeply nested")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or any(not 32 <= ord(c) <= 126 for c in key):
                    raise DiscoveryError("Discovery JSON keys must be ASCII")
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            if any(not 32 <= ord(c) <= 126 for c in item):
                raise DiscoveryError("Discovery JSON strings must be ASCII")
        elif type(item) is bool:
            pass
        elif type(item) is int:
            _integer(item, "integer")
        else:
            raise DiscoveryError("Unsupported discovery JSON value")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _json_loads(payload: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise DiscoveryError("Duplicate discovery JSON key")
            result[key] = value
        return result
    try:
        return json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DiscoveryError("Invalid discovery JSON") from exc


def normalize_policy(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) - {"authorities", "threshold", "refresh_seconds", "timeout_seconds"}:
        raise DiscoveryError("Invalid relay_discovery configuration")
    authorities = raw.get("authorities")
    if not isinstance(authorities, list) or not 1 <= len(authorities) <= 16:
        raise DiscoveryError("Discovery requires 1-16 explicit authorities")
    authorities = [_address(item) for item in authorities]
    if len(set(authorities)) != len(authorities):
        raise DiscoveryError("Duplicate discovery authority")
    threshold = _integer(raw.get("threshold"), "threshold", len(authorities) // 2 + 1, len(authorities))
    return {"authorities": authorities, "threshold": threshold,
            "refresh_seconds": _integer(raw.get("refresh_seconds", 30), "refresh_seconds", 1, 120),
            "timeout_seconds": _integer(raw.get("timeout_seconds", 3), "timeout_seconds", 1, 10)}


def normalize_context(raw: Any) -> dict[str, Any]:
    fields = {"network_id", "channel_id", "chain_id", "settlement_contract", "protocol_version", "network_profile"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise DiscoveryError("Invalid discovery network context")
    for key in ("network_id", "channel_id"):
        if not isinstance(raw[key], str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", raw[key]) is None:
            raise DiscoveryError(f"Invalid discovery {key}")
    _integer(raw["chain_id"], "chain_id", 1)
    _address(raw["settlement_contract"])
    if type(raw["protocol_version"]) is not int or raw["protocol_version"] not in {8, 9, 10}:
        raise DiscoveryError("Discovery requires Settlement V8, V9 or V10")
    if raw["network_profile"] not in {"local", "testnet", "open"}:
        raise DiscoveryError("Invalid discovery network profile")
    return dict(raw)


def validate_origin(value: Any, *, network_profile: str, literal: bool = False) -> str:
    if not isinstance(value, str) or not value.isascii() or len(value) > 512 or any(c.isspace() for c in value):
        raise DiscoveryError("Invalid discovery URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
        host = parsed.hostname
        if (not host or parsed.username is not None or parsed.password is not None or parsed.path
                or parsed.query or parsed.fragment or "\\" in value or (port is not None and not 1 <= port <= 65535)):
            raise ValueError("invalid origin")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if literal and address is None:
            raise ValueError("dynamic endpoints require literal IPs")
        if address is not None:
            if "%" in host or getattr(address, "ipv4_mapped", None) is not None:
                raise ValueError("ambiguous IP")
            if network_profile == "local" and address.is_loopback:
                if parsed.scheme not in {"http", "https"}:
                    raise ValueError("invalid local scheme")
            elif not is_public_discovery_address(address) or parsed.scheme != "https":
                raise ValueError("non-public IP or insecure scheme")
        elif parsed.scheme != "https" or re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) is None:
            raise ValueError("invalid bootstrap hostname")
        canonical_host = f"[{address}]" if address is not None and address.version == 6 else str(address or host)
        canonical_port = "" if port is None or port == (443 if parsed.scheme == "https" else 80) else f":{port}"
        if value != f"{parsed.scheme}://{canonical_host}{canonical_port}":
            raise ValueError("noncanonical origin")
    except ValueError as exc:
        raise DiscoveryError("Discovery URL must be a safe HTTPS origin (loopback HTTP only in local profile)") from exc
    return value


def load_discovery_config(path: str | Path) -> dict[str, Any] | None:
    path = Path(path)
    raw = _read_file(path, 64 * 1024)
    if not isinstance(raw, dict):
        raise DiscoveryError("Network manifest must be an object")
    if "relay_discovery" not in raw:
        return None
    policy = normalize_policy(raw["relay_discovery"])
    name = raw.get("deployment")
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise DiscoveryError("Discovery deployment must be a sibling filename")
    deployment = _read_file(path.parent / name, 64 * 1024)
    if not isinstance(deployment, dict):
        raise DiscoveryError("Discovery deployment must be an object")
    context = normalize_context({"network_id": raw.get("network_id"), "channel_id": raw.get("channel_id"),
        "chain_id": deployment.get("chain_id"), "settlement_contract": deployment.get("settlement"),
        "protocol_version": deployment.get("protocol_version"), "network_profile": raw.get("network_profile")})
    if any(deployment.get(key) != context[key] for key in ("network_id", "channel_id")):
        raise DiscoveryError("Discovery manifest and deployment disagree")
    bridges = raw.get("bridge_urls")
    if not isinstance(bridges, list) or not bridges:
        raise DiscoveryError("Discovery requires 1-8 distinct bootstrap Bridges")
    bridges = normalize_bridge_urls(bridges, network_profile=context["network_profile"])
    return {"policy": policy, "context": context, "bridge_urls": list(bridges)}


def normalize_bridge_urls(urls: Any, *, network_profile: str) -> list[str]:
    if not isinstance(urls, (list, tuple)) or len(urls) > 8:
        raise DiscoveryError("Discovery supports at most eight bootstrap Bridges")
    result = [validate_origin(url, network_profile=network_profile) for url in urls]
    if len(set(result)) != len(result):
        raise DiscoveryError("Duplicate discovery bootstrap Bridge")
    return result


def _read_file(path: Path, maximum: int) -> Any:
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise DiscoveryError("Discovery configuration exceeds size limit")
    return _json_loads(data)


def _binding(record: dict[str, Any], context: dict[str, Any]) -> None:
    for key in ("network_id", "channel_id", "chain_id", "settlement_contract", "protocol_version"):
        if record.get(key) != context[key] or type(record.get(key)) is not type(context[key]):
            raise DiscoveryError(f"Relay discovery {key} mismatch")
    _integer(record["provider_port"], "provider_port", 1, 65535)
    for key in ("payment_address", "attestation_address"):
        _address(record[key])
    if type(record["provider_tls"]) is not bool or (context["network_profile"] != "local" and not record["provider_tls"]):
        raise DiscoveryError("Discovered Provider transport requires TLS")
    origin = validate_origin(record["public_url"], network_profile=context["network_profile"], literal=True)
    host = record["host"]
    if not isinstance(host, str) or host != urllib.parse.urlsplit(origin).hostname:
        raise DiscoveryError("Relay Provider host must match its public IP")
    if str(ipaddress.ip_address(host)) != host:
        raise DiscoveryError("Relay host must be a canonical IP address")


def signed_digest(schema: str, unsigned: dict[str, Any]) -> bytes:
    return keccak256((schema + "\n").encode("ascii") + canonical_json(unsigned))


def sign_record(schema: str, unsigned: dict[str, Any], private_key: str) -> str:
    sig = sign_evm_digest(private_key, signed_digest(schema, unsigned))
    return "0x" + sig.r[2:].zfill(64) + sig.s[2:].zfill(64) + format(sig.v, "02x")


def _verify_signature(schema: str, unsigned: dict[str, Any], signature: Any, signer: str) -> None:
    if not isinstance(signature, str) or re.fullmatch(r"0x[0-9a-f]{130}", signature) is None:
        raise DiscoveryError("Invalid discovery signature encoding")
    raw = bytes.fromhex(signature[2:])
    r, s, v = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]
    if not 0 < r < SECP256K1_N or not 0 < s <= SECP256K1_N // 2 or v not in {27, 28}:
        raise DiscoveryError("Noncanonical discovery signature")
    try:
        recovered = recover_evm_address(signed_digest(schema, unsigned), EvmSignature("0x" + raw[:32].hex(), "0x" + raw[32:64].hex(), v))
    except (ChainError, ValueError, ArithmeticError) as exc:
        raise DiscoveryError("Invalid discovery signature") from exc
    if recovered != signer:
        raise DiscoveryError("Discovery signature identity mismatch")


def verify_admission(record: Any, *, policy: dict[str, Any], context: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    if not isinstance(record, dict) or set(record) != BINDING_FIELDS | {"schema", "expires_at", "signatures"}:
        raise DiscoveryError("Invalid Relay admission fields")
    if len(canonical_json(record)) > MAX_RECORD_BYTES or record["schema"] != ADMISSION_SCHEMA:
        raise DiscoveryError("Invalid Relay admission schema or size")
    _binding(record, context)
    _integer(record["expires_at"], "admission expiry", now + 1, now + 366 * 86400)
    signatures = record["signatures"]
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= 16:
        raise DiscoveryError("Invalid Relay admission endorsements")
    unsigned = {key: value for key, value in record.items() if key != "signatures"}
    seen = set()
    for entry in signatures:
        if not isinstance(entry, dict) or set(entry) != {"signer", "signature"}:
            raise DiscoveryError("Invalid Relay admission endorsement")
        signer = _address(entry["signer"])
        if signer in seen or signer not in policy["authorities"]:
            raise DiscoveryError("Duplicate or untrusted discovery authority")
        _verify_signature(ADMISSION_SCHEMA, unsigned, entry["signature"], signer)
        seen.add(signer)
    if len(seen) < policy["threshold"]:
        raise DiscoveryError("Relay admission does not meet authority quorum")
    return copy.deepcopy(record)


def verify_announcement(record: Any, *, policy: dict[str, Any], context: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    if not isinstance(record, dict) or set(record) != BINDING_FIELDS | {"schema", "sequence", "issued_at", "expires_at", "admission", "signature"}:
        raise DiscoveryError("Invalid Relay announcement fields")
    if len(canonical_json(record)) > MAX_RECORD_BYTES or record["schema"] != ANNOUNCEMENT_SCHEMA:
        raise DiscoveryError("Invalid Relay announcement schema or size")
    _binding(record, context)
    _integer(record["sequence"], "sequence", 1)
    _integer(record["issued_at"], "issued_at", 0, now + 30)
    _integer(record["expires_at"], "expires_at", max(now + 1, record["issued_at"] + 1), record["issued_at"] + 300)
    admission = verify_admission(record["admission"], policy=policy, context=context, now=now)
    if any(record[key] != admission[key] or type(record[key]) is not type(admission[key]) for key in BINDING_FIELDS):
        raise DiscoveryError("Relay announcement and admission bindings disagree")
    if record["expires_at"] > admission["expires_at"]:
        raise DiscoveryError("Relay announcement outlives admission")
    _verify_signature(ANNOUNCEMENT_SCHEMA, {k: v for k, v in record.items() if k != "signature"}, record["signature"], record["attestation_address"])
    return copy.deepcopy(record)


def build_admission(binding: dict[str, Any], *, expires_at: int, private_keys: list[str]) -> dict[str, Any]:
    unsigned = {"schema": ADMISSION_SCHEMA, **binding, "expires_at": expires_at}
    return {**unsigned, "signatures": [{"signer": private_key_to_address(parse_private_key(key)),
        "signature": sign_record(ADMISSION_SCHEMA, unsigned, key)} for key in private_keys]}


def build_announcement(admission: dict[str, Any], private_key: str, sequence: int, *, now: int | None = None, ttl_seconds: int = 120) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    _integer(sequence, "sequence", 1)
    _integer(ttl_seconds, "TTL", 1, 300)
    unsigned = {"schema": ANNOUNCEMENT_SCHEMA, **{key: admission[key] for key in BINDING_FIELDS},
                "sequence": sequence, "issued_at": now, "expires_at": min(now + ttl_seconds, admission["expires_at"]),
                "admission": copy.deepcopy(admission)}
    return {**unsigned, "signature": sign_record(ANNOUNCEMENT_SCHEMA, unsigned, private_key)}


class RelayDirectory:
    """SQLite transactions retain sequence watermarks even when an announcement expires."""

    def __init__(self, path: str | Path | None = None, *, policy: dict[str, Any], context: dict[str, Any], max_entries: int = MAX_RELAYS):
        self.policy = normalize_policy(policy)
        self.context = normalize_context(context)
        self.max_entries = _integer(max_entries, "directory limit", 1, MAX_RELAYS)
        self._lock = threading.RLock()
        if path is not None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise DiscoveryError("Discovery cache must be a regular file")
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        self._db = sqlite3.connect(str(path) if path is not None else ":memory:", check_same_thread=False, timeout=3)
        self._db.execute("CREATE TABLE IF NOT EXISTS relay_records (scope TEXT, signer TEXT, sequence INTEGER, record TEXT, PRIMARY KEY(scope, signer))")
        self._db.execute("CREATE TABLE IF NOT EXISTS relay_sequences (scope TEXT, signer TEXT, sequence INTEGER, PRIMARY KEY(scope, signer))")
        self._db.commit()
        self._scope = keccak256(canonical_json(self.context)).hex()
        self._verified: dict[str, dict[str, Any]] = {}
        self._closed = False

    def merge(self, record: Any, *, now: int | None = None) -> bool:
        verified = verify_announcement(record, policy=self.policy, context=self.context, now=now)
        encoded = canonical_json(verified).decode("ascii")
        signer = verified["attestation_address"]
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute("SELECT sequence, record FROM relay_records WHERE scope=? AND signer=?", (self._scope, signer)).fetchone()
                if row:
                    if verified["sequence"] < row[0] or (verified["sequence"] == row[0] and encoded != row[1]):
                        raise DiscoveryError("Relay announcement rollback or same-sequence conflict")
                    if verified["sequence"] == row[0]:
                        self._db.rollback()
                        return False
                else:
                    count = self._db.execute("SELECT count(*) FROM relay_records WHERE scope=?", (self._scope,)).fetchone()[0]
                    if count >= self.max_entries:
                        raise DiscoveryError("Relay directory identity capacity reached")
                self._db.execute("INSERT OR REPLACE INTO relay_records VALUES (?,?,?,?)", (self._scope, signer, verified["sequence"], encoded))
                self._db.commit()
                self._verified[encoded] = verified
                # Keep the in-memory verified cache bounded to current records.
                if len(self._verified) > self.max_entries:
                    self._verified.clear()
                return True
            except BaseException:
                self._db.rollback()
                raise

    def live(self, *, now: int | None = None) -> list[dict[str, Any]]:
        now = int(time.time()) if now is None else now
        result = []
        with self._lock:
            rows = self._db.execute("SELECT record FROM relay_records WHERE scope=? ORDER BY signer LIMIT ?", (self._scope, self.max_entries)).fetchall()
            for (encoded,) in rows:
                try:
                    record = self._verified.get(encoded)
                    if record is None:
                        record = verify_announcement(_json_loads(encoded.encode()), policy=self.policy, context=self.context, now=now)
                        self._verified[encoded] = record
                    if record["expires_at"] > now and record["issued_at"] <= now + 30:
                        result.append(copy.deepcopy(record))
                except (ValueError, TypeError, KeyError):
                    continue
        return result

    def next_sequence(self, signer: str) -> int:
        signer = _address(signer)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute("SELECT sequence FROM relay_sequences WHERE scope=? AND signer=?", (self._scope, signer)).fetchone()
                published = self._db.execute("SELECT sequence FROM relay_records WHERE scope=? AND signer=?", (self._scope, signer)).fetchone()
                sequence = max(row[0] if row else 0, published[0] if published else 0) + 1
                _integer(sequence, "sequence", 1)
                self._db.execute("INSERT OR REPLACE INTO relay_sequences VALUES (?,?,?)", (self._scope, signer, sequence))
                self._db.commit()
                return sequence
            except BaseException:
                self._db.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def request_json(url: str, *, timeout: float = 3, maximum: int = MAX_DIRECTORY_BYTES, body: Any = None) -> Any:
    if not 0 < timeout <= 10 or not 0 < maximum <= MAX_DIRECTORY_BYTES:
        raise DiscoveryError("Invalid discovery HTTP limits")
    data = canonical_json(body) if body is not None else None
    if data is not None and len(data) > MAX_DIRECTORY_BYTES:
        raise DiscoveryError("Discovery request is too large")
    deadline = time.monotonic() + timeout
    request = urllib.request.Request(url, data=data, headers={"Accept": "application/json", "Content-Type": "application/json"})
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)
    if not _HTTP_SLOTS.acquire(blocking=False):
        raise DiscoveryError("Discovery HTTP worker capacity reached")
    def run() -> None:
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
            with opener.open(request, timeout=timeout) as response:
                if response.status != 200:
                    raise DiscoveryError("Discovery endpoint returned unsuccessful status")
                payload = read_bounded(response, maximum=maximum, deadline=deadline, label="discovery response")
            result.put((True, _json_loads(payload)))
        except Exception as exc:
            result.put((False, exc))
        finally:
            _HTTP_SLOTS.release()
    # Socket timeouts do not bound libc DNS. A bounded daemon pool also bounds
    # caller latency when a trusted bootstrap hostname's resolver stalls.
    threading.Thread(target=run, daemon=True, name="relay-discovery-http").start()
    try:
        succeeded, value = result.get(timeout=max(0.001, deadline - time.monotonic()))
    except queue.Empty as exc:
        raise DiscoveryError("Discovery HTTP deadline exceeded") from exc
    if not succeeded:
        raise DiscoveryError("Discovery HTTP request failed") from value
    return value


def fetch_directories(bridge_urls: list[str] | tuple[str, ...], *, timeout: float = 3, network_profile: str = "testnet") -> list[dict[str, Any]]:
    if len(bridge_urls) > 8:
        raise DiscoveryError("Too many discovery bootstrap Bridges")
    results: queue.Queue[list[Any]] = queue.Queue()
    def fetch(url: str) -> None:
        try:
            value = request_json(url + "/relays", timeout=timeout)
            if (isinstance(value, dict) and set(value) == {"schema", "relays"} and value["schema"] == DIRECTORY_SCHEMA
                    and isinstance(value["relays"], list) and len(value["relays"]) <= MAX_RELAYS):
                results.put(value["relays"])
            else:
                results.put([])
        except (ValueError, OSError):
            results.put([])
    pending = 0
    for url in bridge_urls:
        validate_origin(url, network_profile=network_profile)
        threading.Thread(target=fetch, args=(url,), daemon=True, name="relay-directory-fetch").start()
        pending += 1
    records = []
    deadline = time.monotonic() + timeout + 0.1
    for _ in range(pending):
        try:
            records.extend(results.get(timeout=max(0.001, deadline - time.monotonic())))
        except queue.Empty:
            break
    return records


def probe_announcement(record: dict[str, Any], *, policy: dict[str, Any], context: dict[str, Any], timeout: float = 3) -> dict[str, Any]:
    expected = verify_announcement(record, policy=policy, context=context)
    live = request_json(expected["public_url"] + "/relay-announcement", timeout=timeout, maximum=MAX_RECORD_BYTES)
    live = verify_announcement(live, policy=policy, context=context)
    if any(live[key] != expected[key] for key in BINDING_FIELDS) or live["sequence"] < expected["sequence"]:
        raise DiscoveryError("Discovered Relay endpoint identity or sequence mismatch")
    if live["sequence"] == expected["sequence"] and canonical_json(live) != canonical_json(expected):
        raise DiscoveryError("Discovered Relay endpoint equivocated")
    health = request_json(expected["public_url"] + "/health", timeout=timeout, maximum=256 * 1024)
    if (not isinstance(health, dict) or health.get("ok") is not True or health.get("settlement_ready") is not True
            or health.get("relay_payment_address") != expected["payment_address"]
            or health.get("relay_attestation_address") != expected["attestation_address"]):
        raise DiscoveryError("Discovered Relay is unready or has different payment/signing identities")
    return live


class RelayDiscoveryClient:
    def __init__(self, *, policy: dict[str, Any], context: dict[str, Any], bridge_urls: list[str] | tuple[str, ...], cache_path: str | Path):
        self.directory = RelayDirectory(cache_path, policy=policy, context=context)
        self.policy, self.context = self.directory.policy, self.directory.context
        self.bridge_urls = list(bridge_urls)
        if not 1 <= len(self.bridge_urls) <= 8:
            raise DiscoveryError("Discovery requires 1-8 Bridges")
        for url in self.bridge_urls:
            validate_origin(url, network_profile=self.context["network_profile"])
        self._lock = threading.Lock()
        self._refreshed_at = float("-inf")
        self._probe_cursor = 0
        self._lifecycle_lock = threading.Lock()
        self._background: threading.Thread | None = None
        self._closing = False

    @classmethod
    def from_network_manifest(cls, path: str | Path, *, cache_path: str | Path) -> RelayDiscoveryClient | None:
        config = load_discovery_config(path)
        return None if config is None else cls(**config, cache_path=cache_path)

    def refresh(self, *, force: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            if force or time.monotonic() - self._refreshed_at >= self.policy["refresh_seconds"]:
                records = fetch_directories(self.bridge_urls, timeout=self.policy["timeout_seconds"], network_profile=self.context["network_profile"])
                for record in records:
                    try:
                        self.directory.merge(record)
                    except (DiscoveryError, TypeError, KeyError):
                        continue
                self._refreshed_at = time.monotonic()
            return self.directory.live()

    def start_refresh(self) -> None:
        def run() -> None:
            try:
                self.refresh()
            except (OSError, ValueError, sqlite3.Error):
                pass
            finally:
                with self._lifecycle_lock:
                    self._background = None
                    if self._closing:
                        self.directory.close()
        with self._lifecycle_lock:
            if self._closing or self._background is not None:
                return
            self._background = threading.Thread(target=run, name="provider-relay-discovery", daemon=True)
            self._background.start()

    def endpoints(self, *, force: bool = False) -> list[dict[str, Any]]:
        records = self.refresh(force=force)
        if not records:
            return []
        # Bound reconnect latency and rotate across the full directory on later attempts.
        offset = self._probe_cursor % len(records)
        records = (records[offset:] + records[:offset])[:3]
        self._probe_cursor = offset + len(records)
        def probe(record: dict[str, Any]) -> dict[str, Any] | None:
            try:
                live = probe_announcement(record, policy=self.policy, context=self.context, timeout=self.policy["timeout_seconds"])
                self.directory.merge(live)
                return {**{key: live[key] for key in ENDPOINT_FIELDS}, "discovery_expires_at": live["expires_at"]}
            except (DiscoveryError, TypeError, KeyError):
                return None
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="relay-discovery-probe") as executor:
            return [endpoint for endpoint in executor.map(probe, records) if endpoint is not None]

    def close(self) -> None:
        with self._lifecycle_lock:
            self._closing = True
            background = self._background
            if background is None:
                self.directory.close()
                return
        background.join(timeout=self.policy["timeout_seconds"] + 2)
        # A worker still validating a large directory owns closing its database.
        # It is independent of Provider registration callback/heartbeat cleanup.
