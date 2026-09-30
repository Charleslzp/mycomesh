"""TLS without certificate authorities: Relays pin their self-signed certificate on-chain.

A Relay announces ``https://IP:PORT#sha256=<hex>`` in the RelayDirectoryV11;
the fingerprint is the SHA-256 of its certificate (DER). Clients complete the
handshake, compare the fingerprint before sending a byte, and never consult a
CA or a domain name, like Bitcoin peers that trust keys rather than names.
"""
from __future__ import annotations

import datetime
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PIN_PREFIX = "#sha256="


class PinError(ssl.SSLError):
    pass


def split_pin(endpoint: str) -> tuple[str, str | None]:
    """``url#sha256=abc`` -> (``url``, ``abc``)."""
    base, _, pin = endpoint.partition(PIN_PREFIX)
    return base, (pin.lower() or None)


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def generate_certificate(cert_path: Path, key_path: Path, host: str, *, days: int = 3650) -> str:
    """Write a self-signed certificate for an IP address or host name; return its pin."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    try:
        alt = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        alt = x509.DNSName(host)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"mycomesh-relay {host}")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=days))
                   .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
                   .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return fingerprint(certificate.public_bytes(serialization.Encoding.DER))


def certificate_pin(cert_path: Path) -> str:
    return fingerprint(ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text()))


def server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def check_pin(sock: ssl.SSLSocket, pin: str) -> None:
    der = sock.getpeercert(binary_form=True)
    if not der or fingerprint(der) != pin:
        sock.close()
        raise PinError("Relay certificate does not match its on-chain pin")


def pinned_context() -> ssl.SSLContext:
    """Handshake without CA checks; the caller must check_pin before sending anything."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def connect(host: str, port: int, *, pin: str | None, ca_file: str | None = None, timeout: float = 10.0) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=timeout)
    if pin:
        sock = pinned_context().wrap_socket(raw, server_hostname=host)
        check_pin(sock, pin)
        return sock
    context = ssl.create_default_context()
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    return context.wrap_socket(raw, server_hostname=host)


def request_json(url: str, *, method: str = "GET", body: Any = None, ca_file: str | None = None,
                 timeout: float = 30.0) -> tuple[int, Any]:
    """HTTP(S) JSON request honouring an optional ``#sha256=`` pin on the URL."""
    base, pin = split_pin(url)
    parts = urlsplit(base)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json", **({"Content-Type": "application/json"} if data else {})}
    if parts.scheme == "http":
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    else:
        port = parts.port or 443
        conn = http.client.HTTPSConnection(parts.hostname, port, timeout=timeout)
        conn.sock = connect(parts.hostname, port, pin=pin, ca_file=ca_file, timeout=timeout)
    try:
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        return response.status, (json.loads(raw) if raw else {})
    finally:
        conn.close()
