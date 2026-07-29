#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path


def render(address: str, port: int) -> str:
    parsed = ipaddress.ip_address(address)
    if not isinstance(parsed, ipaddress.IPv4Address) or not parsed.is_loopback:
        raise ValueError("Proxy upstream address must be an IPv4 loopback address")
    if not 1 <= port <= 65535:
        raise ValueError("Proxy upstream port must be between 1 and 65535")
    return (
        "upstream mycomesh_gateway {\n"
        f"    server {parsed}:{port} max_fails=2 fail_timeout=5s;\n"
        "    keepalive 16;\n"
        "}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        rendered = render(args.address, args.port)
    except ValueError as exc:
        parser.error(str(exc))
    args.output.write_text(rendered, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
