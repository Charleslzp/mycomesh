"""The public V11 network manifest shared by Consumers, Relays, Providers and keepers."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evm import normalize_address
from .settlement import Deployment

SCHEMA = "mycomesh.v11.network.v1"


class NetworkError(ValueError):
    pass


@dataclass(frozen=True)
class RelayEntry:
    url: str
    signer: str
    link_host: str | None
    link_port: int | None
    link_tls: bool = True


@dataclass(frozen=True)
class Network:
    network_id: str
    chain_id: int
    settlement: str
    stablecoin: str
    registry: str
    rpc_urls: tuple[str, ...]
    relays: tuple[RelayEntry, ...]
    deployment_block: int
    tls_ca_file: Path | None
    relay_directory: str | None = None
    faucet_url: str | None = None

    @property
    def deployment(self) -> Deployment:
        return Deployment(self.chain_id, self.settlement)

    def all_relays(self) -> list[RelayEntry]:
        """Manifest Relays plus every active Relay announced in the on-chain directory."""
        relays = list(self.relays)
        if self.relay_directory:
            from .directory import list_relays

            known = {relay.signer for relay in relays}
            for entry in list_relays(self.rpc_urls, self.relay_directory):
                if not entry["active"] or entry["signer"] in known:
                    continue
                host, _, port = entry["link"].rpartition(":")
                relays.append(RelayEntry(entry["url"], entry["signer"], host or None, int(port) if host else None))
                known.add(entry["signer"])
        return relays


def load_network(path: str | Path) -> Network:
    path = Path(path)
    try:
        raw: dict[str, Any] = json.loads(path.read_text())
        if raw.get("schema") != SCHEMA:
            raise NetworkError(f"{path} is not a MycoMesh V11 network manifest")
        relays = []
        for entry in raw.get("relays", []):
            host, _, port = str(entry.get("link") or "").rpartition(":")
            relays.append(RelayEntry(str(entry["url"]).rstrip("/"), normalize_address(entry["signer"]),
                                     host or None, int(port) if host else None, bool(entry.get("link_tls", True))))
        ca = raw.get("tls_ca_file")
        return Network(
            network_id=str(raw["network_id"]), chain_id=int(raw["chain_id"]),
            settlement=normalize_address(raw["settlement"]), stablecoin=normalize_address(raw["stablecoin"]),
            registry=normalize_address(raw["registry"]), rpc_urls=tuple(str(url) for url in raw["rpc_urls"]),
            relays=tuple(relays), deployment_block=int(raw.get("deployment_block", 0)),
            tls_ca_file=(path.parent / ca) if ca else None,
            relay_directory=normalize_address(raw["relay_directory"]) if raw.get("relay_directory") else None,
            faucet_url=str(raw["faucet_url"]).rstrip("/") if raw.get("faucet_url") else None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, NetworkError):
            raise
        raise NetworkError(f"invalid network manifest {path}: {exc}") from exc
