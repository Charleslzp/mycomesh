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
    pin: str | None = None  # self-signed certificate pin from the directory (see tlspin)


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
    probe_ledger: str | None = None
    emission: str | None = None
    token: str | None = None
    emission_block: int = 0
    capability_floors: dict[int, float] | None = None  # per tier, from the manifest's tiers.<n>.capability_floor

    @property
    def deployment(self) -> Deployment:
        return Deployment(self.chain_id, self.settlement)

    def all_relays(self) -> list[RelayEntry]:
        """Manifest Relays plus every active Relay announced in the on-chain directory."""
        relays = list(self.relays)
        if self.relay_directory:
            from .directory import list_relays

            from dataclasses import replace

            from .tlspin import split_pin

            known = {relay.signer: index for index, relay in enumerate(relays)}
            for entry in list_relays(self.rpc_urls, self.relay_directory):
                if not entry["active"]:
                    continue
                if entry["signer"] in known:
                    # A manifest Relay that also pinned its certificate on-chain is checked by the pin.
                    index = known[entry["signer"]]
                    relays[index] = replace(relays[index], pin=split_pin(entry["url"])[1] or relays[index].pin)
                    continue
                url, pin = split_pin(entry["url"])
                link, _ = split_pin(entry["link"])
                host, _, port = link.rpartition(":")
                relays.append(RelayEntry(url, entry["signer"], host or None, int(port) if host else None, True, pin))
                known[entry["signer"]] = len(relays) - 1
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
            probe_ledger=normalize_address(raw["probe_ledger"]) if raw.get("probe_ledger") else None,
            emission=normalize_address(raw["emission"]) if raw.get("emission") else None,
            token=normalize_address(raw["token"]) if raw.get("token") else None,
            emission_block=int(raw.get("emission_block", 0)),
            capability_floors={int(tier): float(config["capability_floor"]) for tier, config in (raw.get("tiers") or {}).items()
                               if isinstance(config, dict) and "capability_floor" in config} or None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, NetworkError):
            raise
        raise NetworkError(f"invalid network manifest {path}: {exc}") from exc
