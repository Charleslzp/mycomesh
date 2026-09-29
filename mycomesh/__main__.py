"""mycomesh: run a V11 Relay, Provider or bridge keeper, and bind their keys on-chain.

  python -m mycomesh key new FILE
  python -m mycomesh relay register|serve  --network N ...
  python -m mycomesh provider register|serve --network N ...
  python -m mycomesh keeper serve --network N ...
"""
from __future__ import annotations

import argparse
import logging
import os
import secrets
import signal
import sys
import threading
from pathlib import Path

from . import jury, rpc
from .evm import address_of, encode_call, keccak256
from .identity import load_or_create_identity
from .network import Network, load_network
from .protocol import Prices
from .settlement import SettlementReader

log = logging.getLogger("mycomesh")


def read_key(path: str) -> str:
    value = Path(path).read_text().strip()
    return value if value.startswith("0x") else "0x" + value


def write_key(path: str) -> str:
    target = Path(path)
    if target.exists():
        raise SystemExit(f"{path} already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    private = "0x" + secrets.token_hex(32)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(private + "\n")
    return address_of(private)


def _address(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host, int(port)


def _send(network: Network, key: str, to: str, calldata: str) -> None:
    tx = rpc.send_transaction(network.rpc_urls, key, to=to, data=calldata)
    rpc.wait_for_receipt(network.rpc_urls, tx)
    print(f"  {tx}")


def _wait_forever(stop: threading.Event) -> None:
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()


# ---------------- relay ----------------

def relay_register(args: argparse.Namespace, network: Network) -> None:
    owner, signer = read_key(args.owner_key), read_key(args.signer_key)
    reader = SettlementReader(network.rpc_urls, network.deployment)
    if reader.relay_owner(address_of(signer)) != address_of(owner):
        _send(network, owner, network.settlement,
              encode_call("authorizeRelaySigner(address)", ["address"], [address_of(signer)]))
    # Reporter bonds for failed probes come from the owner's wallet.
    _send(network, owner, network.stablecoin,
          encode_call("approve(address,uint256)", ["address", "uint256"], [network.settlement, 2**255]))
    if args.deposit:
        _send(network, owner, network.settlement, encode_call("deposit(uint256)", ["uint256"], [args.deposit]))
    print(f"relay owner {address_of(owner)} signer {address_of(signer)}")


def relay_serve(args: argparse.Namespace, network: Network) -> None:
    from .relay.core import RelayCore
    from .relay.disputes import DisputeDesk
    from .relay.probes import ProbeRunner
    from .relay.server import RelayServer

    owner, signer = read_key(args.owner_key), read_key(args.signer_key)
    reader = SettlementReader(network.rpc_urls, network.deployment)
    cases = jury.CaseReader(network.rpc_urls, network.deployment, network.registry)
    core = RelayCore(network.deployment, signer, reader, Path(args.data_dir))
    desk = DisputeDesk(core, cases, owner, network.rpc_urls)
    probes = ProbeRunner(core, cases, desk, owner_private=owner, submitter_private=owner, rpc_url=network.rpc_urls,
                         max_fee=args.probe_max_fee) if args.probe_interval > 0 else None
    server = RelayServer(core, _address(args.http), _address(args.link), owner, network.rpc_urls, args.dispute_window,
                         settle_interval=args.settle_interval, settle_count=args.settle_count, desk=desk, probes=probes,
                         probe_interval=args.probe_interval or 3_600.0)
    server.start()
    log.info("relay %s serving http %s link %s", core.signer, server.http_address, server.link_address)
    stop = threading.Event()
    _wait_forever(stop)
    server.stop()


# ---------------- provider ----------------

def _backend(args: argparse.Namespace):
    from .provider.backends import AnthropicBackend, OpenAICompatibleBackend
    from .provider.codex import CodexBackend

    api_key = os.environ.get(args.api_key_env, "") if args.api_key_env else ""
    if args.backend == "codex":
        return CodexBackend(codex_home=args.codex_home, command=args.codex_command, timeout=args.timeout,
                            max_concurrent=args.capacity)
    if args.backend == "anthropic":
        return AnthropicBackend(api_key, **({"base_url": args.base_url} if args.base_url else {}))
    return OpenAICompatibleBackend(args.base_url or "https://api.openai.com/v1", api_key, timeout=args.timeout)


def provider_register(args: argparse.Namespace, network: Network) -> None:
    if not args.owner_key or not args.operator_id:
        raise SystemExit("provider register needs --owner-key and --operator-id")
    owner, signer = read_key(args.owner_key), read_key(args.signer_key)
    identity = load_or_create_identity(args.identity)
    reader = SettlementReader(network.rpc_urls, network.deployment)
    if reader.provider_owner(address_of(signer)) != address_of(owner):
        _send(network, owner, network.settlement,
              encode_call("authorizeProviderSigner(address)", ["address"], [address_of(signer)]))
    hashes = ["0x" + keccak256(value.encode()).hex()
              for value in (args.operator_id, identity.peer_id, ",".join(sorted(args.model)))]
    # Jury votes are signed with the Provider signer, so Relays can reach every juror over its link.
    _send(network, owner, network.registry, encode_call(
        "register(address,bytes32,bytes32,bytes32)", ["address", "bytes32", "bytes32", "bytes32"],
        [address_of(signer), *hashes]))
    print(f"provider owner {address_of(owner)} signer {address_of(signer)} peer {identity.peer_id}")


def provider_serve(args: argparse.Namespace, network: Network) -> None:
    from .provider.link import RelayEndpoint, run_provider
    from .provider.worker import ProviderWorker

    worker = ProviderWorker(
        identity=load_or_create_identity(args.identity), provider_private=read_key(args.signer_key),
        deployment=network.deployment, backend=_backend(args),
        prices=Prices(args.price_input, args.price_output, args.price_min), models=tuple(args.model),
        data_dir=Path(args.data_dir), capacity=args.capacity,
        cases=jury.CaseReader(network.rpc_urls, network.deployment, network.registry), jury_model=args.jury_model,
    )
    ca = str(network.tls_ca_file) if network.tls_ca_file else None
    endpoints = [RelayEndpoint(relay.link_host, relay.link_port, tls=relay.link_tls, ca_file=ca)
                 for relay in network.relays if relay.link_host]
    if not endpoints:
        raise SystemExit("the network manifest lists no Relay link endpoints")
    stop = threading.Event()
    links = run_provider(worker, endpoints, stop)
    log.info("provider %s linking to %s", worker.signer, ", ".join(f"{e.host}:{e.port}" for e in endpoints))
    _wait_forever(stop)
    for link in links:
        link.join(timeout=5)


# ---------------- keeper ----------------

def keeper_serve(args: argparse.Namespace, network: Network) -> None:
    from .keeper import Keeper

    keeper = Keeper(jury.CaseReader(network.rpc_urls, network.deployment, network.registry), read_key(args.key),
                    Path(args.data_dir), start_block=network.deployment_block, grace=args.grace)
    log.info("keeper %s following %s from block %d", address_of(keeper.key_private), network.settlement,
             network.deployment_block)
    stop = threading.Event()
    thread = threading.Thread(target=keeper.run, args=(stop,), kwargs={"interval": args.interval}, daemon=True)
    thread.start()
    _wait_forever(stop)
    thread.join(timeout=10)


# ---------------- entry ----------------

def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="mycomesh", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = root.add_subparsers(dest="role", required=True)

    key = sub.add_parser("key", help="create or inspect an EVM key file")
    key.add_argument("action", choices=["new", "address"])
    key.add_argument("file")

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--network", required=True, help="MycoMesh V11 network manifest")

    relay = sub.add_parser("relay", help="Relay commands")
    relay.add_argument("action", choices=["register", "serve"])
    common(relay)
    relay.add_argument("--owner-key", required=True, help="pays gas, owns probe keys and bonds")
    relay.add_argument("--signer-key", required=True, help="signs dispatches")
    relay.add_argument("--data-dir", default="data")
    relay.add_argument("--http", default="127.0.0.1:11100")
    relay.add_argument("--link", default="127.0.0.1:11101")
    relay.add_argument("--dispute-window", type=int, default=86_400)
    relay.add_argument("--settle-interval", type=float, default=600.0)
    relay.add_argument("--settle-count", type=int, default=32)
    relay.add_argument("--probe-interval", type=float, default=3_600.0, help="mean seconds between probes; 0 disables")
    relay.add_argument("--probe-max-fee", type=int, default=200_000)
    relay.add_argument("--deposit", type=int, default=0, help="register: stablecoin units to deposit for probes")

    provider = sub.add_parser("provider", help="Provider commands")
    provider.add_argument("action", choices=["register", "serve"])
    common(provider)
    provider.add_argument("--signer-key", required=True, help="signs receipts, transport keys and jury votes")
    provider.add_argument("--owner-key", help="register: receives payouts and pays gas")
    provider.add_argument("--identity", default="data/node-identity.json")
    provider.add_argument("--operator-id", default="")
    provider.add_argument("--data-dir", default="data")
    provider.add_argument("--backend", choices=["codex", "openai", "anthropic"], default="codex")
    provider.add_argument("--codex-home", default=os.path.expanduser("~/.codex"))
    provider.add_argument("--codex-command", default="codex")
    provider.add_argument("--base-url")
    provider.add_argument("--api-key-env", help="environment variable holding the backend API key")
    provider.add_argument("--model", action="append", required=True)
    provider.add_argument("--jury-model")
    provider.add_argument("--price-input", type=int, default=1_000, help="stablecoin units per 1k input tokens")
    provider.add_argument("--price-output", type=int, default=4_000, help="stablecoin units per 1k output tokens")
    provider.add_argument("--price-min", type=int, default=100)
    provider.add_argument("--capacity", type=int, default=1)
    provider.add_argument("--timeout", type=float, default=300.0)

    keeper = sub.add_parser("keeper", help="bridge keeper")
    keeper.add_argument("action", choices=["serve"])
    common(keeper)
    keeper.add_argument("--key", required=True)
    keeper.add_argument("--data-dir", default="data")
    keeper.add_argument("--grace", type=int, default=3_600)
    keeper.add_argument("--interval", type=float, default=60.0)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=os.environ.get("MYCOMESH_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s", stream=sys.stdout)
    if args.role == "key":
        print(write_key(args.file) if args.action == "new" else address_of(read_key(args.file)))
        return 0
    network = load_network(args.network)
    commands = {
        ("relay", "register"): relay_register, ("relay", "serve"): relay_serve,
        ("provider", "register"): provider_register, ("provider", "serve"): provider_serve,
        ("keeper", "serve"): keeper_serve,
    }
    commands[(args.role, args.action)](args, network)
    return 0


if __name__ == "__main__":
    sys.exit(main())
