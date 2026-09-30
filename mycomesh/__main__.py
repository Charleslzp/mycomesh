"""mycomesh: run a V11 Relay, Provider or bridge keeper, and bind their keys on-chain.

  python -m mycomesh key new FILE
  python -m mycomesh relay register|serve|earnings|claim --network N ...
  python -m mycomesh provider register|serve|earnings|claim --network N ...
  python -m mycomesh keeper serve --network N ...
  python -m mycomesh monitor serve --network N [--webhook URL]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import signal
import sys
import threading
from pathlib import Path

from . import account, jury, rpc
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

def _need(args: argparse.Namespace, *names: str) -> None:
    missing = [f"--{name.replace('_', '-')}" for name in names if not getattr(args, name, None)]
    if missing:
        raise SystemExit(f"{args.role} {args.action} needs {', '.join(missing)}")


def earnings(args: argparse.Namespace, network: Network) -> None:
    owner = args.owner or (address_of(read_key(args.owner_key)) if args.owner_key else None)
    if not owner:
        raise SystemExit("earnings needs --owner ADDRESS or --owner-key")
    print(json.dumps(account.summary(network, owner.lower()), indent=2))


def claim(args: argparse.Namespace, network: Network) -> None:
    _need(args, "owner_key")
    owner = read_key(args.owner_key)
    address = address_of(owner)
    before = account.summary(network, address)
    # Matured holdback moves to claimable first; then everything claimable is paid out.
    if before["holdback"]:
        _send(network, owner, network.settlement, account.encode_release_holdback(address))
    claimable = account.summary(network, address)["claimable"]
    if claimable:
        _send(network, owner, network.settlement, account.encode_claim())
    print(json.dumps({"owner": address, "claimed": claimable, "holdback_before": before["holdback"]}))


def relay_register(args: argparse.Namespace, network: Network) -> None:
    _need(args, "owner_key", "signer_key")
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
    url, link = args.public_url, args.public_link
    if args.public_host:
        # Self-signed and pinned: the directory entry itself says which certificate to expect.
        from .tlspin import PIN_PREFIX, certificate_pin

        pin = f"{PIN_PREFIX}{certificate_pin(Path(args.tls_cert))}" if args.tls_cert else ""
        url = f"https://{args.public_host}:{args.public_http_port}{pin}"
        link = f"{args.public_host}:{args.public_link_port}{pin}"
    if url:
        if not network.relay_directory:
            raise SystemExit("this network has no relay directory")
        from .directory import encode_announce

        _send(network, owner, network.relay_directory, encode_announce(address_of(signer), url, link or ""))
        print(f"announced {url}")
    print(f"relay owner {address_of(owner)} signer {address_of(signer)}")


def relay_cert(args: argparse.Namespace, network: Network) -> None:
    """Create a self-signed certificate; its SHA-256 pin goes on-chain with the announcement."""
    from .tlspin import generate_certificate

    if not args.public_host or not args.tls_cert or not args.tls_key:
        raise SystemExit("relay cert needs --public-host, --tls-cert and --tls-key")
    if Path(args.tls_cert).exists():
        raise SystemExit(f"{args.tls_cert} already exists")
    print(generate_certificate(Path(args.tls_cert), Path(args.tls_key), args.public_host))


def relay_serve(args: argparse.Namespace, network: Network) -> None:
    from .relay.core import RelayCore
    from .relay.disputes import DisputeDesk
    from .relay.probes import ProbeRunner
    from .relay.server import RelayServer

    _need(args, "owner_key", "signer_key")
    owner, signer = read_key(args.owner_key), read_key(args.signer_key)
    reader = SettlementReader(network.rpc_urls, network.deployment)
    cases = jury.CaseReader(network.rpc_urls, network.deployment, network.registry)
    faucet = None
    if args.faucet_key:
        from .relay.faucet import Faucet

        faucet = Faucet(read_key(args.faucet_key), network.rpc_urls, network.stablecoin, Path(args.data_dir))
    core = RelayCore(network.deployment, signer, reader, Path(args.data_dir))
    desk = DisputeDesk(core, cases, owner, network.rpc_urls)
    probes = ProbeRunner(core, cases, desk, owner_private=owner, submitter_private=owner, rpc_url=network.rpc_urls,
                         max_fee=args.probe_max_fee, ledger=network.probe_ledger) if args.probe_interval > 0 else None
    tls = None
    if args.tls_cert:
        from .tlspin import server_context

        tls = server_context(Path(args.tls_cert), Path(args.tls_key))
    server = RelayServer(core, _address(args.http), _address(args.link), owner, network.rpc_urls, args.dispute_window,
                         settle_interval=args.settle_interval, settle_count=args.settle_count, desk=desk, probes=probes,
                         probe_interval=args.probe_interval or 3_600.0, faucet=faucet, link_tls=tls, http_tls=tls)
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
    _need(args, "owner_key", "signer_key", "operator_id")
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

    _need(args, "signer_key")
    if not args.model:
        raise SystemExit("provider serve needs at least one --model")
    worker = ProviderWorker(
        identity=load_or_create_identity(args.identity), provider_private=read_key(args.signer_key),
        deployment=network.deployment, backend=_backend(args),
        prices=Prices(args.price_input, args.price_output, args.price_min), models=tuple(args.model),
        data_dir=Path(args.data_dir), capacity=args.capacity,
        cases=jury.CaseReader(network.rpc_urls, network.deployment, network.registry), jury_model=args.jury_model,
    )
    ca = str(network.tls_ca_file) if network.tls_ca_file else None

    def endpoints() -> dict[str, RelayEndpoint]:
        try:
            relays = network.all_relays()
        except rpc.RpcError as exc:
            log.warning("relay directory unreadable, using the manifest: %s", exc)
            relays = list(network.relays)
        return {relay.signer: RelayEndpoint(relay.link_host, relay.link_port, tls=relay.link_tls, ca_file=ca,
                                            signer=relay.signer, pin=relay.pin) for relay in relays if relay.link_host}

    serving = endpoints()
    if not serving:
        raise SystemExit("no Relay link endpoints in the manifest or directory")
    stop = threading.Event()
    links = run_provider(worker, list(serving.values()), stop)
    log.info("provider %s linking to %s", worker.signer, ", ".join(f"{e.host}:{e.port}" for e in serving.values()))

    def follow_directory() -> None:
        # Relays that announce themselves later are joined without a restart.
        while not stop.wait(600):
            fresh = {signer: endpoint for signer, endpoint in endpoints().items() if signer not in serving}
            if fresh:
                serving.update(fresh)
                links.extend(run_provider(worker, list(fresh.values()), stop))
                log.info("provider joined %s", ", ".join(f"{e.host}:{e.port}" for e in fresh.values()))

    threading.Thread(target=follow_directory, daemon=True).start()
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


def monitor_serve(args: argparse.Namespace, network: Network) -> None:
    from .monitor import Monitor

    monitor = Monitor(network, tuple(address.lower() for address in args.watch or ()), int(args.min_eth * 10**18),
                      args.webhook or os.environ.get("MYCOMESH_ALERT_WEBHOOK"), args.webhook_format)
    stop = threading.Event()
    thread = threading.Thread(target=monitor.run, args=(stop,), kwargs={"interval": args.interval}, daemon=True)
    thread.start()
    log.info("monitoring %s", network.network_id)
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
    relay.add_argument("action", choices=["register", "serve", "earnings", "claim", "cert"])
    common(relay)
    relay.add_argument("--owner-key", help="pays gas, owns probe keys and bonds, receives the Relay share")
    relay.add_argument("--owner", help="earnings: owner address instead of a key")
    relay.add_argument("--signer-key", help="signs dispatches")
    relay.add_argument("--public-url", help="register: announce this HTTPS URL in the relay directory")
    relay.add_argument("--public-link", help="register: announce this host:port for Provider links")
    relay.add_argument("--faucet-key", help="serve: run the testnet faucet from this funded key")
    relay.add_argument("--tls-cert", help="serve: terminate TLS with this certificate; register: pin it on-chain")
    relay.add_argument("--tls-key", help="serve: the certificate's private key")
    relay.add_argument("--public-host", help="register: public IP or name; announces pinned https and link endpoints")
    relay.add_argument("--public-http-port", type=int, default=10443)
    relay.add_argument("--public-link-port", type=int, default=10991)
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
    provider.add_argument("action", choices=["register", "serve", "earnings", "claim"])
    common(provider)
    provider.add_argument("--signer-key", help="signs receipts, transport keys and jury votes")
    provider.add_argument("--owner-key", help="register/claim: receives payouts and pays gas")
    provider.add_argument("--owner", help="earnings: owner address instead of a key")
    provider.add_argument("--identity", default="data/node-identity.json")
    provider.add_argument("--operator-id", default="")
    provider.add_argument("--data-dir", default="data")
    provider.add_argument("--backend", choices=["codex", "openai", "anthropic"], default="codex")
    provider.add_argument("--codex-home", default=os.path.expanduser("~/.codex"))
    provider.add_argument("--codex-command", default="codex")
    provider.add_argument("--base-url")
    provider.add_argument("--api-key-env", help="environment variable holding the backend API key")
    provider.add_argument("--model", action="append")
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

    monitor = sub.add_parser("monitor", help="health checks and alerts")
    monitor.add_argument("action", choices=["serve"])
    common(monitor)
    monitor.add_argument("--watch", action="append", help="also alert when this address runs low on gas")
    monitor.add_argument("--min-eth", type=float, default=0.01)
    monitor.add_argument("--webhook", help="POST alerts here (or set MYCOMESH_ALERT_WEBHOOK)")
    monitor.add_argument("--webhook-format", choices=["json", "slack", "feishu"], default="json")
    monitor.add_argument("--interval", type=float, default=60.0)
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
        ("keeper", "serve"): keeper_serve, ("monitor", "serve"): monitor_serve,
        ("relay", "earnings"): earnings, ("relay", "claim"): claim, ("relay", "cert"): relay_cert,
        ("provider", "earnings"): earnings, ("provider", "claim"): claim,
    }
    commands[(args.role, args.action)](args, network)
    return 0


if __name__ == "__main__":
    sys.exit(main())
