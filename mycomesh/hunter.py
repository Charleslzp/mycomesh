"""Third-party hunting: probe any Provider through the public Relays and accuse cheaters for a bounty.

A hunter is an ordinary Consumer to every Relay and Provider. It reaches
Providers through the Relays' public routes, uses the same ProbeRunner as a
Relay (hidden commitments, batch voids, verdicts, capability cases), and
publishes its evidence to every Relay's evidence desk, where juries are run.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from . import jury
from .network import Network, RelayEntry
from .relay.probes import ProbeRunner, Target
from .tlspin import PIN_PREFIX, request_json

log = logging.getLogger("mycomesh.hunter")


def _url(relay: RelayEntry, path: str) -> str:
    return relay.url + path + (f"{PIN_PREFIX}{relay.pin}" if relay.pin else "")


def relay_targets(network: Network, cases: jury.CaseReader) -> list[Target]:
    """Every Provider every reachable Relay offers, with a sender through that Relay."""
    ca = str(network.tls_ca_file) if network.tls_ca_file else None
    targets, owners = [], {}
    for relay in network.all_relays():
        try:
            status, body = request_json(_url(relay, "/providers"), ca_file=ca, timeout=10)
        except OSError as exc:
            log.info("relay %s unreachable: %s", relay.url, exc)
            continue
        if status != 200:
            continue

        def send(payload: dict[str, Any], relay: RelayEntry = relay) -> dict[str, Any]:
            code, reply = request_json(_url(relay, "/v11/requests"), method="POST", body=payload, ca_file=ca, timeout=330)
            if code != 200:
                raise OSError(f"relay answered {code}: {str(reply.get('error'))[:200]}")
            return reply

        for descriptor in body.get("providers", []):
            signer = str(descriptor["provider_signer"]).lower()
            if signer not in owners:
                owners[signer] = cases.provider_signer_owner(signer)
            targets.append(Target(signer, owners[signer], descriptor, relay.signer, send))
    return targets


def publisher(network: Network):
    """Hand evidence to every Relay's desk: any of them can run the jury."""
    ca = str(network.tls_ca_file) if network.tls_ca_file else None

    def publish(evidence: dict[str, Any]) -> None:
        accepted = 0
        for relay in network.all_relays():
            try:
                status, _ = request_json(_url(relay, "/v11/evidence"), method="POST", body=evidence, ca_file=ca, timeout=60)
                accepted += status == 200
            except OSError:
                continue
        if not accepted:
            log.warning("no Relay accepted evidence %s", evidence.get("schema"))

    return publish


def faucet_funder(network: Network):
    """Fund each fresh probe owner from the testnet faucet, like any new user: nothing links it to the hunter."""
    ca = str(network.tls_ca_file) if network.tls_ca_file else None

    def fund(owner: str, units: int) -> None:
        status, body = request_json(network.faucet_url + "/v11/faucet", method="POST", body={"address": owner},
                                    ca_file=ca, timeout=400)
        if status != 200:
            raise OSError(f"faucet refused {owner}: {body.get('error')}")

    return fund


def load_questions(path: Path) -> list[dict[str, str]]:
    """Custom capability questions, one JSON object per line: {"question", "reference", "grader"}."""
    from .capability import CUSTOM, build_capability_task

    questions = []
    for line in path.read_text().splitlines():
        if line.strip():
            item = json.loads(line)
            build_capability_task(CUSTOM, item)  # validate now, not mid-probe
            questions.append({"question": item["question"], "reference": str(item["reference"]), "grader": item["grader"]})
    return questions


def hunter_runner(network: Network, hunter_private: str, data_dir: Path, *, probe_owner_private: str | None = None,
                  questions: list[dict[str, str]] | None = None, funder: Any = None) -> ProbeRunner:
    cases = jury.CaseReader(network.rpc_urls, network.deployment, network.registry)
    return ProbeRunner(None, cases, None, owner_private=hunter_private, rpc_url=network.rpc_urls, data_dir=data_dir,
                       targets=lambda: relay_targets(network, cases), publish=publisher(network), funder=funder,
                       probe_owner_private=probe_owner_private, custom_tasks=questions or (), ledger=network.probe_ledger,
                       capability_floors=network.capability_floors)
