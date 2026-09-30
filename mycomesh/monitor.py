"""Network health checks with alerts on every state change."""
from __future__ import annotations

import json
import logging
import threading
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import rpc

log = logging.getLogger("mycomesh.monitor")


@dataclass
class Monitor:
    network: Any
    watch: tuple[str, ...] = ()
    min_eth_wei: int = 10**16
    webhook: str | None = None
    webhook_format: str = "json"
    _state: dict[str, str] = field(default_factory=dict, init=False)

    def check(self) -> dict[str, str]:
        """name -> "ok" or a problem description."""
        results: dict[str, str] = {}
        try:
            relays = self.network.all_relays()
        except rpc.RpcError as exc:
            relays = list(self.network.relays)
            results["directory"] = f"unreadable: {exc}"
        watched = set(self.watch)
        for relay in relays:
            name = f"relay {relay.url}"
            try:
                from .tlspin import PIN_PREFIX, request_json

                url = relay.url + "/health" + (f"{PIN_PREFIX}{relay.pin}" if relay.pin else "")
                status, health = request_json(url, ca_file=str(self.network.tls_ca_file) if self.network.tls_ca_file else None,
                                              timeout=10)
                if status != 200:
                    raise OSError(f"HTTP {status}")
                problems = []
                if health.get("relay_signer") != relay.signer:
                    problems.append("reports a different signer")
                if not health.get("providers"):
                    problems.append("no Providers connected")
                if (health.get("settlement_worker") or {}).get("error"):
                    problems.append(f"settlement worker error {health['settlement_worker']['error']}")
                results[name] = "; ".join(problems) or "ok"
            except (OSError, ValueError) as exc:
                results[name] = f"unreachable: {exc}"
            try:
                owner = "0x" + rpc.eth_call(self.network.rpc_urls, self.network.settlement,
                                            "0x" + _selector("relaySignerOwner(address)") + relay.signer[2:].rjust(64, "0"))[-40:]
                watched.add(owner)
            except rpc.RpcError:
                pass
        for address in sorted(watched):
            try:
                balance = rpc.quantity(rpc.call(self.network.rpc_urls, "eth_getBalance", [address, "latest"]))
                results[f"gas {address}"] = "ok" if balance >= self.min_eth_wei else f"low: {balance / 1e18:.4f} ETH"
            except rpc.RpcError as exc:
                results[f"gas {address}"] = f"unreadable: {exc}"
        return results

    def cycle(self) -> list[str]:
        """Check once; alert on transitions and return the alert lines."""
        alerts = []
        for name, status in self.check().items():
            previous = self._state.get(name)
            if previous != status and (previous is not None or status != "ok"):
                alerts.append(f"RESOLVED {name}" if status == "ok" else f"ALERT {name}: {status}")
            self._state[name] = status
        for line in alerts:
            log.warning(line)
        if alerts and self.webhook:
            self._notify("\n".join(alerts))
        return alerts

    def _notify(self, text: str) -> None:
        text = f"[MycoMesh {self.network.network_id}]\n{text}"
        body = {"text": text} if self.webhook_format in {"json", "slack"} else {"msg_type": "text", "content": {"text": text}}
        request = urllib.request.Request(self.webhook, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(request, timeout=10).close()
        except OSError as exc:
            log.warning("webhook failed: %s", exc)

    def run(self, stop: threading.Event, *, interval: float = 60.0) -> None:
        while not stop.is_set():
            try:
                self.cycle()
            except Exception as exc:  # keep watching
                log.warning("monitor cycle failed: %s", exc)
            stop.wait(interval)


def _selector(signature: str) -> str:
    from .evm import function_selector

    return function_selector(signature).hex()
