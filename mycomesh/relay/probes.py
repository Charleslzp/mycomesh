"""Relay probes: free known-answer requests whose cost the Provider bears.

The Relay owner commits a Merkle root of fresh probe keys before using them,
then sends ordinary sealed requests with those keys to its own Providers. A
probe looks like any paid request until it has been answered and settled; a
passing probe is then voided on-chain (the key is refunded, the Provider is not
paid) and a failing one is disputed with self-verifying evidence.
"""
from __future__ import annotations

import logging
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import jury, rpc
from ..consumer import dispute_evidence, open_response, prepare_request
from ..evm import address_of, encode_call
from ..protocol import ProtocolError
from ..secure_transport import SecureTransportError
from ..settlement import SettlementError
from .core import RelayCore, RelayError
from .disputes import DisputeDesk

log = logging.getLogger("mycomesh.relay.probes")
_random = secrets.SystemRandom()

PROMPTS = (
    "What is {a} multiplied by {b}? Reply with the number only.",
    "Compute {a} * {b}. Answer with just the result.",
    "Quick check: {a} times {b} equals what? Only the number, please.",
)


def probe_task() -> tuple[str, str]:
    a, b = _random.randint(12, 989), _random.randint(12, 989)
    return _random.choice(PROMPTS).format(a=a, b=b), str(a * b)


def output_text(output: Any) -> str:
    if isinstance(output, dict):
        if isinstance(output.get("output_text"), str):
            return output["output_text"]
        if output.get("choices"):
            return str(output["choices"][0].get("message", {}).get("content", ""))
        if isinstance(output.get("content"), list):
            return "".join(str(part.get("text", "")) for part in output["content"] if isinstance(part, dict))
        texts = [part.get("text", "") for item in output.get("output", []) if isinstance(item, dict)
                 for part in item.get("content", []) if isinstance(part, dict)]
        return "".join(str(text) for text in texts)
    return str(output)


@dataclass
class ProbeResult:
    provider_signer: str
    settlement_key: str
    outcome: str  # voided | disputed | unreachable | skipped
    detail: str = ""


class ProbeRunner:
    def __init__(self, core: RelayCore, cases: jury.CaseReader, desk: DisputeDesk | None, *, owner_private: str,
                 submitter_private: str, rpc_url: str, voids_per_day: int = 10, max_fee: int = 200_000,
                 keys_per_batch: int = 8) -> None:
        self.core = core
        self.cases = cases
        self.desk = desk
        self.owner_private = owner_private
        self.owner = address_of(owner_private)
        self.submitter_private = submitter_private
        self.rpc_url = rpc_url
        self.voids_per_day = voids_per_day
        self.max_fee = max_fee
        self.keys_per_batch = keys_per_batch
        path = Path(core.data_dir) / "relay-probe-keys.sqlite3"
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        path.chmod(0o600)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS probe_keys (address TEXT PRIMARY KEY, private TEXT NOT NULL, "
            "root_index INTEGER NOT NULL, proof TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)"
        )
        self._lock = threading.Lock()

    # ---------------- keys ----------------

    def unused_keys(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM probe_keys WHERE used=0").fetchone()[0])

    def commit_keys(self) -> int:
        """Commit a fresh batch of probe keys on-chain and grant each one."""
        privates = ["0x" + secrets.token_hex(32) for _ in range(self.keys_per_batch)]
        addresses = [address_of(private) for private in privates]
        root, proofs = jury.merkle_root_and_proofs(addresses)
        self._send(encode_call("commitProbeKeys(bytes32)", ["bytes32"], [root]))
        index = self.cases.probe_root_count(self.owner) - 1
        for address in addresses:
            self._send(encode_call("registerKey(address,uint256,uint64)", ["address", "uint256", "uint64"],
                                   [address, self.max_fee, 0]))
        with self._lock:
            self._db.executemany(
                "INSERT INTO probe_keys (address, private, root_index, proof) VALUES (?, ?, ?, ?)",
                [(address, private, index, ",".join(proofs[address])) for address, private in zip(addresses, privates)],
            )
        return index

    def _take_key(self) -> tuple[str, str, int, list[str]]:
        with self._lock:
            row = self._db.execute(
                "SELECT address, private, root_index, proof FROM probe_keys WHERE used=0 ORDER BY root_index LIMIT 1"
            ).fetchone()
            if row is None:
                raise LookupError("no committed probe key is available")
            self._db.execute("UPDATE probe_keys SET used=1 WHERE address=?", (row[0],))
        return row[0], row[1], row[2], [item for item in row[3].split(",") if item]

    # ---------------- probing ----------------

    def probe(self, provider_signer: str | None = None) -> ProbeResult:
        with self.core._lock:
            candidates = [signer for signer in self.core.providers if provider_signer in (None, signer)]
        if not candidates:
            return ProbeResult(provider_signer or "", "", "skipped", "no connected Provider")
        signer = _random.choice(candidates)
        session = self.core.providers[signer]
        day = rpc.block_time(self.rpc_url) // 86_400
        if self.cases.probe_voids_today(self.owner, session.owner, day) >= self.voids_per_day:
            return ProbeResult(signer, "", "skipped", "daily free probe allowance used")
        if not self.unused_keys():
            self.commit_keys()
        address, private, root_index, proof = self._take_key()
        prompt, expected = probe_task()
        descriptor = session.descriptor
        endpoint = _random.choice(("responses", "chat"))
        content = [{"role": "user", "content": prompt}] if endpoint == "chat" else prompt
        prepared = prepare_request(
            descriptor=descriptor, deployment=self.core.deployment, key_private=private, relay_signer=self.core.signer,
            endpoint=endpoint, model=_random.choice(descriptor["models"]), content=content,
            max_output_tokens=256, max_fee=self.max_fee,
        )
        key = prepared.authorization.settlement_key
        try:
            result = self.core.handle_request(prepared.payload)
        except RelayError as exc:
            return ProbeResult(signer, key, "unreachable", str(exc)[:200])
        try:
            response, signed = open_response(prepared, result, self.core.deployment)
            answer = output_text(response.get("output"))
        except (ProtocolError, SecureTransportError, SettlementError, ValueError, KeyError) as exc:
            # The receipt verified at the Relay, so an unreadable response is itself disputable.
            response, signed, answer = None, None, f"unreadable response: {exc}"
        self.core.settle_queued(self.submitter_private, self.rpc_url)
        if response is not None and expected in answer.replace(",", ""):
            self._send(encode_call("voidProbe(bytes32,uint256,bytes32[])", ["bytes32", "uint256", ("array", "bytes32")],
                                   [key, root_index, proof]))
            self.core.queue.mark(key, "voided")
            return ProbeResult(signer, key, "voided")
        self.core.suspend(signer, "failed a known-answer probe")
        if signed is None:
            return ProbeResult(signer, key, "disputed", "response could not be opened; Provider suspended")
        evidence = dispute_evidence(prepared, signed, reason_code="known_answer_probe_failed", statement=(
            f"Relay known-answer probe. The request asks for the product of two integers; the correct answer is "
            f"{expected}. The Provider-signed response does not contain it."))
        self._send(jury.encode_open_dispute(key, jury.evidence_hash(evidence)))
        self.core.queue.mark(key, "disputed")
        if self.desk is not None:
            self.desk.submit_evidence(evidence)
        return ProbeResult(signer, key, "disputed", f"expected {expected}")

    def _send(self, calldata: str) -> None:
        tx = rpc.send_transaction(self.rpc_url, self.owner_private, to=self.core.deployment.settlement, data=calldata)
        rpc.wait_for_receipt(self.rpc_url, tx)


def probe_loop(runner: ProbeRunner, stop: threading.Event, *, mean_interval: float) -> None:
    """Probe a random Provider at exponentially distributed intervals."""
    while not stop.wait(_random.expovariate(1.0 / mean_interval)):
        try:
            result = runner.probe()
            log.info("probe %s: %s %s", result.provider_signer, result.outcome, result.detail)
        except Exception as exc:  # keep probing; the next cycle retries
            log.warning("probe failed: %s", exc)
