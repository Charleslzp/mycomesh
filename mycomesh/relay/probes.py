"""Relay probes: free known-answer requests whose cost the Provider bears.

The Relay owner commits a Merkle root of fresh probe keys before using them,
then sends ordinary sealed requests with those keys to its own Providers. A
probe looks like any paid request until it has been answered and settled; a
passing probe is then voided on-chain (the key is refunded, the Provider is not
paid) and a failing one is disputed with self-verifying evidence.
"""
from __future__ import annotations

import datetime
import logging
import re
import secrets
import time
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import capability, jury, rpc
from ..consumer import dispute_evidence, open_response, prepare_request
from ..evm import address_of, encode_call
from ..protocol import ProtocolError, output_text
from ..secure_transport import SecureTransportError
from ..settlement import SettlementError
from .core import RelayCore, RelayError
from .disputes import DisputeDesk

log = logging.getLogger("mycomesh.relay.probes")
_random = secrets.SystemRandom()

# ---------------- probe tasks ----------------
#
# Each probe hides one objectively checkable task inside ordinary-looking
# traffic. The tasks are easy for the frontier models Providers advertise and
# unreliable for small substitutes (4-digit products, character-level string
# work, ordering), so a Provider quietly serving a cheaper model fails a
# measurable share of them. Only an empty or unrelated answer is disputed; a
# wrong one lowers the Provider's local probe score.

WORDS = ("amber", "basalt", "cobalt", "dune", "ember", "fjord", "garnet", "harbor", "indigo", "juniper", "kelp",
         "lagoon", "meadow", "nectar", "orchid", "pebble", "quartz", "raven", "saffron", "tundra", "umber", "willow")
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
CONTEXTS = ("", "I'm double-checking a spreadsheet. ", "Quick question for a report I'm writing. ",
            "My colleague and I disagree on this. ", "Sanity check before I send an email: ")
FORMATS = ("Reply with the answer only.", "Just give me the result.", "Answer briefly.", "Only the answer, please.")
SYSTEM_PROMPTS = (None, "You are a helpful assistant.", "You are a concise assistant for a small finance team.",
                  "You are a careful assistant. Keep answers short.")


def _numbers(answer: str) -> list[str]:
    """Integers in an answer, accepting 1,234,567 and 1 234 567 groupings."""
    return [re.sub(r"[,\s_]", "", match) for match in re.findall(r"[0-9]{1,3}(?:[,\s_][0-9]{3})+(?![0-9])|[0-9]+", answer)]


@dataclass(frozen=True)
class ProbeTask:
    """One checkable task; ``build_task(kind, params)`` recreates it exactly, so anyone can re-grade."""

    kind: str
    params: dict
    question: str
    reference: str
    numeric: bool

    def grade(self, answer: str) -> str:
        """pass | wrong | unrelated (empty, or no attempt at the task at all)."""
        text = answer.strip()
        if not text:
            return "unrelated"
        if self.numeric:
            numbers = _numbers(text)
            if not numbers:
                return "unrelated"
            return "pass" if self.reference in numbers else "wrong"
        if self.kind == "reverse":
            return "pass" if self.reference in text.lower() else "wrong"
        if self.kind == "sort":
            words = self.reference.split(", ")
            positions = [text.lower().find(word) for word in words]
            if all(position < 0 for position in positions):
                return "unrelated"
            return "pass" if all(p >= 0 for p in positions) and positions == sorted(positions) else "wrong"
        if self.kind == "weekday":
            named = [day for day in WEEKDAYS if day.lower() in text.lower()]
            if not named:
                return "unrelated"
            return "pass" if named == [self.reference] else "wrong"
        raise ValueError(f"unknown probe kind {self.kind}")


def build_task(kind: str, params: dict) -> ProbeTask | capability.CapabilityTask:
    """The deterministic question and answer for a task; mirrored in the Node Consumer."""
    if kind in capability.KINDS:
        return capability.build_capability_task(kind, params)
    if kind == "multiply":
        a, b = int(params["a"]), int(params["b"])
        return ProbeTask(kind, params, f"What is {a} multiplied by {b}?", str(a * b), True)
    if kind == "sum":
        values = [int(value) for value in params["values"]]
        return ProbeTask(kind, params, f"What is the sum of {', '.join(map(str, values))}?", str(sum(values)), True)
    if kind == "count":
        letters, target = str(params["letters"]), str(params["target"])
        return ProbeTask(kind, params, f'How many times does the letter "{target}" appear in "{letters}"?',
                         str(letters.count(target)), True)
    if kind == "reverse":
        word = str(params["word"])
        return ProbeTask(kind, params, f'Write the string "{word}" backwards, letter by letter.', word[::-1], False)
    if kind == "sort":
        words = [str(word) for word in params["words"]]
        return ProbeTask(kind, params, f"Sort these words alphabetically: {', '.join(words)}.", ", ".join(sorted(words)), False)
    if kind == "weekday":
        start, offset = datetime.date.fromisoformat(str(params["start"])), int(params["offset"])
        answer = WEEKDAYS[(start + datetime.timedelta(days=offset)).weekday()]
        return ProbeTask(kind, params, f"What day of the week is {offset} days after {start.isoformat()}?", answer, False)
    raise ValueError(f"unknown probe kind {kind}")


def _multiply() -> ProbeTask:
    return build_task("multiply", {"a": _random.randint(1_000, 9_999), "b": _random.randint(100, 999)})


def _sum() -> ProbeTask:
    return build_task("sum", {"values": [_random.randint(100, 999) for _ in range(8)]})


def _count() -> ProbeTask:
    return build_task("count", {"letters": "".join(_random.choice("abcdeorst") for _ in range(32)),
                                "target": _random.choice("aeors")})


def _reverse() -> ProbeTask:
    return build_task("reverse", {"word": "".join(_random.choice("bcdfghklmnprstvz") + _random.choice("aeiou")
                                                  for _ in range(6))})


def _sort() -> ProbeTask:
    return build_task("sort", {"words": _random.sample(WORDS, 6)})


def _weekday() -> ProbeTask:
    start = datetime.date(2020, 1, 1) + datetime.timedelta(days=_random.randint(0, 2_000))
    return build_task("weekday", {"start": start.isoformat(), "offset": _random.randint(20, 400)})


TASKS = (_multiply, _sum, _count, _reverse, _sort, _weekday)
MULTIPLY_ONLY = (_multiply,)
CAPABILITY_SHARE = 0.5  # of probes that test the advertised model's capability rather than liveness


def probe_request(task: ProbeTask, endpoint: str) -> tuple[Any, dict[str, Any]]:
    """Wrap a task in a randomly shaped, realistic request: (content, options)."""
    question = f"{_random.choice(CONTEXTS)}{task.question} {_random.choice(FORMATS)}"
    system = _random.choice(SYSTEM_PROMPTS)
    if endpoint == "chat":
        messages = [{"role": "system", "content": system}] if system else []
        if _random.random() < 0.4:
            messages += [{"role": "user", "content": "Hi, can you help me with something?"},
                         {"role": "assistant", "content": "Of course. What do you need?"}]
        return messages + [{"role": "user", "content": question}], {}
    return question, ({"instructions": system} if system else {})


@dataclass
class ProbeResult:
    provider_signer: str
    settlement_key: str
    outcome: str  # voided | disputed | unreachable | skipped
    detail: str = ""
    grade: str = ""  # pass | wrong | unrelated


class ProbeRunner:
    def __init__(self, core: RelayCore, cases: jury.CaseReader, desk: DisputeDesk | None, *, owner_private: str,
                 submitter_private: str, rpc_url: str, voids_per_day: int = 10, max_fee: int = 200_000,
                 keys_per_batch: int = 8, tasks: tuple[Any, ...] = TASKS, quality_window: int = 10,
                 max_failure_rate: float = 0.4, ledger: str | None = None,
                 capability_share: float = CAPABILITY_SHARE, capability_floors: dict[int, float] | None = None,
                 capability_window: int = 40) -> None:
        self.ledger = ledger  # ProbeLedgerV11: verdicts become public, re-gradable evidence
        self._last_probe: dict[str, float] = {}
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
        self.tasks = tasks
        self.quality_window = quality_window
        self.max_failure_rate = max_failure_rate
        self.capability_share = capability_share
        self.capability_floors = {**capability.FLOORS, **(capability_floors or {})}
        self.capability_window = capability_window
        path = Path(core.data_dir) / "relay-probe-keys.sqlite3"
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        path.chmod(0o600)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS probe_keys (address TEXT PRIMARY KEY, private TEXT NOT NULL, "
            "root_index INTEGER NOT NULL, proof TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)"
        )
        self._db.execute("CREATE TABLE IF NOT EXISTS probe_grades (provider TEXT NOT NULL, at INTEGER NOT NULL, "
                         "kind TEXT NOT NULL, grade TEXT NOT NULL)")
        self._lock = threading.Lock()
        self._db.execute("CREATE TABLE IF NOT EXISTS capability_grades (provider TEXT NOT NULL, tier INTEGER NOT NULL, "
                         "at INTEGER NOT NULL, kind TEXT NOT NULL, grade TEXT NOT NULL)")
        for signer in {row[0] for row in self._db.execute("SELECT DISTINCT provider FROM probe_grades")}:
            if self.failing(signer):
                core.suspend(signer, "probe pass rate below threshold")
        for signer, tier in self._db.execute("SELECT DISTINCT provider, tier FROM capability_grades").fetchall():
            if self.downgraded(signer, tier):
                core.suspend(signer, "capability pass rate below the tier floor")

    # ---------------- quality ----------------

    def record(self, signer: str, kind: str, grade: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO probe_grades VALUES (?, ?, ?, ?)", (signer, int(time.time()), kind, grade))

    def score(self, signer: str) -> tuple[int, int]:
        """(failures, graded) over the most recent window of probes."""
        with self._lock:
            grades = [row[0] for row in self._db.execute(
                "SELECT grade FROM probe_grades WHERE provider=? ORDER BY rowid DESC LIMIT ?",
                (signer, self.quality_window))]
        return sum(grade != "pass" for grade in grades), len(grades)

    def failing(self, signer: str) -> bool:
        failures, graded = self.score(signer)
        return graded >= 4 and failures / graded >= self.max_failure_rate

    def record_capability(self, signer: str, tier: int, kind: str, grade: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO capability_grades VALUES (?, ?, ?, ?, ?)", (signer, tier, int(time.time()), kind, grade))

    def capability_score(self, signer: str, tier: int) -> tuple[int, int]:
        """(passes, graded) over the most recent capability probes in this tier."""
        with self._lock:
            grades = [row[0] for row in self._db.execute(
                "SELECT grade FROM capability_grades WHERE provider=? AND tier=? ORDER BY rowid DESC LIMIT ?",
                (signer, tier, self.capability_window))]
        return sum(grade == "pass" for grade in grades), len(grades)

    def downgraded(self, signer: str, tier: int) -> bool:
        """99% confident the Provider's model is below what its tier promises."""
        floor = self.capability_floors.get(tier)
        return floor is not None and capability.flagged(*self.capability_score(signer, tier), floor)

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
        # Every Provider is probed at least daily: probes are also how the chain sees it online (supply).
        stale = [c for c in candidates if time.time() - self._last_probe.get(c, 0) > 20 * 3600]
        signer = _random.choice(stale or candidates)
        self._last_probe[signer] = time.time()
        session = self.core.providers[signer]
        day = rpc.block_time(self.rpc_url) // 86_400
        if self.cases.probe_voids_today(self.owner, session.owner, day) >= self.voids_per_day:
            return ProbeResult(signer, "", "skipped", "daily free probe allowance used")
        if not self.unused_keys():
            self.commit_keys()
        address, private, root_index, proof = self._take_key()
        descriptor = session.descriptor
        tier = int(descriptor.get("tier") or 0)
        capable = tier in self.capability_floors and _random.random() < self.capability_share
        task = capability.random_task() if capable else _random.choice(self.tasks)()
        endpoint = _random.choice(("responses", "chat"))
        content, options = probe_request(task, endpoint)
        prepared = prepare_request(
            descriptor=descriptor, deployment=self.core.deployment, key_private=private, relay_signer=self.core.signer,
            endpoint=endpoint, model=_random.choice(descriptor["models"]), content=content,
            # Reasoning models think before answering a hard task: never cut them off.
            max_output_tokens=_random.choice((16_000, 32_000) if capable else (512, 1024, 2048, 4096)),
            max_fee=self.max_fee, options=options,
        )
        key = prepared.authorization.settlement_key
        try:
            result = self.core.handle_request(prepared.payload)
        except RelayError as exc:
            return ProbeResult(signer, key, "unreachable", str(exc)[:200])
        try:
            response, signed = open_response(prepared, result, self.core.deployment)
            grade = task.grade(output_text(response.get("output")))
        except (ProtocolError, SecureTransportError, SettlementError, ValueError, KeyError):
            # The receipt verified at the Relay, so an unreadable response is itself disputable.
            response, signed, grade = None, None, "wrong" if capable else "unrelated"
        if capable:
            self.record_capability(signer, tier, task.kind, grade)
        else:
            self.record(signer, task.kind, grade)
        if not self._settle(prepared.authorization):
            # Still queued: the settlement worker retries it, and the Provider is paid for this one probe.
            return ProbeResult(signer, key, "unsettled", f"{task.kind}: {grade}; settlement pending", grade)
        if grade != "unrelated":
            # Correct or merely wrong: the Provider is not paid for a probe either way.
            self._send(encode_call("voidProbe(bytes32,uint256,bytes32[])", ["bytes32", "uint256", ("array", "bytes32")],
                                   [key, root_index, proof]))
            self.core.queue.mark(key, "voided")
            if self.ledger and self.desk is not None:
                self._record_verdict(prepared, signed, task, grade)
            if self.failing(signer):
                failures, graded = self.score(signer)
                self.core.suspend(signer, f"failed {failures} of the last {graded} probes")
            if capable and self.downgraded(signer, tier):
                passes, graded = self.capability_score(signer, tier)
                self.core.suspend(signer, f"passed {passes} of {graded} capability probes, below tier {tier}'s floor "
                                          f"{self.capability_floors[tier]:.0%}: the advertised model is likely not served")
            return ProbeResult(signer, key, "voided", f"{task.kind}: {grade}", grade)
        self.core.suspend(signer, "gave no answer to a known-answer probe")
        if signed is None:
            return ProbeResult(signer, key, "disputed", "response could not be opened; Provider suspended", grade)
        evidence = dispute_evidence(prepared, signed, reason_code="known_answer_probe_unanswered", statement=(
            f"Relay known-answer probe ({task.kind}). The request asks: {task.question} The correct answer is "
            f"{task.reference}. The Provider-signed response does not attempt the task at all."))
        self._send(jury.encode_open_dispute(key, jury.evidence_hash(evidence)))
        self.core.queue.mark(key, "disputed")
        if self.desk is not None:
            self.desk.submit_evidence(evidence)
        return ProbeResult(signer, key, "disputed", f"expected {task.reference}", grade)

    def _record_verdict(self, prepared: Any, signed: Any, task: ProbeTask, grade: str) -> None:
        from ..probe_evidence import build_probe_evidence, encode_record

        evidence = build_probe_evidence(signed, prepared.request_plaintext, prepared.response_plaintext,
                                        kind=task.kind, params=task.params, verdict=grade)
        self.desk.publish(evidence)
        try:
            tx = rpc.send_transaction(self.rpc_url, self.owner_private, to=self.ledger,
                                      data=encode_record(signed.authorization.settlement_key, evidence))
            rpc.wait_for_receipt(self.rpc_url, tx)
        except rpc.RpcError as exc:  # the verdict is still published off-chain; the next probe tries again
            log.warning("probe verdict not recorded: %s", exc)

    def _settle(self, authorization: Any, attempts: int = 4) -> bool:
        """Settle the probe now so it can be voided inside its dispute window."""
        for attempt in range(attempts):
            # The contract rejects an authorization issued after the block being built.
            deadline = time.monotonic() + 60
            while rpc.block_time(self.rpc_url) <= authorization.issued_at and time.monotonic() < deadline:
                time.sleep(3)
            self.core.settle_queued(self.submitter_private, self.rpc_url)
            if self.core.reader.is_settled(authorization.settlement_key):
                return True
            time.sleep(10 * (attempt + 1))
        return False

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
