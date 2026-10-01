"""Probes: free known-answer requests whose cost the Provider bears, open to any hunter.

A hunter (a Relay, a custodial service, anyone) commits a Merkle root of fresh
probe keys behind keccak256(hunter, root, salt), which names nobody, then sends
ordinary sealed requests with those keys. The keys belong to a probe owner that
is not linked to the hunter: a fresh, separately funded account per batch, or a
custodial account whose tenants' traffic hides the probes. A probe looks like any
paid request; once the batch is spent its owner voids every probe (refunded, the
Provider unpaid) or disputes one that was not answered at all. Voiding a whole
batch at once keeps the owner unknown until no key of it is left to recognise.

Capability probes feed a statistical case: when a hunter's probes show, with
99% confidence, a Provider passing hard tasks less often than its tier promises,
the hunter accuses it on-chain with every probe it voided on it (see
mycomesh/hunting.py); a same-tier jury replays them as a control group.
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

import json
from collections.abc import Callable, Sequence

from .. import capability, hunting, jury, rpc
from ..consumer import dispute_evidence, open_response, prepare_request
from ..evm import address_of, encode_call
from ..protocol import ProtocolError, b64decode, output_text
from ..secure_transport import SecureTransportError
from ..settlement import SettlementError, SignedReceipt
from .core import RelayCore, RelayError

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
    if kind in capability.KINDS or kind == capability.CUSTOM:
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
CAPABILITY_SHARE = 0.7  # of probes that test the advertised model's capability rather than liveness


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
    outcome: str  # answered | voided | disputed | unreachable | skipped | unsettled
    detail: str = ""
    grade: str = ""  # pass | wrong | unrelated


@dataclass
class Target:
    """A Provider a hunter can reach: its descriptor and how to send it a prepared request."""

    signer: str
    owner: str
    descriptor: dict[str, Any]
    relay_signer: str
    send: Callable[[dict[str, Any]], dict[str, Any]]


class ProbeRunner:
    """Probe Providers, void probes in batches, record verdicts, and accuse downgraded Providers.

    ``owner_private`` is the hunter: it posts commitments, records verdicts in the ProbeLedger, opens
    capability cases (paying the bond) and receives bounties. ``probe_owner_private`` fixes the account
    that owns the probe keys (a custodial service hiding probes among its tenants); without it every
    batch gets a fresh owner, funded by ``funder(address, usdc_units)``.
    """

    def __init__(self, core: RelayCore | None, cases: jury.CaseReader, desk: Any, *, owner_private: str,
                 rpc_url: Any, submitter_private: str | None = None, data_dir: Path | None = None,
                 targets: Callable[[], list[Target]] | None = None, funder: Callable[[str, int], None] | None = None,
                 publish: Callable[[dict[str, Any]], None] | None = None, probe_owner_private: str | None = None,
                 voids_per_day: int | None = None, max_fee: int = 50_000, keys_per_batch: int = 8,
                 tasks: tuple[Any, ...] = TASKS, custom_tasks: Sequence[dict] = (), quality_window: int = 10,
                 max_failure_rate: float = 0.4, ledger: str | None = None,
                 capability_share: float = CAPABILITY_SHARE, capability_floors: dict[int, float] | None = None,
                 capability_window: int = 100, capability_minimum: int = 20, flush_after: int = 12 * 3600,
                 open_cases: bool = True) -> None:
        self.core, self.cases, self.desk = core, cases, desk
        self.ledger = ledger  # ProbeLedgerV11: verdicts become public, re-gradable evidence
        self._last_probe: dict[str, float] = {}
        self.owner_private = owner_private
        self.owner = address_of(owner_private)  # the hunter
        self.hunter = self.owner
        self.submitter_private = submitter_private or owner_private
        self.rpc_url = rpc_url
        self.deployment = cases.deployment
        self.targets = targets or self._relay_targets
        self.funder = funder or self._transfer_funds
        self.publish = publish or self._publish_locally
        self.probe_owner_private = probe_owner_private
        self.voids_per_day = voids_per_day
        self.max_fee = max_fee
        self.keys_per_batch = keys_per_batch
        self.tasks = tasks
        self.custom_tasks = list(custom_tasks)
        self.quality_window = quality_window
        self.max_failure_rate = max_failure_rate
        self.capability_share = capability_share
        self.capability_floors = {**capability.FLOORS, **(capability_floors or {})}
        self.capability_window = capability_window
        self.capability_minimum = capability_minimum
        self.flush_after = flush_after
        self.open_cases = open_cases
        directory = Path(data_dir or core.data_dir)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "relay-probe-keys.sqlite3"
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        path.chmod(0o600)
        self._db.execute("CREATE TABLE IF NOT EXISTS hunt_batches (id INTEGER PRIMARY KEY, owner_private TEXT NOT NULL, "
                         "root TEXT NOT NULL, salt TEXT NOT NULL, committed_at INTEGER NOT NULL, "
                         "state TEXT NOT NULL DEFAULT 'open')")
        if "max_fee" not in {row[1] for row in self._db.execute("PRAGMA table_info(hunt_batches)")}:
            # Each batch's keys are granted one maximum fee; a probe must ask no more, even after a restart.
            self._db.execute("ALTER TABLE hunt_batches ADD COLUMN max_fee INTEGER")
        self._db.execute("CREATE TABLE IF NOT EXISTS hunt_keys (address TEXT PRIMARY KEY, private TEXT NOT NULL, "
                         "batch INTEGER NOT NULL, proof TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
        self._db.execute("CREATE TABLE IF NOT EXISTS hunt_probes (settlement_key TEXT PRIMARY KEY, batch INTEGER NOT NULL, "
                         "key TEXT NOT NULL, provider_signer TEXT NOT NULL, provider TEXT NOT NULL, tier INTEGER NOT NULL, "
                         "kind TEXT NOT NULL, grade TEXT NOT NULL, record TEXT NOT NULL, state TEXT NOT NULL, "
                         "void_day INTEGER, in_case INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS probe_grades (provider TEXT NOT NULL, at INTEGER NOT NULL, "
                         "kind TEXT NOT NULL, grade TEXT NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS capability_grades (provider TEXT NOT NULL, tier INTEGER NOT NULL, "
                         "at INTEGER NOT NULL, kind TEXT NOT NULL, grade TEXT NOT NULL)")
        self._lock = threading.Lock()
        for signer in {row[0] for row in self._db.execute("SELECT DISTINCT provider FROM probe_grades")}:
            if self.failing(signer):
                self._suspend(signer, "probe pass rate below threshold")
        for signer, tier in self._db.execute("SELECT DISTINCT provider, tier FROM capability_grades").fetchall():
            if self.downgraded(signer, tier):
                self._suspend(signer, "capability pass rate below the tier floor")

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
        return floor is not None and capability.flagged(*self.capability_score(signer, tier), floor,
                                                        minimum=self.capability_minimum)

    def _suspend(self, signer: str, reason: str) -> None:
        if self.core is not None:  # a Relay stops routing; any other hunter can only accuse
            self.core.suspend(signer, reason)
        log.warning("probe: %s %s", signer, reason)

    # ---------------- batches of probe keys ----------------

    def _send_tx(self, private: str, to: str, data: str, value: int = 0) -> dict[str, Any]:
        return rpc.wait_for_receipt(self.rpc_url, rpc.send_transaction(self.rpc_url, private, to=to, data=data, value=value))

    def _stablecoin(self) -> str:
        if not hasattr(self, "_token"):
            raw = rpc.eth_call(self.rpc_url, self.deployment.settlement, encode_call("stablecoin()", [], []))
            self._token = "0x" + raw[-40:]
        return self._token

    def _transfer_funds(self, owner: str, units: int) -> None:
        """Fund a fresh probe owner from the hunter's own wallet. On a public chain this links the two;
        fund it from somewhere unlinked (an exchange withdrawal, the testnet faucet) instead."""
        self._send_tx(self.owner_private, owner, "0x", value=self._gas_budget())
        self._send_tx(self.owner_private, self._stablecoin(),
                      encode_call("transfer(address,uint256)", ["address", "uint256"], [owner, units]))

    def _gas_budget(self) -> int:
        """ETH a fresh probe owner needs: approve, deposit, a key grant and a void per key, with margin."""
        price = rpc.suggested_gas_price(self.rpc_url)
        return price * 250_000 * (2 * self.keys_per_batch + 3) * 2

    def unused_keys(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM hunt_keys k JOIN hunt_batches b ON k.batch=b.id "
                                        "WHERE k.used=0 AND b.state='open'").fetchone()[0])

    def commit_keys(self) -> int:
        """Start a batch: probe keys under a probe owner, and a commitment that names nobody."""
        rules = self.cases.probe_rules()
        max_fee = min(self.max_fee, rules["max_fee"])
        if max_fee <= 0:
            raise LookupError("free probes are disabled on this network")
        owner_private = self.probe_owner_private or "0x" + secrets.token_hex(32)
        owner = address_of(owner_private)
        privates = ["0x" + secrets.token_hex(32) for _ in range(self.keys_per_batch)]
        addresses = [address_of(private) for private in privates]
        if not self.probe_owner_private:
            # Deposit for every key, plus a reporter bond for a probe that is not answered at all.
            self.funder(owner, max_fee * len(addresses) + rules["reporter_bond"])
            self._send_tx(owner_private, self._stablecoin(), encode_call(
                "approve(address,uint256)", ["address", "uint256"], [self.deployment.settlement, 2**255]))
            self._send_tx(owner_private, self.deployment.settlement,
                          encode_call("deposit(uint256)", ["uint256"], [max_fee * len(addresses)]))
        for address in addresses:
            self._send_tx(owner_private, self.deployment.settlement, encode_call(
                "registerKey(address,uint256,uint64)", ["address", "uint256", "uint64"], [address, max_fee, 0]))
        root, proofs = jury.merkle_root_and_proofs(addresses)
        salt = "0x" + secrets.token_hex(32)
        receipt = self._send_tx(self.submitter_private, self.deployment.settlement,
                                hunting.encode_commit_probes(hunting.probe_commitment(self.hunter, root, salt)))
        block = rpc.call(self.rpc_url, "eth_getBlockByNumber", [receipt["blockNumber"], False])
        with self._lock:
            batch = self._db.execute("INSERT INTO hunt_batches (owner_private, root, salt, committed_at, max_fee) "
                                     "VALUES (?, ?, ?, ?, ?)",
                                     (owner_private, root, salt, rpc.quantity(block["timestamp"]), max_fee)).lastrowid
            self._db.executemany("INSERT INTO hunt_keys (address, private, batch, proof) VALUES (?, ?, ?, ?)",
                                 [(a, p, batch, ",".join(proofs[a.lower()])) for a, p in zip(addresses, privates)])
        return int(batch)

    def _take_key(self) -> tuple[str, str, int, int, int]:
        with self._lock:
            row = self._db.execute(
                "SELECT k.address, k.private, k.batch, b.committed_at, b.max_fee FROM hunt_keys k "
                "JOIN hunt_batches b ON k.batch=b.id WHERE k.used=0 AND b.state='open' ORDER BY k.batch LIMIT 1").fetchone()
            if row is None:
                raise LookupError("no committed probe key is available")
            self._db.execute("UPDATE hunt_keys SET used=1 WHERE address=?", (row[0],))
        # Batches from before the column existed were granted min(our cap, the network's cap).
        max_fee = row[4] if row[4] is not None else min(self.max_fee, self.cases.probe_rules()["max_fee"])
        return row[0], row[1], int(row[2]), int(row[3]), int(max_fee)

    # ---------------- probing ----------------

    def _relay_targets(self) -> list[Target]:
        with self.core._lock:
            sessions = dict(self.core.providers)
        return [Target(signer, session.owner, session.descriptor, self.core.signer,
                       lambda payload: self.core.handle_request(payload)) for signer, session in sessions.items()]

    def _today(self) -> int:
        return rpc.block_time(self.rpc_url) // 86_400

    def probe(self, provider_signer: str | None = None) -> ProbeResult:
        candidates = [t for t in self.targets() if provider_signer in (None, t.signer)]
        if not candidates:
            return ProbeResult(provider_signer or "", "", "skipped", "no reachable Provider")
        # Every Provider is probed at least daily: probes are also how the chain sees it online (supply).
        stale = [t for t in candidates if time.time() - self._last_probe.get(t.signer, 0) > 20 * 3600]
        target = _random.choice(stale or candidates)
        signer = target.signer
        self._last_probe[signer] = time.time()
        allowance = self.voids_per_day or self.cases.probe_rules()["voids_per_day"]
        with self._lock:
            pending = self._db.execute("SELECT COUNT(*) FROM hunt_probes WHERE provider=? AND state='answered'",
                                       (target.owner,)).fetchone()[0]
        if self.cases.provider_probe_voids(target.owner, self._today()) + pending >= allowance:
            return ProbeResult(signer, "", "skipped", "the Provider's free probes for today are used")
        if not self.unused_keys():
            self.commit_keys()
        address, private, batch, committed_at, max_fee = self._take_key()
        descriptor = target.descriptor
        tier = int(descriptor.get("tier") or 0)
        capable = tier in self.capability_floors and _random.random() < self.capability_share
        if capable:
            task = (capability.build_capability_task(capability.CUSTOM, _random.choice(self.custom_tasks))
                    if self.custom_tasks and _random.random() < 0.5 else capability.random_task())
        else:
            task = _random.choice(self.tasks)()
        endpoint = _random.choice(("responses", "chat"))
        content, options = probe_request(task, endpoint)
        now = max(int(time.time()), committed_at + 1)  # issued after the commitment, or the void is refused
        prepared = prepare_request(
            descriptor=descriptor, deployment=self.deployment, key_private=private, relay_signer=target.relay_signer,
            endpoint=endpoint, model=_random.choice(descriptor["models"]), content=content,
            # Reasoning models think before answering a hard task: never cut them off.
            max_output_tokens=_random.choice((16_000, 32_000) if capable else (512, 1024, 2048, 4096)),
            max_fee=max_fee, options=options, now=now,
        )
        key = prepared.authorization.settlement_key
        try:
            result = target.send(prepared.payload)
        except (RelayError, OSError, ValueError) as exc:
            return ProbeResult(signer, key, "unreachable", str(exc)[:200])
        try:
            response, signed = open_response(prepared, result, self.deployment)
            grade = task.grade(output_text(response.get("output")))
        except (ProtocolError, SecureTransportError, SettlementError, ValueError, KeyError):
            # The receipt verified at the Relay, so an unreadable response is itself disputable.
            response, signed, grade = None, None, "wrong" if capable else "unrelated"
        if capable:
            self.record_capability(signer, tier, task.kind, grade)
        else:
            self.record(signer, task.kind, grade)
        if signed is not None:
            record = hunting.probe_record(signed, prepared.request_plaintext, prepared.response_plaintext, task.kind, task.params)
            with self._lock:
                self._db.execute("INSERT INTO hunt_probes (settlement_key, batch, key, provider_signer, provider, tier, kind, "
                                 "grade, record, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'answered', ?)",
                                 (key, batch, address, signer, target.owner, tier, task.kind, grade, json.dumps(record),
                                  int(time.time())))
        if grade == "unrelated" or self.failing(signer):
            failures, graded = self.score(signer)
            self._suspend(signer, "gave no answer to a known-answer probe" if grade == "unrelated"
                          else f"failed {failures} of the last {graded} probes")
        if capable and self.downgraded(signer, tier):
            passes, graded = self.capability_score(signer, tier)
            self._suspend(signer, f"passed {passes} of {graded} capability probes, below tier {tier}'s floor "
                                  f"{self.capability_floors[tier]:.0%}: the advertised model is likely not served")
        self.flush()
        return ProbeResult(signer, key, "answered", f"{task.kind}: {grade}", grade)

    # ---------------- voiding, disputes and verdicts ----------------

    def pending(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM hunt_probes WHERE state='answered'").fetchone()[0])

    def flush(self, *, force: bool = False) -> list[tuple[str, str]]:
        """Void (or dispute) every probe of each batch that is spent or old enough, all at once."""
        with self._lock:
            batches = self._db.execute(
                "SELECT b.id, b.owner_private, b.root, b.salt, MIN(p.created_at), b.state, "
                "(SELECT COUNT(*) FROM hunt_keys k WHERE k.batch=b.id AND k.used=0) "
                "FROM hunt_batches b JOIN hunt_probes p ON p.batch=b.id WHERE p.state='answered' GROUP BY b.id").fetchall()
        done = []
        for batch, owner_private, root, salt, oldest, state, unused in batches:
            if not (force or state == "flushed" or unused == 0 or time.time() - oldest >= self.flush_after):
                continue
            with self._lock:  # the batch's owner is about to be revealed: retire its remaining keys
                self._db.execute("UPDATE hunt_batches SET state='flushed' WHERE id=?", (batch,))
                probes = self._db.execute("SELECT settlement_key, key, grade, record FROM hunt_probes "
                                          "WHERE batch=? AND state='answered'", (batch,)).fetchall()
            for key, address, grade, record in probes:
                outcome = self._finish(key, address, grade, json.loads(record), owner_private, root, salt)
                if outcome != "waiting":
                    done.append((key, outcome))
        if done and self.open_cases:
            self.maybe_open_cases()
        return done

    def _settled(self, key: str) -> bool:
        if self.cases.settlement(key)["status"] == "none" and self.core is not None:
            self.core.settle_queued(self.submitter_private, self.rpc_url)  # a Relay settles its own queue now
        return self.cases.settlement(key)["status"] != "none"

    def _finish(self, key: str, address: str, grade: str, record: dict, owner_private: str, root: str, salt: str) -> str:
        if not self._settled(key):
            return "waiting"  # still queued at its Relay: voided on a later flush, within the dispute window
        if self.cases.settlement(key)["status"] != "pending":
            self._mark(key, "missed")
            return "missed"
        signed = SignedReceipt.from_payload(record["signed_receipt"])
        if grade == "unrelated":
            task = build_task(record["task"]["kind"], record["task"]["params"])
            evidence = jury.build_evidence(signed, b64decode(record["request"]), b64decode(record["response"]),
                                           reason_code="known_answer_probe_unanswered", statement=(
                f"Known-answer probe ({task.kind}). The request asks: {task.question} The correct answer is "
                f"{task.reference}. The Provider-signed response does not attempt the task at all."))
            self._send_tx(owner_private, self.deployment.settlement, jury.encode_open_dispute(key, jury.evidence_hash(evidence)))
            self.publish(evidence)
            self._mark(key, "disputed")
            return "disputed"
        with self._lock:
            proof = self._db.execute("SELECT proof FROM hunt_keys WHERE address=?", (address,)).fetchone()[0]
        try:
            self._send_tx(owner_private, self.deployment.settlement, hunting.encode_void_probe(
                key, self.hunter, root, salt, [item for item in proof.split(",") if item]))
        except rpc.RpcError as exc:  # another hunter used today's allowance first: this probe is paid
            log.info("probe %s not voided: %s", key, exc)
            self._mark(key, "paid")
            return "paid"
        day = self.cases.probe_void(key)["day"]
        with self._lock:
            self._db.execute("UPDATE hunt_probes SET state='voided', void_day=? WHERE settlement_key=?", (day, key))
        if self.ledger:
            self._record_verdict(record, grade)
        return "voided"

    def _mark(self, key: str, state: str) -> None:
        with self._lock:
            self._db.execute("UPDATE hunt_probes SET state=? WHERE settlement_key=?", (state, key))

    def _record_verdict(self, record: dict, grade: str) -> None:
        from ..probe_evidence import SCHEMA, encode_record

        evidence = {"schema": SCHEMA, "settlement_key": record["settlement_key"], "signed_receipt": record["signed_receipt"],
                    "request": record["request"], "response": record["response"], "task": record["task"], "verdict": grade}
        self.publish(evidence)
        try:
            self._send_tx(self.owner_private, self.ledger, encode_record(record["settlement_key"], evidence))
        except rpc.RpcError as exc:  # the verdict is still published off-chain
            log.warning("probe verdict not recorded: %s", exc)

    def _publish_locally(self, evidence: dict[str, Any]) -> None:
        if self.desk is None:
            return
        if evidence.get("schema") == jury.EVIDENCE_SCHEMA:
            self.desk.submit_evidence(evidence)
        elif evidence.get("schema") == hunting.CASE_SCHEMA:
            self.desk.submit_capability_evidence(evidence)
        else:
            self.desk.publish(evidence)

    # ---------------- capability cases ----------------

    def maybe_open_cases(self) -> list[str]:
        """Accuse every Provider this hunter is 99% sure serves less than its tier, with all its probes."""
        opened = []
        with self._lock:
            flagged = self._db.execute("SELECT DISTINCT provider_signer, provider, tier FROM hunt_probes "
                                       "WHERE state='voided' AND in_case=0").fetchall()
        for signer, provider, tier in flagged:
            if not self.downgraded(signer, tier):
                continue
            try:
                case = self.open_case(provider)
            except (CaseNotReady, rpc.RpcError) as exc:
                log.info("capability case against %s not opened: %s", provider, exc)
                continue
            opened.append(case)
        return opened

    def open_case(self, provider: str) -> str:
        today = self._today()
        with self._lock:
            rows = self._db.execute("SELECT settlement_key, void_day, record FROM hunt_probes WHERE provider=? "
                                    "AND state='voided' AND in_case=0 AND void_day<? ORDER BY void_day DESC",
                                    (provider, today)).fetchall()
        by_day: dict[int, list[tuple[str, dict]]] = {}
        for key, day, record in rows:
            by_day.setdefault(day, []).append((key, json.loads(record)))
        chosen: list[tuple[str, dict]] = []
        days: list[int] = []
        for day in sorted(by_day, reverse=True):  # the most recent closed days, whole days only
            if len(chosen) + len(by_day[day]) > hunting.MAX_CASE_PROBES or (days and days[0] - day >= hunting.MAX_CASE_DAYS):
                break
            if self.cases.hunter_probe_voids(self.hunter, provider, day) != len(by_day[day]):
                raise CaseNotReady(f"day {day}: the chain counts other voids under this hunter")
            chosen += by_day[day]
            days.insert(0, day)
        if len(chosen) < hunting.MIN_CASE_PROBES:
            raise CaseNotReady(f"{len(chosen)} probes; a case needs {hunting.MIN_CASE_PROBES}")
        evidence = hunting.build_case_evidence(self.hunter, provider, days[0], days[-1], [record for _, record in chosen])
        keys = [key for key, _ in chosen]
        self._send_tx(self.owner_private, self.deployment.settlement,
                      hunting.encode_open_case(provider, days[0], days[-1], keys, hunting.evidence_hash(evidence)))
        with self._lock:
            self._db.executemany("UPDATE hunt_probes SET in_case=1 WHERE settlement_key=?", [(key,) for key in keys])
        self.publish(evidence)
        case = hunting.case_id(self.hunter, provider, days[0], days[-1])
        log.warning("opened capability case %s against %s with %d probes", case, provider, len(keys))
        return case


class CaseNotReady(RuntimeError):
    pass


def probe_loop(runner: ProbeRunner, stop: threading.Event, *, mean_interval: float) -> None:
    """Probe a random Provider at exponentially distributed intervals; flush old batches between."""
    while not stop.wait(_random.expovariate(1.0 / mean_interval)):
        try:
            result = runner.probe()
            log.info("probe %s: %s %s", result.provider_signer, result.outcome, result.detail)
            for key, outcome in runner.flush():  # probes whose Relay had not settled them yet
                log.info("probe %s: %s", key, outcome)
        except Exception as exc:  # keep probing; the next cycle retries
            log.warning("probe failed: %s", exc)
