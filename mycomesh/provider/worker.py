"""Provider job handling: verify, decrypt, execute once, seal the response, sign the receipt."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..evm import address_of
from ..identity import NodeIdentity
from ..identity import canonical_json
from ..protocol import (
    SEALED_DELTA_PURPOSE, SEALED_REQUEST_PURPOSE, SEALED_RESPONSE_PURPOSE, Prices, ProtocolError, attest_transport, b64decode,
    b64encode, build_response, sha256_hex, validate_request,
)
from ..replay import SqliteReplayStore
from ..secure_transport import (
    SecureTransportError, TransportKeyPair, generate_transport_key, open_frame, seal_frame,
    verify_transport_key_binding,
)
from ..settlement import (
    Authorization, Deployment, SettlementError, build_receipt, sign_receipt, verify_authorization,
    verify_dispatch,
)

# (request document) -> (output, input_tokens, output_tokens). A backend with
# ``streams = True`` also accepts ``on_delta=callable(text)`` for streamed text.
Backend = Callable[[dict[str, Any]], tuple[Any, int, int]]
# Emits one sealed delta frame (base64) toward the Consumer.
Emit = Callable[[str], None]
DELTA_FLUSH_SECONDS = 0.05
DELTA_FLUSH_CHARS = 256

TRANSPORT_KEY_LIFETIME = 7 * 24 * 3600
TRANSPORT_KEY_ROTATE_BEFORE = 24 * 3600


class JobRejected(RuntimeError):
    """The job was not executed; the Relay may report it as not dispatched."""


@dataclass
class ProviderWorker:
    identity: NodeIdentity
    provider_private: str
    deployment: Deployment
    backend: Backend
    prices: Prices
    models: tuple[str, ...]
    data_dir: Path
    capacity: int = 1
    # Jury duty needs chain reads; a Provider without them only serves requests.
    cases: Any = None  # mycomesh.jury.CaseReader
    jury_model: str | None = None
    # mycomesh.pricing.NetworkPricing: the network price replaces ``prices`` (one price for all Providers).
    pricing: Any = None
    tier: int = 0
    _keys: list[TransportKeyPair] = field(default_factory=list, init=False, repr=False)
    # capability case id -> {"pending": True} while the control group runs, then the signed vote
    _capability_votes: dict[str, dict[str, Any]] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.signer = address_of(self.provider_private)
        self._replay = SqliteReplayStore(self.data_dir / "provider-replay.sqlite3")
        self._journal = sqlite3.connect(self.data_dir / "provider-journal.sqlite3", timeout=30,
                                        isolation_level=None, check_same_thread=False)
        self._journal.execute("PRAGMA journal_mode=WAL")
        self._journal.execute(
            "CREATE TABLE IF NOT EXISTS executions (settlement_key TEXT PRIMARY KEY, state TEXT NOT NULL, "
            "result TEXT, updated_at INTEGER NOT NULL)"
        )
        self._slots = threading.BoundedSemaphore(self.capacity)

    # ---------------- identity ----------------

    def current_transport_key(self, now: int | None = None) -> TransportKeyPair:
        current = int(time.time() if now is None else now)
        with self._lock:
            self._keys = [key for key in self._keys if key.binding["expires_at"] > current]
            if not self._keys or self._keys[-1].binding["expires_at"] - current < TRANSPORT_KEY_ROTATE_BEFORE:
                self._keys.append(generate_transport_key(self.identity, lifetime_seconds=TRANSPORT_KEY_LIFETIME, now=current))
            return self._keys[-1]

    def descriptor(self, now: int | None = None) -> dict[str, Any]:
        """What a Relay publishes so a Consumer can seal to this Provider."""
        key = self.current_transport_key(now)
        return {
            "peer_id": self.identity.peer_id,
            "identity_public_key": self.identity.public_key,
            "transport_key": key.binding,
            "transport_attestation": attest_transport(
                self.provider_private, identity_public_key=self.identity.public_key,
                transport_key_id=key.binding["key_id"], expires_at=key.binding["expires_at"],
                deployment=self.deployment,
            ),
            "provider_signer": self.signer,
            "models": list(self.models),
            "prices": self._advertised_prices(now),
            "tier": self.tier,
            "capacity": self.capacity,
        }

    def _advertised_prices(self, now: int | None = None) -> dict[str, int]:
        if self.pricing is None:
            return self.prices.to_payload()
        try:
            current = self.pricing.effective_prices(self.tier, now)
            return {"input_per_1k": current["input_per_1k"], "output_per_1k": current["output_per_1k"],
                    "minimum_fee": current["minimum_fee"]}
        except Exception:  # the chain is unreachable: advertise the last configured prices
            return self.prices.to_payload()

    def _key_for(self, key_id: str) -> TransportKeyPair:
        with self._lock:
            for key in self._keys:
                if key.binding["key_id"] == key_id:
                    return key
        raise JobRejected("sealed request targets an unknown or expired transport key")

    # ---------------- jobs ----------------

    def handle_job(self, job: Mapping[str, Any], *, now: int | None = None, emit: Emit | None = None) -> dict[str, Any]:
        if job.get("kind") == "jury":
            return self.handle_jury(job, now=now)
        if job.get("kind") == "capability_jury":
            return self.handle_capability_jury(job, now=now)
        current = int(time.time() if now is None else now)
        try:
            authorization = Authorization.from_payload(job.get("authorization"))
            verify_authorization(authorization, str(job.get("key_signature")), self.deployment, now=current,
                                 provider_signer=self.signer)
            verify_dispatch(authorization, str(job.get("relay_signature")), self.deployment)
        except (SettlementError, ValueError, TypeError) as exc:
            raise JobRejected(f"job authorization rejected: {exc}") from exc
        key = authorization.settlement_key
        previous = self._journal.execute(
            "SELECT state, result FROM executions WHERE settlement_key=?", (key,)
        ).fetchone()
        if previous is not None:
            if previous[0] == "completed":
                return json.loads(previous[1])
            # Started before a crash or concurrently: never execute twice.
            raise JobRejected("request execution outcome is already in progress or unknown")
        plaintext, reply_binding = self._open(job, authorization, current)
        document = json.loads(plaintext)
        if not self._slots.acquire(blocking=False):
            raise JobRejected("provider is at capacity")
        try:
            try:
                self._journal.execute(
                    "INSERT INTO executions (settlement_key, state, updated_at) VALUES (?, 'running', ?)",
                    (key, current),
                )
            except sqlite3.IntegrityError as exc:
                raise JobRejected("request is already executing") from exc
            if emit is not None and job.get("stream") and getattr(self.backend, "streams", False):
                sealer = _DeltaSealer(self.identity, reply_binding, emit)
                output, input_tokens, output_tokens = self.backend(document, on_delta=sealer.add)
                sealer.flush()
            else:
                output, input_tokens, output_tokens = self.backend(document)
            if self.pricing is not None:
                quote = self.pricing.quote(self.signer, authorization.issued_at, input_tokens, output_tokens)
            else:
                quote = self.prices.quote(input_tokens, output_tokens)
            fee = min(quote, authorization.max_fee)
            response = build_response(request_hash=authorization.request_hash, output=output,
                                      input_tokens=input_tokens, output_tokens=output_tokens)
            receipt = build_receipt(authorization, response_hash=sha256_hex(response),
                                    input_tokens=input_tokens, output_tokens=output_tokens, actual_fee=fee)
            sealed = seal_frame(response, sender=self.identity, recipient_binding=reply_binding,
                                expected_recipient_peer_id=reply_binding["peer_id"],
                                purpose=SEALED_RESPONSE_PURPOSE, ttl_seconds=300,
                                now=max(current, int(time.time())))  # sealed when done, not when started
            result = {
                "sealed_response": b64encode(sealed),
                "receipt": receipt.to_payload(),
                "provider_signature": sign_receipt(self.provider_private, authorization, receipt, self.deployment),
            }
            self._journal.execute(
                "UPDATE executions SET state='completed', result=?, updated_at=? WHERE settlement_key=?",
                (json.dumps(result, sort_keys=True), int(time.time()), key),
            )
            return result
        finally:
            self._slots.release()

    def handle_jury(self, job: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
        """Judge one case this Provider was drawn for and sign its vote, or abstain.

        Every input is re-checked against the chain, so a Relay can only relay
        the case, never shape it.
        """
        from .. import jury

        current = int(time.time() if now is None else now)
        if self.cases is None:
            raise JobRejected("this Provider does not serve on juries")
        try:
            key = jury.check_bytes32(job.get("settlement_key"))
            report = jury.check_bytes32(job.get("report_id"))
            evidence = job.get("evidence")
            assignment = self.cases.assignment(key)
            if assignment["status"] != "ready" or not self.cases.is_vote_signer(key, self.signer):
                raise JobRejected("this Provider was not drawn for the case")
            if self.cases.report_evidence(key, report) != jury.evidence_hash(evidence):
                raise JobRejected("evidence differs from the hash committed on-chain")
            signed, request, response = jury.verify_evidence(evidence, self.deployment)
        except (jury.JuryError, SettlementError, ProtocolError, ValueError, TypeError) as exc:
            raise JobRejected(f"invalid jury job: {exc}") from exc
        if signed.authorization.provider_signer == self.signer:
            raise JobRejected("a Provider cannot judge its own case")
        output, _, _ = self.backend({
            "endpoint": "chat", "model": self.jury_model or self.models[0],
            "messages": jury.juror_prompt(evidence, request, response),
            "max_output_tokens": jury.DEFAULT_POLICY["max_output_tokens"], "options": {},
        })
        try:
            verdict = jury.parse_verdict(output)
        except (jury.JuryError, ValueError) as exc:
            return {"abstain": True, "reason_code": "unparseable_verdict", "detail": str(exc)[:200]}
        if verdict["confidence_bps"] < jury.CONFIDENCE_THRESHOLD:
            return {"abstain": True, "reason_code": verdict["reason_code"]}
        voted_report = report if verdict["confirmed"] else jury.ZERO_BYTES32
        return jury.sign_vote(
            self.provider_private, self.deployment, settlement_key=key, assignment_hash=assignment["hash"],
            confirmed=verdict["confirmed"], report_id=voted_report,
            decision=jury.decision_hash(key, assignment["hash"], verdict["confirmed"], voted_report, jury.DEFAULT_POLICY),
            nonce=self.cases.adjudicator_nonce(key, self.signer), deadline=current + 3600,
        )

    def handle_capability_jury(self, job: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
        """Judge a capability case as one of its same-tier jurors: replay every probe on this Provider's own
        model (the control group), grade both answers, and vote by the statistical rule in mycomesh.hunting.

        Replaying takes a while, so the first call starts it and answers {"pending": true} until the vote is
        signed. Every input is checked against the chain first.
        """
        from .. import hunting, jury

        if self.cases is None:
            raise JobRejected("this Provider does not serve on juries")
        case = jury.check_bytes32(job.get("case_id"))
        with self._lock:
            known = self._capability_votes.get(case)
        if known is not None:
            return known
        try:
            record = self.cases.capability_case(case)
            assignment = self.cases.assignment(case)
            if record["status"] != "open" or assignment["status"] != "ready" or not self.cases.is_vote_signer(case, self.signer):
                raise JobRejected("this Provider was not drawn for an open case")
            evidence = job.get("evidence")
            if hunting.evidence_hash(evidence) != record["evidence_hash"]:
                raise JobRejected("evidence differs from the hash committed on-chain")
            probes = hunting.verify_case_evidence(evidence, self.deployment)
            if hunting.keys_hash([item["settlement_key"] for item, _, _ in probes]) != record["keys_hash"]:
                raise JobRejected("evidence holds other probes than the case")
            for item, _, _ in probes:
                settlement = self.cases.settlement(item["settlement_key"])
                void = self.cases.probe_void(item["settlement_key"])
                if settlement["status"] != "voided" or settlement["provider"] != record["provider"] or void["hunter"] != record["hunter"]:
                    raise JobRejected("a probe is not the hunter's voided probe of the accused")
        except (hunting.CaseError, jury.JuryError, SettlementError, ProtocolError, ValueError, KeyError, TypeError) as exc:
            raise JobRejected(f"invalid capability case: {exc}") from exc
        if record["provider"] == self.cases.provider_signer_owner(self.signer):
            raise JobRejected("a Provider cannot judge its own case")
        with self._lock:
            self._capability_votes[case] = {"pending": True}
        threading.Thread(target=self._judge_capability, args=(case, record, assignment, probes, now), daemon=True,
                         name=f"capability-jury-{case[:10]}").start()
        return {"pending": True}

    def _judge_capability(self, case: str, record: Mapping[str, Any], assignment: Mapping[str, Any],
                          probes: list[tuple[Mapping[str, Any], dict, str]], now: int | None) -> None:
        from .. import hunting, jury, rpc
        from ..protocol import output_text

        try:
            accused, control = [], []
            for item, document, answer in probes:
                task = hunting.task_for(item)
                output, _, _ = self.backend(hunting.control_request(document, self.models))
                accused.append(task.grade(answer) == "pass")
                control.append(task.grade(output_text(output)) == "pass")
            outcome = hunting.decide(accused, control)
            confirmed = outcome["convict"]
            report = (jury.report_id(case, record["hunter"], record["evidence_hash"]) if confirmed else jury.ZERO_BYTES32)
            current = int(time.time() if now is None else now)
            vote = jury.sign_vote(
                self.provider_private, self.deployment, settlement_key=case, assignment_hash=assignment["hash"],
                confirmed=confirmed, report_id=report,
                decision=jury.decision_hash(case, assignment["hash"], confirmed, report, hunting.CAPABILITY_POLICY),
                # Votes are checked against chain time, which the control group may have outlasted.
                nonce=self.cases.adjudicator_nonce(case, self.signer),
                deadline=max(current, int(time.time()), rpc.block_time(self.cases.rpc)) + 6 * 3600)
            vote["summary"] = outcome
        except Exception as exc:  # a juror that cannot finish abstains; the case times out without it
            vote = {"abstain": True, "reason_code": "control_group_failed", "detail": str(exc)[:200]}
        with self._lock:
            self._capability_votes[case] = vote

    def _open(self, job: Mapping[str, Any], authorization: Authorization, now: int) -> tuple[bytes, dict[str, Any]]:
        try:
            frame = b64decode(job.get("sealed_request"))
            envelope = json.loads(frame[4:])
            opened = open_frame(frame, recipient_key=self._key_for(str(envelope.get("recipient_key_id"))),
                                expected_purpose=SEALED_REQUEST_PURPOSE, replay_store=self._replay, now=now)
        except (SecureTransportError, ProtocolError, ValueError) as exc:
            raise JobRejected(f"sealed request rejected: {exc}") from exc
        if sha256_hex(opened.payload) != authorization.request_hash:
            raise JobRejected("sealed request does not match the authorized request hash")
        try:
            document = validate_request(json.loads(opened.payload))
            reply_binding = job.get("reply_transport_key")
            verified = verify_transport_key_binding(reply_binding, now=now)
        except (ProtocolError, SecureTransportError, ValueError) as exc:
            raise JobRejected(f"request rejected: {exc}") from exc
        if verified.key_id != document["reply_key_id"]:
            raise JobRejected("reply key is not the one the Consumer authorized")
        return opened.payload, dict(reply_binding)


class _DeltaSealer:
    """Batches streamed text and seals each batch to the Consumer's reply key.

    Deltas are a preview: the Consumer shows them as they arrive and then
    checks that their concatenation equals the text of the final, receipted
    response.
    """

    def __init__(self, identity: NodeIdentity, reply_binding: dict[str, Any], emit: Emit) -> None:
        self.identity, self.binding, self.emit = identity, reply_binding, emit
        self.buffer: list[str] = []
        self.seq = 0
        self.last = time.monotonic()

    def add(self, text: str) -> None:
        if not text:
            return
        self.buffer.append(text)
        if time.monotonic() - self.last >= DELTA_FLUSH_SECONDS or sum(map(len, self.buffer)) >= DELTA_FLUSH_CHARS:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        payload = canonical_json({"seq": self.seq, "delta": "".join(self.buffer)}).encode("utf-8")
        self.buffer, self.seq, self.last = [], self.seq + 1, time.monotonic()
        sealed = seal_frame(payload, sender=self.identity, recipient_binding=self.binding,
                            expected_recipient_peer_id=self.binding["peer_id"], purpose=SEALED_DELTA_PURPOSE,
                            ttl_seconds=300)
        try:
            self.emit(b64encode(sealed))
        except Exception:  # a dropped preview never stops execution; the final response still arrives
            pass
