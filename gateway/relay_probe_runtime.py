"""Explicitly funded active probes through the normal V8/V9 Relay request path.

Disabled by default. Startup never funds/authorizes a key or makes an RPC call.
The operator supplies a dedicated, pre-authorized sponsor payment-key FILE and
explicit limits. Full maximum authorization amounts are durably reserved before
dispatch and never released on timeout/error/restart: uncertain work may settle.
Successful evidence is retained locally; capability mismatches are soft signals,
not model-identity proof, slashing grounds, or an automatic bounty.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import logging
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any, Iterator, Mapping

from .chain import ChainError, normalize_address
from .chain_v8 import build_authorization, payment_key_address, payment_private_key, verify_signed_receipt
from .relay_incidents import evidence_hash
from .relay_integrity import validate_authorization_binding, validate_provider_response
from .relay_probe import RelayProbeCoordinator, RelayProbeError, VerifiedProbeResponse, probe_digest


class RelayProbeRuntimeError(RelayProbeError):
    pass


def _positive(value: Any, name: str) -> int:
    # Environment values are decimal strings; reject booleans, signs, floats.
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise RelayProbeRuntimeError(f"{name} must be an explicit positive integer")
    number = int(value)
    if not 0 < number <= 2**63 - 1:
        raise RelayProbeRuntimeError(f"{name} is outside its supported range")
    return number


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RelayProbeRuntimeError("probe receipt evidence must be finite JSON") from exc


class ProbeBudgetStore:
    """Daily UTC spend ceiling over maximum authorized fees, durable on restart.

    Scope is sponsor address + chain + contract. The same inference request hash
    can never dispatch twice in a scope, even on another day. This sacrifices
    uncertain capacity for safety and is deliberately not an actual-charge meter.
    """

    def __init__(self, path: str) -> None:
        if not path or path == ":memory:" or path.startswith("file:"):
            raise RelayProbeRuntimeError("probe budget requires a durable file database")
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(path, timeout=10, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS probe_budget_reservations (
                scope TEXT NOT NULL, request_hash TEXT NOT NULL, utc_day INTEGER NOT NULL,
                max_fee_units INTEGER NOT NULL, reserved_at INTEGER NOT NULL,
                PRIMARY KEY(scope, request_hash)
            );
            CREATE INDEX IF NOT EXISTS probe_budget_daily ON probe_budget_reservations(scope, utc_day);
            CREATE TABLE IF NOT EXISTS probe_verified_receipts (
                scope TEXT NOT NULL, request_hash TEXT NOT NULL, evidence_hash TEXT NOT NULL UNIQUE,
                evidence_json TEXT NOT NULL, recorded_at INTEGER NOT NULL,
                PRIMARY KEY(scope, request_hash)
            );
        """)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RelayProbeRuntimeError("probe budget store is closed")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def reserve(self, *, scope: str, request_hash: str, max_fee_units: int, daily_budget_units: int,
                now: int | None = None) -> None:
        current = int(time.time()) if now is None else now
        if (not isinstance(scope, str) or not scope or not isinstance(request_hash, str) or not request_hash
                or type(current) is not int or current < 0
                or type(max_fee_units) is not int or type(daily_budget_units) is not int
                or not 0 < max_fee_units <= daily_budget_units <= 2**63 - 1):
            raise RelayProbeRuntimeError("invalid probe budget reservation")
        day = current // 86_400
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM probe_budget_reservations WHERE scope=? AND request_hash=?", (scope, request_hash)).fetchone():
                raise RelayProbeRuntimeError("probe request already reserved; redispatch is forbidden")
            spent = db.execute("SELECT COALESCE(SUM(max_fee_units), 0) FROM probe_budget_reservations WHERE scope=? AND utc_day=?",
                               (scope, day)).fetchone()[0]
            if spent + max_fee_units > daily_budget_units:
                raise RelayProbeRuntimeError("probe daily authorization budget exhausted")
            db.execute("INSERT INTO probe_budget_reservations VALUES (?, ?, ?, ?, ?)",
                       (scope, request_hash, day, max_fee_units, current))

    def reserved_units(self, scope: str, *, now: int | None = None) -> int:
        day = (int(time.time()) if now is None else now) // 86_400
        with self._transaction() as db:
            return int(db.execute("SELECT COALESCE(SUM(max_fee_units), 0) FROM probe_budget_reservations WHERE scope=? AND utc_day=?",
                                  (scope, day)).fetchone()[0])

    def record_receipt(self, *, scope: str, request_hash: str, evidence: Mapping[str, Any]) -> str:
        encoded = _canonical(dict(evidence))
        if len(encoded.encode("utf-8")) > 1_048_576:
            raise RelayProbeRuntimeError("probe receipt evidence exceeds the local limit")
        digest = evidence_hash(json.loads(encoded))
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM probe_budget_reservations WHERE scope=? AND request_hash=?", (scope, request_hash)).fetchone() is None:
                raise RelayProbeRuntimeError("probe receipt has no durable budget reservation")
            row = db.execute("SELECT * FROM probe_verified_receipts WHERE scope=? AND request_hash=?", (scope, request_hash)).fetchone()
            if row is not None:
                if row["evidence_hash"] != digest or row["evidence_json"] != encoded:
                    raise RelayProbeRuntimeError("conflicting verified probe receipt")
                return digest
            db.execute("INSERT INTO probe_verified_receipts VALUES (?, ?, ?, ?, ?)",
                       (scope, request_hash, digest, encoded, int(time.time())))
        return digest

    def get_receipt(self, digest: str) -> dict[str, Any] | None:
        with self._transaction() as db:
            row = db.execute("SELECT evidence_json FROM probe_verified_receipts WHERE evidence_hash=?", (digest,)).fetchone()
            return json.loads(row["evidence_json"]) if row else None


def _sponsor_key(path: str) -> str:
    if not path:
        raise RelayProbeRuntimeError("MYCOMESH_RELAY_PROBE_SPONSOR_KEY_FILE is required")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}:
                raise RelayProbeRuntimeError("probe sponsor key must be a regular 0400/0600 file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise RelayProbeRuntimeError("probe sponsor key must be owned by the Relay process user")
            raw = os.read(fd, 257)
            if len(raw) > 256:
                raise RelayProbeRuntimeError("invalid probe sponsor key file")
        finally:
            os.close(fd)
        return payment_private_key(raw.decode("ascii").strip())
    except (OSError, UnicodeError, ChainError) as exc:
        # Do not interpolate malformed key contents or exception text.
        raise RelayProbeRuntimeError("unable to load a protected probe sponsor key file") from None


class RelayProbeRuntime:
    def __init__(self, state: Any, *, sponsor_key: str, max_fee_units: int, daily_budget_units: int,
                 budget: ProbeBudgetStore, interval_seconds: float, timeout_seconds: float) -> None:
        self.state, self._sponsor_key, self.budget = state, sponsor_key, budget
        self.settlement_version = int(state.settlement_version)
        if self.settlement_version not in {8, 9}:
            raise RelayProbeRuntimeError("active probes require V8 or V9")
        if self.settlement_version == 9:
            from . import chain_v9
            self._build_authorization = chain_v9.build_authorization
            self._verify_signed_receipt = chain_v9.verify_signed_receipt
        else:
            self._build_authorization = build_authorization
            self._verify_signed_receipt = verify_signed_receipt
        self.sponsor_address = payment_key_address(sponsor_key)
        self.max_fee_units, self.daily_budget_units = max_fee_units, daily_budget_units
        self.scope = f"{self.sponsor_address}:{int(state.settlement_chain_id)}:{normalize_address(state.settlement_contract)}"
        self._stop_event = threading.Event()
        self._drain_lock = threading.Lock()
        self._drain_thread: threading.Thread | None = None
        self._drain_complete = threading.Event()
        self._drain_cancel = threading.Event()
        self._closed = False
        self.coordinator = RelayProbeCoordinator(
            state._probe_store, self.dispatch, enabled=True, observation_callback=self.observe,
            interval_seconds=interval_seconds, timeout_seconds=timeout_seconds,
            max_inflight=1, max_probes_per_interval=1,
        )

    def provider_ids(self) -> list[str]:
        from . import relay
        # Candidate/risk checks are local only. Suspect peers remain probeable so
        # successful capability checks can recover; quarantined peers never run.
        return [session.peer_id for session in relay._v7_provider_candidates(
            self.state, chain_id=int(self.state.settlement_chain_id), contract=self.state.settlement_contract,
        ) if relay._advertised_provider_signer(session)]

    def dispatch(self, provider_id: str, envelope: Mapping[str, Any], timeout: float) -> VerifiedProbeResponse:
        from . import relay
        if self._stop_event.is_set():
            raise RelayProbeRuntimeError("probe runtime stopped")
        if not isinstance(envelope.get("input"), str) or not envelope["input"]:
            raise RelayProbeRuntimeError("probe input must be synthetic text")
        if type(envelope.get("max_output_tokens")) is not int or not 1 <= envelope["max_output_tokens"] <= 512:
            raise RelayProbeRuntimeError("probe output limit is invalid")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise RelayProbeRuntimeError("probe timeout is invalid")
        with self.state.lock:
            session = self.state.providers.get(provider_id)
            if session is None:
                raise RelayProbeRuntimeError("probe Provider disconnected")
            peer = dict(session.peer)
            signer = relay._advertised_provider_signer(session)
        if signer is None or relay._provider_quarantine_reason(self.state, session) is not None:
            raise RelayProbeRuntimeError("probe Provider is not eligible")
        model = peer.get("model") or next(iter(peer.get("models") or []), None)
        if not isinstance(model, str) or not model:
            raise RelayProbeRuntimeError("probe Provider has no advertised model")
        body = {"model": model, "input": envelope["input"], "max_output_tokens": envelope["max_output_tokens"],
                "metadata": {"mycomesh_provider_signer": signer}}
        request = relay._v7_normalize_request(self.state, "/v1/responses", body, payment=None)
        selected = peer.get("settlement") or {}
        if (request["chain_id"] != int(self.state.settlement_chain_id)
                or normalize_address(request["contract"]) != normalize_address(self.state.settlement_contract)
                or request["chain_id"] != int(selected.get("chain_id") or 0)
                or normalize_address(request["contract"]) != normalize_address(selected.get("contract") or "")
                or request["pricing_version"] != int(selected.get("pricing_version") or 0)
                or request["pricing_hash"] != str(selected.get("pricing_hash") or "").lower()):
            raise RelayProbeRuntimeError("probe deployment does not match the selected Provider")
        now = int(time.time())
        request_id = evidence_hash({"scope": self.scope, "inference_request_hash": request["request_hash"]})
        self.budget.reserve(scope=self.scope, request_hash=request["request_hash"], max_fee_units=self.max_fee_units,
                            daily_budget_units=self.daily_budget_units, now=now)
        payment = self._build_authorization(
            payment_key=self._sponsor_key, chain_id=request["chain_id"], settlement_contract=request["contract"],
            request_id=request_id, request_hash=request["request_hash"], relay=self.state.payment_address,
            relay_signer=self.state.attestation_address, channel_hash=request["channel_hash"],
            pricing_version=request["pricing_version"], pricing_hash=request["pricing_hash"],
            max_fee=self.max_fee_units, issued_at=now, deadline=now + math.ceil(timeout) + 30,
        )
        request["request_id"] = request_id
        output, receipt_envelope = relay.relay_v7_openai(
            self.state, "/v1/responses", body, payment,
            deadline=time.monotonic() + timeout, audit_provider_id=provider_id,
        )
        # The normal path has already passed transport/body checks. Require its
        # internal proof envelope and independently recheck it before recording a
        # success, so no arbitrary Provider return can construct this trusted type.
        response = receipt_envelope.get("audit_provider_response")
        if receipt_envelope.get("audit_provider_id") != provider_id or not isinstance(response, Mapping):
            raise RelayProbeRuntimeError("probe response lacks the selected Provider proof")
        verified = validate_provider_response(
            response, payment, settlement_version=self.settlement_version, request=request,
            expected_provider=str(peer.get("payment_address") or ""), expected_provider_signer=signer,
            expected_relay=str(self.state.payment_address), expected_relay_signer=str(self.state.attestation_address),
            expected_provider_public_key=str(peer.get("public_key") or ""),
            expected_response_audience=self.state._scheduler_identity.public_key,
        )
        signed = receipt_envelope.get("signed_receipt")
        authorization, signed_usage, _ = self._verify_signed_receipt(signed)
        validate_authorization_binding(payment["authorization"], authorization["authorization"])
        if signed_usage.provider_signer != verified.provider_signer or signed_usage.to_payload() != verified.receipt:
            raise RelayProbeRuntimeError("probe final receipt differs from verified Provider receipt")
        if not isinstance(output, Mapping) or _canonical(output) != _canonical(response.get("raw")):
            raise RelayProbeRuntimeError("probe output differs from its verified body")
        evidence = {
            "schema": "mycomesh.relay.verified-probe.v1", "provider_id": provider_id,
            "provider_signer": verified.provider_signer, "chain_id": request["chain_id"], "contract": request["contract"],
            "probe_envelope": dict(envelope), "payment": payment, "provider_response": dict(response),
            "signed_receipt": signed, "output": dict(output),
        }
        receipt_hash = self.budget.record_receipt(scope=self.scope, request_hash=request["request_hash"], evidence=evidence)
        return VerifiedProbeResponse(provider_id=provider_id, request_hash=probe_digest(envelope),
                                     output_text=response["output_text"], receipt_hash=receipt_hash)

    def observe(self, observation: Mapping[str, Any]) -> None:
        outcome = observation.get("outcome")
        if outcome not in {"passed", "capability_mismatch"}:
            return  # Timeouts, local errors and missing verification are inconclusive.
        if type(observation.get("passed")) is not bool or observation["passed"] != (outcome == "passed"):
            raise RelayProbeRuntimeError("probe observation outcome is inconsistent")
        details = observation.get("evidence") or {}
        probe = self.state._probe_store.get(str(observation.get("probe_id") or ""))
        committed = {"passed": observation["passed"], "result_hash": observation.get("result_hash"), "evidence": details}
        if (probe["status"] != "completed" or probe["provider_id"] != observation.get("provider_id")
                or probe["result_hash"] != observation.get("result_hash")
                or _canonical(json.loads(probe["evidence_json"])) != _canonical(committed)
                or probe_digest(details) != observation.get("result_hash")):
            raise RelayProbeRuntimeError("probe observation differs from the completed durable result")
        saved = self.budget.get_receipt(str(details.get("receipt_hash") or ""))
        if (saved is None or saved["provider_id"] != observation.get("provider_id")
                or probe_digest(saved["probe_envelope"]) != probe["request_hash"]
                or saved["probe_envelope"]["nonce"] != probe["nonce"]):
            raise RelayProbeRuntimeError("probe observation has no verified persisted receipt")
        from . import relay
        aliases = (saved["provider_id"], relay._signer_risk_key(saved["chain_id"], saved["contract"], saved["provider_signer"]))
        for identity in aliases:
            self.state._incident_store.record_observation(
                provider_id=identity, evidence_id="probe:" + probe["probe_id"],
                passed=observation["passed"], hard_violation=False,
            )

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.coordinator.tick(self.provider_ids())
            except Exception as exc:
                # Never include exception values that may contain credentials.
                logging.getLogger(__name__).warning("active probe scheduler paused (%s)", type(exc).__name__)
            self._stop_event.wait(min(0.25, self.coordinator.timeout_seconds, self.coordinator.interval_seconds))

    def stop(self) -> None:
        self._stop_event.set()
        self.coordinator.stop()

    def drain(self, timeout_seconds: float = 1.0) -> bool:
        """Collect existing results after stop, without dispatching new probes.

        The caller's wait is bounded by a monotonic deadline. A single daemon
        poller also bounds shutdown when result persistence or a risk callback
        blocks inside tick. It cannot cancel dispatched work or release its
        reserved funds. False means the budget/store must remain open; a later
        call may finish draining once the outstanding callback exits.
        """
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise RelayProbeRuntimeError("probe drain timeout must be finite and positive")
        if not self._stop_event.is_set():
            raise RelayProbeRuntimeError("stop probe runtime before draining")
        deadline = time.monotonic() + timeout_seconds
        if not self._drain_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            return False
        try:
            if self._closed:
                raise RelayProbeRuntimeError("probe runtime is closed")
            thread = self._drain_thread
            if thread is None or not thread.is_alive():
                self._drain_complete = threading.Event()
                self._drain_cancel = threading.Event()
                complete, cancel = self._drain_complete, self._drain_cancel

                def poll() -> None:
                    try:
                        while not cancel.is_set() and time.monotonic() < deadline:
                            self.coordinator.tick(())
                            if self.coordinator.inflight_count == 0:
                                complete.set()
                                return
                            cancel.wait(min(0.025, max(0.0, deadline - time.monotonic())))
                    except Exception as exc:
                        logging.getLogger(__name__).warning("active probe drain incomplete (%s)", type(exc).__name__)

                thread = threading.Thread(target=poll, name="mycomesh-relay-probe-drain", daemon=True)
                self._drain_thread = thread
                try:
                    thread.start()
                except RuntimeError:
                    logging.getLogger(__name__).warning("active probe drain could not start its collector")
                    return False
            complete, cancel = self._drain_complete, self._drain_cancel
        finally:
            self._drain_lock.release()
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            cancel.set()
            return False
        return complete.is_set()

    def close(self) -> None:
        with self._drain_lock:
            if self._closed:
                return
            if self._drain_thread is not None and self._drain_thread.is_alive():
                raise RelayProbeRuntimeError("cannot close probe budget while result collection remains in flight")
            self.stop()
            if self.coordinator.inflight_count:
                raise RelayProbeRuntimeError("cannot close probe budget while dispatches remain in flight")
            self.budget.close()
            self._closed = True


def create_relay_probe_runtime(state: Any, env: Mapping[str, str] | None = None) -> RelayProbeRuntime | None:
    settings = os.environ if env is None else env
    enabled = str(settings.get("MYCOMESH_RELAY_PROBES_ENABLED", "false")).strip().lower()
    if enabled in {"false", "0", "no", "off", ""}:
        return None  # Crucially: no sponsor file access when disabled.
    if enabled not in {"true", "1", "yes", "on"}:
        raise RelayProbeRuntimeError("MYCOMESH_RELAY_PROBES_ENABLED must be boolean")
    if int(state.settlement_version) not in {8, 9} or state._settlement_submitter is None:
        raise RelayProbeRuntimeError("active probes require a ready V8/V9 settlement path")
    for store in (state._probe_store, state._incident_store):
        path = getattr(store, "path", None)
        if not path or path == ":memory:" or path.startswith("file:"):
            raise RelayProbeRuntimeError("active probes require durable probe and incident stores")
    max_fee = _positive(settings.get("MYCOMESH_RELAY_PROBE_MAX_FEE_UNITS"), "MYCOMESH_RELAY_PROBE_MAX_FEE_UNITS")
    daily = _positive(settings.get("MYCOMESH_RELAY_PROBE_DAILY_BUDGET_UNITS"), "MYCOMESH_RELAY_PROBE_DAILY_BUDGET_UNITS")
    if daily < max_fee:
        raise RelayProbeRuntimeError("probe daily budget is smaller than one authorization")
    sponsor_key = _sponsor_key(str(settings.get("MYCOMESH_RELAY_PROBE_SPONSOR_KEY_FILE") or ""))
    sponsor = payment_key_address(sponsor_key)
    prohibited = {str(state.payment_address).lower(), str(state.attestation_address).lower(),
                  str(getattr(state._settlement_submitter, "address", "")).lower(),
                  *(str(key).lower() for key in state.attestation_private_keys)}
    if state.settlement_private_key:
        prohibited.add(payment_key_address(state.settlement_private_key))
    if sponsor in prohibited:
        raise RelayProbeRuntimeError("probe sponsor must not reuse payout, attestation, or relayer keys")
    interval = _positive(settings.get("MYCOMESH_RELAY_PROBE_INTERVAL_SECONDS", "60"), "probe interval")
    timeout = _positive(settings.get("MYCOMESH_RELAY_PROBE_TIMEOUT_SECONDS", "20"), "probe timeout")
    if interval > 600 or timeout > 600:
        raise RelayProbeRuntimeError("probe interval and timeout must not exceed 600 seconds")
    budget = ProbeBudgetStore(str(settings.get("MYCOMESH_RELAY_PROBE_BUDGET_DB") or (state._probe_store.path + ".budget.sqlite3")))
    try:
        return RelayProbeRuntime(state, sponsor_key=sponsor_key, max_fee_units=max_fee,
                                 daily_budget_units=daily, budget=budget,
                                 interval_seconds=interval, timeout_seconds=timeout)
    except BaseException:
        budget.close()
        raise
