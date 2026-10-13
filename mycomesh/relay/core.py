"""Relay admission, relay-blind dispatch and durable batch settlement."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import rpc
from ..evm import ZERO_ADDRESS, address_of
from ..protocol import Prices, ProtocolError, verify_transport_attestation
from ..secure_transport import SecureTransportError, verify_transport_key_binding
from ..settlement import (
    MAX_BATCH_SIZE, Authorization, Deployment, Receipt, SettlementError, SettlementReader, SignedReceipt,
    RELEASE_BATCH, encode_release_batch, encode_settle_batch, sign_dispatch, verify_authorization,
)

# Delivers one job to a connected Provider and returns its result, or raises.
ProviderSend = Callable[[dict[str, Any]], dict[str, Any]]


# Admission reads chain state for every request; these run them side by side.
_READS = ThreadPoolExecutor(max_workers=64, thread_name_prefix="relay-reads")
TIER_CACHE_SECONDS = 600  # a Provider's tier changes only by re-registering
DELIVERY_CHECK_SECONDS = 300  # how often to ask whether the settlement requires delivery signatures (v10)

class SubmitterUnfunded(RuntimeError):
    """The account that submits settlements cannot pay gas: the receipts wait, uncounted, until it is funded."""


def _unfunded(exc: Exception) -> bool:
    return "insufficient funds" in str(exc).lower()


class RelayError(RuntimeError):
    def __init__(self, message: str, status: int = 400, *, dispatched: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.dispatched = dispatched


@dataclass
class ProviderSession:
    descriptor: dict[str, Any]
    send: ProviderSend
    owner: str
    in_flight: int = 0  # jobs dispatched and not yet answered

    @property
    def capacity(self) -> int:
        return max(1, int(self.descriptor.get("capacity") or 1))


@dataclass
class PreparedJob:
    job: dict[str, Any]
    authorization: Authorization
    key_signature: str
    session: ProviderSession
    owner: str


@dataclass
class RelayCore:
    deployment: Deployment
    relay_private: str
    reader: SettlementReader
    data_dir: Path
    pricing: Any = None  # mycomesh.pricing.NetworkPricing: capacity and network-price checks
    providers: dict[str, ProviderSession] = field(default_factory=dict, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _outstanding_owner: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _outstanding_provider: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _outstanding_key: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _settle_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _key_owner: dict[str, str] = field(default_factory=dict, init=False, repr=False)  # last owner seen per payment key
    _tiers: dict[str, tuple[float, int]] = field(default_factory=dict, init=False, repr=False)
    _delivery: tuple[float, bool] | None = field(default=None, init=False, repr=False)
    # Providers this Relay stopped routing to (failed probes); local policy, not a verdict.
    suspended: dict[str, str] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.signer = address_of(self.relay_private)
        self.queue = SettlementQueue(self.data_dir / "relay-settlement.sqlite3")

    # ---------------- Providers ----------------

    def register_provider(self, descriptor: Mapping[str, Any], send: ProviderSend, *, now: int | None = None) -> str:
        """Admit any Provider whose signer is bound on-chain (no allowlist, no stake)."""
        current = int(time.time() if now is None else now)
        try:
            binding = verify_transport_key_binding(descriptor["transport_key"], now=current)
            signer = verify_transport_attestation(
                descriptor["transport_attestation"], identity_public_key=binding.identity_public_key,
                transport_key_id=binding.key_id, deployment=self.deployment, now=current,
            )
            Prices.from_payload(descriptor["prices"])
        except (KeyError, ProtocolError, SecureTransportError, ValueError, TypeError) as exc:
            raise RelayError(f"invalid Provider descriptor: {exc}") from exc
        if signer != str(descriptor.get("provider_signer", "")).lower():
            raise RelayError("descriptor signer differs from its attestation")
        owner = self.reader.provider_owner(signer)
        if owner == ZERO_ADDRESS:
            raise RelayError("Provider signer is not bound on-chain")
        with self._lock:
            self.providers[signer] = ProviderSession(dict(descriptor), send, owner)
        return signer

    def unregister_provider(self, signer: str) -> None:
        with self._lock:
            self.providers.pop(signer.lower(), None)

    def provider_descriptors(self) -> list[dict[str, Any]]:
        with self._lock:
            return [session.descriptor for signer, session in self.providers.items() if signer not in self.suspended]

    def suspend(self, signer: str, reason: str) -> None:
        with self._lock:
            self.suspended[signer.lower()] = reason

    # ---------------- requests ----------------

    def handle_request(self, payload: Mapping[str, Any], *, now: int | None = None,
                       on_chunk: Callable[[str], None] | None = None) -> dict[str, Any]:
        return self.dispatch(self.prepare(payload, now=now), on_chunk=on_chunk)

    def prepare(self, payload: Mapping[str, Any], *, now: int | None = None) -> "PreparedJob":
        """Verify and admit a request; nothing is dispatched yet, so errors here are safe to fail over."""
        current = int(time.time() if now is None else now)
        try:
            authorization = Authorization.from_payload(payload.get("authorization"))
            key_signature = str(payload.get("key_signature"))
            verify_authorization(authorization, key_signature, self.deployment, now=current, relay_signer=self.signer)
        except (SettlementError, ValueError, TypeError) as exc:
            raise RelayError(f"payment authorization rejected: {exc}", 402) from exc
        with self._lock:
            session = self.providers.get(authorization.provider_signer)
            if authorization.provider_signer in self.suspended:
                session = None
        if session is None:
            raise RelayError("the authorized Provider is not connected to this Relay", 503)
        # A busy Provider would refuse the job anyway: say so now, before any chain read, so the Consumer
        # fails over to another Provider at once.
        with self._lock:
            if session.in_flight >= session.capacity:
                raise RelayError("provider is at capacity", 503)
            session.in_flight += 1
        try:
            owner = self._admit(authorization, session)
        except BaseException:
            with self._lock:
                session.in_flight -= 1
            raise
        job = {
            "authorization": authorization.to_payload(), "key_signature": key_signature,
            "relay_signature": sign_dispatch(self.relay_private, authorization, self.deployment),
            "sealed_request": payload.get("sealed_request"), "reply_transport_key": payload.get("reply_transport_key"),
        }
        return PreparedJob(job, authorization, key_signature, session, owner)

    def dispatch(self, prepared: "PreparedJob", *, on_chunk: Callable[[str], None] | None = None) -> dict[str, Any]:
        try:
            return self._dispatch(prepared, on_chunk)
        finally:
            with self._lock:
                prepared.session.in_flight -= 1

    def _dispatch(self, prepared: "PreparedJob", on_chunk: Callable[[str], None] | None) -> dict[str, Any]:
        job, authorization, key_signature, session, owner = (
            prepared.job, prepared.authorization, prepared.key_signature, prepared.session, prepared.owner)
        try:
            if on_chunk is not None:
                job = {**job, "stream": True}
                result = session.send(job, on_chunk)
            else:
                result = session.send(job)
        except Exception as exc:
            self._release(owner, session.owner, authorization.max_fee, authorization.key)
            raise RelayError(f"Provider did not execute the request: {exc}", 502) from exc
        try:
            signed = SignedReceipt(authorization, Receipt.from_payload(result.get("receipt")), key_signature,
                                   str(result.get("provider_signature")), job["relay_signature"])
            signed.verify(self.deployment)
            if self.pricing is not None:
                receipt = signed.receipt
                try:
                    price = self.pricing.quote(authorization.provider_signer, authorization.issued_at,
                                               receipt.input_tokens, receipt.output_tokens)
                except rpc.RpcError:
                    price = None  # settlement enforces the price anyway
                if price is not None and receipt.actual_fee != min(price, authorization.max_fee):
                    raise SettlementError("fee is not the network price")
        except (SettlementError, ValueError, TypeError, AttributeError) as exc:
            self._release(owner, session.owner, authorization.max_fee, authorization.key)
            raise RelayError(f"Provider returned an invalid receipt: {exc}", 502, dispatched=True) from exc
        self.queue.add(signed, owner=owner, provider=session.owner)
        self._release(owner, session.owner, authorization.max_fee, authorization.key)
        return {"sealed_response": result.get("sealed_response"), "receipt": signed.to_payload()}

    def _admit(self, authorization: Authorization, session: ProviderSession) -> str:
        # The chain reads run side by side, so admission costs about one RPC round trip (a public RPC answers
        # each in ~0.1-0.25 s). Everything is read fresh for every request except a Provider's tier (it changes
        # only by re-registering) and the day's price multiplier (fixed for the day).
        def budget() -> tuple[int, int]:
            try:
                return self.reader.key_budget(authorization.key)
            except rpc.RpcError:  # a settlement without per-key budgets
                return 0, 0

        def tier() -> int:
            signer = authorization.provider_signer
            with self._lock:
                cached = self._tiers.get(signer)
            if cached is not None and time.monotonic() - cached[0] < TIER_CACHE_SECONDS:
                return cached[1]
            value = self.pricing.signer(signer)["tier"]
            with self._lock:
                self._tiers[signer] = (time.monotonic(), value)
            return value

        def capacity() -> int | None:
            if self.pricing is None:
                return None
            try:
                multiplier = self.pricing.multiplier(tier())  # both cached: no round trip after the first
                return self.pricing.remaining_capacity(authorization.provider_signer) * multiplier // 1_000_000
            except rpc.RpcError:
                return None

        grant_f = _READS.submit(self.reader.key_grant, authorization.key)
        with self._lock:
            hinted_owner = self._key_owner.get(authorization.key)
        # The balance of the owner this key had last time, read alongside the grant; re-read if it changed.
        balance_f = _READS.submit(self.reader.available_balance, hinted_owner) if hinted_owner else None
        pending_f = _READS.submit(self.reader.pending_exposure, session.owner)
        cap_f = _READS.submit(self.reader.exposure_cap, session.owner)
        budget_f, capacity_f = _READS.submit(budget), _READS.submit(capacity)
        grant = grant_f.result()
        if not grant["active"] or grant["owner"] == ZERO_ADDRESS or grant["max_per_request"] < authorization.max_fee:
            raise RelayError("payment key is not an active grant for this fee", 402)
        if grant["valid_until"] and grant["valid_until"] < authorization.deadline:
            raise RelayError("payment key expires before the authorization", 402)
        owner = grant["owner"]
        with self._lock:
            self._key_owner[authorization.key] = owner
        balance = balance_f.result() if balance_f is not None and hinted_owner == owner else self.reader.available_balance(owner)
        pending, cap = pending_f.result(), cap_f.result()
        limit, spent = budget_f.result()
        if limit:
            with self._lock:
                committed = spent + self._outstanding_key.get(authorization.key, 0) + self.queue.unsettled_fees(key=authorization.key)
            if committed + authorization.max_fee > limit:
                # A settlement may be landing right now: its fee is already spent on-chain but still queued
                # here. Let it finish, then count once more before refusing the tenant.
                with self._settle_lock:
                    limit, spent = self.reader.key_budget(authorization.key)
        remaining = capacity_f.result()
        with self._lock:
            if limit:
                # A tenant key's budget is enforced at settlement; never dispatch work it could not pay for.
                committed = spent + self._outstanding_key.get(authorization.key, 0) + self.queue.unsettled_fees(key=authorization.key)
                if committed + authorization.max_fee > limit:
                    raise RelayError("payment key has reached its budget", 402)
            owner_load = self._outstanding_owner.get(owner, 0) + self.queue.unsettled_fees(owner=owner)
            provider_load = self._outstanding_provider.get(session.owner, 0) + self.queue.unsettled_fees(provider=session.owner)
            if owner_load + authorization.max_fee > balance:
                raise RelayError("consumer deposit does not cover outstanding requests", 402)
            if pending + provider_load + authorization.max_fee > cap:
                raise RelayError("Provider has reached its unsettled exposure cap", 503)
            if remaining is not None and provider_load + authorization.max_fee > remaining:
                raise RelayError("Provider has used its declared capacity for today", 503)
            self._outstanding_key[authorization.key] = self._outstanding_key.get(authorization.key, 0) + authorization.max_fee
            self._outstanding_owner[owner] = self._outstanding_owner.get(owner, 0) + authorization.max_fee
            self._outstanding_provider[session.owner] = self._outstanding_provider.get(session.owner, 0) + authorization.max_fee
        return owner

    def _release(self, owner: str, provider: str, amount: int, key: str = "") -> None:
        with self._lock:
            if key:
                self._outstanding_key[key] = max(0, self._outstanding_key.get(key, 0) - amount)
            self._outstanding_owner[owner] = max(0, self._outstanding_owner.get(owner, 0) - amount)
            self._outstanding_provider[provider] = max(0, self._outstanding_provider.get(provider, 0) - amount)

    # ---------------- settlement ----------------

    def settle_queued(self, submitter_private: str, rpc_url: str) -> list[str]:
        """Submit queued receipts; a reverted batch is retried one receipt at a time."""
        with self._settle_lock:
            return self._settle_queued(submitter_private, rpc_url)

    def _for_settlement(self, receipt: SignedReceipt) -> SignedReceipt:
        """A queued receipt as settleBatch takes it: since v10, signed by this Relay as delivered (every queued
        receipt's answer came back through it). Before the upgrade, the dispatch signature it carries."""
        if self._delivery is None or time.monotonic() - self._delivery[0] > DELIVERY_CHECK_SECONDS:
            try:
                self._delivery = (time.monotonic(), self.reader.requires_delivery())
            except rpc.RpcError:
                if self._delivery is None:
                    raise
        return receipt.delivered(self.relay_private, self.deployment) if self._delivery[1] else receipt

    def _settle_queued(self, submitter_private: str, rpc_url: str) -> list[str]:
        batch = self.queue.take(MAX_BATCH_SIZE)
        if not batch:
            return []
        settled: list[str] = []
        try:
            self._submit(submitter_private, rpc_url, encode_settle_batch([self._for_settlement(item) for _, item in batch]))
            settled = [key for key, _ in batch]
        except rpc.RpcError as exc:
            if _unfunded(exc):
                raise SubmitterUnfunded(f"{address_of(submitter_private)} cannot pay gas; {len(batch)}+ receipts wait") from exc
            self._delivery = None  # the contract may have just been upgraded: ask again
            for key, item in batch:
                try:
                    self._submit(submitter_private, rpc_url, encode_settle_batch([self._for_settlement(item)]))
                    settled.append(key)
                except rpc.RpcError as exc:
                    if _unfunded(exc):  # not the receipt's fault: stop here, count nothing
                        for done in settled:
                            self.queue.mark(done, "settled")
                        raise SubmitterUnfunded(f"{address_of(submitter_private)} cannot pay gas") from exc
                    # Transient RPC failures and a chain clock behind issuedAt both clear on retry.
                    self.queue.fail(key, str(exc)[:300])
        for key in settled:
            self.queue.mark(key, "settled")
        return settled

    def release_due(self, submitter_private: str, rpc_url: str, dispute_window: int, *, now: int | None = None) -> list[str]:
        current = int(time.time() if now is None else now)
        released = []
        due = self.queue.due_for_release(current - dispute_window)
        for start in range(0, len(due), RELEASE_BATCH):
            batch = due[start:start + RELEASE_BATCH]
            try:
                self._submit(submitter_private, rpc_url, encode_release_batch(batch))
            except rpc.RpcError as exc:
                # A revert means none of them was still due (a keeper released them, or they were disputed).
                if "revert" not in str(exc).lower():
                    continue
            for key in batch:
                self.queue.mark(key, "released")
            released += batch
        return released

    def _submit(self, submitter_private: str, rpc_url: str, calldata: str) -> None:
        tx = rpc.send_transaction(rpc_url, submitter_private, to=self.deployment.settlement, data=calldata)
        rpc.wait_for_receipt(rpc_url, tx)


MAX_SETTLE_ATTEMPTS = 6


class SettlementQueue:
    """Durable receipt queue: nothing a Provider signed is ever lost."""

    def __init__(self, path: Path) -> None:
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS receipts (settlement_key TEXT PRIMARY KEY, payload TEXT NOT NULL, "
            "owner TEXT NOT NULL, provider TEXT NOT NULL, fee INTEGER NOT NULL, state TEXT NOT NULL, "
            "error TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(receipts)")}
        if "attempts" not in columns:
            self._db.execute("ALTER TABLE receipts ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
        if "payment_key" not in columns:
            self._db.execute("ALTER TABLE receipts ADD COLUMN payment_key TEXT NOT NULL DEFAULT ''")
        self._lock = threading.Lock()

    def add(self, signed: SignedReceipt, *, owner: str, provider: str) -> None:
        now = int(time.time())
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO receipts (settlement_key, payload, owner, provider, fee, state, error, created_at, "
                "updated_at, payment_key) VALUES (?, ?, ?, ?, ?, 'queued', NULL, ?, ?, ?)",
                (signed.authorization.settlement_key, json.dumps(signed.to_payload(), sort_keys=True),
                 owner, provider, signed.receipt.actual_fee, now, now, signed.authorization.key),
            )

    def take(self, limit: int) -> list[tuple[str, SignedReceipt]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT settlement_key, payload FROM receipts WHERE state='queued' ORDER BY created_at LIMIT ?", (limit,)
            ).fetchall()
        return [(key, SignedReceipt.from_payload(json.loads(payload))) for key, payload in rows]

    def mark(self, key: str, state: str, *, error: str | None = None) -> None:
        with self._lock:
            self._db.execute("UPDATE receipts SET state=?, error=?, updated_at=? WHERE settlement_key=?",
                             (state, error, int(time.time()), key))

    def fail(self, key: str, error: str, *, max_attempts: int = MAX_SETTLE_ATTEMPTS) -> None:
        """Count a failed submission; only repeated failures reject a receipt for good."""
        with self._lock:
            self._db.execute(
                "UPDATE receipts SET attempts=attempts+1, error=?, updated_at=?, "
                "state=CASE WHEN attempts+1 >= ? THEN 'rejected' ELSE state END WHERE settlement_key=?",
                (error, int(time.time()), max_attempts, key),
            )

    def unsettled_fees(self, *, owner: str | None = None, provider: str | None = None, key: str | None = None) -> int:
        column, value = (("owner", owner) if owner is not None else ("provider", provider) if provider is not None
                         else ("payment_key", key))
        with self._lock:
            row = self._db.execute(
                f"SELECT COALESCE(SUM(fee), 0) FROM receipts WHERE state='queued' AND {column}=?", (value,)
            ).fetchone()
        return int(row[0])

    def due_for_release(self, settled_before: int) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT settlement_key FROM receipts WHERE state='settled' AND updated_at <= ?", (settled_before,)
            ).fetchall()
        return [row[0] for row in rows]

    def oldest_queued_age(self) -> float | None:
        with self._lock:
            row = self._db.execute("SELECT MIN(created_at) FROM receipts WHERE state='queued'").fetchone()
        return None if row[0] is None else time.time() - row[0]

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._db.execute("SELECT state, COUNT(*) FROM receipts GROUP BY state").fetchall())
