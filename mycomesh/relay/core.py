"""Relay admission, relay-blind dispatch and durable batch settlement."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import rpc
from ..evm import ZERO_ADDRESS, address_of
from ..protocol import Prices, ProtocolError, verify_transport_attestation
from ..secure_transport import SecureTransportError, verify_transport_key_binding
from ..settlement import (
    MAX_BATCH_SIZE, Authorization, Deployment, Receipt, SettlementError, SettlementReader, SignedReceipt,
    encode_release, encode_settle_batch, sign_dispatch, verify_authorization,
)

# Delivers one job to a connected Provider and returns its result, or raises.
ProviderSend = Callable[[dict[str, Any]], dict[str, Any]]


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


@dataclass
class RelayCore:
    deployment: Deployment
    relay_private: str
    reader: SettlementReader
    data_dir: Path
    providers: dict[str, ProviderSession] = field(default_factory=dict, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _outstanding_owner: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _outstanding_provider: dict[str, int] = field(default_factory=dict, init=False, repr=False)

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
            return [session.descriptor for session in self.providers.values()]

    # ---------------- requests ----------------

    def handle_request(self, payload: Mapping[str, Any], *, now: int | None = None) -> dict[str, Any]:
        current = int(time.time() if now is None else now)
        try:
            authorization = Authorization.from_payload(payload.get("authorization"))
            key_signature = str(payload.get("key_signature"))
            verify_authorization(authorization, key_signature, self.deployment, now=current, relay_signer=self.signer)
        except (SettlementError, ValueError, TypeError) as exc:
            raise RelayError(f"payment authorization rejected: {exc}", 402) from exc
        with self._lock:
            session = self.providers.get(authorization.provider_signer)
        if session is None:
            raise RelayError("the authorized Provider is not connected to this Relay", 503)
        owner = self._admit(authorization, session)
        job = {
            "authorization": authorization.to_payload(), "key_signature": key_signature,
            "relay_signature": sign_dispatch(self.relay_private, authorization, self.deployment),
            "sealed_request": payload.get("sealed_request"), "reply_transport_key": payload.get("reply_transport_key"),
        }
        try:
            result = session.send(job)
        except Exception as exc:
            self._release(owner, session.owner, authorization.max_fee)
            raise RelayError(f"Provider did not execute the request: {exc}", 502) from exc
        try:
            signed = SignedReceipt(authorization, Receipt.from_payload(result.get("receipt")), key_signature,
                                   str(result.get("provider_signature")), job["relay_signature"])
            signed.verify(self.deployment)
        except (SettlementError, ValueError, TypeError, AttributeError) as exc:
            self._release(owner, session.owner, authorization.max_fee)
            raise RelayError(f"Provider returned an invalid receipt: {exc}", 502, dispatched=True) from exc
        self.queue.add(signed, owner=owner, provider=session.owner)
        self._release(owner, session.owner, authorization.max_fee)
        return {"sealed_response": result.get("sealed_response"), "receipt": signed.to_payload()}

    def _admit(self, authorization: Authorization, session: ProviderSession) -> str:
        grant = self.reader.key_grant(authorization.key)
        if not grant["active"] or grant["owner"] == ZERO_ADDRESS or grant["max_per_request"] < authorization.max_fee:
            raise RelayError("payment key is not an active grant for this fee", 402)
        if grant["valid_until"] and grant["valid_until"] < authorization.deadline:
            raise RelayError("payment key expires before the authorization", 402)
        owner = grant["owner"]
        balance = self.reader.available_balance(owner)
        pending, cap = self.reader.exposure(session.owner)
        with self._lock:
            owner_load = self._outstanding_owner.get(owner, 0) + self.queue.unsettled_fees(owner=owner)
            provider_load = self._outstanding_provider.get(session.owner, 0) + self.queue.unsettled_fees(provider=session.owner)
            if owner_load + authorization.max_fee > balance:
                raise RelayError("consumer deposit does not cover outstanding requests", 402)
            if pending + provider_load + authorization.max_fee > cap:
                raise RelayError("Provider has reached its unsettled exposure cap", 503)
            self._outstanding_owner[owner] = self._outstanding_owner.get(owner, 0) + authorization.max_fee
            self._outstanding_provider[session.owner] = self._outstanding_provider.get(session.owner, 0) + authorization.max_fee
        return owner

    def _release(self, owner: str, provider: str, amount: int) -> None:
        with self._lock:
            self._outstanding_owner[owner] = max(0, self._outstanding_owner.get(owner, 0) - amount)
            self._outstanding_provider[provider] = max(0, self._outstanding_provider.get(provider, 0) - amount)

    # ---------------- settlement ----------------

    def settle_queued(self, submitter_private: str, rpc_url: str) -> list[str]:
        """Submit queued receipts; a reverted batch is retried one receipt at a time."""
        batch = self.queue.take(MAX_BATCH_SIZE)
        if not batch:
            return []
        settled: list[str] = []
        try:
            self._submit(submitter_private, rpc_url, encode_settle_batch([item for _, item in batch]))
            settled = [key for key, _ in batch]
        except rpc.RpcError:
            for key, item in batch:
                try:
                    self._submit(submitter_private, rpc_url, encode_settle_batch([item]))
                    settled.append(key)
                except rpc.RpcError as exc:
                    self.queue.mark(key, "rejected", error=str(exc)[:300])
        for key in settled:
            self.queue.mark(key, "settled")
        return settled

    def release_due(self, submitter_private: str, rpc_url: str, dispute_window: int, *, now: int | None = None) -> list[str]:
        current = int(time.time() if now is None else now)
        released = []
        for key in self.queue.due_for_release(current - dispute_window):
            try:
                self._submit(submitter_private, rpc_url, encode_release(key))
            except rpc.RpcError as exc:
                if "not pending" not in str(exc) and "revert" not in str(exc).lower():
                    continue
            self.queue.mark(key, "released")
            released.append(key)
        return released

    def _submit(self, submitter_private: str, rpc_url: str, calldata: str) -> None:
        tx = rpc.send_transaction(rpc_url, submitter_private, to=self.deployment.settlement, data=calldata)
        rpc.wait_for_receipt(rpc_url, tx)


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
        self._lock = threading.Lock()

    def add(self, signed: SignedReceipt, *, owner: str, provider: str) -> None:
        now = int(time.time())
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO receipts VALUES (?, ?, ?, ?, ?, 'queued', NULL, ?, ?)",
                (signed.authorization.settlement_key, json.dumps(signed.to_payload(), sort_keys=True),
                 owner, provider, signed.receipt.actual_fee, now, now),
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

    def unsettled_fees(self, *, owner: str | None = None, provider: str | None = None) -> int:
        column, value = ("owner", owner) if owner is not None else ("provider", provider)
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
