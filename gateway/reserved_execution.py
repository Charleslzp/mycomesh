"""V10 Provider execution journal: one writer, durable permanent max-fee debits.

No private key, signing or network calls live in the ledger. Callers supply a
verified canonical channel snapshot and already-verified authorization/dispatch.
The independent outbox CLI below exports complete signed settlement calldata;
it never needs a Relay to sign after execution.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
import uuid
from typing import Any, Mapping

from .chain import normalize_address, normalize_bytes32


class ReservedExecutionError(ValueError):
    pass


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _uint(value: Any, name: str, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0) or value >= 2**256:
        raise ReservedExecutionError(f"invalid {name}")
    return value


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _protected_parent(path: Path) -> None:
    for parent in [path.parent, *path.parent.parents]:
        if parent.is_symlink():
            raise ReservedExecutionError("journal paths must not use symlink directories")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ReservedExecutionError("journal state must be regular non-symlink files")


class ReservedExecutionLedger:
    """Lock held until close. Neither failure nor completion refunds max-fee quota.

    Deleting or rolling back only the database fails against a separate anchor.
    If all local state is lost, past-start channels cannot be activated into a
    fresh ledger. Recover the original state or open a new future-start channel.
    """

    def __init__(self, path: str | Path, *, anchor_path: str | Path,
                 provider_signer: str, create: bool = False):
        import fcntl
        self.path, self.anchor_path = Path(path).absolute(), Path(anchor_path).absolute()
        if self.path == self.anchor_path:
            raise ReservedExecutionError("ledger and anchor must be separate files")
        self.provider_signer = normalize_address(provider_signer)
        self._mutex = threading.RLock()
        self._closed = False
        self._db = None
        self._lock_fd = None
        self._database_lock_fd = None
        self._fcntl = fcntl
        for target in (self.path, self.anchor_path):
            _protected_parent(target)
        lock_path = self.anchor_path.with_name(self.anchor_path.name + ".writer-lock")
        self._lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            database_lock = self.path.with_name(self.path.name + ".writer-lock")
            self._database_lock_fd = os.open(database_lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self._database_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            present = (self.path.exists(), self.anchor_path.exists())
            if present[0] != present[1]:
                raise ReservedExecutionError("ledger/anchor missing; recovery is required, never initialize an empty replacement")
            if not present[0] and create is not True:
                raise ReservedExecutionError("ledger is not initialized; explicit initialization is required")
            self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=10)
            os.chmod(self.path, 0o600)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            if not present[0]:
                self._db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), database_id TEXT NOT NULL, signer TEXT NOT NULL, sequence INTEGER NOT NULL);
                    CREATE TABLE channels (contract TEXT NOT NULL, channel_id TEXT NOT NULL, snapshot TEXT NOT NULL, binding_hash TEXT NOT NULL, capacity TEXT NOT NULL, reserved TEXT NOT NULL, valid_from INTEGER NOT NULL, admit_until INTEGER NOT NULL, claim_until INTEGER NOT NULL, PRIMARY KEY(contract,channel_id));
                    CREATE TABLE executions (contract TEXT NOT NULL, channel_id TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL, max_fee TEXT NOT NULL, authorization TEXT NOT NULL, dispatch TEXT NOT NULL, state TEXT NOT NULL, response TEXT, signed_receipt TEXT, response_digest TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY(contract,channel_id,request_id));
                    COMMIT;
                """)
                self._db.execute("INSERT INTO meta VALUES(1,?,?,0)", (uuid.uuid4().hex, self.provider_signer))
                _sync_directory(self.path.parent)
            meta = self._db.execute("SELECT * FROM meta WHERE id=1").fetchone()
            if meta is None or meta["signer"] != self.provider_signer:
                raise ReservedExecutionError("ledger signer mismatch")
            self.database_id = meta["database_id"]
            self._inode = (self.path.stat().st_dev, self.path.stat().st_ino)
            if present[0]:
                anchor = json.loads(self.anchor_path.read_text())
                if (anchor.get("database_id") != self.database_id or anchor.get("provider_signer") != self.provider_signer
                        or type(anchor.get("sequence")) is not int or meta["sequence"] < anchor["sequence"]):
                    raise ReservedExecutionError("ledger was replaced or rolled back; restore the complete latest state")
                # A crash after DB commit but before anchor commit cannot have
                # dispatched work: reserve returns only after both are synced.
            self._write_anchor(meta["sequence"])
        except BaseException as exc:
            self.close()
            if isinstance(exc, BlockingIOError):
                raise ReservedExecutionError("another Provider writer owns this signer ledger") from exc
            raise

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
        if self._lock_fd is not None:
            self._fcntl.flock(self._lock_fd, self._fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None
        if self._database_lock_fd is not None:
            self._fcntl.flock(self._database_lock_fd, self._fcntl.LOCK_UN)
            os.close(self._database_lock_fd)
            self._database_lock_fd = None
        self._closed = True

    def _check_storage(self) -> None:
        if self._closed or self._db is None:
            raise ReservedExecutionError("ledger is closed")
        try:
            info = self.path.lstat()
            anchor = json.loads(self.anchor_path.read_text())
        except (OSError, ValueError) as exc:
            raise ReservedExecutionError("ledger/anchor unavailable; stop execution and recover") from exc
        sequence = self._db.execute("SELECT sequence FROM meta WHERE id=1").fetchone()[0]
        if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self._inode
                or self.anchor_path.is_symlink() or anchor.get("database_id") != self.database_id
                or anchor.get("provider_signer") != self.provider_signer
                or type(anchor.get("sequence")) is not int or sequence < anchor["sequence"]):
            raise ReservedExecutionError("ledger/anchor changed; stop execution and recover")

    def _write_anchor(self, sequence: int) -> None:
        temporary = self.anchor_path.with_name(self.anchor_path.name + "." + uuid.uuid4().hex + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(_json({"database_id": self.database_id, "provider_signer": self.provider_signer, "sequence": sequence}))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.anchor_path)
            _sync_directory(self.anchor_path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    @contextmanager
    def _transaction(self):
        with self._mutex:
            self._check_storage()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.execute("UPDATE meta SET sequence=sequence+1 WHERE id=1")
                sequence = self._db.execute("SELECT sequence FROM meta WHERE id=1").fetchone()[0]
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
            # If this fails, caller MUST NOT execute. The committed reservation
            # remains occupied and a restart retains it, never retries the model.
            self._write_anchor(sequence)

    def activate(self, contract: str, channel_id: str, snapshot: Mapping[str, Any], *, now: int,
                 clock_allowance: int = 300) -> None:
        """snapshot must already be canonical, confirmed and binding-verified.

        channel config is immutable. Empty state can activate only before the
        future start, never by inferring 'unused' from zero chain settlements.
        """
        contract, channel_id = normalize_address(contract), normalize_bytes32(channel_id)
        config = dict(snapshot["config"])
        encoded = _json(config)
        binding_hash = hashlib.sha256(encoded.encode()).hexdigest()
        now = _uint(now, "now")
        _uint(clock_allowance, "clock_allowance")
        capacity = _uint(config["capacity"], "capacity", True)
        for name in ("valid_from", "admit_until", "claim_until"):
            _uint(config[name], name, True)
        if not config["valid_from"] < config["admit_until"] < config["claim_until"]:
            raise ReservedExecutionError("invalid channel time bounds")
        if normalize_address(config["provider_signer"]) != self.provider_signer:
            raise ReservedExecutionError("channel belongs to another Provider signer")
        with self._transaction():
            existing = self._db.execute("SELECT binding_hash FROM channels WHERE contract=? AND channel_id=?", (contract, channel_id)).fetchone()
            if existing:
                if existing[0] != binding_hash:
                    raise ReservedExecutionError("channel immutable bindings changed")
                return
            if (snapshot.get("closed") is not False or now + clock_allowance >= config["valid_from"]
                    or _uint(snapshot["block_timestamp"], "block_timestamp") >= config["valid_from"]
                    or _uint(snapshot.get("settled_max_fee"), "settled_max_fee") != 0):
                raise ReservedExecutionError("new local channel must be confirmed before its future start; restore old ledger or open a new channel")
            if min(_uint(snapshot["credit_remaining"], "credit_remaining"), _uint(snapshot["stake_remaining"], "stake_remaining")) < capacity:
                raise ReservedExecutionError("channel budget/stake is not fully reserved")
            self._db.execute("INSERT INTO channels VALUES(?,?,?,?,?,?,?,?,?)", (contract, channel_id, _json(snapshot), binding_hash,
                str(capacity), "0", config["valid_from"], config["admit_until"], config["claim_until"]))

    def channel(self, contract: str, channel_id: str) -> dict[str, Any] | None:
        with self._mutex:
            self._check_storage()
            row = self._db.execute("SELECT * FROM channels WHERE contract=? AND channel_id=?", (normalize_address(contract), normalize_bytes32(channel_id))).fetchone()
            return dict(row) if row else None

    def lookup(self, contract: str, channel_id: str, request_id: str) -> dict[str, Any] | None:
        with self._mutex:
            self._check_storage()
            row = self._db.execute("SELECT * FROM executions WHERE contract=? AND channel_id=? AND request_id=?", (
                normalize_address(contract), normalize_bytes32(channel_id), normalize_bytes32(request_id))).fetchone()
            return self._decode(row) if row else None

    def reserve(self, contract: str, channel_id: str, *, request_id: str, request_hash: str,
                max_fee: int, authorization: Mapping[str, Any], dispatch: Mapping[str, Any], now: int) -> dict[str, Any]:
        contract, channel_id = normalize_address(contract), normalize_bytes32(channel_id)
        request_id, request_hash = normalize_bytes32(request_id), normalize_bytes32(request_hash)
        max_fee, now = _uint(max_fee, "max_fee", True), _uint(now, "now")
        auth_json, dispatch_json = _json(authorization), _json(dispatch)
        with self._transaction():
            row = self._db.execute("SELECT * FROM executions WHERE contract=? AND channel_id=? AND request_id=?", (contract, channel_id, request_id)).fetchone()
            if row:
                if row["request_hash"] != request_hash or row["authorization"] != auth_json or row["dispatch"] != dispatch_json or int(row["max_fee"]) != max_fee:
                    raise ReservedExecutionError("request identity reused with different authorization, dispatch or content")
                return {"execute": False, **self._decode(row)}
            channel = self._db.execute("SELECT * FROM channels WHERE contract=? AND channel_id=?", (contract, channel_id)).fetchone()
            if channel is None:
                raise ReservedExecutionError("channel has no trusted local ledger; do not reconstruct past execution capacity")
            config = json.loads(channel["snapshot"])["config"]
            if not channel["valid_from"] <= now <= channel["admit_until"]:
                raise ReservedExecutionError("channel is not in its execution window")
            if max_fee > int(config["max_fee_per_request"]) or int(channel["reserved"]) + max_fee > int(channel["capacity"]):
                raise ReservedExecutionError("channel permanent max-fee budget exhausted")
            self._db.execute("UPDATE channels SET reserved=? WHERE contract=? AND channel_id=?", (str(int(channel["reserved"]) + max_fee), contract, channel_id))
            self._db.execute("INSERT INTO executions VALUES(?,?,?,?,?,?,?,'unknown',NULL,NULL,NULL,?)", (
                contract, channel_id, request_id, request_hash, str(max_fee), auth_json, dispatch_json, now))
            return {"execute": True, "state": "unknown", "request_id": request_id}

    def complete(self, contract: str, channel_id: str, request_id: str, *, response: Mapping[str, Any],
                 signed_receipt: Mapping[str, Any], now: int) -> None:
        ids = (normalize_address(contract), normalize_bytes32(channel_id), normalize_bytes32(request_id))
        response_json, receipt_json = _json(response), _json(signed_receipt)
        with self._transaction():
            row = self._db.execute("SELECT * FROM executions WHERE contract=? AND channel_id=? AND request_id=?", ids).fetchone()
            if row is None:
                raise ReservedExecutionError("completion has no durable execution reservation")
            if (signed_receipt.get("authorization") != json.loads(row["authorization"])
                    or signed_receipt.get("dispatch") != json.loads(row["dispatch"])):
                raise ReservedExecutionError("completion must retain the exact reserved authorization and dispatch")
            actual_fee = signed_receipt.get("receipt", {}).get("actual_fee")
            if _uint(actual_fee, "actual_fee", True) > int(row["max_fee"]):
                raise ReservedExecutionError("receipt exceeds permanent max-fee reservation")
            if row["state"] == "completed":
                if row["response"] != response_json or row["signed_receipt"] != receipt_json:
                    raise ReservedExecutionError("completed result cannot be replaced")
                return
            self._db.execute("UPDATE executions SET state='completed',response=?,signed_receipt=?,response_digest=?,updated_at=? WHERE contract=? AND channel_id=? AND request_id=?", (
                response_json, receipt_json, hashlib.sha256(response_json.encode()).hexdigest(), _uint(now, "now"), *ids))

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        for name in ("authorization", "dispatch", "response", "signed_receipt"):
            result[name] = json.loads(result[name]) if result[name] else None
        if result["response"] is not None and hashlib.sha256(_json(result["response"]).encode()).hexdigest() != result["response_digest"]:
            raise ReservedExecutionError("durable response checksum mismatch")
        return result

    def outbox(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._mutex:
            self._check_storage()
            rows = self._db.execute("SELECT * FROM executions WHERE state='completed' ORDER BY updated_at,request_id LIMIT ?", (_uint(limit, "limit", True),)).fetchall()
            return [self._decode(row) for row in rows]


def confirmed_channel_snapshot(rpc_url: str, contract: str, channel_id: str, *, chain_id: int,
                               confirmations: int = 6, timeout: float = 20, now: int | None = None,
                               deadline: float | None = None) -> dict[str, Any]:
    """Read one confirmed canonical hash and check that it stayed canonical.

    The application pins its RPC and deployment. We fail closed on missing
    EIP-1898 support, stale/future chain clocks or a reorg during the read.
    An optional monotonic deadline bounds the entire snapshot; timeout remains
    the per-RPC limit for existing callers that do not provide a deadline.
    """
    from .chain import rpc_call, rpc_int
    from .chain_v10 import OPEN_FIELDS, channel_info, channel_id_for
    if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)):
        raise ReservedExecutionError("V10 canonical channel snapshot deadline is invalid")

    def remaining_timeout() -> float:
        if deadline is None:
            return timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReservedExecutionError("V10 canonical channel snapshot deadline exceeded")
        return min(timeout, remaining)

    now = int(time.time()) if now is None else now
    if rpc_int(rpc_url, "eth_chainId", [], remaining_timeout()) != chain_id:
        raise ReservedExecutionError("V10 RPC chain ID mismatch")
    head = rpc_call(rpc_url, "eth_getBlockByNumber", ["latest", False], remaining_timeout())
    try:
        number, timestamp = int(head["number"], 16), int(head["timestamp"], 16)
        if abs(timestamp - now) > 300:
            raise ReservedExecutionError("V10 RPC head clock differs by more than 300 seconds")
        target = number - _uint(confirmations, "confirmations")
        if target < 0:
            raise ReservedExecutionError("V10 channel has insufficient confirmations")
        block = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(target), False], remaining_timeout())
        block_hash = normalize_bytes32(block["hash"])
        if int(block["number"], 16) != target:
            raise ReservedExecutionError("V10 RPC returned the wrong confirmed block")
        channel = channel_info(rpc_url, contract, channel_id, timeout=remaining_timeout(),
            block_tag={"blockHash": block_hash, "requireCanonical": True})
        current = rpc_call(rpc_url, "eth_getBlockByNumber", [hex(target), False], remaining_timeout())
        if normalize_bytes32(current["hash"]) != block_hash:
            raise ReservedExecutionError("V10 confirmed channel changed during read")
        config = {name: channel[name] for name, _ in OPEN_FIELDS}
        if channel_id_for(config, chain_id=chain_id, settlement_contract=contract) != normalize_bytes32(channel_id):
            raise ReservedExecutionError("V10 canonical channel ID/bindings mismatch")
        remaining_timeout()
        return {**channel, "config": config, "block_hash": block_hash, "block_number": target,
                "block_timestamp": int(block["timestamp"], 16), "head_timestamp": timestamp}
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ReservedExecutionError):
            raise
        raise ReservedExecutionError("V10 canonical channel snapshot is invalid") from exc


def read_execution_outbox(path: str | Path, *, anchor_path: str | Path, provider_signer: str,
                          limit: int = 1000, unexpired_at: int | None = None,
                          submission_outbox: str | Path | None = None) -> list[dict[str, Any]]:
    """Read a consistent outbox while its one execution writer is still running.

    No creation, signing or journal writes. SQLite read transactions serialize
    with FULL-synchronous commits. A racing anchor update fails safely/retryably.
    """
    path, anchor_path = Path(path).absolute(), Path(anchor_path).absolute()
    for target in (path, anchor_path):
        if not target.is_file() or target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
            raise ReservedExecutionError("outbox requires original regular ledger and anchor files")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    try:
        db.row_factory = sqlite3.Row
        terminal_filter = ""
        if submission_outbox is not None and Path(submission_outbox).exists():
            submission_path = Path(submission_outbox).absolute()
            if (not submission_path.is_file() or submission_path.is_symlink()
                    or any(parent.is_symlink() for parent in submission_path.parents)):
                raise ReservedExecutionError("submission outbox requires an original regular file")
            db.execute("ATTACH DATABASE ? AS submission", (submission_path.as_uri() + "?mode=ro",))
            # Filter terminal history before LIMIT, binding all four identifiers.
            # A matching request on another channel/deployment is unrelated.
            terminal_filter = """ AND (contract,channel_id,request_id,json_extract(signed_receipt,'$.chain_id')) NOT IN (
                SELECT settlement_contract,json_extract(payload_json,'$.channel_id'),session_id,chain_id
                FROM submission.relay_settlement_outbox
                WHERE status IN ('escrowed','confirmed','failed')
                  AND json_extract(payload_json,'$.protocol_version')=10
                  AND json_type(payload_json,'$.channel_id')='text')"""
        db.execute("BEGIN")
        meta = db.execute("SELECT * FROM meta WHERE id=1").fetchone()
        anchor = json.loads(anchor_path.read_text())
        if (meta is None or meta["signer"] != normalize_address(provider_signer)
                or anchor.get("database_id") != meta["database_id"]
                or anchor.get("provider_signer") != meta["signer"]
                or type(anchor.get("sequence")) is not int or anchor["sequence"] > meta["sequence"]):
            raise ReservedExecutionError("outbox ledger/anchor mismatch; recover or retry")
        # Filter before LIMIT so archived completed history cannot starve live
        # receipts. Unknown submitted transactions recover from their own DB.
        clause = " AND json_extract(authorization, '$.authorization.deadline') > ?" if unexpired_at is not None else ""
        parameters = ([_uint(unexpired_at, "unexpired_at")] if unexpired_at is not None else []) + [_uint(limit, "limit", True)]
        rows = db.execute("SELECT * FROM executions WHERE state='completed'" + clause + terminal_filter +
            " ORDER BY updated_at,request_id LIMIT ?", parameters).fetchall()
        return [ReservedExecutionLedger._decode(row) for row in rows]
    finally:
        db.close()


def submit_execution_outbox(rows: list[dict[str, Any]], *, rpc_url: str, contract: str, chain_id: int,
                            confirmations: int = 6, send: bool = False, transaction_identity: str | None = None,
                            submission_outbox: str | None = None, force: bool = False,
                            batch_size: int = 2) -> dict[str, Any]:
    """Independent, permissionless submission. Broadcast requires explicit send.

    Use a dedicated gas identity for this outbox; another worker must not send
    transactions from the same account with a different nonce journal.
    A normal periodic call respects the durable 7200-second / 100-receipt
    schedule. Only an explicit force bypasses that schedule for one batch.
    """
    from .chain_v10 import encode_signed_batch_tuples
    from .v10_relayer import prepare_v10_relay_settlement
    from .session_relayer import RelaySettlementOutbox, RelaySettlementSubmitter
    from .provider_bootstrap import load_provider_evm_identity
    if type(batch_size) is not int or not 1 <= batch_size <= 32:
        raise ReservedExecutionError("batch_size must be an integer between 1 and 32")
    contract = normalize_address(contract)
    prepared, skipped, snapshots = [], [], {}
    for row in rows:
        receipt = row["signed_receipt"]
        if row["contract"] != contract or receipt.get("chain_id") != chain_id:
            continue
        try:
            channel_id = row["channel_id"]
            if channel_id not in snapshots:
                snapshots[channel_id] = confirmed_channel_snapshot(rpc_url, contract, channel_id,
                    chain_id=chain_id, confirmations=confirmations)
            prepared.append(prepare_v10_relay_settlement(receipt, channel=snapshots[channel_id],
                expected_chain_id=chain_id, expected_contract=contract))
        except Exception as exc:
            skipped.append({"channel_id": row["channel_id"], "request_id": row["request_id"], "error": str(exc)})
    result = {"broadcast": False, "prepared": len(prepared), "skipped": skipped,
        "transactions": [{"to": contract, "chain_id": chain_id, "value": "0x0", "data": item.calldata} for item in prepared]}
    if not send:
        return result
    if not transaction_identity or not submission_outbox:
        raise ReservedExecutionError("submit --send requires a dedicated --transaction-identity and --submission-outbox")
    destination = Path(submission_outbox).absolute()
    _protected_parent(destination)
    signer = load_provider_evm_identity(transaction_identity)
    # This CLI has its own persistent nonce/transaction journal. The same
    # execution ledger remains writable by its Provider process.
    outbox = RelaySettlementOutbox(destination)
    os.chmod(destination, 0o600)
    submitter = RelaySettlementSubmitter(outbox=outbox, rpc_url=rpc_url, private_key=signer.private_key,
        settlement_version=10, expected_chain_id=chain_id, expected_contract=contract,
        batch_encoder=encode_signed_batch_tuples, batch_size=batch_size)
    for item in prepared:
        submitter.enqueue(item)
    # Bounded run. Re-running the CLI reconciles pending/unknown transactions
    # using the same outbox before allocating any new nonce.
    processed = submitter.process_once(force=force)
    result.pop("broadcast", None)
    return {**result, "submission_attempted": True, "processed": processed, "submission_status": outbox.snapshot(),
            "gas_address": signer.address, "note": "A submission attempt is not a claim of final settlement; inspect submission_status."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="V10 Provider durable journal / independent settlement outbox")
    parser.add_argument("command", choices=("initialize", "activate", "outbox", "submit"))
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--anchor", required=True)
    parser.add_argument("--provider-signer", required=True)
    parser.add_argument("--rpc-url")
    parser.add_argument("--contract")
    parser.add_argument("--channel-id")
    parser.add_argument("--chain-id", type=int)
    parser.add_argument("--confirmations", type=int, default=6)
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--send", action="store_true", help="Permit one bounded batch when the durable settlement schedule is due")
    parser.add_argument("--force", action="store_true", help="Explicitly bypass the schedule for one batch; requires --send to broadcast")
    parser.add_argument("--batch-size", type=int, choices=range(1, 33), default=2, metavar="1..32",
                        help="Independent Provider batch size (default 2); normal gas admission still applies")
    parser.add_argument("--include-expired", action="store_true", help="Include expired receipts in submit planning; outbox exports already include all")
    parser.add_argument("--transaction-identity", help="Protected JSON identity for this dedicated gas sender")
    parser.add_argument("--submission-outbox", help="Persistent submission DB; never share its gas sender with another outbox")
    args = parser.parse_args(argv)
    if args.command in {"outbox", "submit"}:
        rows = read_execution_outbox(args.ledger, anchor_path=args.anchor,
            provider_signer=args.provider_signer, limit=args.limit,
            unexpired_at=int(time.time()) if args.command == "submit" and not args.include_expired else None,
            submission_outbox=args.submission_outbox if args.command == "submit" else None)
        if args.command == "outbox":
            print(_json({"receipts": [{"contract": row["contract"], "channel_id": row["channel_id"],
                "request_id": row["request_id"], "signed_receipt": row["signed_receipt"]} for row in rows],
                "broadcast": False, "permissionless_submission": True}))
        else:
            if not all((args.rpc_url, args.contract, args.chain_id)):
                parser.error("submit requires --rpc-url, --contract and --chain-id")
            print(_json(submit_execution_outbox(rows, rpc_url=args.rpc_url, contract=args.contract,
                chain_id=args.chain_id, confirmations=args.confirmations, send=args.send,
                transaction_identity=args.transaction_identity, submission_outbox=args.submission_outbox,
                force=args.force, batch_size=args.batch_size)))
        return 0
    ledger = ReservedExecutionLedger(args.ledger, anchor_path=args.anchor,
        provider_signer=args.provider_signer, create=args.command == "initialize")
    try:
        if args.command == "initialize":
            print(_json({"initialized": True, "provider_signer": ledger.provider_signer}))
        else:
            if not all((args.rpc_url, args.contract, args.channel_id, args.chain_id)):
                parser.error("activate requires --rpc-url, --contract, --channel-id and --chain-id")
            snapshot = confirmed_channel_snapshot(args.rpc_url, args.contract, args.channel_id,
                chain_id=args.chain_id, confirmations=args.confirmations)
            ledger.activate(args.contract, args.channel_id, snapshot, now=int(time.time()))
            print(_json({"activated": True, "channel_id": args.channel_id, "valid_from": snapshot["valid_from"]}))
        return 0
    finally:
        ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
