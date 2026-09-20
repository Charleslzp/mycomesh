"""V10 maintenance plus optional V9 drain using one dedicated sender/outbox.
Only release and nonpunitive timeout; no reports, votes, claims or transfers.
Existing V9 scan state stays intact. Replace its separate timer with this combined
worker when sharing a signer: each saved plan is recovered against its own pins.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import stat
import time
from typing import Any
from . import chain, chain_v9, chain_v10
from .relay_incidents import evidence_hash
from .relay_keeper_v9 import V9EscrowKeeper
from .relay_adjudication_v9 import V9AdjudicationClient, V9OperatorConfig, V9TransactionOutbox, V9AdjudicationError, _address, _hash, _json, _protected_key, _uint

@dataclass(frozen=True)
class V10OperatorConfig(V9OperatorConfig):
    protocol_version: int = 10
    def __post_init__(self):
        super().__post_init__()
        if type(self.protocol_version) is not int or self.protocol_version != 10:
            raise V9AdjudicationError('V10 keeper requires protocol 10')
    @property
    def domain(self): return {**super().domain, 'protocol_version': 10}

class V10MaintenanceClient(V9AdjudicationClient):
    def confirmed_context(self):
        context=super().confirmed_context()
        tag={'blockHash':context['block_hash'],'requireCanonical':True}
        if self._uint_call('PROTOCOL_VERSION()',[],tag)!=10:
            raise V9AdjudicationError('keeper contract is not reserved V10')
        actual=self.rpc('eth_call',[{'to':self.config.settlement_contract,'data':chain.encode_contract_call('DOMAIN_SEPARATOR()',[])},tag])
        if actual!=chain_v10.domain_separator(chain_id=self.config.chain_id,verifying_contract=self.config.settlement_contract):
            raise V9AdjudicationError('V10 keeper EIP712 domain mismatch')
        return context
    def _plan(self,action,snapshot,data,inputs,*,amounts=None):
        if action not in ('release','timeout'):raise V9AdjudicationError('V10 keeper only releases or resolves timeout')
        result=super()._plan(action,snapshot,data,inputs,amounts=amounts)
        result.pop('plan_hash');result['schema']='mycomesh.v10.maintenance-plan.v1'
        result['plan_hash']=evidence_hash(result);return result
    def _plan_lifecycle(self,action,*,actor,settlement_key):
        actor,settlement_key=_address(actor),_hash(settlement_key)
        if actor==chain.ZERO_ADDRESS or settlement_key==chain.ZERO_BYTES32:raise V9AdjudicationError('zero keeper actor/key')
        snap=self.snapshot(settlement_key,actor);record=snap['settlement'];tag={'blockHash':snap['block_hash'],'requireCanonical':True}
        if not record['settled_at'] or record['gross_fee']<=0 or self._uint_call('settled(bytes32)',[settlement_key],tag)!=1:
            raise V9AdjudicationError('V10 maintenance requires confirmed escrow')
        if action=='release':
            if record['status']!=1 or snap['timestamp']<record['release_at']:raise V9AdjudicationError('escrow release not due')
            data=chain_v10.encode_release(settlement_key)
        elif action=='timeout':
            if record['status']!=2 or snap['dispute']['resolve_at']<=record['release_at'] or snap['timestamp']<snap['dispute']['resolve_at']:raise V9AdjudicationError('escrow timeout not due')
            data=chain_v10.encode_resolve_timed_out_dispute(settlement_key)
        else:raise V9AdjudicationError('unknown lifecycle action')
        return self._plan(action,snap,data,{'actor':actor,'settlement_key':settlement_key},amounts={'escrow_fee_units':record['gross_fee']})
    def plan_report(self,**kwargs):raise V9AdjudicationError('keeper cannot report')
    def plan_vote(self,**kwargs):raise V9AdjudicationError('keeper cannot vote')
    def plan_claim(self,**kwargs):raise V9AdjudicationError('keeper cannot claim')

class RoutedMaintenanceOutbox(V9TransactionOutbox):
    def __init__(self,path,clients):
        super().__init__(path);self.clients={_json(c.config.domain):c for c in clients}
    def _client_for(self,plan_hash):
        row=self.db.execute('SELECT plan_json FROM v9_operator_transactions WHERE plan_hash=?',(plan_hash,)).fetchone()
        if row is None:raise V9AdjudicationError('unknown maintenance plan')
        plan=json.loads(row['plan_json']);client=self.clients.get(_json(plan.get('domain')))
        if client is None:raise V9AdjudicationError('saved maintenance deployment pins are unavailable')
        if plan.get('action') not in ('release','timeout'):raise V9AdjudicationError('non-maintenance transaction in keeper outbox')
        return client
    def reconcile(self,client,plan_hash):return super().reconcile(self._client_for(plan_hash),plan_hash)
    def resume_signed_lifecycle(self,client,plan_hash,*,allow_send=False):
        return super().resume_signed_lifecycle(self._client_for(plan_hash),plan_hash,allow_send=allow_send)

class V10EscrowKeeper:
    """Bounded scans and durable plans share the transaction outbox's database.

    Event keys are hints only. Fresh hash-pinned onchain state is authoritative
    before every signed transaction. A changed scan checkpoint halts rather
    than silently advancing past a reorganization or allocating a new nonce.
    """

    def __init__(self, client: V9AdjudicationClient, *, actor: str, database: str | Path,
                 start_block: int, max_scan_blocks: int = 1000, max_jobs: int = 4,
                 reserved_senders: tuple[str, ...] = ()) -> None:
        self.client, self.actor = client, _address(actor)
        if self.actor == chain.ZERO_ADDRESS:
            raise V9AdjudicationError("keeper requires a nonzero dedicated actor")
        self.start_block = _uint(start_block, "start block", positive=True)
        if not 1 <= max_scan_blocks <= 2000 or not 1 <= max_jobs <= 100:
            raise V9AdjudicationError("keeper scan and candidate limits are out of bounds")
        self.max_scan_blocks, self.max_jobs = max_scan_blocks, max_jobs
        self.reserved_senders = {_address(x) for x in reserved_senders}
        self.path = Path(database)
        self.outbox = V9TransactionOutbox(database)
        db = self.outbox.db
        db.execute("""CREATE TABLE IF NOT EXISTS v10_keeper_config (
            id INTEGER PRIMARY KEY CHECK(id=1), domain TEXT NOT NULL,
            actor TEXT NOT NULL, start_block INTEGER NOT NULL,
            cursor_number INTEGER NOT NULL, cursor_hash TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS v10_keeper_escrows (
            settlement_key TEXT PRIMARY KEY, event_block INTEGER NOT NULL,
            event_hash TEXT NOT NULL, last_checked INTEGER NOT NULL DEFAULT 0,
            observed_status TEXT NOT NULL DEFAULT 'unexamined', plan_json TEXT)""")
        db.execute("INSERT OR IGNORE INTO v10_keeper_config VALUES (1,?,?,?,?,NULL)",
                   (_json(client.config.domain), self.actor, start_block, start_block - 1))
        saved = db.execute("SELECT * FROM v10_keeper_config WHERE id=1").fetchone()
        if (saved["domain"], saved["actor"], saved["start_block"]) != (
                _json(client.config.domain), self.actor, start_block):
            self.outbox.close()
            raise V9AdjudicationError("keeper database belongs to another deployment, actor or scan range")

    def close(self) -> None:
        self.outbox.close()

    @contextmanager
    def _cycle_lock(self):
        """Serialize scanning/plan selection; SQL separately reserves the nonce."""
        fd = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise V9AdjudicationError("keeper lock must be an owned regular file")
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise V9AdjudicationError("another keeper cycle is active") from None
            yield
        finally:
            os.close(fd)

    def scan(self) -> dict[str, Any]:
        # Validate chain, genesis, runtime, policy and committee before accepting
        # events, even when the scanned range contains no settlements.
        snap = self.client.confirmed_context()
        db = self.outbox.db
        checkpoint = db.execute("SELECT * FROM v10_keeper_config WHERE id=1").fetchone()
        cursor = checkpoint["cursor_number"]
        if checkpoint["cursor_hash"] is not None:
            previous = self.client.rpc("eth_getBlockByNumber", [hex(cursor), False])
            if not previous or previous["hash"].lower() != checkpoint["cursor_hash"]:
                raise V9AdjudicationError("keeper scan checkpoint reorganized; stop and reconcile saved transactions")
        end = min(snap["block_number"], cursor + self.max_scan_blocks)
        if end <= cursor:
            return {"from_block": cursor + 1, "through_block": cursor, "discovered": 0}
        boundary = self.client.rpc("eth_getBlockByNumber", [hex(end), False])
        boundary_hash = _hash(boundary["hash"])
        logs = self.client.rpc("eth_getLogs", [{"address": self.client.config.settlement_contract,
            "fromBlock": hex(cursor + 1), "toBlock": hex(end), "topics": [chain_v9.RECEIPT_ESCROWED_TOPIC]}])
        if not isinstance(logs, list) or len(logs) > 2000:
            raise V9AdjudicationError("keeper event range too large; use a smaller scan span")
        entries, hashes = [], {}
        for log in logs:
            event = chain_v9.parse_receipt_escrowed(log, expected_contract=self.client.config.settlement_contract)
            number, block_hash = int(log["blockNumber"], 16), _hash(log["blockHash"])
            if log.get("removed") or not cursor < number <= end:
                raise V9AdjudicationError("noncanonical or out-of-range escrow event")
            if number not in hashes:
                hashes[number] = self.client.rpc("eth_getBlockByNumber", [hex(number), False])["hash"].lower()
            if hashes[number] != block_hash:
                raise V9AdjudicationError("escrow event block is not canonical")
            entries.append((event["settlement_key"], number, block_hash))
        if self.client.rpc("eth_getBlockByNumber", [hex(end), False])["hash"].lower() != boundary_hash:
            raise V9AdjudicationError("scan boundary reorganized before checkpoint commit")
        db.execute("BEGIN IMMEDIATE")
        try:
            for entry in entries:
                db.execute("INSERT OR IGNORE INTO v10_keeper_escrows(settlement_key,event_block,event_hash) VALUES (?,?,?)", entry)
            db.execute("UPDATE v10_keeper_config SET cursor_number=?,cursor_hash=? WHERE id=1", (end, boundary_hash))
            db.commit()
        except BaseException:
            db.rollback()
            raise
        return {"from_block": cursor + 1, "through_block": end, "discovered": len(entries),
                "confirmed_head": snap["block_number"], "caught_up": end == snap["block_number"]}

    def _plan(self, settlement_key: str) -> tuple[dict[str, Any] | None, str]:
        snap = self.client.snapshot(settlement_key, self.actor)
        record, timestamp = snap["settlement"], snap["timestamp"]
        if record["status"] == 1 and timestamp >= record["release_at"]:
            return self.client.plan_release(actor=self.actor, settlement_key=settlement_key), "mature_release"
        if (record["status"] == 2 and snap["dispute"]["resolve_at"] > record["release_at"]
                and timestamp >= snap["dispute"]["resolve_at"]):
            return self.client.plan_timeout(actor=self.actor, settlement_key=settlement_key), "mature_timeout"
        status = "dispute_active" if record["status"] == 2 else "not_mature" if record["status"] == 1 else "terminal_or_missing"
        return None, status

    def run_once(self, *, send: bool = False, dedicated_sender: bool = False,
                 key_file: str | Path | None = None, max_gas_price_wei: int | None = None,
                 max_gas_units: int | None = None, max_total_gas_cost_wei: int | None = None,
                 resume_signed: bool = False) -> dict[str, Any]:
        if resume_signed and not send:
            raise V9AdjudicationError("signed recovery requires explicit send mode")
        if send:
            if (not dedicated_sender or self.actor in self.reserved_senders
                    or self.actor in self.client.config.adjudicators
                    or self.actor == self.client.config.reporter_address):
                raise V9AdjudicationError("send mode requires a dedicated keeper, separate from Relay/reporter/juror senders")
            if not key_file or chain.private_key_to_address(_protected_key(key_file)) != self.actor:
                raise V9AdjudicationError("keeper key does not match configured dedicated actor")
            for value, label in ((max_gas_price_wei, "gas price cap"), (max_gas_units, "gas limit cap"),
                                 (max_total_gas_cost_wei, "gas cost cap")):
                _uint(value, label, positive=True)
        with self._cycle_lock():
            result = {"dry_run": not send, "actor": self.actor, "wallet_payout_verified": False,
                      "scan": self.scan(), "transactions": [], "candidates": []}
            # Recover the previously signed hash before planning anything else.
            # An unresolved nonce blocks every new send, including after restart.
            for row in self.outbox.unresolved(self.actor):
                if resume_signed:
                    recovered = self.outbox.resume_signed_lifecycle(self.client, row["plan_hash"], allow_send=True)
                else:
                    recovered = self.outbox.reconcile(self.client, row["plan_hash"])
                result["transactions"].append(recovered)
                if recovered["state"] not in ("confirmed", "reverted"):
                    result["blocked"] = "unresolved_transaction"
                    return result
            rows = self.outbox.db.execute("SELECT * FROM v10_keeper_escrows ORDER BY last_checked,event_block,settlement_key LIMIT ?",
                                           (self.max_jobs,)).fetchall()
            for row in rows:
                key = row["settlement_key"]
                saved = json.loads(row["plan_json"]) if row["plan_json"] else None
                previous = self.outbox.get(saved["plan_hash"]) if saved else None
                if previous:
                    # Recheck even a completed transaction when revisiting the
                    # candidate, so a reorg revokes the old verified outcome.
                    previous = self.outbox.reconcile(self.client, saved["plan_hash"])
                    result["transactions"].append(previous)
                    if previous["state"] not in ("confirmed", "reverted"):
                        result["blocked"] = "unresolved_transaction"
                        return result
                    if previous["state"] == "confirmed":
                        self._record(key, "verified_" + saved["action"], saved)
                        continue
                plan, status = self._plan(key)
                if plan is None:
                    self._record(key, status, None)
                    result["candidates"].append({"settlement_key": key, "status": status})
                    continue
                if send:
                    parties = {plan["snapshot"]["settlement"].get(name) for name in (
                        "owner", "key", "provider", "provider_signer", "relay", "relay_signer", "pool", "treasury")}
                    if self.actor in parties:
                        raise V9AdjudicationError("keeper sender is reused by a settlement party")
                # Persist the exact plan before outbox execution. If the process
                # dies after outbox commit, this points to the same signed hash.
                self._record(key, status, plan)
                result["candidates"].append({"settlement_key": key, "status": status, "plan": plan})
                if send:
                    tx = self.outbox.execute(self.client, plan, allow_send=True,
                        approved_plan_hash=plan["plan_hash"], key_file=key_file,
                        max_gas_price_wei=max_gas_price_wei, max_gas_units=max_gas_units,
                        max_total_gas_cost_wei=max_total_gas_cost_wei)
                    result["transactions"].append(tx)
                    # At most one new nonce per cycle, until its receipt and
                    # resulting business state receive the pinned confirmations.
                    break
            return result

    def _record(self, key: str, status: str, plan: dict[str, Any] | None) -> None:
        self.outbox.db.execute("UPDATE v10_keeper_escrows SET last_checked=?,observed_status=?,plan_json=? WHERE settlement_key=?",
                              (time.time_ns(), status, _json(plan) if plan else None, key))


class SharedEscrowKeeper:
    """One database, cycle lock and sender nonce fence across both contracts."""
    def __init__(self,client,*,actor,database,start_block,legacy_client=None,legacy_start_block=None,**options):
        clients=[client]+([legacy_client] if legacy_client else [])
        if legacy_client and (legacy_client.config.chain_id!=client.config.chain_id or legacy_client.config.genesis_hash!=client.config.genesis_hash):
            raise V9AdjudicationError('shared keeper deployments must be on the same chain')
        self.keepers=[]
        if legacy_client:
            self.keepers.append(V9EscrowKeeper(legacy_client,actor=actor,database=database,start_block=legacy_start_block,**options))
        self.keepers.append(V10EscrowKeeper(client,actor=actor,database=database,start_block=start_block,**options))
        for keeper in self.keepers:
            keeper.outbox.close();keeper.outbox=RoutedMaintenanceOutbox(database,clients)
    def run_once(self,**options):return {'deployments':[keeper.run_once(**options) for keeper in self.keepers]}
    def close(self):
        for keeper in self.keepers:keeper.close()

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('config','database','actor'):p.add_argument('--'+name,required=True)
    p.add_argument('--start-block',type=int,required=True);p.add_argument('--legacy-config');p.add_argument('--legacy-start-block',type=int)
    p.add_argument('--max-scan-blocks',type=int,default=1000);p.add_argument('--max-jobs',type=int,default=4)
    p.add_argument('--reserved-sender',action='append',default=[])
    p.add_argument('--send',action='store_true');p.add_argument('--dedicated-sender',action='store_true');p.add_argument('--key-file');p.add_argument('--resume-signed',action='store_true')
    for name in ('max-gas-price-wei','max-gas-units','max-total-gas-cost-wei'):p.add_argument('--'+name,type=int)
    args=p.parse_args(argv);keeper=None
    try:
        legacy=V9AdjudicationClient(V9OperatorConfig.load(args.legacy_config)) if args.legacy_config else None
        if bool(legacy)!=bool(args.legacy_start_block):raise V9AdjudicationError('legacy config and start block required together')
        keeper=SharedEscrowKeeper(V10MaintenanceClient(V10OperatorConfig.load(args.config)),actor=args.actor,database=args.database,start_block=args.start_block,legacy_client=legacy,legacy_start_block=args.legacy_start_block,max_scan_blocks=args.max_scan_blocks,max_jobs=args.max_jobs,reserved_senders=tuple(args.reserved_sender))
        result=keeper.run_once(send=args.send,dedicated_sender=args.dedicated_sender,key_file=args.key_file,resume_signed=args.resume_signed,max_gas_price_wei=args.max_gas_price_wei,max_gas_units=args.max_gas_units,max_total_gas_cost_wei=args.max_total_gas_cost_wei)
        print(json.dumps(result,sort_keys=True));return 0
    except (V9AdjudicationError,chain.ChainError,OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'error':type(exc).__name__,'message':'maintenance stopped; no automatic retry'}));return 1
    finally:
        if keeper:keeper.close()

if __name__=='__main__':raise SystemExit(main())
