"""Bounded Provider fallback submitter, normally idle while its Relay is healthy.

Called by an operator-managed oneshot timer in the existing Provider container.
Only an explicit local environment switch enables broadcasting. The receipt
identity can pay gas if this is its only transaction outbox; offline receipt
signatures do not consume account nonces.
"""
from __future__ import annotations
import json
import math
import os
from pathlib import Path
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any, Mapping


def fallback_decision(rows: list[Mapping[str, Any]], *, relay_ready: bool, now: int,
                      deadline_margin: int = 900, batch_size: int = 16) -> dict[str, Any]:
    """A healthy Relay gets the first chance; preserve a bounded rescue window."""
    deadlines = [int(row['signed_receipt']['authorization']['authorization']['deadline']) for row in rows]
    live = [deadline for deadline in deadlines if deadline > now]
    if type(batch_size) is not int or not 1<=batch_size<=32:
        raise ValueError('fallback batch size must be 1..32')
    # Budget two minutes per batch for RPC/receipt recovery plus five minutes
    # final margin. A large backlog begins rescue before a fixed 15-min window.
    protection_window=max(deadline_margin, math.ceil(len(live)/batch_size)*120+300)
    near = bool(live and min(live) - now <= protection_window)
    return {'attempt': bool(rows) and (not relay_ready or near), 'force': near,
        'reason': 'deadline_protection' if near else 'relay_unavailable' if rows and not relay_ready
                  else 'relay_healthy' if rows else 'no_completed_receipts',
        'earliest_live_deadline': min(live) if live else None,
        'pending_count':len(live),'protection_window_seconds':protection_window}


def relay_ready(url: str, *, ca_file: str, chain_id: int, contract: str) -> bool:
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    try:
        with opener.open(url.rstrip('/')+'/health',timeout=4) as response:
            raw=response.read(1024*1024+1)
            if len(raw)>1024*1024:return False
            health=json.loads(raw)
        capability=health.get('v10') or {}
        return (health.get('settlement_ready') is True and capability.get('protocol_version')==10
            and capability.get('reservation_mode')=='provider_bound_channel'
            and capability.get('chain_id')==chain_id and capability.get('settlement_contract')==contract)
    except Exception:
        return False


def run(env: Mapping[str,str] | None = None) -> dict[str,Any]:
    from .chain import normalize_address
    from .chain_v10 import load_deployment, settlement_key_for
    from .provider_bootstrap import load_provider_evm_identity
    from .reserved_execution import read_execution_outbox, submit_execution_outbox
    from .session_relayer import RelaySettlementOutbox
    env=os.environ if env is None else env
    enabled=env.get('MYCOMESH_PROVIDER_INDEPENDENT_SUBMIT_ENABLED')=='1'
    if not enabled:return {'enabled':False,'broadcast':False,'reason':'local_operator_switch_disabled'}
    manifest=load_deployment(Path(env.get('MYCO_DEPLOYMENT','/candidate/deployment.json')),
        allow_controlled_test=env.get('MYCOMESH_ALLOW_CONTROLLED_V10_TEST')=='1')
    network=json.loads(Path(env.get('MYCOMESH_PROVIDER_NETWORK_CONFIG','/candidate/network.json')).read_text())
    identity_path=env.get('MYCOMESH_PROVIDER_SUBMIT_IDENTITY','/data/provider-evm-identity.json')
    identity=load_provider_evm_identity(identity_path)
    expected=normalize_address(env.get('MYCOMESH_PROVIDER_SUBMIT_ADDRESS',identity.address))
    if identity.address!=expected:raise ValueError('Provider fallback gas identity mismatch')
    ledger=env.get('MYCOMESH_V10_EXECUTION_LEDGER','/data/v10-execution.sqlite3')
    anchor=env.get('MYCOMESH_V10_EXECUTION_ANCHOR','/data/v10-execution-anchor.json')
    submission=env.get('MYCOMESH_PROVIDER_SUBMISSION_OUTBOX','/data/v10-independent-settlement.sqlite3')
    if Path(submission).absolute() in {Path(ledger).absolute(),Path(anchor).absolute()}:
        raise ValueError('submission outbox must be separate from execution state')
    margin=int(env.get('MYCOMESH_PROVIDER_SUBMIT_DEADLINE_MARGIN_SECONDS','900'))
    if not 600<=margin<=1800:raise ValueError('fallback deadline margin must be 600..1800 seconds')
    batch_size=int(env.get('MYCOMESH_PROVIDER_SUBMIT_BATCH_SIZE','16'))
    if not 1<=batch_size<=32:raise ValueError('fallback batch size must be 1..32')
    now=int(time.time())
    outbox=RelaySettlementOutbox(submission)
    os.chmod(submission,0o600)
    rows=read_execution_outbox(ledger,anchor_path=anchor,provider_signer=identity.address,
        limit=1000,unexpired_at=now,submission_outbox=submission)
    rows=[row for row in rows if row['contract']==manifest.settlement
          and row['signed_receipt'].get('chain_id')==manifest.chain_id]
    # A possibly broadcast local transaction always needs identical-byte
    # recovery, even after the Relay becomes healthy or authorization expires.
    keys=[f'v10:{manifest.chain_id}:{manifest.settlement}:{settlement_key_for(row["channel_id"],row["request_id"])}' for row in rows]
    known=outbox.known_statuses(keys)
    rows=[row for row,key in zip(rows,keys) if known.get(key) not in {'escrowed','confirmed','failed'}]
    status=outbox.snapshot()
    recovering=any(int(status.get(name,0)) for name in ('submitted','broadcast_unknown'))
    schedule=outbox.batching_schedule(interval_seconds=7200,count_threshold=100,
        deadline_margin_seconds=margin,now=now)
    # Expired execution exports are empty, but a durable pending receipt still
    # needs canonical reconciliation before it can be declared uncollectible.
    pending_deadline=schedule['earliest_authorization_deadline']
    recovering=recovering or (pending_deadline is not None and pending_deadline<=now)
    healthy=relay_ready(network['relay']['public_url'],ca_file=env.get('SSL_CERT_FILE','/run/mesh-ca.crt'),
        chain_id=manifest.chain_id,contract=manifest.settlement)
    decision=fallback_decision(rows,relay_ready=healthy,now=now,deadline_margin=margin,batch_size=batch_size)
    if not decision['attempt'] and not recovering:
        return {'enabled':True,'broadcast':False,'relay_ready':healthy,**decision}
    rpc=','.join(network.get('settlement_rpc_urls') or [network['settlement_rpc_url']])
    result=submit_execution_outbox(rows,rpc_url=rpc,contract=manifest.settlement,
        chain_id=manifest.chain_id,confirmations=6,send=True,transaction_identity=identity_path,
        submission_outbox=submission,force=decision['force'],batch_size=batch_size)
    # Operational logs need counts/status only, never signed raw calldata.
    return {'enabled':True,'relay_ready':healthy,**decision,'recovering':recovering,
        'prepared':result.get('prepared'),'skipped_count':len(result.get('skipped') or []),
        'processed':result.get('processed'),'submission_status':result.get('submission_status'),
        'gas_address':identity.address,'submission_attempted':result.get('submission_attempted') is True}


def main() -> int:
    try:
        print(json.dumps(run(),sort_keys=True));return 0
    except Exception:
        # RPC exception text can contain calldata or credentials. Evidence is
        # retained in durable state; the service emits a public enum only.
        print(json.dumps({'ok':False,'broadcast_confirmed':False,'error_code':'provider_fallback_failed'}));return 2


if __name__=='__main__':raise SystemExit(main())
