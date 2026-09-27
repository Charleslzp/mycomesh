from __future__ import annotations

"""V10 fixed-budget channel wire protocol. Pure signing/encoding and read-only RPC.
No helper broadcasts transactions or reads wallet files. Existing V9 obligations
remain in their original domain. Execution requires a durable Provider ledger.
"""
import json
import re
import time
from dataclasses import asdict, dataclass, make_dataclass
from pathlib import Path
from typing import Any, Mapping
from . import chain_v9 as v9
from .chain import ChainError, ZERO_ADDRESS, abi_encode_arg, keccak256, normalize_address, normalize_bytes32, parse_private_key, private_key_to_address, recover_evm_address, sign_evm_digest
from .chain_v4 import _dynamic_bytes, _signature_bytes

PROTOCOL_VERSION = 10
AUTH_SCHEMA = "mycomesh.x402.myco-credit-v4"
DISPATCH_SCHEMA = "mycomesh.settlement.v10.dispatch.v1"
PROVIDER_SCHEMA = SIGNED_SCHEMA = "mycomesh.settlement.v10.signed.v1"
OPEN_SCHEMA = "mycomesh.settlement.v10.channel-permit.v1"
RESERVATION_MODE = "provider_bound_channel"
DYNAMIC_PROVIDER_JURY = "dynamic_provider_ai_v1"
DYNAMIC_JURY_FORBIDDEN_FIELDS = frozenset((
    "adjudicators",
    "adjudicator_operators",
    "independence_attested",
    "jury_provider_evidence",
))
JURY_RANDOMNESS = "future_blockhash_v1"
JURY_RANDOMNESS_HASH = "0x" + keccak256(JURY_RANDOMNESS.encode()).hex()
REPUTATION_HISTORY_FIELD = "reputation_history_import"
REPUTATION_HISTORY_SCHEMA = "mycomesh.v10.reputation-history-import.v1"
REPUTATION_HISTORY_FIELDS = frozenset((
    "schema", "source_network_id", "source_protocol_version",
    "source_chain_id", "source_genesis_hash", "source_settlement_contract",
    "source_runtime_code_hash", "source_deployment_block",
    "source_deployment_block_hash", "source_history_through_block",
    "source_history_through_block_hash", "confirmations",
    "artifact_sha256", "artifact_root",
))
ARTIFACT = "out/MycoSettlementV10.sol/MycoSettlementV10.json"
DEFAULT_DEPLOYMENT = "deployments/sepolia-myco-v10.json"
MAX_AUTHORIZATION_TTL = 10800
LEGACY_MAX_CHANNEL_DURATION = 7 * 86400
MAX_CHANNEL_DURATION = 30 * 86400
SUPPORTED_MAX_CHANNEL_DURATIONS = frozenset((LEGACY_MAX_CHANNEL_DURATION, MAX_CHANNEL_DURATION))
DEFAULT_AUTHORIZATION_DEADLINE_SECONDS = 9000
AUTHORIZATION_CLOCK_SKEW_SECONDS = 300
ZERO_BYTES32 = v9.ZERO_BYTES32
AUTHORIZATION_TYPE = "ReservedPaymentAuthorization(bytes32 channelId,bytes32 requestId,bytes32 requestHash,address key,uint256 maxFee,uint64 issuedAt,uint64 executeBy,uint64 deadline)"
RECEIPT_TYPE = "ReservedUsageReceipt(bytes32 channelId,bytes32 authorizationHash,bytes32 dispatchHash,bytes32 responseHash,uint256 inputTokens,uint256 outputTokens,uint256 actualFee)"
DISPATCH_TYPE = "RelayDispatch(bytes32 authorizationHash,bytes32 channelId)"
OPEN_TYPE = "OpenCapacityChannel(address consumerOwner,address consumerKey,address providerOwner,address providerSigner,address relay,address relaySigner,address pool,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,uint256 capacity,uint256 maxFeePerRequest,uint64 validFrom,uint64 admitUntil,uint64 claimUntil,uint256 consumerNonce,uint256 providerNonce,uint64 permitDeadline)"
VOTE_TYPE = "DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)"
AUTH_FIELDS = (('channel_id','bytes32'),('request_id','bytes32'),('request_hash','bytes32'),('key','address'),('max_fee','uint256'),('issued_at','uint64'),('execute_by','uint64'),('deadline','uint64'))
RECEIPT_FIELDS = (('channel_id','bytes32'),('authorization_hash','bytes32'),('dispatch_hash','bytes32'),('response_hash','bytes32'),('input_tokens','uint256'),('output_tokens','uint256'),('actual_fee','uint256'))
OPEN_FIELDS = (('consumer_owner','address'),('consumer_key','address'),('provider_owner','address'),('provider_signer','address'),('relay','address'),('relay_signer','address'),('pool','address'),('channel','bytes32'),('pricing_version','uint64'),('pricing_hash','bytes32'),('capacity','uint256'),('max_fee_per_request','uint256'),('valid_from','uint64'),('admit_until','uint64'),('claim_until','uint64'),('consumer_nonce','uint256'),('provider_nonce','uint256'),('permit_deadline','uint64'))
VOTE_FIELDS = (('assignment_hash','bytes32'),('confirmed','bool'),('report_id','bytes32'),('decision_hash','bytes32'),('nonce','uint256'),('deadline','uint64'))
VOTE_HASH_FIELDS = (('settlement_key','bytes32'),) + VOTE_FIELDS
AUTH_TUPLE = '(' + ','.join(t for _,t in AUTH_FIELDS) + ')'
RECEIPT_TUPLE = '(' + ','.join(t for _,t in RECEIPT_FIELDS) + ')'
OPEN_TUPLE = '(' + ','.join(t for _,t in OPEN_FIELDS) + ')'
VOTE_TUPLE = '(bytes32,bool,bytes32,bytes32,uint256,uint64,bytes)'
SIGNED_TUPLE = f'({AUTH_TUPLE},{RECEIPT_TUPLE},bytes,bytes,bytes)'
SETTLE_SIGNATURE = f'settleReservedReceipt({SIGNED_TUPLE})'
BATCH_SIGNATURE = f'settleReservedBatch({SIGNED_TUPLE}[])'
OPEN_SIGNATURE = f'openCapacityChannels(({OPEN_TUPLE},bytes,bytes)[])'
VOTE_SIGNATURE = f'voteDisputeBySig(bytes32,{VOTE_TUPLE}[])'

class _Record:
    def to_payload(self): return asdict(self)
    def abi_args(self): return [str(v) for v in asdict(self).values()]
PaymentAuthorization = make_dataclass('PaymentAuthorization', [(n, Any) for n,_ in AUTH_FIELDS], bases=(_Record,), frozen=True)
UsageReceipt = make_dataclass('UsageReceipt', [(n, Any) for n,_ in RECEIPT_FIELDS], bases=(_Record,), frozen=True)
OpenChannel = make_dataclass('OpenChannel', [(n, Any) for n,_ in OPEN_FIELDS], bases=(_Record,), frozen=True)
DisputeVote = make_dataclass('DisputeVote', [(n, Any) for n,_ in VOTE_FIELDS], bases=(_Record,), frozen=True)
_VoteHash = make_dataclass('_VoteHash', [(n, Any) for n,_ in VOTE_HASH_FIELDS], bases=(_Record,), frozen=True)

def _parse(raw, fields, cls):
    if isinstance(raw, _Record): raw = raw.to_payload()
    if not isinstance(raw, Mapping): raise ChainError('V10 missing structured payload')
    result = {}
    for name, kind in fields:
        value = raw.get(name)
        if kind == 'address':
            result[name] = normalize_address(str(value or ''))
            if name != 'pool' and result[name] == ZERO_ADDRESS: raise ChainError(f'V10 zero {name}')
        elif kind == 'bytes32':
            result[name] = normalize_bytes32(str(value or ''))
            if result[name] == ZERO_BYTES32: raise ChainError(f'V10 zero {name}')
        else: result[name] = v9._uint(value, name, bits=int(kind[4:]))
    return cls(**result)

def _auth(raw): return _parse(raw, AUTH_FIELDS, PaymentAuthorization)
def _receipt(raw): return _parse(raw, RECEIPT_FIELDS, UsageReceipt)
def _config(raw): return _parse(raw, OPEN_FIELDS, OpenChannel)
def _vote(raw):
    if isinstance(raw, _Record): raw = raw.to_payload()
    if not isinstance(raw, Mapping): raise ChainError('V10 missing dispute vote payload')
    confirmed = raw.get('confirmed')
    if type(confirmed) is not bool:
        raise ChainError('V10 dispute vote confirmed must be boolean')
    assignment_hash = normalize_bytes32(str(raw.get('assignment_hash') or ''))
    if assignment_hash == ZERO_BYTES32:
        raise ChainError('V10 dispute vote assignment_hash cannot be zero')
    return DisputeVote(
        assignment_hash=assignment_hash,
        confirmed=confirmed,
        report_id=normalize_bytes32(str(raw.get('report_id') or '')),
        decision_hash=normalize_bytes32(str(raw.get('decision_hash') or '')),
        nonce=v9._uint(raw.get('nonce'), 'nonce', bits=256),
        deadline=v9._uint(raw.get('deadline'), 'deadline', bits=64),
    )
def _hash(type_string, value):
    return '0x' + keccak256(keccak256(type_string.encode()) + b''.join(abi_encode_arg(a) for a in value.abi_args())).hex()
def domain_separator(*, chain_id: int, verifying_contract: str) -> str:
    return '0x' + keccak256(keccak256(v9.DOMAIN_TYPE.encode()) + keccak256(b'MycoMesh Settlement') + keccak256(b'10') + abi_encode_arg(str(v9._positive_uint(chain_id,'chain_id'))) + abi_encode_arg(v9._nonzero_address(verifying_contract,'contract'))).hex()
def _digest(struct_hash, *, chain_id, verifying_contract):
    return keccak256(b'\x19\x01' + bytes.fromhex(domain_separator(chain_id=chain_id,verifying_contract=verifying_contract)[2:]) + bytes.fromhex(struct_hash[2:]))
def authorization_struct_hash(value): return _hash(AUTHORIZATION_TYPE,_auth(value))
def receipt_struct_hash(value): return _hash(RECEIPT_TYPE,_receipt(value))
def open_channel_struct_hash(value): return _hash(OPEN_TYPE,_config(value))
def dispute_vote_struct_hash(settlement_key, value):
    vote = _vote(value)
    return _hash(VOTE_TYPE, _VoteHash(settlement_key=normalize_bytes32(settlement_key), **vote.to_payload()))
def authorization_digest(value, **domain): return _digest(authorization_struct_hash(value),**domain)
def receipt_digest(value, **domain): return _digest(receipt_struct_hash(value),**domain)
def channel_id_for(config, *, chain_id, verifying_contract=None, settlement_contract=None):
    return '0x' + _digest(open_channel_struct_hash(config), chain_id=chain_id, verifying_contract=verifying_contract or settlement_contract).hex()
def dispatch_struct_hash(authorization_hash, channel_id):
    return '0x'+keccak256(keccak256(DISPATCH_TYPE.encode())+abi_encode_arg(normalize_bytes32(authorization_hash))+abi_encode_arg(normalize_bytes32(channel_id))).hex()
def dispatch_digest(authorization_hash,channel_id,**domain): return _digest(dispatch_struct_hash(authorization_hash,channel_id),**domain)
def dispute_vote_digest(settlement_key, value, *, chain_id, settlement_contract):
    return _digest(dispute_vote_struct_hash(settlement_key, value), chain_id=chain_id, verifying_contract=settlement_contract)
def _sign(key,digest): return '0x'+_signature_bytes(sign_evm_digest(key,digest),'V10').hex()
def _signer(digest,signature): return recover_evm_address(digest,v9._evm_signature(v9._raw_signature(signature,'V10')))
def _domain(payload): return dict(chain_id=v9._positive_uint(payload.get('chain_id'),'chain_id'),verifying_contract=v9._nonzero_address(payload.get('settlement_contract'),'contract'))
def _envelope(schema, chain_id, contract, **fields):
    return dict(schema=schema,protocol_version=10,chain_id=v9._positive_uint(chain_id,'chain_id'),settlement_contract=v9._nonzero_address(contract,'contract'),**fields)

def build_dispute_vote(*, settlement_key, assignment_hash, confirmed, report_id, decision_hash, nonce, deadline,
                       judge_private_key, chain_id, settlement_contract):
    vote = _vote({'assignment_hash': assignment_hash, 'confirmed': confirmed,
                  'report_id': report_id, 'decision_hash': decision_hash,
                  'nonce': nonce, 'deadline': deadline})
    digest = dispute_vote_digest(settlement_key, vote, chain_id=chain_id, settlement_contract=settlement_contract)
    private_key = str(judge_private_key)
    if not private_key.startswith(("0x", "myco_sk_")):
        private_key = "0x" + private_key
    private_key = v9.payment_private_key(private_key)
    return {
        **vote.to_payload(),
        'settlement_key': normalize_bytes32(settlement_key),
        'signature': _sign(private_key, digest),
        'chain_id': v9._positive_uint(chain_id, 'chain_id'),
        'settlement_contract': v9._nonzero_address(settlement_contract, 'contract'),
        'judge': private_key_to_address(parse_private_key(private_key)),
    }

def verify_dispute_vote(value, *, expected_settlement_key=None, expected_assignment_hash=None, expected_chain_id=None,
                        expected_contract=None, expected_judge=None, now=None):
    if not isinstance(value, Mapping):
        raise ChainError('V10 dispute vote must be an object')
    vote = _vote(value)
    key = normalize_bytes32(str(value.get('settlement_key') or ''))
    domain_chain = v9._positive_uint(value.get('chain_id'), 'chain_id')
    domain_contract = v9._nonzero_address(value.get('settlement_contract'), 'contract')
    v9._expect_bytes32(expected_settlement_key, key, 'settlement_key')
    v9._expect_bytes32(expected_assignment_hash, vote.assignment_hash, 'assignment_hash')
    v9._expect(expected_chain_id, domain_chain, 'chain_id')
    v9._expect_address(expected_contract, domain_contract, 'contract')
    current = int(time.time()) if now is None else int(now)
    if vote.deadline < current:
        raise ChainError('V10 dispute vote expired')
    digest = dispute_vote_digest(key, vote, chain_id=domain_chain, settlement_contract=domain_contract)
    signer = _signer(digest, value.get('signature'))
    v9._expect_address(expected_judge, signer, 'judge')
    return {**vote.to_payload(), 'settlement_key': key, 'chain_id': domain_chain,
            'settlement_contract': domain_contract, 'judge': signer, 'signature': value.get('signature')}

def build_authorization(*, payment_key, chain_id, settlement_contract, channel_id, request_id, request_hash, max_fee, issued_at=None, execute_by=None, deadline=None):
    now = int(time.time()) if issued_at is None else issued_at
    private_key = v9.payment_private_key(payment_key)
    a = _auth(dict(channel_id=channel_id,request_id=request_id,request_hash=request_hash,key=v9.payment_key_address(private_key),max_fee=max_fee,issued_at=now,execute_by=execute_by if execute_by is not None else now+300,deadline=deadline if deadline is not None else now+9000))
    _authorization_window(a, now=a.issued_at)
    digest = authorization_digest(a,chain_id=chain_id,verifying_contract=settlement_contract)
    return _envelope(AUTH_SCHEMA,chain_id,settlement_contract,authorization=a.to_payload(),authorization_hash=authorization_struct_hash(a),authorization_digest='0x'+digest.hex(),key_signature=_sign(private_key,digest))

def _authorization_window(a, *, now):
    if not (a.max_fee > 0 and a.issued_at <= now <= a.deadline and a.issued_at <= a.execute_by < a.deadline and a.deadline-a.issued_at <= MAX_AUTHORIZATION_TTL): raise ChainError('V10 authorization time/fee invalid')
def verify_authorization(value, *, expected_chain_id=None, expected_contract=None, expected_channel_id=None, expected_request_id=None, expected_request_hash=None, now=None):
    if not isinstance(value,Mapping) or value.get('schema')!=AUTH_SCHEMA or value.get('protocol_version')!=10: raise ChainError('unsupported V10 authorization')
    a=_auth(value.get('authorization')); domain=_domain(value)
    _authorization_window(a,now=int(time.time()) if now is None else now)
    v9._expect(expected_chain_id,domain['chain_id'],'chain_id');v9._expect_address(expected_contract,domain['verifying_contract'],'contract')
    for expected,actual,label in ((expected_channel_id,a.channel_id,'channel_id'),(expected_request_id,a.request_id,'request_id'),(expected_request_hash,a.request_hash,'request_hash')):v9._expect_bytes32(expected,actual,label)
    digest=authorization_digest(a,**domain)
    if value.get('authorization_hash')!=authorization_struct_hash(a) or value.get('authorization_digest')!='0x'+digest.hex() or _signer(digest,value.get('key_signature'))!=a.key: raise ChainError('V10 authorization signature/hash mismatch')
    return {**dict(value),'authorization':a.to_payload(),'chain_id':domain['chain_id'],'settlement_contract':domain['verifying_contract']}

def build_relay_dispatch(*, authorization_payload, relay_private_key, now=None):
    a=verify_authorization(authorization_payload,now=now); domain=_domain(a)
    signer=private_key_to_address(parse_private_key(relay_private_key)); digest=dispatch_digest(a['authorization_hash'],a['authorization']['channel_id'],**domain)
    return _envelope(DISPATCH_SCHEMA,domain['chain_id'],domain['verifying_contract'],authorization=a,dispatch_hash=dispatch_struct_hash(a['authorization_hash'],a['authorization']['channel_id']),dispatch_digest='0x'+digest.hex(),relay_signer=signer,relay_signature=_sign(relay_private_key,digest))

def verify_relay_dispatch(value, *, expected_relay_signer=None, expected_channel_id=None, now=None):
    if not isinstance(value,Mapping) or value.get('schema')!=DISPATCH_SCHEMA or value.get('protocol_version')!=10: raise ChainError('unsupported V10 dispatch')
    a=verify_authorization(value.get('authorization'),expected_channel_id=expected_channel_id,now=now)
    if _domain(value)!=_domain(a): raise ChainError('V10 dispatch deployment mismatch')
    digest=dispatch_digest(a['authorization_hash'],a['authorization']['channel_id'],**_domain(a))
    signer=v9._nonzero_address(value.get('relay_signer'),'relay_signer');v9._expect_address(expected_relay_signer,signer,'relay_signer')
    if value.get('dispatch_hash')!=dispatch_struct_hash(a['authorization_hash'],a['authorization']['channel_id']) or value.get('dispatch_digest')!='0x'+digest.hex() or _signer(digest,value.get('relay_signature'))!=signer:raise ChainError('V10 dispatch signature/hash mismatch')
    return {**dict(value),'authorization':a,'relay_signer':signer}

def validate_channel_authorization(channel, authorization_payload, *, now=None, for_execution=True):
    a=verify_authorization(authorization_payload,now=now)['authorization']; c=_config(channel); current=int(time.time()) if now is None else now
    expected=channel_id_for(c,**_domain(authorization_payload))
    if a['channel_id']!=expected or a['key']!=c.consumer_key or channel.get('closed') is not False: raise ChainError('V10 inactive/mismatched channel')
    if not (c.valid_from<=a['issued_at']<=a['execute_by']<=c.admit_until and a['deadline']<=c.claim_until and 0<a['max_fee']<=c.max_fee_per_request<=c.capacity):raise ChainError('V10 authorization exceeds channel terms')
    if for_execution and not c.valid_from<=current<=a['execute_by']:raise ChainError('V10 channel execution window closed')
    if for_execution and (int(channel.get('credit_remaining',-1))<a['max_fee'] or int(channel.get('stake_remaining',-1))<a['max_fee']):raise ChainError('V10 channel backing insufficient')
    return a

def build_provider_receipt(*, provider_private_key, dispatch_payload, response_hash, input_tokens, output_tokens, actual_fee, channel=None, now=None):
    d=verify_relay_dispatch(dispatch_payload,expected_relay_signer=channel['relay_signer'] if channel else None,now=now)
    a=d['authorization']; signer=private_key_to_address(parse_private_key(provider_private_key))
    if channel:
        validate_channel_authorization(channel,a,now=now,for_execution=False)
        if signer!=normalize_address(channel['provider_signer']):raise ChainError('V10 Provider channel signer mismatch')
    receipt=_receipt(dict(channel_id=a['authorization']['channel_id'],authorization_hash=a['authorization_hash'],dispatch_hash=d['dispatch_hash'],response_hash=response_hash,input_tokens=input_tokens,output_tokens=output_tokens,actual_fee=actual_fee))
    if not 0<receipt.actual_fee<=a['authorization']['max_fee']:raise ChainError('V10 fee exceeds authorization')
    digest=receipt_digest(receipt,**_domain(a))
    return _envelope(SIGNED_SCHEMA,a['chain_id'],a['settlement_contract'],authorization=a,dispatch=d,receipt=receipt.to_payload(),key_signature=a['key_signature'],provider_signer=signer,provider_signature=_sign(provider_private_key,digest),relay_signature=d['relay_signature'])

finalize_provider_receipt=build_provider_receipt

def verify_signed_receipt(value, *, channel=None, now=None):
    if not isinstance(value,Mapping) or value.get('schema')!=SIGNED_SCHEMA or value.get('protocol_version')!=10:raise ChainError('unsupported V10 signed receipt')
    d=verify_relay_dispatch(value.get('dispatch'),expected_relay_signer=channel['relay_signer'] if channel else None,now=now)
    a=verify_authorization(value.get('authorization'),now=now)
    if a!=d['authorization'] or _domain(value)!=_domain(a):raise ChainError('V10 receipt authorization/deployment mismatch')
    r=_receipt(value.get('receipt'));signer=v9._nonzero_address(value.get('provider_signer'),'provider_signer')
    if (r.channel_id!=a['authorization']['channel_id'] or r.authorization_hash!=a['authorization_hash'] or r.dispatch_hash!=d['dispatch_hash'] or not 0<r.actual_fee<=a['authorization']['max_fee']):raise ChainError('V10 receipt binding/fee mismatch')
    if _signer(receipt_digest(r,**_domain(a)),value.get('provider_signature'))!=signer:raise ChainError('V10 Provider signature mismatch')
    if channel:
        validate_channel_authorization(channel,a,now=now,for_execution=False)
        if signer!=normalize_address(channel['provider_signer']):raise ChainError('V10 channel Provider mismatch')
    if value.get('key_signature')!=a['key_signature'] or value.get('relay_signature')!=d['relay_signature']:raise ChainError('V10 receipt signature envelope mismatch')
    return a,r,[v9._raw_signature(value[n],n) for n in ('key_signature','provider_signature','relay_signature')]

def _tuple_with_bytes(static_values, signatures):
    head=b''.join(abi_encode_arg(str(v)) for v in static_values); offset=len(head)+32*len(signatures); tails=[_dynamic_bytes(x) for x in signatures]; offsets=[]
    for tail in tails:offsets.append(offset.to_bytes(32,'big'));offset+=len(tail)
    return head+b''.join(offsets)+b''.join(tails)
def _array(signature,tuples):
    if not 1<=len(tuples)<=32:raise ChainError('V10 batch must have 1..32 items')
    offset=32*len(tuples); offsets=[]
    for t in tuples:offsets.append(offset.to_bytes(32,'big'));offset+=len(t)
    return '0x'+(keccak256(signature.encode())[:4]+(32).to_bytes(32,'big')+len(tuples).to_bytes(32,'big')+b''.join(offsets)+b''.join(tuples)).hex()
def encode_signed_receipt_tuple(value):
    a,r,sigs=verify_signed_receipt(value)
    return _tuple_with_bytes(_auth(a['authorization']).abi_args()+r.abi_args(),sigs)
def encode_signed_receipt(value):return '0x'+(keccak256(SETTLE_SIGNATURE.encode())[:4]+(32).to_bytes(32,'big')+encode_signed_receipt_tuple(value)).hex()
def encode_signed_batch(values):return encode_signed_batch_tuples([encode_signed_receipt_tuple(v) for v in values])
def encode_signed_batch_tuples(tuples):return _array(BATCH_SIGNATURE,tuples)

def build_channel_permit(*, config, consumer_private_key, provider_private_key, chain_id, settlement_contract):
    c=_config(config);digest=bytes.fromhex(channel_id_for(c,chain_id=chain_id,verifying_contract=settlement_contract)[2:])
    if private_key_to_address(parse_private_key(consumer_private_key))!=c.consumer_owner or private_key_to_address(parse_private_key(provider_private_key))!=c.provider_owner:raise ChainError('V10 owner permit signer mismatch')
    return _envelope(OPEN_SCHEMA,chain_id,settlement_contract,config=c.to_payload(),channel_id='0x'+digest.hex(),consumer_signature=_sign(consumer_private_key,digest),provider_signature=_sign(provider_private_key,digest))
def verify_channel_permit(value):
    if not isinstance(value,Mapping) or value.get('schema')!=OPEN_SCHEMA or value.get('protocol_version')!=10:raise ChainError('unsupported V10 channel permit')
    c=_config(value.get('config'));digest=bytes.fromhex(channel_id_for(c,**_domain(value))[2:])
    if value.get('channel_id')!='0x'+digest.hex() or _signer(digest,value.get('consumer_signature'))!=c.consumer_owner or _signer(digest,value.get('provider_signature'))!=c.provider_owner:raise ChainError('V10 owner permit signature mismatch')
    if not (0<c.max_fee_per_request<=c.capacity and c.valid_from<c.admit_until<c.claim_until):raise ChainError('V10 invalid channel limits')
    return c

def validate_channel_open(value,*,now=None,max_channel_duration):
    c=verify_channel_permit(value)
    current=int(time.time()) if now is None else now
    if type(current) is not int or current<0:raise ChainError('V10 invalid channel open time')
    if max_channel_duration not in SUPPORTED_MAX_CHANNEL_DURATIONS:raise ChainError('V10 unsupported channel duration')
    if not (current<c.valid_from<c.admit_until<c.claim_until
            and c.claim_until-current<=max_channel_duration
            and c.permit_deadline>=current):raise ChainError('V10 channel cannot be opened at this time')
    return c

def encode_open_capacity_channels(values,*,now=None,max_channel_duration):
    current=int(time.time()) if now is None else now
    tuples=[];domain=None
    for v in values:
        c=validate_channel_open(v,now=current,max_channel_duration=max_channel_duration)
        if domain is not None and domain!=_domain(v):raise ChainError('V10 mixed open deployment')
        domain=_domain(v);tuples.append(_tuple_with_bytes(c.abi_args(),[v9._raw_signature(v[n],n) for n in ('consumer_signature','provider_signature')]))
    return _array(OPEN_SIGNATURE,tuples)

def encode_dispute_vote_by_sig(settlement_key, values):
    key = normalize_bytes32(settlement_key)
    if not 1 <= len(values) <= 16:
        raise ChainError('V10 dispute vote batch must have 1..16 items')
    tuples = []
    assignment_hash = None
    for value in values:
        vote = verify_dispute_vote(
            value, expected_settlement_key=key,
            expected_assignment_hash=assignment_hash,
        )
        assignment_hash = vote['assignment_hash']
        tuples.append(_tuple_with_bytes(
            [vote['assignment_hash'], str(vote['confirmed']), vote['report_id'], vote['decision_hash'],
             str(vote['nonce']), str(vote['deadline'])],
            [v9._raw_signature(value.get('signature'), 'signature')],
        ))
    offsets = []
    offset = 32 * len(tuples)
    for item in tuples:
        offsets.append(offset.to_bytes(32, 'big'))
        offset += len(item)
    selector = keccak256(VOTE_SIGNATURE.encode())[:4]
    encoded = selector + abi_encode_arg(key) + (64).to_bytes(32, 'big')
    encoded += len(tuples).to_bytes(32, 'big') + b''.join(offsets) + b''.join(tuples)
    return '0x' + encoded.hex()

def encode_close_expired_channel(channel_id):return v9._calldata('closeExpiredChannel(bytes32)',[v9._nonzero_hash(channel_id,'channel_id')])
def settlement_key_for(channel_id,request_id):return '0x'+keccak256(abi_encode_arg(v9._nonzero_hash(channel_id,'channel_id'))+abi_encode_arg(v9._nonzero_hash(request_id,'request_id'))).hex()

def capacity_channel(rpc_url,settlement,channel_id,*,timeout=15.0,block_tag='latest'):
    words=v9._read(rpc_url,settlement,'channelInfo(bytes32)',[v9._nonzero_hash(channel_id,'channel_id')],22,timeout=timeout,block_tag=block_tag)
    result={}
    for (name,kind),word in zip(OPEN_FIELDS,words[:18]):result[name]=v9._word_address(word) if kind=='address' else '0x'+word if kind=='bytes32' else int(word,16)
    result.update(settled_max_fee=int(words[18],16),credit_remaining=int(words[19],16),stake_remaining=int(words[20],16),closed=v9._word_bool(words[21]),channel_id=normalize_bytes32(channel_id))
    if not result['capacity']:raise ChainError('V10 unknown capacity channel')
    if result['settled_max_fee']>result['capacity'] or max(result['credit_remaining'],result['stake_remaining'])>result['capacity']:raise ChainError('V10 invalid channel accounting')
    return result
channel_info=capacity_channel

def provider_stake_status(rpc_url,settlement,provider,**options):
    options={**options,'block_tag':v9._pinned_block_tag(rpc_url,options.get('block_tag','latest'),options.get('timeout',15.0))}
    result=v9.provider_stake_status(rpc_url,settlement,provider,**options)
    allocated=int(v9._read(rpc_url,settlement,'allocatedStake(address)',[normalize_address(provider)],1,**options)[0],16)
    if allocated>result['available']:raise ChainError('V10 allocated stake exceeds free stake')
    return {**result,'allocated':allocated,'available':result['available']-allocated}

def max_authorization_ttl(rpc_url,settlement,**options):
    value=v9.max_authorization_ttl(rpc_url,settlement,**options)
    if value!=MAX_AUTHORIZATION_TTL:raise ChainError('V10 TTL differs from protocol')
    return value

def max_channel_duration(rpc_url,settlement,*,expected=None,**options):
    value=int(v9._read(rpc_url,settlement,'MAX_CHANNEL_DURATION()',[],1,**options)[0],16)
    if value not in SUPPORTED_MAX_CHANNEL_DURATIONS:raise ChainError('V10 channel duration differs from supported protocol')
    if expected is not None and value!=expected:raise ChainError('V10 channel duration differs from manifest')
    return value

def jury_registry_address(rpc_url, settlement, **options):
    return v9._word_address(v9._read(rpc_url, settlement, 'juryRegistry()', [], 1, **options)[0])

def can_form_jury_for(rpc_url, registry, channel_id, **options):
    """Return channel-specific jury capacity at the caller's pinned block."""
    registry = v9._nonzero_address(registry, 'jury_registry')
    channel_id = v9._nonzero_hash(channel_id, 'channel_id')
    return v9._word_bool(v9._read(
        rpc_url, registry, 'canFormJuryFor(bytes32)', [channel_id], 1, **options,
    )[0])

def adjudication_threshold(rpc_url, settlement, **options):
    return int(v9._read(rpc_url, settlement, 'adjudicationThreshold()', [], 1, **options)[0], 16)

def adjudicator_nonce(rpc_url, settlement, settlement_key, judge, **options):
    return int(v9._read(rpc_url, settlement, 'adjudicatorNonce(bytes32,address)',
                       [v9._nonzero_hash(settlement_key, 'settlement_key'),
                        v9._nonzero_address(judge, 'judge')], 1, **options)[0], 16)

def jury_assignment_hash(rpc_url, registry, settlement_key, **options):
    return '0x' + v9._read(rpc_url, registry, 'assignmentHash(bytes32)',
                           [v9._nonzero_hash(settlement_key, 'settlement_key')], 1, **options)[0]

def jury_assignment_provider(rpc_url, registry, settlement_key, vote_signer, **options):
    words = v9._read(
        rpc_url, registry, 'assignmentProviderForSigner(bytes32,address)',
        [v9._nonzero_hash(settlement_key, 'settlement_key'),
         v9._nonzero_address(vote_signer, 'vote_signer')], 6, **options,
    )
    return {
        'found': v9._word_bool(words[0]),
        'owner': v9._word_address(words[1]),
        'operator_id_hash': '0x' + words[2],
        'peer_id_hash': '0x' + words[3],
        'capability_hash': '0x' + words[4],
        'reputation': int(words[5], 16),
    }

def jury_registry_provider(rpc_url, registry, index, **options):
    raw_index = v9._uint(index, 'provider index')
    # The shared ABI encoder accepts canonical string arguments; keep the
    # public helper integer-friendly while avoiding implicit type failures.
    words = v9._read(rpc_url, registry, 'providerAt(uint256)', [str(raw_index)], 7, **options)
    result = {
        'owner': v9._word_address(words[0]),
        'vote_signer': v9._word_address(words[1]),
        'operator_id_hash': '0x' + words[2],
        'peer_id_hash': '0x' + words[3],
        'capability_hash': '0x' + words[4],
        'reputation': int(words[5], 16),
        'active': v9._word_bool(words[6]),
    }
    return result

def jury_registry_state(rpc_url, registry, *, timeout=15.0, block_tag='latest'):
    pinned = v9._pinned_block_tag(rpc_url, block_tag, timeout)
    options = {'timeout': timeout, 'block_tag': pinned}
    def address_value(signature):
        return v9._word_address(v9._read(rpc_url, registry, signature, [], 1, **options)[0])
    def uint_value(signature):
        return int(v9._read(rpc_url, registry, signature, [], 1, **options)[0], 16)
    count = uint_value('providerCount()')
    if count > 64:
        raise ChainError('V10 jury registry exceeds provider bound')
    providers = tuple(jury_registry_provider(rpc_url, registry, index, **options) for index in range(count))
    state = {
        'registry': v9._nonzero_address(registry, 'jury_registry'),
        'settlement': address_value('settlement()'),
        'governance': address_value('governance()'),
        'reputation_authority': address_value('reputationAuthority()'),
        'bond_penalty_recipient': address_value('bondPenaltyRecipient()'),
        'minimum_provider_reputation': uint_value('minimumReputation()'),
        'jury_size': uint_value('jurySize()'),
        'adjudication_threshold': uint_value('threshold()'),
        'jury_selection_delay_blocks': uint_value('selectionDelayBlocks()'),
        'roster_version': uint_value('rosterVersion()'),
        'provider_count': count,
        'can_form_jury': v9._word_bool(v9._read(rpc_url, registry, 'canFormJury()', [], 1, **options)[0]),
        'randomness_mode_hash': '0x' + v9._read(rpc_url, registry, 'RANDOMNESS_MODE_HASH()', [], 1, **options)[0],
        'providers': providers,
        'block_tag': pinned,
    }
    return state

# Unchanged on-chain escrow/jury/read ABIs; signatures never reuse the V9 domain.
for _name in ('key_grant','account_balance','claimable_balance','provider_signer_authorized','settlement_info','dispute_info','dispute_policy','adjudicators','report_info','report_id_for','parse_receipt_escrowed','encode_release','encode_resolve_timed_out_dispute','encode_claim_payout','encode_claim_dispute_bond','encode_open_dispute','encode_deposit_stake','encode_fund_token_rewards','encode_claim_token_reward','encode_vote_dispute','RECEIPT_ESCROWED_TOPIC','STATUS_NAMES','POLICY_FIELDS'):
    if hasattr(v9,_name):globals()[_name]=getattr(v9,_name)

@dataclass(frozen=True)
class V10Deployment(v9.V9Deployment):
    eip712_version: str = '10'
    max_authorization_ttl_seconds: int = MAX_AUTHORIZATION_TTL
    authorization_deadline_seconds: int = DEFAULT_AUTHORIZATION_DEADLINE_SECONDS
    max_channel_duration_seconds: int = MAX_CHANNEL_DURATION
    reservation_mode: str = RESERVATION_MODE
    chain_domain: str = '10'
    capacity_channel_ids: tuple[str, ...] = ()
    jury_registry: str = ZERO_ADDRESS
    jury_registry_governance: str = ZERO_ADDRESS
    reputation_authority: str = ZERO_ADDRESS
    minimum_provider_reputation: int = 0
    jury_size: int = 0
    jury_selection_delay_blocks: int = 0
    jury_randomness: str = ''
    jury_decision_policy_hash: str = ZERO_BYTES32
    genesis_hash: str = ZERO_BYTES32
    deployment_block_hash: str = ZERO_BYTES32
    settlement_runtime_code_keccak256: str = ZERO_BYTES32
    reputation_history_import: dict[str, Any] | None = None
    def to_dict(self):
        value = asdict(self)
        if self.committee_mode == DYNAMIC_PROVIDER_JURY:
            for name in ('adjudicators', 'adjudicator_operators', 'independence_attested'):
                value.pop(name, None)
        else:
            for name in ('jury_registry', 'jury_registry_governance', 'reputation_authority',
                         'minimum_provider_reputation', 'jury_size', 'jury_selection_delay_blocks',
                         'jury_randomness', 'jury_decision_policy_hash',
                         'deployment_block_hash', 'settlement_runtime_code_keccak256'):
                value.pop(name, None)
            value.pop('genesis_hash', None)
            value.pop(REPUTATION_HISTORY_FIELD, None)
        return value


def _reputation_history_lineage(value, *, chain_id, genesis_hash, settlement, network_id):
    if not isinstance(value, Mapping) or set(value) != REPUTATION_HISTORY_FIELDS:
        raise ChainError('V10 reputation_history_import must be a non-null exact lineage object')
    source_network = value.get('source_network_id')
    source_protocol = value.get('source_protocol_version')
    source_chain = value.get('source_chain_id')
    confirmations = value.get('confirmations')
    source_genesis = normalize_bytes32(str(value.get('source_genesis_hash') or ''))
    source_settlement = normalize_address(str(value.get('source_settlement_contract') or ''))
    source_runtime = normalize_bytes32(str(value.get('source_runtime_code_hash') or ''))
    source_deployment_block = value.get('source_deployment_block')
    source_deployment_block_hash = normalize_bytes32(
        str(value.get('source_deployment_block_hash') or ''))
    source_history_through_block = value.get('source_history_through_block')
    source_history_through_block_hash = normalize_bytes32(
        str(value.get('source_history_through_block_hash') or ''))
    artifact_root = normalize_bytes32(str(value.get('artifact_root') or ''))
    artifact_sha = value.get('artifact_sha256')
    if (
        value.get('schema') != REPUTATION_HISTORY_SCHEMA
        or not isinstance(source_network, str)
        or not source_network
        or source_network != source_network.strip()
        or len(source_network) > 160
        or source_network == network_id
        or type(source_protocol) is not int
        or source_protocol not in (9, 10)
        or type(source_chain) is not int
        or source_chain != chain_id
        or value.get('source_genesis_hash') != source_genesis
        or source_genesis != genesis_hash
        or value.get('source_settlement_contract') != source_settlement
        or source_settlement in (ZERO_ADDRESS, settlement)
        or value.get('source_runtime_code_hash') != source_runtime
        or source_runtime == ZERO_BYTES32
        or type(source_deployment_block) is not int
        or source_deployment_block <= 0
        or value.get('source_deployment_block_hash') != source_deployment_block_hash
        or source_deployment_block_hash == ZERO_BYTES32
        or type(source_history_through_block) is not int
        or source_history_through_block < source_deployment_block
        or value.get('source_history_through_block_hash') != source_history_through_block_hash
        or source_history_through_block_hash == ZERO_BYTES32
        or type(confirmations) is not int
        or not 2 <= confirmations <= 256
        or not isinstance(artifact_sha, str)
        or re.fullmatch(r'[0-9a-f]{64}', artifact_sha) is None
        or artifact_sha == '0' * 64
        or value.get('artifact_root') != artifact_root
        or artifact_root == ZERO_BYTES32
    ):
        raise ChainError('V10 reputation history lineage is invalid or not a prior same-chain deployment')
    return dict(value)

def _dynamic_validation_surrogate(value, *, jury_size, threshold):
    """Build throw-away judges only to reuse V9's common manifest checks.

    Dynamic V10 manifests deliberately do not contain a Provider roster.  The
    eligible set is mutable reputation state in ``ProviderJuryRegistryV1`` and
    is verified from a pinned chain snapshot.  These addresses never leave this
    validator and are discarded from the returned V10 deployment.
    """
    prohibited = {
        v9._nonzero_address(value.get(name), name)
        for name in ('settlement', 'governance', 'treasury')
    }
    policy = value.get('policy')
    if isinstance(policy, Mapping):
        prohibited.add(v9._nonzero_address(
            policy.get('bond_penalty_recipient'), 'bond_penalty_recipient'))
    judges = []
    candidate = 1
    while len(judges) < jury_size:
        address = f'0x{candidate:040x}'
        candidate += 1
        if address not in prohibited:
            judges.append(address)
    return {
        **dict(value), 'protocol_version': 9, 'eip712_version': '9',
        'committee_mode': v9.INDEPENDENT_COMMITTEE, 'independence_attested': True,
        'adjudication_threshold': threshold,
        'adjudicators': judges,
        'adjudicator_operators': {
            address: f'dynamic-provider-jury-validator-{index}'
            for index, address in enumerate(judges)
        },
    }

def validate_deployment(value,*,allow_controlled_test=False):
    if not isinstance(value,Mapping) or type(value.get('protocol_version')) is not int or value.get('protocol_version')!=10 or value.get('eip712_version')!='10' or value.get('reservation_mode')!=RESERVATION_MODE or value.get('chain_domain') not in ('10',10):raise ChainError('deployment is not fixed-channel V10')
    if value.get('max_authorization_ttl_seconds')!=MAX_AUTHORIZATION_TTL:raise ChainError('V10 manifest must pin 10800-second TTL')
    if value.get('max_channel_duration_seconds') not in SUPPORTED_MAX_CHANNEL_DURATIONS:raise ChainError('V10 manifest must pin a supported channel duration')
    mode = value.get('committee_mode', v9.INDEPENDENT_COMMITTEE)
    dynamic = mode == DYNAMIC_PROVIDER_JURY
    if dynamic:
        forbidden = sorted(DYNAMIC_JURY_FORBIDDEN_FIELDS.intersection(value))
        if forbidden:
            raise ChainError(
                'V10 dynamic jury deployment contains forbidden static committee fields: '
                + ', '.join(forbidden))
        registry = v9._nonzero_address(value.get('jury_registry'), 'jury_registry')
        registry_governance = v9._nonzero_address(value.get('jury_registry_governance'), 'jury_registry_governance')
        reputation_authority = v9._nonzero_address(value.get('reputation_authority'), 'reputation_authority')
        minimum_reputation = v9._positive_uint(value.get('minimum_provider_reputation'), 'minimum_provider_reputation', bits=64)
        jury_size = v9._positive_uint(value.get('jury_size'), 'jury_size', bits=16)
        threshold = v9._positive_uint(value.get('adjudication_threshold'), 'adjudication_threshold', bits=16)
        selection_delay = v9._positive_uint(value.get('jury_selection_delay_blocks'), 'jury_selection_delay_blocks', bits=16)
        raw_decision_policy_hash = value.get('jury_decision_policy_hash')
        decision_policy_hash = v9._nonzero_hash(
            raw_decision_policy_hash, 'jury_decision_policy_hash')
        if raw_decision_policy_hash != decision_policy_hash:
            raise ChainError('V10 jury_decision_policy_hash must be canonical lowercase bytes32')
        if not 3 <= jury_size <= 7 or not jury_size // 2 < threshold <= jury_size or threshold < 2:
            raise ChainError('V10 invalid dynamic jury quorum')
        if selection_delay > 64 or value.get('jury_randomness') != JURY_RANDOMNESS:
            raise ChainError('V10 unsupported dynamic jury randomness policy')
        settlement = v9._nonzero_address(value.get('settlement'), 'settlement')
        chain_id = v9._positive_uint(value.get('chain_id'), 'chain_id')
        raw_genesis_hash = value.get('genesis_hash')
        genesis_hash = v9._nonzero_hash(raw_genesis_hash, 'genesis_hash')
        if raw_genesis_hash != genesis_hash:
            raise ChainError('V10 genesis_hash must be canonical lowercase bytes32')
        deployment_block = v9._positive_uint(
            value.get('deployment_block'), 'deployment_block', bits=64)
        raw_deployment_block_hash = value.get('deployment_block_hash')
        deployment_block_hash = v9._nonzero_hash(
            raw_deployment_block_hash, 'deployment_block_hash')
        raw_runtime_hash = value.get('settlement_runtime_code_keccak256')
        settlement_runtime_code_keccak256 = v9._nonzero_hash(
            raw_runtime_hash, 'settlement_runtime_code_keccak256')
        if (raw_deployment_block_hash != deployment_block_hash
                or raw_runtime_hash != settlement_runtime_code_keccak256):
            raise ChainError(
                'V10 dynamic Settlement deployment boundary must use canonical lowercase hashes')
        network_id = value.get('network_id')
        history_import = _reputation_history_lineage(
            value.get(REPUTATION_HISTORY_FIELD),
            chain_id=chain_id,
            genesis_hash=genesis_hash,
            settlement=settlement,
            network_id=network_id,
        )
        governance = v9._nonzero_address(value.get('governance'), 'governance')
        treasury = v9._nonzero_address(value.get('treasury'), 'treasury')
        if (registry_governance != governance
                or len({registry, settlement, registry_governance, reputation_authority}) != 4):
            raise ChainError('V10 dynamic jury authority bindings are unsafe')
        surrogate = _dynamic_validation_surrogate(
            value, jury_size=jury_size, threshold=threshold)
        base = v9.validate_deployment(surrogate, allow_controlled_test=False)
    else:
        if REPUTATION_HISTORY_FIELD in value:
            raise ChainError('V10 reputation_history_import requires a dynamic Provider jury deployment')
        # Legacy V10 manifests remain readable until the dynamic deployment is promoted.
        base=v9.validate_deployment({**dict(value),'protocol_version':9,'eip712_version':'9'},allow_controlled_test=allow_controlled_test)
    ids=value.get('capacity_channel_ids',())
    if not isinstance(ids,(list,tuple)):raise ChainError('V10 capacity_channel_ids must be an array')
    ids=tuple(v9._nonzero_hash(x,'capacity_channel_id') for x in ids)
    if len(ids)!=len(set(ids)):raise ChainError('V10 duplicate capacity_channel_id')
    normalized = {**asdict(base), 'protocol_version':10, 'eip712_version':'10',
                  'reservation_mode':RESERVATION_MODE, 'chain_domain':'10',
                  'max_channel_duration_seconds':value['max_channel_duration_seconds'],
                  'capacity_channel_ids':ids}
    if dynamic:
        normalized.update(
            committee_mode=DYNAMIC_PROVIDER_JURY, adjudicators=(), adjudicator_operators={},
            # Dynamic independence is verified per assignment; it is not a
            # static committee attestation carried by the deployment.
            independence_attested=False, adjudication_threshold=threshold,
            jury_registry=registry, jury_registry_governance=registry_governance,
            reputation_authority=reputation_authority,
            minimum_provider_reputation=minimum_reputation, jury_size=jury_size,
            jury_selection_delay_blocks=selection_delay, jury_randomness=JURY_RANDOMNESS,
            jury_decision_policy_hash=decision_policy_hash,
            genesis_hash=genesis_hash,
            deployment_block=deployment_block,
            deployment_block_hash=deployment_block_hash,
            settlement_runtime_code_keccak256=settlement_runtime_code_keccak256,
            reputation_history_import=history_import,
        )
    return V10Deployment(**normalized)

def validate_dynamic_jury_state(rpc_url, deployment, *, timeout=15.0, block_tag='latest'):
    config = deployment if isinstance(deployment, V10Deployment) else validate_deployment(deployment)
    if config.committee_mode != DYNAMIC_PROVIDER_JURY:
        raise ChainError('V10 deployment does not use dynamic Provider jury')
    pinned = v9._pinned_block_tag(rpc_url, block_tag, timeout)
    options = {'timeout': timeout, 'block_tag': pinned}
    registry = jury_registry_address(rpc_url, config.settlement, **options)
    threshold = adjudication_threshold(rpc_url, config.settlement, **options)
    state = jury_registry_state(rpc_url, registry, **options)
    expected = {
        'registry': config.jury_registry,
        'settlement': config.settlement,
        'governance': config.jury_registry_governance,
        'reputation_authority': config.reputation_authority,
        'bond_penalty_recipient': config.policy['bond_penalty_recipient'],
        'minimum_provider_reputation': config.minimum_provider_reputation,
        'jury_size': config.jury_size,
        'adjudication_threshold': config.adjudication_threshold,
        'jury_selection_delay_blocks': config.jury_selection_delay_blocks,
        'randomness_mode_hash': JURY_RANDOMNESS_HASH,
    }
    observed = {name: state[name] for name in expected}
    if registry != config.jury_registry or threshold != config.adjudication_threshold or observed != expected:
        raise ChainError('V10 dynamic jury chain state differs from manifest')
    if (not state['can_form_jury'] or state['roster_version'] <= 0
            or not config.jury_size <= state['provider_count'] <= 64):
        raise ChainError('V10 dynamic reputation pool cannot currently form a jury')
    return state
def load_deployment(path=Path(DEFAULT_DEPLOYMENT),*,allow_controlled_test=False):
    try:return validate_deployment(json.loads(Path(path).read_text()),allow_controlled_test=allow_controlled_test)
    except (OSError,json.JSONDecodeError) as exc:raise ChainError('V10 deployment could not be read') from exc
