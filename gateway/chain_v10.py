from __future__ import annotations

"""V10 fixed-budget channel wire protocol. Pure signing/encoding and read-only RPC.
No helper broadcasts transactions or reads wallet files. Existing V9 obligations
remain in their original domain. Execution requires a durable Provider ledger.
"""
import json
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
VOTE_TYPE = "DisputeVote(bytes32 settlementKey,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)"
AUTH_FIELDS = (('channel_id','bytes32'),('request_id','bytes32'),('request_hash','bytes32'),('key','address'),('max_fee','uint256'),('issued_at','uint64'),('execute_by','uint64'),('deadline','uint64'))
RECEIPT_FIELDS = (('channel_id','bytes32'),('authorization_hash','bytes32'),('dispatch_hash','bytes32'),('response_hash','bytes32'),('input_tokens','uint256'),('output_tokens','uint256'),('actual_fee','uint256'))
OPEN_FIELDS = (('consumer_owner','address'),('consumer_key','address'),('provider_owner','address'),('provider_signer','address'),('relay','address'),('relay_signer','address'),('pool','address'),('channel','bytes32'),('pricing_version','uint64'),('pricing_hash','bytes32'),('capacity','uint256'),('max_fee_per_request','uint256'),('valid_from','uint64'),('admit_until','uint64'),('claim_until','uint64'),('consumer_nonce','uint256'),('provider_nonce','uint256'),('permit_deadline','uint64'))
VOTE_FIELDS = (('confirmed','bool'),('report_id','bytes32'),('decision_hash','bytes32'),('nonce','uint256'),('deadline','uint64'))
VOTE_HASH_FIELDS = (('settlement_key','bytes32'),) + VOTE_FIELDS
AUTH_TUPLE = '(' + ','.join(t for _,t in AUTH_FIELDS) + ')'
RECEIPT_TUPLE = '(' + ','.join(t for _,t in RECEIPT_FIELDS) + ')'
OPEN_TUPLE = '(' + ','.join(t for _,t in OPEN_FIELDS) + ')'
VOTE_TUPLE = '(bool,bytes32,bytes32,uint256,uint64,bytes)'
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
    return DisputeVote(
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

def build_dispute_vote(*, settlement_key, confirmed, report_id, decision_hash, nonce, deadline,
                       judge_private_key, chain_id, settlement_contract):
    vote = _vote({'confirmed': confirmed, 'report_id': report_id, 'decision_hash': decision_hash,
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

def verify_dispute_vote(value, *, expected_settlement_key=None, expected_chain_id=None,
                        expected_contract=None, expected_judge=None, now=None):
    if not isinstance(value, Mapping):
        raise ChainError('V10 dispute vote must be an object')
    vote = _vote(value)
    key = normalize_bytes32(str(value.get('settlement_key') or ''))
    domain_chain = v9._positive_uint(value.get('chain_id'), 'chain_id')
    domain_contract = v9._nonzero_address(value.get('settlement_contract'), 'contract')
    v9._expect_bytes32(expected_settlement_key, key, 'settlement_key')
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
    for value in values:
        vote = verify_dispute_vote(value, expected_settlement_key=key)
        tuples.append(_tuple_with_bytes(
            [str(vote['confirmed']), vote['report_id'], vote['decision_hash'],
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

# Unchanged on-chain escrow/jury/read ABIs; signatures never reuse the V9 domain.
for _name in ('key_grant','account_balance','claimable_balance','provider_signer_authorized','settlement_info','dispute_info','dispute_policy','adjudicators','report_info','report_id_for','parse_receipt_escrowed','encode_release','encode_resolve_timed_out_dispute','encode_claim_payout','encode_claim_dispute_bond','encode_open_dispute','encode_submit_evidence','encode_deposit_stake','encode_fund_token_rewards','encode_claim_token_reward','encode_vote_dispute','RECEIPT_ESCROWED_TOPIC','STATUS_NAMES','POLICY_FIELDS'):
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
    def to_dict(self):return asdict(self)

def validate_deployment(value,*,allow_controlled_test=False):
    if not isinstance(value,Mapping) or type(value.get('protocol_version')) is not int or value.get('protocol_version')!=10 or value.get('eip712_version')!='10' or value.get('reservation_mode')!=RESERVATION_MODE or value.get('chain_domain') not in ('10',10):raise ChainError('deployment is not fixed-channel V10')
    if value.get('max_authorization_ttl_seconds')!=MAX_AUTHORIZATION_TTL:raise ChainError('V10 manifest must pin 10800-second TTL')
    if value.get('max_channel_duration_seconds') not in SUPPORTED_MAX_CHANNEL_DURATIONS:raise ChainError('V10 manifest must pin a supported channel duration')
    # Reuse explicit human committee / monetary policy validation, not signatures.
    base=v9.validate_deployment({**dict(value),'protocol_version':9,'eip712_version':'9'},allow_controlled_test=allow_controlled_test)
    ids=value.get('capacity_channel_ids',())
    if not isinstance(ids,(list,tuple)):raise ChainError('V10 capacity_channel_ids must be an array')
    ids=tuple(v9._nonzero_hash(x,'capacity_channel_id') for x in ids)
    if len(ids)!=len(set(ids)):raise ChainError('V10 duplicate capacity_channel_id')
    return V10Deployment(**{**asdict(base),'protocol_version':10,'eip712_version':'10','reservation_mode':RESERVATION_MODE,'chain_domain':'10','max_channel_duration_seconds':value['max_channel_duration_seconds'],'capacity_channel_ids':ids})
def load_deployment(path=Path(DEFAULT_DEPLOYMENT),*,allow_controlled_test=False):
    try:return validate_deployment(json.loads(Path(path).read_text()),allow_controlled_test=allow_controlled_test)
    except (OSError,json.JSONDecodeError) as exc:raise ChainError('V10 deployment could not be read') from exc
