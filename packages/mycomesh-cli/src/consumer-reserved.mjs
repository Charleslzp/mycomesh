import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3.js';

// These types are shared with MycoSettlementV10.sol and gateway/chain_v10.py.
export const RESERVED_AUTH_SCHEMA = 'mycomesh.x402.myco-credit-v4';
export const RESERVED_SIGNED_SCHEMA = 'mycomesh.settlement.v10.signed.v1';
const AUTH_TYPE = 'ReservedPaymentAuthorization(bytes32 channelId,bytes32 requestId,bytes32 requestHash,address key,uint256 maxFee,uint64 issuedAt,uint64 executeBy,uint64 deadline)';
const RECEIPT_TYPE = 'ReservedUsageReceipt(bytes32 channelId,bytes32 authorizationHash,bytes32 dispatchHash,bytes32 responseHash,uint256 inputTokens,uint256 outputTokens,uint256 actualFee)';
const DISPATCH_TYPE = 'RelayDispatch(bytes32 authorizationHash,bytes32 channelId)';
const OPEN_TYPE = 'OpenCapacityChannel(address consumerOwner,address consumerKey,address providerOwner,address providerSigner,address relay,address relaySigner,address pool,bytes32 channel,uint64 pricingVersion,bytes32 pricingHash,uint256 capacity,uint256 maxFeePerRequest,uint64 validFrom,uint64 admitUntil,uint64 claimUntil,uint256 consumerNonce,uint256 providerNonce,uint64 permitDeadline)';
const AUTH_FIELDS = [['channel_id','b'],['request_id','b'],['request_hash','b'],['key','a'],['max_fee',256],['issued_at',64],['execute_by',64],['deadline',64]];
const RECEIPT_FIELDS = [['channel_id','b'],['authorization_hash','b'],['dispatch_hash','b'],['response_hash','b'],['input_tokens',256],['output_tokens',256],['actual_fee',256]];
export const CHANNEL_FIELDS = [['consumer_owner','a'],['consumer_key','a'],['provider_owner','a'],['provider_signer','a'],['relay','a'],['relay_signer','a'],['pool','a'],['channel','b'],['pricing_version',64],['pricing_hash','b'],['capacity',256],['max_fee_per_request',256],['valid_from',64],['admit_until',64],['claim_until',64],['consumer_nonce',256],['provider_nonce',256],['permit_deadline',64]];
const hash = bytes => '0x' + Buffer.from(keccak_256(bytes)).toString('hex');
const bytes = value => Buffer.from(value.slice(2), 'hex');
const textHash = value => bytes(hash(Buffer.from(value)));
const integer = value => value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
function record(raw, fields) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('missing V10 record');
  return Object.fromEntries(fields.map(([name, kind]) => {
    let value = raw[name];
    if (kind === 'a' || kind === 'b') {
      if (typeof value !== 'string' || !(kind === 'a' ? /^0x[\da-f]{40}$/i : /^0x[\da-f]{64}$/i).test(value)
          || (name !== 'pool' && /^0x0+$/.test(value))) throw new Error(`invalid V10 ${name}`);
      value = value.toLowerCase();
    } else {
      if (!(typeof value === 'number' && Number.isSafeInteger(value)) && !(typeof value === 'string' && /^\d+$/.test(value))) throw new Error(`invalid V10 ${name}`);
      const n = BigInt(value);
      if (n < 0n || n >= (1n << BigInt(kind))) throw new Error(`invalid V10 ${name}`);
      value = integer(n);
    }
    return [name, value];
  }));
}
const word = value => Buffer.from((typeof value === 'string' && value.startsWith('0x') ? value.slice(2) : BigInt(value).toString(16)).padStart(64, '0'), 'hex');
const structHash = (type, raw, fields) => hash(Buffer.concat([textHash(type), ...Object.values(record(raw, fields)).map(word)]));
function digest(struct, chainId, contract) {
  const c = record({key:contract}, [['key','a']]).key;
  if (!Number.isSafeInteger(Number(chainId)) || BigInt(chainId) <= 0n) throw new Error('invalid V10 chain ID');
  const domain = hash(Buffer.concat([textHash('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'), textHash('MycoMesh Settlement'), textHash('10'), word(chainId), word(c)]));
  return bytes(hash(Buffer.concat([Buffer.from([25,1]), bytes(domain), bytes(struct)])));
}
function privateBytes(key) {
  return String(key).startsWith('myco_sk_') ? Buffer.from(key.slice(8), 'base64url') : Buffer.from(key.replace(/^0x/, ''), 'hex');
}
function recover(d, sig) {
  if (typeof sig !== 'string' || !/^0x[\da-f]{130}$/i.test(sig)) throw new Error('invalid V10 signature');
  const raw = bytes(sig), recovery = raw[64] >= 27 ? raw[64]-27 : raw[64];
  if (recovery > 1) throw new Error('invalid V10 signature recovery');
  const s = secp256k1.Signature.fromCompact(raw.subarray(0,64));
  if (s.hasHighS()) throw new Error('noncanonical V10 signature');
  return '0x'+hash(s.addRecoveryBit(recovery).recoverPublicKey(d).toRawBytes(false).slice(1)).slice(-40);
}
export function capacityChannelId(config, chainId, contract) { return '0x' + digest(structHash(OPEN_TYPE, config, CHANNEL_FIELDS), chainId, contract).toString('hex'); }
export function reservedSettlementKey(channelId, requestId) {
  const normalized = record({channel_id:channelId,request_id:requestId},AUTH_FIELDS.slice(0,2));
  return hash(Buffer.concat(Object.values(normalized).map(word)));
}
export function decodeCapacityChannel(output, channelId, chainId, contract) {
  if (typeof output !== 'string' || !/^0x[\da-f]{1408}$/i.test(output)) throw new Error('invalid channelInfo response');
  const words = output.slice(2).match(/.{64}/g);
  const raw = Object.fromEntries(CHANNEL_FIELDS.map(([name,kind],i) => {
    if (kind === 'a' && !/^0{24}/.test(words[i])) throw new Error('noncanonical channel address');
    return [name,kind === 'a' ? '0x'+words[i].slice(24) : kind === 'b' ? '0x'+words[i] : BigInt('0x'+words[i]).toString()];
  }));
  const config = record(raw, CHANNEL_FIELDS);
  const [settled,credit,stake,closed] = words.slice(18).map(w=>BigInt('0x'+w));
  if (closed > 1n || BigInt(config.capacity) === 0n || [settled,credit,stake].some(n=>n>BigInt(config.capacity))) throw new Error('invalid channel accounting');
  if (capacityChannelId(config,chainId,contract) !== channelId.toLowerCase()) throw new Error('channel identity mismatch');
  return {...config,channel_id:channelId.toLowerCase(),settled_max_fee:integer(settled),credit_remaining:integer(credit),stake_remaining:integer(stake),closed:closed===1n};
}
export function buildReservedAuthorization({paymentKey,chainId,settlementContract,channelId,requestId,requestHash,maxFee,issuedAt,executeBy,deadline}) {
  const keyBytes=privateBytes(paymentKey);
  const key='0x'+hash(secp256k1.getPublicKey(keyBytes,false).slice(1)).slice(-40);
  const authorization=record({channel_id:channelId,request_id:requestId,request_hash:requestHash,key,max_fee:maxFee,issued_at:issuedAt,execute_by:executeBy,deadline},AUTH_FIELDS);
  const h=structHash(AUTH_TYPE,authorization,AUTH_FIELDS), d=digest(h,chainId,settlementContract);
  const sig=secp256k1.sign(d,keyBytes,{lowS:true,prehash:false});
  const envelope={schema:RESERVED_AUTH_SCHEMA,protocol_version:10,chain_id:Number(chainId),settlement_contract:settlementContract.toLowerCase(),authorization,authorization_hash:h,authorization_digest:'0x'+d.toString('hex'),key_signature:'0x'+Buffer.concat([Buffer.from(sig.toCompactRawBytes()),Buffer.from([27+sig.recovery])]).toString('hex')};
  verifyReservedAuthorization(envelope,{now:issuedAt});
  return envelope;
}
export function verifyReservedAuthorization(value, expected={}) {
  if (value?.schema!==RESERVED_AUTH_SCHEMA || value.protocol_version!==10) throw new Error('unsupported reserved authorization');
  if (expected.protocolVersion!==undefined && expected.protocolVersion!==10) throw new Error('settlement protocol version mismatch');
  const a=record(value.authorization,AUTH_FIELDS), now=BigInt(expected.now ?? Math.floor(Date.now()/1000));
  if (!(BigInt(a.max_fee)>0n && BigInt(a.issued_at)<=now && now<=BigInt(a.deadline) && BigInt(a.issued_at)<=BigInt(a.execute_by) && BigInt(a.execute_by)<BigInt(a.deadline) && BigInt(a.deadline)-BigInt(a.issued_at)<=10800n)) throw new Error('V10 authorization time/fee invalid');
  for (const [wanted,actual] of [[expected.chainId,value.chain_id],[expected.contract,value.settlement_contract],[expected.channelId,a.channel_id],[expected.requestId,a.request_id],[expected.requestHash,a.request_hash]]) {
    if (wanted!==undefined && String(wanted).toLowerCase()!==String(actual).toLowerCase()) throw new Error('V10 authorization scope mismatch');
  }
  const h=structHash(AUTH_TYPE,a,AUTH_FIELDS),d=digest(h,value.chain_id,value.settlement_contract);
  if (value.authorization_hash!==h || value.authorization_digest!=='0x'+d.toString('hex') || recover(d,value.key_signature)!==a.key) throw new Error('V10 authorization signature/hash mismatch');
  return {...value,authorization:a};
}
export function verifyReservedReceipt(value, expected={}) {
  if (value?.schema!==RESERVED_SIGNED_SCHEMA || value.protocol_version!==10) throw new Error('unsupported reserved receipt');
  const a=verifyReservedAuthorization(value.authorization,expected),c=expected.channel;
  // Role identities must come from a pinned on-chain channel, never the Relay's envelope.
  if (!c || capacityChannelId(c,a.chain_id,a.settlement_contract)!==a.authorization.channel_id || c.closed!==false || c.consumer_key!==a.authorization.key) throw new Error('verified capacity channel required');
  const auth=a.authorization;
  if (!(BigInt(c.valid_from)<=BigInt(auth.issued_at) && BigInt(auth.execute_by)<=BigInt(c.admit_until) && BigInt(auth.deadline)<=BigInt(c.claim_until) && BigInt(auth.max_fee)<=BigInt(c.max_fee_per_request))) throw new Error('authorization exceeds channel terms');
  const d=value.dispatch;
  if (d?.schema!=='mycomesh.settlement.v10.dispatch.v1' || d.protocol_version!==10 || d.authorization?.authorization_hash!==a.authorization_hash || d.authorization?.key_signature!==a.key_signature) throw new Error('invalid Relay dispatch');
  verifyReservedAuthorization(d.authorization,expected);
  for (const envelope of [value,d]) if (envelope.chain_id!==a.chain_id || envelope.settlement_contract!==a.settlement_contract) throw new Error('V10 receipt deployment mismatch');
  const dh=hash(Buffer.concat([textHash(DISPATCH_TYPE),word(a.authorization_hash),word(auth.channel_id)]));
  const dd=digest(dh,a.chain_id,a.settlement_contract);
  if (d.dispatch_hash!==dh || d.dispatch_digest!=='0x'+dd.toString('hex') || d.relay_signer!==c.relay_signer || recover(dd,d.relay_signature)!==c.relay_signer || value.relay_signature!==d.relay_signature) throw new Error('V10 Relay dispatch signature mismatch');
  const r=record(value.receipt,RECEIPT_FIELDS);
  if (r.channel_id!==auth.channel_id || r.authorization_hash!==a.authorization_hash || r.dispatch_hash!==dh || BigInt(r.actual_fee)<=0n || BigInt(r.actual_fee)>BigInt(auth.max_fee) || value.key_signature!==a.key_signature || value.provider_signer!==c.provider_signer) throw new Error('V10 receipt binding mismatch');
  if (recover(digest(structHash(RECEIPT_TYPE,r,RECEIPT_FIELDS),a.chain_id,a.settlement_contract),value.provider_signature)!==c.provider_signer) throw new Error('V10 Provider signature mismatch');
  return {authorization:a,receipt:{...r,provider:c.provider_owner,provider_signer:c.provider_signer,relay:c.relay,pool:c.pool}};
}
