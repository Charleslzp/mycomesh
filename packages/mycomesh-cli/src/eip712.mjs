// EVM primitives for the V11 Consumer; mirrors mycomesh/evm.py and mycomesh/settlement.py.
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";

export const DOMAIN_NAME = "MycoMesh Settlement";
export const DOMAIN_VERSION = "11";
export const MAX_AUTHORIZATION_TTL = 3 * 60 * 60;

const enc = new TextEncoder();
export const keccak = (bytes) => Buffer.from(keccak_256(bytes));
export const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
export const unhex = (value) => Buffer.from(String(value).replace(/^0x/, ""), "hex");
const typehash = (text) => keccak(enc.encode(text));

export const AUTHORIZATION_TYPEHASH = typehash(
  "PaymentAuthorization(bytes32 requestId,bytes32 requestHash,address key,address providerSigner,"
  + "address relaySigner,uint256 maxFee,uint64 issuedAt,uint64 executeBy,uint64 deadline)");
export const RECEIPT_TYPEHASH = typehash(
  "UsageReceipt(bytes32 authorizationHash,bytes32 dispatchHash,bytes32 responseHash,uint256 inputTokens,"
  + "uint256 outputTokens,uint256 actualFee)");
export const DISPATCH_TYPEHASH = typehash("RelayDispatch(bytes32 authorizationHash)");
export const PROVIDER_TRANSPORT_TYPEHASH = typehash(
  "ProviderTransport(address providerSigner,bytes32 identityPublicKey,bytes32 transportKeyId,uint64 expiresAt)");
const DOMAIN_TYPEHASH = typehash("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

export function normalizeAddress(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new Error(`invalid address: ${value}`);
  return value.toLowerCase();
}

export function word(kind, value) {
  if (kind === "bytes32") {
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`invalid bytes32: ${value}`);
    return unhex(value);
  }
  if (kind === "address") return Buffer.concat([Buffer.alloc(12), unhex(normalizeAddress(value))]);
  if (kind === "uint") {
    const number = BigInt(value);
    if (number < 0n || number >= 1n << 256n) throw new Error("uint out of range");
    return Buffer.from(number.toString(16).padStart(64, "0"), "hex");
  }
  if (kind === "bool") return word("uint", value ? 1 : 0);
  throw new Error(`unsupported word type ${kind}`);
}

export const encodeWords = (pairs) => Buffer.concat(pairs.map(([kind, value]) => word(kind, value)));

export function addressOf(privateKey) {
  const pub = secp256k1.getPublicKey(unhex(privateKey), false);
  return hex(keccak(pub.subarray(1)).subarray(12));
}

export function signDigest(privateKey, digest) {
  const signature = secp256k1.sign(digest, unhex(privateKey), { lowS: true });
  return hex(Buffer.concat([
    Buffer.from(signature.r.toString(16).padStart(64, "0"), "hex"),
    Buffer.from(signature.s.toString(16).padStart(64, "0"), "hex"),
    Buffer.from([27 + signature.recovery]),
  ]));
}

export function recoverAddress(digest, signatureHex) {
  const raw = unhex(signatureHex);
  if (raw.length !== 65) throw new Error("signature must be 65 bytes");
  const v = raw[64] >= 27 ? raw[64] - 27 : raw[64];
  const r = BigInt(hex(raw.subarray(0, 32)));
  const s = BigInt(hex(raw.subarray(32, 64)));
  if (s > secp256k1.CURVE.n / 2n || (v !== 0 && v !== 1)) throw new Error("signature is not canonical");
  const point = new secp256k1.Signature(r, s).addRecoveryBit(v).recoverPublicKey(digest);
  return hex(keccak(point.toRawBytes(false).subarray(1)).subarray(12));
}

export function domainSeparator(chainId, verifyingContract) {
  return keccak(encodeWords([
    ["bytes32", hex(DOMAIN_TYPEHASH)], ["bytes32", hex(keccak(enc.encode(DOMAIN_NAME)))],
    ["bytes32", hex(keccak(enc.encode(DOMAIN_VERSION)))], ["uint", chainId], ["address", verifyingContract],
  ]));
}

export const typedDigest = (deployment, structHash) =>
  keccak(Buffer.concat([Buffer.from([0x19, 0x01]), domainSeparator(deployment.chainId, deployment.settlement), structHash]));

export function authorizationStructHash(a) {
  return keccak(encodeWords([
    ["bytes32", hex(AUTHORIZATION_TYPEHASH)], ["bytes32", a.request_id], ["bytes32", a.request_hash],
    ["address", a.key], ["address", a.provider_signer], ["address", a.relay_signer], ["uint", a.max_fee],
    ["uint", a.issued_at], ["uint", a.execute_by], ["uint", a.deadline],
  ]));
}

export const dispatchStructHash = (authorizationHash) =>
  keccak(encodeWords([["bytes32", hex(DISPATCH_TYPEHASH)], ["bytes32", hex(authorizationHash)]]));

export function receiptStructHash(r) {
  return keccak(encodeWords([
    ["bytes32", hex(RECEIPT_TYPEHASH)], ["bytes32", r.authorization_hash], ["bytes32", r.dispatch_hash],
    ["bytes32", r.response_hash], ["uint", r.input_tokens], ["uint", r.output_tokens], ["uint", r.actual_fee],
  ]));
}

export const requestIdFor = (key, nonce) => hex(keccak(encodeWords([["address", key], ["bytes32", nonce]])));
export const settlementKey = (key, requestId) => hex(keccak(encodeWords([["address", key], ["bytes32", requestId]])));

/** Every check the settlement contract makes that needs no chain state. */
export function verifySignedReceipt(signed, deployment) {
  const a = signed.authorization;
  const r = signed.receipt;
  const authHash = authorizationStructHash(a);
  if (r.authorization_hash !== hex(authHash) || r.dispatch_hash !== hex(dispatchStructHash(authHash))) {
    throw new Error("receipt is not bound to its authorization");
  }
  if (!(BigInt(r.actual_fee) > 0n && BigInt(r.actual_fee) <= BigInt(a.max_fee))) throw new Error("receipt fee exceeds the authorization");
  if (recoverAddress(typedDigest(deployment, authHash), signed.key_signature) !== a.key) throw new Error("bad consumer key signature");
  if (recoverAddress(typedDigest(deployment, dispatchStructHash(authHash)), signed.relay_signature) !== a.relay_signer) {
    throw new Error("bad relay dispatch signature");
  }
  if (recoverAddress(typedDigest(deployment, receiptStructHash(r)), signed.provider_signature) !== a.provider_signer) {
    throw new Error("bad provider signature");
  }
}

// ---------------- transactions (Consumer setup: approve, deposit, registerKey) ----------------

function rlp(value) {
  if (Array.isArray(value)) return prefix(Buffer.concat(value.map(rlp)), 0xc0);
  let bytes;
  if (typeof value === "bigint" || typeof value === "number") {
    const number = BigInt(value);
    bytes = number === 0n ? Buffer.alloc(0) : Buffer.from(number.toString(16).padStart(Math.ceil(number.toString(16).length / 2) * 2, "0"), "hex");
  } else bytes = Buffer.from(value);
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  return prefix(bytes, 0x80);
}

function prefix(payload, offset) {
  if (payload.length <= 55) return Buffer.concat([Buffer.from([offset + payload.length]), payload]);
  const lengthHex = payload.length.toString(16);
  const length = Buffer.from(lengthHex.padStart(Math.ceil(lengthHex.length / 2) * 2, "0"), "hex");
  return Buffer.concat([Buffer.from([offset + 55 + length.length]), length, payload]);
}

export function signLegacyTransaction(privateKey, { nonce, gasPrice, gasLimit, to, value = 0n, data, chainId }) {
  const fields = [BigInt(nonce), BigInt(gasPrice), BigInt(gasLimit), to ? unhex(normalizeAddress(to)) : Buffer.alloc(0),
    BigInt(value), unhex(data)];
  const signature = secp256k1.sign(keccak(rlp([...fields, BigInt(chainId), 0n, 0n])), unhex(privateKey), { lowS: true });
  return hex(rlp([...fields, BigInt(chainId) * 2n + 35n + BigInt(signature.recovery), signature.r, signature.s]));
}

export function encodeCall(signature, pairs) {
  return hex(Buffer.concat([keccak(enc.encode(signature)).subarray(0, 4), encodeWords(pairs)]));
}
