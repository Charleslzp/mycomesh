// V11 sealed request/response protocol; mirrors mycomesh/protocol.py and mycomesh/consumer.py.
import { createHash, randomBytes } from "node:crypto";
import {
  PROVIDER_TRANSPORT_TYPEHASH, addressOf, authorizationStructHash, encodeWords, hex, keccak, normalizeAddress,
  recoverAddress, requestIdFor, signDigest, typedDigest, verifySignedReceipt,
} from "./eip712.mjs";
import {
  canonicalJson, generateIdentity, generateTransportKey, openFrame, sealFrame, verifyTransportKeyBinding,
} from "./secure-envelope.mjs";

export const REQUEST_SCHEMA = "mycomesh.v11.request.v1";
export const RESPONSE_SCHEMA = "mycomesh.v11.response.v1";
export const SEALED_REQUEST_PURPOSE = "mycomesh.v11.sealed-request";
export const SEALED_RESPONSE_PURPOSE = "mycomesh.v11.sealed-response";
export const SEALED_DELTA_PURPOSE = "mycomesh.v11.sealed-delta";

export const sha256Hex = (bytes) => `0x${createHash("sha256").update(bytes).digest("hex")}`;

export function buildRequest({ endpoint, model, content, maxOutputTokens, replyKeyId, options = {} }) {
  if (!["responses", "chat"].includes(endpoint)) throw new Error("unsupported endpoint");
  if (!Number.isSafeInteger(maxOutputTokens) || maxOutputTokens < 1) throw new Error("invalid max_output_tokens");
  const document = {
    schema: REQUEST_SCHEMA, endpoint, model, [endpoint === "chat" ? "messages" : "input"]: content,
    max_output_tokens: maxOutputTokens, options, reply_key_id: replyKeyId,
  };
  return Buffer.from(canonicalJson(document), "utf8");
}

/** Return the Provider signer a descriptor's own EVM attestation proves; a Relay cannot forge it. */
export function verifiedProvider(descriptor, deployment, now) {
  const binding = verifyTransportKeyBinding(descriptor.transport_key, { now });
  const attestation = descriptor.transport_attestation || {};
  const signer = normalizeAddress(attestation.provider_signer);
  if (!Number.isSafeInteger(attestation.expires_at) || attestation.expires_at <= now) throw new Error("transport attestation expired");
  const structHash = keccak(encodeWords([
    ["bytes32", hex(PROVIDER_TRANSPORT_TYPEHASH)], ["address", signer],
    ["bytes32", `0x${binding.identityPublicKey}`], ["bytes32", `0x${binding.keyId.replace(/^x25519_/, "")}`],
    ["uint", attestation.expires_at],
  ]));
  if (recoverAddress(typedDigest(deployment, structHash), attestation.signature) !== signer) {
    throw new Error("transport attestation signature is invalid");
  }
  if (String(descriptor.provider_signer || "").toLowerCase() !== signer) throw new Error("descriptor signer differs from its attestation");
  return { signer, binding: descriptor.transport_key };
}

export function prepareRequest({ descriptor, deployment, keyPrivate, relaySigner, endpoint, model, content,
  maxOutputTokens, maxFee, options = {}, now = Math.floor(Date.now() / 1000) }) {
  const { signer, binding } = verifiedProvider(descriptor, deployment, now);
  const identity = generateIdentity();
  const replyKey = generateTransportKey(identity, { lifetimeSeconds: 3600, now });
  const plaintext = buildRequest({ endpoint, model, content, maxOutputTokens, replyKeyId: replyKey.binding.key_id, options });
  const key = addressOf(keyPrivate);
  const authorization = {
    request_id: requestIdFor(key, hex(randomBytes(32))), request_hash: sha256Hex(plaintext), key,
    provider_signer: signer, relay_signer: normalizeAddress(relaySigner), max_fee: maxFee,
    issued_at: now, execute_by: now + 300, deadline: now + 7200,
  };
  const sealed = sealFrame(plaintext, {
    sender: identity, recipientBinding: binding, expectedRecipientPeerId: binding.peer_id,
    purpose: SEALED_REQUEST_PURPOSE, ttlSeconds: 300, now,
  });
  return {
    authorization, replyKey, providerPeerId: binding.peer_id, requestPlaintext: plaintext,
    payload: {
      authorization,
      key_signature: signDigest(keyPrivate, typedDigest(deployment, authorizationStructHash(authorization))),
      sealed_request: sealed.toString("base64"),
      reply_transport_key: replyKey.binding,
    },
  };
}

/** The assistant text of a Responses, Chat Completions or Anthropic Messages payload. */
export function outputText(output) {
  if (output && typeof output === "object") {
    if (typeof output.output_text === "string") return output.output_text;
    if (Array.isArray(output.choices) && output.choices.length) return String(output.choices[0].message?.content ?? "");
    if (Array.isArray(output.content)) return output.content.map((part) => part?.text ?? "").join("");
    return (output.output || []).flatMap((item) => item?.content || []).map((part) => part?.text ?? "").join("");
  }
  return output == null ? "" : String(output);
}

/** Decrypt one streamed delta; a Relay can drop or stall deltas but never reorder or forge them. */
export function openDelta(prepared, sealed, expectedSeq, now = Math.floor(Date.now() / 1000)) {
  const opened = openFrame(Buffer.from(sealed, "base64"), {
    recipientKey: prepared.replyKey, expectedPurpose: SEALED_DELTA_PURPOSE, replaySet: new Set(),
    expectedSenderPeerId: prepared.providerPeerId, now,
  });
  const value = JSON.parse(opened.payload.toString("utf8"));
  if (value.seq !== expectedSeq || typeof value.delta !== "string") throw new Error("streamed delta is out of order");
  return value.delta;
}

/** Decrypt the response and prove it is exactly what the Provider signed for. */
export function openResponse(prepared, result, deployment, now = Math.floor(Date.now() / 1000)) {
  const signed = result.receipt;
  if (canonicalJson(signed.authorization) !== canonicalJson(prepared.authorization)) {
    throw new Error("receipt is for a different authorization");
  }
  verifySignedReceipt(signed, deployment);
  const opened = openFrame(Buffer.from(result.sealed_response, "base64"), {
    recipientKey: prepared.replyKey, expectedPurpose: SEALED_RESPONSE_PURPOSE, replaySet: new Set(),
    expectedSenderPeerId: prepared.providerPeerId, now,
  });
  if (sha256Hex(opened.payload) !== signed.receipt.response_hash) throw new Error("response differs from the Provider-signed receipt");
  const response = JSON.parse(opened.payload.toString("utf8"));
  if (response.schema !== RESPONSE_SCHEMA || response.request_hash !== prepared.authorization.request_hash) {
    throw new Error("response is not bound to this request");
  }
  return { response, receipt: signed, responsePlaintext: opened.payload };
}
