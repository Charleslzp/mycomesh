import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { verifyResponseProof, RESPONSE_PROOF_SCHEMA } from '../src/consumer-runtime.mjs';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const context = { requestId: `0x${'42'.repeat(32)}`, endpoint: 'responses', model: 'fixture-model' };
function pythonProof() {
  const result = spawnSync('python3', ['-B', '-c', `
import json
from gateway.relay_integrity import provider_response_hash,provider_response_proof
body={'peer':{'peer_id':'fixture','public_key':'test'},'request_id':'${context.requestId}',
'endpoint':'responses','model':'fixture-model','output_text':'你好 🧪','usage':{'input_tokens':2,'output_tokens':4},
'raw':{'output_text':'你好 🧪','output':[{'type':'function_call','name':'pay','arguments':'{"amount":0.000001}'}],
'probability':1e-7,'score':1.0,'negative_zero':-0.0,'extras':{'2':'two','10':'ten'}}}
print(json.dumps({'proof':provider_response_proof(body),'receipt':{'response_hash':provider_response_hash(body)}}))
`], { cwd: ROOT, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
const fixture = pythonProof();

test('exact Python bytes verify in JS despite float, Unicode and numeric-key serialization differences', () => {
  const raw = verifyResponseProof(fixture.proof, fixture.receipt, context);
  assert.equal(raw.output_text, '你好 🧪');
  assert.equal(raw.probability, 1e-7);
  assert.equal(raw.output[0].arguments, '{"amount":0.000001}');
  const parsed = JSON.parse(Buffer.from(fixture.proof.commitment_b64, 'base64'));
  assert.notEqual(`0x${createHash('sha256').update(JSON.stringify(parsed)).digest('hex')}`, fixture.receipt.response_hash,
    'test must exercise bytes which JS would serialize differently');
});

for (const field of ['requestId', 'model', 'endpoint']) {
  test(`valid signed bytes for another ${field} cannot be substituted`, () => {
    assert.throws(() => verifyResponseProof(fixture.proof, fixture.receipt, { ...context, [field]: 'other' }), /match this request/);
  });
}
test('proof ignores unsigned sibling answers and returns only Provider committed raw', () => {
  const raw = verifyResponseProof({ ...fixture.proof, raw: { output_text: 'relay forgery' }, output_text: 'relay forgery' }, fixture.receipt, context);
  assert.equal(raw.output_text, '你好 🧪');
});
test('malformed and oversized proof encodings fail closed', () => {
  for (const proof of [null, {}, { schema: RESPONSE_PROOF_SCHEMA, commitment_b64: '%%%INVALID' },
    { ...fixture.proof, commitment_b64: `${fixture.proof.commitment_b64}\n` },
    { schema: RESPONSE_PROOF_SCHEMA, commitment_b64: 'A'.repeat(32 * 1024 * 1024 + 1) }]) {
    assert.throws(() => verifyResponseProof(proof, fixture.receipt, context));
  }
});
test('changed content with unchanged receipt fails authentication', () => {
  const value = JSON.parse(Buffer.from(fixture.proof.commitment_b64, 'base64'));
  value.raw.output[0].arguments = '{"amount":99999}';
  assert.throws(() => verifyResponseProof({ ...fixture.proof, commitment_b64: Buffer.from(JSON.stringify(value)).toString('base64') }, fixture.receipt, context), /signed commitment/);
});
