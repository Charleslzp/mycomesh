import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ConsumerRequestJournal, RequestJournalError, requestPayloadHash } from '../src/consumer-request-journal.mjs';
const contract='0x'+'11'.repeat(20), key='0x'+'22'.repeat(20);
const hash=requestPayloadHash({path:'/v1/responses',body:{input:'PRIVATE PROMPT must not be stored',model:'fixture'}});
const result={status:200,headers:{'content-type':'application/json','x-mycomesh-request-id':'req-fixture'},payload:{id:'response-1',object:'response',output_text:'answer',usage:{input_tokens:3,output_tokens:2}}};
function setup(t,opts={}) {
  const directory=mkdtempSync(join(tmpdir(),'mycomesh-idempotency-'));
  t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const config={directory,chainId:11155111,contract,paymentKeyAddress:key,...opts};
  return {config,journal:new ConsumerRequestJournal(config)};
}
function claim(journal,idempotencyKey='caller-key-1',payloadHash=hash) {return journal.claim({idempotencyKey,payloadHash});}
function file(journal,claim) {return join(journal.directory,claim.entryKey+'.json');}
test('canonical payload hashes bind endpoint and JSON content but ignore object key order',()=>{
  assert.equal(requestPayloadHash({a:1,b:[2,3]}),requestPayloadHash({b:[2,3],a:1}));
  assert.notEqual(requestPayloadHash({path:'/a',body:{a:1}}),requestPayloadHash({path:'/b',body:{a:1}}));
  for(const bad of [NaN,undefined,{a:undefined},new Date(),[Infinity],new Array(1)])assert.throws(()=>requestPayloadHash(bad));
  const cycle={};cycle.self=cycle;assert.throws(()=>requestPayloadHash(cycle));
});
test('claim is durable across new instances and incomplete execution never reopens',t=>{
  const {journal,config}=setup(t),first=claim(journal);
  assert.equal(first.action,'execute');assert.match(first.requestId,/^0x[0-9a-f]{64}$/);
  assert.throws(()=>claim(new ConsumerRequestJournal(config)),e=>e instanceof RequestJournalError&&e.code==='idempotency_outcome_unknown'&&e.requestId===first.requestId&&e.statusCode===422&&!e.retryable);
  const saved=JSON.parse(readFileSync(file(journal,first),'utf8'));assert.equal(saved.phase,'in_progress');
  assert.equal(saved.request_id,first.requestId);
});
test('completed output replays under the same stable request ID after restart',t=>{
  const {journal,config}=setup(t),first=claim(journal),cached=journal.complete(first,result);
  const replay=claim(new ConsumerRequestJournal(config));
  assert.equal(replay.action,'replay');assert.equal(replay.requestId,first.requestId);assert.deepEqual(replay.result,cached);
  assert.deepEqual(replay.result,result);
});
test('key and payload conflicts cannot execute or replace an existing response',t=>{
  const {journal}=setup(t),first=claim(journal);
  journal.complete(first,result);
  assert.throws(()=>claim(journal,'caller-key-1',requestPayloadHash({different:true})),e=>e.code==='idempotency_conflict');
  assert.throws(()=>journal.complete(first,{...result,payload:{output_text:'replacement'}}),e=>e.code==='idempotency_completion_conflict');
  assert.deepEqual(claim(journal).result,result);
});
test('unknown and ancient tombstones remain fenced forever; late owner completion is allowed',t=>{
  const {journal,config}=setup(t),first=claim(journal);
  journal.markOutcomeUnknown(first);
  const saved=JSON.parse(readFileSync(file(journal,first),'utf8'));saved.created_at=1;saved.updated_at=1;
  writeFileSync(file(journal,first),JSON.stringify(saved),{mode:0o600});
  assert.throws(()=>claim(new ConsumerRequestJournal(config)),e=>e.code==='idempotency_outcome_unknown');
  journal.complete(first,result);journal.markOutcomeUnknown(first);
  assert.equal(claim(journal).action,'replay');
});
test('journal scope isolates chain contract and payment key',t=>{
  const {journal,config}=setup(t),first=claim(journal);
  for(const changes of [{chainId:1},{contract:'0x'+'33'.repeat(20)},{paymentKeyAddress:'0x'+'44'.repeat(20)}]) {
    const next=claim(new ConsumerRequestJournal({...config,...changes}));assert.equal(next.action,'execute');assert.notEqual(next.requestId,first.requestId);
  }
});
test('journal never saves caller key, prompt, credentials, or payment proofs',t=>{
  const {journal}=setup(t),first=claim(journal,'raw-idempotency-key-secret');
  const clean=journal.complete(first,{...result,headers:{...result.headers,'PAYMENT-RESPONSE':'signed-secret','authorization':'Bearer SECRET','set-cookie':'SECRET'},payload:{...result.payload,input:'PRIVATE PROMPT',instructions:'PRIVATE INSTRUCTIONS',metadata:{api_key:'SECRET'},signed_receipt:{key_signature:'SECRET'},api_key:'SECRET'}});
  const content=readFileSync(file(journal,first),'utf8');
  for(const secret of ['raw-idempotency-key-secret','PRIVATE PROMPT','PRIVATE INSTRUCTIONS','signed-secret','SECRET',first.claimToken])assert.ok(!content.includes(secret));
  assert.deepEqual(clean,result);assert.equal(statSync(file(journal,first)).mode&0o777,0o600);assert.equal(statSync(journal.directory).mode&0o777,0o700);
});
test('oversized or credential-like result never clears the execution fence',t=>{
  const {journal}=setup(t,{maxResponseBytes:256}),first=claim(journal);
  assert.throws(()=>journal.complete(first,{...result,payload:{output_text:'x'.repeat(500)}}),e=>e.code==='cached_response_too_large');
  assert.throws(()=>journal.complete(first,{...result,payload:{output_text:'myco_sk_abcdefghijklmnopqrstuvwxyz'}}),e=>e.code==='unsafe_cached_response');
  assert.throws(()=>claim(journal),e=>e.code==='idempotency_outcome_unknown');
});
test('wrong owner cannot complete another process execution',t=>{
  const {journal}=setup(t),first=claim(journal);
  assert.throws(()=>journal.complete({...first,claimToken:'ff'.repeat(32)},result),e=>e.code==='idempotency_claim_mismatch');
  journal.complete(first,result);assert.equal(claim(journal).action,'replay');
});
test('partial file and stale update lock fail closed instead of expiring',t=>{
  const {journal}=setup(t),entry=createHash('sha256').update('partial').digest('hex');
  writeFileSync(join(journal.directory,entry+'.json'),'{',{mode:0o600});
  assert.throws(()=>claim(journal,'partial'),e=>e.code==='idempotency_state_unknown');
  const first=claim(journal);writeFileSync(file(journal,first)+'.update-lock','',{mode:0o600});
  assert.throws(()=>journal.complete(first,result),e=>e.code==='idempotency_update_locked');
  assert.throws(()=>claim(journal),e=>e.code==='idempotency_outcome_unknown');
});
test('symlink claim files cannot be followed',t=>{
  const {journal}=setup(t),first=claim(journal),target=join(journal.root,'target');writeFileSync(target,'unchanged');
  rmSync(file(journal,first));symlinkSync(target,file(journal,first));
  assert.throws(()=>claim(journal),e=>e.code==='idempotency_state_unknown');assert.equal(readFileSync(target,'utf8'),'unchanged');
});
test('eight independent processes have exactly one successful claim',async t=>{
  const {journal,config}=setup(t),module=new URL('../src/consumer-request-journal.mjs',import.meta.url).href;
  const program=`import {ConsumerRequestJournal} from ${JSON.stringify(module)}; const j=new ConsumerRequestJournal(JSON.parse(process.argv[1])); try { const c=j.claim({idempotencyKey:'parallel',payloadHash:${JSON.stringify(hash)}}); console.log(c.action); } catch(e) { console.log(e.code); }`;
  const outcomes=await Promise.all(Array.from({length:8},()=>new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--input-type=module','-e',program,JSON.stringify(config)],{stdio:['ignore','pipe','pipe']});let out='',err='';
    child.stdout.on('data',v=>out+=v);child.stderr.on('data',v=>err+=v);child.on('error',reject);
    child.on('exit',code=>code?reject(new Error(err)):resolve(out.trim()));
  })));
  assert.equal(outcomes.filter(v=>v==='execute').length,1);
  assert.ok(outcomes.every(v=>['execute','idempotency_outcome_unknown','idempotency_state_unknown'].includes(v)));
  assert.equal(readdirSync(journal.directory).filter(v=>v.endsWith('.json')).length,1);
});
