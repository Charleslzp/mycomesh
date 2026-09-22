import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { secp256k1 } from '@noble/curves/secp256k1';
import { CHANNEL_FIELDS, capacityChannelId, decodeCapacityChannel, buildReservedAuthorization, verifyReservedReceipt, reservedSettlementKey } from '../src/consumer-reserved.mjs';
import { NativeConsumerState, paymentKeyAddress, createReceiptStatusQuery, RESPONSE_PROOF_SCHEMA, walletMessageDigest } from '../src/consumer-runtime.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0'), a=n=>'0x'+n.toString(16).padStart(40,'0');
const ROOT=new URL('../../../',import.meta.url).pathname;
const TEST_PYTHON=process.env.MYCOMESH_TEST_PYTHON||'python3';
const key=h(1), contract=a(50), provider=paymentKeyAddress(h(2)), relay=paymentKeyAddress(h(3));
const word=v=>(typeof v==='string'&&v.startsWith('0x')?v.slice(2):BigInt(v).toString(16)).padStart(64,'0');
const abi=values=>'0x'+values.map(word).join('');
function python(program,payload) {
  const r=spawnSync(TEST_PYTHON,['-B','-c',program],{cwd:ROOT,input:JSON.stringify(payload),encoding:'utf8',timeout:15000});
  assert.equal(r.status,0,r.stderr); return JSON.parse(r.stdout);
}
function channel() {
  const now=Math.floor(Date.now()/1000);
  const c={consumer_owner:a(80),consumer_key:paymentKeyAddress(key),provider_owner:a(81),provider_signer:provider,relay:a(82),relay_signer:relay,pool:a(0),channel:h(6),pricing_version:1,pricing_hash:h(7),capacity:1000000,max_fee_per_request:100000,valid_from:now-600,admit_until:now+18000,claim_until:now+27000,consumer_nonce:0,provider_nonce:0,permit_deadline:now-500};
  return {...c,channel_id:capacityChannelId(c,31337,contract),settled_max_fee:0,credit_remaining:1000000,stake_remaining:1000000,closed:false};
}
function auth(c) { const now=Math.floor(Date.now()/1000);return buildReservedAuthorization({paymentKey:key,chainId:31337,settlementContract:contract,channelId:c.channel_id,requestId:h(1),requestHash:h(2),maxFee:100000,issuedAt:now-300,executeBy:now+360,deadline:now+9000}); }
function signed(c,payment) {
  return python(`import json,sys
from gateway import chain_v10 as v
from gateway.relay_integrity import provider_response_hash,provider_response_proof
p=json.load(sys.stdin); c=p['channel']; a=p['payment']; v.validate_channel_authorization(c,a)
body={'peer':{'peer_id':'fixture','public_key':'fixture-key'},'request_id':a['authorization']['request_id'],'endpoint':'responses','model':'fixture-model','output_text':'fixed-budget-ok','usage':{'input_tokens':12,'output_tokens':7},'raw':{'id':'resp_fixture','object':'response','model':'fixture-model','output':[],'output_text':'fixed-budget-ok','usage':{'input_tokens':12,'output_tokens':7}}}
d=v.build_relay_dispatch(authorization_payload=a,relay_private_key='${h(3)}')
r=v.build_provider_receipt(provider_private_key='${h(2)}',dispatch_payload=d,response_hash=provider_response_hash(body),input_tokens=12,output_tokens=7,actual_fee=2000,channel=c)
print(json.dumps({'signed':r,'proof':provider_response_proof(body),'channel_id':v.channel_id_for(c,chain_id=31337,verifying_contract='${contract}'),'settlement_key':v.settlement_key_for(c['channel_id'],a['authorization']['request_id'])}))`,{channel:c,payment});
}
test('Node authorization and channel IDs agree with Python; full Provider receipt verified',()=>{
  const c=channel(),p=auth(c),r=signed(c,p);
  assert.equal(r.channel_id,c.channel_id);
  assert.equal(r.settlement_key,reservedSettlementKey(c.channel_id,h(1)));
  assert.equal(verifyReservedReceipt(r.signed,{channel:c}).receipt.provider,a(81));
  assert.equal(verifyReservedReceipt(r.signed,{channel:c}).receipt.actual_fee,2000);
  assert.throws(()=>verifyReservedReceipt(r.signed),/channel/);
  for (const mutate of [v=>v.receipt.actual_fee++,v=>v.relay_signature=v.provider_signature,v=>v.chain_id++,v=>v.dispatch.authorization.authorization.request_hash=h(99),v=>v.provider_signer=a(99)]) {
    const bad=structuredClone(r.signed);mutate(bad);assert.throws(()=>verifyReservedReceipt(bad,{channel:c}));
  }
  assert.throws(()=>verifyReservedReceipt(r.signed,{channel:{...c,provider_signer:a(99)}}));
});
test('channel ABI canonical bounds and domain binding',()=>{
  const c=channel(),encoded=abi([...CHANNEL_FIELDS.map(([n])=>c[n]),0,1000000,1000000,0]);
  assert.equal(decodeCapacityChannel(encoded,c.channel_id,31337,contract).provider_signer,provider);
  assert.throws(()=>decodeCapacityChannel(encoded+'00',c.channel_id,31337,contract));
  assert.throws(()=>decodeCapacityChannel(encoded,c.channel_id,1,contract));
  assert.throws(()=>decodeCapacityChannel(encoded.slice(0,-1)+'2',c.channel_id,31337,contract));
  assert.notEqual(reservedSettlementKey(c.channel_id,h(1)),reservedSettlementKey(h(55),h(1)));
});
function manifest(c) {
  return {protocol_version:10,eip712_name:'MycoMesh Settlement',eip712_version:'10',reservation_mode:'provider_bound_channel',chain_domain:'10',max_authorization_ttl_seconds:10800,authorization_deadline_seconds:9000,max_channel_duration_seconds:2592000,
    chain_id:31337,deployer:a(1),stablecoin:a(2),settlement:contract,treasury:a(4),governance:a(5),channel:'codex',channel_hash:h(6),pricing_version:1,pricing_hash:h(7),reward_token:a(0),network_id:'fixture-controlled-test',channel_id:'codex',backend_policy:'fixture',committee_mode:'controlled_test',independence_attested:false,
    adjudicators:[a(10),a(11),a(12)],adjudication_threshold:2,adjudicator_operators:{[a(10)]:'test-operator',[a(11)]:'test-operator',[a(12)]:'test-operator'},
    policy:{dispute_window:60,arbitration_timeout:120,consumer_withdrawal_delay:60,reporter_bond:100,slash_bps:5000,slash_cap:10000,reporter_bounty_bps:2000,stable_bounty_cap:1000,token_reward:0,token_reward_cap:0,token_minimum_exposure:0,token_minimum_penalty:0,bond_penalty_recipient:a(9)},capacity_channel_ids:[c.channel_id]};
}
async function runtime(t, {respond, receiptStatus = "pending"} = {}) {
  const c=channel(),dir=mkdtempSync(join(tmpdir(),'mycomesh-v10-node-'));
  const path=join(dir,'network.json');writeFileSync(path,JSON.stringify(manifest(c)));
  assert.throws(()=>new NativeConsumerState({dataDir:join(dir,'denied'),networkConfig:path,env:{MYCOMESH_V8_PAYMENT_KEY:key}}),/controlled-test/);
  let posts=0;
  const server=createServer(async(req,res)=>{
    let raw='';for await (const chunk of req) raw+=chunk;
    const payment=JSON.parse(Buffer.from(req.headers['payment-signature'],'base64url'));
    assert.equal(JSON.parse(raw).metadata.mycomesh_provider_signer,provider);posts++;
    if (respond) return respond(req,res,payment);
    const r=signed(c,payment);
    res.setHeader('PAYMENT-RESPONSE',Buffer.from(JSON.stringify({accepted:true,status:receiptStatus,settlement_key:r.settlement_key,signed_receipt:r.signed})).toString('base64url'));
    res.setHeader('content-type','application/json');res.end(JSON.stringify(r.proof));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const url='http://127.0.0.1:'+server.address().port;
  const state=new NativeConsumerState({dataDir:join(dir,'data'),historyDir:join(dir,'shared'),networkConfig:path,allowControlledTest:true,relayUrls:url,env:{MYCOMESH_V8_PAYMENT_KEY:key},timeoutMs:5000});
  state.unlockedWallet=c.consumer_owner;state.managementToken='fixture';state.paymentUnlocked=true;
  state.capacityChannels=async()=>[c];
  state.relayHealth=async()=>({ok:true,v10:{enabled:true,providers:1,chain_id:31337,settlement_contract:contract,relay_payment_address:c.relay,relay_signer_address:relay,channel_hash:c.channel,pricing_version:1,pricing_hash:c.pricing_hash,models:['fixture-model'],response_proof:RESPONSE_PROOF_SCHEMA,reservation_mode:'provider_bound_channel',scheduler:{session_affinity:true},provider_signers:[provider],provider_routes:[{provider_signer:provider,provider:c.provider_owner,models:['fixture-model']}]}});
  t.after(async()=>{await new Promise(resolve=>{server.closeAllConnections();server.close(resolve);});rmSync(dir,{recursive:true,force:true});});
  return {state,c,posts:()=>posts,url};
}
test('V10 native Consumer full HTTP path pins Provider, verifies content and journals channel scope',async t=>{
  const f=await runtime(t);
  const r=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'});
  assert.equal(r.status,200,JSON.stringify(r.payload));assert.equal(r.payload.output_text,'fixed-budget-ok');
  assert.equal(r.headers['x-mycomesh-content-verification'],'provider-signed');assert.equal(f.posts(),1);
  const rows=f.state.history(0);assert.equal(rows.length,1);assert.equal(rows[0].capacity_channel_id,f.c.channel_id);assert.equal(rows[0].max_fee_units,100000);assert.equal(rows[0].actual_fee_units,2000);
  f.state.historyLedger.append({...rows[0],capacity_channel_id:h(88)});assert.equal(f.state.history(0).length,2);
});
test('fixed budget refuses exhausted, early, late and unavailable Provider without execution',async t=>{
  const f=await runtime(t);
  for (const changes of [{settled_max_fee:1000000},{valid_from:Math.floor(Date.now()/1000)+1000},{claim_until:Math.floor(Date.now()/1000)+7200},{provider_signer:a(99)}]) {
    f.state.capacityChannels=async()=>[{...f.c,...changes}];
    const r=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'});
    assert.equal(r.status,402);assert.equal(f.posts(),0);
    assert.equal(r.payload.error.execution_status,'not_dispatched');
    assert.equal(r.payload.error.code,changes.valid_from?'budget_not_started':'budget_unavailable');
  }
});
test('signed status query is channel scoped v2',()=>{
  const q=createReceiptStatusQuery(key,{chainId:31337,contract,requestId:h(1),channelId:h(2),issuedAt:100});
  assert.equal(q.channel_id,h(2));
  assert.notEqual(q.signature,createReceiptStatusQuery(key,{chainId:31337,contract,requestId:h(1),channelId:h(3),issuedAt:100}).signature);
});

test('V10 unsigned not_dispatched label cannot release budget or trigger a second POST',async t=>{
  const f=await runtime(t,{respond:(_req,res)=>{res.statusCode=503;res.setHeader('content-type','application/json');res.end(JSON.stringify({error:{message:'not dispatched',execution_status:'not_dispatched'}}));}});
  f.state.relayUrls=[f.url,f.url+'/second-route'];
  const result=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'});
  assert.equal(result.status,422);assert.equal(result.headers['x-should-retry'],'false');
  assert.equal(result.payload.error.retryable,false);assert.equal(result.payload.error.execution_status,'unknown');assert.equal(f.posts(),1);
  const row=f.state.history(0)[0];assert.notEqual(row.status,'not_dispatched');assert.equal(row.max_fee_units,100000);
});
test('V10 lost response remains unknown with one POST and permanent local maximum',async t=>{
  const f=await runtime(t,{respond:(req)=>req.socket.destroy()});
  f.state.relayUrls=[f.url,f.url+'/second-route'];
  const result=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'});
  assert.equal(result.status,422);assert.equal(result.headers['x-should-retry'],'false');
  assert.equal(result.payload.error.retryable,false);assert.equal(result.payload.error.execution_status,'unknown');assert.equal(f.posts(),1);
  assert.equal(f.state.history(0)[0].status,'outcome_unknown');
  assert.equal(f.state.history(0)[0].max_fee_units,100000);
});

test('V10 transport diagnostics expose only known codes and never replay an unknown request',async t=>{
  const f=await runtime(t);
  for(const code of ['UND_ERR_CONNECT_TIMEOUT','Bearer private-token']) {
    let calls=0;
    const mocked=t.mock.method(globalThis,'fetch',async()=>{
      calls++;
      throw new TypeError('private request details',{cause:Object.assign(new Error('private proxy credentials'),{code})});
    });
    const result=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'});
    mocked.mock.restore();
    assert.equal(calls,1);
    assert.equal(result.status,422);
    assert.equal(result.payload.error.execution_status,'unknown');
    assert.equal(result.payload.error.retryable,false);
    assert.equal(result.payload.error.transport_code,code==='UND_ERR_CONNECT_TIMEOUT'?code:undefined);
    assert.ok(!JSON.stringify(result.payload).includes('private'));
    f.state.relayFailures.clear();
  }
  assert.equal(f.posts(),0);
});
test('unsigned Relay released label cannot present a signed receipt as paid',async t=>{
  const f=await runtime(t,{receiptStatus:'released'});
  const result=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'});
  assert.equal(result.status,200);assert.equal(f.state.history(0)[0].status,'pending');
});
test('authorization rejects zero fees, more than three hours, and invalid admission deadlines',()=>{
  const c=channel(),now=Math.floor(Date.now()/1000);
  const params={paymentKey:key,chainId:31337,settlementContract:contract,channelId:c.channel_id,requestId:h(1),requestHash:h(2),maxFee:100000,issuedAt:now,executeBy:now+60,deadline:now+9000};
  for(const change of [{maxFee:0},{deadline:now+10801},{executeBy:now+9000},{issuedAt:now+61,executeBy:now+60}]) {
    assert.throws(()=>buildReservedAuthorization({...params,...change}),/time\/fee/);
  }
});
test('revoking a key does not erase its already owner-approved fixed channel at wallet login',async t=>{
  const f=await runtime(t),privateKey=Buffer.from(h(80).slice(2),'hex'),wallet=paymentKeyAddress(h(80));
  f.c.consumer_owner=wallet;f.c.channel_id=capacityChannelId(f.c,31337,contract);
  f.state.keyGrant=async()=>({owner:wallet,active:false,max_per_request:100000,valid_until:0});
  const challenge=f.state.createWalletChallenge(wallet),signature=secp256k1.sign(walletMessageDigest(challenge.message),privateKey,{lowS:true,prehash:false});
  const raw='0x'+Buffer.concat([Buffer.from(signature.toCompactRawBytes()),Buffer.from([27+signature.recovery])]).toString('hex');
  const result=await f.state.authenticateWallet({wallet,signature:raw});
  assert.equal(result.grant.active,false);assert.equal(result.auth.key_ready,true);
});
test('owner budget view retains channels allocated to a previous payment key',async t=>{
  const f=await runtime(t),old={...f.c,consumer_key:paymentKeyAddress(h(90))};old.channel_id=capacityChannelId(old,31337,contract);
  f.state.capacityChannels=async()=>[f.c,old];f.state.historySyncAt=Date.now();
  f.state.keyGrant=async()=>({owner:f.c.consumer_owner,active:true,max_per_request:100000,valid_until:0});
  f.state.accountBalance=async()=> '0';f.state.rpcValue=async()=> '0x0';
  const result=await f.state.dashboardPayload(true);
  assert.equal(result.capacity_channels.length,2);assert.equal(result.budget_locked_units,'2000000');
  assert.equal(result.capacity_channels[1].budget.reason,'previous_key');
  assert.equal(result.budget_available_units,'1000000');
});

test('budget panel and dispatch reject the same unusable channel without executing',async t=>{
  const f=await runtime(t),now=Math.floor(Date.now()/1000);
  f.state.historySyncAt=Date.now();
  f.state.keyGrant=async()=>({owner:f.c.consumer_owner,active:true,max_per_request:100000,valid_until:0});
  f.state.accountBalance=async()=> '0';f.state.rpcValue=async()=> '0x0';
  const cases=[
    ['previous_key',{consumer_key:paymentKeyAddress(h(90))}],
    ['capacity_exhausted',{settled_max_fee:1000000}],
    ['request_limit',{max_fee_per_request:99999}],
    ['credit_insufficient',{credit_remaining:99999}],
    ['stake_insufficient',{stake_remaining:99999}],
    ['admission_window_short',{admit_until:now+30}],
    ['claim_window_short',{claim_until:now+8990}],
    ['not_started',{valid_from:now+1000}],
  ];
  for(const [reason,changes] of cases){
    await t.test(reason,async()=>{
      f.state.capacityChannels=async()=>[{...f.c,...changes}];
      const dashboard=await f.state.dashboardPayload(true);
      assert.equal(dashboard.capacity_channels[0].budget.reason,reason);
      assert.equal(dashboard.budget_available_units,'0');
      assert.equal(dashboard.inference_ready,false);
      const response=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'});
      assert.equal(response.status,402);assert.equal(response.payload.error.execution_status,'not_dispatched');
      assert.equal(f.posts(),0);
    });
  }
});

test('budget estimate retains unknown MAX and uses the stricter local or settled total',async t=>{
  const f=await runtime(t),now=Math.floor(Date.now()/1000);
  const rows=[{capacity_channel_id:f.c.channel_id,status:'unknown',max_fee_units:100000},
    {capacity_channel_id:f.c.channel_id,status:'not_dispatched',max_fee_units:900000}];
  let budget=f.state.capacityBudget(f.c,rows,now);
  assert.equal(budget.remaining_units,'900000');assert.equal(budget.estimated_requests,'9');
  budget=f.state.capacityBudget({...f.c,settled_max_fee:300000},rows,now);
  assert.equal(budget.remaining_units,'700000');assert.equal(budget.estimated_requests,'7');
  budget=f.state.capacityBudget({...f.c,stake_remaining:250000},rows,now);
  assert.equal(budget.remaining_units,'250000');assert.equal(budget.estimated_requests,'2');
  rows[0].max_fee_units=1000000;
  assert.equal(f.state.capacityBudget(f.c,rows,now).reason,'capacity_exhausted');
  const boundary={...f.c,admit_until:now+Math.ceil(f.state.timeoutMs/1000)+60};
  assert.equal(f.state.capacityBudget(boundary,[],now).ready,true);
  assert.equal(f.state.capacityBudget(boundary,[],now+1).reason,'admission_window_short');
});

test('V10 Idempotency-Key replays the protected success once and rejects changed content',async t=>{
  const f=await runtime(t),body={model:'fixture-model',input:'test'},headers={'Idempotency-Key':'one-logical-request'};
  const first=await f.state.relayInference('/v1/responses',body,headers);
  assert.equal(first.status,200,JSON.stringify(first.payload));
  assert.equal(first.headers['PAYMENT-RESPONSE'],undefined);
  assert.equal(first.headers['payment-response'],undefined);
  const repeated=await f.state.relayInference('/v1/responses',structuredClone(body),{...headers,'x-stainless-retry-count':'1'});
  assert.deepEqual(repeated,first);assert.equal(f.posts(),1);assert.equal(f.state.history(0).length,1);
  assert.equal(first.headers['x-mycomesh-request-id'],f.state.history(0)[0].request_id);
  const changed=await f.state.relayInference('/v1/responses',{...body,input:'different'},headers);
  assert.equal(changed.status,422);assert.equal(changed.payload.error.code,'idempotency_conflict');
  assert.equal(changed.payload.error.retryable,false);assert.equal(changed.headers['x-should-retry'],'false');
  assert.equal(f.posts(),1);
});

test('V10 unknown Idempotency-Key stays fenced across repeated client requests',async t=>{
  const f=await runtime(t,{respond:(req)=>req.socket.destroy()}),body={model:'fixture-model',input:'test'},headers={'idempotency-key':'unknown-logical-request'};
  const first=await f.state.relayInference('/v1/responses',body,headers);
  assert.equal(first.status,422);assert.equal(first.payload.error.execution_status,'unknown');
  const repeated=await f.state.relayInference('/v1/responses',structuredClone(body),{...headers,'x-stainless-retry-count':'1'});
  assert.equal(repeated.status,422);assert.equal(repeated.payload.error.code,'idempotency_outcome_unknown');
  assert.equal(repeated.headers['x-mycomesh-request-id'],first.headers['x-mycomesh-request-id']);
  assert.equal(repeated.payload.error.retryable,false);assert.equal(repeated.headers['x-should-retry'],'false');
  assert.equal(f.posts(),1);assert.equal(f.state.history(0).length,1);
  assert.equal(f.state.history(0)[0].max_fee_units,100000);
});

test('V10 SDK retry without a stable Idempotency-Key never dispatches',async t=>{
  const f=await runtime(t);
  const result=await f.state.relayInference('/v1/responses',{model:'fixture-model',input:'test'},{'x-stainless-retry-count':'1'});
  assert.equal(result.status,422);assert.equal(result.payload.error.code,'idempotency_key_required');
  assert.equal(result.payload.error.retryable,false);assert.equal(result.headers['x-should-retry'],'false');
  assert.equal(f.posts(),0);assert.equal(f.state.history(0).length,0);
});
