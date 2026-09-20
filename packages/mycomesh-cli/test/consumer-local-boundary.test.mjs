import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NativeConsumerState, createConsumerServer } from '../src/consumer-runtime.mjs';

test('unlocked local credentials remain token, loopback Host and same-origin protected', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'myco-local-boundary-'));
  const state = new NativeConsumerState({ dataDir: directory, historyDir: join(directory, 'history'), env: {} });
  state.paymentUnlocked = true;
  state.managementToken = 'fixture-management-only';
  const edge = createConsumerServer(state, { port: 0 });
  const address = await edge.listen();
  t.after(async () => { await edge.close(); await rm(directory, { recursive: true, force: true }); });
  const read = (path, headers = {}) => new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: address.port, path, headers }, (res) => {
      let body = ''; res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.on('error', reject); req.end();
  });
  const authorization = `Bearer ${state.managementToken}`;
  assert.equal((await read('/credentials')).status, 401);
  assert.equal((await read('/credentials', { authorization: `Bearer ${state.paymentKey}` })).status, 401);
  for (const headers of [
    { host: `evil.example:${address.port}` }, { origin: 'https://evil.example' },
    { origin: 'null' }, { 'sec-fetch-site': 'cross-site' },
  ]) {
    const rejected = await read('/credentials', { authorization, ...headers });
    assert.equal(rejected.status, 403);
    assert.ok(!rejected.body.includes(state.paymentKey));
    assert.equal((await read('/v1/mycomesh/local/dashboard', { authorization, ...headers })).status, 403);
  }
  const good = await read('/credentials', { authorization, origin: `http://127.0.0.1:${address.port}` });
  assert.equal(good.status, 200);
  assert.ok(good.body.includes(state.paymentKey));
  assert.equal(good.headers['cache-control'], 'no-store');
  const page = await read('/');
  assert.equal(page.headers['x-frame-options'], 'DENY');
  assert.match(page.body, /id="setupAccess"/);
  assert.doesNotMatch(page.body, /Consumer V8/);
});
