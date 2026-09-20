import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NativeConsumerState } from '../src/consumer-runtime.mjs';
import { parseDiscoveryConfig } from '../src/consumer-discovery.mjs';
import { parseArguments } from '../src/consumer.mjs';

async function fixture(t, changes = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'myco-manifest-relays-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'network.json');
  await writeFile(path, JSON.stringify({ protocol_version: 8, chain_id: 31337,
    settlement: `0x${'11'.repeat(20)}`, stablecoin: `0x${'22'.repeat(20)}`,
    relay: { public_url: 'https://relay-a.example' }, relay_fallbacks: [
      { public_url: 'https://relay-b.example/' }, { public_url: 'https://relay-b.example' },
    ], bridge_urls: ['https://discovery-only.example'], ...changes }));
  return { directory, path, state: (options = {}) => new NativeConsumerState({ env: {}, dataDir: directory,
    historyDir: join(directory, 'history'), networkConfig: path, ...options }) };
}

test('Consumer reads trusted primary/backup Relays automatically, deduplicates and excludes discovery-only Bridges', async (t) => {
  const f = await fixture(t);
  assert.deepEqual(f.state().relayUrls, ['https://relay-a.example', 'https://relay-b.example']);
});
test('explicit operator Relay override retains priority over network manifest', async (t) => {
  const f = await fixture(t);
  assert.deepEqual(f.state({ relayUrls: 'https://override.example' }).relayUrls, ['https://override.example']);
  assert.deepEqual(f.state({ env: { MYCOMESH_V8_RELAY_URLS: 'https://env.example' } }).relayUrls, ['https://env.example']);
});

test('controlled-test manifest can carry a relative private CA and exposes verified TLS mode', async (t) => {
  const f = await fixture(t, { tls_ca_file: 'ca.crt' });
  await writeFile(join(f.directory, 'ca.crt'), '-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n');
  const state = f.state({ allowControlledTest: true });
  assert.equal(state.tlsCaFile, join(f.directory, 'ca.crt'));
  assert.equal(state.healthPayload().relay_tls.mode, 'controlled_test_ca');
  assert.equal(state.healthPayload().relay_tls.configured, true);
  assert.throws(() => f.state(), /custom Relay TLS CA is only allowed/);
});

test('controlled-test manifest fails closed when its private CA is absent or malformed', async (t) => {
  const f = await fixture(t, { tls_ca_file: 'missing-ca.crt' });
  assert.throws(() => f.state({ allowControlledTest: true }), /TLS CA file is missing/);
  await writeFile(join(f.directory, 'missing-ca.crt'), 'not a certificate');
  assert.throws(() => f.state({ allowControlledTest: true }), /does not contain a PEM certificate/);
});

test('explicit CA environment cannot silently widen trust outside controlled-test mode', async (t) => {
  const f = await fixture(t);
  await writeFile(join(f.directory, 'ca.crt'), '-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n');
  assert.throws(() => f.state({ env: { MYCOMESH_CONSUMER_CA_FILE: join(f.directory, 'ca.crt') } }), /custom Relay TLS CA is only allowed/);
});
test('launcher default does not accidentally override manifest Relay discovery', () => {
  const selected = parseArguments(['--network-config', '/tmp/public-network.json'], {});
  assert.equal(selected.networkConfig, '/tmp/public-network.json');
  assert.equal(selected.relayUrlsExplicit, false);
  assert.equal(parseArguments(['--relay', 'https://override.example'], {}).relayUrlsExplicit, true);
});

test('V10 discovery policy accepts the fixed-budget protocol version', () => {
  const config = parseDiscoveryConfig({
    network_id: 'mycomesh-v10-fixed-budget-controlled-test',
    channel_id: 'codex',
    network_profile: 'testnet',
    bridge_urls: ['https://relay.example'],
    relay_discovery: { authorities: [`0x${'11'.repeat(20)}`], threshold: 1 },
  }, {
    chain_id: 11155111,
    settlement_contract: `0x${'22'.repeat(20)}`,
    protocol_version: 10,
  });
  assert.equal(config.protocol_version, 10);
});
for (const entry of [null, {}, { public_url: 'http://remote.example' },
  { public_url: 'https://user:pass@relay.example' }, { public_url: 'https://relay.example/?secret=value' }]) {
  test(`invalid configured fallback fails closed instead of using default: ${JSON.stringify(entry)}`, async (t) => {
    const f = await fixture(t, { relay_fallbacks: [entry] });
    assert.throws(() => f.state(), /Invalid configured settlement network/);
  });
}
