// Kept-alive connections to Relays: reused, never cutting a slow answer, and safe when the Relay closed one.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { closeConnections, httpJson, httpNdjson, keepAlive } from "../src/consumer.mjs";

async function serve(handler) {
  const server = createServer(handler);
  const connections = [];
  server.on("connection", (socket) => connections.push(socket));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, connections, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}

const json = (res, value) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(value)); };

test("requests to one Relay reuse a connection", async (t) => {
  const relay = await serve((req, res) => json(res, { ok: true }));
  t.after(async () => { closeConnections(); await relay.close(); });
  for (let i = 0; i < 3; i += 1) assert.equal((await httpJson(`${relay.url}/providers`)).body.ok, true);
  assert.equal(relay.connections.length, 1);
});

test("an answer slower than the idle timeout is not cut", async (t) => {
  keepAlive.idleMs = 200;
  t.after(() => { keepAlive.idleMs = 30_000; });
  const relay = await serve((req, res) => {
    res.setHeader("content-type", "application/x-ndjson");
    res.write(`${JSON.stringify({ n: 1 })}\n`);
    setTimeout(() => res.end(`${JSON.stringify({ n: 2 })}\n`), 700);  // a model thinking
  });
  t.after(async () => { closeConnections(); await relay.close(); });
  const lines = [];
  const result = await httpNdjson(`${relay.url}/v11/requests`, { body: {}, onLine: (line) => lines.push(line.n) });
  assert.deepEqual([result.streamed, lines], [true, [1, 2]]);
});

test("a kept connection the Relay already closed is replaced, and the request goes through once", async (t) => {
  let served = 0;
  const relay = await serve((req, res) => {
    req.socket.count = (req.socket.count || 0) + 1;
    if (req.socket.count === 2) { req.socket.destroy(); return; }  // closed while idle: the request never arrived
    served += 1;
    json(res, { served });
  });
  t.after(async () => { closeConnections(); await relay.close(); });
  assert.equal((await httpJson(`${relay.url}/a`)).body.served, 1);
  assert.equal((await httpJson(`${relay.url}/v11/requests`, { method: "POST", body: { x: 1 } })).body.served, 2);
  assert.equal(relay.connections.length, 2);
});

test("a fresh connection that fails is reported, not retried", async (t) => {
  let attempts = 0;
  const relay = await serve((req) => { attempts += 1; req.socket.destroy(); });
  t.after(async () => { closeConnections(); await relay.close(); });
  await assert.rejects(httpJson(`${relay.url}/v11/requests`, { method: "POST", body: {} }));
  assert.equal(attempts, 1);
});

test("discovery is shared by a node's Consumers and refreshed behind the requests", async (t) => {
  const { Consumer } = await import("../src/consumer.mjs");
  t.mock.timers.enable({ apis: ["Date"], now: 1_000_000 });
  const network = { chain_id: 1, settlement: "0x" + "00".repeat(20), relays: [], rpc_urls: [] };
  let fetches = 0;
  let release;
  const fetchJson = async () => { fetches += 1; await new Promise((resolve) => { release = resolve; }); return { status: 200, body: { providers: [] } }; };
  const relay = { url: "https://relay.example", signer: "0x" + "11".repeat(20) };
  const node = new Consumer({ network, keyPrivate: "0x" + "22".repeat(32), maxFee: 1, fetchJson });
  const tenant = new Consumer({ network, keyPrivate: "0x" + "33".repeat(32), maxFee: 1, fetchJson });

  const first = node.providers(relay);  // nothing cached: waits for the Relay
  release(); await first;
  await tenant.providers(relay);         // fresh, and shared with the tenant
  assert.equal(fetches, 1);

  t.mock.timers.setTime(1_000_000 + 40_000);  // stale but usable: answered at once, refreshed behind
  await tenant.providers(relay);
  assert.equal(fetches, 2);
  await node.providers(relay);           // one refresh at a time
  assert.equal(fetches, 2);
  release(); await new Promise((resolve) => setImmediate(resolve));

  t.mock.timers.setTime(1_000_000 + 40_000 + 301_000);  // too old to use: waits again
  let done = false;
  const waiting = node.providers(relay).then(() => { done = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal([fetches, done].join(), "3,false");
  release(); await waiting;
});
