// Session affinity: a conversation's turns go back to the Provider holding its upstream prompt cache.
import assert from "node:assert/strict";
import test from "node:test";
import { Consumer, sessionKey } from "../src/consumer.mjs";
import { fromAnthropic } from "../src/dialects.mjs";

const network = { chain_id: 1, settlement: "0x" + "00".repeat(20), relays: [], rpc_urls: [] };
const descriptor = (n) => ({ provider_signer: `0x${String(n).repeat(40)}`, capacity: 2, prices: { input_per_1k: 7, output_per_1k: 628 } });

test("every turn of a conversation has one session key; other conversations differ", () => {
  const system = { role: "system", content: "Be terse." };
  const first = [system, { role: "user", content: "Plan a trip to Kyoto." }];
  const second = [...first, { role: "assistant", content: "Day 1: ..." }, { role: "user", content: "Make it cheaper." }];
  const key = (content, extra = {}) => sessionKey({ endpoint: "chat", model: "gpt-5.5", content, ...extra });
  assert.equal(key(first), key(second));
  assert.notEqual(key(first), key([system, { role: "user", content: "Plan a trip to Osaka." }]));
  assert.notEqual(key(first), sessionKey({ endpoint: "chat", model: "claude-sonnet-4-6", content: first }));
  // A Responses turn sent as a string continues as a list.
  assert.equal(sessionKey({ endpoint: "responses", model: "gpt-5.5", content: "hi" }),
    sessionKey({ endpoint: "responses", model: "gpt-5.5", content: [{ role: "user", content: "hi" }, { role: "assistant", content: "hello" }, { role: "user", content: "more" }] }));
  // The client's own session id wins over the opening.
  assert.equal(key(first, { session: "abc" }), key([{ role: "user", content: "anything" }], { session: "abc" }));
  assert.equal(key(first, { options: { prompt_cache_key: "k1" } }), key(second, { options: { prompt_cache_key: "k1" } }));
  assert.equal(fromAnthropic({ model: "m", messages: [{ role: "user", content: "x" }], metadata: { user_id: "user_1_session_9" } }).session,
    "user_1_session_9");
});

test("the conversation's Provider goes first, but never ahead of what the chain proves or of a full Provider", () => {
  const consumer = new Consumer({ network, keyPrivate: "0x" + "22".repeat(32), maxFee: 1 });
  const [a, b, c] = [descriptor(1), descriptor(2), descriptor(3)];
  for (let i = 0; i < 20; i += 1) assert.equal(consumer.rank([a, b, c], {}, b.provider_signer)[0], b);
  const now = Math.floor(Date.now() / 1000);
  const fraud = { [b.provider_signer]: { last_fraud_at: now, probes_passed: 0, probes_failed_verified: 0, counted_volume: "0" } };
  assert.notEqual(consumer.rank([a, b, c], fraud, b.provider_signer)[0], b);
  consumer.inFlight.set(b.provider_signer, 2); // this Consumer already fills it
  assert.notEqual(consumer.rank([a, b, c], {}, b.provider_signer)[0], b);
});

test("sessions are remembered for an hour, least recently used dropped first", (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 1_000_000 });
  const consumer = new Consumer({ network, keyPrivate: "0x" + "33".repeat(32), maxFee: 1 });
  consumer.remember("s1", "0xaa");
  assert.equal(consumer.stickyProvider("s1"), "0xaa");
  t.mock.timers.setTime(1_000_000 + 3_600_001);
  assert.equal(consumer.stickyProvider("s1"), undefined);
  for (let i = 0; i < 10_001; i += 1) consumer.remember(`k${i}`, "0xbb");
  assert.equal(consumer.sessions.size, 10_000);
  assert.equal(consumer.stickyProvider("k0"), undefined);
  assert.equal(consumer.stickyProvider("k10000"), "0xbb");
});
