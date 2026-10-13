// The local console asks for the wallet password only to sign, and once per unlock.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { consoleRoutes, UNLOCK_MS } from "../src/console.mjs";
import { createWallet } from "../src/wallet.mjs";

test("signing actions need the password once per unlock; reads and locking need none", async (t) => {
  const dataDir = mkdtempSync(join(tmpdir(), "console-"));
  await createWallet(dataDir, "correct horse");
  const network = { network_id: "test", chain_id: 1, settlement: "0x" + "00".repeat(20), relays: [], rpc_urls: ["http://127.0.0.1:9"] };
  const routes = consoleRoutes({ consumer: { network, key: "0x" + "11".repeat(20), maxFee: 1 }, dataDir });
  const sign = () => routes["POST /api/tenants/revoke"]({ name: "nobody" }); // signs with the owner wallet first

  await assert.rejects(sign(), (error) => error.code === "locked" && error.status === 401);
  await assert.rejects(routes["POST /api/unlock"]({ password: "wrong" }), /wrong wallet password/);
  const { unlocked_until: until } = await routes["POST /api/unlock"]({ password: "correct horse" });
  assert.ok(until > Date.now() && until <= Date.now() + UNLOCK_MS);
  await assert.rejects(sign(), (error) => error.code !== "locked"); // past the wallet: fails later, on the chain
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() + UNLOCK_MS + 1 });
  await assert.rejects(sign(), (error) => error.code === "locked"); // the unlock ran out
  t.mock.timers.reset();
  await routes["POST /api/unlock"]({ password: "correct horse" });
  await routes["POST /api/lock"]({});
  await assert.rejects(sign(), (error) => error.code === "locked");
});

test("amounts are base units as before, or tUSDC when written so", async () => {
  const { parseAmount, tusdc } = await import("../src/cli.mjs");
  assert.equal(parseAmount("20000000", "x"), 20_000_000n);
  assert.equal(parseAmount("20tUSDC", "x"), 20_000_000n);
  assert.equal(parseAmount("20 usdc", "x"), 20_000_000n);
  assert.equal(parseAmount("0.5", "x"), 500_000n);
  assert.equal(parseAmount("1.000001TUSDC", "x"), 1_000_001n);
  assert.throws(() => parseAmount("20 dollars", "x"), /tUSDC/);
  assert.throws(() => parseAmount("0.0000001", "x"), /tUSDC/);
  assert.equal(tusdc(20_500_000n), "20.5 tUSDC");
});
