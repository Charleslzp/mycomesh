// What a Provider operator reads: live status, earnings with dates, errors that say what to do; and a
// dashboard that asks for the wallet password once per unlock.
import assert from "node:assert/strict";
import test from "node:test";
import { describeClaim, describeEarnings, describeLive, explain } from "../src/cli.mjs";
import { serveDashboard } from "../src/dashboard.mjs";

test("live status says whether the Provider is serving, and why not", () => {
  const now = Date.now() / 1000;
  const live = { container: "running", live: true, relays_connected: 2, relays_total: 2, restarts: 0, relays: [],
    jobs: { served_today: 12, refused_today: 1, failed_today: 0, last_served_at: now - 30 } };
  assert.match(describeLive(live), /live: linked to 2 of 2 Relays\ntoday: 12 answered, 1 refused, 0 failed; last answer 30 s ago/);
  const offline = { ...live, live: false, relays_connected: 0, jobs: null,
    relays: [{ relay: "1.2.3.4:10991", connected: false, last_error: "connection refused" }] };
  assert.match(describeLive(offline), /not linked to any Relay yet\n  1.2.3.4:10991: connection refused/);
  assert.match(describeLive({ container: "exited", exit_code: 1, relays: [] }), /stopped: the container is exited \(exit 1\)/);
  assert.match(describeLive({ container: "absent", relays: [] }), /not started/);
});

test("earnings say when the locked money becomes claimable", () => {
  const text = describeEarnings({ claimable: 1_500_000, in_escrow: 6_764, holdback: 19_991, eth_wei: "0",
    schedule: { holdback_matured: 7_511, escrow_next_release_at: 1_800_000_000, escrow_all_released_by: 1_800_080_000,
      holdback_maturing: [{ at: 1_800_100_000, amount: 1_248 }] },
    myco: { roles: { provider: { claimable_wei: "2000000000000000000", blocks_waiting: 14, next_unlock_at: 1_800_003_600 } } } });
  assert.match(text, /claimable now {6}1\.5 tUSDC \(\+ 0\.007511 tUSDC matured holdback, moved on claim\)/);
  assert.match(text, /in escrow .* next released after .* all by /);
  assert.match(text, /held back .* next 0\.001248 tUSDC matures /);
  assert.match(text, /MYCO claimable {5}2 MYCO {2}14 more hours unlock from /);
  assert.match(text, /too little to claim/);
  assert.equal(describeClaim({ claimed: 0, myco_claimed: {} }), "nothing to claim yet (see mycomesh-provider earnings for when)");
  assert.match(describeClaim({ claimed: 2_000_000, myco_claimed: { provider: 3 }, owner: "0xabc" }), /claimed 2 tUSDC and 3 hours of MYCO to 0xabc/);
});

test("errors say what to do", () => {
  assert.match(explain("Traceback ...\nSystemExit: no ETH for gas: the owner wallet 0x1 holds 0.00000 ETH"), /mycomesh-provider faucet/);
  assert.match(explain("ValueError: wrong key password"), /Wrong wallet password/);
  assert.match(explain("Cannot connect to the Docker daemon at unix:///var/run/docker.sock"), /Docker is not running/);
  assert.equal(explain("something else"), "something else");
});

test("the dashboard signs with the wallet password once per unlock", async (t) => {
  const passwords = [];
  const main = async (args, { stdout }) => {
    if (args[0] === "claim") {
      passwords.push(process.env.MYCOMESH_KEY_PASSWORD);
      if (process.env.MYCOMESH_KEY_PASSWORD !== "secret") throw new Error("wrong key password");
      stdout.write(JSON.stringify({ owner: "0xabc", claimed: "0", myco_claimed: {} }));
    } else stdout.write("{}");
  };
  const server = await serveDashboard(main, { port: 0 });
  t.after(() => server.close());
  const call = async (path, body) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`,
      body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {});
    return { status: response.status, body: await response.json() };
  };
  assert.match((await call("/api/claim", {})).body.error, /locked/);
  assert.match((await call("/api/claim", { password: "nope" })).body.error, /Wrong wallet password/);
  assert.equal((await call("/api/claim", { password: "secret" })).status, 200);
  assert.equal((await call("/api/claim", {})).status, 200); // unlocked: no password this time
  assert.deepEqual(passwords, ["nope", "secret", "secret"]);
  await call("/api/lock", {});
  assert.match((await call("/api/claim", {})).body.error, /locked/);
});
