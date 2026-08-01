# Settlement V6 migration

Settlement V6 is a new contract deployment. It cannot replace the V5 address
in place, and an existing V5 Session remains a V5 Session until it is closed
and a new V6 Session is opened.

## What V6 changes

- A Session binds Provider, Pool, and the current Relay route.
- The Consumer can call `rotateSessionRelay(sessionId, relay, relaySigner)`.
- Every receipt and Relay attestation carries `relayEpoch`.
- Old epochs remain readable, so a receipt already in flight can settle after a
  Relay rotation.
- Provider, Relay, Gateway, local Consumer, browser ABI, and batch settlement
  paths all accept V6.
- `rewardsEnabled` remains disabled on a fresh deployment. Enable rewards only
  after the reward token's mint authority has been deliberately configured.

Relay rotation is an explicit Consumer wallet transaction. V6 preserves the
old route for in-flight receipts, but it does not discover a replacement Relay
or rewrite an already persisted Consumer plan automatically. After rotating,
the Consumer must refresh its session route/epoch before sending new requests.

## Deploy a V6 contract

Build the artifact first:

```sh
python3 scripts/compile-v6-artifact.py
```

Deploy with the same stablecoin, reward token, treasury, and governance policy
used by the testnet. Values below are placeholders and must be replaced with
your own addresses:

```sh
python3 -m gateway.client chain deploy-myco-v6-testnet \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --stablecoin 0xSTABLECOIN \
  --reward-token 0xREWARD_TOKEN \
  --treasury 0xTREASURY \
  --governance 0xGOVERNANCE \
  --deployment deployments/sepolia-myco-v6.json
```

The command writes the signed deployment manifest. Do not invent or hand-edit
the settlement address in a network config. Publish the generated manifest and
then create a V6 Provider network config that points to it and contains the
actual Relay payout and attestation addresses.

For a V6 testnet process, set these role selectors in `.env.deploy`:

```dotenv
MYCOMESH_SESSION_PROTOCOL_VERSION=6
MYCOMESH_SESSION_DEPLOYMENT=/app/deployments/sepolia-myco-v6.json
MYCOMESH_PROVIDER_SETTLEMENT_VERSION=6
MYCOMESH_PROVIDER_DEPLOYMENT=/app/deployments/sepolia-myco-v6.json
MYCOMESH_PROVIDER_NETWORK_CONFIG=/app/deployments/sepolia-provider-network-v6.json
MYCOMESH_BRIDGE_SETTLEMENT_VERSION=6
MYCOMESH_BRIDGE_DEPLOYMENT=/app/deployments/sepolia-myco-v6.json
```

The public app is configured for this V6 manifest with
`VITE_SESSION_PROTOCOL_VERSION=6`, `VITE_SESSION_SETTLEMENT_ADDRESS`, and
`VITE_SESSION_DEPLOYMENT_BLOCK`. V5 remains available as an explicit
compatibility override; do not mix a V5 manifest with V6 role selectors.

Payouts are pull-based:

```sh
python3 -m gateway.client chain v6-claim-payout \
  --deployment deployments/sepolia-myco-v6.json \
  --identity /path/to/provider-evm-identity.json \
  --rpc-url "$ETH_RPC_URL"
```

The same command works for a Relay or Pool identity. A settlement transaction
is still required to move a batch of signed receipts on-chain; the recipient
does not need to pre-fund the contract, only the submitting account needs gas.

## What V6 does not fix

V6 does not make an unavailable Relay reachable, repair DNS/proxy settings, or
cancel an old in-flight request. A stale V5 process/session can still produce
409 errors; stop the old Consumer process and create a fresh V6 Session after
switching manifests. A 502/503 caused by a refused Relay connection remains a
network availability problem, not a settlement-version problem.
