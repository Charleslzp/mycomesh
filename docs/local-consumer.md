# Local Consumer Docker

The `consumer` Compose profile starts the complete Direct Web Consumer plus a
localhost-only OpenAI-compatible edge. Open
`http://127.0.0.1:8110/app/playground` and connect an injected wallet to run the
browser-owned Bridge/Relay/Settlement V3 path. It does not depend on the public
MycoMesh Gateway. The browser stores its own non-extractable Ed25519 signing key
in IndexedDB for the local origin; `/app/access` shows only its public key and
Peer ID. On first start the separate headless API edge creates two volume-local
credentials with mode `0600`:

- an API key used only by clients on this machine;
- an Ed25519 Consumer request identity.

Start it with:

```bash
make consumer-up
```

Then open `http://127.0.0.1:8110/app/playground`. Operational and headless API
commands are available separately:

```bash
make consumer-health
make consumer-credentials
```

The credentials command prints the local base URL, API key, model, and public
Consumer identity. The default URL is `http://127.0.0.1:8110/v1`. The key is not
written to container logs and is not returned by the HTTP status endpoint.

Inspect initialization state with either interface:

```bash
docker compose --profile consumer exec consumer \
  python -m gateway.local_consumer status

curl -H "Authorization: Bearer $LOCAL_MYCOMESH_API_KEY" \
  http://127.0.0.1:8110/v1/mycomesh/local/status
```

Register only the public address of an external Consumer wallet:

```bash
docker compose --profile consumer exec consumer \
  python -m gateway.local_consumer init-wallet \
  --address 0xYOUR_CONSUMER_WALLET
```

The browser app uses the wallet directly and never sends an EVM private key to
the container. Its Direct inference path is independent of the readiness state
of the headless API. The headless OpenAI-compatible API deliberately does not
accept an EVM private key through HTTP or store one in the Consumer volume. Until a
local external signer and the V3 reservation executor are connected,
`/v1/responses` and `/v1/chat/completions` return a
structured `503 consumer_not_ready` error. `/health` remains healthy so the
container can serve the browser app while headless initialization is incomplete;
`/ready` remains `503` for that headless interface.

The network topology, model, Bridge URL, Relay URL, channel, and Settlement V3
binding come from `deployments/sepolia-provider-network.json`. There is no public
Gateway URL in the Consumer service configuration.
