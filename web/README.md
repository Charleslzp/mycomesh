# MycoMesh Web

This package serves both public surfaces:

- `mycomesh.xyz` is the project homepage and live network view.
- `app.mycomesh.xyz` is the consumer dApp. `/app` is also supported on the apex domain.

The browser never receives provider administration credentials. Consumer API
secrets are generated in the browser, only their SHA-256 hashes are registered,
and the active secret is scoped to the current tab.

## Local development

Use Node 22 and copy `.env.example` to `.env.local`. For the local gateway and
bridge, set the two base URLs explicitly and add `http://127.0.0.1:5173` to the
servers' exact CORS origin allowlists.

```bash
npm install
npm run dev
```

The homepage is at `http://127.0.0.1:5173/`; the dApp is at
`http://127.0.0.1:5173/app`.

## Verification

```bash
npm run typecheck
npm test
npm run build
npm run e2e
```

## Production deployment

The tracked `.env.production` contains only the public canonical Sepolia V3
manifest and service origins. A production build is therefore reproducible with:

```bash
npm run build
```

Use `.env.production.local` only for an intentional public deployment override.
Every `VITE_*` value is compiled into browser JavaScript, including URL paths
and query strings, so never put private RPC credentials, keys, or tokens there.
Keep credentialed RPC endpoints in the backend environment or expose a bounded
same-origin server proxy instead.

Publish `dist/` from the same build to both website hosts. The application
detects `app.mycomesh.xyz` and opens the dApp directly; other hosts open the
homepage. `_redirects` and `vercel.json` provide history fallback for common
static hosts.

Create these DNS records at the hosting providers you choose:

| Host | Target |
| --- | --- |
| `@` | Static frontend deployment |
| `app` | Static frontend deployment |
| `gateway` | HTTPS reverse proxy to Consumer Proxy `127.0.0.1:8100` |
| `bridge` | HTTPS reverse proxy to Bridge `127.0.0.1:9800` |

Do not set the V3 environment variables until a verified deployment manifest
contains the protocol version, all contract addresses, chain ID, and deployment
block. The optional V4 session manifest consists of
`VITE_SESSION_PROTOCOL_VERSION=4`, `VITE_SESSION_SETTLEMENT_ADDRESS`, and (for
operator auditability) `VITE_SESSION_DEPLOYMENT_BLOCK`. When it is present, the
Funds page deposits into V4 and the Playground asks for one bounded
`openSession` transaction; subsequent requests use the normal HTTP API path.
`VITE_STABLECOIN_ADDRESS` must also identify the token wired into the V4
constructor. If the Gateway reports `activation_required=false`, the browser
verifies and restores the existing session instead of asking for another wallet
transaction.
Missing fields intentionally disable contract actions instead of falling back
to legacy V2.
