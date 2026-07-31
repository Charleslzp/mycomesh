# mycomesh-relay

The MycoMesh Relay installer is a small Node.js launcher around the repository's
Docker Compose Relay runtime. It downloads a pinned checkout, opens the
loopback browser onboarding wizard, and then runs `make relay-start`.

## Install

```sh
npm install --global mycomesh-relay
mycomesh-relay
```

The wizard asks for a public payout address, maximum concurrent sessions and an
optional usage limit. It never accepts an EVM private key, seed phrase, OAuth
credential or API key. If on-screen browser opening is unavailable, use
`--no-browser` and open the printed loopback URL yourself.

```sh
mycomesh-relay --ref <reviewed-commit> --no-browser
```

Docker Engine, Docker Compose V2 and GNU Make are still required. The npm
package is only the onboarding launcher; the Relay remains Docker-backed.

Settlement configuration is deliberately separate. Put the protected Relay
transaction signer and the public contract/RPC settings in the checkout's
`.env.deploy` according to the operator documentation. The public payout
address entered in the wizard is not the gas-funded transaction identity.

Use `--no-start` to download a checkout without starting it, and
`--source-dir /srv/mycomesh` to choose a persistent location. Keep the checkout
and named Docker volumes for upgrades; do not run `docker compose down -v`.
