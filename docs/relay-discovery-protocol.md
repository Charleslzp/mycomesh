# Relay Discovery Protocol V1

Implementation contract for authenticated Relay discovery. Discovery does not
authorize payments, change model trust, migrate Provider sessions, or replay an
inference request. Economic policy is unchanged.

## Trust And Configuration

Discovery is opt-in using a trusted local network manifest:

```json
{
  "relay_discovery": {
    "authorities": ["0x...", "0x...", "0x..."],
    "threshold": 2,
    "refresh_seconds": 30,
    "timeout_seconds": 3
  }
}
```

`authorities` contains 1-16 unique, nonzero EVM addresses. `threshold` is an
integer, a strict majority, and at least two when multiple authorities exist.
These discovery authorities are explicitly configured network operators, NOT
automatically the settlement adjudicators. No production keys or authorities
are generated or silently selected. With discovery absent, static operation
remains unchanged. `bridge_urls` are trusted bootstrap HTTPS origins (local
profile permits loopback HTTP). At most eight are queried concurrently.

## Signed Messages

All objects use exact field sets, printable ASCII strings, safe nonnegative JSON integers,
lowercase EVM addresses and lowercase `0x` signatures. Canonical JSON is UTF-8
with keys sorted recursively and no whitespace. Signature encoding is 65-byte
`r || s || v`, v=27/28, low-s required. Use existing secp256k1 primitives.

Binding fields shared by admission and announcement:

```
network_id, channel_id, chain_id, settlement_contract, protocol_version,
host, provider_port, public_url, provider_tls,
payment_address, attestation_address
```

Only V8/V9 are enabled. `provider_tls` must be true outside local profile.
`public_url` is an origin, without path, credentials, query or fragment.
V1 dynamically learned Relay endpoints use literal public unicast IPs, including
IPv6, with HTTPS. `host` must be the same literal IP as `public_url`. This avoids
DNS rebinding and does not require DNS. Local-profile tests permit literal
loopback IPs and HTTP. Static configured DNS endpoints are unaffected. Every
dynamic HTTP request forbids redirects and uses bounded response bodies/time.

An admission is:

```json
{
  "schema": "mycomesh.relay-admission.v1",
  "network_id": "...",
  "channel_id": "...",
  "chain_id": 11155111,
  "settlement_contract": "0x...",
  "protocol_version": 8,
  "host": "203.0.113.1",
  "provider_port": 9901,
  "public_url": "https://203.0.113.1",
  "provider_tls": true,
  "payment_address": "0x...",
  "attestation_address": "0x...",
  "expires_at": 0,
  "signatures": [{"signer": "0x...", "signature": "0x..."}]
}
```

Example IP and values above are placeholders, not valid deployment defaults.
Sign `keccak256(b"mycomesh.relay-admission.v1\\n" + canonical(unsigned_admission))`.
The actual prefix terminator is one newline byte, not backslash+n.
`unsigned_admission` is the entire admission minus `signatures`. Validate all
signers and count unique configured authorities; require threshold. Signature
order does not matter. Admission expires within at most 366 days of verification.

An announcement contains exactly the binding fields plus:

```
schema = "mycomesh.relay-announcement.v1"
sequence                  # persistent monotonic integer, >= 1
issued_at                 # Unix seconds, <= now + 30 seconds
expires_at                # Unix seconds, > now, issued_at < expires_at
admission                 # full admission above, every binding field identical
signature                 # signature by attestation_address
```

Sign `keccak256(b"mycomesh.relay-announcement.v1\\n" + canonical(unsigned_announcement))`.
Unsigned announcement is the full announcement minus `signature`. Lifetime
is at most 300 seconds and cannot extend beyond admission expiry. Consumers and
Providers validate the complete certificate, signature and deployment binding
themselves, not just the Bridge's JSON wrapper. Max announcement size 16 KiB.

## HTTP And Caches

Bridge `POST /relays/register` accepts `{ "announcement": <signed record> }`.
Bridge `GET /relays` returns:

```json
{"schema":"mycomesh.relay-directory.v1","relays":["<signed records>"]}
```

The maximum directory is 64 live records and 1 MiB per response. Invalid entries
cannot suppress valid entries from other Bridges. A Relay signing identity has
one current record. Caches retain bounded high-water marks after expiry, reject
sequence rollback and conflicting same-sequence content, and accept identical
duplicates without extending the signed expiry. Persist high-water marks and
signed records across restarts. Never evict a live/remembered identity merely to
admit an untrusted directory flood: fail closed at the configured record limit.
V1 retains up to 64 identity watermarks without automatic eviction. Replacing a
Relay's signing identity consumes another slot; planned identity rotation or
directory capacity migration requires an operator-controlled cache migration.

The native Consumer uses an exclusive cache write lock and durable atomic file
replacement. A corrupt cache or a lock left behind by a crashed writer disables
dynamic updates, not static routes. Never delete the cache to clear a lock: that
would discard anti-replay watermarks. Confirm all writers have stopped, preserve
the cache, and recover the lock or restore a known-good cache before restarting.

Bridges pull from configured `bootstrap_pools` on an independent bounded worker,
validate original records, and merge without re-signing or refreshing expiry.
They do not follow URLs learned from directory responses as new Bridge seeds.

Relay exposes its current record at `GET /relay-announcement`; publication to
each configured Bridge uses the same signed record and refreshes before expiry.
Endpoint probes fetch this record and require the intended binding and a sequence
at least as fresh as the discovered candidate. Probe is not an inference request.
Health must still pass existing settlement/readiness checks and match both Relay
payment and attestation addresses before payment or Provider registration.

Provider refreshes candidates at startup/reconnect, without disconnecting a
healthy current Relay. Consumer refreshes with coalescing/TTL before route
selection; a discovery outage cannot erase unexpired previously verified records
or static fallbacks. Expired dynamic routes cannot be used for new dispatch.
Existing sessions stay with their Provider signer, including Relay recovery.
Provider keeps still-valid probe results across its three-Relay probe windows
so reconnect attempts cannot repeatedly skip healthy candidates in other windows.

## Scope

This provides dynamic discovery within explicitly admitted network membership,
not permissionless Sybil-resistant admission, a DHT, arbitrary DNS discovery, or
automatic discovery of new Bridge bootstrap authorities. Operators distribute
trust roots once and issue a certificate for each new Relay. New endpoints then
propagate without individual client configuration edits. Authority rotation and
emergency revocation require a trusted manifest update; admission expiry bounds
the lifetime of an unchanged certificate.

## Enablement

This change does not enable discovery in the existing production manifests or
silently create trust roots. Deploy the updated Python package and native CLI
before adding `relay_discovery` to the trusted manifest distributed to clients.
Use the same authority addresses, quorum, network, channel and settlement
deployment on all participants. Configure the existing three Bridge HTTPS
origins in `bridge_urls`; their certificates must already be trusted by clients.
IP-only discovery does not bypass certificate verification.

For each new Relay, create an admission JSON matching the admission structure
above, with `signatures: []`, real endpoint bindings and a finite Unix expiry.
Each configured authority independently reviews and endorses that exact file:

```sh
python -m gateway.relay_discovery_admin endorse \
  --network-config /etc/mycomesh/network.json \
  --admission /etc/mycomesh/relay-admission-draft.json \
  --identity-file /secure/discovery-authority.json \
  --output /etc/mycomesh/relay-admission-one.json
```

Pass the public output to the next authority and repeat with a different output
filename. Identity files use the existing protected EVM identity format
(`schema_version`, `address`, `private_key`) and require mode 0600 or stricter.
The command reads an existing key, never generates one, never prints it, never
accepts a key as a command-line argument, and never sends a transaction. Do not
collect different authorities' private keys on the Relay. Validate the final
quorum certificate without a private key:

```sh
python -m gateway.relay_discovery_admin verify \
  --network-config /etc/mycomesh/network.json \
  --admission /etc/mycomesh/relay-admission.json
```

Append these options to each existing Bridge service's launch command, retaining
its current settlement, Provider authorization, TLS and other security options:

```text
--network-config /etc/mycomesh/network.json
--discovery-cache /var/lib/mycomesh/bridge-relay-directory.sqlite3
```

Bridge defaults to syncing the manifest's Bridge list (excluding its own
`--public-url`); repeat `--bootstrap-pool https://BRIDGE_IP` to explicitly override
the trusted peer set. Relay launch adds:

```text
--network-config /etc/mycomesh/network.json
--relay-admission /etc/mycomesh/relay-admission.json
--discovery-cache /var/lib/mycomesh/relay-announcement.sqlite3
```

These also have environment equivalents: `MYCOMESH_DISCOVERY_NETWORK_CONFIG`,
`MYCOMESH_BRIDGE_DISCOVERY_CACHE`, `MYCOMESH_RELAY_DISCOVERY_CACHE`, and
`MYCOMESH_RELAY_ADMISSION`. Relay's advertised host and public control/Provider
ports must match its admission, including when TLS terminates at the existing
edge proxy. Keep the SQLite files across restarts and container replacements.
The edge must expose Bridge `/relays` and `/relays/register`, and Relay
`/relay-announcement`, `/health`, and the existing Consumer `/relay/health` route.
The existing IP-mesh nginx catch-all and health alias already support these paths.

Provider and native Consumer automatically read the opt-in policy from their
existing network manifest. No new Provider wallet action or signing-key prompt
is introduced. Provider keeps its static primary fast path and refreshes at
reconnection; healthy connected Providers are not moved. Consumer keeps static
fallbacks while refreshing Bridge directories in parallel with route selection.
All discovered endpoints must pass signed endpoint and identity/readiness checks
before use. A directory query itself never buys inference.

Acceptance: start a Relay absent from client static lists, issue its admission,
observe the same signed announcement on all three Bridges, then stop a client's
primary Relay and confirm discovery of the new endpoint. Verify that any existing
session only recovers when its original Provider signer is available. Stop two
Bridges and repeat with the third; then stop all Bridges and confirm unexpired
cache/static operation, rejection after expiry, and no blind replay of dispatched
requests. Local automated checks cover these components; production activation
requires explicit operator selection of discovery authority addresses/certificates.

Run the focused suites from the repository root with the gateway Python
dependencies and native CLI npm dependencies installed:

```sh
python3 -m unittest tests.test_relay_discovery tests.test_relay_discovery_runtime tests.test_provider_relay_discovery tests.test_relay_discovery_ipv6
node --test packages/mycomesh-cli/test/consumer-discovery.test.mjs
```

The native interoperability test invokes `python3`; set `MYCOMESH_TEST_PYTHON`
to the gateway Python interpreter when multiple Python environments are present.
Local transport tests use test identities and controlled readiness/payment
fixtures. They are not evidence of production model inference or on-chain payment.
