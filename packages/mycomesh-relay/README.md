# mycomesh-relay

Run an independent MycoMesh V11 Relay. Like a Bitcoin node, it needs no domain
name and no certificate authority: its self-signed TLS certificate is pinned in
the on-chain Relay directory, and every Consumer and Provider checks the pin.
Requires Node.js 20+, Docker, and ports 10443 and 10991 open.

```sh
npm install --global mycomesh-relay
mycomesh-relay init            # owner + signer keys, self-signed certificate for this machine's public IP
mycomesh-relay register        # bind the signer, fund probes, announce the pinned endpoints on-chain
mycomesh-relay start --with-keeper
mycomesh-relay status
mycomesh-relay earnings        # the Relay's share of every fee it dispatched
```

Once announced, Providers join the Relay automatically and Consumers discover it
from the chain. The Relay probes its Providers with free known-answer requests,
records re-gradable verdicts in the probe ledger, and helps run Provider-AI juries.
