# mycomesh-provider

Run a MycoMesh V11 Provider. Providers post no stake: new Providers start with a
50 tUSDC unsettled-exposure cap that grows with clean volume, and Relays check
them with free known-answer probes. Requires Node.js 20+ and Docker.

```sh
npx mycomesh-provider                              # the dashboard at http://127.0.0.1:8120/ walks through every step

# or step by step, serving from an API key:
mycomesh-provider init                             # creates the signer key in ~/.mycomesh/provider
mycomesh-provider wallet                           # payout wallet, encrypted with MYCOMESH_KEY_PASSWORD
mycomesh-provider register --model claude-sonnet-4-6   # joins the tier that lists the model
mycomesh-provider start --backend anthropic --api-key-env ANTHROPIC_API_KEY --model claude-sonnet-4-6
mycomesh-provider status
```

The dashboard shows the container, logs, earnings (escrow, holdback, claimable), the exposure cap
that replaces a stake, and progress toward jury eligibility; it can claim, start, restart and stop.
It is served to this machine only.

- The **owner** account receives payouts and pays the registration gas, so it
  needs a little Sepolia ETH. Its key is only mounted for `register`.
- The **signer** key stays in `~/.mycomesh/provider/keys`; it signs receipts,
  transport keys and jury votes.
- `login` signs in to ChatGPT for the Codex backend instead (the default backend).
- `earnings` and `claim` cover stablecoin payouts and MYCO rewards together.
- `--codex-home DIR` reuses an existing Codex login directory.

Once registered and serving, the Provider is also eligible for Provider-AI juries
after its first released request, and votes automatically when drawn.
