# mycomesh-provider

Run a MycoMesh V11 Provider. Providers post no stake: new Providers start with a
50 tUSDC unsettled-exposure cap that grows with clean volume, and Relays check
them with free known-answer probes. Requires Node.js 20+ and Docker.

```sh
npm install --global mycomesh-provider
mycomesh-provider init                             # creates the signer key in ~/.mycomesh/provider
mycomesh-provider login                            # ChatGPT device login for Codex (one time)
mycomesh-provider register --owner-key-file owner.key
mycomesh-provider start
mycomesh-provider status
mycomesh-provider dashboard                        # http://127.0.0.1:8120/
```

The dashboard shows the container, logs, earnings (escrow, holdback, claimable), the exposure cap
that replaces a stake, and progress toward jury eligibility; it can claim, start, restart and stop.
It is served to this machine only.

- The **owner** account receives payouts and pays the registration gas, so it
  needs a little Sepolia ETH. Its key is only mounted for `register`.
- The **signer** key stays in `~/.mycomesh/provider/keys`; it signs receipts,
  transport keys and jury votes.
- `start --backend openai --api-key-env OPENAI_API_KEY` or `--backend anthropic
  --api-key-env ANTHROPIC_API_KEY --model claude-sonnet-4-6` serve from an API key
  instead of Codex. `--model` is repeatable.
- `--codex-home DIR` reuses an existing Codex login directory.

Once registered and serving, the Provider is also eligible for Provider-AI juries
after its first released request, and votes automatically when drawn.
