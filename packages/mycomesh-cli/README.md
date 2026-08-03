# mycomesh-consumer

Local-first launcher and request CLI for the MycoMesh OpenAI-compatible
Consumer edge. With no arguments it starts the pinned Docker runtime, opens a
local page containing the export URL and payment key, and opens Codex through
the loopback proxy.

The package is published as `mycomesh-consumer`. `mycomesh-consumer` and the
short `mycomesh` command are equivalent.

## Requirements

- Node.js 20 or newer
- Docker Desktop/Engine with Compose V2
- The official Codex dependency installed with this npm package

For local development, install it directly from the repository:

```sh
npm install --global ./packages/mycomesh-cli
```

For an npm install from the public registry:

```sh
npm install --global mycomesh-consumer
mycomesh-consumer
```

No checkout, separate Codex install, host Python, GNU Make, public Gateway URL, or command arguments are
required. The command prints the local credentials URL and opens it when
possible. The page contains only `OPENAI_BASE_URL` and `OPENAI_API_KEY` exports;
the payment key is generated and persisted in a protected Docker volume. No
wallet signature or browser session is required.

The runtime image is pinned by digest. Stop it without deleting state with:

```sh
mycomesh-consumer --stop
```

Use `--no-browser` on a headless machine or `--no-codex` to leave only the
local proxy running. Consumer network traffic is direct by default. Use
`--proxy http://127.0.0.1:10792` only when a proxy is needed; loopback proxy
hosts are translated to `host.docker.internal`. Dedicated
`MYCOMESH_CONSUMER_*_PROXY` variables remain available for operators.

Upgrading the npm package does not require clearing the payment key. The
Consumer volume is intentionally reused so its key and routing state survive
restarts. To reset all local Consumer state,
use the explicit, confirmed reset command:

```sh
mycomesh-consumer --reset-local
```

If Codex reports an interrupted request, stop Codex and run
`mycomesh-consumer --no-codex` to restart the local edge.

This removes the local payment key and Consumer state. The command asks you to type `RESET`
and removes only the fixed Consumer Compose project and its protected volume.

The existing stateless API commands remain available. For example:

```sh
npx --yes --package=mycomesh-consumer mycomesh-consumer health
```

## Configuration

```sh
export MYCOMESH_BASE_URL=http://127.0.0.1:8110/v1
export MYCOMESH_API_KEY=your-consumer-key
```

`--base-url` and `--api-key` override their corresponding environment
variables. A base URL may be the service root or end in `/v1`.
Remote base URLs must use HTTPS. Loopback HTTP remains available for local
development; `--allow-insecure-http` is an explicit test-only escape hatch.
Requests default to a 300-second deadline. Set `MYCOMESH_TIMEOUT_SECONDS` or
`--timeout`; successful JSON bodies are capped at 32 MiB while SSE remains
streamed with backpressure.

Prefer `MYCOMESH_API_KEY` over `--api-key`: command-line arguments may be stored
in shell history or visible to other local processes. The CLI never writes the
key to disk and redacts it from HTTP error output.

The zero-argument launcher configures Codex directly with a temporary
`mycomesh` model provider and does not modify `~/.codex/config.toml`. For manual
API commands, read the local credentials with the repository operator command
or provide explicit values:

```sh
export MYCOMESH_BASE_URL=http://127.0.0.1:8110/v1
export MYCOMESH_API_KEY='replace-with-local-consumer-key'
```

The local proxy selects a healthy Relay and authorizes each request with the
persisted payment key. No session identifier or per-request wallet signature is needed. A public Gateway can
still be used explicitly with `--base-url`, but it is never the default.

## Commands

```sh
mycomesh health
mycomesh models

mycomesh responses \
  --input "Summarize this text" \
  --model mycomesh-codex-standard-v1 \
  --max-output-tokens 500

mycomesh chat \
  --message "Explain this function" \
  --system "Be concise." \
  --model mycomesh-codex-standard-v1 \
  --max-completion-tokens 500
```

The request CLI sends standard OpenAI-shaped requests. The local proxy binds
each request to the persisted payment key automatically.

Use `--stream` to request SSE. SSE bytes are forwarded to stdout as they arrive,
without rewriting event boundaries:

```sh
mycomesh responses \
  --input "Write a short status update" \
  --max-output-tokens 500 \
  --stream
```

## JSON Input

Pass an inline object, read a file, or read stdin explicitly:

```sh
mycomesh responses --json '{"model":"my-model","input":"hello"}'
mycomesh chat --json @request.json
generate-request | mycomesh responses --json -
```

Piped stdin is treated as JSON even without `--json`:

```sh
printf '%s' '{"model":"my-model","messages":[{"role":"user","content":"hello"}]}' \
  | mycomesh chat
```

Explicit flags such as `--model`, `--input`, `--message`, `--system`, and
`--stream` override the corresponding JSON fields. Successful JSON responses
are pretty-printed. SSE and other response types are copied to stdout. HTTP and
input errors are written to stderr and return a nonzero exit status.

## Development

```sh
cd packages/mycomesh-cli
npm test
```
