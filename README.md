# Multi-Agent Code Gateway

This is a local orchestrator for personal multi-agent code automation. Child agents call it with the OpenAI Chat Completions HTTP protocol, while the gateway maps each request to a user, workspace, code task, child agent, and session before forwarding it to one central inference backend.

Do not put your OpenAI or Codex account password into this project. Use either an OpenAI-compatible API key, or run the official `codex login` command yourself and let the gateway call the local Codex CLI login state.

## What It Does

- Accepts `POST /v1/chat/completions`
- Accepts `POST /v1/responses`
- Accepts `GET /v1/models`
- Uses internal agent keys to identify child agents
- Tracks user, workspace, task, agent, and session context
- Keeps isolated SQLite history per `(user_id, workspace_id, task_id, agent_id, session_id)`
- Injects routing context and per-agent code-task prompts
- Forwards to one upstream OpenAI-compatible endpoint, or local Codex CLI
- Supports a Codex center-orchestrator mode that routes work to child agents
- Provides local username/password login for your own gateway users
- Transparently proxies other `/v1/*` routes to the upstream

## OpenAI Compatibility

For child agents, configure only:

```text
base_url = http://<gateway-host>:8000/v1
api_key = <agent-key>
```

Supported with `GATEWAY_BACKEND=codex_cli` or `GATEWAY_BACKEND=codex_app_server`:

- `/v1/chat/completions`: bridged to Codex
- `/v1/chat/completions` with `stream=true`: returns OpenAI-style SSE chunks after Codex completes
- `/v1/responses`: bridged to Codex
- `/v1/responses` with `stream=true`: returns Responses-style SSE events after Codex completes
- `/v1/models`: returns gateway model ids
- model identity: `PUBLIC_MODEL_ID` controls the model name exposed to child agents

Explicitly unsupported with Codex backends:

- `/v1/embeddings`
- `/v1/files`
- `/v1/audio/*`
- `/v1/images/*`
- true OpenAI tool execution semantics

Tool calls and JSON response formats have compatibility shims for SDK/test compatibility, but Codex is still the actual backend. Unsupported endpoints return an OpenAI-style JSON error instead of silently failing. With `GATEWAY_BACKEND=openai_http`, unsupported local routes are proxied to the configured upstream.

## Codex Center Orchestration

When an agent in `agents.json` has `"orchestrates": true`, requests using that agent's key are handled as a center-orchestrator request. The gateway asks Codex to return a strict JSON decision:

```json
{
  "action": "final",
  "final": "answer to return"
}
```

or:

```json
{
  "action": "call_agent",
  "target_agent": "planner",
  "input": "task for the child agent",
  "session_id": "optional-child-session"
}
```

For `call_agent`, the gateway invokes the target child agent internally with that agent's prompt and isolated session, then gives the child result back to the center Codex orchestrator. This repeats up to `GATEWAY_ORCHESTRATION_MAX_STEPS`, then the final answer is wrapped as a normal OpenAI-compatible chat completion.

The default `agents.json` marks `coder-local-key` as the center entrypoint:

```text
external child/client -> coder-local-key -> center Codex -> planner/coder/reviewer -> final OpenAI-style response
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
cp agents.example.json agents.json
```

Edit `.env`:

```bash
GATEWAY_BACKEND=openai_http
UPSTREAM_BASE_URL=https://api.openai.com/v1
UPSTREAM_API_KEY=your-openai-api-key
CENTER_MODEL=your-central-model
PUBLIC_MODEL_ID=gpt-5.5
DEFAULT_USER_ID=local-user
DEFAULT_WORKSPACE_ID=default-workspace
```

For Codex Pro/Plus via official CLI login:

```bash
codex login
```

Then set:

```bash
GATEWAY_BACKEND=codex_app_server
CODEX_COMMAND=codex
CODEX_HOME=/Users/lzp/mutilpleagent/.codex-gateway-home
CODEX_WORKDIR=/path/to/your/code/workspace
CODEX_SANDBOX=workspace-write
CENTER_MODEL=
PUBLIC_MODEL_ID=gpt-5.5
CODEX_INTERNAL_MODEL=gpt-5.5
```

This uses the Codex CLI auth state inside `CODEX_HOME`; the gateway never asks for or stores your OpenAI/Codex password. Keep `CODEX_HOME` project-specific if you want this gateway login to be isolated from your normal `~/.codex` setup. `CODEX_INTERNAL_MODEL` is passed to Codex as the actual model selection. Use `GATEWAY_BACKEND=codex_cli` instead if you need the older `codex exec` bridge.

Start an isolated browser/device login for this gateway:

```bash
CODEX_HOME=/Users/lzp/mutilpleagent/.codex-gateway-home codex login --device-auth
```

Or use the bundled gateway client command:

```bash
python -m gateway login
```

Start the gateway:

```bash
uvicorn gateway.main:app --reload --host 127.0.0.1 --port 8000
```

Run tests:

```bash
python -m unittest discover -s tests -q
```

## Gateway Client Commands

The gateway can be operated as a local client around the existing server.

Start the official Codex login flow:

```bash
python -m gateway login
```

Generate a gateway API key for an agent:

```bash
python -m gateway key create --agent coder
```

List stored key fingerprints:

```bash
python -m gateway key list
```

Delete a key by full key, unique key prefix, or fingerprint prefix:

```bash
python -m gateway key delete --agent coder <selector>
```

Rotate a key by creating a replacement and removing the selected old key:

```bash
python -m gateway key rotate --agent coder <selector>
```

Print the public OpenAI-compatible base URL when a Cloudflare tunnel URL is
present in `.codex-run/cloudflared*.log`:

```bash
python -m gateway url --port 8000
```

Call the local or public `/health` endpoint:

```bash
python -m gateway health --port 8000
python -m gateway health --public --port 8000
```

Print a compact local status summary:

```bash
python -m gateway status --port 8000
```

Start the gateway in the foreground:

```bash
python -m gateway serve --port 8000
```

Start the gateway and a Cloudflare quick tunnel together:

```bash
python -m gateway serve --port 8000 --with-tunnel
```

Manage only the tunnel:

```bash
python -m gateway tunnel start --port 8000
python -m gateway tunnel status --port 8000
python -m gateway tunnel stop --port 8000
```

Clear the isolated Codex login state used by this gateway:

```bash
python -m gateway logout
```

Generated keys are stored in `agents.json`. Restart an already running gateway
after creating or deleting keys so the server reloads the updated agent config.
Managed gateway and tunnel processes write logs and pid files to `.codex-run`.

## P2P Inference Provider

The current gateway can run as the local execution client for a P2P inference
provider. The first P2P version uses a direct TCP JSON-lines protocol so the
useful-work path can be tested before adding DHT/libp2p discovery.

Start the local gateway:

```bash
python -m gateway serve --port 8000
```

Generate a provider key if needed:

```bash
python -m gateway key create --agent coder
```

Expose this gateway as a P2P provider:

```bash
python -m gateway p2p serve \
  --port 9700 \
  --advertise-host 127.0.0.1 \
  --agent coder \
  --gateway-url http://127.0.0.1:8000/v1 \
  --channel codex-standard-v1
```

Ping a provider:

```bash
python -m gateway p2p ping 127.0.0.1:9700
```

Send one inference task through P2P:

```bash
python -m gateway p2p infer 127.0.0.1:9700 "只回复 OK"
```

Bootstrap one provider to another:

```bash
python -m gateway p2p serve --port 9701 --bootstrap 127.0.0.1:9700
python -m gateway p2p peers 127.0.0.1:9700
```

In this MVP, the generated gateway key is local to the provider node. External
peers never receive the key. They send P2P inference tasks to the provider; the
provider then calls its own local gateway with its local agent key.

## Local User Login

This login is for your gateway users, not for OpenAI/Codex.

Register a local user:

```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123","user_id":"user-alice"}'
```

Login:

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

The response returns `access_token`. Send it as `X-User-Token`:

```bash
curl http://127.0.0.1:8000/auth/me \
  -H "X-User-Token: <access_token>"
```

Set `REQUIRE_USER_AUTH=true` in `.env` if every gateway request must include `X-User-Token`.

## Child Agent Request

Each child agent uses the gateway as its OpenAI base URL and its own internal key as the API key.

```python
from openai import OpenAI

planner = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="planner-local-key",
)

response = planner.chat.completions.create(
    model="gpt-5.5",
    extra_headers={
        "X-User-Token": "optional-local-user-token",
        "X-User-ID": "user-001",
        "X-Workspace-ID": "repo-main",
        "X-Task-ID": "task-123",
        "X-Session-ID": "planner-session",
    },
    messages=[
        {"role": "user", "content": "Plan the code change for adding login rate limits."}
    ],
)

print(response.choices[0].message.content)
```

Responses API example:

```python
response = planner.responses.create(
    model="gpt-5.5",
    input="只回复 OK，测试 Responses API"
)

print(response.output_text)
```

Recommended routing headers:

- `Authorization: Bearer <agent-key>`: identifies the child agent
- `X-User-Token`: local gateway user token when `REQUIRE_USER_AUTH=true`
- `X-User-ID`: your end user or owner id
- `X-Workspace-ID`: repo/workspace id
- `X-Task-ID`: code task id
- `X-Session-ID`: child-agent conversation id within that task

If a child agent cannot send custom headers, it can put the same values in the request body:

```json
{
  "gateway_user_id": "user-001",
  "gateway_workspace_id": "repo-main",
  "gateway_task_id": "task-123",
  "gateway_session_id": "planner-session",
  "messages": []
}
```

The OpenAI-compatible `user` field is also accepted as a fallback user/session id.

## Session Behavior

When a session id is present, the gateway is stateful by default:

```text
user id + workspace id + task id + agent key + session id -> isolated stored conversation
```

For stateful calls, send only the new turn in `messages`; the gateway injects prior stored turns. If a child agent sends the full conversation every time, set `gateway_stateful=false` or omit the session id to avoid duplicate history.

Useful controls:

- `user`: OpenAI-compatible fallback user/session id
- `X-Session-ID`: session id header
- `gateway_session_id`: body field for clients that support extra body fields
- `gateway_stateful=false`: disable stored history for one request
- `gateway_clear_session=true`: clear the session before this request

## Inspect Or Clear Sessions

```bash
curl http://127.0.0.1:8000/gateway/sessions

curl -H "X-User-ID: user-001" \
  -H "X-Workspace-ID: repo-main" \
  -H "X-Task-ID: task-123" \
  http://127.0.0.1:8000/gateway/sessions

curl -X DELETE \
  -H "Authorization: Bearer planner-local-key" \
  -H "X-User-ID: user-001" \
  -H "X-Workspace-ID: repo-main" \
  -H "X-Task-ID: task-123" \
  http://127.0.0.1:8000/gateway/sessions/planner-session
```

## Agent Config

`agents.json` defines internal keys, roles, and per-agent prompts:

```json
{
  "agents": {
    "planner": {
      "keys": ["planner-local-key"],
      "role": "planner",
      "description": "Break a code task into ordered implementation steps.",
      "system_prompt": "You are the planner agent for code-change tasks."
    }
  }
}
```

These keys are your gateway's internal access tokens. They are not OpenAI API keys.

Optional per-agent restrictions:

```json
{
  "workspace_ids": ["repo-main"],
  "allowed_users": ["user-001"]
}
```

If these arrays are present, the gateway rejects requests outside the allowed user/workspace scope.
