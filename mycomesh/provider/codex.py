"""Codex backend: serve OpenAI models from a ChatGPT-login Codex CLI.

Each request runs one ephemeral ``codex app-server`` turn with the shell,
plugins, MCP servers and web search disabled and a read-only sandbox, so the
model can only answer. Usage comes from Codex's own token accounting.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .backends import BackendError

MAX_MESSAGE_BYTES = 8 * 1024 * 1024
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY",
                 "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
DISABLED_FEATURES = (
    "shell_tool", "unified_exec", "shell_snapshot", "hooks", "code_mode", "code_mode_host", "multi_agent", "apps",
    "plugins", "in_app_browser", "browser_use", "browser_use_full_cdp_access", "browser_use_external",
    "computer_use", "remote_plugin", "plugin_sharing", "image_generation", "skill_mcp_dependency_install",
    "tool_suggest", "tool_call_mcp_elicitation",
)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content)
    return json.dumps(content, ensure_ascii=False)


def prompt_of(request: dict[str, Any]) -> tuple[str, str | None]:
    """(user prompt, developer instructions) for a V11 request document."""
    if request["endpoint"] == "chat":
        messages = request["messages"]
    elif isinstance(request["input"], list):
        messages = request["input"]
    else:
        messages = [{"role": "user", "content": request["input"]}]
    instructions = [str(request["options"]["instructions"])] if request["options"].get("instructions") else []
    turns = []
    for message in messages:
        if not isinstance(message, dict):
            turns.append(("user", _text(message)))
        elif message.get("role") in {"system", "developer"}:
            instructions.append(_text(message.get("content")))
        else:
            turns.append((str(message.get("role") or "user"), _text(message.get("content"))))
    if len(turns) == 1 and turns[0][0] == "user":
        prompt = turns[0][1]
    else:
        prompt = "\n\n".join(f"[{role}]\n{text}" for role, text in turns)
    return prompt, "\n\n".join(instructions) or None


def shape_output(request: dict[str, Any], text: str, input_tokens: int, output_tokens: int) -> dict[str, Any]:
    if request["endpoint"] == "chat":
        return {"id": f"chatcmpl_{secrets.token_hex(12)}", "object": "chat.completion", "created": int(time.time()),
                "model": request["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens,
                          "total_tokens": input_tokens + output_tokens}}
    return {"id": f"resp_{secrets.token_hex(12)}", "object": "response", "created_at": int(time.time()),
            "status": "completed", "model": request["model"], "output_text": text,
            "output": [{"type": "message", "id": f"msg_{secrets.token_hex(12)}", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": text, "annotations": []}]}],
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                      "total_tokens": input_tokens + output_tokens}}


class _AppServer:
    """One ``codex app-server --stdio`` process speaking newline JSON-RPC."""

    def __init__(self, command: str, codex_home: str, deadline: float) -> None:
        env = {name: os.environ[name] for name in ENV_ALLOWLIST if name in os.environ}
        env["CODEX_HOME"] = codex_home
        self.deadline = deadline
        self.process = subprocess.Popen([command, "app-server", "--stdio"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                        start_new_session=True)
        self._stderr = bytearray()
        threading.Thread(target=self._drain, daemon=True).start()
        self._timer = threading.Timer(max(0.0, deadline - time.monotonic()), self.process.kill)
        self._timer.start()
        self._next = 1

    def _drain(self) -> None:
        for chunk in iter(lambda: self.process.stderr.read(4096), b""):
            if len(self._stderr) < 16_384:
                self._stderr.extend(chunk)

    def close(self) -> None:
        self._timer.cancel()
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)

    def send(self, message: dict[str, Any]) -> None:
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()

    def read(self) -> dict[str, Any]:
        line = self.process.stdout.readline(MAX_MESSAGE_BYTES + 1)
        if not line:
            detail = self._stderr.decode("utf-8", "replace").strip()[-300:]
            timed_out = time.monotonic() >= self.deadline
            raise BackendError("Codex timed out" if timed_out else f"Codex app-server exited: {detail or 'no output'}")
        if len(line) > MAX_MESSAGE_BYTES:
            raise BackendError("Codex app-server message too large")
        message = json.loads(line)
        if "id" in message and isinstance(message.get("method"), str):
            # Server-initiated requests (approvals, tools) are never granted.
            self.send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Method not found"}})
        return message

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self._next
        self._next += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            message = self.read()
            if message.get("id") == request_id and "method" not in message:
                if "error" in message:
                    error = message["error"]
                    raise BackendError(f"Codex {method} failed: {error.get('message') if isinstance(error, dict) else error}")
                return message.get("result") or {}


@dataclass
class CodexBackend:
    codex_home: str
    command: str = "codex"
    workdir: str = "/tmp/mycomesh-codex"
    timeout: float = 300.0
    max_concurrent: int = 1
    _slots: threading.BoundedSemaphore = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._slots = threading.BoundedSemaphore(self.max_concurrent)
        Path(self.workdir).mkdir(parents=True, exist_ok=True)

    def __call__(self, request: dict[str, Any]) -> tuple[Any, int, int]:
        prompt, instructions = prompt_of(request)
        with self._slots:
            reasoning = request["options"].get("reasoning")
            effort = reasoning.get("effort") if isinstance(reasoning, dict) else request["options"].get("reasoning_effort")
            text, input_tokens, output_tokens = self.turn(request["model"], prompt, instructions, effort=effort)
        return shape_output(request, text, input_tokens, output_tokens), input_tokens, output_tokens

    def turn(self, model: str, prompt: str, instructions: str | None, *, effort: Any = None) -> tuple[str, int, int]:
        server = _AppServer(self.command, self.codex_home, time.monotonic() + self.timeout)
        try:
            server.request("initialize", {"clientInfo": {"name": "mycomesh-provider", "version": "11"},
                                          "capabilities": {"experimentalApi": True}})
            thread = {
                "model": model, "cwd": self.workdir, "approvalPolicy": "never", "sandbox": "read-only",
                "ephemeral": True,
                "config": {"web_search": "disabled", "mcp_servers": {}, "plugins": {},
                           "features": {name: False for name in DISABLED_FEATURES}},
            }
            if instructions:
                thread["developerInstructions"] = instructions
            thread_id = server.request("thread/start", thread)["thread"]["id"]
            turn = {"threadId": thread_id, "input": [{"type": "text", "text": prompt, "text_elements": []}],
                    "cwd": self.workdir, "approvalPolicy": "never", "model": model}
            if effort in {"minimal", "low", "medium", "high", "xhigh"}:
                turn["effort"] = effort
            turn_id = server.request("turn/start", turn)["turn"]["id"]
            return self._collect(server, thread_id, turn_id)
        finally:
            server.close()

    @staticmethod
    def _collect(server: _AppServer, thread_id: str, turn_id: str) -> tuple[str, int, int]:
        deltas: list[str] = []
        final: str | None = None
        usage: dict[str, Any] | None = None
        while True:
            message = server.read()
            method = message.get("method")
            params = message.get("params") or {}
            if method == "error":
                if params.get("willRetry"):
                    continue
                raise BackendError(f"Codex error: {str(params.get('message') or params)[:300]}")
            if params.get("threadId") not in {None, thread_id} or params.get("turnId") not in {None, turn_id}:
                continue
            if method == "item/agentMessage/delta":
                deltas.append(str(params.get("delta", "")))
            elif method == "item/completed" and (params.get("item") or {}).get("type") == "agentMessage":
                final = str(params["item"].get("text", ""))
            elif method == "thread/tokenUsage/updated":
                usage = (params.get("tokenUsage") or {}).get("total")
            elif method == "turn/completed" and (params.get("turn") or {}).get("id") == turn_id:
                status = params["turn"].get("status")
                if status != "completed":
                    error = params["turn"].get("error")
                    raise BackendError(f"Codex turn {status}: {error.get('message') if isinstance(error, dict) else error}")
                if not isinstance(usage, dict):
                    raise BackendError("Codex reported no token usage")
                return (final if final is not None else "".join(deltas),
                        int(usage.get("inputTokens") or 0), int(usage.get("outputTokens") or 0))
