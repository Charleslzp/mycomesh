"""Codex backend: serve OpenAI models from a ChatGPT-login Codex CLI.

Each request is one ephemeral thread on a resident ``codex app-server`` (a few
processes, each multiplexing several threads), with the shell, plugins, MCP
servers and web search disabled and a read-only sandbox, so the model can only
answer. In passthrough mode (the default) the Consumer's system message
replaces Codex's own base instructions, Codex's environment and permission
preambles are left out, and earlier turns go in as real conversation history,
so the model sees what the Consumer sent and little else. Usage comes from
Codex's own token accounting.
"""
from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .backends import BackendError, content_parts, request_tools, shape_output, tool_call

MAX_MESSAGE_BYTES = 8 * 1024 * 1024
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY",
                 "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
DISABLED_FEATURES = (
    "shell_tool", "unified_exec", "shell_snapshot", "hooks", "code_mode", "code_mode_host", "multi_agent", "apps",
    "plugins", "in_app_browser", "browser_use", "browser_use_full_cdp_access", "browser_use_external",
    "computer_use", "remote_plugin", "plugin_sharing", "image_generation", "skill_mcp_dependency_install",
    "tool_suggest", "tool_call_mcp_elicitation",
    # codex-cli 0.162: more features that add tools or preambles to every turn
    "goals", "skill_search", "sleep_tool", "view_image", "realtime_conversation", "mentions_v2", "worktrees", "in_app_chat",
    "in_app_local_automation", "in_app_dictation", "in_app_voice", "browser_annotation_api", "unified_exec_tty",
    "unified_exec_zsh_fork", "write_stdin_approval", "auth_elicitation", "guardian_approval", "workspace_dependencies",
    "steer", "multi_agent_v2", "model_catalog_in_context",
)
TOOL_CALL = "item/tool/call"  # the model calls one of the request's tools (dynamicTools)
USAGE_AFTER_CALL_SECONDS = 8.0  # how long to wait for the turn's token usage once it has called a tool
# Passthrough: leave out Codex's own preambles (sandbox permissions, environment, apps, collaboration modes).
LEAN_CONFIG = {"include_permissions_instructions": False, "include_environment_context": False,
               "include_apps_instructions": False, "include_collaboration_mode_instructions": False,
               "skills": {"include_instructions": False}}


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


def conversation_of(request: dict[str, Any]) -> tuple[str, list[dict[str, Any]], str]:
    """(instructions, history, prompt) for passthrough: the system and developer messages, the earlier turns as
    Responses items (messages, the assistant's tool calls and their results), and the last user message. After
    a tool result the prompt is empty: the model goes on from the result. A conversation that ends with the
    assistant is sent as one prompt, as in :func:`prompt_of`."""
    if request["endpoint"] == "chat":
        messages = request["messages"]
    elif isinstance(request["input"], list):
        messages = request["input"]
    else:
        messages = [{"role": "user", "content": request["input"]}]
    instructions = [str(request["options"]["instructions"])] if request["options"].get("instructions") else []
    items: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            items.append(_message_item("user", _text(message)))
            continue
        role = message.get("role")
        if role in {"system", "developer"}:
            instructions.append(_text(message.get("content")))
        elif role == "tool":
            items.append({"type": "function_call_output", "call_id": str(message.get("tool_call_id")),
                          "output": _text(message.get("content"))})
        elif role == "assistant":
            if message.get("content"):
                items.append(_message_item("assistant", _text(message.get("content"))))
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                arguments = function.get("arguments")
                items.append({"type": "function_call", "call_id": str(call.get("id")), "name": str(function.get("name")),
                              "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments or {})})
        elif role in {None, "user"}:
            items.append(_user_item(message.get("content")))
        else:
            prompt, _ = prompt_of(request)
            return "\n\n".join(instructions), [], prompt
    last = items[-1] if items else None
    if last and last.get("type") == "message" and last["role"] == "user":
        # This turn's input: its text, and its images as Codex image inputs.
        prompt = [{"type": "text", "text": part["text"], "text_elements": []} if part["type"] == "input_text"
                  else {"type": "image", "url": part["image_url"]} for part in last["content"]]
        return "\n\n".join(instructions), items[:-1], prompt
    if last and last.get("type") == "function_call_output":
        return "\n\n".join(instructions), items, ""
    prompt, _ = prompt_of(request)
    return "\n\n".join(instructions), [], prompt


def _user_item(content: Any) -> dict[str, Any]:
    """A user message as a Responses item: its text and images (Codex reads no files: see ``inputs``)."""
    parts: list[dict[str, Any]] = []
    for part in content_parts(content):
        if part["type"] == "text":
            parts.append({"type": "input_text", "text": part["text"]})
        elif part["type"] == "image_url":
            parts.append({"type": "input_image", "image_url": part["image_url"]["url"]})
        else:
            parts.append({"type": "input_text", "text": f"[file {part['file'].get('filename', '')} omitted: this backend reads no files]"})
    return {"type": "message", "role": "user", "content": parts or [{"type": "input_text", "text": ""}]}


def _message_item(role: str, text: str) -> dict[str, Any]:
    return {"type": "message", "role": role, "content": [{"type": "input_text" if role == "user" else "output_text", "text": text}]}


def dynamic_tools(request: dict[str, Any]) -> list[dict[str, Any]]:
    """The request's function tools as Codex dynamic tools: the model may call them, the Consumer runs them."""
    return [{"type": "function", "name": tool["function"]["name"], "description": tool["function"].get("description") or "",
             "inputSchema": tool["function"].get("parameters") or {"type": "object", "properties": {}}}
            for tool in request_tools(request)]


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
        self._timer = threading.Timer(max(0.0, deadline - time.monotonic()), self._kill)
        self._timer.start()
        self._next = 1
        self._write = threading.Lock()

    def _drain(self) -> None:
        for chunk in iter(lambda: self.process.stderr.read(4096), b""):
            if len(self._stderr) < 16_384:
                self._stderr.extend(chunk)

    def _kill(self) -> None:
        """Kill the whole session. ``codex`` is a Node wrapper that spawns the native app-server; SIGKILL on the
        wrapper alone leaves the app-server running (~100 MB each), orphaned to the container's PID 1."""
        try:
            os.killpg(self.process.pid, signal.SIGKILL)  # start_new_session: the group is wrapper + app-server
        except (ProcessLookupError, PermissionError):
            pass

    def close(self) -> None:
        self._timer.cancel()
        try:
            self.process.stdin.close()  # the app-server exits on end of input
        except OSError:
            pass
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        self._kill()  # whatever is left of the session, the wrapper's children included
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        for stream in (self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass

    def send(self, message: dict[str, Any]) -> None:
        with self._write:
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
        if "id" in message and isinstance(message.get("method"), str) and message["method"] != TOOL_CALL:
            # Server-initiated requests (approvals, its own tools) are never granted. A call to one of the
            # Consumer's tools is not answered either: the turn ends there and the call goes back to the Consumer.
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


class _SharedServer(_AppServer):
    """A resident ``codex app-server`` serving many threads at once. One reader thread routes replies to their
    callers by id and notifications to their thread by ``threadId``; a dead process fails every caller."""

    def __init__(self, command: str, codex_home: str, call_timeout: float = 60.0) -> None:
        super().__init__(command, codex_home, time.monotonic() + 10 * 365 * 86_400)
        self._timer.cancel()  # resident: turns carry their own deadlines
        self.call_timeout = call_timeout
        self._lock = threading.Lock()
        self._pending: dict[int, queue.Queue] = {}
        self._threads: dict[str, queue.Queue] = {}
        self.dead: str | None = None
        self.active = 0  # turns in progress
        self.served = 0  # turns started
        threading.Thread(target=self._route, daemon=True).start()
        try:
            self.call("initialize", {"clientInfo": {"name": "mycomesh-provider", "version": "11"},
                                     "capabilities": {"experimentalApi": True}})
        except BaseException:
            self.close()
            raise

    def _route(self) -> None:
        try:
            while True:
                message = _AppServer.read(self)
                if "method" not in message:
                    with self._lock:
                        waiter = self._pending.pop(message.get("id"), None)
                    if waiter is not None:
                        waiter.put(message)
                    continue
                thread_id = (message.get("params") or {}).get("threadId")
                with self._lock:
                    inbox = self._threads.get(thread_id)
                if inbox is not None:
                    inbox.put(message)
        except Exception as exc:  # end of output, or garbage on it
            self.dead = str(exc) or type(exc).__name__
            with self._lock:
                waiters = list(self._pending.values()) + list(self._threads.values())
                self._pending.clear()
            for waiter in waiters:
                waiter.put(None)

    def call(self, method: str, params: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        waiter: queue.Queue = queue.Queue()
        with self._lock:
            if self.dead:
                raise BackendError(f"Codex app-server exited: {self.dead}")
            request_id = self._next
            self._next += 1
            self._pending[request_id] = waiter
            self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        try:
            message = waiter.get(timeout=self.call_timeout if timeout is None else max(0.0, timeout))
        except queue.Empty:
            with self._lock:
                self._pending.pop(request_id, None)
            raise BackendError(f"Codex {method} timed out") from None
        if message is None:
            raise BackendError(f"Codex app-server exited: {self.dead}")
        if "error" in message:
            error = message["error"]
            raise BackendError(f"Codex {method} failed: {error.get('message') if isinstance(error, dict) else error}")
        return message.get("result") or {}

    def notify(self, method: str, params: dict[str, Any]) -> None:
        """A request whose reply nobody waits for (interrupt, unsubscribe)."""
        with self._lock:
            if self.dead:
                return
            request_id = self._next
            self._next += 1
            try:
                self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            except OSError:
                pass

    def subscribe(self, thread_id: str, deadline: float) -> "_ThreadReader":
        inbox: queue.Queue = queue.Queue()
        with self._lock:
            self._threads[thread_id] = inbox
        return _ThreadReader(self, inbox, deadline)

    def unsubscribe(self, thread_id: str) -> None:
        with self._lock:
            self._threads.pop(thread_id, None)
        self.notify("thread/unsubscribe", {"threadId": thread_id})  # ephemeral: the server drops the thread


class _ThreadReader:
    """One thread's notifications, in order, until the turn's deadline."""

    def __init__(self, server: _SharedServer, inbox: queue.Queue, deadline: float) -> None:
        self.server, self.inbox, self.deadline = server, inbox, deadline

    def read(self, wait: float | None = None) -> dict[str, Any] | None:
        """The next notification; None when ``wait`` seconds pass first (the turn's deadline still applies)."""
        left = max(0.0, self.deadline - time.monotonic())
        try:
            message = self.inbox.get(timeout=left if wait is None else min(left, wait))
        except queue.Empty:
            if wait is not None and time.monotonic() < self.deadline:
                return None
            raise BackendError("Codex timed out") from None
        if message is None:
            raise BackendError(f"Codex app-server exited: {self.server.dead}")
        return message


@dataclass
class CodexBackend:
    codex_home: str
    command: str = "codex"
    workdir: str = "/tmp/mycomesh-codex"
    timeout: float = 300.0
    max_concurrent: int = 1
    passthrough: bool = True  # the Consumer's own instructions instead of Codex's (see the module docstring)
    resident: bool = True  # long-lived app-servers; False starts one per request
    threads_per_server: int = 8
    # Turns per process before it is retired (once idle). An ephemeral thread stays loaded in the app-server
    # after its turn (unsubscribe does not unload it, delete refuses it), about 1 MB each.
    recycle_after: int = 100
    _slots: threading.BoundedSemaphore = field(init=False, repr=False)
    streams = True
    inputs = ("text", "image")  # Codex takes images as turn inputs and history items; it has no file input

    def __post_init__(self) -> None:
        self._slots = threading.BoundedSemaphore(self.max_concurrent)
        self._pool: list[_SharedServer] = []
        self._pool_lock = threading.Lock()
        Path(self.workdir).mkdir(parents=True, exist_ok=True)

    @property
    def input_overhead_tokens(self) -> int:
        """Input tokens Codex adds that the Consumer never sees. Measured on codex-cli 0.162 with GPT-6 models:
        ~4,200 in passthrough (built-in tool definitions and multi-agent preambles the server sends for these
        models, which no client setting removes), ~10,000 with Codex's own instructions."""
        return 5_000 if self.passthrough else 10_000

    def __call__(self, request: dict[str, Any], on_delta: Any = None) -> tuple[Any, int, int]:
        reasoning = request["options"].get("reasoning")
        effort = reasoning.get("effort") if isinstance(reasoning, dict) else request["options"].get("reasoning_effort")
        tools = dynamic_tools(request)
        if self.passthrough or tools:
            instructions, history, prompt = conversation_of(request)
        else:
            (prompt, instructions), history = prompt_of(request), []
        calls: list[dict[str, Any]] = []
        with self._slots:
            text, input_tokens, output_tokens = self.turn(request["model"], prompt, instructions, effort=effort,
                                                          on_delta=on_delta, history=history, tools=tools, calls=calls)
        return shape_output(request, text, input_tokens, output_tokens, calls), input_tokens, output_tokens

    def _thread_params(self, model: str, instructions: str | None, tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        thread: dict[str, Any] = {
            "model": model, "cwd": self.workdir, "approvalPolicy": "never", "sandbox": "read-only",
            "ephemeral": True,
            "config": {"web_search": "disabled", "mcp_servers": {}, "plugins": {},
                       "features": {name: False for name in DISABLED_FEATURES}},
        }
        if self.passthrough:
            thread["baseInstructions"] = instructions or ""
            thread["config"].update(LEAN_CONFIG)
        elif instructions:
            thread["developerInstructions"] = instructions
        if tools:
            thread["dynamicTools"] = tools
        return thread

    def _turn_params(self, thread_id: str, model: str, prompt: str | list[dict[str, Any]], effort: Any) -> dict[str, Any]:
        items = prompt if isinstance(prompt, list) else [{"type": "text", "text": prompt, "text_elements": []}]
        turn = {"threadId": thread_id, "input": items,
                "cwd": self.workdir, "approvalPolicy": "never", "model": model}
        if effort in {"minimal", "low", "medium", "high", "xhigh"}:
            turn["effort"] = effort
        return turn

    def available_models(self) -> set[str]:
        """The models this ChatGPT account may use through Codex (the app-server's model/list)."""
        if self.resident:
            server = self._acquire()
            try:
                listed = server.call("model/list", {})
            finally:
                self._release(server)
        else:
            server = _AppServer(self.command, self.codex_home, time.monotonic() + 60)
            try:
                server.request("initialize", {"clientInfo": {"name": "mycomesh-provider", "version": "11"},
                                              "capabilities": {"experimentalApi": True}})
                listed = server.request("model/list", {})
            finally:
                server.close()
        return {str(m.get("id") or m.get("model")) for m in listed.get("data") or [] if isinstance(m, dict)}

    def warm(self) -> None:
        """Start the first resident app-server now rather than on the first request."""
        if self.resident:
            self._release(self._acquire())

    def _acquire(self) -> _SharedServer:
        with self._pool_lock:
            for server in [s for s in self._pool if s.dead or s.process.poll() is not None]:
                self._pool.remove(server)
                if server.active == 0:
                    threading.Thread(target=server.close, daemon=True).start()
            open_servers = [s for s in self._pool if s.served < self.recycle_after and s.active < self.threads_per_server]
            if open_servers:
                server = min(open_servers, key=lambda s: s.active)
            else:
                server = _SharedServer(self.command, self.codex_home)
                self._pool.append(server)
            server.active += 1
            server.served += 1
            spare = server.served == self.recycle_after and len(self._pool) == 1
        if spare:  # its last turn: start the next process now, so no request waits for one
            threading.Thread(target=self._add_spare, daemon=True).start()
        return server

    def _add_spare(self) -> None:
        try:
            server = _SharedServer(self.command, self.codex_home)
        except BackendError:
            return  # the next request starts one
        with self._pool_lock:
            self._pool.append(server)

    def _release(self, server: _SharedServer) -> None:
        with self._pool_lock:
            server.active -= 1
            retire = server.active == 0 and (server.dead or server.served >= self.recycle_after)
            if retire and server in self._pool:
                self._pool.remove(server)
        if retire:
            threading.Thread(target=server.close, daemon=True).start()

    def close(self) -> None:
        with self._pool_lock:
            servers, self._pool = self._pool, []
        for server in servers:
            server.close()

    def turn(self, model: str, prompt: str, instructions: str | None, *, effort: Any = None,
             on_delta: Any = None, history: list[dict[str, Any]] | None = None, tools: list[dict[str, Any]] | None = None,
             calls: list[dict[str, Any]] | None = None) -> tuple[str, int, int]:
        if self.resident:
            return self._resident_turn(model, prompt, instructions, effort, on_delta, history or [], tools or [], calls)
        server = _AppServer(self.command, self.codex_home, time.monotonic() + self.timeout)
        try:
            server.request("initialize", {"clientInfo": {"name": "mycomesh-provider", "version": "11"},
                                          "capabilities": {"experimentalApi": True}})
            thread_id = server.request("thread/start", self._thread_params(model, instructions, tools))["thread"]["id"]
            if history:
                server.request("thread/inject_items", {"threadId": thread_id, "items": history})
            turn_id = server.request("turn/start", self._turn_params(thread_id, model, prompt, effort))["turn"]["id"]
            stop = lambda: server.send({"jsonrpc": "2.0", "id": 0, "method": "turn/interrupt",  # noqa: E731
                                        "params": {"threadId": thread_id, "turnId": turn_id}})
            return self._collect(server, thread_id, turn_id, on_delta, calls=calls, interrupt=stop)
        finally:
            server.close()

    def _resident_turn(self, model: str, prompt: str, instructions: str | None, effort: Any, on_delta: Any,
                       history: list[dict[str, Any]], tools: list[dict[str, Any]],
                       calls: list[dict[str, Any]] | None) -> tuple[str, int, int]:
        deadline = time.monotonic() + self.timeout
        server = self._acquire()
        thread_id = turn_id = None
        try:
            thread_id = server.call("thread/start", self._thread_params(model, instructions, tools),
                                    deadline - time.monotonic())["thread"]["id"]
            reader = server.subscribe(thread_id, deadline)
            if history:
                server.call("thread/inject_items", {"threadId": thread_id, "items": history}, deadline - time.monotonic())
            turn_id = server.call("turn/start", self._turn_params(thread_id, model, prompt, effort),
                                  deadline - time.monotonic())["turn"]["id"]
            current = turn_id
            stop = lambda: server.notify("turn/interrupt", {"threadId": thread_id, "turnId": current})  # noqa: E731
            result = self._collect(reader, thread_id, turn_id, on_delta, calls=calls, interrupt=stop)
            turn_id = None
            return result
        finally:
            if thread_id is not None:
                if turn_id is not None:  # timed out or failed mid-turn: stop the model
                    server.notify("turn/interrupt", {"threadId": thread_id, "turnId": turn_id})
                server.unsubscribe(thread_id)
            self._release(server)

    @staticmethod
    def _collect(server: _AppServer, thread_id: str, turn_id: str, on_delta: Any = None, *,
                 calls: list[dict[str, Any]] | None = None, interrupt: Any = None) -> tuple[str, int, int]:
        """The turn's answer: every agent message of the turn, in order, separated by a blank line. A turn can
        hold several (a remark, then the answer); the answer is all of them, so the streamed text and the
        receipted text are always the same. When the model calls the Consumer's tools (``calls`` collects
        them), the turn is stopped once its token usage is in: the calls are the answer, and the Consumer's
        next request brings their results."""
        messages: list[list[str]] = []  # per agent message item, its text
        item_ids: list[str] = []
        usage: dict[str, Any] | None = None
        called_at: float | None = None
        stopping = False

        def piece(item_id: str, text: str) -> None:
            if not item_ids or item_ids[-1] != item_id:
                if messages and on_delta is not None:
                    on_delta("\n\n")
                item_ids.append(item_id)
                messages.append([])
            messages[-1].append(text)
            if on_delta is not None and text:
                on_delta(text)

        def stop() -> None:
            nonlocal stopping
            if not stopping and interrupt is not None:
                stopping = True
                interrupt()

        while True:
            if called_at is not None and not stopping and time.monotonic() - called_at > USAGE_AFTER_CALL_SECONDS:
                stop()  # no usage report came: end the turn anyway (it is reported on the way out, if at all)
            message = server.read(1.0) if called_at is not None and isinstance(server, _ThreadReader) else server.read()
            if message is None:
                continue
            method = message.get("method")
            params = message.get("params") or {}
            if method == TOOL_CALL and calls is not None:
                if params.get("threadId") == thread_id:
                    calls.append(tool_call(params.get("callId") or f"call_{len(calls)}", params.get("tool", ""),
                                           params.get("arguments") if params.get("arguments") is not None else {}))
                    called_at = called_at or time.monotonic()
                continue
            if method == "error":
                if params.get("willRetry"):
                    continue
                raise BackendError(f"Codex error: {str(params.get('message') or params)[:300]}")
            if params.get("threadId") not in {None, thread_id} or params.get("turnId") not in {None, turn_id}:
                continue
            if method == "item/agentMessage/delta":
                piece(str(params.get("itemId") or (item_ids[-1] if item_ids else "item")), str(params.get("delta", "")))
            elif method == "item/completed" and (params.get("item") or {}).get("type") == "agentMessage":
                item = params["item"]
                item_id = str(item.get("id") or (item_ids[-1] if item_ids else "item"))
                streamed = "".join(messages[item_ids.index(item_id)]) if item_id in item_ids else None
                text = str(item.get("text", ""))
                if streamed is None:
                    piece(item_id, text)  # a message that arrived whole
                elif text.startswith(streamed) and text != streamed:
                    piece(item_id, text[len(streamed):])  # deltas lost on the way: send the rest
            elif method == "thread/tokenUsage/updated":
                usage = (params.get("tokenUsage") or {}).get("total")
                if called_at is not None:
                    stop()  # parallel calls arrive together, before the usage of the response that made them
            elif method == "turn/completed" and (params.get("turn") or {}).get("id") == turn_id:
                status = params["turn"].get("status")
                if status != "completed" and not (status == "interrupted" and calls):
                    error = params["turn"].get("error")
                    raise BackendError(f"Codex turn {status}: {error.get('message') if isinstance(error, dict) else error}")
                if not isinstance(usage, dict):
                    raise BackendError("Codex reported no token usage")
                return ("\n\n".join("".join(parts) for parts in messages),
                        int(usage.get("inputTokens") or 0), int(usage.get("outputTokens") or 0))
