"""Provider backend plugins: registered by name, loaded from a directory or a module, or any program via exec."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

from mycomesh.provider import plugins
from mycomesh.provider.backends import BackendError

REQUEST = {"endpoint": "responses", "model": "m", "input": "hello", "max_output_tokens": 50, "options": {}}
CHAT = {"endpoint": "chat", "model": "m", "messages": [{"role": "user", "content": "hi"}], "max_output_tokens": 50,
        "options": {}}

STREAMING_PROGRAM = textwrap.dedent("""
    import json, sys
    request = json.loads(sys.stdin.readline())
    print("noise on stderr", file=sys.stderr)
    text = "plugin says " + str(request.get("input") or request["messages"][-1]["content"])
    for word in text.split(" "):
        print(json.dumps({"delta": word + " "}), flush=True)
    print(json.dumps({"output_text": text, "input_tokens": 7, "output_tokens": 3}))
""")


class PluginTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.context = plugins.Context(timeout=20)

    def test_built_ins_are_listed(self) -> None:
        names = {plugin.name for plugin in plugins.available()}
        self.assertTrue({"codex", "openai", "anthropic", "exec"} <= names)

    def test_a_python_file_in_the_plugin_directory_becomes_a_backend(self) -> None:
        (self.dir / "shout.py").write_text(textwrap.dedent("""
            from mycomesh.provider.plugins import register, shape_output

            @register("shout", description="answers in capitals")
            def make(options, context):
                suffix = options.get("suffix", "")
                def backend(request, on_delta=None):
                    text = str(request["input"]).upper() + suffix
                    return shape_output(request, text, 1, 2), 1, 2
                return backend
        """))
        (self.dir / "broken.py").write_text("raise RuntimeError('a broken plugin')\n")  # must not stop the others
        backend = plugins.create("shout", {"suffix": "!"}, self.context, plugin_dir=self.dir)
        output, input_tokens, output_tokens = backend(REQUEST)
        self.assertEqual((output["output_text"], input_tokens, output_tokens), ("HELLO!", 1, 2))
        self.assertIn("shout", {plugin.name for plugin in plugins.available(self.dir)})

    def test_module_factory_and_unknown_names(self) -> None:
        module = self.dir / "acme_backend.py"
        module.write_text("def factory(options, context):\n    return lambda request, on_delta=None: ({'output_text': 'acme'}, 1, 1)\n")
        sys.path.insert(0, str(self.dir))
        self.addCleanup(sys.path.remove, str(self.dir))
        backend = plugins.create("acme_backend:factory", {}, self.context)
        self.assertEqual(backend(REQUEST)[0]["output_text"], "acme")
        with self.assertRaises(ValueError) as unknown:
            plugins.create("nope", {}, self.context)
        self.assertIn("available", str(unknown.exception))

    def test_options_read_secrets_from_the_environment(self) -> None:
        os.environ["PLUGIN_TEST_TOKEN"] = "s3cret"
        self.addCleanup(os.environ.pop, "PLUGIN_TEST_TOKEN")
        self.assertEqual(plugins.resolve_options(["token=env:PLUGIN_TEST_TOKEN", "url=http://x=y"]),
                         {"token": "s3cret", "url": "http://x=y"})
        with self.assertRaises(ValueError):
            plugins.resolve_options(["token=env:PLUGIN_TEST_MISSING"])
        with self.assertRaises(ValueError):
            plugins.resolve_options(["no-equals-sign"])

    def test_exec_runs_any_program_and_streams(self) -> None:
        program = self.dir / "answer.py"
        program.write_text(STREAMING_PROGRAM)
        backend = plugins.create("exec", {"command": f"{sys.executable} {program}"}, self.context)
        deltas: list[str] = []
        output, input_tokens, output_tokens = backend(REQUEST, on_delta=deltas.append)
        self.assertEqual(output["output_text"], "plugin says hello")
        self.assertEqual("".join(deltas).strip(), "plugin says hello")
        self.assertEqual((input_tokens, output_tokens), (7, 3))
        chat, _, _ = backend(CHAT)
        self.assertEqual(chat["choices"][0]["message"]["content"], "plugin says hi")

    def test_exec_failures_fail_the_request(self) -> None:
        failing = self.dir / "fail.py"
        failing.write_text("import json, sys\nsys.stdin.readline()\nprint(json.dumps({'error': 'quota exhausted'}))\n")
        with self.assertRaises(BackendError) as error:
            plugins.create("exec", {"command": f"{sys.executable} {failing}"}, self.context)(REQUEST)
        self.assertIn("quota exhausted", str(error.exception))
        silent = self.dir / "silent.py"
        silent.write_text("import sys\nsys.stdin.readline()\nprint('oops', file=sys.stderr)\nsys.exit(2)\n")
        with self.assertRaises(BackendError) as error:
            plugins.create("exec", {"command": f"{sys.executable} {silent}"}, self.context)(REQUEST)
        self.assertIn("oops", str(error.exception))
        with self.assertRaises(ValueError):
            plugins.create("exec", {}, self.context)


if __name__ == "__main__":
    unittest.main()


class GeminiBackendTest(unittest.TestCase):
    """The gemini built-in against a stand-in Generative Language API."""

    def test_generate_and_stream(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = []

        class Fake(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: D401
                pass

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((self.path, self.headers.get("x-goog-api-key"), body))
                usage = {"promptTokenCount": 5, "candidatesTokenCount": 2, "thoughtsTokenCount": 1}
                if "streamGenerateContent" in self.path:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    for piece in ("he", "llo"):
                        self.wfile.write(f"data: {json.dumps({'candidates': [{'content': {'parts': [{'text': piece}]}}]})}\n\n".encode())
                    self.wfile.write(f"data: {json.dumps({'candidates': [{'content': {'parts': []}, 'finishReason': 'STOP'}], 'usageMetadata': usage})}\n\n".encode())
                    return
                data = json.dumps({"candidates": [{"content": {"parts": [{"text": "think", "thought": True}, {"text": "hello"}]}}],
                                   "usageMetadata": usage}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        os.environ["GEMINI_TEST_KEY"] = "g-key"
        self.addCleanup(os.environ.pop, "GEMINI_TEST_KEY")
        backend = plugins.create("gemini", {"api_key_env": "GEMINI_TEST_KEY",
                                            "base_url": f"http://127.0.0.1:{server.server_address[1]}/v1beta"}, plugins.Context())
        chat = {"endpoint": "chat", "model": "gemini-2.5-pro", "max_output_tokens": 64, "options": {"temperature": 0},
                "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]}
        output, input_tokens, output_tokens = backend(chat)
        self.assertEqual((output["choices"][0]["message"]["content"], input_tokens, output_tokens), ("hello", 5, 3))
        path, key, body = seen[-1]
        self.assertEqual((path, key), ("/v1beta/models/gemini-2.5-pro:generateContent", "g-key"))
        self.assertEqual(body["systemInstruction"], {"parts": [{"text": "be brief"}]})
        self.assertEqual(body["generationConfig"], {"maxOutputTokens": 64, "temperature": 0})
        deltas = []
        output, _, output_tokens = backend(REQUEST | {"model": "gemini-2.5-pro"}, on_delta=deltas.append)
        self.assertEqual((output["output_text"], "".join(deltas), output_tokens), ("hello", "hello", 3))
        self.assertIn("alt=sse", seen[-1][0])


from tests.mycomesh_anvil import CONSUMER_KEY, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available  # noqa: E402


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class PluginEndToEndTest(unittest.TestCase):
    """A Provider whose model is an arbitrary program serves a paid, verified, settled request."""

    def test_exec_backend_serves_and_settles(self) -> None:
        from mycomesh.consumer import open_response, prepare_request
        from mycomesh.evm import address_of
        from mycomesh.identity import create_identity
        from mycomesh.protocol import Prices
        from mycomesh.provider.worker import ProviderWorker
        from mycomesh.relay.core import RelayCore

        chain = AnvilV11()
        self.addCleanup(chain.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        program = Path(tmp.name) / "model.py"
        program.write_text(STREAMING_PROGRAM)
        backend = plugins.create("exec", {"command": f"{sys.executable} {program}"}, plugins.Context(timeout=30))
        worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=chain.deployment,
                                backend=backend, prices=Prices(1_000, 4_000, 100), models=("my-model",),
                                data_dir=Path(tmp.name) / "provider")
        relay = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, Path(tmp.name) / "relay")
        now = chain.now()
        relay.register_provider(worker.descriptor(now), lambda job: worker.handle_job(job, now=chain.now()), now=now)
        prepared = prepare_request(descriptor=relay.provider_descriptors()[0], deployment=chain.deployment,
                                   key_private=CONSUMER_KEY, relay_signer=address_of(RELAY_SIGNER), endpoint="responses",
                                   model="my-model", content="from a plugin", max_output_tokens=50, max_fee=1_000_000, now=now)
        response, signed = open_response(prepared, relay.handle_request(prepared.payload, now=now), chain.deployment)
        self.assertEqual(response["output"]["output_text"], "plugin says from a plugin")
        self.assertEqual((signed.receipt.input_tokens, signed.receipt.output_tokens), (7, 3))
        self.assertTrue(relay.settle_queued(chain.relay, chain.rpc))
        self.assertTrue(chain.reader.is_settled(signed.authorization.settlement_key))


class CodexSessionCleanupTest(unittest.TestCase):
    """A Codex session is a Node wrapper plus the native app-server it spawns: closing must end both."""

    def test_close_kills_the_wrapper_and_its_child(self) -> None:
        import subprocess
        import time as _time
        from mycomesh.provider.codex import _AppServer

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pid_file = Path(tmp.name) / "child.pid"
        wrapper = Path(tmp.name) / "codex"
        # Like codex.js: spawn the real server with inherited stdio, ignore stdin EOF, keep running.
        wrapper.write_text(f"#!/bin/sh\nsleep 300 < /dev/null &\necho $! > {pid_file}\nwait\n")
        wrapper.chmod(0o755)
        server = _AppServer(str(wrapper), tmp.name, _time.monotonic() + 60)
        deadline = _time.monotonic() + 5
        while not pid_file.exists() and _time.monotonic() < deadline:
            _time.sleep(0.05)
        child = int(pid_file.read_text())
        server.close()
        _time.sleep(0.2)
        alive = subprocess.run(["ps", "-p", str(child), "-o", "stat="], capture_output=True, text=True).stdout.strip()
        self.assertTrue(alive == "" or alive.startswith("Z"), f"app-server child still running: {alive!r}")


class CodexCollectTest(unittest.TestCase):
    """A Codex turn with two agent messages: the streamed text and the answer must be identical."""

    def test_streamed_text_equals_the_answer(self) -> None:
        from mycomesh.provider.codex import CodexBackend

        events = [
            {"method": "item/agentMessage/delta", "params": {"threadId": "t", "turnId": "u", "itemId": "a", "delta": "Let me "}},
            {"method": "item/agentMessage/delta", "params": {"threadId": "t", "turnId": "u", "itemId": "a", "delta": "check."}},
            {"method": "item/completed", "params": {"threadId": "t", "turnId": "u", "item": {"type": "agentMessage", "id": "a", "text": "Let me check."}}},
            {"method": "item/agentMessage/delta", "params": {"threadId": "t", "turnId": "u", "itemId": "b", "delta": "42"}},
            {"method": "item/completed", "params": {"threadId": "t", "turnId": "u", "item": {"type": "agentMessage", "id": "b", "text": "42 indeed"}}},
            {"method": "item/completed", "params": {"threadId": "t", "turnId": "u", "item": {"type": "agentMessage", "id": "c", "text": "Done."}}},
            {"method": "thread/tokenUsage/updated", "params": {"threadId": "t", "tokenUsage": {"total": {"inputTokens": 9, "outputTokens": 4}}}},
            {"method": "turn/completed", "params": {"threadId": "t", "turn": {"id": "u", "status": "completed"}}},
        ]

        class Server:
            def read(self):
                return events.pop(0)

        streamed: list[str] = []
        text, input_tokens, output_tokens = CodexBackend._collect(Server(), "t", "u", streamed.append)
        self.assertEqual(text, "Let me check.\n\n42 indeed\n\nDone.")
        self.assertEqual("".join(streamed), text)
        self.assertEqual((input_tokens, output_tokens), (9, 4))


class ToolTranslationTest(unittest.TestCase):
    def test_anthropic_messages_carry_tool_use_and_merged_tool_results(self) -> None:
        from mycomesh.provider.backends import anthropic_messages

        out = anthropic_messages([
            {"role": "user", "content": "ls"},
            {"role": "assistant", "content": "ok", "tool_calls": [{"id": "a", "type": "function", "function": {"name": "Bash", "arguments": '{"c":1}'}},
                                                                  {"id": "b", "type": "function", "function": {"name": "Bash", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "a", "content": "x"}, {"role": "tool", "tool_call_id": "b", "content": "y"}])
        self.assertEqual(out[1]["content"][1], {"type": "tool_use", "id": "a", "name": "Bash", "input": {"c": 1}})
        self.assertEqual(out[2], {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a", "content": "x"},
                                                             {"type": "tool_result", "tool_use_id": "b", "content": "y"}]})

    def test_openai_streamed_tool_calls_are_assembled(self) -> None:
        import http.server
        from mycomesh.provider.backends import OpenAICompatibleBackend

        events = [{"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "sh", "arguments": '{"cm'}}]}}]},
                  {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": 'd":"ls"}'}}]}, "finish_reason": "tool_calls"}]},
                  {"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 3}}]

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):  # noqa: N802
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
                for event in events:
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        backend = OpenAICompatibleBackend(f"http://127.0.0.1:{server.server_address[1]}")
        output, i, o = backend({"endpoint": "chat", "model": "m", "messages": [], "max_output_tokens": 9, "options": {}}, lambda d: None)
        self.assertEqual(output["choices"][0]["message"]["tool_calls"], [{"id": "c1", "type": "function", "function": {"name": "sh", "arguments": '{"cmd":"ls"}'}}])
        self.assertEqual((output["choices"][0]["finish_reason"], i, o), ("tool_calls", 7, 3))

    def test_the_worst_case_price_counts_tool_definitions(self) -> None:
        from mycomesh.protocol import worst_case_tokens

        document = {"endpoint": "chat", "messages": [{"role": "user", "content": "hi"}], "max_output_tokens": 10, "options": {}}
        bare = worst_case_tokens(document)[0]
        document["options"]["tools"] = [{"type": "function", "function": {"name": "t", "description": "x" * 3000}}]
        self.assertGreater(worst_case_tokens(document)[0], bare + 999)


FAKE_APP_SERVER = r'''#!/usr/bin/env python3
# A stand-in for `codex app-server --stdio`: answers "echo: <prompt>" after a delay, one thread per request.
import json, os, sys, threading, time
log = open(os.environ["CODEX_HOME"] + "/requests.jsonl", "a")
lock = threading.Lock()
def send(message):
    with lock:
        sys.stdout.write(json.dumps(message) + "\n"); sys.stdout.flush()
def run_turn(thread, turn, prompt):
    if prompt == "die":
        os._exit(1)
    if prompt == "hang":
        return
    time.sleep(0.3)
    for piece in ("echo: ", prompt):
        send({"method": "item/agentMessage/delta", "params": {"threadId": thread, "turnId": turn, "itemId": "a", "delta": piece}})
    send({"method": "thread/tokenUsage/updated", "params": {"threadId": thread, "tokenUsage": {"total": {"inputTokens": 5, "outputTokens": 2}}}})
    send({"method": "turn/completed", "params": {"threadId": thread, "turn": {"id": turn, "status": "completed"}}})
count = 0
tools = {}
for line in sys.stdin:
    message = json.loads(line)
    log.write(json.dumps({"pid": os.getpid(), **message}) + "\n"); log.flush()
    method, params = message.get("method"), message.get("params") or {}
    if method == "thread/start":
        count += 1
        tools[f"t{os.getpid()}-{count}"] = params.get("dynamicTools") or []
        send({"id": message["id"], "result": {"thread": {"id": f"t{os.getpid()}-{count}"}}})
    elif method == "turn/start":
        turn = params["threadId"] + "-turn"
        send({"id": message["id"], "result": {"turn": {"id": turn}}})
        if "weather" in params["input"][0]["text"] and tools.get(params["threadId"]):
            # The model calls the Consumer's tool twice in parallel, then reports the response's usage.
            for city in ("Paris", "Tokyo"):
                send({"id": 1000 + len(city), "method": "item/tool/call", "params": {"threadId": params["threadId"], "turnId": turn,
                      "callId": "call_" + city, "tool": tools[params["threadId"]][0]["name"], "arguments": {"city": city}}})
            send({"method": "thread/tokenUsage/updated", "params": {"threadId": params["threadId"], "tokenUsage": {"total": {"inputTokens": 40, "outputTokens": 9}}}})
            continue
        threading.Thread(target=run_turn, args=(params["threadId"], turn, params["input"][0]["text"])).start()
    elif method == "turn/interrupt":
        send({"id": message["id"], "result": {}})
        send({"method": "turn/completed", "params": {"threadId": params["threadId"], "turn": {"id": params["turnId"], "status": "interrupted"}}})
    else:
        send({"id": message["id"], "result": {}})
'''


class CodexResidentTest(unittest.TestCase):
    """Resident app-servers: concurrent threads on one process, passthrough parameters, recovery, timeouts."""

    def setUp(self) -> None:
        from mycomesh.provider.codex import CodexBackend

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        command = self.home / "codex"
        command.write_text(FAKE_APP_SERVER.replace("#!/usr/bin/env python3", f"#!{sys.executable}"))
        command.chmod(0o755)
        self.backend = CodexBackend(codex_home=str(self.home), command=str(command), workdir=str(self.home / "work"),
                                    timeout=10, max_concurrent=16)
        self.addCleanup(self.backend.close)

    def requests(self) -> list[dict]:
        return [json.loads(line) for line in (self.home / "requests.jsonl").read_text().splitlines()]

    def chat(self, messages: list[dict]) -> dict:
        return {"endpoint": "chat", "model": "gpt-5.5", "messages": messages, "options": {}, "max_output_tokens": 100}

    def test_concurrent_turns_share_one_process(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        self.backend.warm()
        with ThreadPoolExecutor(8) as pool:
            answers = list(pool.map(lambda i: self.backend(self.chat([{"role": "user", "content": f"q{i}"}]))[0]["choices"][0]["message"]["content"],
                                    range(8)))
        self.assertEqual(answers, [f"echo: q{i}" for i in range(8)])
        self.assertEqual(len({r["pid"] for r in self.requests()}), 1)
        self.assertEqual(sum(r.get("method") == "thread/unsubscribe" for r in self.requests()), 8)

    def test_passthrough_sends_the_consumers_conversation(self) -> None:
        output, input_tokens, output_tokens = self.backend(self.chat([
            {"role": "system", "content": "Be terse."}, {"role": "user", "content": "My name is Li."},
            {"role": "assistant", "content": "Hi Li."}, {"role": "user", "content": "Name?"}]))
        self.assertEqual((output["choices"][0]["message"]["content"], input_tokens, output_tokens), ("echo: Name?", 5, 2))
        start = next(r for r in self.requests() if r.get("method") == "thread/start")["params"]
        self.assertEqual(start["baseInstructions"], "Be terse.")
        self.assertNotIn("developerInstructions", start)
        self.assertFalse(start["config"]["include_environment_context"])
        injected = next(r for r in self.requests() if r.get("method") == "thread/inject_items")["params"]["items"]
        self.assertEqual([(i["role"], i["content"][0]["type"], i["content"][0]["text"]) for i in injected],
                         [("user", "input_text", "My name is Li."), ("assistant", "output_text", "Hi Li.")])
        self.assertEqual(self.backend.input_overhead_tokens, 1_000)

    def test_a_crashed_process_fails_its_turn_and_is_replaced(self) -> None:
        from mycomesh.provider.backends import BackendError

        with self.assertRaisesRegex(BackendError, "exited"):
            self.backend(self.chat([{"role": "user", "content": "die"}]))
        self.assertEqual(self.backend(self.chat([{"role": "user", "content": "again"}]))[0]["choices"][0]["message"]["content"], "echo: again")
        self.assertEqual(len({r["pid"] for r in self.requests()}), 2)

    def test_a_timed_out_turn_is_interrupted(self) -> None:
        from mycomesh.provider.backends import BackendError

        self.backend.timeout = 1
        with self.assertRaisesRegex(BackendError, "timed out"):
            self.backend(self.chat([{"role": "user", "content": "hang"}]))
        time.sleep(0.2)
        self.assertTrue(any(r.get("method") == "turn/interrupt" for r in self.requests()))
        self.backend.timeout = 10
        self.assertEqual(self.backend(self.chat([{"role": "user", "content": "ok"}]))[0]["choices"][0]["message"]["content"], "echo: ok")
        self.assertEqual(len({r["pid"] for r in self.requests()}), 1)  # the process lives on

    def test_the_consumers_tools_are_offered_and_their_calls_come_back(self) -> None:
        tools = [{"type": "function", "function": {"name": "get_weather", "description": "weather",
                                                   "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}}]
        request = self.chat([{"role": "user", "content": "weather in Paris and Tokyo?"}])
        request["options"] = {"tools": tools}
        output, input_tokens, output_tokens = self.backend(request)
        choice = output["choices"][0]
        self.assertEqual(choice["finish_reason"], "tool_calls")
        self.assertEqual([(c["id"], c["function"]["name"], json.loads(c["function"]["arguments"])) for c in choice["message"]["tool_calls"]],
                         [("call_Paris", "get_weather", {"city": "Paris"}), ("call_Tokyo", "get_weather", {"city": "Tokyo"})])
        self.assertEqual((input_tokens, output_tokens), (40, 9))  # the usage of the response that made the calls
        start = next(r for r in self.requests() if r.get("method") == "thread/start")["params"]
        self.assertEqual(start["dynamicTools"], [{"type": "function", "name": "get_weather", "description": "weather",
                                                  "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}}}])
        self.assertTrue(any(r.get("method") == "turn/interrupt" for r in self.requests()))
        self.assertFalse(any(r.get("id") in (1005, 1009) for r in self.requests()))  # the calls were never answered here

        # The next request brings the results: they go in as history, and the model goes on from them.
        follow = self.chat([{"role": "user", "content": "weather in Paris and Tokyo?"},
                            {"role": "assistant", "content": None, "tool_calls": choice["message"]["tool_calls"]},
                            {"role": "tool", "tool_call_id": "call_Paris", "content": "17C"},
                            {"role": "tool", "tool_call_id": "call_Tokyo", "content": "22C"}])
        follow["options"] = {"tools": tools}
        self.assertEqual(self.backend(follow)[0]["choices"][0]["message"]["content"], "echo: ")
        injected = [r for r in self.requests() if r.get("method") == "thread/inject_items"][-1]["params"]["items"]
        self.assertEqual([i["type"] for i in injected], ["message", "function_call", "function_call", "function_call_output", "function_call_output"])
        self.assertEqual(injected[3], {"type": "function_call_output", "call_id": "call_Paris", "output": "17C"})

    def test_a_worn_process_is_replaced_without_a_cold_start(self) -> None:
        self.backend.recycle_after = 3
        for i in range(3):
            self.backend(self.chat([{"role": "user", "content": f"q{i}"}]))
        time.sleep(1)
        self.assertEqual(len(self.backend._pool), 1)  # the worn process retired, the spare in its place
        self.assertEqual(self.backend._pool[0].served, 0)
        self.assertEqual(self.backend(self.chat([{"role": "user", "content": "next"}]))[0]["choices"][0]["message"]["content"],
                         "echo: next")
