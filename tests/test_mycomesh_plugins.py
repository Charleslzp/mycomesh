"""Provider backend plugins: registered by name, loaded from a directory or a module, or any program via exec."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
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
