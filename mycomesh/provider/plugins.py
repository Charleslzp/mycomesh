"""Provider backends as plugins: add a model source without touching MycoMesh.

A backend is any callable

    backend(request: dict, on_delta=None) -> (output, input_tokens, output_tokens)

``request`` is the V11 request document (``endpoint`` "responses" or "chat", ``model``, ``input`` or
``messages``, ``max_output_tokens``, ``options``). ``output`` is an OpenAI-shaped response (build it
with ``shape_output``) or a dict with ``output_text``; the token counts set the fee at the network
price. A backend that sets ``streams = True`` receives ``on_delta(text)`` to stream its answer.

Backends are made by factories registered under a name:

    from mycomesh.provider.plugins import register, shape_output

    @register("echo", description="answers with the question")
    def make_echo(options, context):
        def backend(request, on_delta=None):
            text = str(request.get("input"))
            return shape_output(request, text, len(text) // 4, len(text) // 4), len(text) // 4, len(text) // 4
        return backend

``options`` are the ``--backend-option KEY=VALUE`` strings (a value ``env:NAME`` reads the environment
variable NAME, so secrets never appear in arguments); ``context`` carries ``timeout``, ``capacity`` and
``data_dir``. A factory finds plugins in three places:

* built in: ``codex``, ``openai``, ``anthropic`` and ``exec`` (any program, in any language);
* Python files in a plugin directory (``--plugin-dir``; the launcher mounts ~/.mycomesh/provider/plugins);
* installed packages exposing the entry point group ``mycomesh.backends``, or ``--backend package.module:factory``.

``exec`` runs a command per request: the request document arrives as one JSON line on stdin; the
program writes JSON lines to stdout, ``{"delta": "..."}`` while streaming (optional) and finally
``{"output_text": "...", "input_tokens": N, "output_tokens": M}``. A non-zero exit or
``{"error": "..."}`` fails the request. Keep such programs in ``plugins/bin/``: every ``*.py`` directly
in the plugin directory is imported as a Python plugin. Templates: examples/provider-plugins.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .backends import BackendError, shape_output

Factory = Callable[[Mapping[str, str], "Context"], Any]
ENTRY_POINT_GROUP = "mycomesh.backends"

__all__ = ["BackendError", "Context", "available", "create", "load_plugin_dir", "register", "shape_output"]


@dataclass(frozen=True)
class Context:
    timeout: float = 300.0
    capacity: int = 1
    data_dir: Path = Path("data")


@dataclass(frozen=True)
class Plugin:
    name: str
    factory: Factory
    description: str = ""
    source: str = "built-in"


_REGISTRY: dict[str, Plugin] = {}
_lock = threading.Lock()


def register(name: str, *, description: str = "") -> Callable[[Factory], Factory]:
    """Decorator: make ``factory`` available as ``--backend name``."""
    def decorate(factory: Factory) -> Factory:
        module = getattr(factory, "__module__", "")
        source = "built-in" if module.startswith("mycomesh.") else module
        with _lock:
            _REGISTRY[name] = Plugin(name, factory, description or (factory.__doc__ or "").strip().split("\n")[0], source)
        return factory
    return decorate


def load_plugin_dir(directory: str | Path) -> list[str]:
    """Import every ``*.py`` in a directory; each registers its backends. Returns the names added."""
    before = set(_REGISTRY)
    path = Path(directory)
    if not path.is_dir():
        return []
    for file in sorted(path.glob("*.py")):
        spec = importlib.util.spec_from_file_location(f"mycomesh_plugin_{file.stem}", file)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # one broken plugin must not stop the Provider from serving the others
            print(f"mycomesh: plugin {file} failed to load: {exc}", file=sys.stderr)
            sys.modules.pop(spec.name, None)
    return sorted(set(_REGISTRY) - before)


def _load_entry_points() -> None:
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover
        return
    try:
        found = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # Python < 3.10 API
        found = entry_points().get(ENTRY_POINT_GROUP, [])
    for entry in found:
        if entry.name not in _REGISTRY:
            try:
                register(entry.name)(entry.load())
            except Exception as exc:
                print(f"mycomesh: backend {entry.name} failed to load: {exc}", file=sys.stderr)


def available(plugin_dir: str | Path | None = None) -> list[Plugin]:
    if plugin_dir:
        load_plugin_dir(plugin_dir)
    _load_entry_points()
    return sorted(_REGISTRY.values(), key=lambda plugin: (plugin.source != "built-in", plugin.name))


def resolve_options(pairs: list[str] | None) -> dict[str, str]:
    """``KEY=VALUE`` strings; ``env:NAME`` values are read from the environment."""
    options: dict[str, str] = {}
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise ValueError(f"--backend-option needs KEY=VALUE, got {pair!r}")
        if value.startswith("env:"):
            name = value[4:]
            if name not in os.environ:
                raise ValueError(f"backend option {key} reads ${name}, which is not set")
            value = os.environ[name]
        options[key] = value
    return options


def create(name: str, options: Mapping[str, str], context: Context, *, plugin_dir: str | Path | None = None) -> Any:
    """The backend ``name`` with its options: built in, from the plugin directory, installed, or ``module:factory``."""
    if plugin_dir:
        load_plugin_dir(plugin_dir)
    if name not in _REGISTRY:
        _load_entry_points()
    if name not in _REGISTRY and ":" in name:
        module, _, attribute = name.partition(":")
        register(name)(getattr(importlib.import_module(module), attribute))
    plugin = _REGISTRY.get(name)
    if plugin is None:
        known = ", ".join(sorted(_REGISTRY)) or "none"
        raise ValueError(f"unknown backend {name!r} (available: {known})")
    backend = plugin.factory(dict(options), context)
    if not callable(backend):
        raise ValueError(f"backend {name!r} factory did not return a callable")
    return backend


# ---------------- built-in backends ----------------

def _api_key(options: Mapping[str, str]) -> str:
    if options.get("api_key"):
        return options["api_key"]
    name = options.get("api_key_env")
    return os.environ.get(name, "") if name else ""


@register("codex", description="OpenAI models through a ChatGPT-login Codex CLI (options: codex_home, command)")
def _codex(options: Mapping[str, str], context: Context) -> Any:
    from .codex import CodexBackend

    return CodexBackend(codex_home=options.get("codex_home", os.path.expanduser("~/.codex")),
                        command=options.get("command", "codex"), timeout=context.timeout,
                        max_concurrent=context.capacity)


@register("openai", description="any OpenAI-compatible API: OpenAI, vLLM, Ollama… (options: base_url, api_key_env)")
def _openai(options: Mapping[str, str], context: Context) -> Any:
    from .backends import OpenAICompatibleBackend

    return OpenAICompatibleBackend(options.get("base_url") or "https://api.openai.com/v1", _api_key(options),
                                   timeout=context.timeout)


@register("anthropic", description="Claude through the Anthropic Messages API (options: api_key_env, base_url)")
def _anthropic(options: Mapping[str, str], context: Context) -> Any:
    from .backends import AnthropicBackend

    extra = {"base_url": options["base_url"]} if options.get("base_url") else {}
    return AnthropicBackend(_api_key(options), timeout=context.timeout, **extra)


@dataclass
class ExecBackend:
    """Runs ``command`` per request, speaking JSON lines (see the module docstring)."""

    command: list[str]
    timeout: float = 300.0
    env: dict[str, str] = field(default_factory=dict)
    streams = True

    def __call__(self, request: dict[str, Any], on_delta: Any = None) -> tuple[Any, int, int]:
        process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env={**os.environ, **self.env})
        timer = threading.Timer(self.timeout, process.kill)
        timer.start()
        errors: list[str] = []  # drained alongside stdout, so a chatty plugin cannot block on a full pipe
        drain = threading.Thread(target=lambda: errors.append(process.stderr.read()), daemon=True)
        drain.start()
        try:
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.close()
            final = None
            for line in process.stdout:
                if not line.strip():
                    continue
                try:
                    message = json.loads(line)
                except ValueError as exc:
                    raise BackendError(f"plugin wrote a line that is not JSON: {line[:200]!r}") from exc
                if "error" in message:
                    raise BackendError(f"plugin failed: {str(message['error'])[:300]}")
                if "delta" in message:
                    if on_delta is not None and message["delta"]:
                        on_delta(str(message["delta"]))
                elif "output_text" in message:
                    final = message
            code = process.wait()
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            drain.join(timeout=1)
            process.stdout.close()
            process.stderr.close()
        if code != 0 or final is None:
            detail = "".join(errors)[-300:]
            raise BackendError(f"plugin exited {code} without an answer: {detail}")
        input_tokens, output_tokens = int(final.get("input_tokens") or 0), int(final.get("output_tokens") or 0)
        return shape_output(request, str(final["output_text"]), input_tokens, output_tokens), input_tokens, output_tokens


@register("exec", description="any program, any language, over JSON lines (options: command, env_*)")
def _exec(options: Mapping[str, str], context: Context) -> Any:
    if not options.get("command"):
        raise ValueError("the exec backend needs --backend-option command=\"program args\"")
    env = {key[4:].upper(): value for key, value in options.items() if key.startswith("env_")}
    return ExecBackend(shlex.split(options["command"]), timeout=context.timeout, env=env)


@dataclass
class GeminiBackend:
    """Gemini through the Google Generative Language API (generateContent, streamed with alt=sse)."""

    api_key: str
    base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    timeout: float = 300.0
    streams = True

    def __call__(self, request: dict[str, Any], on_delta: Any = None) -> tuple[Any, int, int]:
        from .backends import _events, _post

        if request["endpoint"] == "chat":
            messages = request["messages"]
        else:
            content = request["input"]
            messages = [{"role": "user", "content": content if isinstance(content, str) else json.dumps(content)}]
        text_of = lambda content: content if isinstance(content, str) else "".join(  # noqa: E731
            str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content or [])
        system = [text_of(m["content"]) for m in messages if isinstance(m, dict) and m.get("role") in {"system", "developer"}]
        contents = [{"role": "model" if m.get("role") == "assistant" else "user", "parts": [{"text": text_of(m.get("content"))}]}
                    for m in messages if isinstance(m, dict) and m.get("role") not in {"system", "developer"}]
        config: dict[str, Any] = {"maxOutputTokens": request["max_output_tokens"]}
        options = request["options"]
        for source, target in (("temperature", "temperature"), ("top_p", "topP"), ("stop", "stopSequences")):
            if source in options:
                config[target] = options[source]
        body: dict[str, Any] = {"contents": contents, "generationConfig": config}
        if system:
            body["systemInstruction"] = {"parts": [{"text": "\n\n".join(system)}]}
        headers = {"x-goog-api-key": self.api_key}
        base = f"{self.base_url.rstrip('/')}/models/{request['model']}"
        text, usage = [], {}
        if on_delta is not None:
            for chunk in _events(f"{base}:streamGenerateContent?alt=sse", body, headers, self.timeout):
                usage = chunk.get("usageMetadata") or usage
                for candidate in chunk.get("candidates") or []:
                    for part in (candidate.get("content") or {}).get("parts") or []:
                        if part.get("text") and not part.get("thought"):
                            text.append(part["text"])
                            on_delta(part["text"])
        else:
            result = _post(f"{base}:generateContent", body, headers, self.timeout)
            usage = result.get("usageMetadata") or {}
            for candidate in (result.get("candidates") or [])[:1]:
                text += [p["text"] for p in (candidate.get("content") or {}).get("parts") or [] if p.get("text") and not p.get("thought")]
        input_tokens = int(usage.get("promptTokenCount") or 0)
        output_tokens = int(usage.get("candidatesTokenCount") or 0) + int(usage.get("thoughtsTokenCount") or 0)
        return shape_output(request, "".join(text), input_tokens, output_tokens), input_tokens, output_tokens


@register("gemini", description="Gemini through the Google AI API (options: api_key_env, base_url)")
def _gemini(options: Mapping[str, str], context: Context) -> Any:
    extra = {"base_url": options["base_url"]} if options.get("base_url") else {}
    return GeminiBackend(_api_key(options), timeout=context.timeout, **extra)
