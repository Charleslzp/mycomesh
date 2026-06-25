from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .config import load_config


DEFAULT_AGENT_ID = "coder"
DEFAULT_RUN_DIR = ".codex-run"
KEY_PREFIX = "gwk"
PUBLIC_URL_PATTERN = re.compile(r"https://[a-zA-Z0-9.-]+\.trycloudflare\.com")


@dataclass(frozen=True)
class RuntimeProcess:
    name: str
    pid: int
    log_path: Path
    process: subprocess.Popen | None = None
    already_running: bool = False


@dataclass(frozen=True)
class ManagedKey:
    agent_id: str
    key: str

    @property
    def fingerprint(self) -> str:
        return key_fingerprint(self.key)

    @property
    def display(self) -> str:
        if len(self.key) <= 14:
            return self.key
        return f"{self.key[:10]}...{self.key[-4:]}"


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gateway-client",
        description="Manage the local Codex gateway client.",
    )
    parser.add_argument(
        "--agents-file",
        default=os.getenv("AGENTS_FILE", "agents.json"),
        help="Path to the agents config file. Defaults to AGENTS_FILE or agents.json.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login = subparsers.add_parser("login", help="Start the official Codex login flow.")
    login.add_argument(
        "--no-device-auth",
        action="store_true",
        help="Run `codex login` instead of `codex login --device-auth`.",
    )
    login.set_defaults(func=_cmd_login)

    logout = subparsers.add_parser("logout", help="Clear this gateway's isolated Codex login state.")
    logout.add_argument(
        "--yes",
        action="store_true",
        help="Do not prompt before moving auth files out of CODEX_HOME.",
    )
    logout.set_defaults(func=_cmd_logout)

    key = subparsers.add_parser("key", help="Manage gateway agent keys.")
    key_subparsers = key.add_subparsers(dest="key_command", required=True)

    key_create = key_subparsers.add_parser(
        "create",
        aliases=["generate"],
        help="Generate and store a new key for an agent.",
    )
    key_create.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Agent id to update.")
    key_create.add_argument("--role", default="worker", help="Role for a new agent.")
    key_create.add_argument("--description", help="Description for a new agent.")
    key_create.set_defaults(func=_cmd_key_create)

    key_delete = key_subparsers.add_parser("delete", help="Delete a stored agent key.")
    key_delete.add_argument("selector", help="Full key, unique key prefix, or fingerprint prefix.")
    key_delete.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Agent id to update.")
    key_delete.set_defaults(func=_cmd_key_delete)

    key_list = key_subparsers.add_parser("list", help="List stored key fingerprints.")
    key_list.add_argument("--agent", help="Only list keys for this agent.")
    key_list.set_defaults(func=_cmd_key_list)

    key_rotate = key_subparsers.add_parser(
        "rotate",
        help="Create a replacement key and remove the selected old key.",
    )
    key_rotate.add_argument("selector", help="Old full key, unique key prefix, or fingerprint prefix.")
    key_rotate.add_argument("--agent", default=DEFAULT_AGENT_ID, help="Agent id to update.")
    key_rotate.add_argument("--role", default="worker", help="Role for a new agent if missing.")
    key_rotate.add_argument("--description", help="Description for a new agent if missing.")
    key_rotate.set_defaults(func=_cmd_key_rotate)

    url = subparsers.add_parser("url", help="Print the public gateway URL if known.")
    url.add_argument(
        "--run-dir",
        default=DEFAULT_RUN_DIR,
        help="Directory containing cloudflared logs. Defaults to .codex-run.",
    )
    url.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    url.set_defaults(func=_cmd_url)

    status = subparsers.add_parser("status", help="Print local client status.")
    status.add_argument(
        "--run-dir",
        default=DEFAULT_RUN_DIR,
        help="Directory containing gateway and cloudflared runtime files.",
    )
    status.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    status.set_defaults(func=_cmd_status)

    serve = subparsers.add_parser("serve", help="Start the gateway server.")
    serve.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    serve.add_argument("--reload", action="store_true", help="Pass --reload to uvicorn.")
    serve.add_argument("--with-tunnel", action="store_true", help="Also start a Cloudflare quick tunnel.")
    serve.add_argument(
        "--tunnel-protocol",
        choices=["quic", "http2"],
        help="Optional cloudflared protocol override.",
    )
    serve.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    serve.set_defaults(func=_cmd_serve)

    tunnel = subparsers.add_parser("tunnel", help="Manage a Cloudflare quick tunnel.")
    tunnel_subparsers = tunnel.add_subparsers(dest="tunnel_command", required=True)

    tunnel_start = tunnel_subparsers.add_parser("start", help="Start a Cloudflare quick tunnel.")
    tunnel_start.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    tunnel_start.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    tunnel_start.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    tunnel_start.add_argument("--protocol", choices=["quic", "http2"], help="Optional protocol override.")
    tunnel_start.set_defaults(func=_cmd_tunnel_start)

    tunnel_stop = tunnel_subparsers.add_parser("stop", help="Stop a managed Cloudflare tunnel.")
    tunnel_stop.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    tunnel_stop.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    tunnel_stop.set_defaults(func=_cmd_tunnel_stop)

    tunnel_status = tunnel_subparsers.add_parser("status", help="Print managed tunnel status.")
    tunnel_status.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    tunnel_status.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    tunnel_status.set_defaults(func=_cmd_tunnel_status)

    health = subparsers.add_parser("health", help="Call the gateway /health endpoint.")
    health.add_argument("--url", help="Base URL or /health URL. Defaults to local gateway.")
    health.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    health.add_argument("--public", action="store_true", help="Use the discovered public tunnel URL.")
    health.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    health.add_argument("--timeout", type=float, default=5.0)
    health.set_defaults(func=_cmd_health)

    return parser


def _cmd_login(args: argparse.Namespace) -> int:
    config = load_config()
    Path(config.codex_home).mkdir(parents=True, exist_ok=True)
    command = [config.codex_command, "login"]
    if not args.no_device_auth:
        command.append("--device-auth")

    print("Starting Codex login.")
    print("Use the link printed by Codex to sign in with your Codex/OpenAI account.")
    print(f"CODEX_HOME={config.codex_home}")
    try:
        completed = subprocess.run(
            command,
            env={**os.environ, "CODEX_HOME": config.codex_home},
            check=False,
        )
    except FileNotFoundError:
        print(f"Codex command not found: {config.codex_command}", file=sys.stderr)
        return 127
    return completed.returncode


def _cmd_logout(args: argparse.Namespace) -> int:
    config = load_config()
    codex_home = Path(config.codex_home)
    auth_paths = [
        codex_home / "auth.json",
        codex_home / "login.json",
    ]
    existing = [path for path in auth_paths if path.exists()]
    if not existing:
        print("No Codex auth files found for this gateway.")
        return 0

    if not args.yes:
        print("This will move the gateway Codex auth files into a backup directory:")
        for path in existing:
            print(f"- {path}")
        answer = input("Continue? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Logout cancelled.")
            return 1

    backup_dir = codex_home / "auth-backups" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in existing:
        target = backup_dir / path.name
        path.replace(target)
        print(f"Moved {path} -> {target}")
    print("Gateway Codex login state cleared.")
    return 0


def _cmd_key_create(args: argparse.Namespace) -> int:
    key = create_agent_key(
        path=Path(args.agents_file),
        agent_id=args.agent,
        role=args.role,
        description=args.description,
    )
    print("Created gateway key.")
    print(f"agent_id: {key.agent_id}")
    print(f"api_key: {key.key}")
    print(f"fingerprint: {key.fingerprint}")
    print("Use it as `Authorization: Bearer <api_key>` or an OpenAI-compatible api_key.")
    return 0


def _cmd_key_delete(args: argparse.Namespace) -> int:
    removed = delete_agent_key(
        path=Path(args.agents_file),
        agent_id=args.agent,
        selector=args.selector,
    )
    print("Deleted gateway key.")
    print(f"agent_id: {removed.agent_id}")
    print(f"key: {removed.display}")
    print(f"fingerprint: {removed.fingerprint}")
    return 0


def _cmd_key_list(args: argparse.Namespace) -> int:
    keys = list_agent_keys(Path(args.agents_file), agent_id=args.agent)
    if not keys:
        print("No gateway keys found.")
        return 0
    for key in keys:
        print(f"{key.agent_id}\t{key.display}\t{key.fingerprint}")
    return 0


def _cmd_key_rotate(args: argparse.Namespace) -> int:
    new_key, old_key = rotate_agent_key(
        path=Path(args.agents_file),
        agent_id=args.agent,
        selector=args.selector,
        role=args.role,
        description=args.description,
    )
    print("Rotated gateway key.")
    print(f"agent_id: {new_key.agent_id}")
    print(f"old_key: {old_key.display}")
    print(f"old_fingerprint: {old_key.fingerprint}")
    print(f"new_api_key: {new_key.key}")
    print(f"new_fingerprint: {new_key.fingerprint}")
    print("Restart an already running gateway so the new key config is loaded.")
    return 0


def _cmd_url(args: argparse.Namespace) -> int:
    public_url = discover_public_url(Path(args.run_dir))
    if public_url:
        print(public_url.rstrip("/") + "/v1")
        return 0
    print(f"No public tunnel URL found. Local URL: http://127.0.0.1:{args.port}/v1")
    return 1


def _cmd_status(args: argparse.Namespace) -> int:
    config = load_config()
    agents_path = Path(args.agents_file)
    public_url = discover_public_url(Path(args.run_dir))
    print(f"backend: {config.backend}")
    print(f"codex_home: {config.codex_home}")
    print(f"agents_file: {agents_path}")
    print(f"agent_keys: {len(list_agent_keys(agents_path))}")
    print(f"local_url: http://127.0.0.1:{args.port}/v1")
    print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'not found'}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    gateway = start_gateway(
        host=args.host,
        port=args.port,
        run_dir=run_dir,
        reload=args.reload,
    )
    print(f"Gateway running on http://{args.host}:{args.port}/v1")
    print(f"gateway_pid: {gateway.pid}")
    print(f"gateway_log: {gateway.log_path}")

    tunnel: RuntimeProcess | None = None
    if args.with_tunnel:
        tunnel = start_tunnel(
            host=args.host,
            port=args.port,
            run_dir=run_dir,
            protocol=args.tunnel_protocol,
        )
        print(f"tunnel_pid: {tunnel.pid}")
        print(f"tunnel_log: {tunnel.log_path}")
        public_url = wait_for_public_url(run_dir, timeout_seconds=20)
        print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'pending'}")

    print("Press Ctrl+C to stop processes started by this command.")
    processes = [proc.process for proc in (gateway, tunnel) if proc and proc.process]
    try:
        while True:
            for process in processes:
                if process.poll() is not None:
                    return process.returncode or 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping...")
        for process in reversed(processes):
            _terminate_process(process)
        return 130


def _cmd_tunnel_start(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    tunnel = start_tunnel(
        host=args.host,
        port=args.port,
        run_dir=run_dir,
        protocol=args.protocol,
    )
    if tunnel.already_running:
        print(f"Tunnel already running with pid {tunnel.pid}.")
    else:
        print(f"Started tunnel with pid {tunnel.pid}.")
    print(f"tunnel_log: {tunnel.log_path}")
    public_url = wait_for_public_url(run_dir, timeout_seconds=20)
    print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'pending'}")
    return 0


def _cmd_tunnel_stop(args: argparse.Namespace) -> int:
    stopped = stop_managed_process(_pid_path(Path(args.run_dir), "cloudflared", args.port))
    print("Stopped tunnel." if stopped else "No managed tunnel is running.")
    return 0 if stopped else 1


def _cmd_tunnel_status(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    pid_path = _pid_path(run_dir, "cloudflared", args.port)
    pid = _read_pid(pid_path)
    running = bool(pid and _process_running(pid))
    public_url = discover_public_url(run_dir)
    print(f"running: {str(running).lower()}")
    print(f"pid: {pid if pid else 'not found'}")
    print(f"public_url: {public_url.rstrip('/') + '/v1' if public_url else 'not found'}")
    return 0 if running else 1


def _cmd_health(args: argparse.Namespace) -> int:
    url = _health_url(args.url, args.public, Path(args.run_dir), args.port)
    try:
        status_code, body = fetch_health(url, timeout=args.timeout)
    except urllib.error.URLError as exc:
        print(f"health_url: {url}")
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"health_url: {url}")
    print(f"status_code: {status_code}")
    print(body)
    return 0 if 200 <= status_code < 300 else 1


def create_agent_key(
    path: Path,
    agent_id: str,
    role: str = "worker",
    description: str | None = None,
) -> ManagedKey:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    agent = agents.get(agent_id)
    if agent is None:
        agent = {"keys": [], "role": role}
        if description:
            agent["description"] = description
        agents[agent_id] = agent
    if not isinstance(agent, dict):
        raise ValueError(f"agent {agent_id!r} must be an object")

    keys = agent.setdefault("keys", [])
    if not isinstance(keys, list):
        raise ValueError(f"agent {agent_id!r} keys must be a list")

    key = _new_key()
    keys.append(key)
    _write_agents_document(path, document)
    return ManagedKey(agent_id=agent_id, key=key)


def delete_agent_key(path: Path, agent_id: str, selector: str) -> ManagedKey:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    agent = agents.get(agent_id)
    if not isinstance(agent, dict):
        raise ValueError(f"agent {agent_id!r} not found")
    keys = agent.get("keys")
    if not isinstance(keys, list):
        raise ValueError(f"agent {agent_id!r} keys must be a list")

    matches = [
        key
        for key in keys
        if isinstance(key, str) and _matches_selector(key=key, selector=selector)
    ]
    if not matches:
        raise ValueError(f"no key matched selector {selector!r}")
    if len(matches) > 1:
        fingerprints = ", ".join(key_fingerprint(key) for key in matches)
        raise ValueError(f"selector matched multiple keys: {fingerprints}")

    removed = matches[0]
    keys.remove(removed)
    _write_agents_document(path, document)
    return ManagedKey(agent_id=agent_id, key=removed)


def rotate_agent_key(
    path: Path,
    agent_id: str,
    selector: str,
    role: str = "worker",
    description: str | None = None,
) -> tuple[ManagedKey, ManagedKey]:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    agent = agents.get(agent_id)
    if agent is None:
        raise ValueError(f"agent {agent_id!r} not found")
    if not isinstance(agent, dict):
        raise ValueError(f"agent {agent_id!r} must be an object")
    keys = agent.get("keys")
    if not isinstance(keys, list):
        raise ValueError(f"agent {agent_id!r} keys must be a list")

    matches = [
        key
        for key in keys
        if isinstance(key, str) and _matches_selector(key=key, selector=selector)
    ]
    if not matches:
        raise ValueError(f"no key matched selector {selector!r}")
    if len(matches) > 1:
        fingerprints = ", ".join(key_fingerprint(key) for key in matches)
        raise ValueError(f"selector matched multiple keys: {fingerprints}")

    old_key = matches[0]
    new_key = _new_key()
    keys[keys.index(old_key)] = new_key
    if "role" not in agent:
        agent["role"] = role
    if description and "description" not in agent:
        agent["description"] = description
    _write_agents_document(path, document)
    return ManagedKey(agent_id=agent_id, key=new_key), ManagedKey(agent_id=agent_id, key=old_key)


def list_agent_keys(path: Path, agent_id: str | None = None) -> list[ManagedKey]:
    document = _load_agents_document(path)
    agents = _agents_object(document)
    managed: list[ManagedKey] = []
    for current_agent_id, agent in agents.items():
        if agent_id is not None and current_agent_id != agent_id:
            continue
        if not isinstance(agent, dict):
            continue
        keys = agent.get("keys", [])
        if not isinstance(keys, list):
            continue
        for key in keys:
            if isinstance(key, str):
                managed.append(ManagedKey(agent_id=current_agent_id, key=key))
    return managed


def discover_public_url(run_dir: Path) -> str | None:
    configured = os.getenv("PUBLIC_BASE_URL") or os.getenv("GATEWAY_PUBLIC_URL")
    if configured:
        return configured.rstrip("/")

    if not run_dir.exists():
        return None
    candidates: list[tuple[float, str]] = []
    for log_path in run_dir.glob("cloudflared*.log"):
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = PUBLIC_URL_PATTERN.findall(text)
        if matches:
            candidates.append((log_path.stat().st_mtime, matches[-1]))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1].rstrip("/")


def wait_for_public_url(run_dir: Path, timeout_seconds: float) -> str | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        public_url = discover_public_url(run_dir)
        if public_url:
            return public_url
        time.sleep(0.5)
    return discover_public_url(run_dir)


def start_gateway(host: str, port: int, run_dir: Path, reload: bool = False) -> RuntimeProcess:
    run_dir.mkdir(parents=True, exist_ok=True)
    pid_path = _pid_path(run_dir, "gateway", port)
    existing_pid = _read_pid(pid_path)
    log_path = run_dir / f"gateway-{port}.log"
    if existing_pid and _process_running(existing_pid):
        return RuntimeProcess(
            name="gateway",
            pid=existing_pid,
            log_path=log_path,
            already_running=True,
        )

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "gateway.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload:
        command.append("--reload")
    process = _popen_logged(command, log_path)
    _write_pid(pid_path, process.pid)
    return RuntimeProcess(name="gateway", pid=process.pid, log_path=log_path, process=process)


def start_tunnel(
    host: str,
    port: int,
    run_dir: Path,
    protocol: str | None = None,
) -> RuntimeProcess:
    run_dir.mkdir(parents=True, exist_ok=True)
    pid_path = _pid_path(run_dir, "cloudflared", port)
    existing_pid = _read_pid(pid_path)
    log_path = run_dir / f"cloudflared-{port}.log"
    if existing_pid and _process_running(existing_pid):
        return RuntimeProcess(
            name="cloudflared",
            pid=existing_pid,
            log_path=log_path,
            already_running=True,
        )

    command = [
        "cloudflared",
        "tunnel",
        "--url",
        f"http://{host}:{port}",
    ]
    if protocol:
        command.extend(["--protocol", protocol])
    try:
        process = _popen_logged(command, log_path)
    except FileNotFoundError as exc:
        raise ValueError("cloudflared command not found") from exc
    _write_pid(pid_path, process.pid)
    return RuntimeProcess(name="cloudflared", pid=process.pid, log_path=log_path, process=process)


def stop_managed_process(pid_path: Path) -> bool:
    pid = _read_pid(pid_path)
    if not pid:
        return False
    if not _process_running(pid):
        _remove_pid(pid_path)
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        _remove_pid(pid_path)
        return False

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _process_running(pid):
            _remove_pid(pid_path)
            return True
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    _remove_pid(pid_path)
    return True


def fetch_health(url: str, timeout: float) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def key_fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _new_key() -> str:
    return f"{KEY_PREFIX}_{secrets.token_urlsafe(32)}"


def _matches_selector(key: str, selector: str) -> bool:
    selector = selector.strip()
    return key == selector or key.startswith(selector) or key_fingerprint(key).startswith(selector)


def _load_agents_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"agents": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_agents_document(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _agents_object(document: dict[str, Any]) -> dict[str, Any]:
    raw_agents = document.setdefault("agents", {})
    if not isinstance(raw_agents, dict):
        raise ValueError("agents config must contain an object named 'agents'")
    return raw_agents


def _health_url(base_or_health_url: str | None, public: bool, run_dir: Path, port: int) -> str:
    if base_or_health_url:
        value = base_or_health_url.rstrip("/")
        if value.endswith("/health"):
            return value
        if value.endswith("/v1"):
            value = value[:-3]
        return value.rstrip("/") + "/health"
    if public:
        public_url = discover_public_url(run_dir)
        if not public_url:
            raise ValueError("no public tunnel URL found")
        return public_url.rstrip("/") + "/health"
    return f"http://127.0.0.1:{port}/health"


def _pid_path(run_dir: Path, name: str, port: int) -> Path:
    return run_dir / f"{name}-{port}.pid"


def _read_pid(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _write_pid(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), encoding="utf-8")


def _remove_pid(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _popen_logged(command: list[str], log_path: Path) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("ab")
    return subprocess.Popen(
        command,
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        close_fds=True,
    )


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
