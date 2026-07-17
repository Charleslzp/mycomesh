from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from .upstream import normalize_upstream_base_url


load_dotenv()


@dataclass(frozen=True)
class AgentConfig:
    agent_id: str
    keys: tuple[str, ...] = ()
    system_prompt: str | None = None
    model: str | None = None
    role: str = "worker"
    description: str | None = None
    orchestrates: bool = False
    workspace_ids: tuple[str, ...] = ()
    allowed_users: tuple[str, ...] = ()


@dataclass(frozen=True)
class GatewayConfig:
    backend: str
    network_profile: str
    production_strict: bool
    upstream_base_url: str
    upstream_api_key: str | None
    center_model: str | None
    public_model_id: str | None
    codex_internal_model: str | None
    codex_command: str
    codex_home: str
    codex_workdir: str
    codex_sandbox: str
    codex_timeout_seconds: float
    codex_testnet_metering: bool
    codex_testnet_max_output_tokens: int
    orchestration_max_steps: int
    session_db: str
    history_limit: int
    default_user_id: str
    default_workspace_id: str
    require_user_auth: bool
    auth_token_ttl_seconds: int
    allow_anonymous_gateway: bool
    allow_public_user_registration: bool
    upstream_timeout_seconds: float
    upstream_max_response_bytes: int
    upstream_max_stream_bytes: int
    upstream_expected_model_revision: str | None
    upstream_metering_public_key: str | None
    upstream_capabilities_sha256: str | None
    upstream_metering_audience: str | None
    upstream_default_max_output_tokens: int
    max_request_bytes: int
    agents: dict[str, AgentConfig] = field(default_factory=dict)
    key_to_agent: dict[str, str] = field(default_factory=dict)


def load_config() -> GatewayConfig:
    agents_file = os.getenv("AGENTS_FILE", "agents.json")
    agents = _load_agents_file(Path(agents_file))
    agents = _merge_env_agent_keys(agents, os.getenv("AGENT_KEYS", ""))

    key_to_agent: dict[str, str] = {}
    for agent_id, config in agents.items():
        for key in config.keys:
            if key:
                key_to_agent[key] = agent_id

    network_profile = _network_profile(os.getenv("MYCOMESH_NETWORK_PROFILE", "local"))
    local_strict = _env_bool(
        "MYCOMESH_PRODUCTION_STRICT",
        _env_bool("CODEX_PRODUCTION_STRICT", False),
    )
    production_strict = network_profile != "local" or local_strict
    backend = os.getenv("GATEWAY_BACKEND", "openai_http")
    codex_sandbox = os.getenv("CODEX_SANDBOX", "workspace-write")
    codex_testnet_metering = _env_bool("MYCOMESH_CODEX_TESTNET_METERING", False)
    if codex_testnet_metering:
        if network_profile != "testnet":
            raise ValueError("MYCOMESH_CODEX_TESTNET_METERING is valid only in the testnet profile")
        if backend != "codex_app_server":
            raise ValueError(
                "MYCOMESH_CODEX_TESTNET_METERING requires GATEWAY_BACKEND=codex_app_server"
            )
        if codex_sandbox != "read-only":
            raise ValueError("Codex testnet Providers require CODEX_SANDBOX=read-only")
        if os.getenv("CODEX_MAX_CONCURRENT_PROCESSES", "4") != "1":
            raise ValueError(
                "Codex testnet Providers require CODEX_MAX_CONCURRENT_PROCESSES=1"
            )
        if os.getenv("CODEX_PROVIDER_BASE_URL"):
            raise ValueError(
                "Codex testnet Providers require CODEX_PROVIDER_BASE_URL to remain empty"
            )

    return GatewayConfig(
        backend=backend,
        network_profile=network_profile,
        production_strict=production_strict,
        upstream_base_url=normalize_upstream_base_url(
            os.getenv("UPSTREAM_BASE_URL", "https://api.openai.com/v1")
        ),
        upstream_api_key=os.getenv("UPSTREAM_API_KEY") or None,
        center_model=os.getenv("CENTER_MODEL") or None,
        public_model_id=os.getenv("PUBLIC_MODEL_ID") or os.getenv("CENTER_MODEL") or None,
        codex_internal_model=(
            os.getenv("CODEX_INTERNAL_MODEL")
            or os.getenv("PUBLIC_MODEL_ID")
            or os.getenv("CENTER_MODEL")
            or "codex-cli"
        ),
        codex_command=os.getenv("CODEX_COMMAND", "codex"),
        codex_home=os.getenv("CODEX_HOME", str(Path(os.getcwd()) / ".codex-gateway-home")),
        codex_workdir=os.getenv("CODEX_WORKDIR", os.getcwd()),
        codex_sandbox=codex_sandbox,
        codex_timeout_seconds=float(os.getenv("CODEX_TIMEOUT_SECONDS", "600")),
        codex_testnet_metering=codex_testnet_metering,
        codex_testnet_max_output_tokens=int(
            os.getenv("CODEX_TESTNET_MAX_OUTPUT_TOKENS", "2000")
        ),
        orchestration_max_steps=int(os.getenv("GATEWAY_ORCHESTRATION_MAX_STEPS", "4")),
        session_db=os.getenv("SESSION_DB", "sessions.sqlite3"),
        history_limit=int(os.getenv("SESSION_HISTORY_LIMIT", "40")),
        default_user_id=os.getenv("DEFAULT_USER_ID", "local-user"),
        default_workspace_id=os.getenv("DEFAULT_WORKSPACE_ID", "default-workspace"),
        require_user_auth=_env_bool("REQUIRE_USER_AUTH", False),
        auth_token_ttl_seconds=int(os.getenv("AUTH_TOKEN_TTL_SECONDS", str(60 * 60 * 24 * 30))),
        allow_anonymous_gateway=_env_bool("ALLOW_ANONYMOUS_GATEWAY", False),
        allow_public_user_registration=_env_bool("ALLOW_PUBLIC_USER_REGISTRATION", False),
        upstream_timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "180")),
        upstream_max_response_bytes=int(
            os.getenv("UPSTREAM_MAX_RESPONSE_BYTES", str(32 * 1024 * 1024))
        ),
        upstream_max_stream_bytes=int(
            os.getenv("UPSTREAM_MAX_STREAM_BYTES", str(32 * 1024 * 1024))
        ),
        upstream_expected_model_revision=os.getenv("UPSTREAM_EXPECTED_MODEL_REVISION") or None,
        upstream_metering_public_key=os.getenv("UPSTREAM_METERING_PUBLIC_KEY") or None,
        upstream_capabilities_sha256=os.getenv("UPSTREAM_CAPABILITIES_SHA256") or None,
        upstream_metering_audience=os.getenv("UPSTREAM_METERING_AUDIENCE") or None,
        upstream_default_max_output_tokens=int(
            os.getenv("UPSTREAM_DEFAULT_MAX_OUTPUT_TOKENS", "2000")
        ),
        max_request_bytes=int(os.getenv("GATEWAY_MAX_REQUEST_BYTES", str(16 * 1024 * 1024))),
        agents=agents,
        key_to_agent=key_to_agent,
    )


def _load_agents_file(path: Path) -> dict[str, AgentConfig]:
    if not path.exists():
        return {}

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_agents = raw.get("agents", raw)
    agents: dict[str, AgentConfig] = {}
    for agent_id, value in raw_agents.items():
        if not isinstance(value, dict):
            raise ValueError(f"agent {agent_id!r} must be an object")

        keys = tuple(str(key) for key in value.get("keys", []) if key)
        agents[agent_id] = AgentConfig(
            agent_id=agent_id,
            keys=keys,
            system_prompt=value.get("system_prompt"),
            model=value.get("model"),
            role=value.get("role", "worker"),
            description=value.get("description"),
            orchestrates=bool(value.get("orchestrates", False)),
            workspace_ids=tuple(str(item) for item in value.get("workspace_ids", []) if item),
            allowed_users=tuple(str(item) for item in value.get("allowed_users", []) if item),
        )
    return agents


def _merge_env_agent_keys(
    agents: dict[str, AgentConfig],
    agent_keys: str,
) -> dict[str, AgentConfig]:
    if not agent_keys.strip():
        return agents

    merged = dict(agents)
    for pair in agent_keys.split(","):
        if not pair.strip():
            continue
        if "=" not in pair:
            raise ValueError("AGENT_KEYS entries must look like agent_id=secret")
        agent_id, key = (part.strip() for part in pair.split("=", 1))
        existing = merged.get(agent_id, AgentConfig(agent_id=agent_id))
        merged[agent_id] = AgentConfig(
            agent_id=agent_id,
            keys=existing.keys + (key,),
            system_prompt=existing.system_prompt,
            model=existing.model,
            role=existing.role,
            description=existing.description,
            orchestrates=existing.orchestrates,
            workspace_ids=existing.workspace_ids,
            allowed_users=existing.allowed_users,
        )
    return merged


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _network_profile(value: str) -> str:
    profile = str(value or "").strip().lower()
    if profile not in {"local", "testnet", "open"}:
        raise ValueError(f"unknown MycoMesh network profile: {value}")
    return profile
