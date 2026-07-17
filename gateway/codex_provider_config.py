from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .upstream import normalize_upstream_base_url


MANAGED_CONFIG_MARKER = "# mycomesh-managed-codex-provider-config-v1"
DEFAULT_MODEL_PROVIDER = "mycomesh"
DEFAULT_WIRE_API = "responses"
_PROVIDER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class CodexProviderConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ManagedCodexProviderConfig:
    codex_home: Path
    model_provider: str | None = None
    provider_name: str | None = None
    base_url: str | None = None
    wire_api: str = DEFAULT_WIRE_API

    @property
    def path(self) -> Path:
        return self.codex_home / "config.toml"

    def render(self) -> str:
        lines = [
            f"{MANAGED_CONFIG_MARKER}\n"
            "# Generated for an isolated MycoMesh Provider CODEX_HOME.\n",
            'forced_login_method = "chatgpt"\n',
            'cli_auth_credentials_store = "file"\n',
            "check_for_update_on_startup = false\n",
            'web_search = "disabled"\n',
        ]
        if self.base_url is not None:
            if self.model_provider is None or self.provider_name is None:
                raise CodexProviderConfigError("custom Provider config is incomplete")
            provider_key = _toml_string(self.model_provider)
            lines.append(f"model_provider = {provider_key}\n")
        lines.extend(
            [
                "\n[history]\n",
                'persistence = "none"\n',
                "\n[features]\n",
                "shell_tool = false\n",
                "unified_exec = false\n",
                "shell_snapshot = false\n",
                "hooks = false\n",
                "code_mode = false\n",
                "code_mode_host = false\n",
                "multi_agent = false\n",
                "apps = false\n",
                "plugins = false\n",
                "in_app_browser = false\n",
                "browser_use = false\n",
                "browser_use_full_cdp_access = false\n",
                "browser_use_external = false\n",
                "computer_use = false\n",
                "remote_plugin = false\n",
                "plugin_sharing = false\n",
                "image_generation = false\n",
                "skill_mcp_dependency_install = false\n",
                "tool_suggest = false\n",
                "tool_call_mcp_elicitation = false\n",
                "auth_elicitation = false\n",
                "workspace_dependencies = false\n",
            ]
        )
        if self.base_url is not None:
            provider_key = _toml_string(self.model_provider or "")
            lines.extend(
                [
                    f"\n[model_providers.{provider_key}]\n",
                    f"name = {_toml_string(self.provider_name or '')}\n",
                    f"base_url = {_toml_string(self.base_url)}\n",
                    f"wire_api = {_toml_string(self.wire_api)}\n",
                    "requires_openai_auth = true\n",
                ]
            )
        return "".join(lines)


def configure_codex_provider_from_env(
    codex_home: str | Path,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Create an isolated ChatGPT-login config with an optional explicit proxy."""

    values = os.environ if env is None else env
    raw_base_url = str(values.get("CODEX_PROVIDER_BASE_URL") or "")
    if raw_base_url != raw_base_url.strip():
        raise CodexProviderConfigError(
            "CODEX_PROVIDER_BASE_URL must not contain surrounding whitespace"
        )
    network_profile = str(values.get("MYCOMESH_NETWORK_PROFILE") or "").strip().lower()
    if raw_base_url and network_profile == "testnet":
        raise CodexProviderConfigError(
            "testnet Codex Providers require CODEX_PROVIDER_BASE_URL to remain empty"
        )

    normalized_base_url = _provider_base_url(raw_base_url) if raw_base_url else None
    config = ManagedCodexProviderConfig(
        codex_home=_isolated_codex_home(codex_home),
        model_provider=(
            _model_provider(values.get("CODEX_MODEL_PROVIDER"))
            if normalized_base_url is not None
            else None
        ),
        provider_name=(
            _provider_name(values.get("CODEX_PROVIDER_NAME"))
            if normalized_base_url is not None
            else None
        ),
        base_url=normalized_base_url,
        wire_api=_wire_api(values.get("CODEX_PROVIDER_WIRE_API")),
    )
    _write_managed_config(config)
    return config.path


def secure_codex_home(codex_home: str | Path) -> Path:
    """Secure the isolated home and auth metadata without reading credentials."""

    home = _isolated_codex_home(codex_home)
    _secure_home_directory(home)
    for name in ("auth.json", "login.json"):
        path = home / name
        if path.is_symlink():
            raise CodexProviderConfigError(f"{name} must not be a symbolic link")
        if not path.exists():
            continue
        try:
            mode = path.stat().st_mode
            if not stat.S_ISREG(mode):
                raise CodexProviderConfigError(f"{name} must be a regular file")
            path.chmod(0o600)
        except OSError as exc:
            raise CodexProviderConfigError(f"could not secure {name}: {exc}") from exc
    return home


def _isolated_codex_home(value: str | Path) -> Path:
    raw = str(value)
    if not raw or raw != raw.strip():
        raise CodexProviderConfigError("CODEX_HOME must be a non-empty isolated path")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.absolute()
    default_home = (Path.home() / ".codex").absolute()
    if path in {Path("/"), Path.home().absolute(), default_home}:
        raise CodexProviderConfigError(
            "managed Provider config refuses the default or non-isolated CODEX_HOME"
        )
    if path.is_symlink():
        raise CodexProviderConfigError("CODEX_HOME must not be a symbolic link")
    return path


def _model_provider(value: str | None) -> str:
    provider = str(value or DEFAULT_MODEL_PROVIDER).strip()
    if _PROVIDER_ID_PATTERN.fullmatch(provider) is None:
        raise CodexProviderConfigError(
            "CODEX_MODEL_PROVIDER must contain only letters, digits, underscores, or hyphens"
        )
    return provider


def _provider_name(value: str | None) -> str:
    name = str(value or "MycoMesh Codex Provider").strip()
    if not name or len(name) > 128 or any(ord(character) < 32 for character in name):
        raise CodexProviderConfigError("CODEX_PROVIDER_NAME must be 1-128 printable characters")
    return name


def _wire_api(value: str | None) -> str:
    wire_api = str(value or DEFAULT_WIRE_API).strip().lower()
    if wire_api != DEFAULT_WIRE_API:
        raise CodexProviderConfigError("CODEX_PROVIDER_WIRE_API must be responses")
    return wire_api


def _provider_base_url(value: str) -> str:
    try:
        normalized = normalize_upstream_base_url(value)
    except ValueError as exc:
        raise CodexProviderConfigError(
            str(exc).replace("UPSTREAM_BASE_URL", "CODEX_PROVIDER_BASE_URL")
        ) from exc
    parsed = urlsplit(normalized)
    if parsed.scheme == "https":
        return normalized
    hostname = parsed.hostname or ""
    try:
        is_loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = hostname.lower() == "localhost"
    if not is_loopback:
        raise CodexProviderConfigError(
            "CODEX_PROVIDER_BASE_URL must use HTTPS except for an explicit loopback address"
        )
    return normalized


def _write_managed_config(config: ManagedCodexProviderConfig) -> None:
    home = config.codex_home
    _secure_home_directory(home)

    target = config.path
    rendered = config.render()
    if target.is_symlink():
        raise CodexProviderConfigError("managed Codex config must not be a symbolic link")
    if target.exists():
        mode = target.stat().st_mode
        if not stat.S_ISREG(mode):
            raise CodexProviderConfigError("managed Codex config path must be a regular file")
        try:
            current = target.read_text(encoding="utf-8")
        except OSError as exc:
            raise CodexProviderConfigError(f"could not read existing Codex config: {exc}") from exc
        if not current.startswith(MANAGED_CONFIG_MARKER + "\n"):
            raise CodexProviderConfigError(
                "refusing to overwrite an unmanaged CODEX_HOME/config.toml"
            )
        if current == rendered:
            try:
                target.chmod(0o600)
            except OSError as exc:
                raise CodexProviderConfigError(
                    f"could not secure managed Codex config: {exc}"
                ) from exc
            return

    temporary_path: Path | None = None
    try:
        descriptor, raw_path = tempfile.mkstemp(prefix=".config.toml.", dir=home)
        temporary_path = Path(raw_path)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
        target.chmod(0o600)
    except OSError as exc:
        raise CodexProviderConfigError(f"could not write managed Codex config: {exc}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _secure_home_directory(home: Path) -> None:
    try:
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise CodexProviderConfigError(f"could not create CODEX_HOME: {exc}") from exc
    if home.is_symlink():
        raise CodexProviderConfigError("CODEX_HOME must not be a symbolic link")
    try:
        if not stat.S_ISDIR(home.stat().st_mode):
            raise CodexProviderConfigError("CODEX_HOME must be a directory")
        home.chmod(0o700)
    except OSError as exc:
        raise CodexProviderConfigError(f"could not secure CODEX_HOME: {exc}") from exc


def _toml_string(value: str) -> str:
    # TOML basic strings share JSON's escaping for the characters allowed above.
    return json.dumps(value, ensure_ascii=True)
