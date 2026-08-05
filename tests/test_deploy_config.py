from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _service_block(compose: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)",
        compose,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing Compose service {name}")
    return match.group(0)


def _nginx_server_blocks(config: str) -> list[str]:
    lines = config.splitlines(keepends=True)
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        if re.fullmatch(r"server\s*\{\s*", lines[index].strip()) is None:
            index += 1
            continue
        start = index
        depth = 0
        while index < len(lines):
            depth += lines[index].count("{") - lines[index].count("}")
            index += 1
            if depth == 0:
                blocks.append("".join(lines[start:index]))
                break
        else:
            raise AssertionError("unterminated Nginx server block")
    return blocks


class ProductionDeploymentConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        cls.nginx = (ROOT / "deploy/nginx-mycomesh.conf").read_text(encoding="utf-8")
        cls.nginx_proxy = (ROOT / "deploy/nginx-mycomesh-proxy.conf").read_text(
            encoding="utf-8"
        )
        cls.nginx_tls = (ROOT / "deploy/nginx-mycomesh-tls.conf").read_text(
            encoding="utf-8"
        )
        cls.nginx_bootstrap = (
            ROOT / "deploy/nginx-mycomesh-bootstrap.conf"
        ).read_text(encoding="utf-8")
        cls.nginx_stream = (ROOT / "deploy/nginx-mycomesh-stream.conf").read_text(
            encoding="utf-8"
        )

    def test_production_roles_are_nonroot_and_volumes_are_isolated(self) -> None:
        for name in ("proxy", "indexer", "bridge", "relay", "provider-sidecar", "provider"):
            with self.subTest(service=name):
                self.assertIn('user: "10001:10001"', _service_block(self.compose, name))
        self.assertIn('user: "0:0"', _service_block(self.compose, "gateway"))
        self.assertIn("mycomesh-gateway-data:/data", _service_block(self.compose, "gateway"))
        self.assertIn("mycomesh-proxy-data:/data", _service_block(self.compose, "proxy"))
        provider = _service_block(self.compose, "provider")
        sidecar = _service_block(self.compose, "provider-sidecar")
        self.assertNotIn("mycomesh-proxy-data", provider)
        self.assertIn("mycomesh-provider-data:/data", provider)
        self.assertNotIn("mycomesh-provider-codex-data", provider)
        self.assertNotIn("mycomesh-provider-workspace", provider)
        self.assertIn("mycomesh-provider-codex-data:/data", sidecar)
        self.assertIn("mycomesh-provider-workspace:/workspace:ro", sidecar)
        self.assertIn(
            "CODEX_APP_SERVER_SOCKET: /tmp/mycomesh-codex-app-server.sock",
            sidecar,
        )
        self.assertIn('codex app-server --listen "unix://$$codex_app_server_socket"', sidecar)
        self.assertNotIn("mycomesh-provider-data", sidecar)
        self.assertIn("mycomesh-provider-agent-data:/agent:ro", provider)
        self.assertIn("mycomesh-provider-agent-data:/agent:ro", sidecar)
        for name in (
            "proxy-volume-init",
            "public-node-volume-init",
            "provider-volume-init",
        ):
            block = _service_block(self.compose, name)
            self.assertIn('user: "0:0"', block)
            self.assertIn("cap_add:", block)
            self.assertIn("- CHOWN", block)
            self.assertIn("network_mode: none", block)
        self.assertIn(
            "- FOWNER",
            _service_block(self.compose, "provider-volume-init"),
        )

    def test_compose_identity_and_production_resource_limits_are_fixed(self) -> None:
        self.assertRegex(self.compose, r"\Aname: mycomesh\n")
        self.assertIn("x-production-logging: &production-logging", self.compose)
        self.assertIn("driver: json-file", self.compose)
        self.assertIn('max-size: "20m"', self.compose)
        self.assertIn('max-file: "5"', self.compose)

        expected_limits = {
            "postgres": (256, "1g", "2.0"),
            "proxy": (256, "1g", "2.0"),
            "indexer": (256, "512m", "1.0"),
            "bridge": (512, "768m", "2.0"),
            "relay": (512, "768m", "2.0"),
            "provider-sidecar": (512, "2g", "4.0"),
            "provider": (512, "2g", "4.0"),
        }
        for name, (pids, memory, cpus) in expected_limits.items():
            with self.subTest(service=name):
                block = _service_block(self.compose, name)
                self.assertIn(f"pids_limit: {pids}", block)
                self.assertIn(f"mem_limit: {memory}", block)
                self.assertIn(f'cpus: "{cpus}"', block)
                self.assertIn("logging: *production-logging", block)

    def test_public_node_uses_v8_while_retaining_v3_admission_compatibility(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "PUBLIC_NODE_SETTLEMENT_VERSION ?= $(or $(MYCOMESH_PUBLIC_NODE_SETTLEMENT_VERSION),$(call deploy_env_value,MYCOMESH_PUBLIC_NODE_SETTLEMENT_VERSION),8)",
            makefile,
        )
        self.assertIn(
            "/app/deployments/sepolia-myco-v8.json",
            makefile,
        )
        public_node_start = makefile.index("PUBLIC_NODE_ENV = \\\n")
        public_node_end = makefile.index("\n\n", public_node_start)
        public_node_env = makefile[public_node_start:public_node_end]
        self.assertIn("MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER=false", public_node_env)
        self.assertNotIn("MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER=true", public_node_env)
        self.assertIn(
            "MYCOMESH_RELAY_CONSUMER_PUBLIC_KEYS=$(PUBLIC_NODE_RELAY_CONSUMER_PUBLIC_KEYS)",
            public_node_env,
        )
        self.assertIn(
            "MYCOMESH_BRIDGE_REPUTATION_SIGNER_PUBLIC_KEYS=$(PUBLIC_NODE_REPUTATION_SIGNER_PUBLIC_KEYS)",
            public_node_env,
        )
        self.assertIn(
            "$(call deploy_env_value,MYCOMESH_RELAY_V3_ADMISSION_RPC_URL)",
            makefile,
        )
        self.assertIn(
            "MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz,http://127.0.0.1:8110,http://localhost:8110",
            public_node_env,
        )
        self.assertIn(
            "MYCOMESH_POOL_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz,http://127.0.0.1:8110,http://localhost:8110",
            public_node_env,
        )
        self.assertIn(
            "MYCOMESH_RELAY_V3_ADMISSION_RPC_URL=$(PUBLIC_NODE_RPC_URL)",
            public_node_env,
        )
        self.assertIn("public-node-tls-health:", makefile)
        public_health = makefile[
            makefile.index("public-node-health:"):
            makefile.index("public-node-tls-health:")
        ]
        self.assertNotIn("ssl.create_default_context", public_health)
        self.assertIn('value["settlement"]["version"]', public_health)

        relay = _service_block(self.compose, "relay")
        self.assertIn(
            "MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER: "
            "${MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER:-false}",
            relay,
        )
        self.assertIn(
            "MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS: "
            "${MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS:-}",
            relay,
        )
        self.assertIn('--consumer-public-key "$$public_key"', relay)
        self.assertIn("--v3-admission-rpc-url", relay)

        bridge = _service_block(self.compose, "bridge")
        self.assertIn("--require-provider-backend-metadata", bridge)
        self.assertIn(
            "value.get('require_provider_backend_metadata') is True",
            bridge,
        )

    def test_proxy_requires_signed_codex_sidecar_capabilities(self) -> None:
        proxy = _service_block(self.compose, "proxy")
        self.assertIn(
            "MYCOMESH_PROVIDER_BACKEND_KIND: "
            "${MYCOMESH_PROVIDER_BACKEND_KIND:-codex_oauth_sidecar}",
            proxy,
        )
        self.assertIn(
            "MYCOMESH_MIN_PROVIDER_TRUST: "
            "${MYCOMESH_MIN_PROVIDER_TRUST:-self_attested}",
            proxy,
        )

    def test_role_environments_do_not_cross_secret_boundaries(self) -> None:
        bridge = _service_block(self.compose, "bridge")
        relay = _service_block(self.compose, "relay")
        provider = _service_block(self.compose, "provider")
        sidecar = _service_block(self.compose, "provider-sidecar")
        proxy = _service_block(self.compose, "proxy")
        indexer = _service_block(self.compose, "indexer")

        for block in (bridge, relay):
            for secret in (
                "MYCOMESH_ADMIN_TOKEN:",
                "MYCOMESH_BILLING_DB:",
                "UPSTREAM_API_KEY:",
                "ETH_RPC_URL:",
            ):
                self.assertNotIn(secret, block)
        for secret in ("MYCOMESH_ADMIN_TOKEN:", "MYCOMESH_BILLING_DB:"):
            self.assertNotIn(secret, provider)
            self.assertNotIn(secret, sidecar)
        for secret in (
            "UPSTREAM_API_KEY:",
            "CODEX_HOME:",
            "OPENAI_ACCESS_TOKEN:",
            "CODEX_ACCESS_TOKEN:",
            "CHATGPT_ACCESS_TOKEN:",
        ):
            self.assertNotIn(secret, provider)
        for secret in (
            "MYCOMESH_PROVIDER_EVM_IDENTITY:",
            "MYCOMESH_PROVIDER_IDENTITY:",
            "MYCOMESH_REPLAY_DB:",
        ):
            self.assertNotIn(secret, sidecar)
        for secret in ("UPSTREAM_API_KEY:", "MYCOMESH_REPLAY_DB:"):
            self.assertNotIn(secret, proxy)
        for secret in ("MYCOMESH_ADMIN_TOKEN:", "UPSTREAM_API_KEY:"):
            self.assertNotIn(secret, indexer)

        self.assertIn("MYCOMESH_REPLAY_DB: /data/relay-replay.sqlite3", relay)
        self.assertIn("MYCOMESH_REPLAY_DB: /data/provider-replay.sqlite3", provider)
        self.assertNotIn("postgres:", relay)
        self.assertNotIn("postgres:", provider)
        self.assertEqual(
            'profiles: ["proxy"]' in _service_block(self.compose, "postgres"),
            True,
        )

    def test_provider_image_pull_only_fetches_provider_images(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        target = re.search(
            r"(?ms)^provider-image-pull:.*?(?=^[^\t\n]|\Z)",
            makefile,
        )
        self.assertIsNotNone(target)
        pull = re.search(r"(?m)\bpull\s+([^\n]+)$", target.group(0))
        self.assertIsNotNone(pull)
        self.assertEqual(
            pull.group(1).split(),
            ["provider-volume-init", "provider-sidecar", "provider"],
        )

    def test_provider_entrypoint_clears_persistent_child_pid_files_before_start(self) -> None:
        provider = _service_block(self.compose, "provider")
        cleanup = 'rm -f "$$run_dir"/provider-*.pid'
        start = 'set -- python -m gateway provider start'

        self.assertIn('run_dir="$${MYCOMESH_PROVIDER_RUN_DIR:-/data/run}"', provider)
        self.assertIn(cleanup, provider)
        self.assertLess(provider.index(cleanup), provider.index(start))
        self.assertIn('--run-dir "$$run_dir"', provider)

    def test_provider_codex_sidecar_is_private_and_credential_isolated(self) -> None:
        provider = _service_block(self.compose, "provider")
        sidecar = _service_block(self.compose, "provider-sidecar")
        initializer = _service_block(self.compose, "provider-volume-init")

        self.assertNotIn("ports:", sidecar)
        self.assertIn("provider-sidecar:\n        condition: service_healthy", provider)
        self.assertIn("--gateway-url http://provider-sidecar:8000/v1", provider)
        self.assertIn("--allow-private-gateway-http", provider)
        self.assertIn('AGENT_KEYS: ""', sidecar)
        self.assertIn("ALLOW_ANONYMOUS_GATEWAY: \"false\"", sidecar)
        self.assertIn("AGENTS_FILE: /agent/agents.json", sidecar)
        self.assertIn("ensure_agent_key", initializer)
        self.assertNotIn("change-me-coder-key", provider)
        self.assertNotIn("change-me-coder-key", sidecar)

    def test_provider_environment_does_not_inherit_v2_contract_overrides(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        provider_env = re.search(
            r"(?ms)^PROVIDER_ENV = \\\n.*?(?=^\n\.PHONY:)",
            makefile,
        )
        self.assertIsNotNone(provider_env)
        for name in (
            "MYCO_SETTLEMENT",
            "MYCO_TOKEN",
            "MYCO_TEST_USDC",
            "MYCO_TREASURY",
            "MYCO_CHANNEL_HASH",
        ):
            with self.subTest(name=name):
                self.assertRegex(
                    provider_env.group(0),
                    rf"(?m)^\t{re.escape(name)}= ?\\?$",
                )

    def test_provider_runtime_defaults_v8_without_weakening_v3_finality(self) -> None:
        provider = _service_block(self.compose, "provider")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn(
            "MYCOMESH_SETTLEMENT_VERSION: ${MYCOMESH_PROVIDER_SETTLEMENT_VERSION:-8}",
            provider,
        )
        self.assertIn("case \"$$settlement_version\" in", provider)
        self.assertIn("3|4|5|6) ;;", provider)
        self.assertIn(
            'if [ "$$settlement_version" = "3" ] && '
            '[ "$$MYCOMESH_SETTLEMENT_CONFIRMATIONS" -lt 6 ]; then',
            provider,
        )
        self.assertIn(
            "PROVIDER_SETTLEMENT_VERSION ?= $(or $(MYCOMESH_PROVIDER_SETTLEMENT_VERSION),$(call deploy_env_value,MYCOMESH_PROVIDER_SETTLEMENT_VERSION),8)",
            makefile,
        )
        self.assertIn(
            "/app/deployments/sepolia-provider-network-v8.json",
            makefile,
        )
        self.assertIn(
            "MYCOMESH_SETTLEMENT_VERSION=$(PROVIDER_SETTLEMENT_VERSION)",
            makefile,
        )
        self.assertIn(
            "MYCOMESH_PROVIDER_DEPLOYMENT=$(PROVIDER_DEPLOYMENT)",
            makefile,
        )
        deploy_example = (ROOT / ".env.deploy.example").read_text(encoding="utf-8")
        self.assertIn("MYCOMESH_PROVIDER_SETTLEMENT_VERSION=8", deploy_example)
        self.assertIn(
            "MYCOMESH_PROVIDER_NETWORK_CONFIG=/app/deployments/sepolia-provider-network-v8.json",
            deploy_example,
        )
        self.assertIn(
            "MYCOMESH_PROVIDER_DEPLOYMENT=/app/deployments/sepolia-myco-v8.json",
            deploy_example,
        )
        installer = (ROOT / "scripts" / "install-provider.sh").read_text(encoding="utf-8")
        self.assertIn('PUBLIC_PROVIDER_SETTLEMENT_VERSION="8"', installer)
        self.assertIn(
            'PUBLIC_PROVIDER_NETWORK_CONFIG="${MYCOMESH_PUBLIC_PROVIDER_NETWORK_CONFIG:-/app/deployments/sepolia-provider-network-v${PUBLIC_PROVIDER_SETTLEMENT_VERSION}.json}"',
            installer,
        )
        self.assertIn(
            'PUBLIC_PROVIDER_DEPLOYMENT="${MYCOMESH_PUBLIC_PROVIDER_DEPLOYMENT:-/app/deployments/sepolia-myco-v${PUBLIC_PROVIDER_SETTLEMENT_VERSION}.json}"',
            installer,
        )
        self.assertIn(
            'PUBLIC_PROVIDER_BRIDGE_URL="https://bridge.mycomesh.xyz"',
            installer,
        )
        self.assertIn('"PROVIDER_SETTLEMENT_VERSION=$PUBLIC_PROVIDER_SETTLEMENT_VERSION"', installer)
        self.assertIn('"PROVIDER_NETWORK_CONFIG=$PUBLIC_PROVIDER_NETWORK_CONFIG"', installer)
        self.assertIn('"PROVIDER_DEPLOYMENT=$PUBLIC_PROVIDER_DEPLOYMENT"', installer)
        self.assertIn("--skip-provider-config", installer)
        self.assertIn('PROVIDER_ONBOARDING_HELPER=', installer)
        self.assertIn('--image "$PROVIDER_IMAGE"', installer)
        self.assertNotIn('PYTHON_BIN=', installer)
        self.assertNotIn('PROVIDER_HOST_VENV=', installer)
        self.assertIn('make_args+=("PROVIDER_PAYMENT_ADDRESS=")', installer)
        self.assertIn('empty value deliberately overrides stale .env.deploy values', installer)
        self.assertNotIn('python -m pip', installer)
        self.assertNotIn('pip._vendor.certifi', installer)
        onboarding = (
            ROOT / "scripts" / "provider-onboarding-container.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('--read-only', onboarding)
        self.assertIn('--publish "$publish_arg"', onboarding)
        self.assertIn(
            'mktemp -d "$output_dir/.mycomesh-provider-onboarding.XXXXXX"',
            onboarding,
        )
        self.assertIn(
            '--mount "type=bind,source=$STAGING_DIR,target=/run/mycomesh-state"',
            onboarding,
        )
        self.assertNotIn('source=$output_dir,target=', onboarding)
        self.assertIn('--allow-container-bind', onboarding)
        self.assertIn('--display-host 127.0.0.1', onboarding)
        self.assertIn('--protected-wallet', onboarding)
        self.assertIn('--protected-identity', onboarding)
        self.assertIn('cp -p -- "$PROTECTED_IDENTITY"', onboarding)
        self.assertIn(
            'elif ((!PROTECTED_WALLET)) && [[ -f "$identity_target" ]]',
            onboarding,
        )
        self.assertIn('if ((!PROTECTED_WALLET)) && [[ -e "$staged_identity" ]]', onboarding)
        self.assertLess(
            onboarding.index('ln -- "$IDENTITY_TEMPORARY" "$identity_target"'),
            onboarding.index('mv -f -- "$CONFIG_TEMPORARY" "$output_target"'),
        )
        self.assertIn('-m gateway.operator_setup wizard provider', onboarding)
        self.assertIn('scripts/install-provider.sh', makefile)
        self.assertIn('--configure-only', makefile)
        self.assertNotIn('scripts/provider-onboarding-container.sh', makefile)
        self.assertNotIn('python3 -m gateway.operator_setup wizard provider', makefile)
        bootstrap_provider = (ROOT / "scripts" / "bootstrap-provider.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('bootstrap_ensure_provider_host_python', bootstrap_provider)
        self.assertIn('"$provider_python" -m gateway.operator_setup', bootstrap_provider)
        self.assertNotIn('python3 -m gateway.operator_setup', bootstrap_provider)
        self.assertIn("pip._vendor.certifi", bootstrap_provider)
        self.assertIn('"PROVIDER_OPERATOR_CONFIG=$PROVIDER_OPERATOR_CONFIG"', installer)
        self.assertIn("provider-configure: deploy-env", makefile)
        self.assertIn("provider-auth-ensure-image: deploy-env require-provider-image", makefile)
        self.assertIn(
            'if python -m gateway codex-provider status --codex-home "$$CODEX_HOME"',
            makefile,
        )
        self.assertIn("make_target provider-auth-ensure-image", installer)
        self.assertIn('"$MAKE_BIN" --silent --no-print-directory', installer)
        self.assertIn("provider-operator-config-export-image", makefile)
        self.assertIn("export-provider-profile", makefile)
        self.assertIn("provider-identity-export-image", makefile)
        self.assertIn("provider-config-apply-image", makefile)
        self.assertIn("$(PROVIDER_ONBOARDING_ENV)", makefile)
        operator_env = next(
            line for line in makefile.splitlines() if line.startswith("PROVIDER_OPERATOR_ENV =")
        )
        self.assertIn("MYCOMESH_PROVIDER_IDENTITY_SOURCE=", operator_env)
        self.assertNotIn("PROVIDER_IDENTITY_SOURCE_EXISTS", operator_env)
        self.assertIn("gateway.provider_identity validate", makefile)
        self.assertIn("PROVIDER_IDENTITY_EXPORT_FILE is required", makefile)
        self.assertIn(":/provider-identity-export.json", makefile)
        self.assertIn("stage_protected_provider_identity", installer)
        self.assertIn(
            "$(COMPOSE) --progress quiet --ansi never --env-file",
            makefile,
        )
        self.assertIn("restore_protected_provider_config", installer)
        self.assertIn("--force-recreate --wait", makefile)
        self.assertIn('MYCOMESH_PRICING_VERSION: ""', provider)
        self.assertIn('MYCOMESH_SETTLEMENT_CONTRACT: ""', provider)
        self.assertIn('MYCOMESH_SETTLEMENT_CHAIN_ID: ""', provider)
        self.assertIn(
            "MYCOMESH_SETTLEMENT_RPC_URL: ${MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL:-}",
            provider,
        )
        self.assertNotIn(
            "MYCO_DEPLOYMENT:?provider preflight: MYCO_DEPLOYMENT is required",
            provider,
        )
        self.assertIn(
            'if [ -n "$${MYCO_DEPLOYMENT:-}" ] && [ ! -r "$$MYCO_DEPLOYMENT" ]; then',
            provider,
        )

    def test_provider_operator_config_path_with_spaces_reaches_compose(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mycomesh config ") as directory:
            config = Path(directory) / "provider settings.json"
            config.write_text("{}\n", encoding="utf-8")
            result = subprocess.run(
                [
                    "make",
                    "-n",
                    "provider-up-image",
                    "PROVIDER_IMAGE=ghcr.io/example/provider@sha256:abc",
                    f"PROVIDER_OPERATOR_CONFIG={config}",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'MYCOMESH_PROVIDER_OPERATOR_CONFIG="{config}"', result.stdout)

    def test_provider_installer_uses_container_wizard_without_host_python(self) -> None:
        """The current Provider flow must not execute host Python or pip."""

        with tempfile.TemporaryDirectory(prefix="mycomesh-provider-python-") as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            fake_python = bin_dir / "python3"
            fake_python.write_text(
                "#!/bin/sh\nexit 91\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            fake_docker = bin_dir / "docker"
            fake_docker.write_text(
                """#!/bin/sh
if [ "${1-}" = "--version" ]; then echo 'Docker version 28.0.0'; exit 0; fi
if [ "${1-}" = "compose" ] && [ "${2-}" = "version" ]; then echo 'Docker Compose version v2.0'; exit 0; fi
exit 0
""",
                encoding="utf-8",
            )
            fake_docker.chmod(0o700)
            fake_make = bin_dir / "make"
            fake_make.write_text(
                """#!/bin/sh
if [ "${1-}" = "--version" ]; then echo 'GNU Make 4.4'; exit 0; fi
exit 0
""",
                encoding="utf-8",
            )
            fake_make.chmod(0o700)
            config = root / "state" / "settings.json"
            env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
                "MYCOMESH_DOCKER_CLI": str(fake_docker),
                "MYCOMESH_PROVIDER_OPERATOR_CONFIG": str(config),
                "MYCOMESH_PROVIDER_IMAGE": "example/provider:test",
            }
            env.pop("MYCOMESH_PROVIDER_PYTHON", None)
            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts/install-provider.sh"),
                    "--dry-run",
                    "--no-browser",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("provider-onboarding-container.sh", result.stdout)
            self.assertIn("--image example/provider:test", result.stdout)
            self.assertIn("--no-browser", result.stdout)

    def test_production_loopback_upstreams_are_fixed(self) -> None:
        self.assertIn(
            '"${MYCOMESH_PROXY_BIND_ADDRESS:-127.0.0.1}:${MYCOMESH_PROXY_HOST_PORT:-8100}:8100"',
            _service_block(self.compose, "proxy"),
        )
        self.assertIn('"127.0.0.1:9800:9800"', _service_block(self.compose, "bridge"))
        relay = _service_block(self.compose, "relay")
        self.assertIn('"127.0.0.1:9900:9900"', relay)
        self.assertIn('"127.0.0.1:19901:9901"', relay)

    def test_proxy_and_provider_share_the_pinned_public_model_and_limits(self) -> None:
        proxy = _service_block(self.compose, "proxy")
        provider = _service_block(self.compose, "provider")
        sidecar = _service_block(self.compose, "provider-sidecar")
        for block in (proxy, provider):
            self.assertIn("mycomesh-codex-standard-v1", block)
            self.assertIn('MYCOMESH_RESERVE_INPUT_TOKENS: "65536"', block)
            self.assertIn('MYCOMESH_RESERVE_OUTPUT_TOKENS: "2000"', block)
        self.assertIn("PUBLIC_MODEL_ID: mycomesh-codex-standard-v1", sidecar)
        self.assertIn("MYCOMESH_PUBLIC_MODEL_ID: mycomesh-codex-standard-v1", proxy)
        self.assertIn("PUBLIC_MODEL_ID: mycomesh-codex-standard-v1", provider)
        self.assertIn(
            "MYCOMESH_PROVIDER_BACKEND: ${GATEWAY_BACKEND:-openai_http}",
            provider,
        )
        self.assertIn(
            "GATEWAY_BACKEND: ${GATEWAY_BACKEND:-openai_http}",
            provider,
        )

    def test_public_gateway_is_an_explicit_consumer_allowlist(self) -> None:
        for route in (
            "/health",
            "/.well-known/mycomesh.json",
            "/v1/mycomesh/gateways",
            "/v1/models",
            "/v1/mycomesh/keys/challenge",
            "/v1/mycomesh/keys/register",
            "/v1/mycomesh/keys/rotate",
            "/v1/mycomesh/keys/current",
            "/account",
            "/v1/mycomesh/v3/prepare",
            "/v1/mycomesh/session/prepare",
            "/v1/responses",
            "/v1/chat/completions",
        ):
            self.assertIn(f"location = {route} {{", self.nginx)
        self.assertIn("include /etc/nginx/snippets/mycomesh-upstream.conf;", self.nginx)
        self.assertIn("proxy_pass http://mycomesh_gateway;", self.nginx)
        self.assertNotIn("proxy_pass http://127.0.0.1:8100;", self.nginx)
        for route in (
            "/admin",
            "/accounts",
            "/gateways",
            "/docs",
            "/redoc",
            "/openapi.json",
        ):
            self.assertIn(route, self.nginx)
        self.assertIn(
            """location / {
        return 404 '{"detail":"not found"}';
    }""",
            self.nginx,
        )
        self.assertNotIn("$proxy_add_x_forwarded_for", self.nginx)
        self.assertNotIn("$proxy_add_x_forwarded_for", self.nginx_proxy)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", self.nginx_proxy)

    def test_bridge_infer_and_provider_stream_tls_topology_is_preserved(self) -> None:
        self.assertIn("location ^~ /infer/", self.nginx)
        self.assertIn("location = /relay/health", self.nginx)
        self.assertIn("location ~ ^/v1/(responses(?:/compact)?|chat/completions)$", self.nginx)
        self.assertIn("limit_except POST OPTIONS", self.nginx)
        self.assertIn("proxy_pass http://127.0.0.1:9900;", self.nginx)
        self.assertIn("listen 9901 ssl;", self.nginx_stream)

    def test_nginx_tls_is_ubuntu_lts_and_rsa_certificate_compatible(self) -> None:
        self.assertNotIn("ssl_reject_handshake", self.nginx)
        default_tls = next(
            block
            for block in _nginx_server_blocks(self.nginx)
            if "listen 443 ssl http2 default_server;" in block
        )
        self.assertIn("include /etc/nginx/snippets/mycomesh-tls.conf;", default_tls)
        self.assertIn("return 444;", default_tls)
        self.assertIn("ECDHE-ECDSA-AES256-GCM-SHA384", self.nginx_tls)
        self.assertIn("ECDHE-RSA-AES256-GCM-SHA384", self.nginx_tls)

    def test_nginx_bootstrap_only_serves_acme_challenges(self) -> None:
        self.assertIn("listen 80 default_server;", self.nginx_bootstrap)
        self.assertIn("listen [::]:80 default_server;", self.nginx_bootstrap)
        self.assertIn("server_name _;", self.nginx_bootstrap)
        self.assertIn("location ^~ /.well-known/acme-challenge/", self.nginx_bootstrap)
        self.assertIn("return 404;", self.nginx_bootstrap)
        self.assertNotIn("listen 443", self.nginx_bootstrap)
        self.assertNotIn("proxy_pass", self.nginx_bootstrap)
        self.assertIn("proxy_pass 127.0.0.1:19901;", self.nginx_stream)

    def test_plain_http_only_allows_acme_health_or_https_redirects(self) -> None:
        http_blocks = [
            block
            for block in _nginx_server_blocks(self.nginx)
            if re.search(r"^\s*listen (?:\[::\]:)?80(?:\s|;)", block, flags=re.MULTILINE)
        ]
        self.assertEqual(len(http_blocks), 4)
        allowed_locations = {
            "^~ /.well-known/acme-challenge/",
            "= /healthz",
            "/",
        }
        for block in http_blocks:
            with self.subTest(server=re.search(r"server_name ([^;]+);", block).group(1)):
                locations = {
                    " ".join(match.group(1).split())
                    for match in re.finditer(
                        r"^\s*location\s+([^\{]+)\{",
                        block,
                        flags=re.MULTILINE,
                    )
                }
                self.assertLessEqual(locations, allowed_locations)
                self.assertNotIn("root /var/www/mycomesh", block)
                self.assertNotIn("index index.html", block)
                self.assertNotIn("proxy_pass", block)
                self.assertNotRegex(block, r"location\s+~")
                if "default_server" in block:
                    self.assertIn("return 444;", block)
                else:
                    self.assertIn("return 301 https://$host$request_uri;", block)

    def test_image_and_dependency_inputs_are_pinned(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("--shell /usr/sbin/nologin mycomesh", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("python -m pip install --require-hashes -r requirements.lock", dockerfile)
        self.assertIn("npm ci --omit=dev --ignore-scripts", dockerfile)
        self.assertNotIn("npm install --global", dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^\s*VOLUME(?:\s|\[)")
        self.assertIn(
            "COPY --from=codex-cli /opt/codex-cli/node_modules /opt/codex-cli/node_modules",
            dockerfile,
        )
        self.assertNotRegex(dockerfile, r"COPY[^\n]*codex-linux-(?:x64|arm64)")
        self.assertRegex(dockerfile, r"FROM node:[^\n]+@sha256:[0-9a-f]{64}")
        self.assertRegex(dockerfile, r"FROM python:[^\n]+@sha256:[0-9a-f]{64}")

        expected = (
            "fastapi==0.139.0",
            "httpx==0.28.1",
            "cryptography==46.0.7",
            "python-dotenv==1.2.2",
            "pycryptodome==3.23.0",
            "psycopg==3.3.4",
            "psycopg-binary==3.3.4",
            "uvicorn==0.51.0",
        )
        lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
        for requirement in expected:
            self.assertIn(requirement, lock)
        self.assertGreater(lock.count("--hash=sha256:"), 50)

        codex_lock = json.loads(
            (ROOT / "deploy/codex-cli/package-lock.json").read_text(encoding="utf-8")
        )
        codex = codex_lock["packages"]["node_modules/@openai/codex"]
        self.assertEqual(codex["version"], "0.144.1")
        self.assertTrue(codex["integrity"].startswith("sha512-"))
        for architecture in ("x64", "arm64"):
            with self.subTest(codex_architecture=architecture):
                linux = codex_lock["packages"][
                    f"node_modules/@openai/codex-linux-{architecture}"
                ]
                self.assertEqual(linux["version"], f"0.144.1-linux-{architecture}")
                self.assertTrue(linux["integrity"].startswith("sha512-"))

    def test_nginx_install_order_is_fail_closed(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        install = makefile.split("\nnginx-install:", maxsplit=1)[1]
        certificate = install.index('$(MYCOMESH_CERT_DIR)/fullchain.pem')
        web = install.index('$(MYCOMESH_WEB_ROOT)/index.html')
        tls = install.index("deploy/nginx-mycomesh-tls.conf")
        proxy = install.index("deploy/nginx-mycomesh-proxy.conf")
        stream = install.index("deploy/nginx-mycomesh-stream.conf")
        site = install.index("deploy/nginx-mycomesh.conf")
        check = install.index("sudo nginx -t")
        reload_at = install.index("sudo systemctl reload nginx")
        renewal_hook = install.index("mycomesh-reload-nginx")
        self.assertLess(certificate, tls)
        self.assertLess(web, tls)
        self.assertLess(tls, stream)
        self.assertLess(proxy, stream)
        self.assertLess(stream, site)
        self.assertLess(site, renewal_hook)
        self.assertLess(renewal_hook, check)
        self.assertLess(site, check)
        self.assertLess(check, reload_at)
        self.assertIn('sudo test -r "$(MYCOMESH_CERT_DIR)/fullchain.pem"', install)
        self.assertIn(
            'sudo mktemp -d "$(MYCOMESH_WEB_RELEASE_ROOT)/$$(git rev-parse',
            makefile,
        )
        self.assertIn('sudo ln -sfnT "$$mycomesh_release"', makefile)
        self.assertIn("npm --prefix web ci --ignore-scripts --legacy-peer-deps", makefile)

    def test_deploy_env_and_proxy_identity_restore_are_fail_closed(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            'install -m 0600 .env.deploy.example "$(DEPLOY_ENV_FILE)"',
            makefile,
        )
        self.assertIn('chmod 0600 "$(DEPLOY_ENV_FILE)"', makefile)
        self.assertNotIn("--env-file .env.deploy", makefile)
        self.assertIn("proxy-up: proxy-preflight", makefile)
        self.assertIn("proxy-relayer-address: proxy-preflight", makefile)
        self.assertIn('--env-file "$(DEPLOY_ENV_FILE)" --check', makefile)
        bootstrap = makefile.split("\nnginx-bootstrap-install:", maxsplit=1)[1].split(
            "\nnginx-install:", maxsplit=1
        )[0]
        self.assertIn("sudo rm -f /etc/nginx/sites-enabled/default", bootstrap)
        self.assertIn("proxy-identity-import: deploy-env", makefile)
        proxy_init = _service_block(self.compose, "proxy-volume-init")
        self.assertIn("gateway.proxy_identity validate", proxy_init)
        self.assertNotIn("load_or_create_identity", proxy_init)

    def test_v6_browser_and_relay_release_coordinates_are_pinned(self) -> None:
        settlement = "0xdba9f8c7f5de5205459ad908beece27b5dd9e981"
        relay_payment = "0x27bd63aef83554700042685c2862da6f6a9197e8"
        for relative in ("web/.env.production", "web/.env.example"):
            with self.subTest(path=relative):
                values = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(f"VITE_SESSION_SETTLEMENT_ADDRESS={settlement}", values)
                self.assertIn("VITE_SESSION_PROTOCOL_VERSION=6", values)
                self.assertIn("VITE_SESSION_DEPLOYMENT_BLOCK=11397972", values)

        network = json.loads(
            (ROOT / "deployments" / "sepolia-provider-network-v6.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(network["relay"]["payment_address"], relay_payment)

    def test_relay_payment_address_is_required_and_health_checked(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        relay = _service_block(self.compose, "relay")
        provider = _service_block(self.compose, "provider")
        deploy_example = (ROOT / ".env.deploy.example").read_text(encoding="utf-8")

        self.assertIn("MYCOMESH_RELAY_PAYMENT_ADDRESS: ${MYCOMESH_RELAY_PAYMENT_ADDRESS:-}", relay)
        self.assertIn('--payment-address "$$MYCOMESH_RELAY_PAYMENT_ADDRESS"', relay)
        self.assertIn(
            "public-node Relay payment address is required",
            relay,
        )
        self.assertIn("value.get('relay_payment_address') == expected", relay)
        self.assertIn(
            "MYCOMESH_RELAY_PAYMENT_ADDRESS=$(PUBLIC_NODE_RELAY_PAYMENT_ADDRESS)",
            makefile,
        )
        public_health = makefile[
            makefile.index("public-node-health:"):
            makefile.index("public-node-tls-health:")
        ]
        self.assertIn('value.get("relay_payment_address")', public_health)
        self.assertIn(
            "MYCOMESH_RELAY_PAYMENT_ADDRESS=0x27bd63aef83554700042685c2862da6f6a9197e8",
            deploy_example,
        )
        self.assertIn(
            "MYCOMESH_SESSION_RELAY_PAYMENT_ADDRESS=0x27bd63aef83554700042685c2862da6f6a9197e8",
            deploy_example,
        )
        self.assertIn(
            "MYCOMESH_PROVIDER_PAYMENT_ADDRESS=$(PROVIDER_PAYMENT_ADDRESS)",
            makefile,
        )
        self.assertNotIn("\tMYCOMESH_PROVIDER_PAYMENT_ADDRESS= \\", makefile)

        self.assertIn(
            "V8 reads the payout address from the protected operator profile",
            provider,
        )
        self.assertNotIn(
            '--payment-address "$$MYCOMESH_PROVIDER_PAYMENT_ADDRESS"',
            provider,
        )

    def test_provider_evm_identity_restore_target_is_fail_closed(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn("provider-identity-import: deploy-env", makefile)
        self.assertIn('test ! -L "$(PROVIDER_EVM_IDENTITY_FILE)"', makefile)
        self.assertIn("gateway.provider_identity import", makefile)
        self.assertIn(
            "--target /volumes/provider/provider-evm-identity.json",
            makefile,
        )


if __name__ == "__main__":
    unittest.main()
