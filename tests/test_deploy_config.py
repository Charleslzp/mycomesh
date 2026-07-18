from __future__ import annotations

import json
import re
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
        cls.nginx_stream = (ROOT / "deploy/nginx-mycomesh-stream.conf").read_text(
            encoding="utf-8"
        )

    def test_production_roles_are_nonroot_and_volumes_are_isolated(self) -> None:
        for name in ("proxy", "indexer", "bridge", "relay", "provider"):
            with self.subTest(service=name):
                self.assertIn('user: "10001:10001"', _service_block(self.compose, name))
        self.assertIn('user: "0:0"', _service_block(self.compose, "gateway"))
        self.assertIn("mycomesh-gateway-data:/data", _service_block(self.compose, "gateway"))
        self.assertIn("mycomesh-proxy-data:/data", _service_block(self.compose, "proxy"))
        self.assertNotIn("mycomesh-proxy-data", _service_block(self.compose, "provider"))
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
            "provider": (512, "2g", "4.0"),
        }
        for name, (pids, memory, cpus) in expected_limits.items():
            with self.subTest(service=name):
                block = _service_block(self.compose, name)
                self.assertIn(f"pids_limit: {pids}", block)
                self.assertIn(f"mem_limit: {memory}", block)
                self.assertIn(f'cpus: "{cpus}"', block)
                self.assertIn("logging: *production-logging", block)

    def test_public_node_enables_browser_v3_admission_without_open_bypasses(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        public_node_start = makefile.index("PUBLIC_NODE_ENV = \\\n")
        public_node_end = makefile.index("\n\n", public_node_start)
        public_node_env = makefile[public_node_start:public_node_end]
        self.assertIn("MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER=false", public_node_env)
        self.assertNotIn("MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER=true", public_node_env)
        self.assertIn(
            "MYCOMESH_RELAY_CONSUMER_PUBLIC_KEYS=$(PUBLIC_NODE_CONSUMER_KEY)",
            public_node_env,
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

    def test_role_environments_do_not_cross_secret_boundaries(self) -> None:
        bridge = _service_block(self.compose, "bridge")
        relay = _service_block(self.compose, "relay")
        provider = _service_block(self.compose, "provider")
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
        self.assertEqual(pull.group(1).split(), ["provider-volume-init", "provider"])

    def test_provider_entrypoint_clears_persistent_child_pid_files_before_start(self) -> None:
        provider = _service_block(self.compose, "provider")
        cleanup = 'rm -f "$$run_dir"/gateway-*.pid "$$run_dir"/provider-*.pid'
        start = 'set -- python -m gateway provider start'

        self.assertIn('run_dir="$${MYCOMESH_PROVIDER_RUN_DIR:-/data/run}"', provider)
        self.assertIn(cleanup, provider)
        self.assertLess(provider.index(cleanup), provider.index(start))
        self.assertIn('--run-dir "$$run_dir"', provider)

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

    def test_provider_runtime_selects_v3_or_v4_without_weakening_v3_finality(self) -> None:
        provider = _service_block(self.compose, "provider")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn(
            "MYCOMESH_SETTLEMENT_VERSION: ${MYCOMESH_PROVIDER_SETTLEMENT_VERSION:-${MYCOMESH_SETTLEMENT_VERSION:-3}}",
            provider,
        )
        self.assertIn("case \"$$settlement_version\" in", provider)
        self.assertIn("3|4) ;;", provider)
        self.assertIn(
            'if [ "$$settlement_version" = "3" ] && '
            '[ "$$MYCOMESH_SETTLEMENT_CONFIRMATIONS" -lt 6 ]; then',
            provider,
        )
        self.assertIn(
            "PROVIDER_SETTLEMENT_VERSION ?= $(or $(MYCOMESH_PROVIDER_SETTLEMENT_VERSION),$(call deploy_env_value,MYCOMESH_PROVIDER_SETTLEMENT_VERSION),4)",
            makefile,
        )
        self.assertIn(
            "sepolia-provider-network-v4.json",
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
        self.assertIn("MYCOMESH_PROVIDER_SETTLEMENT_VERSION=4", deploy_example)
        self.assertIn(
            "MYCOMESH_PROVIDER_NETWORK_CONFIG=/app/deployments/sepolia-provider-network-v4.json",
            deploy_example,
        )
        self.assertIn(
            "MYCOMESH_PROVIDER_DEPLOYMENT=/app/deployments/sepolia-myco-v4.json",
            deploy_example,
        )
        installer = (ROOT / "scripts" / "install-provider.sh").read_text(encoding="utf-8")
        self.assertIn('PUBLIC_PROVIDER_SETTLEMENT_VERSION="4"', installer)
        self.assertIn(
            'PUBLIC_PROVIDER_NETWORK_CONFIG="/app/deployments/sepolia-provider-network-v4.json"',
            installer,
        )
        self.assertIn(
            'PUBLIC_PROVIDER_DEPLOYMENT="/app/deployments/sepolia-myco-v4.json"',
            installer,
        )
        self.assertIn('"PROVIDER_SETTLEMENT_VERSION=$PUBLIC_PROVIDER_SETTLEMENT_VERSION"', installer)
        self.assertIn('"PROVIDER_NETWORK_CONFIG=$PUBLIC_PROVIDER_NETWORK_CONFIG"', installer)
        self.assertIn('"PROVIDER_DEPLOYMENT=$PUBLIC_PROVIDER_DEPLOYMENT"', installer)
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

    def test_production_loopback_upstreams_are_fixed(self) -> None:
        self.assertIn('"127.0.0.1:8100:8100"', _service_block(self.compose, "proxy"))
        self.assertIn('"127.0.0.1:9800:9800"', _service_block(self.compose, "bridge"))
        relay = _service_block(self.compose, "relay")
        self.assertIn('"127.0.0.1:9900:9900"', relay)
        self.assertIn('"127.0.0.1:19901:9901"', relay)

    def test_proxy_and_provider_share_the_pinned_public_model_and_limits(self) -> None:
        proxy = _service_block(self.compose, "proxy")
        provider = _service_block(self.compose, "provider")
        for block in (proxy, provider):
            self.assertIn("mycomesh-codex-standard-v1", block)
            self.assertIn('MYCOMESH_RESERVE_INPUT_TOKENS: "8000"', block)
            self.assertIn('MYCOMESH_RESERVE_OUTPUT_TOKENS: "2000"', block)
        self.assertIn("MYCOMESH_PUBLIC_MODEL_ID: mycomesh-codex-standard-v1", proxy)
        self.assertIn("PUBLIC_MODEL_ID: mycomesh-codex-standard-v1", provider)

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
        self.assertIn("limit_except POST OPTIONS", self.nginx)
        self.assertIn("proxy_pass http://127.0.0.1:9900;", self.nginx)
        self.assertIn("listen 9901 ssl;", self.nginx_stream)
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
        tls = makefile.index("deploy/nginx-mycomesh-tls.conf")
        proxy = makefile.index("deploy/nginx-mycomesh-proxy.conf")
        stream = makefile.index("deploy/nginx-mycomesh-stream.conf")
        site = makefile.index("deploy/nginx-mycomesh.conf")
        check = makefile.index("sudo nginx -t")
        reload_at = makefile.index("sudo systemctl reload nginx")
        self.assertLess(tls, stream)
        self.assertLess(proxy, stream)
        self.assertLess(stream, site)
        self.assertLess(site, check)
        self.assertLess(check, reload_at)

    def test_deploy_env_and_proxy_identity_restore_are_fail_closed(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("install -m 0600 .env.deploy.example .env.deploy", makefile)
        self.assertIn("chmod 0600 .env.deploy", makefile)
        self.assertIn("proxy-identity-import: deploy-env", makefile)
        proxy_init = _service_block(self.compose, "proxy-volume-init")
        self.assertIn("gateway.proxy_identity validate", proxy_init)
        self.assertNotIn("load_or_create_identity", proxy_init)


if __name__ == "__main__":
    unittest.main()
