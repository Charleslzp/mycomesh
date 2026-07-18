COMPOSE ?= docker compose
SERVICE ?= gateway
IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= charleslzp
IMAGE_TAG ?=
NODE_IMAGE ?= $(if $(IMAGE_TAG),$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/mycomesh-node:$(IMAGE_TAG))
PROVIDER_IMAGE ?= $(if $(IMAGE_TAG),$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/mycomesh-provider-codex:$(IMAGE_TAG))
NODE_IMAGE_ENV = MYCOMESH_NODE_IMAGE=$(NODE_IMAGE)
PROVIDER_IMAGE_ENV = MYCOMESH_PROVIDER_IMAGE=$(PROVIDER_IMAGE)
# Optional public Ed25519 identity for Gateway/V2 Relay compatibility and signed
# reputation updates. Browser V3 Consumer admission does not depend on this key.
PUBLIC_NODE_CONSUMER_KEY ?= 48f8698d2031fe20d13c2e6b5bde6f06c4900a72e730ded3799f367c36f12242
PUBLIC_NODE_RPC_URL ?= https://sepolia.drpc.org
PUBLIC_NODE_ENV = \
	MYCOMESH_PUBLIC_NODE_STRICT=true \
	MYCOMESH_NETWORK_PROFILE=testnet \
	MYCOMESH_NETWORK_ID=mycomesh-testnet \
	MYCO_DEPLOYMENT=/app/deployments/sepolia-myco-v3.json \
	MYCOMESH_POOL_PUBLIC_URL=https://bridge.mycomesh.xyz \
	MYCOMESH_POOL_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz,http://127.0.0.1:8110,http://localhost:8110 \
	MYCOMESH_RELAY_PUBLIC_URL=https://bridge.mycomesh.xyz \
	MYCOMESH_RELAY_ADVERTISE_HOST=bridge.mycomesh.xyz \
	MYCOMESH_RELAY_ADVERTISE_CONTROL_PORT=443 \
	MYCOMESH_RELAY_ADVERTISE_PROVIDER_PORT=9901 \
	MYCOMESH_BRIDGE_ADMISSION_MODE=any-signed \
	MYCOMESH_BRIDGE_REPUTATION_SIGNER_PUBLIC_KEYS=$(PUBLIC_NODE_CONSUMER_KEY) \
	MYCOMESH_BRIDGE_TRUST_PROXY_HEADERS=true \
	MYCOMESH_BRIDGE_TRUSTED_RELAY_ORIGINS=https://bridge.mycomesh.xyz \
	MYCOMESH_BRIDGE_EXTRA_ARGS= \
	MYCOMESH_RELAY_EXTRA_ARGS= \
	MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER=false \
	MYCOMESH_RELAY_CONSUMER_PUBLIC_KEYS=$(PUBLIC_NODE_CONSUMER_KEY) \
	MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz,http://127.0.0.1:8110,http://localhost:8110 \
	MYCOMESH_RELAY_V3_ADMISSION_DEPLOYMENT=/app/deployments/sepolia-myco-v3.json \
	MYCOMESH_RELAY_V3_ADMISSION_RPC_URL=$(PUBLIC_NODE_RPC_URL) \
	MYCOMESH_RELAY_V3_ADMISSION_CONFIRMATIONS=6 \
	MYCOMESH_RELAY_TRUST_PROXY_HEADERS=true \
	MYCOMESH_BRIDGE_BIND_ADDRESS=127.0.0.1 \
	MYCOMESH_RELAY_CONTROL_BIND_ADDRESS=127.0.0.1 \
	MYCOMESH_RELAY_PROVIDER_BIND_ADDRESS=127.0.0.1

PROVIDER_TRANSPORT ?=
PROVIDER_RPC_URL ?=
PROVIDER_BIND_ADDRESS ?= 127.0.0.1
PROVIDER_ENV = \
	GATEWAY_BACKEND=codex_app_server \
	PUBLIC_MODEL_ID=mycomesh-codex-standard-v1 \
	MYCOMESH_RESERVE_INPUT_TOKENS=8000 \
	MYCOMESH_RESERVE_OUTPUT_TOKENS=2000 \
	UPSTREAM_API_KEY= \
	CODEX_PROVIDER_BASE_URL= \
	MYCOMESH_NETWORK_PROFILE=testnet \
	MYCOMESH_NETWORK_ID=mycomesh-testnet \
	MYCOMESH_CODEX_TESTNET_METERING=true \
	MYCOMESH_PROVIDER_NETWORK_CONFIG=/app/deployments/sepolia-provider-network.json \
	MYCOMESH_PROVIDER_EVM_IDENTITY=/data/provider-evm-identity.json \
	MYCOMESH_PROVIDER_POOL_URL= \
	MYCOMESH_PROVIDER_TRANSPORT=$(PROVIDER_TRANSPORT) \
	MYCOMESH_PROVIDER_ADVERTISE_HOST=auto \
	MYCOMESH_PROVIDER_BIND_ADDRESS=$(PROVIDER_BIND_ADDRESS) \
	MYCOMESH_PROVIDER_CONSUMER_PUBLIC_KEY= \
	MYCOMESH_PROVIDER_PAYMENT_ADDRESS= \
	MYCOMESH_PROVIDER_PRICING_HASH= \
	MYCOMESH_PROVIDER_EXTRA_ARGS= \
	MYCOMESH_SETTLEMENT_VERSION=3 \
	MYCOMESH_PRICING_VERSION= \
	MYCOMESH_SETTLEMENT_RPC_URL=$(PROVIDER_RPC_URL) \
	MYCOMESH_SETTLEMENT_CONTRACT= \
	MYCOMESH_SETTLEMENT_CHAIN_ID= \
	MYCO_DEPLOYMENT=/app/deployments/sepolia-myco-v3.json \
	MYCO_SETTLEMENT= \
	MYCO_TOKEN= \
	MYCO_TEST_USDC= \
	MYCO_TREASURY= \
	MYCO_CHANNEL_HASH=

.PHONY: deploy-env require-node-image require-provider-image build images-show node-image-pull provider-image-pull images-pull consumer-up consumer-up-image consumer-down consumer-health consumer-logs consumer-credentials gateway proxy proxy-up proxy-up-image proxy-down proxy-health proxy-logs proxy-identity proxy-identity-import bridge relay public-node-up public-node-up-image main-node-up-image public-node-down public-node-health public-node-logs provider provider-login provider-login-image provider-auth-status-image provider-up provider-up-image provider-down provider-health provider-identity demo up down logs ps test smoke package-install nginx-install

deploy-env:
	@if [ ! -f .env.deploy ]; then install -m 0600 .env.deploy.example .env.deploy; else chmod 0600 .env.deploy; fi

require-node-image:
	@if [ -z "$(NODE_IMAGE)" ]; then echo "Set IMAGE_TAG or NODE_IMAGE explicitly." >&2; exit 2; fi

require-provider-image:
	@if [ -z "$(PROVIDER_IMAGE)" ]; then echo "Set IMAGE_TAG or PROVIDER_IMAGE explicitly." >&2; exit 2; fi

build:
	$(COMPOSE) --env-file .env.deploy --profile gateway --profile bridge --profile provider --profile proxy --profile relay build

images-show: deploy-env require-node-image require-provider-image
	$(NODE_IMAGE_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile gateway --profile consumer --profile public-node --profile proxy --profile provider config --images

node-image-pull: deploy-env require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile gateway --profile consumer --profile public-node --profile proxy pull gateway consumer-volume-init consumer proxy-volume-init proxy indexer public-node-volume-init bridge relay postgres

provider-image-pull: deploy-env require-provider-image
	$(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider pull provider-volume-init provider

images-pull: node-image-pull provider-image-pull

consumer-up: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile consumer config --quiet
	$(COMPOSE) --env-file .env.deploy --profile consumer up -d --build --wait --wait-timeout 90 consumer

consumer-up-image: deploy-env require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile consumer config --quiet
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile consumer up -d --no-build --wait --wait-timeout 90 consumer

consumer-down:
	$(COMPOSE) --env-file .env.deploy --profile consumer stop consumer

consumer-health:
	curl --fail --silent --show-error http://127.0.0.1:8110/health

consumer-logs:
	$(COMPOSE) --env-file .env.deploy --profile consumer logs --tail=200 consumer

consumer-credentials:
	$(COMPOSE) --env-file .env.deploy --profile consumer exec consumer python -m gateway.local_consumer credentials

gateway: deploy-env
	$(COMPOSE) --env-file .env.deploy up --build gateway

proxy: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile proxy up --build indexer proxy

proxy-up: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile proxy config --quiet
	$(COMPOSE) --env-file .env.deploy --profile proxy up -d --build --wait --wait-timeout 180 indexer proxy

proxy-up-image: deploy-env require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile proxy config --quiet
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile proxy up -d --no-build --wait --wait-timeout 180 indexer proxy

proxy-down:
	$(COMPOSE) --env-file .env.deploy --profile proxy stop proxy indexer postgres

proxy-health:
	$(COMPOSE) --env-file .env.deploy --profile proxy exec -T indexer python -m gateway.indexer_service health
	$(COMPOSE) --env-file .env.deploy --profile proxy exec -T proxy python -c 'import json, urllib.request; value=json.load(urllib.request.urlopen("http://127.0.0.1:8100/health", timeout=5)); assert value.get("ok") is True; assert value.get("billing_mode") == "onchain-prepaid"; print(json.dumps(value, sort_keys=True))'

proxy-logs:
	$(COMPOSE) --env-file .env.deploy --profile proxy logs -f indexer proxy

bridge: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile bridge up --build bridge

relay: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile relay up --build relay

public-node-up: deploy-env
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node config --quiet
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node up -d --build --wait --wait-timeout 180 bridge relay

public-node-up-image: deploy-env require-node-image
	$(PUBLIC_NODE_ENV) $(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node config --quiet
	$(PUBLIC_NODE_ENV) $(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node up -d --no-build --wait --wait-timeout 180 bridge relay

main-node-up-image: public-node-up-image proxy-up-image

public-node-down:
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node stop relay bridge

public-node-health:
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node exec -T bridge python -c 'import json, urllib.request; value=json.load(urllib.request.urlopen("http://127.0.0.1:9800/health", timeout=5)); assert value.get("ok") is True; assert value.get("network_profile") == "testnet"; assert isinstance(value.get("settlement"), dict); print(json.dumps(value, sort_keys=True))'
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node exec -T relay python -c 'import json, urllib.request; value=json.load(urllib.request.urlopen("http://127.0.0.1:9900/health", timeout=5)); assert value.get("ok") is True; print(json.dumps(value, sort_keys=True))'
	python3 -c 'import socket, ssl; raw=socket.create_connection(("127.0.0.1", 9901), 5); ctx=ssl.create_default_context(); tls=ctx.wrap_socket(raw, server_hostname="bridge.mycomesh.xyz"); print("relay_provider_tls:", tls.version()); tls.close()'

public-node-logs:
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file .env.deploy --profile public-node logs -f bridge relay

provider: deploy-env
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider up --build provider

provider-login: deploy-env
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --build provider-volume-init
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --build --entrypoint sh provider -ec '\
		umask 077; \
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}"; \
		python -m gateway login; \
		exec python -m gateway codex-provider status --codex-home "$$CODEX_HOME"'

provider-login-image: deploy-env require-provider-image
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps provider-volume-init
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --entrypoint sh provider -ec '\
		umask 077; \
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}"; \
		python -m gateway login; \
		exec python -m gateway codex-provider status --codex-home "$$CODEX_HOME"'

provider-auth-status-image: deploy-env require-provider-image
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --entrypoint sh provider -ec '\
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}" >/dev/null; \
		exec python -m gateway codex-provider status --codex-home "$$CODEX_HOME"'

provider-up: deploy-env
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider config --quiet
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider up -d --build --wait --wait-timeout 120 provider

provider-up-image: deploy-env require-provider-image
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider config --quiet
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider up -d --no-build --wait --wait-timeout 120 provider

provider-down:
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider stop provider

provider-health:
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider exec -T provider sh -ec '\
		umask 077; \
		if [ "$${GATEWAY_BACKEND:-}" = codex_app_server ] || [ "$${GATEWAY_BACKEND:-}" = codex_cli ]; then \
			python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}" >/dev/null; \
			python -m gateway codex-provider status --codex-home "$$CODEX_HOME" >/dev/null; \
		fi; \
		set -- python -m gateway health --url http://127.0.0.1:8000/health --timeout 5; \
		if [ "$${MYCOMESH_NETWORK_PROFILE:-local}" != local ]; then set -- "$$@" --require-settlement-ready; fi; \
		"$$@"; \
		if [ "$${MYCOMESH_PROVIDER_TRANSPORT-}" = direct ]; then \
			exec python -m gateway p2p ping tcp://127.0.0.1:9700 --timeout 5 --require-bridge-ready; \
		elif [ "$${MYCOMESH_NETWORK_PROFILE:-local}" != local ]; then \
			exec python -m gateway.provider_bootstrap --require-bridge-lease; \
		fi'

provider-identity: deploy-env
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --build provider-volume-init
	$(PROVIDER_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --entrypoint sh provider -ec '\
		python -m gateway identity show \
			--identity "$${MYCOMESH_PROVIDER_IDENTITY:-/data/node-identity.json}"; \
		exec python -m gateway.provider_bootstrap \
			--identity "$${MYCOMESH_PROVIDER_EVM_IDENTITY:-/data/provider-evm-identity.json}"'

proxy-identity: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile proxy run --rm --no-deps --build proxy-volume-init
	$(COMPOSE) --env-file .env.deploy --profile proxy run --rm --no-deps proxy identity show --identity /data/request-identity.json

proxy-identity-import: deploy-env
	@test -n "$(PROXY_IDENTITY_FILE)" || { echo "PROXY_IDENTITY_FILE=/secure/request-identity.json is required" >&2; exit 64; }
	@test -f "$(PROXY_IDENTITY_FILE)" || { echo "PROXY_IDENTITY_FILE must be a regular file" >&2; exit 64; }
	$(COMPOSE) --env-file .env.deploy --profile proxy run --rm --no-deps --build \
		--volume "$(abspath $(PROXY_IDENTITY_FILE)):/import/request-identity.json:ro" \
		--entrypoint python proxy-volume-init -m gateway.proxy_identity import \
			--source /import/request-identity.json \
			--target /volumes/proxy/request-identity.json \
			--manifest /app/deployments/sepolia-provider-network.json
	$(COMPOSE) --env-file .env.deploy --profile proxy run --rm --no-deps proxy-volume-init

demo: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile bridge --profile provider --profile proxy up --build

up: demo

down:
	$(COMPOSE) --env-file .env.deploy --profile bridge --profile provider --profile proxy --profile relay down

logs:
	$(COMPOSE) --env-file .env.deploy logs -f $(SERVICE)

ps:
	$(COMPOSE) --env-file .env.deploy ps

test:
	python -m unittest discover -s tests -q

smoke:
	python -m gateway --help >/dev/null
	python -m gateway identity show --identity /tmp/mycomesh-smoke-identity.json --json >/dev/null

package-install:
	python -m pip install -e .

nginx-install:
	@test -r /usr/lib/nginx/modules/ngx_stream_module.so || { \
		echo "nginx stream module is required; install libnginx-mod-stream first" >&2; \
		exit 1; \
	}
	sudo install -d -m 0755 /etc/nginx/snippets /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/modules-enabled
	sudo install -m 0644 deploy/nginx-mycomesh-tls.conf /etc/nginx/snippets/mycomesh-tls.conf
	sudo install -m 0644 deploy/nginx-mycomesh-proxy.conf /etc/nginx/snippets/mycomesh-proxy.conf
	sudo install -m 0644 deploy/nginx-mycomesh-stream.conf /etc/nginx/modules-enabled/90-mycomesh-stream.conf
	sudo install -m 0644 deploy/nginx-mycomesh.conf /etc/nginx/sites-available/mycomesh
	sudo ln -sfn /etc/nginx/sites-available/mycomesh /etc/nginx/sites-enabled/mycomesh
	sudo rm -f /etc/nginx/sites-enabled/default
	sudo nginx -t
	sudo systemctl reload nginx
