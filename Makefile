COMPOSE ?= docker compose
SERVICE ?= gateway
IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= charleslzp
IMAGE_TAG ?=
NODE_IMAGE ?= $(if $(IMAGE_TAG),$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/mycomesh-node:$(IMAGE_TAG))
PROVIDER_IMAGE ?= $(if $(IMAGE_TAG),$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/mycomesh-provider-codex:$(IMAGE_TAG))
NODE_IMAGE_ENV = MYCOMESH_NODE_IMAGE=$(NODE_IMAGE)
PROVIDER_IMAGE_ENV = MYCOMESH_PROVIDER_IMAGE=$(PROVIDER_IMAGE)
DEPLOY_ENV_FILE ?= .env.deploy
MYCOMESH_WEB_ROOT ?= /var/www/mycomesh
MYCOMESH_WEB_RELEASE_ROOT ?= /var/www/mycomesh-releases
MYCOMESH_ACME_WEBROOT ?= /var/www/letsencrypt
MYCOMESH_CERT_DIR ?= /etc/letsencrypt/live/mycomesh.xyz
# Make does not automatically load Compose's --env-file. Read only the
# non-secret role selectors here so `make provider-up` and `make public-node-up`
# use the same V6 manifest as the Compose invocation.
define deploy_env_value
$(strip $(shell if [ -r "$(DEPLOY_ENV_FILE)" ]; then awk -F= -v key="$(1)" '$$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$(DEPLOY_ENV_FILE)"; fi))
endef
PROXY_BIND_ADDRESS ?= $(or $(call deploy_env_value,MYCOMESH_PROXY_BIND_ADDRESS),127.0.0.1)
PROXY_HOST_PORT ?= $(or $(call deploy_env_value,MYCOMESH_PROXY_HOST_PORT),8100)
# Optional public Ed25519 identity for Gateway/V2 Relay compatibility and signed
# reputation updates. Browser V3 Consumer admission does not depend on this key.
PUBLIC_NODE_CONSUMER_KEY ?= b1728209e4fc65f3279b362b3d8066a52388e2835e73f33262772d91fb5f41ed
PUBLIC_NODE_RPC_URL ?= $(or $(MYCOMESH_RELAY_V3_ADMISSION_RPC_URL),$(call deploy_env_value,MYCOMESH_RELAY_V3_ADMISSION_RPC_URL),https://sepolia.drpc.org)
PUBLIC_NODE_REPUTATION_SIGNER_PUBLIC_KEYS ?= $(or $(MYCOMESH_BRIDGE_REPUTATION_SIGNER_PUBLIC_KEYS),$(call deploy_env_value,MYCOMESH_BRIDGE_REPUTATION_SIGNER_PUBLIC_KEYS),$(PUBLIC_NODE_CONSUMER_KEY))
PUBLIC_NODE_RELAY_CONSUMER_PUBLIC_KEYS ?= $(or $(MYCOMESH_RELAY_CONSUMER_PUBLIC_KEYS),$(call deploy_env_value,MYCOMESH_RELAY_CONSUMER_PUBLIC_KEYS),$(PUBLIC_NODE_CONSUMER_KEY))
PUBLIC_NODE_RELAY_PAYMENT_ADDRESS ?= $(or $(MYCOMESH_RELAY_PAYMENT_ADDRESS),$(call deploy_env_value,MYCOMESH_RELAY_PAYMENT_ADDRESS))
PUBLIC_NODE_DEPLOYMENT ?= $(or $(MYCOMESH_PUBLIC_NODE_DEPLOYMENT),$(call deploy_env_value,MYCOMESH_PUBLIC_NODE_DEPLOYMENT),/app/deployments/sepolia-myco-v6.json)
PUBLIC_NODE_SETTLEMENT_VERSION ?= $(or $(MYCOMESH_PUBLIC_NODE_SETTLEMENT_VERSION),$(call deploy_env_value,MYCOMESH_PUBLIC_NODE_SETTLEMENT_VERSION),6)
PUBLIC_NODE_ENV = \
	MYCOMESH_PUBLIC_NODE_STRICT=true \
	MYCOMESH_NETWORK_PROFILE=testnet \
	MYCOMESH_NETWORK_ID=mycomesh-testnet \
	MYCOMESH_SETTLEMENT_VERSION=$(PUBLIC_NODE_SETTLEMENT_VERSION) \
	MYCO_DEPLOYMENT=$(PUBLIC_NODE_DEPLOYMENT) \
	MYCOMESH_POOL_PUBLIC_URL=https://bridge.mycomesh.xyz \
	MYCOMESH_POOL_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz,http://127.0.0.1:8110,http://localhost:8110 \
	MYCOMESH_RELAY_PUBLIC_URL=https://bridge.mycomesh.xyz \
	MYCOMESH_RELAY_ADVERTISE_HOST=bridge.mycomesh.xyz \
	MYCOMESH_RELAY_ADVERTISE_CONTROL_PORT=443 \
	MYCOMESH_RELAY_ADVERTISE_PROVIDER_PORT=9901 \
	MYCOMESH_BRIDGE_ADMISSION_MODE=any-signed \
	MYCOMESH_BRIDGE_REPUTATION_SIGNER_PUBLIC_KEYS=$(PUBLIC_NODE_REPUTATION_SIGNER_PUBLIC_KEYS) \
	MYCOMESH_BRIDGE_TRUST_PROXY_HEADERS=true \
	MYCOMESH_BRIDGE_TRUSTED_RELAY_ORIGINS=https://bridge.mycomesh.xyz \
	MYCOMESH_BRIDGE_EXTRA_ARGS= \
	MYCOMESH_RELAY_EXTRA_ARGS= \
	MYCOMESH_RELAY_ALLOW_ANY_SIGNED_CONSUMER=false \
	MYCOMESH_RELAY_CONSUMER_PUBLIC_KEYS=$(PUBLIC_NODE_RELAY_CONSUMER_PUBLIC_KEYS) \
	MYCOMESH_RELAY_PAYMENT_ADDRESS=$(PUBLIC_NODE_RELAY_PAYMENT_ADDRESS) \
	MYCOMESH_RELAY_NETWORK_CONFIG=/app/deployments/sepolia-provider-network-v6.json \
	MYCOMESH_RELAY_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz,http://127.0.0.1:8110,http://localhost:8110 \
	MYCOMESH_RELAY_V3_ADMISSION_DEPLOYMENT=/app/deployments/sepolia-myco-v3.json \
	MYCOMESH_RELAY_V3_ADMISSION_RPC_URL=$(PUBLIC_NODE_RPC_URL) \
	MYCOMESH_RELAY_V3_ADMISSION_CONFIRMATIONS=6 \
	MYCOMESH_RELAY_TRUST_PROXY_HEADERS=true \
	MYCOMESH_BRIDGE_BIND_ADDRESS=127.0.0.1 \
	MYCOMESH_RELAY_CONTROL_BIND_ADDRESS=127.0.0.1 \
	MYCOMESH_RELAY_PROVIDER_BIND_ADDRESS=127.0.0.1

PROVIDER_TRANSPORT ?=
PROVIDER_RPC_URL ?= $(or $(MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL),$(call deploy_env_value,MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL),$(call deploy_env_value,MYCOMESH_SETTLEMENT_RPC_URL))
PROVIDER_BIND_ADDRESS ?= 127.0.0.1
# Provider operators use the published V6 session network by default. The
# role-specific selector deliberately does not inherit the Proxy's generic V3
# compatibility setting from a shared .env.deploy file.
PROVIDER_SETTLEMENT_VERSION ?= $(or $(MYCOMESH_PROVIDER_SETTLEMENT_VERSION),$(call deploy_env_value,MYCOMESH_PROVIDER_SETTLEMENT_VERSION),6)
PROVIDER_NETWORK_CONFIG ?= $(or $(MYCOMESH_PROVIDER_NETWORK_CONFIG),$(call deploy_env_value,MYCOMESH_PROVIDER_NETWORK_CONFIG),$(if $(filter 4,$(PROVIDER_SETTLEMENT_VERSION)),/app/deployments/sepolia-provider-network-v4.json,$(if $(filter 6,$(PROVIDER_SETTLEMENT_VERSION)),/app/deployments/sepolia-provider-network-v6.json,/app/deployments/sepolia-provider-network.json)))
PROVIDER_DEPLOYMENT ?= $(or $(MYCOMESH_PROVIDER_DEPLOYMENT),$(call deploy_env_value,MYCOMESH_PROVIDER_DEPLOYMENT),$(if $(filter 6,$(PROVIDER_SETTLEMENT_VERSION)),/app/deployments/sepolia-myco-v6.json,$(if $(filter 5,$(PROVIDER_SETTLEMENT_VERSION)),/app/deployments/sepolia-myco-v5.json,$(if $(filter 4,$(PROVIDER_SETTLEMENT_VERSION)),/app/deployments/sepolia-myco-v4.json,/app/deployments/sepolia-myco-v3.json))))
PROVIDER_PAYMENT_ADDRESS ?= $(or $(MYCOMESH_PROVIDER_PAYMENT_ADDRESS),$(call deploy_env_value,MYCOMESH_PROVIDER_PAYMENT_ADDRESS))
OPERATOR_CONFIG_DIR ?= .mycomesh/operator
PROVIDER_OPERATOR_CONFIG ?= $(OPERATOR_CONFIG_DIR)/provider.json
RELAY_OPERATOR_CONFIG ?= $(OPERATOR_CONFIG_DIR)/relay.json
PROVIDER_IDENTITY_SOURCE ?= $(dir $(PROVIDER_OPERATOR_CONFIG))provider-evm-identity.json
# Do not make Compose create a host directory for an optional config.  The
# path is passed only after onboarding has produced a regular 0600 file.
PROVIDER_OPERATOR_CONFIG_EXISTS = $(shell if [ -f "$(PROVIDER_OPERATOR_CONFIG)" ]; then printf 1; fi)
RELAY_OPERATOR_CONFIG_EXISTS = $(shell if [ -f "$(RELAY_OPERATOR_CONFIG)" ]; then printf 1; fi)
PROVIDER_IDENTITY_SOURCE_EXISTS = $(shell if [ -f "$(PROVIDER_IDENTITY_SOURCE)" ]; then printf 1; fi)
PROVIDER_OPERATOR_ENV = MYCOMESH_PROVIDER_OPERATOR_CONFIG="$(if $(PROVIDER_OPERATOR_CONFIG_EXISTS),$(PROVIDER_OPERATOR_CONFIG),)" MYCOMESH_PROVIDER_IDENTITY_SOURCE=
PROVIDER_ONBOARDING_ENV = MYCOMESH_PROVIDER_OPERATOR_CONFIG="$(if $(PROVIDER_OPERATOR_CONFIG_EXISTS),$(PROVIDER_OPERATOR_CONFIG),)" MYCOMESH_PROVIDER_IDENTITY_SOURCE="$(if $(PROVIDER_IDENTITY_SOURCE_EXISTS),$(PROVIDER_IDENTITY_SOURCE),)"
RELAY_OPERATOR_ENV = $(if $(RELAY_OPERATOR_CONFIG_EXISTS),MYCOMESH_RELAY_OPERATOR_CONFIG="$(RELAY_OPERATOR_CONFIG)",)
PROVIDER_ENV = \
	GATEWAY_BACKEND=codex_app_server \
	PUBLIC_MODEL_ID=mycomesh-codex-standard-v1 \
	MYCOMESH_RESERVE_INPUT_TOKENS=65536 \
	MYCOMESH_RESERVE_OUTPUT_TOKENS=2000 \
	UPSTREAM_API_KEY= \
	CODEX_PROVIDER_BASE_URL= \
	MYCOMESH_NETWORK_PROFILE=testnet \
	MYCOMESH_NETWORK_ID=mycomesh-testnet \
	MYCOMESH_CODEX_TESTNET_METERING=true \
	MYCOMESH_PROVIDER_NETWORK_CONFIG=$(PROVIDER_NETWORK_CONFIG) \
	MYCOMESH_PROVIDER_EVM_IDENTITY=/data/provider-evm-identity.json \
	MYCOMESH_PROVIDER_POOL_URL= \
	MYCOMESH_PROVIDER_TRANSPORT=$(PROVIDER_TRANSPORT) \
	MYCOMESH_PROVIDER_ADVERTISE_HOST=auto \
	MYCOMESH_PROVIDER_BIND_ADDRESS=$(PROVIDER_BIND_ADDRESS) \
	MYCOMESH_PROVIDER_CONSUMER_PUBLIC_KEY= \
	MYCOMESH_PROVIDER_PAYMENT_ADDRESS=$(PROVIDER_PAYMENT_ADDRESS) \
	MYCOMESH_PROVIDER_PRICING_HASH= \
	MYCOMESH_PROVIDER_EXTRA_ARGS= \
	MYCOMESH_SETTLEMENT_VERSION=$(PROVIDER_SETTLEMENT_VERSION) \
	MYCOMESH_PRICING_VERSION= \
	MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL=$(PROVIDER_RPC_URL) \
	MYCOMESH_SETTLEMENT_CONTRACT= \
	MYCOMESH_SETTLEMENT_CHAIN_ID= \
	MYCOMESH_PROVIDER_DEPLOYMENT=$(PROVIDER_DEPLOYMENT) \
	MYCO_SETTLEMENT= \
	MYCO_TOKEN= \
	MYCO_TEST_USDC= \
	MYCO_TREASURY= \
	MYCO_CHANNEL_HASH=

.PHONY: deploy-env proxy-configure proxy-preflight proxy-relayer-address relay-transaction-address require-node-image require-provider-image build images-show node-image-pull provider-image-pull images-pull consumer consumer-up consumer-up-image consumer-open consumer-codex consumer-down consumer-health consumer-logs consumer-credentials consumer-codex-env consumer-cli-test gateway proxy proxy-up proxy-up-image proxy-down proxy-health proxy-logs proxy-identity proxy-identity-import bridge relay relay-up relay-down relay-onboard relay-start public-node-up public-node-up-image main-node-up-image public-node-down public-node-health public-node-tls-health public-node-logs provider provider-login provider-login-image provider-operator-config-export-image provider-identity-export-image provider-config-apply-image provider-auth-reset-image provider-auth-ensure-image provider-auth-status-image provider-up provider-up-image provider-configure provider-onboard provider-start provider-down provider-health provider-logs provider-identity provider-identity-import provider-claim-payout demo up down logs ps test smoke package-install web-install nginx-bootstrap-install nginx-install

deploy-env:
	@if [ ! -f "$(DEPLOY_ENV_FILE)" ]; then install -m 0600 .env.deploy.example "$(DEPLOY_ENV_FILE)"; else chmod 0600 "$(DEPLOY_ENV_FILE)"; fi

proxy-configure: deploy-env
	python3 scripts/configure_proxy_env.py --env-file "$(DEPLOY_ENV_FILE)"

proxy-preflight:
	python3 scripts/configure_proxy_env.py --env-file "$(DEPLOY_ENV_FILE)" --check

proxy-relayer-address: proxy-preflight
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy run --rm --no-deps --entrypoint python proxy -c 'from gateway.chain import parse_private_key, private_key_to_address; import os; print(private_key_to_address(parse_private_key(os.environ["MYCOMESH_SESSION_RELAYER_PRIVATE_KEY"])))'

relay-transaction-address: deploy-env
	@test -n "$(call deploy_env_value,MYCOMESH_RELAY_SETTLEMENT_PRIVATE_KEY)" || { echo "MYCOMESH_RELAY_SETTLEMENT_PRIVATE_KEY is required in $(DEPLOY_ENV_FILE)" >&2; exit 2; }
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile relay run --rm --no-deps --entrypoint python relay -c 'from gateway.chain import parse_private_key, private_key_to_address; import os; print(private_key_to_address(parse_private_key(os.environ["MYCOMESH_RELAY_SETTLEMENT_PRIVATE_KEY"])))'

require-node-image:
	@if [ -z "$(NODE_IMAGE)" ]; then echo "Set IMAGE_TAG or NODE_IMAGE explicitly." >&2; exit 2; fi

require-provider-image:
	@if [ -z "$(PROVIDER_IMAGE)" ]; then echo "Set IMAGE_TAG or PROVIDER_IMAGE explicitly." >&2; exit 2; fi

build:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile gateway --profile bridge --profile provider --profile proxy --profile relay build

images-show: deploy-env require-node-image require-provider-image
	$(NODE_IMAGE_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile gateway --profile consumer --profile public-node --profile proxy --profile provider config --images

node-image-pull: deploy-env require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile gateway --profile consumer --profile public-node --profile proxy pull gateway consumer-volume-init consumer proxy-volume-init proxy indexer public-node-volume-init bridge relay postgres

provider-image-pull: deploy-env require-provider-image
	$(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider pull provider-volume-init provider-sidecar provider

images-pull: node-image-pull provider-image-pull

consumer-up: deploy-env
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer config --quiet
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer up -d --build --wait --wait-timeout 90 consumer
	$(MAKE) consumer-open

consumer-up-image: deploy-env require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer config --quiet
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer up -d --no-build --wait --wait-timeout 90 consumer
	$(MAKE) consumer-open

consumer-open:
	@./scripts/open-consumer-browser.sh

# Keep this command attached while the browser completes wallet onboarding,
# then start the host Codex process with the loopback Consumer environment.
consumer: consumer-up
	@./scripts/run-consumer-codex.sh

consumer-codex: deploy-env
	@./scripts/run-consumer-codex.sh

consumer-down:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer stop consumer

consumer-health:
	curl --fail --silent --show-error http://127.0.0.1:8110/health

consumer-logs:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer logs --tail=200 consumer

consumer-credentials:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer exec consumer python -m gateway.local_consumer credentials

# Print, but do not apply, the loopback environment used by Codex and the npm
# client. Use `eval "$$(make consumer-codex-env)"` in the current shell.
consumer-codex-env:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile consumer exec -T consumer python -m gateway.local_consumer codex-env

gateway: deploy-env
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" up --build gateway

proxy: proxy-preflight
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy up --build indexer proxy

proxy-up: proxy-preflight
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy config --quiet
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy up -d --build --wait --wait-timeout 180 indexer proxy

proxy-up-image: proxy-preflight require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy config --quiet
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy up -d --no-build --wait --wait-timeout 180 indexer proxy

proxy-down:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy stop proxy indexer postgres

proxy-health:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy exec -T indexer python -m gateway.indexer_service health
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy exec -T proxy python -c 'import json, urllib.request; value=json.load(urllib.request.urlopen("http://127.0.0.1:8100/health", timeout=5)); assert value.get("ok") is True; assert value.get("billing_mode") == "onchain-prepaid"; print(json.dumps(value, sort_keys=True))'

proxy-logs:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy logs -f indexer proxy

bridge: deploy-env
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile bridge up --build bridge

relay: deploy-env
	$(RELAY_OPERATOR_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile bridge --profile relay up --build bridge relay

relay-up: deploy-env
	$(RELAY_OPERATOR_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile bridge --profile relay config --quiet
	$(RELAY_OPERATOR_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile bridge --profile relay up -d --build --wait --wait-timeout 120 bridge relay

relay-down:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile bridge --profile relay stop relay bridge

relay-onboard: deploy-env
	@install -d -m 700 "$(OPERATOR_CONFIG_DIR)"
	@python3 -m gateway.operator_setup wizard relay --output "$(RELAY_OPERATOR_CONFIG)" --port "$${MYCOMESH_RELAY_WIZARD_PORT:-8766}"
	@$(MAKE) relay-up RELAY_OPERATOR_CONFIG="$(RELAY_OPERATOR_CONFIG)"

relay-start: relay-onboard

public-node-up: deploy-env
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node config --quiet
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node up -d --build --wait --wait-timeout 180 bridge relay

public-node-up-image: deploy-env require-node-image
	$(PUBLIC_NODE_ENV) $(NODE_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node config --quiet
	$(PUBLIC_NODE_ENV) $(NODE_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node up -d --no-build --wait --wait-timeout 180 bridge relay

main-node-up-image: public-node-up-image proxy-up-image

public-node-down:
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node stop relay bridge

public-node-health:
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node exec -T bridge python -c 'import json, os, urllib.request; value=json.load(urllib.request.urlopen("http://127.0.0.1:9800/health", timeout=5)); assert value.get("ok") is True; assert value.get("network_profile") == "testnet"; assert value.get("require_provider_backend_metadata") is True; assert isinstance(value.get("settlement"), dict); assert int(value["settlement"]["version"]) == int(os.environ["MYCOMESH_SETTLEMENT_VERSION"]); print(json.dumps(value, sort_keys=True))'
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node exec -T relay python -c 'import json, os, urllib.request; from gateway.provider_bootstrap import load_provider_network_config; value=json.load(urllib.request.urlopen("http://127.0.0.1:9900/health", timeout=5)); config=load_provider_network_config(os.environ["MYCOMESH_RELAY_NETWORK_CONFIG"]); assert value.get("ok") is True; assert value.get("relay_payment_address") == os.environ["MYCOMESH_RELAY_PAYMENT_ADDRESS"].lower(); assert value.get("relay_attestation_address") == config.relay_attestation_address; print(json.dumps(value, sort_keys=True))'

public-node-tls-health:
	python3 -c 'import socket, ssl; raw=socket.create_connection(("127.0.0.1", 9901), 5); ctx=ssl.create_default_context(); tls=ctx.wrap_socket(raw, server_hostname="bridge.mycomesh.xyz"); print("relay_provider_tls:", tls.version()); tls.close()'

public-node-logs:
	$(PUBLIC_NODE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile public-node logs -f bridge relay

provider: deploy-env
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider up --build provider

provider-login: deploy-env
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --build provider-volume-init
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --build --entrypoint sh provider-sidecar -ec '\
		umask 077; \
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}"; \
		python -m gateway login; \
		exec python -m gateway codex-provider status --codex-home "$$CODEX_HOME"'

provider-login-image: deploy-env require-provider-image
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps provider-volume-init
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --entrypoint sh provider-sidecar -ec '\
		umask 077; \
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}"; \
		python -m gateway login; \
		exec python -m gateway codex-provider status --codex-home "$$CODEX_HOME"'

provider-operator-config-export-image: deploy-env require-provider-image
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --progress quiet --ansi never --env-file "$(DEPLOY_ENV_FILE)" --profile provider run -T --rm --no-deps --entrypoint sh provider-volume-init -ec '\
		if [ -s /volumes/provider/provider-evm-identity.json ]; then \
			exec python -m gateway.operator_setup export-provider-profile \
				--config /volumes/provider/operator-config.json \
				--identity /volumes/provider/provider-evm-identity.json; \
		fi'

provider-identity-export-image: deploy-env require-provider-image
	@test -n "$(PROVIDER_IDENTITY_EXPORT_FILE)" || { echo "PROVIDER_IDENTITY_EXPORT_FILE is required" >&2; exit 64; }
	@test ! -L "$(PROVIDER_IDENTITY_EXPORT_FILE)" || { echo "PROVIDER_IDENTITY_EXPORT_FILE must not be a symbolic link" >&2; exit 64; }
	@test -f "$(PROVIDER_IDENTITY_EXPORT_FILE)" || { echo "PROVIDER_IDENTITY_EXPORT_FILE must be a regular file" >&2; exit 64; }
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --progress quiet --ansi never --env-file "$(DEPLOY_ENV_FILE)" --profile provider run -T --rm --no-deps \
		--volume "$(abspath $(PROVIDER_IDENTITY_EXPORT_FILE)):/provider-identity-export.json" \
		--entrypoint sh provider-volume-init -ec '\
		identity=/volumes/provider/provider-evm-identity.json; \
		python -m gateway.provider_identity validate --identity "$$identity" >/dev/null; \
		cat "$$identity" > /provider-identity-export.json'

provider-config-apply-image: deploy-env require-provider-image
	$(PROVIDER_ONBOARDING_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps provider-volume-init

provider-auth-reset-image: deploy-env require-provider-image
	$(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider stop provider provider-sidecar
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps provider-volume-init
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --entrypoint sh provider-sidecar -ec '\
		umask 077; \
		exec python -m gateway logout --yes'

provider-auth-ensure-image: deploy-env require-provider-image
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps provider-volume-init
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --entrypoint sh provider-sidecar -ec '\
		umask 077; \
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}" >/dev/null; \
		if python -m gateway codex-provider status --codex-home "$$CODEX_HOME" >/dev/null 2>&1; then \
			echo "codex_login: reusing existing ChatGPT login"; \
		else \
			python -m gateway login; \
		fi; \
		exec python -m gateway codex-provider status --codex-home "$$CODEX_HOME"'

provider-auth-status-image: deploy-env require-provider-image
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --entrypoint sh provider-sidecar -ec '\
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}" >/dev/null; \
		exec python -m gateway codex-provider status --codex-home "$$CODEX_HOME"'

provider-up: deploy-env
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --build provider-volume-init
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider config --quiet
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider up -d --build --force-recreate --wait --wait-timeout 120 provider

provider-configure: deploy-env
	@image="$(PROVIDER_IMAGE)"; skip_pull=; \
		if [ -z "$$image" ]; then \
			image=mycomesh/gateway:local; \
			skip_pull=--skip-image-pull; \
			$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider build provider-sidecar; \
		fi; \
		MYCOMESH_PROVIDER_OPERATOR_CONFIG="$(abspath $(PROVIDER_OPERATOR_CONFIG))" \
		MYCOMESH_PROVIDER_IDENTITY_SOURCE="$(abspath $(PROVIDER_IDENTITY_SOURCE))" \
			scripts/install-provider.sh --provider-image "$$image" --configure-only $$skip_pull
	@printf '%s\n' 'Apply with the same pinned image: PROVIDER_IMAGE=<image> make provider-up-image && make provider-health'

provider-onboard: provider-configure
	@$(MAKE) provider-login PROVIDER_OPERATOR_CONFIG="$(PROVIDER_OPERATOR_CONFIG)"
	@$(MAKE) provider-up PROVIDER_OPERATOR_CONFIG="$(PROVIDER_OPERATOR_CONFIG)"

provider-start: provider-onboard

provider-up-image: deploy-env require-provider-image
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps provider-volume-init
	$(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider config --quiet
	@if $(PROVIDER_OPERATOR_ENV) $(PROVIDER_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider up -d --no-build --force-recreate --wait --wait-timeout 120 provider; then \
		:; \
	else \
		status=$$?; \
		printf '%s\n' 'Provider did not become healthy. Recent Provider diagnostics:' >&2; \
		$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider logs --tail=160 provider provider-sidecar >&2 || true; \
		provider_id="$$($(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider ps -q provider 2>/dev/null || true)"; \
		if [ -n "$$provider_id" ]; then \
			docker inspect --format '{{range .State.Health.Log}}{{println "health_exit=" .ExitCode}}{{println .Output}}{{end}}' "$$provider_id" >&2 || true; \
		fi; \
		exit "$$status"; \
	fi

provider-down:
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider stop provider provider-sidecar

provider-health:
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider exec -T provider-sidecar sh -ec '\
		python -m gateway codex-provider configure --codex-home "$${CODEX_HOME:?CODEX_HOME is required}" >/dev/null; \
		python -m gateway codex-provider status --codex-home "$$CODEX_HOME" >/dev/null; \
		exec python -m gateway health --url http://127.0.0.1:8000/ready --timeout 5 --require-settlement-ready'
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider exec -T provider sh -ec '\
		umask 077; \
		set -- python -m gateway health --url http://provider-sidecar:8000/health --timeout 5; \
		if [ "$${MYCOMESH_NETWORK_PROFILE:-local}" != local ]; then set -- "$$@" --require-settlement-ready; fi; \
		"$$@"; \
		if [ "$${MYCOMESH_PROVIDER_TRANSPORT-}" = direct ]; then \
			exec python -m gateway p2p ping tcp://127.0.0.1:9700 --timeout 5 --require-bridge-ready; \
		elif [ "$${MYCOMESH_NETWORK_PROFILE:-local}" != local ]; then \
			exec python -m gateway.provider_bootstrap --require-bridge-lease; \
		fi'

provider-logs:
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider logs -f provider provider-sidecar

provider-identity: deploy-env
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --build provider-volume-init
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --entrypoint sh provider -ec '\
		python -m gateway identity show \
			--identity "$${MYCOMESH_PROVIDER_IDENTITY:-/data/node-identity.json}"; \
		exec python -m gateway.provider_bootstrap \
			--identity "$${MYCOMESH_PROVIDER_EVM_IDENTITY:-/data/provider-evm-identity.json}"'

provider-identity-import: deploy-env
	@test -n "$(PROVIDER_EVM_IDENTITY_FILE)" || { echo "PROVIDER_EVM_IDENTITY_FILE=/secure/provider-evm-identity.json is required" >&2; exit 64; }
	@test ! -L "$(PROVIDER_EVM_IDENTITY_FILE)" || { echo "PROVIDER_EVM_IDENTITY_FILE must not be a symbolic link" >&2; exit 64; }
	@test -f "$(PROVIDER_EVM_IDENTITY_FILE)" || { echo "PROVIDER_EVM_IDENTITY_FILE must be a regular file" >&2; exit 64; }
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --build \
		--volume "$(abspath $(PROVIDER_EVM_IDENTITY_FILE)):/import/provider-evm-identity.json:ro" \
		--entrypoint python provider-volume-init -m gateway.provider_identity import \
			--source /import/provider-evm-identity.json \
			--target /volumes/provider/provider-evm-identity.json
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps provider-volume-init

provider-claim-payout: deploy-env
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --build provider-volume-init
	$(PROVIDER_ENV) $(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile provider run --rm --no-deps --entrypoint sh provider -ec '\
		settlement_version="$${MYCOMESH_SETTLEMENT_VERSION:-6}"; \
		claim_command=v4-claim-payout; deployment="$${MYCO_DEPLOYMENT:-}"; \
		if [ "$$settlement_version" = 5 ]; then claim_command=v5-claim-payout; deployment="$${deployment:-/app/deployments/sepolia-myco-v5.json}"; fi; \
		if [ "$$settlement_version" = 6 ]; then claim_command=v6-claim-payout; deployment="$${deployment:-/app/deployments/sepolia-myco-v6.json}"; fi; \
		exec python -m gateway chain "$$claim_command" \
			--identity "$${MYCOMESH_PROVIDER_EVM_IDENTITY:-/data/provider-evm-identity.json}" \
			--deployment "$$deployment" \
			--rpc-url "$${MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL:?MYCOMESH_PROVIDER_SETTLEMENT_RPC_URL is required}"'

proxy-identity: deploy-env
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy run --rm --no-deps --build proxy-volume-init
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy run --rm --no-deps proxy identity show --identity /data/request-identity.json

proxy-identity-import: deploy-env
	@test -n "$(PROXY_IDENTITY_FILE)" || { echo "PROXY_IDENTITY_FILE=/secure/request-identity.json is required" >&2; exit 64; }
	@test -f "$(PROXY_IDENTITY_FILE)" || { echo "PROXY_IDENTITY_FILE must be a regular file" >&2; exit 64; }
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy run --rm --no-deps --build \
		--volume "$(abspath $(PROXY_IDENTITY_FILE)):/import/request-identity.json:ro" \
		--entrypoint python proxy-volume-init -m gateway.proxy_identity import \
			--source /import/request-identity.json \
			--target /volumes/proxy/request-identity.json \
			--manifest /app/deployments/sepolia-provider-network-v6.json
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile proxy run --rm --no-deps proxy-volume-init

demo: deploy-env
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile bridge --profile provider --profile proxy up --build

up: demo

down:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" --profile bridge --profile provider --profile proxy --profile relay down

logs:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" logs -f $(SERVICE)

ps:
	$(COMPOSE) --env-file "$(DEPLOY_ENV_FILE)" ps

consumer-cli-test:
	npm --prefix packages/mycomesh-cli test

test: consumer-cli-test
	python3 -m unittest discover -s tests -q

smoke:
	python3 -m gateway --help >/dev/null
	python3 -m gateway identity show --identity /tmp/mycomesh-smoke-identity.json --json >/dev/null

package-install:
	python3 -m pip install -e .

web-install:
	npm --prefix web ci --ignore-scripts --legacy-peer-deps
	npm --prefix web run build
	@sudo install -d -m 0755 "$(MYCOMESH_WEB_RELEASE_ROOT)"; \
		mycomesh_release=$$(sudo mktemp -d "$(MYCOMESH_WEB_RELEASE_ROOT)/$$(git rev-parse --short=12 HEAD)-$$(date -u +%Y%m%d%H%M%S).XXXXXX"); \
		trap 'sudo rm -rf "$$mycomesh_release"' EXIT; \
		sudo cp -a web/dist/. "$$mycomesh_release"/; \
		sudo chown -R root:root "$$mycomesh_release"; \
		sudo find "$$mycomesh_release" -type d -exec chmod 0755 {} +; \
		sudo find "$$mycomesh_release" -type f -exec chmod 0644 {} +; \
		sudo ln -sfnT "$$mycomesh_release" "$(MYCOMESH_WEB_ROOT)"; \
		trap - EXIT; \
		true

nginx-bootstrap-install:
	@command -v nginx >/dev/null || { echo "nginx is required" >&2; exit 1; }
	@test ! -e /etc/nginx/sites-enabled/mycomesh || { \
		echo "formal MycoMesh Nginx site is already enabled" >&2; \
		exit 1; \
	}
	sudo install -d -m 0755 "$(MYCOMESH_ACME_WEBROOT)" /etc/nginx/sites-available /etc/nginx/sites-enabled
	sudo install -m 0644 deploy/nginx-mycomesh-bootstrap.conf /etc/nginx/sites-available/mycomesh-bootstrap
	sudo ln -sfn /etc/nginx/sites-available/mycomesh-bootstrap /etc/nginx/sites-enabled/mycomesh-bootstrap
	sudo rm -f /etc/nginx/sites-enabled/default
	sudo nginx -t
	sudo systemctl reload nginx

nginx-install:
	@test -r /usr/lib/nginx/modules/ngx_stream_module.so || { \
		echo "nginx stream module is required; install libnginx-mod-stream first" >&2; \
		exit 1; \
	}
	@sudo test -r "$(MYCOMESH_CERT_DIR)/fullchain.pem" && sudo test -r "$(MYCOMESH_CERT_DIR)/privkey.pem" || { \
		echo "issue the mycomesh.xyz certificate before installing the formal Nginx site" >&2; \
		exit 1; \
	}
	@test -r "$(MYCOMESH_WEB_ROOT)/index.html" || { \
		echo "run make web-install before installing the formal Nginx site" >&2; \
		exit 1; \
	}
	sudo install -d -m 0755 /etc/nginx/snippets /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/modules-enabled
	sudo install -m 0644 deploy/nginx-mycomesh-tls.conf /etc/nginx/snippets/mycomesh-tls.conf
	sudo install -m 0644 deploy/nginx-mycomesh-proxy.conf /etc/nginx/snippets/mycomesh-proxy.conf
	@mycomesh_upstream=$$(mktemp); \
		trap 'rm -f "$$mycomesh_upstream"' EXIT; \
		python3 scripts/render_nginx_upstream.py \
			--address "$(PROXY_BIND_ADDRESS)" \
			--port "$(PROXY_HOST_PORT)" \
			--output "$$mycomesh_upstream"; \
		sudo install -m 0644 "$$mycomesh_upstream" /etc/nginx/snippets/mycomesh-upstream.conf
	sudo install -m 0644 deploy/nginx-mycomesh-stream.conf /etc/nginx/modules-enabled/90-mycomesh-stream.conf
	sudo install -m 0644 deploy/nginx-mycomesh.conf /etc/nginx/sites-available/mycomesh
	sudo install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
	sudo install -m 0755 deploy/reload-nginx-after-renewal.sh /etc/letsencrypt/renewal-hooks/deploy/mycomesh-reload-nginx
	sudo ln -sfn /etc/nginx/sites-available/mycomesh /etc/nginx/sites-enabled/mycomesh
	sudo rm -f /etc/nginx/sites-enabled/mycomesh-bootstrap
	sudo rm -f /etc/nginx/sites-enabled/default
	sudo nginx -t
	sudo systemctl reload nginx
