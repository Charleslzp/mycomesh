COMPOSE ?= docker compose
SERVICE ?= gateway
IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= charleslzp
IMAGE_TAG ?=
NODE_IMAGE ?= $(if $(IMAGE_TAG),$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/mycomesh-node:$(IMAGE_TAG))
PROVIDER_IMAGE ?= $(if $(IMAGE_TAG),$(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/mycomesh-provider-codex:$(IMAGE_TAG))
NODE_IMAGE_ENV = MYCOMESH_NODE_IMAGE=$(NODE_IMAGE)
PROVIDER_IMAGE_ENV = MYCOMESH_PROVIDER_IMAGE=$(PROVIDER_IMAGE)

.PHONY: deploy-env require-node-image require-provider-image build gateway proxy bridge relay provider provider-login provider-auth-status provider-up provider-identity proxy-identity images-show node-image-pull provider-image-pull images-pull main-node-up-image provider-login-image provider-auth-status-image provider-up-image demo up down logs ps test smoke package-install

deploy-env:
	@test -f .env.deploy || cp .env.deploy.example .env.deploy

require-node-image:
	@if [ -z "$(NODE_IMAGE)" ]; then echo "Set IMAGE_TAG or NODE_IMAGE explicitly."; exit 2; fi

require-provider-image:
	@if [ -z "$(PROVIDER_IMAGE)" ]; then echo "Set IMAGE_TAG or PROVIDER_IMAGE explicitly."; exit 2; fi

build:
	$(COMPOSE) --env-file .env.deploy --profile gateway --profile bridge --profile provider --profile proxy --profile relay build

gateway: deploy-env
	$(COMPOSE) --env-file .env.deploy up --build gateway

proxy: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile proxy up --build proxy

bridge: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile bridge up --build bridge

relay: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile relay up --build relay

provider: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile provider up --build provider

provider-login: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile provider run --rm --build --no-deps --entrypoint python provider -m gateway login

provider-auth-status: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile provider run --rm --build --no-deps --entrypoint codex provider login status

provider-up: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile provider up --build -d provider

images-show: deploy-env require-node-image require-provider-image
	$(NODE_IMAGE_ENV) $(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile bridge --profile relay --profile proxy --profile provider config --images

node-image-pull: deploy-env require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile bridge --profile relay --profile proxy pull bridge relay proxy postgres

provider-image-pull: deploy-env require-provider-image
	$(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider pull provider postgres

images-pull: node-image-pull provider-image-pull

main-node-up-image: deploy-env require-node-image
	$(NODE_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile bridge --profile relay --profile proxy up --no-build -d bridge relay proxy

provider-login-image: deploy-env require-provider-image
	$(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --entrypoint python provider -m gateway login

provider-auth-status-image: deploy-env require-provider-image
	$(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider run --rm --no-deps --entrypoint codex provider login status

provider-up-image: deploy-env require-provider-image
	$(PROVIDER_IMAGE_ENV) $(COMPOSE) --env-file .env.deploy --profile provider up --no-build -d provider

provider-identity: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile provider run --rm --build --no-deps --entrypoint python provider -m gateway identity show --identity /data/node-identity.json

proxy-identity: deploy-env
	$(COMPOSE) --env-file .env.deploy --profile proxy run --rm proxy identity show --identity /data/request-identity.json

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
