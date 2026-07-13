COMPOSE ?= docker compose
SERVICE ?= gateway

.PHONY: deploy-env build gateway proxy bridge relay provider provider-login provider-auth-status provider-up provider-identity proxy-identity demo up down logs ps test smoke package-install

deploy-env:
	@test -f .env.deploy || cp .env.deploy.example .env.deploy

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
