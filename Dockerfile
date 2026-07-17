FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS codex-cli

WORKDIR /opt/codex-cli

COPY deploy/codex-cli/package.json deploy/codex-cli/package-lock.json ./

RUN npm ci --omit=dev --ignore-scripts \
    && test "$(node node_modules/@openai/codex/bin/codex.js --version)" = "codex-cli 0.144.1"


FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    MYCOMESH_DATA_DIR=/data \
    CODEX_CLI_VERSION=0.144.1 \
    HOME=/home/mycomesh

COPY --from=codex-cli /usr/local/bin/node /usr/local/bin/node
COPY --from=codex-cli /opt/codex-cli/node_modules /opt/codex-cli/node_modules

RUN ln -s /opt/codex-cli/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex \
    && test "$(codex --version)" = "codex-cli 0.144.1"

WORKDIR /app

COPY requirements.txt requirements.lock ./

RUN python -m pip install --require-hashes -r requirements.lock

COPY pyproject.toml README.md agents.example.json ./
COPY gateway ./gateway
COPY deployments ./deployments

RUN printf '#!/bin/sh\nexec python -m gateway "$@"\n' > /usr/local/bin/mycomesh \
    && chmod +x /usr/local/bin/mycomesh

RUN groupadd --gid 10001 mycomesh \
    && useradd --uid 10001 --gid 10001 --home-dir /home/mycomesh --create-home \
        --shell /usr/sbin/nologin mycomesh \
    && mkdir -p /data /workspace \
    && chown -R 10001:10001 /data /workspace /home/mycomesh

EXPOSE 8000 8100 9700 9800 9900 9901

USER 10001:10001
ENTRYPOINT ["python", "-m", "gateway"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
