# MycoMesh V11 node image: Relay, Provider (with the Codex CLI) and bridge keeper.
FROM python:3.12-slim

ARG CODEX_CLI_VERSION=0.144.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates nodejs npm \
 && npm install -g "@openai/codex@${CODEX_CLI_VERSION}" \
 && npm cache clean --force \
 && apt-get purge -y npm && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN useradd --uid 10001 --create-home mycomesh
WORKDIR /app
COPY mycomesh /app/mycomesh
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-m", "mycomesh"]
CMD ["--help"]
