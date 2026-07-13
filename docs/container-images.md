# MycoMesh Container Images

The git repository stores source code, Dockerfiles, and the build workflow. The
compiled multi-platform images are stored in GitHub Container Registry (GHCR)
packages associated with this private repository:

| Image | Purpose |
| --- | --- |
| `ghcr.io/charleslzp/mycomesh-node` | Gateway, Bridge, Relay, and Consumer Proxy roles |
| `ghcr.io/charleslzp/mycomesh-provider-codex` | Login-backed Codex Provider |

`.github/workflows/publish-images.yml` builds `linux/amd64` and `linux/arm64`
images on pushes to `main`, `v*` tags, and manual dispatches. It publishes
`latest`, `main`, `sha-<short-commit>`, and applicable release tags. Production
deployments should use a `sha-*` tag or digest rather than mutable `latest`.

## Private GHCR Login

On each deployment machine, log in as the Linux user that runs Docker:

```bash
docker login ghcr.io --username Charleslzp
```

At the password prompt, enter a classic GitHub personal access token with only
`read:packages` plus access to this private repository. Prefer a Docker
credential helper. Without one, Docker can store the token as reversible base64
in `~/.docker/config.json`; use a dedicated low-privilege deployment account,
restrict that directory and file to the account, and run `docker logout ghcr.io`
on machines that do not need persistent pulls. Do not put the token in
`.env.deploy`, a Dockerfile, an image, or git.

After the first workflow run, open both Package settings pages and verify their
visibility is `Private` before distributing pull credentials. The workflow can
publish packages but cannot prevent an administrator from later changing package
visibility. Do not change either container package to public; GitHub does not
allow a public package to be made private again.

## Main Node Server

In this repository, the main server target means Bridge discovery, Relay, and
the Consumer Proxy. They share the node image; Relay and Proxy also start the
PostgreSQL dependency. The standalone AI Gateway is not part of this target.

```bash
make deploy-env
# Edit .env.deploy before exposing any service.

export IMAGE_TAG=sha-<short-commit>
make images-show
make node-image-pull
make main-node-up-image
```

For a first smoke test, `IMAGE_TAG=latest` is accepted. Confirm the Bridge after
startup:

```bash
curl -fsS http://127.0.0.1:9800/health
docker compose --env-file .env.deploy ps
```

To pin registry digests directly, set `NODE_IMAGE` and `PROVIDER_IMAGE` instead
of `IMAGE_TAG`:

```bash
export NODE_IMAGE=ghcr.io/charleslzp/mycomesh-node@sha256:<digest>
export PROVIDER_IMAGE=ghcr.io/charleslzp/mycomesh-provider-codex@sha256:<digest>
```

## Codex Provider Machine

The image contains the Codex CLI, not a login. Pull it, create the runtime login
inside the dedicated persistent Docker volume, then start without rebuilding:

```bash
make deploy-env
# Edit .env.deploy for this Provider and its public Bridge or Relay.

export IMAGE_TAG=sha-<short-commit>
make provider-image-pull
make provider-login-image
make provider-auth-status-image
make provider-up-image
make logs SERVICE=provider
```

The named volumes retain the Codex login, Provider identity, and workspace when
containers are replaced. Never publish those volumes, and do not use
`docker compose down -v` unless you intend to erase them.

Compose fixes the project name to `mycomesh`, so these volumes remain attached
when the repository is checked out into a different directory. Override the
project name only when intentionally running a fully separate deployment.

The current Codex backend must first be validated with
`MYCOMESH_NETWORK_PROFILE=local`. Building and publishing the image does not
change its `settlement_ready=false` capability status, so the existing testnet
startup gate remains intentional.
