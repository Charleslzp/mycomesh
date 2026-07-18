# MycoMesh Container Images

The git repository stores source code, Dockerfiles, and the build workflow. The
compiled multi-platform images are stored in GitHub Container Registry (GHCR)
packages associated with this repository:

| Image | Purpose |
| --- | --- |
| `ghcr.io/charleslzp/mycomesh-node` | Gateway, Bridge, Relay, and Consumer Proxy roles |
| `ghcr.io/charleslzp/mycomesh-provider-codex` | Login-backed Codex Provider |

`.github/workflows/publish-images.yml` builds both image names from the same
pinned, locked `Dockerfile`; the Compose role determines whether an image runs
as a Bridge/Relay/Proxy or as a Codex Provider. It builds `linux/amd64` and
`linux/arm64` images on pushes to `main`, `v*` tags, and manual dispatches. It publishes
`latest`, `main`, `sha-<short-commit>`, and applicable release tags. Production
deployments should use a `sha-*` tag or digest rather than mutable `latest`.

## GHCR Access

The production packages are intended to be public Container Registry packages.
Public GHCR container images can be pulled anonymously, so ordinary Provider
operators do not need a GitHub account or a registry token. If a package is
still private during the transition, log in as the Linux user that runs Docker:

```bash
docker login ghcr.io --username Charleslzp
```

At the password prompt, enter a classic GitHub personal access token with only
`read:packages` plus access to the private package. Prefer a Docker credential
helper. Without one, Docker can store the token as reversible base64 in
`~/.docker/config.json`; use a dedicated low-privilege deployment account,
restrict that directory and file to the account, and run `docker logout ghcr.io`
on machines that do not need persistent pulls. Do not put the token in
`.env.deploy`, a Dockerfile, an image, or git. The installer skips login for
public packages; use `--ghcr-login` only while a package remains private.

To make the two personal-account packages public, open the package page from the
GitHub profile's **Packages** tab, choose **Package settings**, then under
**Danger Zone** select **Change visibility -> Public**. Repeat for
`mycomesh-node` and `mycomesh-provider-codex`. GitHub treats this as an
irreversible visibility change, so do it only for images intended for the open
network.

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

The Provider role still runs the normal testnet startup gates. A successful
`provider-login-image` only establishes the isolated Codex account;
`provider-up-image` then loads the committed V4 network/deployment manifests,
checks the channel, pricing, wallet identity and Provider capabilities, and only
then joins the Bridge. V3 remains an explicit compatibility override.
Verify the result with `make provider-health`.

### One-command Provider bootstrap

Linux, macOS, and WSL users can use the checked-in installer to run the same
production targets without remembering the Compose sequence:

```bash
git clone https://github.com/Charleslzp/mycomesh.git
cd mycomesh
scripts/install-provider.sh --image-tag sha-<short-commit>
```

The script checks GNU Make, Docker Compose V2, and the host architecture, creates a
0600 `.env.deploy` when needed, pulls the public multi-architecture Provider
image, prints the one-time Codex device login, and waits for `provider-health`.
Use `--ghcr-login` only while the package is still private. Use `--provider-image
ghcr.io/charleslzp/mycomesh-provider-codex@sha256:<digest>` when a digest is
preferred. `--skip-codex-login` and `--no-start` support repeat runs;
`--dry-run` prints the planned operations.

The installer never accepts or stores an EVM private key and never puts a GHCR
token in `.env.deploy`. Keep the named Docker volumes and do not run
`docker compose down -v` during upgrades. Windows hosts
should run the script inside WSL2 or use Docker Desktop's Linux containers;
native Windows containers are not published by this project.

An npm package is intentionally not required for this role. MycoMesh Provider
startup is Python plus Docker, and npm cannot replace Docker permissions, GHCR
authentication, or the interactive Codex login. A future `npx
@mycomesh/provider-installer@<version>` command can be a thin wrapper around a
signed release bundle, but it must retain those same explicit steps.
