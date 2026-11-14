---
title: Containers
description: Run murk in dev and CI containers with a mounted grant key, one grant per compose service, and build secrets.
sidebar:
  order: 11
---

This page covers dev and CI containers: an app or an agent that reads a few
secrets when it starts. murk is not a secrets manager for a Kubernetes cluster.
For that, use your platform's secret store.

Each pattern below uses an agent [grant](/concepts/grants/) key, not your own
key. A grant key reads only the keys it was minted for. It carries its own
trusted signers and expiry, so a container with no trust pin needs no
`murk trust` and no `MURK_TRUSTED_SIGNERS`.

The vault (`.murk`) can go into the image or be mounted. It is encrypted, so
it is not a secret. The grant key file is the secret. Mount it at run time.
Never copy it into an image.

## Install murk in the image

Download a release binary and check it against the release's `SHA256SUMS`:

```dockerfile
FROM debian:bookworm-slim
ARG MURK_VERSION=v0.15.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    archive="murk-${MURK_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz"; \
    base="https://github.com/interrupted-sh/murk/releases/download/${MURK_VERSION}"; \
    cd /tmp; \
    curl -fsSLO "$base/$archive"; \
    curl -fsSL "$base/SHA256SUMS" | grep " $archive\$" | sha256sum -c -; \
    tar -xzf "$archive" -C /usr/local/bin murk; \
    rm "$archive"
```

The checksum catches a corrupt download. To check the build provenance as
well, see [Verifying releases](https://github.com/interrupted-sh/murk/blob/main/VERIFYING.md).

## Rules for the grant key file

murk refuses a key file in two cases. Both apply inside a container:

- **Group or world bits.** A key file with mode `0644` fails with
  `MURK_KEY_FILE is readable by others (mode 644)`. Give the file mode `0600`
  or `0400`.
- **A symlink.** murk does not follow a symlink at `MURK_KEY_FILE`. It fails
  with `MURK_KEY_FILE is a symlink`. Point `MURK_KEY_FILE` at the real file.

The file must also be readable by the user the container runs as. A bind
mount keeps the host file's mode. Check the owner inside the container with
`ls -ln /run/murk/key`.

## Pattern 1: murk as the entrypoint

Mint a grant for the keys the app needs:

```bash
murk agent grant --name web --only API_KEY --only DATABASE_URL --ttl 7d --out web.key
```

Make `murk agent exec` the entrypoint, so the app starts with only those keys:

```dockerfile
WORKDIR /app
COPY .murk ./
COPY app.sh ./
ENV MURK_KEY_FILE=/run/murk/key
ENTRYPOINT ["murk", "agent", "exec", "--only", "API_KEY", "--only", "DATABASE_URL", "--", "/app/app.sh"]
```

Run it with the key file mounted read-only:

```bash
docker run -v "$PWD/web.key:/run/murk/key:ro" my-app
```

What this gives you:

- The secrets exist only in the app's process environment. They are not in
  an image layer, in `docker inspect` output, or in the container's
  filesystem.
- `agent exec` refuses a key that is not a grant. An operator key mounted by
  mistake fails before any secret is read.
- `agent exec` masks the injected values in the app's stdout and stderr, so a
  value the app logs shows as `***API_KEY***` in `docker logs`. Masking
  matches exact bytes only. See
  [Output masking](/guides/ai-agents-mcp/#output-masking).
- A grant past its expiry fails on the next start:
  `grant web expired ... renew with murk agent grant --renew`.

What to know:

- **murk is PID 1.** `agent exec` supervises the app instead of replacing
  itself with it. `docker stop` sends `SIGTERM` to murk, murk passes it to the
  app, and murk exits with the app's exit code. murk 0.14.1 did not pass on a
  `SIGTERM` from outside the container, so with 0.14.1, use `--init`.
- **`--init` is optional** (compose: `init: true`). murk waits only for the
  app. It does not reap other processes that end up under PID 1. If the app
  starts background processes and does not wait for them, use `--init`, so
  that the exited processes are reaped.
- **`agent exec` clears the environment.** The app gets only `PATH`, `HOME`,
  `TERM`, the injected secrets, `MURK_AGENT=1` and `MURK_STRICT=1`. A setting
  passed with `docker run -e PORT=8080` does not reach it. Put such settings
  in the vault, or use plain `murk exec --only KEY -- app`. `murk exec` keeps
  the environment and removes only `MURK_KEY` and `MURK_KEY_FILE`. It does
  not mask output.
- **Revoking does not stop a running container.** It also does not stop a
  copy of the key file from reading a vault baked into an image before the
  revoke. murk refuses an unchanged copy past its own expiry, but whoever holds the copy can delete the expiry line. To close access, run
  `murk agent revoke web --rotate`, delete every copy of the key file, and
  mint a new grant.

## Pattern 2: compose, one grant per service

Give each service its own grant, so a compromised service reads only its own
keys:

```bash
murk agent grant --name web --only API_KEY --only DATABASE_URL --ttl 7d --out web.key
murk agent grant --name worker --only WORKER_TOKEN --ttl 7d --out worker.key
```

```yaml
services:
  web:
    build: .
    entrypoint: ["murk", "agent", "exec", "--only", "API_KEY", "--only", "DATABASE_URL", "--", "/app/app.sh"]
    environment:
      MURK_KEY_FILE: /run/secrets/web_grant
    secrets: [web_grant]
  worker:
    build: .
    entrypoint: ["murk", "agent", "exec", "--only", "WORKER_TOKEN", "--", "/app/worker.sh"]
    environment:
      MURK_KEY_FILE: /run/secrets/worker_grant
    secrets: [worker_grant]
secrets:
  web_grant:
    file: ./web.key
  worker_grant:
    file: ./worker.key
```

Compose mounts each secret file at `/run/secrets/<name>`. The worker's grant
was never encrypted to `API_KEY`, so the worker cannot read it, whatever it
runs.

Keep `MURK_*` variables out of an `env_file:` that the repository holds. A
repository file must not choose which key or which trusted signers a service
uses.

## Pattern 3: secrets at build time

Pass the grant key as a BuildKit secret. It is mounted for one `RUN` step and
is not stored in any layer:

```dockerfile
# syntax=docker/dockerfile:1
COPY .murk ./
RUN --mount=type=secret,id=murk_grant,target=/run/secrets/murk_grant \
    MURK_KEY_FILE=/run/secrets/murk_grant \
    murk exec --only NPM_TOKEN -- npm ci
```

```bash
docker build --secret id=murk_grant,src=build.key .
```

The value exists only in that step's process. Anything the step writes to the
filesystem stays in the layer, so make sure the build command does not write
the value to a file.

:::danger[Do not export secrets in a build step]
`RUN murk export > .env` or `RUN murk get KEY > token` writes the values into
an image layer. Anyone who can pull the image can read them, even if a later
step deletes the file.
:::

## Agents in containers

A container is also the simplest way to make a grant's scope a real boundary
for an AI agent: the operator's `~/.config/murk` is not in the container, so
the grant key is the only murk key the agent can reach.
[Agent isolation](/guides/agent-isolation/) has a tested recipe and a check
script.
