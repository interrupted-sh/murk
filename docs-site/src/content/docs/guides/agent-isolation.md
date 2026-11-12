---
title: Agent isolation
description: Tested recipes that make a grant key the only murk key an AI agent can reach - a container, a devcontainer, or a separate OS user.
sidebar:
  order: 12
---

A [grant](/concepts/grants/) can decrypt only the keys it was minted for.
That scope is a real boundary only when the grant key is the only murk key
the agent can reach.

On your own laptop, under your own user, it is not. An agent that runs as you
can read `~/.config/murk/keys`. It can also unset `MURK_AGENT`, `MURK_STRICT`,
`MURK_KEY` and `MURK_KEY_FILE` in its own shell. Its next `murk` command then
finds your stored key from the vault's path, and the grant no longer limits
it. A change to this lookup is planned for murk 0.16. Until then, run the
agent where your key directory does not exist or cannot be read:

- [in a container](#recipe-a-container),
- [in a devcontainer](#recipe-a-devcontainer), or
- [as a separate OS user](#recipe-a-separate-os-user).

Each recipe gives the agent two things: a checkout of the repository and one
grant key file. Nothing else from `~/.config/murk` goes in.

## The check

Each recipe ships with a check that runs as the agent, inside the recipe:
[`scripts/agent-isolation/check.sh`](https://github.com/interrupted-sh/murk/blob/main/scripts/agent-isolation/check.sh).
It passes only if all four of these hold:

1. The operator's key directory is not readable.
2. With `MURK_AGENT`, `MURK_STRICT`, `MURK_KEY` and `MURK_KEY_FILE` unset,
   `murk get OUT_OF_SCOPE` fails, because murk finds no key.
3. With the grant key, `murk get IN_SCOPE` works.
4. With the grant key, `murk get OUT_OF_SCOPE` fails with
   `OUT_OF_SCOPE is outside this grant's scope`.

Run it yourself inside your setup:

```bash
GRANT_KEY_FILE=/run/murk/key OPERATOR_KEYS=/home/alice/.config/murk/keys \
  sh check.sh API_KEY OTHER
```

```text
ok   operator key directory /home/alice/.config/murk/keys is not readable
ok   with no murk variables set, murk get OTHER fails: ✕ MURK_KEY not set
ok   the grant reads API_KEY
ok   the grant refuses OTHER: ✕ OTHER is outside this grant's scope
isolation check passed: the grant key is the only murk key here
```

Run under your own user, the same check fails on the first two lines. That is
the gap the recipes close.

[`scripts/agent-isolation/run-checks.sh`](https://github.com/interrupted-sh/murk/blob/main/scripts/agent-isolation/run-checks.sh)
runs each recipe end to end with a throwaway vault and runs the check inside
it:

```bash
sh scripts/agent-isolation/run-checks.sh container
sh scripts/agent-isolation/run-checks.sh devcontainer
sh scripts/agent-isolation/run-checks.sh os-user
```

## Mint the grant key

All three recipes start the same way. Mint a grant for the keys the task needs,
and write the key to a file outside the repository:

```bash
murk agent grant --name agent --only API_KEY --ttl 8h --out ~/agent.key
```

The key file carries the signers your machine trusts and the grant's expiry.
So it works where there is no trust pin, and murk refuses an unchanged copy past that expiry. Whoever holds a copy can delete the expiry line, so keep the TTL short.
See [Grants](/concepts/grants/) for the rest of its rules.

## Recipe: a container

Build an image with murk and your agent CLI in it. The image in
[`scripts/agent-isolation/Dockerfile`](https://github.com/interrupted-sh/murk/blob/main/scripts/agent-isolation/Dockerfile)
installs murk from a release and checks its checksum. Add your agent's own
install steps to it, then build it:

```bash
docker build -t murk-agent-isolation scripts/agent-isolation
```

Run the agent with the repository and the key file mounted, and nothing from
your home directory:

```bash
docker run --rm -it \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/work" -w /work \
  -v "$HOME/agent.key:/run/murk/key:ro" \
  -e MURK_KEY_FILE=/run/murk/key -e MURK_AGENT=1 \
  murk-agent-isolation
```

- `--user` runs the container as you, so it can read the key file and
  `.murk`. murk writes both with mode `0600`.
- Do not mount `$HOME`, `~/.config` or `~/.ssh`.
- Do not pass `MURK_*` variables from your shell with `-e MURK_KEY` or an
  `--env-file`.

[Containers](/guides/containers/) covers the key-file rules, signals and
build secrets.

## Recipe: a devcontainer

Put this `devcontainer.json` next to the Dockerfile in `.devcontainer/`. It
mounts the key file named by `MURK_GRANT_KEY_FILE` on your machine, and
nothing else from your home directory:

```json
{
  "name": "murk agent",
  "build": { "dockerfile": "Dockerfile" },
  "remoteUser": "agent",
  "updateRemoteUserUID": true,
  "mounts": [
    "source=${localEnv:MURK_GRANT_KEY_FILE},target=/run/murk/key,type=bind,readonly"
  ],
  "containerEnv": {
    "MURK_KEY_FILE": "/run/murk/key",
    "MURK_AGENT": "1"
  }
}
```

```bash
MURK_GRANT_KEY_FILE=~/agent.key devcontainer up --workspace-folder .
```

Editors that open the folder in a container (VS Code, for example) read the
same file. Set `MURK_GRANT_KEY_FILE` in the environment the editor starts
from.

Some editor setups mount more than the workspace. VS Code can copy your git
config and forward your SSH agent, for example. Those do not reach
`~/.config/murk`, but check your own settings for any mount of your home
directory.

## Recipe: a separate OS user

On Linux, give the agent its own user. Run these as root:

1. Create the user:

   ```bash
   useradd --create-home --shell /bin/sh murk-agent
   ```

2. Give it the grant key file, owned by that user, mode `0600`:

   ```bash
   install -d -m 0700 -o murk-agent -g murk-agent /home/murk-agent/.config/murk-grant
   install -m 0600 -o murk-agent -g murk-agent ~alice/agent.key /home/murk-agent/.config/murk-grant/key
   ```

3. Give it its own clone of the repository. murk writes `.murk` with mode
   `0600`, so another user cannot read your working copy. git also refuses a
   repository owned by another user until it is listed in `safe.directory`:

   ```bash
   runuser -u murk-agent -- env HOME=/home/murk-agent \
     git config --global --add safe.directory /home/alice/src/app/.git
   runuser -u murk-agent -- env HOME=/home/murk-agent \
     git clone -q /home/alice/src/app /home/murk-agent/app
   ```

4. Start the agent as that user, with only the grant key set:

   ```bash
   cd /home/murk-agent/app
   runuser -u murk-agent -- env -i PATH="$PATH" HOME=/home/murk-agent \
     MURK_KEY_FILE=/home/murk-agent/.config/murk-grant/key MURK_AGENT=1 \
     <your agent command>
   ```

murk creates `~/.config/murk` with mode `0700`, so the agent user cannot read
your keys. [`scripts/agent-isolation/os-user.sh`](https://github.com/interrupted-sh/murk/blob/main/scripts/agent-isolation/os-user.sh)
runs steps 1 to 3 and then the check.

On macOS, create a standard user (System Settings, or `sysadminctl`) and
follow the same steps with `sudo -u` instead of `runuser`. The check script
runs there too. The automated test runs the Linux steps only.

## What the recipes do not cover

- **The grant key is still a bearer credential.** The agent can copy it out
  of the container or the agent user's home. Keep the TTL short.
- **The agent still sees the values it is given.** A grant limits which
  values reach the agent, not what it does with them. See
  [What each approach protects against](/guides/agent-protection-compared/).
- **The vault's history.** A grant key decrypts old vault versions in git
  with raw age, for the keys it could read then. Revoke the grant and rotate
  its secrets to close that.
