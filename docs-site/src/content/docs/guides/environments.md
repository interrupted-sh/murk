---
title: Environments
description: Keep development, staging and production secrets in one repository, with one vault for each environment.
sidebar:
  order: 2.5
---

murk has no environment setting. A vault file is one set of secrets with one
list of recipients. To keep development, staging and production apart, give
each environment its own vault file in the repository:

| File | Environment | Recipients |
|---|---|---|
| `.murk` | development | every developer |
| `.murk.staging` | staging | developers and CI |
| `.murk.prod` | production | the operations team and the production deploy |

Every command takes `--vault FILE`, or reads the file name from
`MURK_VAULT`. Without either, murk uses `.murk`.

Names in the style `prod.murk` and `staging.murk` work the same way. This
guide uses `.murk.prod` and `.murk.staging`.

## One vault per environment, tags, or groups

murk has three ways to divide secrets. Only separate vaults give one key name
a different value in each environment.

| You need | Use |
|---|---|
| `DATABASE_URL` with a different value in dev, staging and prod | one vault per environment |
| Different people or CI jobs for each environment | one vault per environment |
| A separate git history and `murk diff` for production | one vault per environment |
| Export only the keys that one service uses | tags, in one vault |
| Hide some keys from part of the team | a group, in one vault |

A vault holds one value for each key name. Tags only label keys.
`murk export --tag web` exports the keys with that tag, but every teammate on
the vault can still read every shared key. A group limits who can decrypt a
key, but the key still has one value. See [Shared, group and private
secrets](/guides/shared-vs-scoped/) for groups.

## The merge driver covers both naming styles

`murk setup-merge-driver` adds two lines to `.gitattributes`: `*.murk
merge=murk` and `.murk.* merge=murk`. So the [merge
driver](/guides/git-merge-ssh/) applies to `.murk`, `.murk.prod` and
`prod.murk`. If you set up the driver with murk 0.14 or older, run `murk
setup-merge-driver` again to add the second line, and commit
`.gitattributes`.

## Create the vaults

Create the development vault first, then one vault for each other
environment:

```bash
murk init
murk init --vault .murk.staging
murk init --vault .murk.prod
```

When you create the second vault, murk already has a key for `.murk` on this
machine. So `murk init` asks once:

```text
another vault in this directory has a key stored on this machine
  1) use the key of .murk for .murk.staging too (default)
  2) make a separate key for .murk.staging
choose [1]:
```

- **Use the same key** (the default): murk stores your key for the new vault
  too. `.env` does not change. You are the first recipient of the new vault
  with the same public key.
- **Make a separate key**: murk makes a new key for the new vault and shows
  its recovery words. `.env` does not change and still names the key of
  `.murk`.

murk looks only for vaults in the same directory as the new vault, in this
checkout and in the other git worktrees of the repository.

After either choice, every command finds the key of the new vault from
`--vault` or `MURK_VAULT`. You need no other setup. This also works in a new
git worktree, as for `.murk` (see [Git worktrees](/guides/worktrees/)).

```bash
murk add DATABASE_URL --vault .murk.prod
murk get DATABASE_URL --vault .murk.prod
MURK_VAULT=.murk.staging murk ls
```

### Scripts and agents

Without a terminal, `murk init` does not ask. It stops and names the two
flags. `--reuse-key` uses the stored key, and `--separate-key` makes a new
one:

```bash
murk init --vault .murk.staging --reuse-key
```

If the vaults in the directory use different keys, `--reuse-key` does not
choose between them. Run `murk init` in a terminal to choose.

Under `MURK_AGENT` or `MURK_STRICT`, `murk init` never uses a stored key,
even with `--reuse-key`, and never prints where your keys are stored. Create
the vault in your own terminal. An agent can still make a vault with
`--separate-key`.

## Different recipients for each environment

Each vault has its own recipients. Authorize a person on the vaults of the
environments that they work on:

```bash
murk circle authorize age1... --name bob --vault .murk
murk circle authorize age1... --name bob --vault .murk.staging
murk circle authorize age1... --name ops-alice --vault .murk.prod
```

Here bob can read development and staging but not production. To take a
person off one environment, revoke them from that vault only:

```bash
murk circle revoke bob --vault .murk.staging
```

The other parts of trust are also separate for each vault: the [trust
pin](/concepts/recipients-signatures/#trusting-a-signer) (`murk trust --vault
.murk.prod`), the [agent grants](/concepts/grants/) and the agent policy.
Trusting the signer of `.murk` does not trust `.murk.prod`.

## One key, or one key for each environment

| | One key | One key for each environment |
|---|---|---|
| Setup | `murk init` reuses your key | `murk init` makes a new key |
| Recovery words | one set | one set for each key |
| A leaked key exposes | every vault you are a recipient of | the vaults of that key only |
| Hardware key for production | no | yes, see [Hardware keys](/guides/hardware-keys/) |

One key is simpler for most people. Use a separate key when production needs
more protection than your daily key has. For example, keep the production
key on a hardware key.

murk finds a separate key from `--vault` or `MURK_VAULT`. A key in the
environment comes first: if `MURK_KEY` or `MURK_KEY_FILE` is set, murk uses
that key for every vault. `.env` sets `MURK_KEY_FILE` to the key of `.murk`
when your shell loads it (`source .env`, or a `dotenv` line in `.envrc`).
Unset the variable before you use a vault that has a separate key:

```bash
env -u MURK_KEY_FILE murk get DATABASE_URL --vault .murk.prod
```

## direnv for each environment

`murk env` writes a `.envrc` that exports the secrets of one vault:

```bash
murk env --vault .murk.staging
direnv allow
```

The `.envrc` then runs `murk export --vault .murk.staging`. `murk env`
changes nothing when `.envrc` already has a `murk export` line, so a
directory loads one environment. To load another environment, edit the
`--vault` in `.envrc`, or run one command with that environment:

```bash
murk exec --vault .murk.prod -- ./deploy.sh
```

See [direnv integration](/guides/direnv/) for the rest of the setup.

## CI: one grant for each environment

Give each environment its own [scoped grant](/guides/cicd/#prefer-a-scoped-grant-over-a-full-key).
A grant belongs to one vault, so the staging key cannot read `.murk.prod`.
With GitHub environments, store each key in the secrets of its environment:

```bash
murk agent grant --name ci-staging --only DATABASE_URL --vault .murk.staging --out - | gh secret set MURK_KEY --env staging
murk agent grant --name ci-prod --only DATABASE_URL --vault .murk.prod --out - | gh secret set MURK_KEY --env production
git add .murk.staging .murk.prod && git commit -m "grant CI per environment" && git push
```

Give murk-action the vault of each job with its `vault` input:

```yaml
jobs:
  deploy-staging:
    environment: staging
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: interrupted-sh/murk-action@v1
        with:
          murk-key: ${{ secrets.MURK_KEY }}
          vault: .murk.staging
      - run: ./deploy.sh
  deploy-prod:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: interrupted-sh/murk-action@v1
        with:
          murk-key: ${{ secrets.MURK_KEY }}
          vault: .murk.prod
      - run: ./deploy.sh
```

The whole grant key file names the signers of its vault, so neither job needs
`trusted-signers`. Each grant has its own expiry. Renew each one with
`--renew` and its own `--vault`.

## What git history and murk diff show

Each environment is its own file, so git keeps a separate history for each:

```bash
git log -p -- .murk.prod
murk diff --vault .murk.prod
murk diff main --vault .murk.staging
```

`git log` shows only the commits that changed production. `murk diff` shows
what changed in one vault since a git ref (`HEAD` by default): recipients,
signer, signing keys, policy, grants, group members and secret names. It
shows values only with `--show-values`. A change to `.murk.staging` never
appears in the diff of `.murk.prod`.
