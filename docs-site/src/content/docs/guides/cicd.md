---
title: CI/CD
description: Use murk secrets in continuous integration.
sidebar:
  order: 4
---

A CI job needs its own key to decrypt the vault. Give the job a scoped grant
when it needs only some secrets. Give it a full key only when it needs the
same access as a teammate. Store the key in your CI system's secret store,
and decrypt at run time.

## GitHub Actions

Use [murk-action](https://github.com/interrupted-sh/murk-action) to decrypt
secrets into the job environment:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
  - run: ./deploy.sh  # the secrets the key can read are now in the environment
```

The action runs on Linux and macOS runners. It installs murk, runs
`murk export`, and writes each decrypted value to `GITHUB_ENV`, so the later
steps of the job can read them. Its `tags` input takes space-separated tags
and exports only the keys with those tags.

Store the key as a GitHub Actions secret (`Settings → Secrets and variables
→ Actions`). The action registers each decrypted value with the GitHub log
masking. Masking depends on the runner and is not a security boundary, so
never print a decrypted value.

The organization changed its name from `interrupted-inc` to `interrupted-sh`.
Change each workflow that still uses `interrupted-inc/murk-action` to
`interrupted-sh/murk-action`.

## Prefer a scoped grant over a full key

A full key gives CI the same access as a teammate. CI can then decrypt every
shared secret, and a leaked CI secret is as bad as a leaked developer key. If
the job needs only some secrets (deploy credentials, not every key in the
vault), mint a scoped **agent grant**:

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30d --out - | gh secret set MURK_KEY
git add .murk && git commit -m "grant ci-deploy" && git push
```

`--out -` writes the grant key file to stdout and keeps no copy, so the file
goes directly into the Actions secret. Above the key, the file has
`# murk-trusted-signer:` lines and the grant's `# murk-grant-id:` and
`# murk-grant-expires:` lines.

A grant reads only shared values. `murk agent grant` refuses a key that has
only a group value or only a `me` value.

Give the secret to murk-action as `murk-key`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
  - run: ./deploy.sh  # DEPLOY_TOKEN is now in the environment
```

This needs murk-action v1.2.0 or later, which `@v1` gives. The action gives
the whole file to murk. A job that runs `murk` itself uses the same secret as
`MURK_KEY`. The trusted-signer lines name who may sign the vault, so the job
needs no `MURK_TRUSTED_SIGNERS`. One secret is sufficient.

The key stops working at the expiry it was minted with, whatever a later
vault says. When the record in the vault allows more time, the refusal names
the expiry of the key file:

```
✕ grant ci-deploy expired 2026-11-20T19:56:49Z (its key file's expiry) — renew with `murk agent grant --renew` or close it with `murk agent revoke ci-deploy`
```

The grant lives in `.murk`. CI can use the key only after the vault that
holds the grant is on the branch that the job checks out. Under the grant,
`murk export` gives only the granted keys. A `murk get` of any other key
fails with `KEY is outside this grant's scope`.

If you pin a murk-action older than v1.2.0, it takes only the bare key line.
Keep only that line with `grep`:

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30d --out - | grep AGE-SECRET-KEY | gh secret set MURK_KEY
```

A bare key names no signer, so also give the job its signers (see [Telling
CI who may sign the vault](#telling-ci-who-may-sign-the-vault)). A bare key
also has no expiry. Only the grant record in the vault limits it, and each
`murk` command in the job prints a warning:

```
warn this grant key file carries no expiry, so only the vault's grant record bounds it — ask the operator to re-mint it (`murk agent grant --renew`)
```

murk uses the same mechanism to limit what AI agents can read. See [AI
agents & MCP](/guides/ai-agents-mcp/) for the full grant and revoke
lifecycle, and the [CLI reference](/reference/cli/#murk-agent-grant) for all
the flags.

### Renewing the grant

Before the grant expires, run the same two lines with `--renew`. Add the
`grep` if you store the bare key line:

```bash
murk agent grant --name ci-deploy --only DEPLOY_TOKEN --ttl 30d --renew --out - | gh secret set MURK_KEY
git add .murk && git commit -m "renew ci-deploy" && git push
```

`--renew` revokes the old key and mints the new one in a single vault write.
It also works after the grant has expired. Update the Actions secret and push
the vault at the same time. A job that runs between the two fails with
`not a recipient`, never silently.

If you miss the renewal, the job fails with `grant ci-deploy expired`. If
someone writes the vault before that job runs, the write removes the expired
grant, and the job fails with `not a recipient`. In both cases the job fails
closed, as intended.

![A CI grant piped into the CI secret input (gh shimmed locally for the recording) exports only DEPLOY_TOKEN, fails loudly once expired, and comes back after --renew](/demos/ci-grant.gif)

murk enforces the TTL when it reads, so an expired grant fails closed. But an
age key cannot destroy itself, and git keeps the old `.murk` versions
readable. So treat a CI grant as you treat every other credential. Revoke it
(`murk agent revoke NAME --rotate`) when you no longer need it. Rotate what
it exposed if the CI runner or its logs could have leaked it.

## Create a full key for CI

For a key with the same access as a teammate, generate a key pair with
[`age-keygen`](https://github.com/FiloSottile/age). Authorize the public key
and store the secret key:

```bash
age-keygen -o ci.key                    # prints the public key (age1...)
murk circle authorize age1... --name ci
grep AGE-SECRET-KEY ci.key | gh secret set MURK_KEY
rm ci.key
git add .murk && git commit -m "authorize ci" && git push
```

murk-action needs an age secret key (`AGE-SECRET-KEY-1...`), not an SSH key.
A full key needs `MURK_TRUSTED_SIGNERS` (next section).

## Telling CI who may sign the vault

A new CI runner has no [trust pin](/concepts/recipients-signatures/#trusting-a-signer),
and nobody is there to run `murk trust`. murk then refuses the vault with
"not trusted on this machine yet". A [scoped grant's whole key
file](#prefer-a-scoped-grant-over-a-full-key) names its own signers. Every
other key needs `MURK_TRUSTED_SIGNERS`, set to the people who write the
vault. Store it as a secret next to `MURK_KEY`, and give it to murk-action as
`trusted-signers`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: interrupted-sh/murk-action@v1
    with:
      murk-key: ${{ secrets.MURK_KEY }}
      trusted-signers: ${{ secrets.MURK_TRUSTED_SIGNERS }}
  - run: ./deploy.sh
```

The `trusted-signers` input needs murk-action v1.2.0 or later, which `@v1`
gives. On an older murk-action, set `MURK_TRUSTED_SIGNERS` in the `env:` of
the step.

:::caution
Set `MURK_TRUSTED_SIGNERS` only from a CI secret or the real process
environment. Never set it from a file in the repository, or from a `.env`
file that an app's dotenv loader reads. The variable decides which signers
this machine trusts. The murk CLI never reads `.env`, but the Python and
Node bindings read the process environment. So an app that calls
`load_dotenv()` or `dotenv.config()` before `murk.load()` lets a `.env` in
the repository choose the signers.
:::

### The entry format

Each entry names one signer. An age signer is `age1...:<verifying key>`,
which is the recipient, a colon and the base64 Ed25519 verifying key. An `ssh-ed25519`
signer is its public key line. Separate the entries with commas or newlines.

To build the value, each person who writes the vault runs
`murk trust --print-key` on their own machine. It prints their entry to
stdout and their signing-key fingerprint to stderr, so
`murk trust --print-key > entry.txt` keeps only the entry. Put the entries in
the secret, one on each line.

A bare `age1...` key without `:<verifying key>` is an error. murk cannot
compute an age key's verifying key from its recipient string. A key that
cannot sign (`ssh-rsa`, hardware) has no entry. Any entry in neither form is
an error.

### Who to list

List the people who write the vault, not every recipient. `murk circle`
lists the recipients. The variable replaces the trusted set of the pin. The
job accepts a vault only when one of those keys signed it. An age signer's
signature must also verify under the verifying key in its entry. Agent grant
keys in the list never count.

murk does not write the trust from the variable into the pin. So a
self-hosted runner that keeps its home directory does not carry the signers
into later jobs that do not set the variable. When the runner cannot write
to its home directory, murk prints only a warning that it cannot save the
pin.

### Later steps that run murk

The action sets the variable only for the murk commands that it runs. A
later step that runs murk itself needs the variable in its own `env:`:

```yaml
  - run: murk exec -- ./deploy.sh
    env:
      MURK_KEY: ${{ secrets.MURK_KEY }}
      MURK_TRUSTED_SIGNERS: ${{ secrets.MURK_TRUSTED_SIGNERS }}
```

### Scoped grants and signers

A scoped grant key never reads the pin. It trusts the signers in its key
file, which are the `# murk-trusted-signer:` lines that `murk agent grant`
writes above the key, plus each signer in `MURK_TRUSTED_SIGNERS`. So the
whole key file works on a runner with no pin and no variable. murk-action
v1.2.0 and later take the whole file as `murk-key`. A bare key line names no
signer, so a grant given that way needs `MURK_TRUSTED_SIGNERS`.

A signer that you add after you mint the grant is not in its key file. The
grant then refuses the vault. Mint it again with `--renew`, or list that
signer in `MURK_TRUSTED_SIGNERS`.

### Limits

A runner with no pin cannot detect a rollback. An older revision with a
valid signature on the checked-out branch loads. Protect the branch that the
job deploys from.

A teammate with a hardware or `ssh-rsa` key writes the vault unsigned. CI
refuses that vault until a signing teammate runs `murk trust` and commits the
re-signed vault. When `MURK_TRUSTED_SIGNERS` is set, every key refuses an
unsigned vault, including a runner key that cannot sign. When you name the
signers you require, murk never accepts an unsigned vault.

## Vault keys with reserved names

`murk export`, `murk exec` and `murk agent exec` refuse to set a variable
that controls how programs, shells or murk itself run. Examples are `PATH`,
`HOME`, names that start with `GIT_`, `CARGO_`, `NPM_CONFIG_`, `PYTHON`,
`SSL_` or `PIP_`, and names that end in `_PROXY`. A common CI secret such as
`CARGO_REGISTRY_TOKEN` is one of them. The command exits 1 and names the
key: `refusing to set CARGO_REGISTRY_TOKEN from the vault`.

murk-action runs `murk export` without `--allow-reserved` and has no input
for it. So a vault that holds such a key fails the whole action step. To keep
the key out of the job, give the other keys a tag and set the `tags` input
of the action. You can also rename the key.

In a step that runs murk itself, `murk exec --only KEY` passes only the keys
that you name, and `murk export --tag TAG` exports only the tagged keys. You
can also pass `--allow-reserved`, which lets murk set the reserved name.
Review who added the key (`murk diff`, `git log -p`) before you use it.
See [Variable names a vault may not
set](/concepts/env-vars/#variable-names-a-vault-may-not-set) for the full
list.

## Other CI systems

For other CI systems, install murk (see [Install](/install/)). Store the key
in the secret store of the system as `MURK_KEY`, and wrap the command:

```bash
murk exec -- ./deploy.sh
```

`murk exec` decrypts the vault and runs the command with the secrets in its
environment. It needs no `.envrc` or direnv. The command does not get
`MURK_KEY`. Use `--only KEY` (repeatable) to pass a subset of the secrets.
Use `--clean-env` to remove the other variables of the runner. On Unix it
keeps `PATH`, `HOME` and `TERM`. On Windows it keeps `PATH` and the system
variables that Windows programs need.

To run murk inside a container, see [Containers](/guides/containers/).

## Upgrading to 0.14

Before CI loads a vault that murk 0.14 or later wrote, do two things:

1. Install murk 0.14 or later on the runner. A 0.14 save writes a signature
   format that 0.13 refuses. Upgrade the Python or Node binding too, if the
   job uses one. An older binding fails with `unsupported vault version`.
2. Give CI its trusted signers with `trusted-signers` or `MURK_TRUSTED_SIGNERS`
   as described above, or the whole key file of a grant. A runner with a
   0.13-era setup has no pin. Without trusted signers, it refuses the first
   0.14 vault.

Upgrade the people who write the vault too. A runner with no pin keeps no
0.14 mark, so it cannot refuse a vault that 0.13 signed. On a machine with a
pin, the refusal applies per branch. For the full rules, see [upgrading to
0.14](/guides/teams/#upgrading-to-014).
