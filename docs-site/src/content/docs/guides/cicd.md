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

## Check the vault on each pull request

The GitHub merge button, its conflict editor and GitHub merge queues do not
run the murk merge driver. When a pull request and its base branch both
changed `.murk`, a merge without the driver can give a vault whose signature
does not verify. murk refuses that vault on every load, so it never
gives wrong values. But the failure shows only after the merge, on the base
branch. See [server-side merges](/guides/git-merge-ssh/#server-side-merges).

murk-action finds this case before the merge. Set its `mode` input to
`verify` in a workflow that runs on pull requests:

```yaml
name: vault
on:
  pull_request:
  merge_group:
jobs:
  verify-vault:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: interrupted-sh/murk-action@v1.3.0
        with:
          mode: verify
          trusted-signers: ${{ vars.MURK_TRUSTED_SIGNERS }}
```

Verify mode needs murk-action v1.3.0 or later and murk 0.15.2 or later. The
recipe pins v1.3.0. Do not use an older murk-action here: GitHub only warns
about an input that an action does not know, so an older murk-action ignores
`mode` and runs an export.

On a `pull_request` event, `actions/checkout` checks out the test merge that
GitHub makes of the pull request and its base branch
(`refs/pull/N/merge`). So the job checks the vault that the merge button
would give. On a `merge_group` event, it checks out the merge that the merge
queue made.

### What the check does

In verify mode, the action installs murk and runs `murk verify
--signature-only` on the vault. This check needs no key. It verifies that
one of the signers in `trusted-signers` signed the content of the vault.
The action sets no environment variables, sets no `keys` output, and has no
value to print.

The check has these limits:

- It does not decrypt the vault. So it does not check the MAC, that a key
  can decrypt the vault, or the values. For those checks, run the full
  `murk verify` with a key, as a step that has `MURK_KEY` in its `env:`.
- It checks the parsed vault, not the bytes of the file. A reformatted
  `.murk`, or one with an extra unknown field, still passes.
- It trusts each signer in `trusted-signers` and nothing else. It does not
  apply the removed-key or group-membership rules of a load. When someone
  leaves the team, remove their entry from `MURK_TRUSTED_SIGNERS` (the
  repository variable, or the workflow file). Until you do, the check
  accepts a vault that they sign.
- A merge that keeps one whole side of the vault, such as `git checkout
  --ours .murk`, still passes. It drops the changes of the other side.

The trusted-signer entries are public keys, so the recipe reads them from a
repository variable, not a secret. A runner has no trust pin, so verify mode
needs `trusted-signers` (see [The entry format](#the-entry-format)).

GitHub gives neither secrets nor variables to a workflow that a pull request
from a fork starts. To run the check on such a pull request, write the
entries in the workflow file, as a literal value of `trusted-signers`. A pull
request can change the workflow file that its own check runs. So the check
finds a bad merge by mistake, but it does not stop a hostile pull request.
murk still refuses a bad vault on every load.

### When the check fails

The step fails in these cases:

- The signature of the vault does not verify, or murk cannot parse the
  vault. The step then names the cause: both this branch and the base branch
  changed the vault, and a merge
  without the murk merge driver cannot combine two vaults. It tells you to
  run `git fetch origin && git merge origin/<base>` on your machine, push,
  then merge the pull request. The steps are in [server-side
  merges](/guides/git-merge-ssh/#server-side-merges).
- No signer in `trusted-signers` signed the vault, or the vault is unsigned.
  `murk export` refuses that vault too. See [Telling CI who may sign the
  vault](#telling-ci-who-may-sign-the-vault).

When both branches changed `.murk`, the text merge conflicts. GitHub then
runs no `pull_request` workflow and blocks the merge button. The check
fails when someone resolves that conflict as text, for example in the GitHub
conflict editor.

### Make the check required

Make the job a required status check. In the branch protection rule or
ruleset of the base branch, add `verify-vault` as a required check. Also
require branches to be up to date before merging. GitHub runs the check
when the pull request changes, not when the base branch changes. So without
this rule, a passed check can be out of date. With a merge queue, keep the
`merge_group` trigger: the queue waits for the required check on its own
merge. Do not add a `paths` filter to the workflow, because GitHub waits
forever for a required check that did not run.

## Vault keys with reserved names

`murk export`, `murk exec` and `murk agent exec` refuse to set a variable
that controls how programs, shells or murk itself run. Examples are `PATH`,
`HOME`, `TMPDIR`, `KUBECONFIG`, `DOCKER_HOST`, `GOPROXY`, names that start
with `GIT_`, `CARGO_`, `NPM_CONFIG_`, `PYTHON`, `SSL_`, `PIP_` or `XDG_`, and
names that end in `_PROXY`. A common CI secret such as
`CARGO_REGISTRY_TOKEN` is one of them. The command exits 1 and names the
key: `refusing to set CARGO_REGISTRY_TOKEN from the vault`.

murk 0.15 reserves more names than 0.14: shell prompt variables, package
sources such as `GOPROXY` and `UV_INDEX_URL`, client configs such as
`KUBECONFIG`, `DOCKER_HOST` and `AWS_CONFIG_FILE`, and `TMPDIR`. A vault that
0.14 exported in CI can fail on 0.15 if it holds one of them.

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
