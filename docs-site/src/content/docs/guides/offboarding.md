---
title: Offboarding a teammate
description: Revoke access and rotate secrets when someone leaves.
sidebar:
  order: 3
---

When someone leaves the team, revoke their access and rotate every secret
they could read.

![Revoking a teammate and rotating the secrets they could read](https://raw.githubusercontent.com/interrupted-sh/murk/demo/offboard.gif)

## Revoke and rotate in one step

murk cannot change a credential at its provider. Here, rotating means that
you store a replacement value in the vault. First create the new credential
at each service. Invalidate the old one after you push the new vault. In an
urgent case, invalidate it first.

```bash
murk circle revoke carol --rotate
```

`carol` can be a display name, a public key or `github:carol`. murk rejects
a display name that matches more than one key (`ambiguous name "carol"
matches 2 recipients`). In that case, list the full keys with
`murk circle --json` and revoke each one by its public key.

A teammate added with `github:` has one recipient for each key on their
account, all named `carol@github`. Revoking `carol@github` or `github:carol`
removes all of those keys. When there is more than one key, murk lists them
and asks you to confirm. Without a terminal, it refuses unless you pass
`--force`.

Another recipient must run the command. murk refuses to revoke your own key,
so a member who leaves cannot remove themselves. They ask a teammate to run
`murk circle revoke <their name>`.

The command removes carol as a recipient. It re-encrypts the shared secrets
without her key. With `--rotate`, it also asks you for a new value for each
secret she could read, in the same session. That includes shared secrets and
the secrets of her groups. A group secret gets its new value in the same
group. Commit and push the result:

```bash
git commit -am "revoke carol, rotate secrets" && git push
```

If you leave out `--rotate` in an interactive terminal, `murk circle revoke`
offers to rotate. In a script, it prints a hint instead.

## Rotate from a file

If you already have the new values in a file, give it to `--values-from`.
murk then does not ask for values:

```bash
murk circle revoke carol --rotate --values-from .env.rotated
rm .env.rotated
```

The file holds one `KEY=value` line per key, in the same format as
`murk import`. Use `-` to read the lines from stdin. Put a multi-line value,
such as a PEM key, in double quotes (`KEY="..."`). murk refuses the whole file
when a line is not a `KEY=value` entry, when a key is named twice, or when
the file is a symlink. It then rotates and revokes nothing, and its message
gives line numbers, never values. The same rules apply to
`murk rotate --values-from` and `murk agent revoke --rotate --values-from`.

murk matches values to secrets by name, and each secret stays in its tier.
The file must not name a key that cannot be rotated here. That is a key that
is not in the vault, a key in a group you are not in, or a key carol could
not read. If the file names one, murk refuses the whole batch and writes
nothing, so carol stays a recipient.

murk does not rotate the keys that the file leaves out. It reports them, and
`murk rotate --list` continues to list them. Delete the file when you are
done, because it holds plaintext secrets.

## Why rotation matters

Revocation removes carol's key from the shared-secret ciphertexts that murk
writes from now on.

:::caution
Revocation does not erase git history. The revoked user can still decrypt
every version of the vault they had access to, from old git commits. Only
rotation closes that exposure. Create a new credential at the provider and
store it as the new value.
:::

So always rotate after you revoke someone whose access mattered.
`murk circle revoke --rotate` does both in one step. If you leave out
`--rotate`, run `murk rotate KEY` (or `murk rotate --all`) afterwards for
each sensitive secret they could read.

## What stops a revoked teammate coming back

`murk circle revoke` removes every spelling of the key. murk also refuses an
`age1...` key with a non-canonical encoding, so an alias of the key cannot
survive the revocation.

After a machine accepts the vault that removed them, it refuses every vault
that the revoked key signs, on every branch. It also refuses an older
revision that still lists them as a rollback, on each branch that the revoke
has reached. [Trusting a signer](/concepts/recipients-signatures/#trusting-a-signer)
gives the full removal rule and its one exception.

Revoke on the main branch. A revoke on an unmerged branch does not change
the vaults on main. Until you merge it, they are still a recipient on main
and on each branch the revoke has not reached. There they can read every
secret that someone adds or rotates. When you merge, a vault that changed on
both branches gives a [conflict](/guides/git-merge-ssh/#conflicts) that you
resolve by hand.

If you revoked on a branch, merge it into main before you add or rotate
secrets anywhere else. A `--rotate` on that branch protects only the values
it rotated there. To go back to an older vault on purpose, see [rollback and
deliberate reverts](/concepts/recipients-signatures/#rollback-and-deliberate-reverts).

## Agent grants that trusted them

Revoking a teammate also revokes each agent grant whose key file trusts them
as a signer. murk deletes the grant key files that it keeps itself. It
cannot reach the other copies, such as a key file written with `--out`, the
copy on the agent host, or a file minted on another operator's machine. Such
a copy still trusts the revoked teammate.

If the revoked teammate signs a vault built from a copy from before the
revoke, the agent reads the values they chose. The key file's expiry line
ends this. A key file without that line has no limit, because they can write
a later expiry into the vault. Key files minted by an older murk, and bare
key lines, have no expiry line.

So delete every other copy of each revoked grant's key file, including the
copy on the agent host. Then mint the grant again
(`murk agent grant --name NAME --only KEY --renew`). The revoke lists the
grants and prints the commands. Also remove the revoked teammate's entry from
`MURK_TRUSTED_SIGNERS` everywhere it is set.

## Checking what needs rotating

```bash
murk rotate --list         # keys needing rotation: overdue, expiring, post-revoke
murk rotate --list --json
```

This lists the secrets that are overdue for rotation, near an expiry, or
still open after a past revoke. Set the rotation interval and the expiry of a
key with `murk describe`:

```bash
murk describe API_KEY "payments API" --rotate-every 90d --expires 2027-01-31
```

Run `murk rotate --list` as a regular check, not only when someone leaves.
`murk doctor` scans the repository for wider problems. The [CLI
reference](/reference/cli/#murk-circle-revoke) lists all flags of
`circle revoke` and `rotate`.

The human output exits 1 when a secret needs rotation, so you can use it as
a CI gate. With a key, `rotate --list` verifies the vault first. If someone
deletes a `revoked_at` or `expires_at` marker from the header, the command
fails instead of passing the gate. Without a key, it can only read the header
as written. It then prints `warn unverified header`, `--json` reports
`"verified": false`, and under `MURK_STRICT` it exits 1. `--json` prints
`{"verified": ..., "issues": [...]}`.

To add and authorize teammates, see [working in teams](/guides/teams/).
