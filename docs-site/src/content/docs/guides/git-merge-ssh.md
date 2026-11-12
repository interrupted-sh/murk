---
title: Git merge driver & SSH
description: Set up the merge driver and SSH-key authorization.
sidebar:
  order: 9
---

:::caution[Experimental]
The merge driver and `murk diff` are experimental. Few tests run a real git merge, so review a merged vault before you push it. `murk diff` is new in its present form: it also reports recipient, signer, policy, grant and group changes, and its output may change in a minor release.
:::

`.murk` is a single JSON file with encrypted values. A plain git merge does
not work well on it. git cannot know that two different encrypted blobs can
hold changes to different keys that do not conflict. So murk has its own
merge driver. murk also accepts SSH keys as recipients, so you do not need a
separate age key.

![Using an SSH key as a murk recipient](https://raw.githubusercontent.com/interrupted-sh/murk/demo/ssh.gif)

## Setting up the merge driver

```bash
murk setup-merge-driver
```

This command does two things:

- It adds `*.murk merge=murk` and `.murk.* merge=murk` to `.gitattributes`,
  so the driver covers `.murk`, `prod.murk` and `.murk.prod`. Commit that
  file. It goes to every clone with the repository.
- It writes the driver definition to `.git/config`. That is local git
  configuration, which does not go with the repository. Everyone who works
  on the vault runs `murk setup-merge-driver` once in their own clone.

The definition is `murk merge-driver -- %O %A %B %P`, and git runs `murk`
from your `PATH`. git runs the driver during a merge or rebase in which
both branches changed `.murk`. Without it, git does a text three-way merge
on the raw file. The driver's arguments are `BASE OURS THEIRS PATH`. `BASE`
is the common ancestor. `PATH` is the path of the vault (git's `%P`), so the
driver reads the correct trust pin and finds that vault's key. The `--`
keeps a vault named like a flag a path.

The driver merges secret changes that do not conflict, such as different
keys added or changed on each side. It decrypts secret values only when both
sides changed the recipients in the same way. Every ciphertext then differs
from the ancestor, so it compares the values to find which side changed each
secret.

### What the driver checks

Run the driver with your key available: `MURK_KEY`, `MURK_KEY_FILE`, or the
stored key of the vault being merged. The driver finds the stored key of
`.murk.prod` or `prod.murk` as `--vault` does, so a vault with its own key
merges with no setup. A file that matches the pattern but is not a vault
(`.murk.bak`), or a vault on one branch and something else on the other, is
merged as text, with conflict markers where both sides changed the same
lines.

When both branches created the same vault, for example `murk init --vault
.murk.staging` on each, there are two separate vaults, and no merge can
combine them. The driver puts both sides in the file between conflict
markers and stops. It names the secrets that only one side has. Keep one
side and add the other side's secrets again:

```bash
git checkout --ours -- .murk.staging
murk add API_TOKEN --vault .murk.staging
git add .murk.staging
```

With a key, the driver checks **both sides** as a load does:

- the MAC,
- a valid signature from a signer that this machine trusts, not an agent
  grant,
- the same vault id,
- for a side that changed the vault, a save counter above the common
  ancestor's.

It also authenticates the **common ancestor**. The ancestor decides what
counts as a change and which group memberships the sides are judged
against. Without that check, a parent that an attacker chose (a
cherry-pick, a `git apply --3way`) could shape the merge.

The driver merges an ancestor that your key cannot read conservatively. Any
difference in the encrypted metadata is then a conflict. It refuses an ancestor
that fails its checks. An unsigned ancestor from before 0.14 is the
exception. murk cannot check it, and accepts it as history. So a forged
ancestor of that kind, in a commit that you cherry-pick or rebase, can set
values back to an older revision without a conflict. Check what you merged
with `murk diff` (below) before you push.

A side that 0.13 wrote is judged like a load of it on the branch that you
merge into. For these rules, see step 7 of [upgrading to
0.14](/guides/teams/#upgrading-to-014). Make the first 0.14 save on the
default branch before you merge branches that still have 0.13 vaults.

### The merge result

If the ancestor or a side fails, the merge is a conflict that names it. The
driver then writes no new MAC or signature.

Otherwise, the driver writes the merged vault with a new MAC and signs it
with your key. It stays unsigned only when your key cannot sign. The driver
numbers it above both sides and above every vault that this machine has
accepted.

Without a key, the driver cannot verify or sign. So it refuses any merge
that needs new integrity data. It exits 1, and git reports a conflict. Abort
the merge (`git merge --abort`) and run it again with your key available.

The merged vault has your signature, so it must pass the group rule that a
load applies. A member of a group must sign each change to its membership.
When the merge changes a group's membership and your key is not in that
group, the result is a conflict that says so. A member of the group must do
that merge.

### Reviewing a merge

Check what you merged, especially when the driver signed the result in your
name. Compare with the commit you had before the merge:

```bash
git diff ORIG_HEAD -- .murk   # recipients, schema, policy and ciphertext entries
murk diff ORIG_HEAD           # who can read or sign it, and which secrets changed
```

git sets `ORIG_HEAD` to your commit from before a pull or merge, also when
it fast-forwards. Run the diff right after the merge, before another pull,
merge, rebase or reset moves `ORIG_HEAD`. You can also save the commit id
before you merge, and diff against it.

`murk diff [REF]` compares the vault with a git ref. The default is `HEAD`.
It prints the structural changes first, one line each: recipients added and
removed, signer and signing-key changes, and policy, grant and group-member
changes. Then it prints one line for each secret, by key name only: `+`
added, `-` removed, `~` changed. It prints values only with `--show-values`.

```
+ recipient bob@example.com (age1wzsw…8ns8)
~ policy
+ group ops member alice@example.com (age1y8ne…rqke)
- API_KEY
~ DATABASE_URL
+ NEW_TOKEN
```

A vault that a different key signed than before shows `~ signer`, with the
old and the new signer. A recipient whose signing key changed shows
`~ signing key of …`. Add `--json` for a script. It then prints one object
with a `secrets` array and a `changes` array.

`murk diff` also runs on a vault that this machine does not trust yet, with
a warning, because it is the review step before `murk trust`. It verifies
the revision at `REF` before it shows anything from it.

### Upgrading an older driver config

Before 0.14, `murk setup-merge-driver` wrote `murk merge-driver %O %A %B`
with no path. A driver with that configuration still runs. But it uses
`.murk` as the path, so for a vault with another name it reads neither that
vault's trust pin nor its stored key. Such a vault then merges only with
`MURK_KEY` or `MURK_KEY_FILE` set. Run `murk setup-merge-driver` again in
each clone: it replaces the old line with `murk merge-driver -- %O %A %B %P`.

### Merges that never run the driver

git runs the driver only when both branches changed `.murk`. When only one
branch changed the vault, git takes that branch's `.murk` as it is. This is
the usual pull request flow, where main did not change the vault. The merge
then has no conflict, even for a recipient change. The next load still
checks the signature, the signer and the save counter. Such a merge is often
a fast-forward. To see what it changed, run `murk diff ORIG_HEAD` right after
it (see [Reviewing a merge](#reviewing-a-merge)).

Server-side merges (the GitHub web UI, merge queues) also do not run the
driver. When both sides changed the vault, the text merge either conflicts or
gives a vault that fails verification on the next load. murk never gives
values from a vault that it cannot verify. So a bad server-side merge shows
as a refusal, not as wrong values. Run the merge locally if both sides
changed the vault.

## Conflicts

When both branches changed the vault, the driver reports a conflict and git
stops the merge in these cases:

- both sides added or changed the same key,
- one side removed a key that the other side kept or changed,
- only one side added or removed a recipient,
- one side changed a secret while the other side changed recipients,
- both sides changed the recipients in the same way, and also one of these:
  both added the same secret, a secret changed differently on each side, or
  one side removed a secret that the other changed,
- both sides changed the agent policy differently,
- a side, or the common ancestor, fails the checks above (MAC, signature,
  trusted signer, grant key, vault id, save counter),
- the merge changes a group's membership and your key is not in that group.

When both sides changed the recipients in the same way and the ancestor is
an unsigned vault from before 0.14, the driver is stricter. Every secret
whose value differs between the sides conflicts. So does every secret that
your key cannot read (a group you are not in), because the driver cannot
compare it.

To avoid recipient conflicts, authorize and revoke teammates on the main
branch, not on a side branch that also changes secrets. A revoke on a side
branch already makes this machine refuse the revoked key's signatures on
every branch, main included.

The driver lists each conflicting field and exits 1. The `.murk` it leaves
holds the merge of the secrets and recipients of both sides. It keeps the
metadata of our side and has no signature. Do not commit it, and do not
accept it with `murk trust`.

To resolve the conflict, take one side (`git checkout --ours .murk` or
`--theirs`). Then make the changes of the other side again with `murk add
KEY`, `murk circle authorize` or `murk circle revoke`. Check the
result with `murk circle`, then `git add .murk` and commit. If the side you
take is older than the vault this machine accepted on the branch, a load
refuses it as rolled back until you run `murk trust`. Take our side and make
the changes of their side again to avoid that.

## SSH keys as recipients

You can use an SSH key instead of a separate age key pair. murk accepts SSH
public keys as recipients, in the same recipient list as `age1...` keys:

```bash
murk circle authorize ssh:~/.ssh/id_ed25519.pub --name you@example.com
```

To decrypt with the matching private key, point `MURK_KEY_FILE` at it:

```bash
export MURK_KEY_FILE=~/.ssh/id_ed25519
```

murk does not search `~/.ssh` on its own. It needs an unencrypted, supported
SSH private key that only you can read (mode `600`). It cannot read a key
that has a passphrase (`encrypted SSH keys are not yet supported`). Use an
unencrypted key, for example one that you keep only for murk, or use an age
key.

`circle authorize` also accepts a bare `ssh:`, which means
`~/.ssh/id_ed25519.pub`. It also accepts `github:username`, which gets the
SSH keys of a GitHub account. See [working in teams](/guides/teams/) for the
GitHub flow and how it records key fingerprints.

murk accepts `ssh-ed25519` keys by default. It refuses to authorize an
`ssh-rsa` key unless you pass `--allow-ssh-rsa`, because ed25519 is strongly
recommended (see RUSTSEC-2023-0071). With `github:username`, murk skips RSA
keys with a warning instead, and fails only if every key is RSA.

### Signing behavior differs by key type

`ssh-ed25519` keys are Ed25519 signing keys, so murk signs with them
directly. The recipient string contains the verifying key, so the signature
needs no separate registry entry.

`ssh-rsa` keys cannot sign, because age gives no signing scalar for RSA. A
write with an `ssh-rsa` identity leaves the vault unsigned. A machine whose
own key can sign refuses that vault until a signing teammate reviews it and
runs `murk trust`, which re-signs it. The machine of the `ssh-rsa` user
loads an unsigned vault with a warning, and `murk verify` reports it as a
finding. Hardware-backed identities work the same way. See [hardware
keys](/guides/hardware-keys/#mixed-teams) and the [threat
model](/security/threat-model/) for the full signing rules.

## Related

- [CLI reference: `murk setup-merge-driver`](/reference/cli/#murk-setup-merge-driver)
  and [`murk circle authorize`](/reference/cli/#murk-circle-authorize) for
  all the flags.
- [Recipients & signatures](/concepts/recipients-signatures/) for how the
  recipient list, signatures and the trust pin fit together.
