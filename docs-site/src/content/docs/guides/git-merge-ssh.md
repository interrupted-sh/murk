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

Setup changes nothing when another merge driver is in place. This is the
case when git config already sets `merge.murk.driver` to a command that murk
did not write. It is also the case when a line in any attributes file git
reads (each `.gitattributes`, `.git/info/attributes`, `core.attributesFile`
or the system file) gives files that murk's lines would cover another
`merge` setting. A line such as `*.prod merge=custom` counts, because it
covers a `.murk.prod` vault. A line such as `*.png binary` does not stop
setup. The message names each line with its file and line number. Setup
changes git config before `.gitattributes`. If git config fails,
`.gitattributes` stays unchanged.

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
merges with no setup.

The driver never merges a vault as text. It merges as vaults only when murk
reads all three sides as vaults. A file that matches the pattern but cannot
be a vault is merged as text, with conflict markers where both sides changed
the same lines. Examples are `.murk.bak` holding notes, or a `.murk.json`
without vault keys. A file could be a vault when:

- it is valid JSON with a top-level `recipients`, `secrets`, `meta`,
  `vault_name` or `vault_id` key,
- it is not valid JSON and starts with `{`, after a byte-order mark and
  whitespace, or
- it is not valid JSON and uses one of those names as a JSON key
  (`"secrets":`).

The driver reads a UTF-16 file as its text. Notes that only quote a name
(`the "secrets" field`) cannot be a vault.

When a side is or could be a vault but murk cannot read every side, the
driver stops. Examples are a vault re-saved with a byte-order mark, as UTF-16
or with a stray line, and a vault overwritten on one branch. The driver puts
ours and theirs in the file between conflict markers and names each side it
cannot read. When a side is a vault that murk reads, keep one side with `git
checkout --ours` or `--theirs`, check it with `murk verify`, and redo the
other side's changes. When no side reads as a vault, the message says that
the file may be a vault. If it is not a vault, edit the file to merge it by
hand, then `git add` it.

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
- the same vault id, and no second vault file with that id in the checkout,
- the vault id and minimum in `MURK_EXPECTED_VAULT`, when it's set,
- for a side that changed the vault, a save counter above the common
  ancestor's.

It also authenticates the **common ancestor**. The ancestor decides what
counts as a change and which group memberships the sides are judged
against. Without that check, a parent that an attacker chose (a
cherry-pick, a `git apply --3way`) could shape the merge.

The ancestor is an authority on what changed only when your key can read
it, it is signed, and its signer is one this machine trusts now (and has
not recorded as removed). Then the merge is three-way. Otherwise the merge is
two-way: every difference between ours and theirs is a conflict, the driver
keeps ours, and it signs nothing. So an unsigned or forged ancestor, or one
that a removed member signed, can't set values back. The one exception is a
merge where both sides are still 0.13 vaults. That merge is three-way over
the ancestor as it is.

A side that 0.13 wrote is judged like a load of it on the branch that you
merge into. For these rules, see step 7 of [upgrading to
0.14](/guides/teams/#upgrading-to-014). Make the first 0.14 save on the
default branch before you merge branches that still have 0.13 vaults.

### The merge result

If the ancestor or a side fails its checks, the driver writes nothing. The
working file stays ours, byte for byte, and git reports a conflict. The
message names the input that failed, for example "theirs failed its
authenticity check: …". Nothing is signed, and the trust pin doesn't change.

Otherwise, the driver writes the merged vault with a new MAC and signs it
with your key. It stays unsigned only when your key can't sign. The driver
numbers it above both sides and above every vault that this machine has
accepted. It writes no trust pin: your next load records the result.

Before it signs, the driver checks that this machine would load the merged
vault. If it wouldn't, the driver writes nothing and says "this machine would
refuse the merged vault, so murk does not sign it", with the reason.

Without a key, the driver can't verify or sign. So it refuses any merge
that needs new integrity data. It exits 1, and git reports a conflict. Abort
the merge (`git merge --abort`) and run it again with your key available.

The merged vault has your signature, so it must pass the group rule that a
load applies. A member of a group must sign each change to its membership.
When the merge changes a group's membership and your key isn't in that
group, the result is a conflict that says so. A member of the group must do
that merge. A merge that would leave a group that holds values with no
member who is a recipient is a conflict too. Add a member to the group, or
clear its values with `murk rm KEY --group GROUP`, then merge again.

### Your first write can't be a merge

When you join a vault with an age key, the other machines don't know your
signing key yet. Your first signed write shows it to them (see [A new
teammate's first write](/concepts/recipients-signatures/#a-new-teammates-first-write)).
Your own machine must have confirmed your signing key too, before the
driver signs a merge with it. Until then, a merge stops with "this machine
would refuse the merged vault" and keeps ours.

Make one ordinary save first, for example `murk add` or `murk describe`, and
commit it. Then merge.

### Removed members and revoked grants

When your machine recorded that someone was removed from the vault, a merge
side that lists them again is refused, at any save counter, and so is a
merged result that lists them. A side that a removed member signed is
refused too. To take a deliberate re-add:

1. Abort the merge: `git merge --abort`.
2. Review the change with `murk diff` against the other branch's vault file.
3. Do one of these:
   - Merge again. Run `git checkout --theirs -- .murk`. Run
     `murk trust --vault .murk --re-add KEY`. Make this branch's own vault
     changes again with murk. Commit.
   - On this branch, run `murk circle authorize KEY` and commit. Merge again.
     Both sides now add the key, so the recipient merge doesn't conflict on
     it.

A merged result that holds a grant for an agent key that your machine holds
as revoked, or lists that key as a recipient, is a conflict too. Keep the
side that revoked it.

### Cherry-pick and revert

A cherry-pick of a vault commit runs the driver with that commit's parent as
the common ancestor.

- When the parent is genuine and a signer this machine trusts now signed it,
  the change applies as it does in git, and your key signs the result. That
  includes a change that this branch already has or later undid: the change
  comes back.
- When the parent is unsigned, forged, unreadable or signed by a key outside
  the trusted set, the cherry-pick conflicts on every difference and keeps
  this branch's values.
- When the commit's vault file is older than its parent's (a revert commit,
  or a restored file), murk refuses it as rolled back and leaves this
  branch's vault file as it was.

`git revert` of a vault commit that a later vault commit follows stops with a
conflict, and leaves the vault file as it was. To revert the newest vault
commit, git writes the older file without a merge. murk then refuses it as
rolled back until you run `murk trust` (see [Rollback and deliberate
reverts](/concepts/recipients-signatures/#rollback-and-deliberate-reverts)).

Before you push a cherry-pick, check its vault change with `murk diff`
(below).

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
It replaces only lines that murk wrote. If `merge.murk.driver` runs your own
command, for example a wrapper script, setup changes nothing and tells you
to remove the line first. Until you run setup again, the driver warns that
its configuration is old. Its messages then say "the file git is merging"
instead of a file name, because git does not pass the name.

### When the driver stops

Some refusals leave the file as ours, without conflict markers: no key, a
save counter at its limit, an agent grant key, an ancestor or side that
fails its checks, a result this machine would refuse, or a failed write of
the merged vault. The message says that nothing was written and theirs was
not merged. Do not commit the file as it is, because that drops their
changes. Set your key and run the merge again, or keep one side and redo the
other side's changes with murk.

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
- the merge changes a group's membership and your key is not in that group,
- the merge leaves a group that holds values with no member who is a
  recipient,
- a side or the result lists a member this machine recorded as removed, or
  holds an agent grant this machine holds as revoked.

When the common ancestor is not an authority (above), the driver is
stricter. Every difference between ours and theirs conflicts, and the
driver keeps ours.

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
