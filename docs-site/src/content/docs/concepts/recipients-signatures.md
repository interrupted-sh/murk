---
title: Recipients & signatures
description: How recipients are authorized, how the MAC and signature protect the vault, and how a machine decides to trust a signer.
sidebar:
  order: 3
---

:::caution[Experimental]
The trust pin, `murk trust` and the signed format 0.14 writes are new and experimental: their rules and file layout may still change in a minor release. Keys that cannot sign (hardware and `ssh-rsa`) leave a vault unsigned, and an age signer's key is trusted only once `murk trust` has confirmed it. See [Feature status](/reference/feature-status/).
:::

Three mechanisms protect a `.murk` file. The **recipient list** controls who can decrypt it. The **integrity MAC and signature** detect tampering. A **trust check** on each machine decides whether that machine accepts the signer.

## Adding and removing recipients

`murk circle authorize PUBKEY --name NAME` adds a recipient and re-encrypts every shared secret so the new key can read it. PUBKEY can be an `age1...` key, an `ssh-ed25519 ...` key, `ssh:PATH` (a public key file) or `github:USERNAME`. `ssh:` alone reads `~/.ssh/id_ed25519.pub`. Pass `--group NAME` to add the recipient to a group in the same step.

murk refuses `ssh-rsa` keys unless you pass `--allow-ssh-rsa`. For `github:USERNAME`, murk skips a user's `ssh-rsa` keys with a warning instead. murk fetches that user's keys from `https://github.com/USERNAME.keys` and records their fingerprints in `github_pins` in the encrypted meta. If the account's keys change later, the next `authorize github:USERNAME` stops and shows what was added or removed. Pass `--force` to accept the change.

Keys are compared by their canonical spelling. That is lowercase for `age1...` and plugin keys, and `type blob` without the comment for SSH keys. `authorize` refuses a second spelling of a key that is already a recipient, and it stores age keys in lowercase. An `age1...` key whose encoding isn't canonical names the same key under another string, so murk refuses it. That happens when the high bit of its 32-byte value is set, or when the value is out of range.

`revoke` removes every spelling of the key. Otherwise an alias spelling of a revoked key could outlive the revocation. A 3.x vault header that lists one key twice fails validation. A 2.x header written by murk 0.13 that does so still loads, and the next save lists the key once.

murk stores display names only inside the encrypted `meta` blob, never in the plaintext `recipients` list. The pubkey-to-person mapping is therefore protected, even though the existence of a pubkey isn't.

`murk circle revoke RECIPIENT [--rotate]` removes a recipient's pubkey, re-encrypts shared secrets without it, and drops that recipient's private entries. You can't revoke yourself. Ask another recipient to run `murk circle revoke <you>`.

**Revocation doesn't erase git history.** The revoked recipient can still decrypt any vault version they had access to. Rotation is the only way to close the exposure. With `--rotate`, or if you answer yes at the prompt, murk asks you for a new value for each shared or group value the recipient could read. It keeps each value in its tier. If you decline, murk marks those keys with `revoked_at`. `murk doctor` and `murk rotate --list` report them until their values change.

## The integrity MAC

Every save computes a BLAKE3 keyed hash over the vault's key names, per-key ciphertexts, recipient list, schema, group and grant definitions, policy, and any pending-rotation markers. murk stores the digest as `mac` in the encrypted meta, next to its key (`mac_key`). On load, murk recomputes the hash and refuses the vault if it differs. That catches accidental corruption and naive tampering, meaning an edit that doesn't recompute the MAC.

It is **not** a defense against a malicious recipient or anyone else with write access to the repo. age only needs recipients' *public* keys (which sit in the plaintext header) to re-encrypt content. So a repo-writer can mint a fresh `mac_key`, recompute a valid MAC over tampered content, and re-encrypt `meta` to match. Authorship integrity comes from the signature below, not the MAC.

## Signatures

murk signs the vault with Ed25519 on every save where the writer holds a signing-capable identity. The MAC can't say who wrote a vault, because anyone who can write the file can recompute it. A signature can.

Two identity types can sign:

- **age keys** sign with plain Ed25519, using a key derived from the age secret through a BLAKE3 KDF, so the BIP39 phrase still recovers it. Decryption and signing use separate keys. The verifying key can't be computed from the `age1...` recipient. So the signer publishes it in the vault's signer registry on every save, and murk checks the signature against that entry. Because a vault can't vouch for its own registry, a machine believes an entry only after it has been confirmed (see [A new teammate's first write](#a-new-teammates-first-write)).
- **ssh-ed25519 keys** sign directly, since the key is already Ed25519. The verifying key is the one in the recipient string, so there is no registry entry to confirm.

`ssh-rsa` keys and hardware/plugin identities can't sign, so a save made with one of them is written unsigned. See [Hardware-backed keys](/guides/hardware-keys/) for what a mixed team does about that.

The signature covers the vault id, the save counter, the recipients, the schema, every secret, the policy, groups, grants and GitHub pins. A present-but-invalid signature fails the load as tampering.

## Trusting a signer

A valid signature only proves that *some* key listed as a recipient signed the file, and the file chooses its own recipients. Someone with write access to the repo could list their own key and sign. So murk also asks whether *this machine* trusts the signer, and anchors that answer in state the repo can't write.

That state is the **trust pin**, a file under `~/.config/murk/signer-pins/` (mode `0600`, one per repository and vault path, so every git worktree of a repo shares it). It records:

- the keys allowed to sign the next version: the non-grant recipients of the last vault this machine accepted
- the vault's id, and the highest save counter accepted, overall and per git branch
- group membership as last accepted
- every agent-grant key seen, which never counts as a signer
- the verifying key of each age signer this machine has confirmed, which a different key can never replace

Only an accepted load, `murk trust`, or this machine's own `init` and saves write the pin. Nothing from an unverified vault ever does. A pin that can't be parsed is an error, not an empty pin. A pin that can't be written during a normal load (a read-only home, say) only prints a warning: the vault is trusted either way, but murk can't remember it.

Every keyed load checks the vault against it, for the CLI, the MCP server and the Python and Node bindings alike. Write commands load through the same check, so a write never re-signs content the machine doesn't trust. murk refuses the vault when:

- **It's unsigned and your key could have signed it.** murk refuses an unsigned vault when you load it with an `age` or `ssh-ed25519` key. A key that can't sign (`ssh-rsa`, hardware) loads it with a warning, because a team on those keys relies on signed git commits. Setting `MURK_TRUSTED_SIGNERS` ends that allowance. Review the change, then run `murk trust` with a key that can sign.
- **It was signed when this machine last accepted it and is now unsigned.** murk refuses it for every key. Someone stripped the signature, or a merge or a hardware-key write left it unsigned. Review the change, then run `murk trust`.
- **The signer isn't trusted here.** With no pin yet, the message is "not trusted on this machine yet". Otherwise the signer isn't among the keys the pin trusts. Review who signed it and what changed, then run `murk trust`. A CI runner has no pin, so it uses [`MURK_TRUSTED_SIGNERS`](#ci) instead.
- **An age signer's signing key isn't confirmed here yet.** The signer is a trusted recipient, but this machine hasn't seen their signing key before. That is typically a newly authorized teammate's first signed write. murk refuses it once and shows the key's fingerprint. Check the fingerprint with the teammate, then run `murk trust`. See [A new teammate's first write](#a-new-teammates-first-write).
- **An agent grant signed it.** Grants are read-only, so a grant key never signs. A former grant key that is back in the recipients without its grant is refused the same way. `murk trust` won't accept either. Restore the file from git.
- **It's a different vault.** The vault id doesn't match the pinned one, as if another vault's file had been copied over it. Restore the file from git. If you replaced the vault on purpose, review it and run `murk trust`. `murk trust` refuses only another vault's unsigned 0.13 file, because nothing signed shows whose file it is. See [Vault ids and upgrading from 0.13](#vault-ids-and-upgrading-from-013).
- **It's signed by a removed key, or lists one again.** This machine recorded that an accepted vault removed the key. The vault is signed by that key, or it lists the key at or below the counter where it was removed. Update to the vault that removed the key: pull it, or merge the removal into this branch. To bring the key back on purpose, run `murk trust --re-add KEY`. The rules for each case follow the list.
- **It rolled back.** Its save counter is below the highest accepted on the checked-out branch, so an older revision may have been replayed. Switch back to the newer revision. To revert on purpose, see [Rollback and deliberate reverts](#rollback-and-deliberate-reverts).
- **It forked.** Its save counter equals one this machine already accepted on the checked-out branch, but the file is a different vault. The branch was rewritten, or another save with the same counter replaced the accepted one. Merge the two saves with the murk merge driver. If you meant to replace the accepted vault, review it and run `murk trust`.
- **Its counter jumped too far.** Its save counter is more than 1,000,000 above the highest this machine has accepted for the vault. A signer may be running the counter up toward its limit. Review the change, then run `murk trust` to accept the jump.
- **It's in the pre-0.14 format on a branch that was already upgraded.** A 0.13 signature has no counter, so on such a branch the file can only be an older revision. If it is, switch back to the newer revision. To accept this copy, run `murk trust`. See [Vault ids and upgrading from 0.13](#vault-ids-and-upgrading-from-013) for which branches refuse it.
- **A group changed without a member's signature.** A change to a group's membership must be signed by a member of that group as pinned. Removing someone who left the vault entirely is exempt, since `circle revoke` does that. `murk group rm NAME` likewise needs you to be a member of the group. Review the change, then run `murk trust`.
- **A pinned signer shows a different signing key.** An age key's verifying key is derived from its secret, so a second key for the same recipient is a forgery. murk refuses it, and `murk trust` won't accept it. Restore the file from git.

**Removed keys.** When this machine accepts a vault that removes a signer, it records the removal, its counter and the commit checked out. From then on it refuses any vault that the removed key signs, on every branch.

The one exception is the key's own history. The vault must be at the recorded commit or an older one, exactly as committed, on a branch the removal hasn't reached, and numbered at or below the removal. Such a vault loads but never makes the key trusted again. On a branch this machine never accepted, it is read-only. With no recorded commit there is no exception.

A vault that still lists the removed key is a separate case. If it is from at or before the removal, murk refuses it as rolled back wherever the removal has reached. That covers the branch it was made on, branches it was merged or pulled into, a detached HEAD, outside git, and a branch this machine never accepted. On that last kind of branch, the vault loads in one case. The checked-out commit is the one where the removal was recorded, or an ancestor of it, and the vault is exactly as committed there.

A branch this machine accepted before the removal reached it keeps loading and saving vaults that list the key until the removal is merged there. `murk trust` accepts a vault that murk refused for a removed key only when you name the key with `--re-add KEY`.

Each refusal says what happened and points you at the review step. It shows the signer's key next to its name, because whoever wrote the file chose the name. It also lists the recipient changes since the pin.

### `murk trust`

`murk trust` is that step. Review `git log -p -- .murk` and `murk diff ORIG_HEAD` first. A plain `murk diff` compares with `HEAD`, so after a pull it shows nothing. git sets `ORIG_HEAD` to your commit from before the pull or merge, also when it fast-forwards. So run `murk diff ORIG_HEAD` right after the pull, before another pull, merge, rebase or reset moves it.

A fresh clone has no earlier commit, and a newly authorized teammate's key can't open the revisions from before they were authorized. In that case, rely on the log and on what `murk trust` prints. `murk diff` runs on a vault this machine refuses, warns that it isn't trusted, and lists recipient and signer changes next to the value changes.

Then run `murk trust`. It prints the vault id, the counter (and the highest one trusted here), the signer's name and full key, the signer's signing-key fingerprint, and every recipient. A recipient is marked `+` when it's new since this machine last trusted the vault. The fingerprint is marked "trust on first use" when this machine hasn't confirmed that key before. Grant keys are labelled "agent grant, never a signer", and trusted keys that are gone are marked `-`.

It then asks. `--yes` skips the question for scripts. Without a terminal and without `--yes`, it refuses. Accepting confirms only the signer's signing key. The other recipients' signing keys in that vault are taken on the signer's word, so if that signer is removed later, they need `murk trust` again.

What accepting does depends on the vault:

- An unsigned or stripped vault, or a vault in the pre-0.14 format that murk refused, with a key that can sign: murk re-signs it with your key. That is a save, so commit the result. For a pre-0.14 vault, the save writes a 3.0 vault and gives the branch its 0.14 mark. A key that can't sign can't accept a pre-0.14 vault that murk refused.
- A vault in the pre-0.14 format that loads but is read-only: murk says so, asks, and records this exact copy for the branch. It re-signs nothing. The next write upgrades the vault and gives the branch its 0.14 mark. Any change to the file makes it a different copy, read-only again. On a detached HEAD there is no branch to record the copy on, so `murk trust` refuses. Check out a branch first.
- A stripped vault, with a key that can't sign: murk forgets that a signed version was seen, and the vault loads with the warning.
- Anything else: murk pins the vault as shown. For a rollback, a fork or another vault, the counter resets.

For both pre-0.14 cases, see [Vault ids and upgrading from 0.13](#vault-ids-and-upgrading-from-013) for what murk records.

You need it once per vault on each machine: a fresh clone, a new laptop, and the first run after [upgrading to 0.14](/guides/teams/#upgrading-to-014). After that, you need it again when murk refuses a vault and you've reviewed why, including an age-key teammate's first signed write (next section). The first run on a new machine is a human decision. Check the signer's fingerprint with the person who owns the key, over a channel other than the repo.

`murk trust --print-key` shows your own key instead of reviewing a vault. It prints your `MURK_TRUSTED_SIGNERS` entry to stdout and your signing-key fingerprint to stderr. It fails for a key that can't sign. The fingerprint is `SHA256:` and the unpadded base64 of the SHA-256 of the 32-byte verifying key, the form `ssh-keygen -l` prints.

### A new teammate's first write

When someone is authorized with an age key, their signing key isn't in any vault yet. Their first signed write adds it to the registry, and every other machine refuses that write once: "a trusted recipient whose signing key this machine has not confirmed yet". The refusal shows the key's fingerprint.

1. The teammate runs `murk trust --print-key` to see their own fingerprint. `murk init` prints it too, next to the public key, while they're not yet authorized.
2. Everyone else compares it with the fingerprint murk showed them, over a channel other than the repo, and runs `murk trust`.

This is trust on first use. The key arrives in a vault, so the fingerprint comparison is what stops someone with write access from registering their own key under a teammate's recipient. Once confirmed, the key is pinned and never replaced.

Confirmation spreads. A machine that confirmed the key writes a vault whose signed registry carries it. A machine that loads that vault learns the key without another prompt, because the entry comes from a vault signed by a signer it already trusts. It holds that key on the signer's word. If the signer is removed, the key needs `murk trust` again. `ssh-ed25519` teammates, including those added with `murk circle authorize github:user`, need none of this, because their recipient string is their verifying key.

### CI

A CI runner has no pin. Set `MURK_TRUSTED_SIGNERS` to the people who write the vault, separated by commas or newlines. An age signer is `age1...:<verifying key>`. An `ssh-ed25519` signer is its public key line. Each signer runs `murk trust --print-key` to get their entry.

Set it only from a CI secret or the real process environment, never from a file in the repository or a `.env` that an app's dotenv loader reads, because it decides which signers this machine trusts. The CLI never loads `.env` into its environment, so it never takes the variable from there. The Python and Node bindings read the process environment. A `load_dotenv()` or `dotenv.config()` call before you load the vault therefore lets a repo `.env` choose the trust anchor.

When set, the variable replaces the pin's trusted set. An age signer's signature has to verify under the verifying key in its entry. Grant keys listed there still never count. An entry in neither form, including a bare `age1...` key, is an error. Setting it also makes an unsigned vault an error for every key, including keys that can't sign.

A trust decision made through `MURK_TRUSTED_SIGNERS` doesn't widen the local pin, so the variable never adds trust that would outlive it. A runner without a pin can't detect rollback. See [CI/CD](/guides/cicd/).

`MURK_NO_SIGNER_PIN` stops murk reading or writing the pin. It doesn't switch the check off: without `MURK_TRUSTED_SIGNERS`, every signed vault is then refused, and rollback and stripped-signature detection are off. A machine with no home directory behaves the same way.

### Rollback and deliberate reverts

Every save writes a counter one above the highest this machine has seen, and a keyed merge writes one above both sides. The pin keeps the highest counter per git branch, so a branch that went backwards is refused. Switching to an older branch has no counter check, because that branch has its own mark. On a detached HEAD, or a branch this machine has never accepted, there is no counter check.

Loading a vault that gets no counter check never adds trust. Only `murk trust`, your own saves, and a vault newer than everything this machine accepted, on a branch it accepted before (or outside git), change the trusted signers. Loading an older branch, a detached HEAD or an unmerged pull request reads it as history. So reviewing a pull request that authorizes someone doesn't make this machine trust them.

To revert a branch on purpose:

1. Restore the older file.
2. Run `murk trust`. It shows the counter going back.
3. Make any write. murk numbers the write above everything this machine accepted, so teammates accept it as newer.
4. Commit that write together with the restored file. Otherwise your teammates' machines refuse the revert as rolled back.

A `git revert` of a commit that changed the vault restores an older file too. murk refuses it as rolled back until you run `murk trust`. Then follow steps 3 and 4.

One case doesn't recover this way: a vault at the largest counter murk accepts, 2^53 − 1. `murk trust` can still accept it. After that, murk refuses every save on that machine, because the save would go past the limit and every machine would refuse the vault it wrote.

Outside git, restore an earlier vault and run `murk trust`. In a git checkout, `murk trust` lowers only the branch's counter, and the machine numbers every save from its overall counter in the pin. So a revert doesn't help. Instead:

1. Delete this vault's pin file. The refusal names it, and it is in `~/.config/murk/signer-pins/`.
2. Restore an earlier vault from git.
3. Run `murk trust`.

### Vault ids and upgrading from 0.13

A new vault gets a random id at `murk init`. A vault written by 0.13 has none. The first 0.14 save derives one from the vault's `created` timestamp and name, which every copy shares. Teammates who upgrade separately therefore agree on the id and don't refuse each other's saves as another vault.

murk refuses a 0.13 vault only on a branch where this machine has accepted or saved a 0.14 vault. All worktrees of a repository share one pin, but the marks are per branch. A 0.14 save on one branch doesn't make the others refuse their committed 0.13 vaults. On those branches the vault loads as history, which never adds trust. Outside git there is one mark for the vault, so the refusal applies once this machine has seen it saved by 0.14.

A branch gets its 0.14 mark only when this machine saves there. A load never gives it one, and merging the upgrade doesn't either. Until this machine saves on that branch (a merge alone does not count), an older 0.13 revision checked out there still loads, read-only.

Once this machine has seen a 0.14 vault, a 0.13 vault that loads as history is read-only. murk refuses every write over it (every save, and a merge by the merge driver), and nothing is written. The message says the vault "is in the pre-0.14 format on a branch that hasn't taken the upgrade, and this machine hasn't accepted this copy, so it is read-only here".

To go on, review the file (`git log -p -- .murk`, `murk diff`) and run `murk trust --vault .murk` to accept that copy. Or merge the upgrade from the default branch. On a detached HEAD, check out a branch first. A machine that ran murk 0.14.0 has no accepted copies, so its first write over a 0.13 file needs `murk trust` too.

So upgrade the default branch first and merge it into the other branches. See [upgrading to 0.14](/guides/teams/#upgrading-to-014).

1. On the default branch, run `murk trust` once.
2. Make the first 0.14 save there.
3. Merge the default branch into the other branches.

To write on a branch before you merge the upgrade, run `murk trust` there first. The next write upgrades the vault and gives the branch its mark.

When you accept a 0.13 copy, murk records only that copy's fingerprint. The trusted signers, the groups and the recorded removals stay as they are, so a member who joined after the copy was written is never recorded as removed. The save that follows is an own save. It changes the trusted signers only by what it adds or removes itself, and it pins the groups of the file it writes, which are the copy's. Narrower groups only make the group rule stricter. The save encrypts to the copy's recipients, so review the copy first.

A 0.13 file has no vault id, so murk compares the id its first 0.14 save would derive from `created` and the vault name. Neither field is covered by the 0.13 signature or the MAC. A member of another vault, or two vaults created in the same second under the same name, can therefore make that vault's 0.13 file derive this vault's id. On a branch with no 0.14 mark murk then reads its values as this vault's. That is why writes over such a file wait for `murk trust`. You review the copy first, and murk records it.

Two vaults copied from one 0.13 vault (`cp .murk staging.murk`, say) share an id, because 0.14 derives it from what the copies share. For them, only the counter check catches a swapped file, and only when its counter isn't higher. Once the pin has an id, the same comparison applies to another vault's unsigned or stripped 0.13 file. murk refuses it as a different vault, and `murk trust` won't accept it, so murk never re-signs it under this vault's id. Restore the file from git.

A teammate who stays on 0.13 can't load a vault that 0.14 has saved. A vault they write from 0.13 follows the same rule: machines that have accepted a 0.14 vault refuse it.

## What this doesn't cover

A trusted signer can still change values or add recipients. That's authorized by design, and a compromised trusted key is a compromised signer. A rollback onto a branch or detached HEAD this machine never recorded isn't detected, for example when you review a PR branch, though loading it never adds trust.

The commands that only read the plaintext header (`ls`, `info`, `circle`, `skeleton`, `agent plan`, `policy show`, `doctor`) don't run the check. Run without a key, each prints a `warn unverified header` line on stderr, so what they show isn't mistaken for checked data. `rotate --list` is the exception. With a key, it verifies the vault before reporting and fails on a header that was edited. Without a key, it prints the same warning, and `MURK_STRICT` refuses the result.

## Where this fits

The [threat model](/security/threat-model/) covers the full malicious-recipient boundary and what signatures do and don't close. [Vault format](/concepts/vault-format/) shows where the MAC, signature and trust fields live on disk. [Hardware-backed keys](/guides/hardware-keys/) covers plugin identities, which authorize and decrypt normally but can't sign. [Git merge driver & SSH](/guides/git-merge-ssh/) covers `ssh-ed25519` signing and how the merge driver verifies and signs.
