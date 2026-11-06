---
title: Key recovery
description: Recover a lost key from your 24-word phrase.
sidebar:
  order: 5
---

`murk init` prints 24 recovery words, a BIP39 mnemonic of the key's 256 bits
of entropy. murk derives your age key directly from those bytes, so the same
words always give the same key.

![Recovering a lost key from the 24-word BIP39 phrase](https://raw.githubusercontent.com/interrupted-sh/murk/demo/recovery.gif)

## Write the words down when you run `murk init`

```bash
murk init
```

murk prints the 24 words once, when it generates the key. **Store them in a
password manager, or keep a physical copy offline**, as your threat model
requires. Anyone who has your 24 words has your key, so protect the phrase
as you protect the key. Do not paste it into chat or commit it. Do not put a
screenshot of it in a note app that syncs to the cloud before you think
about who else can read that account.

## Recovering a lost key

If the key file is gone (a new machine, a wiped disk) and you still have the
24 words, run `murk restore` in the project directory. It asks for the
phrase, with hidden input, and prints the key. It does not save the key. Write
it to a file that only you can read, and point `MURK_KEY_FILE` at that file:

```bash
mkdir -p -m 700 ~/.config/murk
(umask 077 && murk restore > ~/.config/murk/restored.key)
export MURK_KEY_FILE=~/.config/murk/restored.key
```

Add the `export` line to your shell profile. When you run the command in the
project directory, murk warns you if the restored key is not a recipient of
the vault. That warning means the phrase was wrong.

murk derives the key directly from the words, so it is the key that
`murk init` generated. It has the same public key and is still a recipient of
every vault that authorized it. Nothing changes in the vault.

On a new machine, murk refuses the vault the first time, with "not trusted
on this machine yet". The trust pin is local to each machine, so it did not
come back with the key. Review the vault and run `murk trust` once, as
described in [Trusting the vault on a new
machine](/guides/teams/#trusting-the-vault-on-a-new-machine).

## Displaying your phrase again

```bash
murk recover
```

This command prints the 24 words for the key that murk uses for the vault in
the current directory (`MURK_KEY`, `MURK_KEY_FILE`, or the stored key). Use
it if you did not write down the phrase at `murk init`. It works only for age
keys. SSH keys and hardware identities have no phrase, and `murk recover`
fails on them. Anyone who can read your key file can derive the phrase, so
protect both as one secret.

## What recovery does and doesn't cover

Recovery restores *your key*, not the vault. It happens on your machine and
has no connection to git. If you lose the `.murk` file, the phrase does not
help. The file is in your repository, and git keeps its history.

Only age keys have a recovery phrase. SSH keys and hardware-backed identities
(YubiKey, Secure Enclave, FIDO2) have none. See [hardware
keys](/guides/hardware-keys/) for how recovery works for those.

## If your key was stolen

The phrase gives back the same key, so restoring it does not stop the
attacker. Replace the key instead. Only a current recipient can change the
recipient list, so the new key needs either a teammate or the old key.

1. Create the new key on a machine that you know is clean, in a new clone of
   the repository. Do not use a worktree of an old checkout, because
   `murk init` there reuses the key stored for the old checkout. `murk init`
   uses `MURK_KEY` or `MURK_KEY_FILE` before it looks for a stored key. An
   exported `MURK_KEY` makes it reuse the stolen key, and a `MURK_KEY_FILE`
   that points at a deleted file makes it fail. So first make sure that
   neither variable is set:

   ```bash
   unset MURK_KEY MURK_KEY_FILE
   env | grep -c '^MURK_KEY'    # must print 0
   murk init
   ```

   A shell profile, a sourced `.env` or a direnv `.envrc` can set them
   again, so check in the shell where you run `murk init`.

   When no key is stored for this vault, `murk init` creates a new key. It
   prints the public key and the signing-key fingerprint, and writes a
   `.env` with a `MURK_KEY_FILE` line for the new key. If it says "using
   existing key", it did not make a new key. Stop and find where the old key
   came from.

   If the directory already has a `.env` with a key line, `murk init` asks
   before it replaces that line. Answer `y`. In a shell that sources `.env`,
   source it again afterwards to get the new path.
2. Get the new key authorized, and added to each group that the old key was
   in. If you skip the groups, the new key cannot read or rotate the secrets
   of those groups.
   - **A teammate can do it.** Send them the new public key. They run
     `murk circle authorize <new-public-key>` and, for each group,
     `murk group add NAME --member <new-public-key>`. A teammate who is a
     member of that group must add you to it. They commit and push. Then you
     pull, review the vault, and run `murk trust` (see [Trusting the vault on
     a new machine](/guides/teams/#trusting-the-vault-on-a-new-machine)).
     Your new key is now a recipient, so `murk trust` works with it.
   - **No teammate can do it** (for example, you are the only recipient).
     Restore the old key to a file, but do not export it. Skip the `export`
     line of the example above, in this shell and in your shell profile:

     ```bash
     (umask 077 && murk restore > ~/.config/murk/restored.key)
     ```

     Pass the old key only as a prefix on the commands that need it, so that
     every other command uses the new key. If you already exported it, run
     `unset MURK_KEY_FILE` before the next step.

     If this machine has not trusted the vault yet, first review the
     vault and run `MURK_KEY_FILE=~/.config/murk/restored.key murk trust`.
     `murk trust` needs a key that is a recipient, and the new key is not one
     yet. Then run `murk circle authorize <new-public-key>` and
     `murk group add NAME --member <new-public-key>` with the same
     `MURK_KEY_FILE=~/.config/murk/restored.key` prefix. murk refuses to
     revoke the key that it runs as, so run the next step without the
     prefix.
3. With the new key, in a terminal, revoke the old key and enter a new value
   for each secret: `murk circle revoke <old-public-key> --rotate`. See
   [offboarding a teammate](/guides/offboarding/). Commit and push the vault.
4. Tell your teammates your new key's signing-key fingerprint, over a channel
   other than the repository. `murk init` printed it in step 1, and
   `murk trust --print-key` prints it again. After they pull, each of their
   machines refuses the vault once, because your new key signed it for the
   first time. They compare the fingerprint that the refusal and `murk trust`
   show with the one you sent, then run `murk trust`. A CI runner that uses
   `MURK_TRUSTED_SIGNERS` needs your new entry from `murk trust --print-key`
   in place of the old one.
5. If you restored the old key, delete the restored key file. Remove every
   `export` line, `.env` line or `.envrc` line that still points at the old
   key, and open a new shell.
6. Replace the real credentials at their providers. Distribute the new ones,
   then invalidate the old ones (in an urgent case, invalidate them first).

See the [CLI reference](/reference/cli/#murk-restore) for all the options.
