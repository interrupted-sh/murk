---
title: Upgrading from murk 0.15
description: Upgrade every murk component on a machine together, check the behavior changes, and recover when an older component brought a removed member back.
sidebar:
  order: 14
---

murk now keeps a removed member removed, and a revoked agent grant revoked,
on each machine that recorded the removal or the revocation. murk 0.15.2 and
earlier do not check these records. An older component on the same machine
can load a stale revision that lists a removed member, trust that member
again, and encrypt new values to them. So the protection holds in full only
when every murk component on a machine is the new release. The vault format
is unchanged.

## Upgrade steps

Do these steps on each machine that uses murk.

1. List every `murk` on your shell's `PATH`: `which -a murk`.
2. Run `murk --version` for each one.
3. Find the `murk` that git runs as the merge driver. Run
   `git config --get merge.murk.driver`. It names a bare `murk`, which git
   finds through the `PATH` of the program that runs git. For a terminal,
   that is the first result of step 1. For a GUI client or an IDE, look at
   its git settings or its bundled `PATH`.
4. If a GUI client or an IDE runs your merges, find out which `HOME` it
   gives to git. A sandboxed app (a Flatpak or Snap package, or an app from
   an app store) can use its own `HOME`. If it does, do vault merges in a
   terminal, or set the client to use your `HOME`.
5. In each Python environment that uses murk, run `pip show murk-secrets`.
6. In each Node project that uses murk, run
   `npm ls @interrupted/murk-secrets`.
7. Upgrade every component from steps 1 to 6 to the new release.
8. In each checkout of each vault, run `murk verify` once with the new
   release. Do this before any older component runs again. It copies each
   removal record into a file that older components do not touch. Unset
   `MURK_NO_SIGNER_PIN` for this step: when it is set, `murk verify` copies
   nothing.
9. If you re-added a removed member with murk 0.15.2 or earlier, run
   `murk trust --vault P --re-add KEY` again with the new release. A re-add
   made with an older component does not count.

## Behavior changes to check

- **`MURK_NO_SIGNER_PIN` no longer hides an existing pin.** murk 0.15.2
  stopped reading the pin when the variable was set. Now murk reads a pin
  that already exists and applies every rule against it. The variable only
  stops pin writes. A job that set it to ignore a stale pin can now fail
  with that pin's refusals, for example "rolled back". Find each job and
  shell that sets the variable. Remove the stale pin, or run `murk trust`
  after review.
- **A read-only `HOME` can stop saves.** When murk cannot write the pin
  directory and a pin for the vault exists, a save or a keyed merge fails
  and writes nothing. `MURK_NO_SIGNER_PIN` does not help. With no pin, the
  save writes the vault and warns. Give such jobs a writable `HOME`. See
  [Trusting a signer](/concepts/recipients-signatures/#trusting-a-signer).
- **An empty or relative `HOME` counts as no home directory.** murk warns,
  reads and writes no trust pin, and reads no stored key. Set `HOME` to an
  absolute path, or set `MURK_KEY` or `MURK_KEY_FILE` and
  `MURK_TRUSTED_SIGNERS`.
- **A trust pin or key file that a repository tracks is not used.** When
  `HOME` is at or above a checkout (for example `HOME=/workspace` in a
  container), murk asks git whether the repository that holds the trust pin
  directory or a key directory lists a file there. If it does, or if git
  fails, murk warns and uses no trust pin, or no stored key. murk checks
  only that repository's index, not git history or files copied in by
  other means. Set `HOME` to a directory outside every repository.
- **`MURK_EXPECTED_VAULT` set but empty is an error.** A missing CI secret
  expands to an empty string, so murk fails closed. To turn the check off,
  unset the variable.
- **A member's first write cannot be a merge.** A teammate who joined with
  an age key makes one ordinary save first (for example `murk describe`),
  commits it, then merges.
- **Saves in many worktrees at once can stop.** A save that loses the race
  for the shared pin 16 times stops with "nothing was written … Running the
  command again is safe." Run the command again.
- **A vault that lists a removed member can be refused in a shallow or
  partial clone.** On a branch this machine accepted before, murk reads
  the vault file's git history to see whether the branch merged the
  removal. When it cannot decide, it refuses and says why, with the fix for
  that case: `git fetch --unshallow` for a shallow clone whose boundary
  cuts the history it reads; `git fetch --refetch --no-filter <remote>`,
  then `git config --unset remote.<remote>.promisor` and
  `git config --unset remote.<remote>.partialclonefilter`, for a blobless
  clone missing old vault files. A history over 10000 vault revisions, a
  rewritten history, or a vault revision over 8 MiB or that does not parse
  cannot be fixed by fetching: review the branch, then run
  `murk trust --vault P --re-add KEY`. That trusts the member again on
  every branch on this machine, so fix the history first where you can. CI
  runners that use `MURK_TRUSTED_SIGNERS` keep no removal records and are
  not affected.

## When murk says the pin no longer records a removal

murk prints this warning when an older component erased a removal record
that the new release had copied:

```text
warn the trust pin for P no longer records K as removed, but the copy of this release does.
```

murk keeps K removed. But values that the older component wrote while K was
listed are readable by K. Do these steps:

1. Find the older component, as in steps 1 to 6 of the upgrade steps.
   Upgrade it.
2. If you re-added K on purpose with the older component, run
   `murk trust --vault P --re-add K` with the new release. Stop here.
3. Find the last commit whose vault file does not list K and that this
   machine accepted before the problem. Run `git log --oneline -- P`.
4. For each candidate commit C, run `murk diff C` and look at the
   recipients.
5. Restore that vault file: `git checkout C -- P`.
6. Run `murk trust --vault P`. Review what murk shows. murk can say that the
   file is rolled back, because the older component raised this machine's
   mark. Accept the file.
7. Make again, with murk, each change after commit C that you want to keep.
8. Rotate every value that was in a vault file that the older component
   saved or merged while K was listed. K can read those values.
9. Commit the vault file.
10. Tell each teammate whose machine loaded the replayed file to run
    `murk trust --vault P` on the restored file.

If you cannot restore a vault file (for example, too much work came after
commit C), do these steps instead of steps 3 to 7:

1. Run `murk trust --vault P --re-add K`.
2. Run `murk circle revoke K`.
3. Do steps 8 and 9.

Use this way only as the last choice. `--re-add` accepts the replayed
revision first, with its signers, groups and values.

The [threat model](/security/threat-model/#vault-signatures) (limit 10)
lists what the removal record covers and what it does not.
