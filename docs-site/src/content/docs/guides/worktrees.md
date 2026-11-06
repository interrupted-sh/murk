---
title: Git worktrees
description: Use a vault from any worktree of a repo, with no per-checkout setup.
sidebar:
  order: 8
---

A git worktree gives you a second working directory for the same
repository. It is a branch checked out in another place, with no stash and
no second clone. Use one to review a PR while you continue your work, or to
give a task its own checkout.

Secrets are usually the problem. A new worktree contains only the tracked
files, so each gitignored dotenv file is missing. The usual fix is to copy or
symlink `.env` into each new checkout by hand, every time you create a
worktree.

murk does not need that step, because the two parts of a murk setup reach a
worktree in different ways:

- **The vault is committed.** `.murk` is a tracked file, so a new worktree
  checks it out like every other source file. All the secrets are already
  there, encrypted.
- **The key was never in the repository.** It is in `~/.config/murk/keys/`,
  and murk finds it from the vault, also from a worktree.

So when this machine already has a key stored for the vault in another
checkout of the repository, there is nothing to set up.

## What this looks like

Create a worktree and use the vault immediately:

```bash
git worktree add ../murk-feature-x
cd ../murk-feature-x
murk get API_KEY
murk exec -- ./deploy.sh
```

![A fresh worktree has the committed .murk and no .env; murk get works via the sibling checkout, and the same read fails closed in agent context](/demos/worktree.gif)

You do not copy a `.env`, run `murk env` again, or export a key. The same is
true for a worktree that an agent harness creates, a `git worktree add` in a
post-checkout hook, and a bare-repository layout. In that layout *every*
checkout is a linked worktree, and there is no "main" one.

You do not need `murk init` in a worktree. If you run it, it finds the key
stored for the vault in a sibling checkout and uses it again. It never
replaces a stored key.

## Which checkouts count

murk stores your key under a hash of the absolute path of the vault. So a
copy of another person's vault cannot use your key. A worktree puts the same
vault at a different absolute path. So murk also accepts the key stored for
that vault in a sibling checkout of the same repository.

"Sibling" means what git says it means. murk reads git's own worktree
metadata. It never runs a `git` subprocess. It verifies the relationship in
both directions. The repository must record the checkout of the vault. The
checkout whose key murk uses must point back at the same repository. Any
local process can write a `.git` entry, because it is only a file. So a
directory that only *claims* to be a worktree resolves to no key, and murk
fails closed.

In practice, real worktrees of your repository work. Copies of the vault in
other places on disk do not.

## Trust follows the repository, not the checkout

murk also records which signers it trusts for a vault (the [trust
pin](/concepts/recipients-signatures/#trusting-a-signer)). murk keys that
pin on the common git directory of the repository and on the path of the
vault in the checkout. So all worktrees of a repository share one pin. Run
`murk trust` in one worktree, and the others trust the vault too. A new
worktree of a repository that you already trust needs nothing.

The pin keeps the save counter for each branch. So an older branch in
another worktree is not a rollback. murk compares the vault with the highest
counter accepted on the branch that the worktree has checked out. On a
detached HEAD, or on a branch that this machine has never accepted (a PR
branch that you review, for example), there is no counter check. murk then
accepts a signed vault from a trusted signer, whatever its counter.

The set of trusted signers is shared too. Loading a PR branch never adds a
signer to it. See [Trusting the vault on a new
machine](/guides/teams/#trusting-the-vault-on-a-new-machine) for what does.

The pre-0.14 rules apply per branch, also in worktrees. The first 0.14 save
in one worktree does not make your other worktrees refuse their committed
0.13 vaults. Make that first save on the default branch and commit it, then
merge it into the other branches. See [upgrading to
0.14](/guides/teams/#upgrading-to-014) for the full rules and the refusal
messages.

## Agents need their own key

Strict mode and agent context turn off the lookup of a stored key, in a
worktree or not. Each one is on when `MURK_STRICT` or `MURK_AGENT` is set
to any value except empty, `0`, `false`, `no` or `off`, in any letter case.
So a typo or `on` also turns it on. An agent that works in a new worktree
must present its own key, normally a scoped grant, or fail closed.

This is a default, not a sandbox. A process that runs as you can still read
`~/.config/murk/keys/` directly. To contain an agent, run it where it cannot
read that directory.

See [AI agents & MCP](/guides/ai-agents-mcp/) for how to give an agent a
scoped grant to use in its worktree.

## direnv in a worktree

If you use [direnv](/guides/direnv/), the `.envrc` that `murk env` writes
holds no secret material. It only calls `murk export`. So you can safely
commit it, and then it arrives with every checkout, as the vault does. direnv
still needs an explicit opt-in for each directory, so a new worktree needs
one command:

```bash
direnv allow
```

That is the safety model of direnv. It refuses to run an `.envrc` that you
have not told it to trust, and murk cannot skip that step for you. If you
prefer not to run it, `murk exec` needs no shell integration.

## Related

- [direnv integration](/guides/direnv/) for loading secrets on `cd`.
- [Environment variables](/concepts/env-vars/) documents the full key
  resolution order, including when automatic lookup is disabled.
- [Threat model](/security/threat-model/) explains what the stored key is
  bound to, and why a copied vault can't use it.
