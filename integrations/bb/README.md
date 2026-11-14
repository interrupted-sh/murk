# bb plugin for murk

> **Experimental.** This plugin is niche and may move out of this repository. It builds on murk's agent grants, which are experimental too. See [Feature status](https://murk.interrupted.sh/reference/feature-status/).

Grant-scoped murk secrets for [bb](https://getbb.app) agent threads. Agents see key names and tags; values arrive as short-lived 0600 dotenv files unless a grant explicitly allows reveal.

## Set the operator key

`bb murk grant mint` and `bb murk grant revoke` run murk on the bb server with your key: they add or remove a grant in the vault and sign the result. The plugin picks the key in this order:

1. The plugin's **Operator key file** setting (`keyFile`), if you set it. Use the absolute path of your murk key file: the `MURK_KEY_FILE` path that `murk init` wrote to the vault's `.env`. The plugin passes it only to the murk commands it runs on the bb server, never to an agent thread's environment.
2. `MURK_KEY_FILE` or `MURK_KEY` from the bb server's own environment.
3. If neither is set, murk finds the key it stored for the vault in `~/.config/murk/keys`, as it does in your terminal.

The operator key must be a full recipient key, not an agent grant key. As a guard against the common mistake, the plugin refuses mint and revoke when the key file it would use has grant key lines. That is not a guarantee: murk also accepts a bare grant key without them. Set `keyFile` when the bb server cannot find your key by itself, for example when the key is not in `~/.config/murk/keys`. The plugin never reads the vault's `.env` itself: that file sits in the thread's worktree, where an agent can change it.

## Only you grant access

`bb murk grant mint` and `bb murk grant revoke` refuse a call that comes from a bb thread, so an agent that runs them gets a refusal instead of a new grant. Run both commands in your own terminal, outside bb threads. To limit a grant to one thread, pass `--thread <threadId>`. `bb murk grant list` works from anywhere: it shows no values.

The agent skill tells agents never to run `bb murk grant`. When an agent needs a key, it asks you and gives you the command.

This is a guardrail, not a sandbox. The bb CLI tells the plugin which thread called it from the `BB_THREAD_ID` variable of the calling shell. A process that clears that variable, or calls the bb server directly, looks like your terminal. An agent runs as your OS user, so it can also read your key file directly. To keep an agent away from your key, run the agent as another OS user or in a container.

The plugin's settings are not secret from agents. A thread can run `bb plugin config murk`, which prints the settings, the `keyFile` path included. The path is not the key, but an agent that runs as your user can read the file it names. It is not ruled out that a thread can also change the settings, so check them if an agent had access to the bb CLI.

Tool results that reach an agent (`murk_get`, `murk_plan`) name no key file path: when murk or the binding names one in an error, for example in its hint for a key file that others can read, the plugin shows `<key file>` instead. That covers the `keyFile` setting, the bb server's `MURK_KEY_FILE`, murk's key store and the plugin's grant keys. Your own `bb murk grant` output keeps the full paths, which a thread cannot see because the plugin refuses those commands from a thread.

A revoke succeeds only when murk removes the grant from the vault. Anything else leaves the grant `REVOKE-PENDING` in `bb murk grant list` and exits 1: a stale `keyFile`, a vault that does not load, a vault file that is gone, and also murk reporting that the grant is not in the vault. The plugin still deletes the grant's key file, so threads no longer get the grant from the plugin, but any copy of its key can still read the vault while the grant is in it. The message says what murk reported. Fix the cause and run `bb murk grant revoke` again; the message also gives the `murk agent revoke` command that does the same in your terminal.

`bb murk grant revoke --forget <grantId>` clears a grant in the plugin only, for a grant no revoke can reach: its vault file is gone for good (bb deleted the worktree), or you removed the grant from the vault yourself. It works for a `REVOKE-PENDING` grant or one whose vault file is gone, changes no vault, and leaves the grant in any copy of that vault (another clone, a branch, git history): revoke it there with `murk agent revoke`.

## The plugin and `murk mcp`

Both give an agent grant-scoped access to a murk vault. They differ in who holds the grant key:

- **This plugin.** You mint grants with `bb murk grant mint`. The bb server keeps each grant key in the plugin's data directory. `murk_get` writes the values to a 0600 dotenv file in the thread's worktree, one file per thread. Agent threads never hold a key.
- **`murk mcp`.** `murk agent connect` mints one grant and writes an MCP entry to the editor's config. The editor starts `murk mcp` as a stdio server with that grant key in `MURK_KEY_FILE`. The agent reads values through that server's tools.

## Pre-0.14 vaults

`bb murk grant mint` saves the vault. On a vault written by murk 0.13 or older (format 2.x, no vault id), that save is the vault's first 0.14 save: it rewrites `.murk` in the 0.14 format, uncommitted, on whatever branch the thread's worktree is on. The plugin reads the vault header first (no key needed) and refuses such a mint, naming the vault and branch.

To upgrade the vault where it belongs, do it on the default branch: run `murk trust` there if murk asks, make one write (any write saves it in the 0.14 format), commit `.murk`, and merge it into the feature branch. To upgrade it in the thread's worktree anyway, pass `--upgrade`:

```
bb murk grant mint --keys API_KEY --upgrade
```

`bb murk grant revoke` never runs murk on a pre-0.14 vault, so it never upgrades one. That format cannot hold agent grants, so a grant's vault that now reads as pre-0.14 is not the vault the grant was minted into. The revoke then deletes the grant's key file and leaves the grant `REVOKE-PENDING` until the vault is restored and a retry removes the grant.

## Changelog

### 0.2.0

- `bb murk grant mint` and `bb murk grant revoke` refuse a call from a bb thread. Run them in your own terminal, outside bb threads. The agent skill now tells agents never to run `bb murk grant`.
- New optional **Operator key file** setting (`keyFile`). Mint and revoke pass it to murk as `MURK_KEY_FILE`. With the setting blank, mint and revoke work as before: murk uses `MURK_KEY_FILE` or `MURK_KEY` from the bb server's environment, else the key it stored for the vault in `~/.config/murk/keys`.
- Removed the **Default grant scope** setting. It applied only to mints from inside a thread, which the plugin now refuses. Pass `--thread <threadId>` to limit a grant to one thread.
- `bb murk grant revoke` deletes the grant's key file even when the vault write fails. The grant is then `REVOKE-PENDING`, not revoked, and a retry runs the vault revoke again; only a revoke murk completes marks it revoked. `--forget` clears a pending grant, or one whose vault file is gone, in the plugin only.
- Tool errors that reach an agent no longer name a key file path. Your own `bb murk grant` output keeps full paths.
- The agent skill loads the delivered env file in a subshell, states the default TTL and what `--thread` changes, and says when idle cleanup leaves a file in place.
- Works with `@interrupted/murk-secrets` 0.14 and 0.15 (`^0.14.0 || ^0.15.0`).

### 0.1.1

- `bb murk grant mint` refuses a vault in the pre-0.14 format instead of upgrading it on the thread's branch. Pass `--upgrade` to upgrade it there anyway.
- When the murk binding cannot read the vault format, the error names the binding version the bb server actually loaded. A plugin reload keeps an already-loaded binding, so after a dependency update the error says to restart bb.
