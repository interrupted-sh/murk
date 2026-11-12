# bb plugin for murk

> **Experimental.** This plugin is niche and may move out of this repository. It builds on murk's agent grants, which are experimental too. See [Feature status](https://murk.interrupted.sh/reference/feature-status/).

Grant-scoped murk secrets for [bb](https://getbb.app) agent threads. Agents see key names and tags; values arrive as short-lived 0600 dotenv files unless a grant explicitly allows reveal.

## Set the operator key

`bb murk grant mint` and `bb murk grant revoke` run murk on the bb server with your key: they add or remove a grant in the vault and sign the result. The plugin picks the key in this order:

1. The plugin's **Operator key file** setting (`keyFile`), if you set it. Use the absolute path of your murk key file: the `MURK_KEY_FILE` path that `murk init` wrote to the vault's `.env`. The plugin passes it only to the murk commands it runs on the bb server, never to an agent thread's environment.
2. `MURK_KEY_FILE` or `MURK_KEY` from the bb server's own environment.
3. If neither is set, murk finds the key it stored for the vault in `~/.config/murk/keys`, as it does in your terminal.

Set `keyFile` when the bb server cannot find your key by itself, for example when the key is not in `~/.config/murk/keys`. The plugin never reads the vault's `.env` itself: that file sits in the thread's worktree, where an agent can change it.

## Only you grant access

`bb murk grant mint` and `bb murk grant revoke` refuse a call that comes from a bb thread. Otherwise an agent could grant itself any key and then read it through `murk_get`. Run both commands in your own terminal, outside bb threads. To limit a grant to one thread, pass `--thread <threadId>`. `bb murk grant list` works from anywhere: it shows no values.

The agent skill tells agents never to run `bb murk grant`. When an agent needs a key, it asks you and gives you the command.

This is a guardrail, not a sandbox. The bb CLI tells the plugin which thread called it from the `BB_THREAD_ID` variable of the calling shell. A process that clears that variable, or calls the bb server directly, looks like your terminal. An agent runs as your OS user, so it can also read your key file directly. To keep an agent away from your key, run the agent as another OS user or in a container.

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

`bb murk grant revoke` never calls murk on a pre-0.14 vault: that format cannot hold agent grants, so there is nothing in it to revoke. It deletes the grant's key file and marks the grant revoked.

## Changelog

### 0.2.0

- `bb murk grant mint` and `bb murk grant revoke` refuse a call from a bb thread. Run them in your own terminal, outside bb threads. The agent skill now tells agents never to run `bb murk grant`.
- New optional **Operator key file** setting (`keyFile`). Mint and revoke pass it to murk as `MURK_KEY_FILE`. With the setting blank, mint and revoke work as before: murk uses `MURK_KEY_FILE` or `MURK_KEY` from the bb server's environment, else the key it stored for the vault in `~/.config/murk/keys`.
- Removed the **Default grant scope** setting. It applied only to mints from inside a thread, which the plugin now refuses. Pass `--thread <threadId>` to limit a grant to one thread.
- The agent skill loads the delivered env file in a subshell, states the default TTL and what `--thread` changes, and says when idle cleanup leaves a file in place.

### 0.1.1

- `bb murk grant mint` refuses a vault in the pre-0.14 format instead of upgrading it on the thread's branch. Pass `--upgrade` to upgrade it there anyway.
- When the murk binding cannot read the vault format, the error names the binding version the bb server actually loaded. A plugin reload keeps an already-loaded binding, so after a dependency update the error says to restart bb.
