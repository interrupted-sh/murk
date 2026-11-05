# bb plugin for murk

> **Experimental.** This plugin is niche and may move out of this repository. It builds on murk's agent grants, which are experimental too. See [Feature status](https://murk.interrupted.sh/reference/feature-status/).

Grant-scoped murk secrets for [bb](https://getbb.app) agent threads. Agents see key names and tags; values arrive as short-lived 0600 dotenv files unless a grant explicitly allows reveal.

## Pre-0.14 vaults

`bb murk grant mint` saves the vault. On a vault written by murk 0.13 or older (format 2.x, no vault id), that save is the vault's first 0.14 save: it rewrites `.murk` in the 0.14 format, uncommitted, on whatever branch the thread's worktree is on. The plugin reads the vault header first (no key needed) and refuses such a mint, naming the vault and branch.

To upgrade the vault where it belongs, do it on the default branch: run `murk trust` there if murk asks, make one write (any write saves it in the 0.14 format), commit `.murk`, and merge it into the feature branch. To upgrade it in the thread's worktree anyway, pass `--upgrade`:

```
bb murk grant mint --keys API_KEY --upgrade
```

`bb murk grant revoke` never calls murk on a pre-0.14 vault: that format cannot hold agent grants, so there is nothing in it to revoke. It deletes the grant's key file and marks the grant revoked.

## Changelog

### 0.1.1

- `bb murk grant mint` refuses a vault in the pre-0.14 format instead of upgrading it on the thread's branch. Pass `--upgrade` to upgrade it there anyway.
- When the murk binding cannot read the vault format, the error names the binding version the bb server actually loaded. A plugin reload keeps an already-loaded binding, so after a dependency update the error says to restart bb.
