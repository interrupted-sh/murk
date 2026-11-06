---
title: Grants
description: Scoped vault access for AI agents and automation, with a murk-enforced expiry.
sidebar:
  order: 4
---

:::caution[Experimental]
Grants are new and their access rules changed in 0.14. A running `murk mcp` server does not see a revocation or policy change until it restarts, so restart it after you revoke. Treat grants as a guardrail, not a security boundary.
:::

A grant gives an agent or tool read access to a fixed set of secrets until a murk-enforced expiry, through a key that is deliberately not yours.

## A grant key isn't your key

`murk agent grant --name NAME --only KEY [--ttl DUR]` mints a fresh, ephemeral age identity: never your `MURK_KEY`. The grant is a recipient, but it can't read the encrypted `meta` blob, and it's excluded from the `everyone` layer entirely. It gets its own record (name, scope, issue and expiry times, issuer, and the signer keys it trusts), encrypted to its key alone in the vault's top-level `agents` map.

Its actual access is the set of `--only` keys, each re-encrypted as a private ciphertext addressed to the grant's own pubkey. Nothing else in the vault decrypts for it, shared or otherwise. You can grant only keys that have a shared value. murk refuses a key whose base tier is a named group, or that has only private values.

A live grant follows later changes to a granted key. When a save changes the key's shared value, murk re-encrypts the grant's copy, so the agent reads the new value. When the key moves to a named group or is removed, it leaves the grant's scope, and murk deletes the grant's copy. A grant whose scope becomes empty is removed.

A grant can't check the MAC, because the MAC key lives in the meta. It trusts a vault only by its signature. murk checks that signature against signers named outside the vault: the `# murk-trusted-signer:` lines murk writes into the grant's key file when it mints or renews the grant, plus any in `MURK_TRUSTED_SIGNERS`. With neither, murk refuses the load and tells you to re-mint the grant. murk checks the signature first, then the grant's own record, then its values.

The key is written to `~/.config/murk/agent-keys/<vault-hash>-NAME`. [Environment variables](/concepts/env-vars/#identity-and-vault-selection) defines `<vault-hash>`. Pass `--out PATH` to write the key elsewhere. That refuses an existing file unless you also pass `--force`. Pass `--out -` to stream the key instead of writing a file. It's a bearer credential: whoever holds it has the access it grants, so treat the file like the secrets it unlocks.

## Running with a grant

Point the agent at the grant key and mark it as an agent context:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<vault-hash>-codex MURK_AGENT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

`MURK_AGENT=1` forces strict mode for that process, even if `MURK_STRICT` isn't set. murk then doesn't look up your stored key in `~/.config/murk/keys`: the process must present the grant key or fail closed. This holds only while `MURK_AGENT` and the key variables stay set. An agent running as your user can unset `MURK_AGENT`, `MURK_STRICT`, `MURK_KEY` and `MURK_KEY_FILE`, and its next `murk` command finds your stored key. A change to this lookup is planned for 0.15. Until then, run the agent as a separate OS user or in a container (see [Agent isolation](/guides/agent-isolation/)). `murk agent init` does the whole safe-path setup (optionally setting the allow-list, minting the grant, and printing the exact run command) in one step. See [Environment variables](/concepts/env-vars/) for what each variable does, and [AI agents & MCP](/guides/ai-agents-mcp/) for the full walkthrough, including serving a grant over MCP with `murk mcp`.

## What constrains a grant

Scope is a cryptographic boundary: a grant can't decrypt a key it wasn't given, because no ciphertext exists for its pubkey. age enforces that boundary. The agent policy and the grant expiry are different. The murk binary checks them, so they are guardrails and not cryptography.

The vault's optional **agent policy** (`murk policy set --allow-tag TAG`) is a binary-enforced guardrail. Once set, a secret can only be granted or injected in agent mode if its schema carries an allowed tag, with no override flag. The murk binary enforces it at its agent entry points. It is not a sandbox or an access-control system. A compromised agent process, or a human with `age` and the raw key, is outside what any of this stops. See the [threat model](/security/threat-model/) for the full boundary.

## TTL and revocation

`--ttl` takes a number and a unit: `s`, `m`, `h` or `d`. The default is `2h` and the maximum is `365d`. A bare number is an error. murk records the TTL in the grant's metadata alongside its scope and issuer. **murk enforces the expiry at read time.** Past `expires_at`, the murk binary refuses the grant on every read (CLI, MCP, the bindings). The MCP `murk_plan` tool still lists the schema of the grant's keys.

Like the allow-tag policy, the expiry is a guardrail in the murk binary, not cryptographic access control. age keys can't self-destruct. Until the next vault write removes an expired grant, raw `age` still decrypts the current file with the grant's key. Old vault versions stay decryptable from git history with raw age. So revocation is still what closes the exposure. `murk agent ls` lists active grants with their scope and TTL status (time remaining, or how long expired) and works offline.

To renew a grant past (or nearing) its TTL, pass `--renew` to `murk agent grant`. It revokes the existing key and mints a fresh one under the same name, in a single vault write. Without `--renew`, murk refuses a name that still has a grant record.

An expired grant keeps its record until the next vault write by anyone, and `murk agent ls` shows it as `removed on the next vault write`. That write removes the grant and its recipient entry. The name is then free, and the old key fails with `not a recipient of this vault` instead of `expired`.

`murk agent revoke NAME [--rotate]` removes the grant and its ephemeral recipient, clearing its private ciphertexts so it can no longer read current values. The key could still decrypt old `.murk` versions from git history. **Revocation doesn't erase git history.** `--rotate` re-prompts for new values across the grant's scope, which is the step that actually closes the exposure.

If you don't rotate, murk stamps `revoked_at` on each key the grant could read. `murk doctor` and `murk rotate --list` then report those keys until their values change.

A grant's key file trusts the signers recorded in the grant when it was minted, and nothing updates the key file afterwards. So `murk circle revoke` also revokes every grant that trusts the revoked key, and every grant with no recorded signers (an unknown anchor is treated as trusting every signer). It marks those grants' keys as owing rotation, deletes their key files in murk's own slot, and tells you to delete other copies and re-mint the grants with `murk agent grant --renew`.

Do that. A copy murk can't reach still trusts the revoked key. Such a copy was written with `--out`, handed to the agent host, or made on another operator's machine. It accepts a vault that key signs, including one built from a copy from before the revoke that still carries the grant, and the agent reads the values in it.

A key file stops working at the expiry written into it (`# murk-grant-expires:`), whatever the vault says. A key file without that line is bounded only by the grant record in the vault, and that signer can rewrite the record. That covers a file minted by an older murk and a bare key line.

Revocation and policy changes apply when a process loads the vault. A running `murk mcp` server and a loaded binding object keep the vault state from their last load, so they still serve a revoked grant. Restart the server and reload the binding object after you change access. Grant expiry is checked again on every value read.

## Grants never sign or trust

A grant is read-only. murk refuses a vault signed by a grant key, and refuses a former grant key that shows up in the recipients without its grant. `murk trust` won't accept either, and it won't run under a grant identity. So a grant can't decide what a machine trusts, and it never reads or writes the machine's pin.

A grant trusts only the signers in its key file's `# murk-trusted-signer:` lines, plus any in `MURK_TRUSTED_SIGNERS`. A runner or container therefore needs no pin and no variable for a grant key as minted. A signer added after the grant was minted isn't in the key file. The grant then refuses the vault until you re-mint it with `--renew` or list that signer in `MURK_TRUSTED_SIGNERS`. A key file with no such lines needs `MURK_TRUSTED_SIGNERS` (see [CI/CD](/guides/cicd/#telling-ci-who-may-sign-the-vault)).

## Where grant state lives

The full `grants` registry lives inside the encrypted `meta` blob, not the plaintext header. Each grant also has its own record in the top-level `agents` map, encrypted to that grant only. Grant names, timestamps, issuers and the recorded scope list are encrypted in both places. The ephemeral recipient key and the `scoped` ciphertexts under each secret it can read are plaintext, so which secrets that key can read is visible without decryption. See [Vault format](/concepts/vault-format/) for the full on-disk layout, and [Recipients & signatures](/concepts/recipients-signatures/) for how that meta blob is protected against tampering.
