---
title: How murk works
description: "The single-file vault model behind murk: what's public, what's encrypted, and how layered access works."
sidebar:
  order: 1
---

murk stores secrets in a single `.murk` file that's safe to commit to git. One key unlocks everything you're authorized to read. There's no server and no runtime dependency, and murk implements no custom cryptographic *primitives*. [age](https://age-encryption.org/) does the encryption, with standard BLAKE3 (keyed integrity) and Ed25519 (signatures) on top. What murk adds is the vault format, how those primitives are composed, and the command-line UX around them.

## Your key is your identity

murk finds your private key in one of three places:

- `MURK_KEY`, an inline age secret key.
- `MURK_KEY_FILE`, a path to a key file. The file holds a raw age key, an unencrypted SSH key, or a hardware-backed plugin identity.
- The key file that `murk init` stores under `~/.config/murk/keys/`.

murk derives your public key from that key. The public key determines which private values are yours and which entry in the vault's recipient list is you. See [Environment variables](/concepts/env-vars/) for the lookup order, and [Recipients & signatures](/concepts/recipients-signatures/) for how a key gets added to a vault in the first place.

Losing the key means losing access. When `murk init` generates an age key, it prints a 24-word BIP39 recovery phrase. SSH keys and hardware-backed keys have no recovery phrase. Back up an SSH key yourself, and enroll a second hardware key as a recipient.

## The header is public, the values aren't

A `.murk` file is one JSON document. Everything in it is plaintext *except* the secret values, the per-grant `agents` blobs and one encrypted metadata blob:

- **Recipients**: the public keys authorized to decrypt the vault. No names, just keys.
- **Schema**: key names, descriptions, examples, and tags for every secret. This is what `murk info` and `murk ls` show, and it works without a key at all.
- **Policy**: an optional allow-list constraining what agents can touch (see [Grants](/concepts/grants/)).
- **Secrets**: age ciphertext, one entry per key.
- **Agents**: an optional top-level map from each grant's public key to an age blob that only that grant can decrypt. The blob holds the grant's own record: its name, scope, issue and expiry times, issuer, and the signer keys it trusts.
- **Meta**: a single age blob holding recipient display names, group membership, the grant registry, GitHub key pins, the signer registry and the integrity MAC. Encrypted so none of it leaks to a non-recipient or to an agent grant.
- **Signature** (`sig`): a plaintext top-level field with the signer and an Ed25519 signature over the rest of the file. murk omits it when the last writer's key can't sign.

Anyone with read access to the repo can see what secrets exist and why (`murk info`, `murk ls`), which makes vaults easy to audit and diff in git. Only recipients with a valid key can see the *values*. The full byte-level layout lives in [Vault format](/concepts/vault-format/).

## One base tier and a private value

A secret has at most one base tier. The base tier is either **shared** (encrypted to every recipient except agent grants, the implicit `everyone` group) or a single **named group** (encrypted only to that group's members). A secret can also carry a **private value** (`--group me`), encrypted to just your key. A secret can have only a private value and no base tier.

When you `murk get` or `murk export`, murk resolves each key in this order:

1. Your private value, if you've set one for that key.
2. The named-group value, if the key's base tier is a group and you're a member of it.
3. The shared value, if the key's base tier is shared.

That split is what lets a team share most config while keeping per-developer or per-environment values (a personal API key, a `prod`-only credential) out of everyone's hands. [Shared, group and private secrets](/guides/shared-vs-scoped/) covers the day-to-day workflow for choosing between them.

## Agents get a narrower layer still

Recipients and groups are for people. AI agents and automation get a separate mechanism. A **grant** is an ephemeral identity with a murk-enforced expiry. It is scoped to a fixed set of keys and excluded from the shared tier entirely. It's never your own key. See [Grants](/concepts/grants/) for how that works.

## Each machine decides who it trusts

The vault lists its own recipients, so a file in the repo can't vouch for itself. Every time murk loads a vault with your key, it checks the signature against a **trust pin** that lives on your machine, outside the repo. The pin records who may sign and with which key, which vault this is, and how far its save counter has got.

murk refuses a vault signed by someone this machine hasn't accepted, an unsigned one, a different vault, or an older revision. You review it and run `murk trust` to go on. The same holds for a teammate's first write when it carries a signing key this machine hasn't confirmed. CI has no pin and sets `MURK_TRUSTED_SIGNERS` instead. See [Recipients & signatures](/concepts/recipients-signatures/#trusting-a-signer).

## What this model does and doesn't buy you

Every recipient except agent grants can decrypt every shared secret by design. So murk's access control between recipients is not a hard perimeter against an insider. A malicious recipient, or an old murk binary, can always read what their key is authorized for.

Grants are different. age enforces a grant's scope, because the grant has ciphertext only for the keys it was given. Two checks run in the murk binary instead: the agent policy and the grant expiry. They guard murk's own entry points, and they don't stop someone who uses `age` directly. See [Grants](/concepts/grants/).

Git is the audit trail once you commit each recipient change, rotation and grant (murk does not commit for you). The [threat model](/security/threat-model/) spells out exactly what murk protects against and what it doesn't.

For the authoritative, byte-level specification (including the exact JSON schema and the integrity hash algorithm), see [SPEC.md](https://github.com/interrupted-sh/murk/blob/main/SPEC.md) on GitHub.
