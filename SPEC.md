# murk: Specification v3.0

> Encrypted secrets manager for developers. One key unlocks everything.

## Motivation

Existing secrets tools either need a server (Vault), take more setup (SOPS), share one key across the team (dotenvx), or do not support teams cleanly. murk is a minimal Rust binary that:

- Stores encrypted secrets in a single `.murk` file safe to commit to git
- Uses one key to unlock everything: a key file (`MURK_KEY_FILE`, written by `murk init` to `~/.config/murk/keys/`) is the normal way to hold it, and `MURK_KEY` is the inline option
- Integrates naturally with `direnv`
- Supports multiple users and per-identity private secrets
- Documents itself via `murk info`, which needs no key

---

## Design Philosophy

- **Header is public, values are private.** Anyone with repo access can see what keys exist and what they are for. Only authorized recipients can see values.
- **Standard primitives, murk's own format.** murk uses age for encryption and decryption, BLAKE3 for keyed integrity and signing-key derivation, and Ed25519 for signatures. It implements no custom cryptographic primitives. The vault format and the way it combines these primitives are murk-specific.
- **One binary, no runtime dependency.** Wrappable from any language via subprocess.
- **Git is the audit trail.** murk does not try to replicate what git already does.
- **Explicit over magic.** murk never silently overwrites or destroys data.

---

## Terminology

- **murk**: the shared layer. Secrets encrypted to every recipient except agent grants (the implicit `everyone` group).
- **mote**: a private secret. Encrypted to a single recipient's key. Overrides the shared value during export. On the CLI this is the `me` tier (`--group me`).
- **group**: a named subset of recipients. A secret assigned to a group is encrypted only to that group's members, so a leaked member key cannot read secrets outside that member's groups. `everyone` (every recipient except agent grants) and `me` (just you) are the two reserved, implicit groups. Named groups (e.g. `prod`) sit between them.

---

## Environment Variables

| Variable       | Required | Description                                             |
| -------------- | -------- | ------------------------------------------------------- |
| `MURK_KEY`     | No       | Raw age private key (`AGE-SECRET-KEY-1...`). Convenient for development and CI. The key sits in plaintext wherever you set the variable. |
| `MURK_KEY_FILE`| No       | Path to a private key file. `murk init` writes this reference to `.env`. The file may hold a raw age key, an unencrypted OpenSSH private key, or an age plugin identity file with a `# Recipient: age1...` (or `# public key: age1...`) header. murk refuses a file that is a symlink or readable by group or others. |
| `MURK_VAULT`   | No       | Vault filename. Defaults to `.murk`.                    |
| `MURK_STRICT`  | No       | When set to anything but `0`/`false`/`no`/`off` (or empty), turns on a short list of checks: it turns off stored-key discovery, requires `murk edit`'s scratch file to live on a RAM-backed filesystem, refuses `export`/`get`/`diff --show-values` when stdout is a regular file (plaintext to disk), and refuses a result no key checked (`rotate --list` without a key, or a `diff` revision shown only with a warning, except an unsigned one read with a key that cannot sign when `MURK_TRUSTED_SIGNERS` is unset). An unrecognised value turns it on. It is not a general guarantee that no plaintext reaches disk. |
| `MURK_AGENT`   | No       | Marks the process as running for an AI agent. Forces strict mode, and `MURK_STRICT=0` cannot turn it off. `murk agent exec` sets it on its child, and `murk mcp` needs it. Read like `MURK_STRICT`: any value except unset, empty, `0`, `false`, `no` and `off` turns it on. |
| `MURK_SELF_SCOPE` | No    | Holds your own key to the vault's agent allow-tag policy (see Policy), as if you were an agent. `MURK_AGENT` implies it. It does nothing on a vault with no policy. Read like `MURK_STRICT`. |
| `MURK_TRUSTED_SIGNERS` | No | Signers trusted to sign the vault, separated by commas or newlines, replacing the local trust pin's set: `age1…:<verifying key>` for an age signer, the public key line for an ssh-ed25519 signer (`murk trust --print-key` prints the entry). For CI runners and other machines without a pin. See Trust. |
| `MURK_NO_SIGNER_PIN` | No | When present, murk neither reads nor writes the local trust pin. Trust then comes only from `MURK_TRUSTED_SIGNERS`. |

[docs/env-reference.md](docs/env-reference.md), generated from the code, lists every variable murk reads.

Your identity is your key. murk derives your public key from `MURK_KEY` or `MURK_KEY_FILE` to determine which private secrets are yours and to identify you in the recipient list. Set one, not both: when both are non-empty murk refuses to resolve a key instead of picking one, and an empty value counts as unset. A decrypting command needs an identity. Set either key variable, or rely on stored-key discovery (see Discovery below), which is off in strict and agent mode.

### Hardware-backed identities

When `MURK_KEY_FILE` points at an age plugin identity file, murk uses the hardware-backed key without ever seeing the raw bytes. The file format is:

```
#    Recipient: age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm8cn9ss4xswuaalgb5wh5ug3pcs3
AGE-PLUGIN-YUBIKEY-1Q9WFTQQVZN3FASCJ3N9WEHUMFCYMCQSA2F8YVRMMGY6N76C6DMC6A8FTMP
```

A recipient header is required. murk reads it to determine the recipient without spawning the plugin. murk accepts `# Recipient:` (written by `age-plugin-yubikey`) or `# public key:` (written by `age-keygen`), in any letter case. The `AGE-PLUGIN-<NAME>-1...` line is the opaque pointer the plugin binary understands.

murk invokes `age-plugin-<name>` (which must be on `$PATH`) whenever it encrypts to a plugin recipient and whenever it decrypts with a plugin identity. Every save encrypts the meta to every recipient except agent grants, so every writer to a vault with a plugin recipient needs the plugin installed. On decrypt the plugin may prompt the user for physical consent (touch, PIN). Plugin identities have no BIP39 recovery phrase, so `murk recover` errors on them. Back up a second hardware device as a vault recipient instead.

Setting `MURK_KEY` (the inline env var) to an `AGE-PLUGIN-...` string is rejected. Bare plugin identities do not carry the recipient pubkey, so murk cannot resolve private secrets without spawning the plugin. Use a file path via `MURK_KEY_FILE`.

### Key storage

`murk init` writes a new secret key to `~/.config/murk/keys/<vault-hash>` (chmod 600), or reuses the key already stored there, and writes a `MURK_KEY_FILE` reference to `.env` (created with mode 0600):

```
export MURK_KEY_FILE='/home/alice/.config/murk/keys/a1b2c3d4e5f6a7b8'
```

`<vault-hash>` is the first 16 hex characters of the SHA-256 of the vault's absolute path. murk does not resolve a symlinked vault file, so it never uses the key of the file it points to. On Unix the directory is hashed as given, so a symlinked vault directory keeps its own key. On Windows murk hashes the directory's real path, so every spelling of one directory names the same key.

To use a non-default vault name, add `export MURK_VAULT=prod.murk` to `.env` or your shell yourself. `murk init` does not write it.

The key never appears in the project directory. `.murk` should always be committed.

**Discovery.** With neither `MURK_KEY` nor `MURK_KEY_FILE` set, murk looks up `keys/<vault-hash>` itself.

A git worktree puts the same committed vault at a different absolute path. So murk also accepts the key stored for that vault in a sibling worktree of the same repository: the main checkout first, then linked worktrees in a stable order. A fresh worktree therefore needs no key provisioning.

murk reads membership straight out of git's own worktree metadata (never a `git` subprocess) and verifies it in both directions. The vault's checkout must be one the repository records, and each sibling must resolve back to the same common directory. A `.git` entry is a file anyone can write, so an unverified claim of kinship (like a copied vault under a planted `.git` pointer) resolves to no key at all.

Discovery of any kind is off under `MURK_STRICT` and in agent context.

---

## File Format

A `.murk` file is a single JSON document. All fields are plaintext except the encrypted values, the meta blob and the per-grant `agents` blobs.

```json
{
  "version": "3.0",
  "created": "2026-02-27T00:00:00Z",
  "vault_name": ".murk",
  "repo": "https://github.com/org/repo",
  "vault_id": "0123456789abcdef0123456789abcdef",
  "generation": 12,
  "recipients": [
    "age1abc...",
    "age1xyz...",
    "age1agent..."
  ],
  "schema": {
    "DATABASE_URL": {
      "description": "postgres connection string",
      "example": "postgres://user:pass@host/db",
      "created": "2026-02-27T00:00:00Z",
      "updated": "2026-02-27T00:00:00Z",
      "rotation_interval_days": 90,
      "expires_at": "2026-09-01T23:59:59Z"
    },
    "OPENAI_KEY": {
      "description": "openai api key"
    }
  },
  "policy": {
    "agent_allow_tags": ["agents"]
  },
  "agents": {
    "age1agent...": "<base64 age ciphertext>"
  },
  "secrets": {
    "DATABASE_URL": {
      "shared": "<base64 age ciphertext>",
      "scoped": {
        "age1xyz...": "<base64 age ciphertext>"
      }
    },
    "STRIPE_KEY": {
      "shared": "",
      "grouped": {
        "prod": "<base64 age ciphertext>"
      }
    },
    "OPENAI_KEY": {
      "shared": "<base64 age ciphertext>",
      "scoped": {
        "age1agent...": "<base64 age ciphertext>"
      }
    }
  },
  "meta": "<base64 age ciphertext>",
  "sig": {
    "signer": "age1abc...",
    "v": 2,
    "sig": "base64-ed25519-signature"
  }
}
```

### Vault identity and counter

`vault_id` is 16 bytes as 32 lowercase hex characters. `murk init` mints a random one. The first save of a vault written by murk 0.13 or older derives it from the vault's `created` and `vault_name` instead (see Upgrading from 0.13 under Trust), so every copy gets the same id. Where the file loads only as history and this machine has seen the vault in 0.14 form, that first save waits until `murk trust` accepts the copy (see Trust, rule 6, Read-only copy).

`generation` is a save counter. Every save writes `max(loaded generation, highest generation this machine accepted) + 1`. A keyed merge writes `max(ours, theirs, highest accepted) + 1`. A merge without a key keeps ours' counter. A save or keyed merge is refused when that would exceed 2^53 − 1 (see Trust, rule 9).

Both fields are covered by the signature (signed view v2) and checked against the local trust pin on load (see Trust), so another vault's file and an older revision are refused. The exception is two vaults copied from one 0.13 vault (`cp .murk staging.murk`, say). They derive the same id, so the id cannot tell them apart. A load then refuses the other vault's file only as a rollback or fork, when its counter is at or below this machine's mark on the branch, and accepts it when its counter is higher. The merge driver compares a side's counter with the ancestor's, not with the mark, so it can merge such a file in.

A load also refuses a `generation` more than 1,000,000 above this machine's mark, or above 2^53 − 1 (see Trust, rule 9). Both are omitted when unset, so a vault written by older murk parses unchanged.

### Version

The `version` field is `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` (decimal, no leading zeros) with major `2` or `3`. Any other major is rejected on load. Minor bumps (e.g. `3.1`) are accepted. murk writes `3.0`.

Major 3 means the MAC (`blake3v8:`) and the signature (signed view 2) cover the header identity fields. murk 0.13 and older only accept `2.x`, so they refuse a 3.x vault with "unsupported vault version" instead of reading its MAC as tampering. A 2.x vault still loads and verifies under its old MAC and signed view 1, and is rewritten as 3.0 on the next save (including a merge-driver merge that regenerates the meta). The exception is a murk 0.13 file read as history. It is read-only until `murk trust` accepts that copy (see Trust, rule 6, Read-only copy).

`vault_id` and `generation` are header fields too, and both are omitted when unset. `vault_id` is the vault identity (32 lowercase hex characters, random from `murk init` and derived for a vault upgraded from 0.13), and `generation` is a save counter. `agents` maps an agent grant's pubkey to that grant's own record, encrypted to that grant only, and is omitted when the vault has no grants (see Agent grants). `sig` is the signature over the rest of the file (see Signatures).

### Load-time validation

A `.murk` file arrives through git and is untrusted. Every reader (the working vault, git revisions read by `diff`, and all three merge-driver inputs) checks each field against an allowlist and refuses the whole vault on the first failure, naming the field. `murk` runs the same checks before it writes a vault, so it never writes one it cannot load.

- File size: at most 64 MiB, checked before parsing.
- `version`: as above.
- `created`, the schema `created`/`updated`/`expires_at`/`revoked_at`, and the meta grant `issued_at`/`expires_at`: RFC 3339 timestamps.
- Key names in `schema`, `secrets`, and grant scopes: `[A-Za-z_][A-Za-z0-9_]*`.
- `recipients`, `scoped` keys, `agents` keys, the `sig` signer, and every pubkey in the meta: a public key that murk can encrypt to (age X25519, `ssh-ed25519`/`ssh-rsa`, or an age plugin recipient).
- `recipients`: each key once, compared by canonical spelling (lowercase for age, `type blob` for SSH). murk ≤ 0.13 compared exact strings and could list one key twice (an SSH key with and without its comment), so a 2.x header may repeat a key. Such a header loads, `murk verify` reports it, `murk circle revoke` by either spelling removes every copy, and every save writes each recipient once in its canonical spelling. In a 3.x header a repeated key fails the load.
- `grouped` keys and meta group names: 1–64 characters of `[A-Za-z0-9_-]`, and not a reserved tier alias (`everyone`, `all`, `shared`, `me`, `self`, `mine`). Meta grant names: the same character rule.
- `rotation_interval_days`: at least 1.
- Ciphertexts (`shared`, `scoped`/`grouped` values, `agents` values, `meta`, signer keys, signature): standard base64 with padding. The check accepts an empty string for every one of these fields. murk writes an empty `shared` for a secret with no shared value (a group-only or private-only secret) and an empty `meta` in a skeleton. The check is syntax only. Passing it says nothing about whether a ciphertext decrypts.
- Free text (`vault_name`, `repo`, descriptions, examples, tags, `agent_allow_tags`, display names): no control characters other than tab, CR, and LF. A write is stricter:
  - Text that is new or changed must hold no control character other than tab (a line feed is allowed in descriptions only), no bidi control (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069), no zero-width space (U+200B, U+2060 to U+2064) and no byte-order mark (U+FEFF).
  - The error names the field and never echoes the text.
  - Text the vault already held in the same place is exempt, so a vault that carries such text still loads and stays writable while nothing new of the kind gets in.
  - `murk verify` reports each such field as a finding, and `info`, `circle`, `circle revoke`, `init`, `trust` and `diff` escape these characters (as `\u{202e}`) when they print header text.
- Meta `mac_key`: 64 hex characters.
- `github_pins`: GitHub usernames (1–39 of `[A-Za-z0-9-]`, written lowercase and matched case-insensitively) mapped to `SHA256:` fingerprints (the SHA-256 of the decoded key blob, as `ssh-keygen -l` prints it). Pins written before 0.14 hash the key text instead. They are still matched and are rewritten on the next `authorize`.

The MAC value is not interpreted here, and signature bytes are only checked as base64. The integrity checks below verify both, and a failed check stops the load.

### Recipients

Public keys only, with no names or emails. Name-to-pubkey mappings live inside the encrypted meta blob where only authorized recipients can see them.

murk only writes a vault as one of its recipients. A save is refused when the saving key is not in `recipients`, because the values would be encrypted to keys the saver cannot read back. A vault with an empty `meta` and no secrets loads only for a key listed in `recipients`. Any other key gets "not a recipient". Otherwise anyone with repo write could plant such a vault listing only their own key and receive the next secret written into it.

### Schema

Key metadata stored as a map of key name to entry. Each entry has a `description` and optional `example` and `tags` fields. Schema is public and readable without decryption.

Entries also carry optional lifecycle metadata:

- `created` / `updated`: RFC 3339 UTC timestamps. `updated` is bumped on every value change (`add`, `edit`, `rotate`) and so doubles as the "last rotated" anchor.
- `rotation_interval_days`: soft rotation policy. `doctor` flags the key as overdue when `updated + rotation_interval_days` is in the past.
- `expires_at`: RFC 3339 UTC hard expiry for credentials with a known end-of-life (e.g. a token). `doctor` flags it as expired or expiring soon.
- `revoked_at`: RFC 3339 UTC marker set when a recipient who could read this key is revoked and rotation is deferred, or is removed from the group holding it. Its *presence* is the obligation: they can still decrypt the live value from git history until it changes. `doctor` flags it until then. A write that replaces the shared or group value (`add`, `rotate`, `import`) clears it. Writing a personal override (`--group me`) does not, since that leaves the exposed value in place. Omitted when there is no pending rotation.

Set the rotation/expiry fields with `murk describe KEY "desc" --rotate-every 90d --expires 2026-09-01` (`never` clears either). `revoked_at` is managed automatically by `circle revoke`, `group rm --member`, and `agent revoke` / `agent grant --renew`. All lifecycle fields are covered by the integrity MAC (see Integrity), so an edit that weakens rotation policy or clears a pending-rotation flag is caught by any command that loads the vault with a key. A command that reads the header without a key shows these fields unchecked and says so (see Trust, Header reads).

Key names must be valid shell identifiers: `[A-Za-z_][A-Za-z0-9_]*`.

### Policy

Optional agent access policy, in the plaintext header so it is readable without a key and at the same trust level as the recipient list. It is **not** access control: every recipient can read every shared secret by design, and an insider can use age directly or an old murk binary. Its value is constraining what the murk binary exposes to *agents*, enforced at the agent entry points (`agent exec`, `agent grant`).

- `agent_allow_tags`: in agent mode, a secret may be injected or granted only if its schema carries at least one of these tags. Once a policy is set it is default-deny: an untagged or wrong-tagged key is refused with a clear error. There is no override: the operator edits the policy. An empty list locks agents out entirely.

The policy is covered by the integrity MAC (see Integrity), so a keyed load catches a policy that was stripped or weakened. The field is omitted entirely when no policy is set, keeping policy-free vaults in the same layout as pre-policy murk. `murk policy show` reads the header without a key and labels what it prints unverified (see Trust, Header reads).

### Secrets

Each secret has these fields:

- `shared`: age ciphertext encrypted to every recipient except agent grants (the `everyone` group).
- `scoped` (optional): a map of recipient pubkey to age ciphertext encrypted to only that recipient (the **private** / `me` tier). The on-disk field is named `scoped` for compatibility with vaults written before the tier was renamed.
- `grouped` (optional): a map of group name to age ciphertext encrypted to that group's current members.

A secret has at most one base tier: shared (`everyone`), or a single named group (in which case `shared` is empty and `grouped` holds one entry). It can instead have only private (`me`) values, with an empty `shared` and no `grouped` entry. The `me` tier is a per-identity override layered on top of any base value. Group *names* are plaintext, like key names, and group *membership* lives in the encrypted meta. age determines readability: a non-member simply cannot decrypt a `grouped` ciphertext.

During `murk export` / `get`, resolution is: a personal private (`me`) override first, then a named-group value the current identity can read, then the shared value.

All age ciphertext is base64-encoded (standard alphabet, with padding).

### Meta

The `meta` field is a single age blob encrypted to every recipient except agent grants. A grant reads its own record in `agents` instead (see Agent grants). It contains:

```json
{
  "recipients": {
    "age1abc...": "mickey@example.com",
    "age1xyz...": "alice@example.com",
    "age1agent...": "agent:codex"
  },
  "mac": "blake3v8:abc123...",
  "mac_key": "0a1b2c3d...",
  "signers": {
    "age1abc...": "base64-ed25519-verifying-key"
  },
  "groups": {
    "prod": ["age1abc...", "age1xyz..."]
  },
  "grants": {
    "codex": {
      "pubkey": "age1agent...",
      "scope": ["OPENAI_KEY"],
      "issued_at": "2026-06-16T00:00:00Z",
      "expires_at": "2026-06-16T02:00:00Z",
      "issuer": "age1abc...",
      "anchors": ["age1abc..."]
    }
  },
  "github_pins": {
    "octocat": ["SHA256:abc..."]
  }
}
```

`recipients` maps public keys to display names. This is the only place names are stored.

`mac` is a keyed integrity hash over the vault's encrypted content (see Integrity below).

`mac_key` is a hex-encoded 32-byte random key used for BLAKE3 keyed hashing. murk generates a fresh one on every save. Vaults written by early versions call it `hmac_key`. murk still reads that name.

`signers` is the signer registry. It maps a recipient pubkey to the base64 Ed25519 verifying key that recipient's age key signs with, recorded when that recipient signs. ssh-ed25519 keys are never listed, because the recipient string is the verifying key. Each save writes the entries this machine has pinned (or, when no pin file exists, the loaded vault's) for current recipients, plus the writer's own, so the registry stays across writes by a key that cannot sign. The vault's author writes it, so loaders believe an entry only as described in Trust below. It is omitted when empty.

Vaults written before 3.0 also carry `sig` here: a signed-view-1 signature with `signer`, `v` (`1`), and `sig` (base64). murk now writes the signature to the top-level `sig` field instead and never writes one into the meta. See Signatures below.

`groups` maps a group name to its member pubkeys (a subset of `recipients`). Stored here, not in the plaintext header, so org structure (who is in which group) does not leak. Members are covered by the MAC. The field is omitted entirely when the vault has no named groups, keeping group-free vaults in the same layout as pre-groups murk.

`grants` maps an agent grant name to its metadata: the agent's ephemeral `pubkey` (also a `recipients` entry), the `scope` of keys it may read, `issued_at`/`expires_at` timestamps, the `issuer` pubkey, and `anchors`. `anchors` are the trusted signers written into the grant's key file at mint (canonical keys, empty for a grant minted before they were recorded). `anchors` is covered by the signature, not the MAC.

The agent is excluded from the `everyone` layer and from the meta. Its access is the set of `scoped` ciphertexts encrypted to its pubkey, one per scope key, plus its own record in `agents`. `grants` is stored here (not in the header), so the grant's name, timestamps, issuer and recorded scope list stay out of the plaintext. The MAC covers it, so TTL/scope/issuer cannot be altered undetected. The agent's pubkey is still a plaintext `recipients` entry, and its `scoped` ciphertexts show which secrets it can read. The field is omitted entirely when the vault has no grants.

The `expires_at` TTL is enforced by the murk binary at read time, though not cryptographically (see THREAT_MODEL.md). An expired grant, or one with no or an unreadable `expires_at`, fails closed. The next save removes an expired grant (record, recipient and scoped copies) and marks its keys as owed a rotation.

`github_pins` maps a GitHub username to the SHA-256 fingerprints of the keys that `circle authorize github:USER` fetched. On the next authorize for that user, murk compares them and stops if the set changed (unless you pass `--force`). The signature covers `github_pins`, and the MAC does not. The field is omitted when empty.

A grant record whose `pubkey` is the key that opened the meta was written by a meta writer: grants never open the meta. When that key is an operator key the trust rules know (rule 5 under Trust), the vault is refused as tampering. Otherwise the record is ignored on load and dropped by the next save, and it never makes that key a grant.

### Integrity

The MAC is a BLAKE3 keyed hash covering, in order:

1. **Key names**: iterated in sorted order, each followed by `\x00`
2. **Per-key encrypted values**: for each key (sorted):
   - The shared ciphertext, followed by `\x00`
   - For each scoped entry (sorted by pubkey): the pubkey followed by `\x01`, the scoped ciphertext followed by `\x00`
   - (v6 and later) For each grouped entry (sorted by group name): `\x03`, the group name followed by `\x00`, the grouped ciphertext followed by `\x00`
3. **Recipient pubkeys**: sorted, each followed by `\x00`
4. **Schema**: for each key (sorted): `\x02`, then the key name, description, and example (empty if unset) each followed by `\x00`, then each tag, in the order stored in the vault, followed by `\x00`, then the lifecycle fields `created`, `updated`, `rotation_interval_days` (decimal text), and `expires_at`, each emitted as its bytes (empty if unset) followed by `\x00`
5. **Group definitions** (v6 and later): for each group (sorted by name): `\x04`, the group name followed by `\x00`, then each member pubkey (sorted) prefixed by `\x05`
6. **Grant definitions** (v7 and later): for each grant (sorted by name): `\x06`, then the grant name, agent pubkey, `issued_at`, `expires_at`, and issuer each followed by `\x00`, then each scope key (sorted) prefixed by `\x07`
7. **Policy** (v8 and later, only when a policy is set): `\x08` opens the policy block, then each agent allow-tag (sorted) is length-prefixed (8-byte big-endian length + bytes) so tag contents cannot forge a boundary
8. **Revoked-at markers** (v9 and later): for each schema entry with `revoked_at` set (sorted by key name): `\x09`, the key name followed by `\x00`, the marker timestamp followed by `\x00`. Absent markers emit nothing, so setting then clearing one hashes identically to never setting it.
9. **Header identity** (v10 only): `\x0A`, then `vault_name`, `repo`, `created`, and `vault_id` (empty if unset), each as an 8-byte big-endian length followed by its bytes, then `generation` as an 8-byte big-endian integer (`0` if unset)
10. **Agent blobs** (v10 only): for each `agents` entry (sorted by pubkey): `\x0B`, then the pubkey and the ciphertext, each as an 8-byte big-endian length followed by its bytes

murk writes v10, prefixed `blake3v8:`, on every keyed save, so every vault upgrades on its next write. It writes no other prefix. The digest is stored as the `mac` field in meta, and the 32-byte BLAKE3 key as `mac_key` in the same encrypted meta blob.

On load, murk verifies the MAC. It accepts each prefix in this table. The older prefixes are accepted for vaults written before 3.0:

| Prefix | Internal version | What it adds |
| ------ | ---------------- | ------------ |
| `sha256:` | v1 | Key names, shared ciphertexts and recipients, under unkeyed SHA-256. It does not cover scoped entries. |
| `sha256v2:` | v2 | Scoped entries. Still unkeyed SHA-256. |
| `blake3:` | v3 | The v2 inputs under a BLAKE3 keyed hash. It does not cover the schema. |
| `blake3v2:` | v4 | The schema: each key's description, example and tags. |
| `blake3v3:` | v5 | Lifecycle metadata: `created`, `updated`, `rotation_interval_days` and `expires_at`. |
| `blake3v4:` | v6 | Grouped ciphertexts and group definitions. |
| `blake3v5:` | v7 | Grant definitions. |
| `blake3v6:` | v8 | The policy, when one is set. |
| `blake3v7:` | v9 | Revoked-at markers. |
| `blake3v8:` | v10 | Header identity fields and agent blobs. The only prefix murk writes. |

Each older prefix was written only when the vault needed it, so older murk saves of simpler vaults used older prefixes.

A vault is rejected under an older prefix that does not cover what it carries. This stops an attacker from stripping coverage (for example, clearing a pending-rotation flag) by downgrading the MAC. The minimum prefix is:

- v6 or later for groups,
- v7 or later for grants,
- v8 or later for a policy,
- v9 or later for a revoked-at marker, and
- v10 for a 3.x `version`, a `vault_id`, a non-zero `generation`, or an `agents` entry.

A `blake3vN:` prefix newer than `blake3v8:` fails the load with "written by a newer murk" rather than as tampering.

Because both the MAC and its key live inside the encrypted meta blob, only authorized recipients can compute or verify the hash. This makes the MAC a keyed integrity check for recipients and a tamper/corruption detector. It is **not** a defense against a deliberate attacker with write access to the repo. age encryption needs only the recipients' *public* keys (which are in the plaintext header), so a repo-writer can mint a fresh `mac_key`, recompute a valid MAC over tampered content, and re-encrypt the meta blob. Authorship integrity is provided by the signature below, not the MAC.

### Signatures

murk signs the vault with an Ed25519 key so that a change by someone without a recipient's private key is detectable. The MAC cannot provide this property, since anyone can recompute it. Whether the signer is someone *this machine trusts* is a separate check (see Trust below).

**Signing key.** Two signing-capable key types, both plain Ed25519 (RFC 8032, `ed25519-dalek`):

- **age**: an Ed25519 key derived from the raw 32-byte X25519 secret with `blake3::derive_key("murk.vault.signing.ed25519.v1", age_key_bytes)`, as in murk 0.13. The BIP39 phrase recovers it. Its verifying key cannot be computed from the `age1…` recipient, so the signer records it in the meta's `signers` registry on every save.
- **ssh-ed25519**: the SSH key is itself an Ed25519 signing key, parsed from the OpenSSH private key (age does not expose the scalar, so murk re-parses the retained PEM with the `ssh-key` crate). Its verifying key is the one embedded in the `ssh-ed25519 …` recipient string.

`ssh-rsa` and plugin/hardware identities cannot sign, so their saves are written unsigned. All signing and verification goes through one module (`src/signing.rs`: `VaultSigningKey::sign`, `VaultSigningKey::verifying_key`, `signing::verify`, `signing::checked_verifying_key`). A different scheme would therefore replace that module, not the trust logic.

**Verifying keys.** Every Ed25519 verifying key passes one check (`signing::checked_verifying_key`) wherever it enters murk:

- a `signers` registry entry in the meta,
- the pin's `signers` and its ssh-ed25519 `trusted` and `ever_trusted` keys,
- a `MURK_TRUSTED_SIGNERS` entry,
- a grant key file's anchor line, and
- the key in an `ssh-ed25519 …` signer string.

The check refuses three kinds of key: 32 bytes that are not a curve point, a non-canonical encoding of a point (a second spelling of one key), and a weak (small-order) key, under which a signature can be forged for any message without a secret. An honestly generated key is never any of these. Signatures are checked with ed25519-dalek's `verify_strict`, which also refuses a signature whose `R` is a small-order point.

A refused key has these effects, by where it turns up:

- A vault whose registry carries one fails the load as tampering, before any trust decision, so nothing from it is pinned. The error reads:

  ```
  vault meta is invalid (meta.signers[…]: …) — vault may have been tampered with
  ```

- A signature by an ssh-ed25519 signer whose key is refused does not verify, which fails the load as tampering too.
- A pin holding one ignores that key (its `signers` entry, or the ssh-ed25519 key in `trusted`/`ever_trusted`) with a warning naming the pin file, and the next pin write leaves it out.
- In `MURK_TRUSTED_SIGNERS` or an anchor it is an error naming the variable or the grant key file.

**Signed message (view 2).** murk writes view 2: the domain tag `murk.vault.sig.v2\n` followed by the JSON serialization of the vault file with the top-level `sig` field omitted, fields in file order. That covers every header field (`version`, `created`, `vault_name`, `repo`, `vault_id`, `generation`, `recipients` in stored order, `schema`, `policy`), the `agents` and `secrets` ciphertexts, and the `meta` ciphertext. Because the meta ciphertext is covered, the decrypted meta (MAC, names, `signers`, groups, grants, pins) is authentic too, and the message is rebuilt from the file alone. The signature is computed after the meta is encrypted and stored in the top-level `sig` (`signer`, `v` = `2`, base64 `sig`).

**Signed message (view 1).** Vaults written before 3.0 carry a view-1 signature inside the meta: a domain-tagged (`murk.vault.sig.v1\n`) canonical JSON serialization of a signed view covering `version`, sorted `recipients`, `schema`, `secrets` (all tiers), `policy`, `groups`, `grants`, `github_pins`, and the `signers` registry. It does not cover `vault_name`, `repo`, `created`, `vault_id` or `generation`. It excludes `sig` and the MAC/`mac_key`. murk still verifies view 1, only on a 2.x vault without a `vault_id` or `generation`, and replaces it with view 2 on the next save.

`serde_json` is not a formal canonical encoding, and it does not need to be here. The same serializer both signs and verifies. The signed view holds only strings, integers, sorted maps, and lists (no floats or other ordering ambiguity). No second implementation has to reproduce these bytes. Its deterministic output is therefore sufficient, and a formal canonical form (CBOR/DER) would add nothing.

**Verify.** On load, murk accepts a view-2 signature only in the top-level `sig` and a view-1 signature only in the meta. Anything else (both present, a view in the wrong place) fails the load as tampering. A view newer than 2 fails with "written by a newer murk".

Then the `signer` must be a current recipient (compared by canonical spelling: lowercase for age, `type blob` for SSH). The signature must verify strictly (`verify_strict`, see Verifying keys) under the signer's verifying key: the `ssh-ed25519 …` recipient string for SSH signers, the `signers` registry entry for age signers. A present-but-invalid signature fails the load as tampering, and so does a signature by an agent-grant key (grants are read-only). A valid signature only proves the registry entry's owner signed. Whether that key is really the recipient's is the trust check's job (rule 4 below). `sign_vault` only signs as a current recipient, so it never writes a self-invalidating signature.

**Merge driver.** A keyed merge first authenticates the common ancestor (MAC, signature, a signer this machine ever trusted).

An unsigned ancestor without a `vault_id` is accepted as pre-0.14 history. Its meta is not used: the sides' metas are then merged as if the ancestor were unreadable (any difference is a conflict), and group changes are judged against the pinned membership. Its secrets and policy still decide what counts as a change. A side's counter is not compared with it, since it has none.

Git takes the ancestor from history, so someone with write access and no key can supply a forged one, for example as the parent of a commit that a teammate cherry-picks or rebases. With an older genuine 0.14 revision as the other side, that merge sets values and the agent policy back to that revision without a conflict, and the merging key signs the result.

The driver then checks ours and theirs the way a load does:

- MAC and valid signature,
- a signer this machine trusts, and not a grant,
- the same `vault_id` (which two vaults copied from one 0.13 vault share, see Vault identity), and
- for a side that changed the vault, a `generation` above the ancestor's.

Group changes are judged against the authenticated ancestor's membership. A side's `generation` is compared with the ancestor's, not with the pin's mark. A branch saved on another machine legitimately carries a lower counter than this machine has accepted, and its content enters the merge only as its change from the ancestor. A side (or ancestor) that fails is a conflict naming it, and nothing from it is merged, re-MACed or signed.

A merge that would change a group's membership relative to ours is a conflict when the merging key is not a member of that group, since every machine would refuse the result signed by it. Otherwise the merged vault gets a fresh MAC, `generation = max(ours, theirs, highest accepted) + 1`, and a v2 signature by the merging key (none if that key cannot sign).

**Merge driver and 0.13 sides.** A side written by murk 0.13 (no `vault_id` and no `generation`) carries no authenticated identity or order. The driver judges it like a load of it on the branch being merged into (rule 6).

- Where that branch has a 0.14 mark, the side is refused. Outside git it is refused where the pin holds a `vault_id` or a counter. It could be an older signed revision, or another 0.13 vault of the team, committed on a branch forked from 0.13 history. Its intended change has to be made again with murk after merging.
- Elsewhere the side is pre-0.14 history, but it is still refused when it changed the vault and the other side was written by 0.14.
- A side with only one of the two fields is judged against any 0.14 state in the pin, not the branch's mark. It is refused when the pin holds a `vault_id` or a counter. Like a 0.13 side, it is also refused when it changed the vault and the other side was written by 0.14.
- A side with a `vault_id` other than the pinned one is refused as another vault.
- Both sides may lack a `vault_id` only when the whole merge is 0.13 history and the branch merged into has no 0.14 mark (outside git: the pin holds no `vault_id` or counter).
- Once the pin holds a `vault_id` or a counter, a 0.13 side that this machine has not accepted on that branch is refused too, because it is read-only. Trust, rule 6, Read-only copy, says what the refused merge writes and covers the 0.13 ancestor case.
- Before the pin holds either, and for a copy the user accepted with `murk trust`, the driver cannot tell an older 0.13 revision from a newer one. A branch that commits an older 0.13 file then merges cleanly and sets values back.

**Merge driver in git.** git passes the vault's path as `%P` (`murk merge-driver %O %A %B %P`) so the driver reads the right trust pin. A driver configured before 0.14 has no `%P` and falls back to `.murk`. A merge done without the driver (GitHub's web merge, merge queues) either conflicts textually or produces a vault whose MAC and signature fail, so it is never served. A cherry-pick or `git apply --3way` of commits from history replays their genuine delta. That is git's semantics, not something the driver can tell apart.

**Merge driver and removed keys.** A merge judges removals on every branch, whichever branch it merges into (rule 8 below).

- A side signed by a key this machine recorded as removed is refused.
- A side that lists a removed key that the ancestor does not list, at or below the generation the key was removed at, is an older revision adding the key again. It is refused as rolled back.
- A side that only still lists the key (a branch forked before the removal) passes this check. The merge then reports a conflict, because only one side removed a recipient. Take one side and redo the other side's change with murk.

If the merged recipients still list a removed key, some side numbered above the removal must list it. Otherwise the merge is a conflict and nothing is signed. A side's `generation` may be below the pin's mark, but it may be at most 1,000,000 above both the mark and the ancestor's. A side that sets a secret back to an older ciphertext, signed by a trusted signer, looks the same as a normal edit by that signer, so the merge accepts it.

**Merging a removal into a branch the removed member wrote to.** Alice revokes Bob on `feature`. Before that is merged, Carol (trusted) and then Bob change the vault on `main`. On `main`, Alice's load of Bob's vault is refused ("signed by bob, who was removed from this vault …"), and the hint says how to recover: merge the branch that removed him. Alice then:

1. Runs `git merge feature` with the murk driver. The merge stops with a conflict on the vault: "ours failed its authenticity check, so nothing was merged or signed: rolled back: it is signed by bob, who was removed …". The driver cannot merge Bob's side, because nothing he signed after his removal is trusted.
2. Keeps the side that removed him: `git checkout --theirs -- .murk`, then `git add .murk`. That drops every vault change made on `main` since the branches split, Carol's included, and the hint says so.
3. Runs `murk trust`. The kept vault reads as a rollback or fork of `main`, because her machine already accepted Carol's newer vault there. Accepting it does not re-trust Bob.
4. Finds `main`'s last vault commit not signed by Bob (`git log -- .murk`) and lists what differs with `murk diff <that commit> --show-values`.
5. Reviews it change by change, because a vault someone else signed on top of Bob's write can still carry his changes.
6. Makes only the changes trusted members made again with murk, and commits.

`main` then carries the removal and loads, and Bob is never trusted again. murk 0.14 has no command that re-merges `main`'s last trusted vault with the removing side automatically. If Alice abandons `feature` instead, the removal stays in force on her machine, and the hint says that `murk trust --re-add bob` restores him there.

### Trust

A valid signature proves that some key listed as a recipient signed the vault, and the vault chooses its own recipients. Acceptance is therefore anchored in state the repository cannot write: the local **trust pin** or the `MURK_TRUSTED_SIGNERS` environment variable.

`load_vault` (`src/load.rs`, rules in `src/trust.rs`) applies these rules on every keyed load by a key that opens the meta, before any value is decrypted for the caller. This holds for the CLI, the MCP server and the Python/Node bindings alike, and for write commands too, so a write never re-signs untrusted content. An agent grant's load is anchored in its key file instead (see Agent grants):

1. **Unsigned.** Refused when the loading key can sign (age, ssh-ed25519), or when `MURK_TRUSTED_SIGNERS` is set. Loaded with a warning otherwise (ssh-rsa, hardware/plugin keys): such a team relies on signed git commits.
2. **Stripped.** A vault this machine accepted signed that is now unsigned is refused, for every key.
3. **Trusted signer.** The signer must be in `MURK_TRUSTED_SIGNERS` when that is set (it replaces the pin's set), otherwise in the pin's `trusted` set: the non-grant recipients of the last vault accepted here. With neither, the vault is refused until `murk trust`.
4. **Signing key.** For an age signer, the registry key the signature verified under must be the one pinned for that signer (pin `signers`), or the one `MURK_TRUSTED_SIGNERS` gives for it. A trusted signer with no pinned key yet (a newly authorized teammate's first signed write) is refused until `murk trust` confirms the key: trust on first use. A different key for a signer whose key is pinned is refused outright, and `murk trust` will not accept it. An age key's verifying key is derived from its secret, so a second one for the same recipient is a forgery. ssh-ed25519 signers need no pinned key.
5. **Grants.**
   - A signer that is an agent grant in the vault, or was ever seen here as one, is refused. So is a former grant key listed as a recipient without its grant.
   - A vault whose grant record names an operator key is refused as tampering, and `murk trust` will not accept it. Grants get freshly minted keys, and recording it would mark that teammate as a grant on this machine. An operator key is any of these:
     - a signer this machine trusts or ever trusted,
     - a signer named in `MURK_TRUSTED_SIGNERS` or a grant's key-file anchor,
     - a key with a signer-registry entry (grants never sign), or
     - the loading key when it is an ssh or plugin identity (murk mints grant keys as age keys).
   - A key the pin trusts as a signer is never recorded as a grant and stays a trusted signer. A pinned grant entry never overrides signer trust.
6. **Identity and rollback.**
   - **Identity.** `vault_id` must match the pinned one.
   - **Rollback.** `generation` must not be below the highest accepted on the git branch the vault is checked out on. A branch never seen here and a detached HEAD have no mark. Outside a git checkout, the single highest mark applies.
   - **History.** A load on a branch never accepted here, or on a detached HEAD, is history and never adds trust (see below).
   - **A 0.13 vault has no counter.** A view-1-signed vault (murk 0.13) has no `vault_id` or `generation`, so the counter cannot judge it. It is judged per branch, by whether this machine has a 0.14 mark there. On a git branch that is a mark above 0 for the branch in the pin. Every 0.14 save is numbered from 1, and a view-1 vault is always at generation 0. So a mark of 0 comes from accepting the 0.13 vault (or `murk trust` of one), and it does not count. Outside git it is the overall mark above 0, or a pinned `vault_id`. A detached HEAD has no mark.
   - **A 0.13 vault: refused or history.** Where there is a 0.14 mark, a view-1-signed vault is refused: "vault .murk is in the pre-0.14 format, but this repository's vault has already been upgraded on this branch" (outside git: "…this vault has already been upgraded on this machine"). Everywhere else it loads as history if it passes every other rule. It may narrow the pin and never widen it, and it adds no mark or `vault_id`. The trusted-signer, signing-key, grant, removal and group rules all apply to it.
   - **Another vault's 0.13 file.** In place of its missing `vault_id`, a 0.13 file is compared with the pinned one by the id its first 0.14 save would take, derived from `created` and `vault_name` (see Vault identity). So another vault's 0.13 file is refused as another vault here too, as a load, a merge side and a merge ancestor. An unsigned 0.13 file is judged by that id too. Once the pin has a `vault_id`, another vault's unsigned or stripped 0.13 file is refused as another vault (not as unsigned or stripped). `murk trust` refuses to accept it at all (see `murk trust` below), so it is never re-signed under this vault's id.
   - **Derived ids can collide.** A vault created by murk 0.14 (a random id) has no 0.13 history at all. Neither `created` nor `vault_name` is covered by the view-1 signature or the MAC. So a member of another vault, or two vaults created in the same second under the same name, can make that vault's 0.13 file derive this vault's id. On a branch with no 0.14 mark such a file is then READ as this vault's: its values load as this vault's. That read-side limit stays, but a write over it does not go through.
   - **Read-only copy.** A murk 0.13 file that loads as history is read-only once this machine has seen the vault in 0.14 form (the pin holds a `vault_id` or a counter). It stays read-only until `murk trust` accepts that copy. The flow has five parts:
     - **Refused writes.** Every write over such a file is refused: any save (`add`, `rm`, `rotate`, `edit`, `import`, `describe`, `circle authorize` and `revoke`, `group`, `policy`, `agent grant` and `revoke`, and the writes of the Python and Node bindings) and a keyed merge-driver merge where ours or theirs is such a file. The merge refusal writes nothing to the working file: git keeps ours, as in the generation-limit refusal (rule 9). A 0.13 ancestor with two 0.14 sides still merges, since none of the ancestor's content is written.
     - **The refusal message.** It says that the vault `.murk` "is in the pre-0.14 format on a branch that hasn't taken the upgrade, and this machine hasn't accepted this copy, so it is read-only here" and that nothing was written. It then gives two ways out. One is to review the copy (`git log -p -- .murk`, `murk diff`), run `murk trust --vault .murk` to accept it, then retry. The other is to merge the upgrade from the default branch. On a detached HEAD it says to check out a branch first.
     - **Accepting the copy.** `murk trust` on such a copy says it is read-only until accepted, asks, and records this exact copy for this branch in the pin (`accepted_pre_upgrade`, see The pin). That is all it records. At that moment the trusted set, the groups and the recorded removals stay as they are, so a member who joined after the copy was written is never recorded as removed. A real removal is still learned only from a vault this machine accepts as current. On a detached HEAD `murk trust` refuses, since there is no branch to record the copy on.
     - **The next write.** It goes through and upgrades the file (3.0, numbered past the overall mark, with this vault's id), and the branch gets its 0.14 mark. That save is an own save. It changes the trusted set only by what it adds or removes itself, and it pins the groups the file it writes carries, which are the copy's. Narrower groups only make the group rule stricter. The save does encrypt to the copy's recipients, so review the copy before you accept it.
     - **Limits.** Any change to the file makes it a different copy, read-only again. A pin written by murk 0.14.0 has no accepted copies, so those writes are refused until `murk trust`.
   - **Marks are per branch.** Every worktree of a repository shares one pin, but the marks are per branch. One worktree's 0.14 save gives only its own branch a mark. A load never gives a branch its first mark, and a merge (git or the driver) does not either. So after the upgrade is merged into a branch, that branch has no mark on this machine until this machine saves there (any write counts, not only a merge result). Until then an older 0.13 revision checked out on it still loads there, read-only.
   - **Branch names.** Where git's `core.ignorecase` is true, murk maps a branch name that HEAD spells in another case (`git checkout Main` for `main`) to the branch as stored, so its marks apply. In a repository on git's reftable ref backend, HEAD on disk is a stub, so murk asks git (`git symbolic-ref`) for the current branch, and per-branch marks work the same.
7. **Groups.** A change to a group's membership must be signed by a member of that group as pinned (a new group by one of its members). Removing a member who left the vault entirely is exempt, because `circle revoke` does that for any recipient.
8. **Removal.** When this machine accepts a vault that removes a key from the trusted signers, the pin records the key in `removed` with that vault's generation, the branch the removal was made or accepted on in `removed_on`, and a commit in `removed_at_commit`.
   - **Recorded commit.** For a removal this machine makes (its own save), the commit is the one checked out when it saves, whether or not the removal is committed yet. Every commit at or before it existed before the removal. For a removal it accepts from another signer, the commit is the one checked out only when the vault file is exactly as committed there. Otherwise no commit is recorded.
   - **A vault the key signed.** From then on a vault signed by the key is refused on every branch, on a detached HEAD and outside git, in `MURK_TRUSTED_SIGNERS` mode too. There is one exception. It covers a vault the key signed, checked out on a branch the removal has not reached, at the recorded commit or an ancestor of it, with the vault file exactly as committed there. Its `generation` must also be at or below the one the key was removed at. Both the commit condition and the generation condition are needed.
   - **The generation bound.** A machine that learns of a removal late records a commit whose history may already contain vaults the key signed after the removal. The generation bound refuses those whenever they are numbered above the removal. A vault signed by the key above that generation is refused on every branch.
   - **An exempt vault.** A vault that passes the exception is treated as the key's own history from before the removal. It loads like any other, and it never makes the key trusted again. Because it is at or below the removal, a save over it that keeps the key is refused on a branch this machine never accepted (see below), so there it is read-only.
   - **No other vault is covered.** A vault at any other commit is not covered, even one in the history of a branch the removal reached (after a merge, rebase or squash of that branch). The exception fails closed. With no recorded commit (the removal was made or accepted outside git, accepted from an uncommitted vault file, or recorded by an older murk), or one git no longer has, there is none. murk never infers the commit from branch tips.
   - **Dropping the removal.** No vault drops the recorded removal except as described below.
   - **Listing rule.** A vault that lists the key at that generation or below is refused as rolled back wherever the history contains the removal:
     - on the branch it was made or accepted on,
     - on any branch where this machine later accepts a vault at or after the removal that no longer lists the key (the removal was merged or pulled there),
     - on a detached HEAD,
     - outside git, and
     - on a branch this machine has never accepted, whose history is unknown, so it may be a replay.
   - **Exempt places.** Two places are exempt from the listing rule, because their vaults may still legitimately list the key until the removal is merged there:
     - a branch this machine accepted before the removal reached it, and
     - a never-accepted branch checked out at the recorded commit or an ancestor of it, with the vault file exactly as committed there (an uncommitted change to the vault file loses the exemption).
   - **In the exempt places.** Reading there works. On a branch this machine accepted before, saves work too. On a never-accepted branch a save that would keep the key is still refused. Until the removal reaches a branch this machine accepted before, the key is still a recipient there, so every secret added or rotated on that branch is encrypted to it and readable by its owner. Loads on a never-accepted branch stay history, so they never add trust, and a vault there listing the key again never drops the removal.
   - **Re-adding.** A newer vault from a trusted signer that lists the key again where the listing rule applies re-adds it. So does `murk trust --re-add` naming the key (the way out when the branch that made the removal is abandoned). A save over an older revision that still lists the key is refused where the listing rule applies, with a message to update to the vault that removed it. A save that adds the key itself (`circle authorize`) re-adds it on purpose.
   - **Merges and old pins.** A merge judges removals on every branch (see Merge driver and removed keys, and the recovery after it). A removal recorded before `removed_on` existed applies everywhere.
9. **Counter.** `generation` may be at most 1,000,000 above the pin's mark. Above that, the vault is refused until `murk trust`.
   - **Hard limit.** A `generation` above 2^53 − 1 (the largest integer every JSON reader holds exactly) is refused as tampering, everywhere, and `murk trust` does not accept it. A vault at exactly 2^53 − 1 can still be accepted (through `murk trust`, say).
   - **Writes near the limit.** A save or keyed merge that would be numbered above the limit is refused before anything is written (a merge stops as a conflict and the working file is left as ours), so neither ever writes a vault that every machine refuses. A merge without a key never raises the counter itself: it keeps ours'.
   - **Recovery.** To write again, restore an earlier vault (from git, or an earlier copy outside git) and run `murk trust`. That is enough outside git, where `murk trust` lowers the overall mark. In a git checkout it lowers only the branch's mark, and a save is numbered from the pin's overall mark. So on a machine that accepted a vault at 2^53 − 1 there, every save and keyed merge stays refused until that machine's pin file is deleted (the refusal names it) and `murk trust` is run again.
   - **Forks.** The pin keeps a fingerprint (the SHA-256 of the signature) of the vault accepted at each branch's mark, and outside git at the overall mark. A different vault with the same generation on that branch is a fork: refused until `murk trust`. Two saves with the same counter on different branches are normal (two people saving from one revision), and the merge driver combines them.

An accepted load is either **current** or **history**. It is current when it is newer than everything this machine accepted (its `generation` above the pin's mark) and it is checked out outside git or on a branch this machine accepted before (one with a mark from an earlier `murk trust`, own save or current load). A murk 0.13 vault has no counter: it counts as newer only while the pin holds no 0.14 state (no overall mark and no `vault_id`).

Any other accepted load is history:

- a branch this machine has never accepted (an unmerged pull request, say),
- a detached HEAD,
- a branch behind the mark,
- the vault already accepted,
- a different vault with the counter this machine already accepted, or
- a murk 0.13 vault once the pin holds 0.14 state (rule 6).

Reviewing a pull request from a trusted signer therefore never trusts what it adds: branch protection may stop that signer from making the same change on main. A teammate added on such a branch signs there only after the change reaches a branch this machine accepted, or after `murk trust`.

A current load updates the pin: `trusted` becomes its non-grant recipients, `groups` is replaced, the counters move up, and the signer's verifying key and the registry entries of the vault's trusted recipients are recorded in `signers` where none was pinned. Keys that a current load drops from `trusted` are recorded in `removed` (rule 8).

A history load only narrows the pin. It adds grant keys to `grants`, raises the mark of a branch accepted before (it never gives a branch its first mark), and keeps `was_signed`. It never adds a trusted signer, a verifying key or a group member, so reading history (another branch, a detached HEAD, `murk diff`) never adds trust.

A registry entry is believed only from a vault signed by an already-trusted signer (whose own key matched), or one the user confirmed with `murk trust`. A pinned key is never replaced. An entry for a member of a group (as pinned, or in the vault) is believed only from a member of that group. Binding a key to someone's name lets the signer speak as them, so it must not reach a group the signer could not change itself.

A save signs the registry it writes, so on a machine with a pin it writes only the keys this machine confirmed (plus the writer's own). It never writes an entry the loaded file claimed that this machine did not confirm, and never one this machine pinned on another signer's word. A teammate's key therefore reaches every machine through the next write by anyone who confirmed it. When no pin file exists at save time (for example `MURK_NO_SIGNER_PIN`, or no home directory), the loaded entries are carried forward. On a machine with no pin yet, a load under `MURK_TRUSTED_SIGNERS` writes a pin with no `signers`, so the next save there writes only the writer's own entry.

When the trust came from `MURK_TRUSTED_SIGNERS`, the pin's `trusted`, `groups`, `signers`, `added_by` and `removed` are left unchanged, so the variable never widens trust that outlives it. A pin write that fails during a load only warns. `murk trust` and `murk init` record their result like a current load. The machine's own save changes `trusted` only by what the save itself added and removed, compared with the file it replaced. So a save over a vault read as history does not trust the keys that vault carried. Nothing from a refused or unverified vault is ever written to the pin.

**Registry entries depend on whoever added them.** When the pin takes a verifying key for a recipient from the registry of a vault signed by someone else, it records that signer in `added_by`. The entry counts only while that signer is trusted. When an accepted vault removes the signer, every entry they added is dropped, and is not pinned again from that same vault. The recipient's next signed write is then refused as unconfirmed until `murk trust` confirms the key. A save never writes an entry this machine holds on another signer's word. Otherwise the save would vouch for it under the writer's name, and other machines would keep it after the adder is removed.

An entry with no `added_by` was **independently confirmed**. It is the signer's own key in a vault the user accepted with `murk trust` after its fingerprint was shown, or this machine's own key (its own save or `murk init`). `murk trust` confirms only the signer's key. It shows every recipient, but it pins the other recipients' registry entries on the signer's word, with the signer in `added_by`, so they are dropped if that signer is removed.

Nothing else confirms an entry. A vault signed by the recipient's key and accepted while the adder was still trusted proves only that someone holds that key, and the adder chose that key. If the adder bound their own key to the recipient's name, the adder signed that vault. Another trusted signer whose registry carries the same entry does not confirm it either, because their machine may have pinned it on the adder's word. Pins written before 0.14 have no `added_by`, so their entries count as confirmed, and a machine still on such a pin can vouch for them.

**The pin.** The pin is `~/.config/murk/signer-pins/<hash>.json`, mode `0600`, written atomically. A symlink at the path is refused. The hash is over the repository's common git directory plus the vault's path in the checkout, so every worktree of a repository shares one pin. Outside a repository it is over the resolved absolute path. A pin that exists but cannot be parsed is an error, never an empty pin.

Every update (an accepted load, `murk trust`, a save) re-reads the pin under an exclusive lock on `<hash>.lock` and writes from that fresh copy. A load's acceptance is re-checked against it first. A load that read the pin before another process accepted a newer revision is then refused as rolled back instead of writing its stale view back.

The pin has these fields:

- `trusted`, `grants`, `groups`, `vault_id`, `generation` and `was_signed`
- `ever_trusted`: every key ever trusted here
- `branches`: per-branch high-water marks
- `head` and `branch_heads`: fingerprints of the vaults accepted at those marks
- `signers`: canonical recipient → pinned verifying key
- `added_by`: recipient → the signer whose registry entry pinned its key
- `removed`: canonical key → the generation it was removed at
- `removed_on`: canonical key → the branches whose accepted history contains its removal
- `removed_at_commit`: canonical key → the commit checked out when this machine made or accepted its removal
- `accepted_pre_upgrade`: branch → the SHA-256 fingerprint of the murk 0.13 file `murk trust` accepted there (the key is `""` outside git)

`removed`, `removed_on` and `removed_at_commit` belong to one vault: accepting a vault with another `vault_id` clears them. A murk ≤ 0.13 pin was written trust-on-first-use from unverified vaults, so murk keeps only its `was_signed` bit.

**`murk trust`.** The explicit trust step. It is needed:

- once per vault on each machine (a fresh clone, a new laptop, the first run after upgrading from 0.13),
- on each machine when a newly authorized age-key teammate first writes, and
- whenever a load is refused for a reason a human can accept.

It shows:

- the vault id and counter,
- the signer's name and full key (the name is chosen by whoever wrote the file),
- the signer's **signing-key fingerprint** (`SHA256:` and the unpadded base64 SHA-256 of the 32 verifying-key bytes, the `ssh-keygen -l` form), marked "trust on first use" when this machine has not confirmed it, and
- every recipient with its fingerprint, marked as new or removed since this machine last trusted the vault.

Then it asks (or takes `--yes`). Accepting confirms only the signer's signing key (see Registry entries depend on whoever added them). You should check the fingerprint with its owner out of band. `murk trust --print-key` prints one's own, and `murk init` prints it for a key that is not yet authorized.

What `murk trust` does depends on the vault it accepts:

- **An unsigned or stripped vault, or a murk 0.13-signed vault refused as pre-0.14.** `murk trust` re-signs it with the key you run it with (rule 6 describes the refusal, and `murk trust` prints the refusal's first line as its summary). The re-signing is a save: a 3.0 vault numbered past the mark, and the branch gets a 0.14 mark, so commit the result. Of these, a key that cannot sign can accept only a stripped vault, by forgetting that a signed version was seen. For a murk 0.13 vault, `murk trust` first records only that copy's fingerprint (`accepted_pre_upgrade`), and the save that follows is an own save. Rule 6, Read-only copy, lists what that means.
- **A read-only murk 0.13 copy.** A murk 0.13 vault that loads as history on a branch with no 0.14 mark, once this machine has seen the vault in 0.14 form, is read-only there (rule 6). `murk trust` handles it differently: it re-signs nothing, because the next write upgrades the file. Rule 6, Read-only copy, tells the whole flow.
- **An older murk 0.13 copy accepted for another reason** (it is signed by a key this machine did not trust yet, say), after this machine saw the vault in 0.14 form. The acceptance adds what the user accepted: the copy's signer and recipients become trusted. It narrows nothing. Members who joined after the copy was written stay trusted, nobody is recorded as removed, and the pinned groups stay.
- **Another vault's file.** Accepting it is unchanged: it replaces the trust state for that vault, as before. A 0.13 file that derives another vault's id is refused as another vault before it is refused as pre-0.14, so `murk trust` never re-signs it under this vault's id. Accepting a signed one as another vault pins the id that file derives. An unsigned or stripped 0.13 file is the exception, and it is judged by that id too. Once the pin has a `vault_id`, another vault's is refused as another vault (not as unsigned or stripped), and `murk trust` refuses to accept it at all ("an unsigned pre-0.14 file of another vault can't be accepted as this one").
- **Anything else** is pinned as shown, a rollback or fork acceptance resetting the branch's mark.

`murk trust` refuses vaults signed by a grant key, with a changed signing key, or with a `generation` above 2^53 − 1. It also refuses to run for a grant identity.

A vault signed by a key recorded in `removed` is refused on every branch, and one that lists such a key is refused where its removal applies (rule 8). It is accepted only when each such key is named with `--re-add KEY` (its public key or its name in the vault). Naming it takes the key out of `removed`.

**Trusted-signer entries.** `MURK_TRUSTED_SIGNERS` and an agent grant's key-file anchor use one entry format. An age signer is `age1…:<verifying key>` (the recipient, a colon, the base64 Ed25519 verifying key). An ssh-ed25519 signer is its public key line. `murk trust --print-key` prints the entry for the current key. In `MURK_TRUSTED_SIGNERS` entries are separated by commas or newlines. An invalid entry, or an age key without its verifying key, is an error.

**Historical revisions.** `trust::assess_revision` checks an older revision against `ever_trusted` without rollback or group checks, and never writes the pin, so a revision signed by a teammate revoked since still verifies. The merge driver uses it for the common ancestor. `murk diff` uses it for the revision it compares against. It first verifies that revision's MAC and signature and refuses a revision that fails. It then judges the signer this way, and refuses a revision whose signer fails when this machine has a trust pin or `MURK_TRUSTED_SIGNERS`. With neither it shows the revision with a warning (see `murk diff`). It also warns when the working vault is not trusted.

**CI.** A fresh runner has no pin. `MURK_TRUSTED_SIGNERS` (from a CI secret, in the entry format above) names the keys allowed to sign and the verifying keys their signatures must verify under. Nothing from it is written to the pin as trust. Without a pin there is no rollback mark on a runner.

**Opting out.** `MURK_NO_SIGNER_PIN` (present with any value, or no home directory) stops murk reading or writing the pin. It does not switch the trust check off: every signed vault is then refused unless `MURK_TRUSTED_SIGNERS` names its signer, and rollback and stripped-signature detection are off.

**Bindings.** The Python and Node bindings load through `load_vault` like the CLI. They do it on every call that reads the vault (Node's `add` and `describe` included), with no option to skip it. They update the pin exactly as the CLI's load does.

A refusal (`MurkError::Trust`) or a failed integrity check (`MurkError::Integrity`) raises `murk.TrustError` (a `RuntimeError` subclass) in Python. In Node it throws an `Error` with `code` `'MURK_TRUST'`. Both carry the message the CLI prints. A grant key with no anchor, or reading a 2.x vault, is a trust refusal too.

Warnings about an accepted vault (an unsigned vault loaded by a key that cannot sign, a legacy MAC, a pin that could not be written) are collected in `Murk::warnings`. The CLI prints each as `warn …`, and the bindings expose them as `vault.warnings`.

**Header reads.** The MAC and the signature need a key, so a command that only reads the plaintext header checks nothing. Anyone who can write the repo can drop an `expires_at` or `revoked_at`, or edit a description, and the command shows the edit as fact.

`ls`, `info`, `circle`, `skeleton`, `agent plan`, `policy show` and `doctor` (its rotation check) never load the vault, so they keep working on one this machine has not trusted yet. Run with no key (no `MURK_KEY`, no `MURK_KEY_FILE`, no stored key for the vault), each prints this line to stderr, once, in human and `--json` mode alike:

```
warn unverified header — read without a key, so nothing here is integrity-checked
```

A run that has a key is not labelled, but is not checked either: these commands do not load the vault with it. `murk rotate --list`, whose exit status gates scripts, is the one that verifies: see its entry.

**Deliberate revert.** To go back to an older vault:

1. Restore the older file.
2. Run `murk trust`. It shows the counter going back.
3. Make any write. The save is numbered above everything this machine accepted, so teammates accept it as newer.
4. Commit the write with the restored file. Otherwise teammates' machines refuse the revert as rolled back.

A `git revert` of a commit that changed the vault restores an older file too, so it is refused as rolled back until `murk trust`. This does not recover a machine whose mark reached 2^53 − 1 (rule 9).

**Upgrading from 0.13.** Every teammate needs 0.14. A 0.14 save writes a 3.0 vault with signed view 2, which 0.13 refuses as an unsupported vault version. On each machine the first load is refused once, with the current signer shown. Then:

1. Review `git log -p -- .murk`. After a pull, `murk diff ORIG_HEAD` shows what the pull changed.
2. Run `murk trust`, which shows an age signer's signing-key fingerprint.
3. Make the first 0.14 save on the default branch, and commit it.
4. Merge that commit into the other branches.

The first 0.14 save adds `generation` and a `vault_id` derived from the vault's `created` and `vault_name` (`sha256("murk.vault_id.v1\0" ‖ created ‖ "\0" ‖ vault_name)`, first 16 bytes). Teammates who upgrade separately, or on different branches, therefore agree on the id. The save also gives its branch its first 0.14 mark (outside git, the overall mark is above 0 from then on). From then on, where that mark exists, this machine refuses the view-1-signed revisions. The merge driver refuses a 0.13-era side: review it on that branch and re-sign it there with `murk trust`, or redo its change after merging.

The refusal is per branch, not per repository. Every worktree shares one pin, but a branch that has no 0.14 mark yet still loads its committed 0.13 vault, as history, which may narrow the pin and never widen it. Once this machine has seen the vault in 0.14 form, that history is read-only until `murk trust` accepts that copy on the branch. Branch marks and the read-only flow are in rule 6 (Read-only copy and Marks are per branch).

To write on a branch before merging the upgrade, run `murk trust` there first. The next save then writes a 3.0 vault numbered past the overall mark, takes the pinned `vault_id`, and gives that branch its 0.14 mark. A view-1 vault on that branch is refused from then on. A pin written by murk 0.14.0 has no accepted copies, so the first write over a 0.13 file on such a machine needs `murk trust` too. CI needs `MURK_TRUSTED_SIGNERS` in the entry format above.

### Agent grants

An agent grant is never a recipient of the meta, which holds the MAC key, every name, group, grant and signer. It gets two things only:

- the `scoped` copies of the keys in its scope, encrypted to its pubkey, and
- its own record: `agents[<grant pubkey>]`, an age blob encrypted to its pubkey alone, holding `{"name": "<grant name>", "grant": {pubkey, scope, issued_at, expires_at, issuer}}` (the same fields as its `meta.grants` entry, and nothing else). murk rewrites the blob when the grant record changes and drops it with the grant.

A grant cannot check the MAC, so it trusts a vault only by its signature. The signature is checked against signers named outside the vault: its key file's **anchor**. When `murk agent grant` (or `agent init`, `agent connect`, `--renew`) writes a key file, it puts one line per trusted signer above the key, in the trusted-signer entry format (see Trust). Then it writes the grant's name and expiry:

```
# murk-trusted-signer: age1…:<base64 verifying key>
# murk-trusted-signer: ssh-ed25519 AAAA…
# murk-grant-id: <grant name>
# murk-grant-expires: <RFC 3339 UTC, the record's expires_at>
AGE-SECRET-KEY-1…
```

The lines list this machine's pinned trusted signers for the vault plus the minting key. Grant keys are never among them. age ignores `#` lines, so the file is still a valid age identity file. Re-minting or renewing the grant rewrites the lines, the expiry included. `MURK_TRUSTED_SIGNERS` adds to the anchor. A `murk-grant-id` or `murk-grant-expires` line that is empty, unparseable or repeated is refused, never ignored.

A load whose key has an `agents` entry and cannot open the meta is a grant load, in this order, before anything is handed out:

1. **Anchor.** The key-file lines plus `MURK_TRUSTED_SIGNERS`. If both are empty, the load is refused: "this grant key names no trusted signers, so murk can't check the vault it reads: ask the operator to re-mint the grant (`murk agent grant --renew`), or set MURK_TRUSTED_SIGNERS". A key file from before 0.14 gets this message.
2. **Signature.** The top-level view-2 `sig` must be by a signer in the anchor and verify under the anchor's key for it (the `ssh-ed25519` line for SSH signers). Nothing inside the vault, the `signers` registry included, is read for this. An unsigned vault, a signer not in the anchor and a signature that does not verify are each refused.
3. **Record.** The grant's own `agents` blob is decrypted.
   - If the key file names a grant (`murk-grant-id`), the record must be for that grant, or the load is refused.
   - The grant is bounded by the earlier of the record's `expires_at` and the key file's `murk-grant-expires`. Past either, it fails closed. So no record a trusted signer saves later, an extended expiry included, keeps a key file working past the expiry it was minted with.
   - A key file without `murk-grant-expires` (minted before murk wrote it, or a bare `AGE-SECRET-KEY-1` line) is bounded by the record alone. murk warns once per process that the key file does not bound the grant and should be re-minted.
   - murk-action v1.2.0 and later pass a whole grant key file as its `murk-key` input unchanged, so the key file's signers and expiry apply in CI.
4. **Values.** Only then are its `scoped` values decrypted.

The key file's expiry bounds every copy of that key file, but not its holder: whoever can edit the file can remove the line and fall back to the record. Like the record's TTL, it is a guardrail in the murk binary, not access control (see THREAT_MODEL.md).

A grant load reads and writes no trust pin, so it has no rollback check. Every write by a grant is refused ("agent grants are read-only"). A key that can open the meta always loads as an operator, even with an `agents` entry. A 2.x vault still encrypted its meta to grants: a grant key reading one is refused until the operator saves it with 0.14 or later and re-mints the grant.

---

## Commands

This section states what each command does. [docs/cli-reference.md](docs/cli-reference.md), generated from the CLI, lists every flag with its help text.

### `murk init [--vault NAME]`

Interactive setup. Prompts for a display name. Then:

1. Finds your key. It looks at `MURK_KEY` or `MURK_KEY_FILE` from the environment first. Then it looks at the key stored at `~/.config/murk/keys/<vault-hash>` for this checkout or for the same vault in a sibling worktree (the lookup under Discovery). Only when neither exists does it generate an age keypair via BIP39 (a 24-word mnemonic encodes the key directly) and write the secret key to `~/.config/murk/keys/<vault-hash>` with mode 0600. The key file is created exclusively, so init never overwrites one.
2. For a newly generated key, prints the BIP39 24-word recovery phrase to stderr. A reused key prints none (use `murk recover`).
3. Writes `export MURK_KEY_FILE='<path>'` to `.env` (creates it if missing). It never writes an inline `MURK_KEY`, and in strict or agent mode it never writes a `MURK_KEY_FILE` path from the environment. If `.env` already has a `MURK_KEY` or `MURK_KEY_FILE` line, a reused key leaves that line as it is. If init must generate a new key, it asks before replacing that line and aborts unless you answer yes.
4. Creates the `.murk` vault with your pubkey as the first recipient, a fresh `vault_id` and `generation` 1, signed by your key when that key can sign, and records it in the local trust pin with the creator as its trusted signer.

If the vault already exists, init does not change it. It uses the same key lookup and writes `.env` by the same rules. Then it reports whether the key is a recipient:

- A recipient is told to run `murk trust` once per machine if this machine has no trust pin for the vault yet.
- A key that is not a recipient prints its public key and, for an age or ssh-ed25519 key, its signing-key fingerprint, to send to someone who can authorize it.

init never replaces a stored key file. To get a new identity, move the key file away first. In strict or agent mode, init neither uses nor replaces a stored key. With no key in the environment and a stored key present (here or in a sibling worktree), it refuses. Set `MURK_KEY_FILE` to that path to use it.

---

### `murk add KEY [--group NAME] [--desc DESC] [--example EX] [--tag TAG] [--vault NAME]`

Adds or updates a secret. Prompts for the value interactively (hidden input via rpassword) or reads it from stdin when piped. Piped input is the whole of stdin with one trailing newline removed, so a multi-line value such as a PEM key arrives intact (`cat key.pem | murk add TLS_KEY`).

`--group` selects who can read it:

- `everyone`: the shared/murk layer.
- `me`: only your key (the private/mote layer).
- a named group: encrypted to that group's members. You must be a member.

Assigning a secret to a named group makes that group its sole base tier, so any existing shared value is dropped. When an explicit `--group` moves an existing key to a different tier, murk reports the move. `--scoped` is a deprecated alias for `--group me`.

Without `--group`, an existing key keeps its tier, so an update never widens who can read it:

- A shared value stays shared.
- A group value stays in its group (encrypted to the group's current members).
- A key that has only your `me` override gets a new override value.

Only a new key defaults to `everyone`. A key whose only values are other recipients' `me` overrides is refused until you choose a tier with `--group`. If a group you are not a member of holds the key, murk refuses the write (only `--group me` can add your own override). A member of that group must update it.

`--desc` and `--example` set the key's description and example in the schema. On an existing key, each replaces the current value only when given. `--tag` adds a tag (repeatable) and keeps the existing ones. `murk describe` replaces them instead.

Key names are validated as shell identifiers. Invalid names are rejected. A name that `export`/`exec` treat as reserved (see `murk export`) is accepted with a warning.

---

### `murk generate KEY [--length N] [--hex] [--group NAME] [--desc DESC] [--example EX] [--tag TAG] [--vault NAME]`

Generates a cryptographically random value and stores it. Default length is 32 bytes, output as URL-safe base64 (no padding). Use `--hex` for hexadecimal output. `--group`, `--desc`, `--example` and `--tag` work as for `murk add`. Uses the same RNG as key generation.

---

### `murk rotate [KEY] [--all] [--generate] [--length N] [--hex] [--values-from FILE] [--list [--json]] [--vault NAME]`

Replaces a secret value (`KEY`, or every secret with `--all`). Prompts for the new value interactively, or generates a random one with `--generate`. Use after revoking a recipient to ensure they can no longer use the old value.

Rotation keeps each value in its tier and never widens who can read it:

- A shared value stays shared.
- A group value stays in its group (encrypted to the group's current members).
- A key held only as your personal override stays your override.

A personal override on top of a shared or group value is left unchanged. You cannot rotate a key held by a group you are not a member of: `rotate KEY` refuses it, and `--all` skips it with a warning. The same goes for a key that holds only other recipients' overrides. Other recipients' overrides are never touched.

`murk rotate --all` rotates every secret in the vault, prompting for each in sequence. `--generate` is not allowed with `--all`, because external credentials (database passwords, API keys from third-party services) require manual rotation at the source.

A prompt can wait for minutes, and a `git pull` or checkout meanwhile does not take murk's lock. If the vault file changed on disk between the load and the save, `rotate` saves nothing and exits 1, as `murk edit` does. The message is:

```
changed on disk while murk waited for the new values — nothing saved
```

Re-run `rotate` on the current vault. `circle revoke` and `agent revoke` refuse the same way.

Piped stdin works the same way when the batch takes one value (e.g. `murk rotate KEY`): all of stdin is the value. A batch of several values reads one value per line, matched to keys by position, so values cannot span lines. Input with more lines than values is refused before anything is written. If anything would be skipped, or a key would take more than one value, the batch is refused before any value is read, since later values would land on the wrong keys.

`--values-from FILE` (`-` for stdin) matches values by name instead. It reads the file with the same `.env` parsing as `murk import`: `KEY=value` lines, with an optional `export` prefix and single- or double-quoted values that may span lines. These abort with nothing rotated:

- an unclosed quote or other parse error,
- a file that names a key more than once, and
- a file with any line that is not blank, a comment or a `KEY=value` entry (an invalid or `MURK_*` name, or a line without `=`, such as the body of an unquoted multi-line value).

murk reports the lines of that last kind, and unquoted values containing ` #`, by line number, never by value. Every key the file names must be one this command can rotate, with exactly one value to replace. Otherwise the whole batch is refused before anything is written, naming the keys. Keys the file does not name are left unrotated and reported.

`--values-from` cannot be combined with `--generate`. A values file that is a symlink is refused, and one readable by others gets a warning. `--values-from -` keeps the new values off disk.

`murk rotate --list` reports the keys that need rotating: the same overdue/expiry/post-revoke signals `doctor` evaluates, scoped to rotation. Human output exits 1 when anything needs rotating (usable as a script gate). `--list --json` always exits 0 for a clean or flagged vault.

A gate must not be passable by editing the header, so the result is verified whenever it can be.

**With a key** the vault loads through the full load path first (MAC, signature, this machine's trust verdict). `into_trusted` also records the pin like any load. The report comes from the verified vault. Deleting `revoked_at` or `expires_at` from the header then fails the command (non-zero, no report) instead of reporting that no keys need rotating. So does a vault this machine does not trust, or a key that cannot open it. The command never falls back to an unchecked read.

**With no key** nothing can be checked. The command reads the schema as written and prints the unverified warning (see Trust, Header reads). Under `MURK_STRICT` (or agent context) it refuses the result by exiting 1: in human mode instead of `ok`, in `--json` mode after printing it.

`--json` prints an object, `{"verified": bool, "issues": [...]}`. `issues` is the `reason`-tagged array (`overdue`, `no_baseline`, `expired`, `expiring_soon`, `revoke_pending`) that `--json` printed alone before 0.14. `verified` is `true` when a key verified the vault and `false` otherwise. The array moved under a key because the flag has to be present when no key needs rotating. An empty array has no element to carry it, and `[]` is exactly what a header stripped of its flags produces. Consumers that iterated the old top-level array read `.issues` instead.

---

### `murk rm KEY [--vault NAME]`

Removes a key from the vault (shared value, schema entry, and all private entries). No confirmation prompt: git is your safety net. Refused when the key has a value in a group you are not a member of, or holds only other recipients' personal overrides. Those values would stay in the vault, so only their owners can remove them.

---

### `murk get KEY [--vault NAME]`

Prints a single decrypted value to stdout. Scoped values take priority over shared values. Exits with code 1 if key not found. On a terminal, control and invisible characters in the value are escaped, except tabs and newlines. Piped output keeps the exact bytes.

---

### `murk ls [--tag TAG] [--json] [--vault NAME]`

Lists key names, one per line. `--tag` filters by tag (repeatable). `--json` outputs JSON.

---

### `murk describe KEY "description" [--example EX] [--tag T]... [--rotate-every DAYS] [--expires DATE] [--vault NAME]`

Sets metadata for a key in the plaintext schema. Does not touch encrypted values. Each call replaces the description and the example (omitting `--example` clears it). `--tag` replaces the tags only when given. Refused for a key held by a group you are not a member of, since its tags and policy belong to that group's members.

`--rotate-every` takes a day count (`90` or `90d`) and `--expires` takes a date (`2026-09-01`) or RFC 3339 timestamp. Pass `never` to either to clear it. Both are sticky: a later `describe` that omits the flag leaves the existing value untouched. `doctor` reports keys that are overdue for rotation or past/near their expiry.

---

### `murk edit [KEY] [--scoped] [--group NAME] [--vault NAME]`

Opens secrets in `$EDITOR`. With KEY, edits a single value. Without KEY, edits all secrets as `KEY=VALUE` lines. With `--scoped`, edits private overrides (motes) instead of shared values. With `--group NAME`, edits the values for that named group (you must be a member). An edited value stays in the tier you edited it in. If a group you are not a member of also holds the key, murk refuses to change its shared or group value, as `murk add` does. A new line for a key that is in a different tier is written as `murk add` writes it: without a tier flag, the key keeps its tier. With a tier flag, the key moves to that tier.

murk writes the plaintext buffer to a temp file (mode 0600 on Unix). It uses `XDG_RUNTIME_DIR` when that is a directory, then `/dev/shm` when it is RAM-backed, then the system temp directory. If that directory is not RAM-backed, murk warns that the wipe is best effort.

murk runs the editor (`EDITOR`, then `VISUAL`, then `vi`). The editor does not receive `MURK_KEY` or `MURK_KEY_FILE`. On Unix, murk runs it through `sh`, as git does, so the value can carry arguments such as `code --wait`, and the editor runs in its own process group. On Unix, after the editor exits, murk stops any process left in that group (SIGTERM, then SIGKILL after two seconds). Then murk overwrites the file with zeros and deletes it. The wipe also runs when murk returns an error or unwinds a panic, including editor failure and signals murk catches. SIGKILL, an abort or a power loss skip it. For a single key, an empty value or a non-zero editor exit aborts without saving. In bulk mode a non-zero exit aborts.

The buffer uses `.env` quoting. The bulk buffer has one `KEY=VALUE` line per secret. murk writes a value bare when that is safe, and otherwise in double quotes on one line, with newlines, control characters, invisible characters and whitespace other than a space escaped. Double-quoted values decode `\\`, `\"`, `\n`, `\r`, `\t` and `\u{HEX}`, and single-quoted values are literal.

The single-key buffer has a header that ends with the line `# ---- the value starts below this line ----`. Everything after that line is the value, `#` lines included. The value may be quoted, or pasted as is (trimmed, and it may span lines). `""` sets an empty value.

murk refuses to save a buffer it cannot read (a line without `=`, an invalid or duplicate key, or an unclosed quote), and the error names only the line number. It also refuses to save if the vault file changed on disk while the editor was open.

The wipe is best effort. It cannot undo a write to a journaled or copy-on-write disk, and editors may leave swap files. With `MURK_STRICT` set, `edit` aborts before it starts the editor unless the scratch file is on a RAM-backed filesystem (tmpfs or ramfs). Without `MURK_STRICT`, murk uses the best-effort wipe on any filesystem. A default macOS setup has no RAM-backed temp directory, so strict `edit` fails there. To avoid the editor altogether, pipe values into `add` or `rotate`, or load them from a file with `import`.

---

### `murk export [--tag TAG] [--json] [--allow-reserved] [--vault NAME]`

Prints all secrets as `export KEY=VALUE` statements to stdout. Scoped values override shared values for the current identity. Errors go to stderr. `--tag` filters by tag (repeatable). `--json` outputs JSON instead of shell exports. Both forms skip keys that are not valid shell identifiers.

**Reserved names.** A key named like a variable that changes how a program, its loader, its shell, git or murk runs is refused, and the whole export fails before anything is printed. `--allow-reserved` lifts the refusal. The reserved names are:

- `PATH`, `HOME`, `IFS`, `SHELL`, `ENV`, `BASH_ENV`, `ZDOTDIR`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`, `PS0`–`PS4`, `PROMPT_COMMAND`, `XDG_CONFIG_HOME`, `EDITOR`, `VISUAL`, `PAGER`, `MANPAGER`, `LESSOPEN`, `LESSCLOSE`, `BROWSER`, `SSH_ASKPASS`, `SUDO_ASKPASS`, `NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`, `CLASSPATH`, `GCONV_PATH`, `GLIBC_TUNABLES`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `RUSTFLAGS`, `RUSTDOCFLAGS`, `GOFLAGS`, `MAVEN_OPTS`, `GRADLE_OPTS`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`
- every name starting with `LD_`, `DYLD_`, `GIT_`, `BASH_FUNC_`, `PYTHON`, `PERL`, `RUBY`, `JAVA_`, `_JAVA_`, `JDK_`, `DOTNET_`, `CARGO_`, `RUSTC`, `SSL_`, `PIP_`, `GEM_`, `BUNDLE_`, `NPM_CONFIG_` or `MURK_`
- every name ending in `_PROXY`

murk compares all of them case-insensitively. `NODE_ENV` is not reserved. Whoever can write the vault must not get to run code in the shell that evaluates it, redirect its traffic, or switch off murk's own settings there. `exec`, `agent exec` and the MCP `murk_exec` tool apply the same list. `murk_exec` has no override.

When `MURK_STRICT` is set, `export` refuses to run if stdout is a regular file (e.g. `murk export > .env`), since that persists plaintext secrets to disk. Piping to a process (the direnv flow) and printing to a terminal are still allowed. `get` and `diff --show-values` are guarded the same way. This is a guardrail against accidental redirects, not an airtight control: an explicit `murk export | tee .env` still writes the file.

Primary usage via direnv:

```bash
# .envrc
eval "$(murk export)"
```

---

### `murk exec [--only KEY] [--tag TAG] [--clean-env] [--allow-reserved] [--vault NAME] COMMAND...`

Runs a command with decrypted secrets injected as environment variables. Scoped values override shared values. `--only` injects only the named keys (repeatable), `--tag` filters by tag, `--clean-env` strips the inherited environment so the child sees only murk secrets plus `PATH`, `HOME` and `TERM` on Unix (on Windows, `PATH` and a fixed set of system variables). Reserved names (see `murk export`) are refused unless `--allow-reserved` is passed. On Unix, murk replaces itself with the command via `exec`.

---

### `murk env [--vault NAME]`

Writes a `.envrc` for direnv integration. Creates the file if missing, appends the murk export line if absent, and leaves it untouched when already present.

---

### `murk agent plan [--tag TAG] [--json] [-o FILE] [--vault NAME]`

Emits schema-only context safe to paste into an AI agent prompt: key names, descriptions, examples, and tags. No decryption and no `MURK_KEY` required. The output contains no secret values, recipient pubkeys, vault name, or meta blob. `--tag` filters by tag (repeatable). `--json` outputs JSON. Prints to stdout, or writes to a new file with `-o`. `-o` refuses a path that already exists (a file or a symlink). Without a key the schema is unchecked and the command says so on stderr (see Trust, Header reads).

---

### `murk agent exec --only KEY [--allow-operator-key] [--allow-reserved] [--vault NAME] COMMAND...`

`murk exec` with strict agent-safe defaults: clears the inherited environment, strips `MURK_KEY` so the child process cannot read the vault, and requires explicit `--only` keys (repeatable). Agent mode fails closed: there is no inject-everything path.

The key must be an agent grant key, handed over through `MURK_KEY` or `MURK_KEY_FILE`. An auto-discovered key from `~/.config/murk/keys` is refused before the vault is loaded. Any other key that is a full recipient of the vault, including your own key set through `MURK_KEY` or `MURK_KEY_FILE`, is refused once the vault is open and before any secret is resolved. `--allow-operator-key` lifts both refusals. It prints a warning on every run that decrypts with a non-grant key. A grant key never triggers it.

The child runs supervised, not `exec`-ed: its stdout and stderr are pipes, and every injected value of 4 bytes or more is replaced with `***NAME***` (the secret's name) before it is written out. murk forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to it by another process, and exits with the child's code or re-raises its terminating signal. Reserved names (see `murk export`) are refused unless `--allow-reserved` is passed. See `docs/ai-agents.md`.

---

### `murk agent grant --name NAME --only KEY [--ttl DUR] [--renew] [--out PATH [--force]] [--vault NAME]`

Mints a fresh ephemeral age identity and gives it read access to exactly the `--only` keys (repeatable, required), never the operator's own key. The agent becomes a vault recipient. It gets a private (per-recipient) ciphertext of each `--only` key's shared value and its own record in `agents`. It is excluded from the `everyone` layer and is not a recipient of the meta. murk records grant metadata (scope, TTL, issuer) in the encrypted meta.

murk refuses a name that still has a grant record unless `--renew` is passed. An expired grant keeps its record until the next vault write. `--renew` revokes the existing key and mints the replacement in one vault write. `--ttl` takes a positive number with a unit of `s`, `m`, `h` or `d`, such as `30m`, `2h` or `7d` (default `2h`), at most `365d`. A longer TTL is refused. Reads fail closed after expiry, though the enforcement is binary-level, not cryptographic (see THREAT_MODEL.md).

The agent key is written to `~/.config/murk/agent-keys/<vault-hash>-NAME` (or `--out PATH`, or `--out -` to stream it to stdout). It is always owner-only (`0600`). murk writes it to a temporary file beside the destination and renames it into place only after the vault is saved, so a failed save leaves an existing key file untouched. `--out PATH` refuses a file that already exists (it may be the operator's own key) unless `--force` is passed, and it refuses before the vault changes. The default path is murk's own slot for the grant and is replaced on renewal. The key file is headed by `# murk-trusted-signer:` lines (see Agent grants).

Run the agent with `MURK_KEY_FILE` pointing at that key and `MURK_AGENT=1`. `MURK_AGENT=1` forces strict mode, so the process cannot fall back to the operator's stored key.

---

### `murk agent ls [--json] [--vault NAME]`

Lists active grants: name, truncated pubkey, scope, and TTL status (time remaining, or how long expired). Works offline. `--json` outputs structured data including an `expired` flag.

---

### `murk agent revoke NAME [--rotate] [--values-from FILE] [--vault NAME]`

Removes the grant and its ephemeral recipient (clearing the agent's private ciphertexts).

The handed-off key can still decrypt old `.murk` versions from git history. So murk marks every key it could read as owing a rotation (`revoked_at`), as `circle revoke` does. Those keys are its scope, any key holding a private copy for it, and keys in groups it belonged to. A key is marked if it still has a shared value or a value in one of those groups. `agent grant --renew` marks the previous key's keys the same way.

Rotation is the real close. `--rotate` (or the interactive prompt) re-prompts for a new value for each of those keys, in its own tier. The revoke and the rotated values are written together in one save. So a refused, short, or aborted batch writes nothing, and the grant is not revoked either. The error says how to revoke now and rotate afterwards. Nothing is saved either if the vault file changed on disk while murk waited for the values (see `murk rotate`). `--values-from FILE` supplies the values by name, as for `murk rotate`.

---

### `murk agent init --name NAME --only KEY [--allow-tag TAG] [--ttl DUR] [--out PATH [--force]] [--vault NAME]`

One-step onboarding. With `--allow-tag` (repeatable), it first sets the agent allow-list, as `murk policy set` does. Then it mints a grant as `murk agent grant` does, with the same `--name`, `--only`, `--ttl`, `--out` and `--force` rules. When it writes a key file, it prints the command to run the agent with that key and a note to run the agent as an identity that cannot read `~/.config/murk`.

---

### `murk agent connect [CLIENT] --only KEY [--allow-tag TAG] [--allow-exec] [--allow-get] [--ttl DUR] [--name NAME] [--vault NAME]`

Adds a `murk mcp` server entry to an AI client's MCP config and mints a grant for it. `CLIENT` is one of `claude`, `cursor`, `vscode`, `zed`, `gemini`, `omp` or `codex`. Without it, connect configures every client that already has a config file or marker directory (such as `.cursor/`) next to the vault, and fails when it finds none. `--name` defaults to `mcp`. `--allow-tag` sets the allow-list before the grant is minted. `--allow-exec` writes `--allow-exec` into the server entry, which enables `murk_exec`, and `--allow-get` writes `--allow-get`, which enables `murk_get`. A non-default vault is passed to the server with `--vault`.

A second connect with the same `--name` reuses the grant when `--only` names the same keys, and refuses when the scope differs. It also refuses when the grant exists but its key file is gone. connect renders every config before it changes anything, so a config it cannot parse or that is a symlink fails before a grant is minted. If a write fails after that, connect restores the configs it already wrote and revokes the grant it minted in this run. A grant key cannot run connect. See `docs/ai-agents.md` for each client's config path.

---

### `murk agent disconnect [CLIENT] [--rotate] [--name NAME] [--vault NAME]`

Removes murk's server entry from an AI client's MCP config. Without `CLIENT`, it removes the entry from every client config it knows. The grant stays live unless you pass `--rotate`, which then runs `murk agent revoke NAME --rotate` for the grant named by `--name` (default `mcp`). With `--rotate`, a grant key is refused before any config changes. Exits 1 if any config could not be changed.

---

### `murk mcp [--allow-exec] [--allow-get] [--vault NAME]`

Runs an in-process MCP (Model Context Protocol) stdio server so AI-agent harnesses can read murk secrets on the capability-not-credential model. It calls the murk-cli library directly, with no subprocess and no Node. It fails closed unless the loaded identity is a scoped agent grant with `MURK_AGENT=1`. It refuses to start with the operator's stored key, a plain recipient, or no grant. stdout is the JSON-RPC channel (never written to otherwise). All logs go to stderr.

Before every tool call the server hashes the vault file (BLAKE3). When the bytes changed, it loads those bytes again through the full load path with the grant key it started with, and uses the new state only if that load passes; any failure fails the call. A revoke, a policy change or a tampered file therefore applies to the next call.

Tools, all bounded to the grant:

- `murk_plan`: the schema (key names, descriptions, examples, tags) of the secrets this grant may read, as JSON, with an optional `tags` filter. No values, and no keys outside the grant's scope or the agent policy.
- `murk_get { key }`: opt-in via `--allow-get` (off by default), because the value enters the model's context. One secret value, if the grant may read it. A forbidden or out-of-scope key returns an error result, never the value. Without the flag the tool is not listed, and a call returns an error that names `--allow-get`.
- `murk_exec { only, command }`: opt-in via `--allow-exec` (off by default). Runs a command with the named secrets injected into its environment (no shell), returning captured stdout/stderr and the exit code. Every key must be in scope and policy-allowed, and output and runtime are bounded. `only` scopes the injected secrets, not the command, so it is not a sandbox.

See `docs/ai-agents.md` for setup (`murk agent init`) and a verify snippet.

---

### `murk import [FILE] [--force] [--group NAME] [--example EX] [--vault NAME]`

Imports secrets from a `.env` file (default `.env`). Each entry is `KEY=VALUE`, optionally prefixed with `export `. Bare values are taken literally and trimmed. Double-quoted values decode `\\`, `\"`, `\n`, `\r`, `\t` and `\u{HEX}`, single-quoted values are literal, and both may span lines. A bare value that contains ` #` keeps the `#` as part of the value, and murk prints a notice for that line. An unclosed quote aborts the import with nothing imported.

murk skips every `MURK_*` name, lines without `=` and invalid key names, with a notice that gives the line number and never the value. If a key appears twice, murk keeps the later value and prints `line N: KEY is already set on line M; the later value is kept`, again without the value. If keys already exist, murk refuses the import unless you give `--force`.

`--example` sets the same example on every imported key, replacing an existing one. `--group` assigns all imported secrets to a tier (`everyone`, `me`, or a named group), as for `murk add`. Without `--group`, each existing key keeps its tier and new keys are shared. If murk refuses any key (for example, a key that a group you are not a member of holds), it imports nothing.

---

### `murk info [--tag TAG] [--json] [--vault NAME]`

Prints the public schema. Works without `MURK_KEY`. With a valid key, also shows recipient names and count. `--tag` filters by tag (repeatable). `--json` outputs JSON.

Each key's row shows any rotation interval and expiry as a trailing `rotate 90d  expires 2026-09-01` segment (public, shown without a key). `--json` includes `rotation_interval_days` and `expires_at` per entry. `murk doctor` evaluates these against the clock, and `info` just shows the policy. Without a key none of it is integrity-checked, and `info` says so on stderr (see Trust, Header reads).

---

### `murk recover`

Prints the BIP39 24-word recovery phrase for the key murk resolves: `MURK_KEY`, `MURK_KEY_FILE` or the stored key for the default vault. Age keys only. It errors on an SSH key or a plugin identity.

---

### `murk restore [--vault NAME]`

Derives the secret key from a BIP39 recovery phrase and prints it to stdout. It saves nothing. Prompts for the phrase interactively (hidden input) or reads from stdin when piped. When the vault (`--vault`, default `.murk`) is readable and the restored key is not one of its recipients, murk warns that the phrase may be wrong. The warning never fails the restore.

---

### `murk circle [--json] [--vault NAME]`

Lists all recipients. With `MURK_KEY`, shows display names from the encrypted meta and marks the current user with `◆`. `--json` prints an array of objects with `pubkey`, `name` and `is_self`.

---

### `murk circle authorize PUBKEY [--name NAME] [--group NAME] [--force] [--allow-ssh-rsa] [--vault NAME]`

Adds a new recipient. Re-encrypts all shared secrets to include the new public key. Accepts `age1...`, `ssh-ed25519 ...`, `ssh:PATH` (the first line of an SSH public key file), `ssh:` (`~/.ssh/id_ed25519.pub`) or `github:username`. With `--group`, also adds the new recipient(s) to that group in the same step (you must be a member of the group). murk refuses `ssh-rsa` recipients, however the key is spaced or commented, unless you pass `--allow-ssh-rsa` (see RUSTSEC-2023-0071). For `github:username`, it skips RSA keys with a warning and refuses only when every key is RSA. When a GitHub user's keys differ from the pinned set (see `github_pins` under Meta), authorize stops unless you pass `--force`.

---

### `murk group create NAME [--vault NAME]`

Creates a new named recipient group, seeded with you as its first member so you can always read and re-encrypt it. Reserved names (`everyone`, `me`, `all`, `self`, `mine`, `shared`) are rejected.

---

### `murk group ls [--json] [--vault NAME]`

Lists groups and their members, resolved to display names. The current user is marked with `*`. Requires `MURK_KEY` to decrypt membership. An agent grant cannot open the meta, so it lists no groups and warns on stderr that a grant cannot read group membership.

---

### `murk group add NAME --member RECIPIENT [--vault NAME]`

Adds a recipient (by pubkey or display name) to a group. You must already be a member. The group's secrets are re-encrypted to include the new member on save.

---

### `murk group rm NAME [--member RECIPIENT] [--vault NAME]`

With `--member`, removes a recipient from the group and re-encrypts its secrets so the removed member loses access to current values. Git history stays readable, so each of the group's secrets is marked as owing a rotation (`revoked_at`) and listed. `murk rotate --list` and `doctor` flag them until they are rotated. Without `--member`, deletes the group entirely. The delete is refused if any secret is still assigned to the group. You must be a member to modify or delete a group.

---

### `murk policy show [--json] [--vault NAME]`

Prints the agent access policy. Works without a key, because the policy is in the plaintext header. Without a key it is unchecked, and the command says so on stderr (see Trust, Header reads). Shows the allowed tags, or notes that agent mode is unrestricted (no policy) or locked out (empty allow-list).

---

### `murk policy set --allow-tag TAG... [--vault NAME]`

Sets the agent allow-list: in agent mode (`agent exec`, `agent grant`) a secret may be injected or granted only if it carries one of these tags. `--allow-tag` is repeatable and required. Default-deny once set. Writes the policy into the header, where the MAC and signature cover it.

---

### `murk policy clear [--vault NAME]`

Removes the policy. Agent mode becomes unrestricted again.

---

### `murk circle revoke RECIPIENT [--rotate] [--values-from FILE] [--force] [--vault NAME]`

Removes a recipient by pubkey, display name or `github:username`. Re-encrypts all shared secrets without their key. Removes their private entries. murk refuses to revoke your own key, whether you name it directly or through your display name, before it prompts or writes anything. Another recipient has to revoke you. When the name covers several keys (a GitHub user with more than one key), murk lists them and asks before it revokes them all. Without a terminal it refuses unless you pass `--force`.

An agent grant's key file trusts the signers recorded in the grant (`anchors`) when it was minted, and nothing updates a key file afterwards. So revoking a recipient also revokes:

- every agent grant whose anchors name that key,
- every grant with no recorded anchors (minted before they were recorded, or emptied by a meta writer), because an unknown anchor is treated as trusting every signer, and
- a grant whose key file in this machine's agent-key slot trusts the revoked key, even if its recorded anchors were trimmed.

Revoking a grant's own key never revokes other grants. Each such grant's scope is marked as owing rotation, like after `murk agent revoke`. murk deletes the grant's key file in its own slot and tells you to delete any other copy and re-mint the grant.

murk cannot reach the other copies: one written with `--out`, handed to the agent host, or made on another operator's machine. Such a copy still trusts the revoked key. It accepts a vault signed by that key, including one built from a copy of the vault from before the revoke that still carries the grant, and the agent reads that signer's values.

A copy that carries `murk-grant-expires` stops working at that expiry, whatever the vault's record says (see Agent grants). A copy without it (minted before murk wrote the line, or a bare key line) is bounded only by the record, which that signer can rewrite. Deleting every copy and re-minting the grant closes it sooner. murk also prints the revoked key's trusted-signer entry, to remove from `MURK_TRUSTED_SIGNERS` in CI and anywhere else it is set.

Lists the secrets the revoked recipient had access to.

With `--rotate`, murk prompts for a new value for each value they could read, in the same session, and re-encrypts it in its own tier. The shared value stays shared. A value in a group they belonged to stays in that group, encrypted to its remaining members. Values they could not read (other groups, your personal overrides) are not prompted for.

A group value the revoked recipient could read but you cannot (you are not in that group) cannot be re-encrypted by you. Its current ciphertext still opens with their key until a member of that group rotates it. The revoke says so, and the key keeps its pending-rotation marker. A key they reached only through their own personal override is not marked, since nothing of it is left to rotate.

The revoke and the rotated values are written together in one save. So input that is refused, runs short, or is aborted writes nothing, and the recipient is not revoked either. The error says how to revoke now (`murk circle revoke RECIPIENT` without `--rotate`) and rotate afterwards (`murk rotate --all --values-from FILE`). Nothing is saved either if the vault file changed on disk while murk waited for input (see `murk rotate`). Piped values and `--values-from FILE` follow the rules of `murk rotate`. Keys `--values-from` does not name stay marked, and `murk rotate --list` keeps listing them.

Without the flag on an interactive terminal, murk offers to rotate. Otherwise it prints a hint. The recipient can still decrypt previous versions from git history, so rotation is the only way to close the exposure.

---

### `murk diff [REF] [--show-values] [--json] [--vault NAME]`

Shows which secrets changed between the current vault and a git ref (defaults to `HEAD`), and what changed in who can read or sign it: recipients added or removed, a changed signer, a changed signing key for a recipient, the policy, agent grants and group members. `--show-values` prints the actual values, not just key names. `--vault NAME` selects the vault file (default `.murk`, or `MURK_VAULT`).

The human output prints the structural lines first, one per change, then one line per secret, sorted by key. Every warning goes to stderr before either, and `no changes` goes to stderr when there is nothing to show.

```
+ recipient bob@example.com (age1wzsw…8ns8)
~ policy
+ group ops member alice@example.com (age1y8ne…rqke)
- API_KEY
~ DATABASE_URL
+ NEW_TOKEN
```

A secret line is `+ KEY` (added), `- KEY` (removed) or `~ KEY` (changed). With `--show-values` it is `+ KEY = value`, `- KEY = old value` and `~ KEY old → new`. A value is written the way `murk edit` writes one: bare when that reads back unchanged, double-quoted with control and invisible characters escaped otherwise, so it is always one line.

A structural line is one of these:

- `+`/`- recipient NAME (key)`
- `~ signer OLD → NEW` (`unsigned` when a side has no signature)
- `~ signing key of RECIPIENT → SHA256:…`
- `~ policy`
- `+ grant NAME (RECIPIENT)` for a new grant, `~ grant NAME (RECIPIENT)` for a changed one, and `- grant NAME` for one that is gone
- `+`/`- group NAME member RECIPIENT`

A recipient is shown as `name (age1abcd…wxyz)`, the display name with the key shortened to its first 8 and last 4 characters, or as the shortened key alone when it has no name. Every vault-supplied string (key, group, display and grant names, values) is escaped before it reaches the terminal.

`--json` prints one pretty-printed object, `{"changes": [...], "secrets": [...]}` (object keys sorted). Both arrays are always present.

Each `secrets` entry has `key` and `kind` (`added`, `removed`, `changed`). With `--show-values` it also has `old_value` and `new_value`. They are `null` for the side that has no value (`old_value` of an added secret, `new_value` of a removed one). Entries are sorted by key.

Each `changes` entry has `kind` and `op` (`added`, `removed`, `changed`) and never carries a secret value. A `signer`, `signing_key` or `policy` entry always has `op` `changed`. Each `kind` has these fields:

| `kind` | Fields |
|--------|--------|
| `recipient` | `key`, `name` |
| `signer` | `from`, `to` (public keys; `null` for unsigned) |
| `signing_key` | `key`, `name`, `to` (the new verifying key's `SHA256:` fingerprint) |
| `policy` | none |
| `grant` | `name`, `key` (`null` when removed) |
| `group_member` | `group`, `key`, `name` |

JSON strings are exact (JSON escapes control characters). Escaping for the terminal applies only to the human output.

Values follow the agent policy as `get` and `export` do. The policy applies when the key in use is an agent grant, or self-scope is on (`MURK_AGENT` or `MURK_SELF_SCOPE` turns it on), and the vault has a policy. Then a key the current vault's policy forbids is still listed as added, removed or changed. `--show-values` shows neither of its values (in `--json`, the entry has no `old_value` or `new_value`), and stderr names the keys withheld. That holds at a ref where the vault did not exist, where every secret shows as added.

`diff` runs on a working vault this machine does not trust yet, because it is the review step before `murk trust`. It says so on stderr. It still fails on a broken MAC or signature.

The vault at the ref is verified before anything in it is decrypted. murk checks its MAC and signature as a load does, then its signer against the local trust pin, which is read and never extended. The signer must be one this machine ever trusted, with its pinned verifying key, so a teammate revoked since still verifies for the revisions they signed.

When this machine has a trust pin for the vault or `MURK_TRUSTED_SIGNERS` is set, `diff` exits non-zero rather than show a revision that is refused, that fails verification, or that your key cannot decrypt. With neither, the revision is shown under the same "not trusted on this machine" warning as the working vault.

An unsigned revision is shown with a warning that its integrity rests on git in two cases:

1. Your key cannot sign (an ssh-rsa, hardware or plugin key) and `MURK_TRUSTED_SIGNERS` is unset.
2. The revision is from before 0.14 (no vault id).

Under `MURK_STRICT` the "not trusted on this machine" case is refused instead, and so is the second case unless the first also applies.

`diff` also exits non-zero when the ref does not name a commit or git fails. The vault path is resolved inside the repository that holds it, so `diff` works from a subdirectory. Only a vault that git shows is absent from the ref (or a repository with no commits yet) counts as empty, and then every secret shows as added. A ref that starts with `-` is refused, so it can never reach git as an option.

---

### `murk merge-driver BASE OURS THEIRS [PATH]`

Git merge driver for `.murk` files, called by git (the command is hidden from help). git supplies the three paths (`%O`, `%A`, `%B`) and the vault's path `%P`. The result replaces OURS. It merges non-conflicting secret changes automatically.

**With a key** (`MURK_KEY`, `MURK_KEY_FILE`, or the stored key for a vault named `.murk`, which strict and agent mode do not look up), the driver checks both sides against the trust pin of `PATH` (git's `%P`, default `.murk`). It refuses an untrusted side as a conflict, regenerates the meta and signs the merged result. A keyed merge that would be numbered above 2^53 − 1 exits 1 and writes nothing, so the working file stays OURS (Trust, rule 9).

**Without a key**, the driver merges cleanly only when the merge changed nothing the meta covers. In each of these cases it exits 1 and writes nothing (when there are no merge conflicts):

- the merged secrets, recipients, schema or policy differ from OURS,
- THEIRS changed the encrypted meta (groups, grants, GitHub pins or signers),
- THEIRS' `generation` or `vault_id` differs from both BASE and OURS, or
- the merged `generation` is above 2^53 − 1.

Then you abort the merge and redo it with a key. A clean keyless merge keeps OURS' meta and MAC, is unsigned until a keyholder's next write or `murk trust`, and warns that the meta was not regenerated. See Signatures.

---

### `murk setup-merge-driver`

Configures git to use `murk merge-driver %O %A %B %P` for `.murk` files via `.gitattributes` and `.git/config`.

---

### `murk verify [--vault NAME]`

Verifies vault integrity (MAC and signature), reports whether this machine trusts the signer and why not (the same reasons a load refuses with), checks who signed the last git commit that touched the vault, and runs safety checks without exporting secrets. Exits 1 on any finding.

**Commit check.** Only when the vault has git history. A signed commit proves nothing about who the signer is: git vouches for any key it is told about, an attacker's throwaway key included.

So verify reports the commit as ok only when git verified the signature and the signing key is a trusted signer of this vault. The key must be an ssh-ed25519 key in the set the Trust rules used (`MURK_TRUSTED_SIGNERS` and a grant key file's anchor when either is given, otherwise the pin's trusted set, and grant keys never count), matched by its `ssh-keygen -l` fingerprint. Only an ssh-ed25519 key can match, because it is the only key type that both signs git commits and is a murk signer. The line then reads `ok commit  last .murk commit signed by <name> with key <fingerprint>, a trusted signer of this vault`. Every other outcome is a finding, and exits 1:

- **Signed by another key**: a gpg key, or an ssh key that is not a trusted signer. The message is `signed by key <id>, which is not a trusted signer of this vault`, naming the recipient when the key is one. The vault's own recipients are not trusted by being listed. Trust comes from the pin or the environment.
- **Not vouched for by git**: the signature could not be checked, has expired, or was made with an expired key.
- **Bad**: the signature does not match the commit, or the key is revoked in the user's `gpg.ssh.revocationFile`.
- **Unsigned.**

verify runs git with `gpg.ssh.allowedSignersFile` set to a temporary file listing the trusted ssh-ed25519 signers, so the result does not depend on the user's own allowed-signers list. Without one git cannot check an ssh signature and reports a signed commit as unsigned.

---

### `murk trust [--yes | --print-key] [--re-add KEY]... [--vault NAME]`

Shows who signed the vault, then asks before it records the vault in the local trust pin. It shows:

- the signer's name, full key and signing-key fingerprint, marked trust on first use when this machine has not confirmed it,
- the vault's id and counter, and
- every recipient with its fingerprint and its change since this machine last trusted the vault.

`--yes` accepts without asking. Without a terminal and without `--yes`, it only shows and exits 1.

- An unsigned or stripped vault is re-signed with your key.
- A murk 0.13 vault that is read-only here (a branch with no 0.14 mark, after this machine saw the vault in 0.14 form) is accepted without re-signing. `murk trust` records only that exact copy's fingerprint for the branch, and the next write upgrades it. See Trust, rule 6, Read-only copy.
- murk refuses a vault signed by an agent grant, with a changed signing key or with a generation past the limit. It refuses an unsigned pre-0.14 file of another vault, and it refuses to run with a grant key.
- A vault signed by or listing a key this machine recorded as removed is trusted only when `--re-add` names each such key (its public key or its name in the vault).

`--print-key` prints your own trusted-signer entry to stdout (`age1…:<verifying key>`, or the ssh-ed25519 key line) and your fingerprint to stderr, then exits. See Trust.

---

### `murk doctor [--vault NAME]`

Checks the surrounding repo for hygiene issues: inline keys in `.env`, key files sitting next to the vault, state that would be bad to commit. If a vault is present it also reads the plaintext schema and reports keys overdue for rotation or past/near their `expires_at`. That read is never integrity-checked. With no key `doctor` says so on stderr (see Trust, Header reads), and with one it still does not load the vault, so use `murk rotate --list` or `murk verify` where the result must be trusted. Exits 1 on findings.

---

### `murk skeleton [-o FILE] [--vault NAME]`

Exports a schema-only copy of the vault: key names, descriptions, examples, and tags, with no secrets and no recipients. Prints to stdout, or writes to a new file with `-o`. `-o` refuses a path that already exists (a file or a symlink).

---

### `murk scan [PATHS]... [--vault NAME]`

Scans files for leaked secret values. Decrypts the vault and searches text files under the given paths (defaults to the current directory) for value substrings. Skips hidden directories, `target/` and `node_modules/`, files ending in `.lock` or `.murk`, and unreadable or binary (non-UTF-8) files. It ignores values shorter than 8 bytes to avoid false positives. Exits 1 if any leak is found. A given path that does not exist or cannot be read exits 2 before scanning. A file or directory under it that cannot be read is reported, and the scan exits 1 as incomplete instead of reporting no leaks.

---

### `murk completion generate|install SHELL`

Prints shell completions to stdout (`generate`) or installs them to the shell's standard completion path (`install`). Supports bash, zsh, fish, elvish, and powershell.

---

## Security Model

**What murk protects against:**

- Repo leaks: `.murk` is safe to commit and useless without a private key.
- Accidental secret exposure: `.env` is never committed if `.gitignore` is set correctly.
- Private overrides: private secrets (motes) are encrypted only to their owner.
- A repo-writer replacing the vault. murk refuses these cases:
  - A vault signed by a key the writer listed as a recipient, unless its signer is trusted on this machine.
  - Another vault's file, by its id, unless both vaults were copied from one 0.13 vault and share it (see Vault identity).
  - An older revision, on a branch where this machine has a counter mark.
  - An unsigned vault, when the loading key can sign. A key that cannot sign (ssh-rsa, hardware or plugin) loads it with a warning instead, unless `MURK_TRUSTED_SIGNERS` is set (see Trust).

  A murk 0.13 revision has no counter, so murk refuses it only where that mark is above 0. Elsewhere it loads as history. Once this machine has seen the vault in 0.14 form, every write over it is refused until `murk trust` accepts that copy (see Trust, rule 6, Read-only copy).

**What murk does not protect against:**

- A compromised machine that holds your key. The normal key is a key file (`MURK_KEY_FILE`, written by `murk init`). `MURK_KEY` is the inline option.
- Historical access after revocation: old `.murk` versions remain in git history. Always rotate credentials when revoking.
- Fine-grained audit logging: use a secrets server for regulated environments.
- Malicious recipients: any authorized recipient can decrypt all shared secrets.

**Treat your key like your SSH private key.** Never commit it. Never share it. This holds for a key file and for `MURK_KEY`.

**Revocation is incomplete without credential rotation.** murk always warns about this.

### Scope

murk is appropriate for dev tooling and small teams. It is not designed for regulated environments requiring audit trails, key management infrastructure, or provable access controls.

---

## Crate Dependencies

Main dependencies. `Cargo.toml` has the full list:

- `age`: encryption (the `age` crate from the rage project)
- `bip39`: recovery phrase generation
- `serde` / `serde_json`: serialization
- `clap`: CLI argument parsing
- `blake3`: keyed integrity hashing and signing-key derivation
- `ed25519-dalek`: vault signatures
- `ssh-key`: parses OpenSSH ed25519 private keys for signing
- `sha2`: the `<vault-hash>` in key paths, the `<hash>` in pin paths, key fingerprints, and legacy integrity hashes (backward compatibility)
- `chrono`: timestamps
- `colored`: terminal output
- `rpassword`: hidden input prompting
