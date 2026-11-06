# @interrupted/murk-secrets

[![npm](https://img.shields.io/npm/v/@interrupted/murk-secrets)](https://www.npmjs.com/package/@interrupted/murk-secrets)

> **Experimental writes.** Reading secrets (`load`, `get`, `exportAll`) is stable. Writing (`add`, `describe`) is experimental: the write API is new and may change. See [Feature status](https://murk.interrupted.sh/reference/feature-status/).

Node.js/TypeScript bindings for [murk](https://github.com/interrupted-sh/murk), an encrypted secrets manager for developers.

## Prerequisites

You need the [murk CLI](https://murk.interrupted.sh/install/) to create and manage vaults. This package can read them and store secrets into them. Trust-changing operations (rotation, recipient and group changes, agent grants) stay CLI-only.

```bash
# Install the CLI first
brew install interrupted-sh/tap/murk

# Initialize a vault and add secrets
murk init
murk add DATABASE_URL
murk add API_KEY
```

Then add the Node package to your project:

```bash
npm install @interrupted/murk-secrets
```

## Quick start

```bash
# Optional on the machine that ran murk init (see "Key lookup").
# POSIX shell syntax.
source .env
```

```typescript
import { load, get, exportAll, add } from '@interrupted/murk-secrets'

// Load the vault (finds your key; see "Key lookup")
const vault = load()

// Get a single secret
const dbUrl = vault.get('DATABASE_URL')

// Get all secrets as an object
const secrets = vault.export()

// One-liners
get('DATABASE_URL')
exportAll()

// Store a secret (encrypted to everyone by default)
vault.add('NEW_TOKEN', 'value')
vault.add('MY_TOKEN', 'value', { tier: 'me' })        // a private value, encrypted to you only
vault.add('TEAM_TOKEN', 'value', { tier: 'backend' }) // to a named group
add('NEW_TOKEN', 'value')                             // one-liner
```

## API

### `load(vaultPath?: string): Vault`

Load and decrypt a murk vault. Finds your key as described in [Key lookup](#key-lookup).

### `get(key: string, vaultPath?: string): string | null`

One-liner: load the vault and get a single value.

### `exportAll(vaultPath?: string): Record<string, string>`

One-liner: load the vault and export all secrets as an object.

### `add(key: string, value: string, options?: AddOptions, vaultPath?: string): void`

One-liner: load the vault and store a secret. See `vault.add` in [Writing secrets](#writing-secrets).

### `hasIdentity(): boolean`

Returns `true` if murk can find a key for `./.murk`: `MURK_KEY`, `MURK_KEY_FILE` or the key file `murk init` stored. Returns `false` if no key is found, if both variables are set, or if the key file cannot be read. It does not read the vault, so `true` does not guarantee that `load()` succeeds. It does not check whether a secret exists. Use `vault.has(key)` or `vault.keys()` for that.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `string \| null` | Decrypted value, or `null` if no value is readable for the secret |
| `vault.export()` | `Record<string, string>` | All secrets as an object |
| `vault.keys()` | `string[]` | Names of all secrets in the vault schema, including secrets you cannot read |
| `vault.has(key)` | `boolean` | `true` if the secret is in the schema, even if you cannot read its value |
| `vault.length` | `number` | Number of secrets in the schema |
| `vault.add(key, value, options?: AddOptions)` | `void` | Store a secret (see below) |
| `vault.describe(key, description, options?: DescribeOptions)` | `void` | Set a secret's description, tags or example |
| `vault.warnings` | `string[]` | Warnings about an accepted vault, the ones the CLI prints as `warn …` (empty for a clean load) |

`get()` and `export()` pick a value in this order: your private value, then a group value you can read, then the shared value. A private value is one you added with the `me` tier (`murk add KEY --group me`).

### Trust

Every call that reads the vault (`load`, `get`, `exportAll`, `add`, `vault.add`, `vault.describe`) applies the same trust check as the CLI. The check refuses a vault that this machine does not trust. That means a vault that is unsigned when your key could have signed it, signed by a key this machine has not accepted, rolled back, or tampered with. The binding throws an `Error` whose `code` is `'MURK_TRUST'`, with the CLI's message. Nothing in the binding skips the check.

To accept a vault, run `murk trust` once from a shell. In CI, set `MURK_TRUSTED_SIGNERS` to the signers you allow. Set it only from a CI secret or the real process environment, never from a file in the repository or a `.env` that an app's dotenv loader reads, because it decides which signers this machine trusts.

The binding reads `MURK_TRUSTED_SIGNERS` from the process environment. An app that calls `dotenv.config()` before `load()` lets a repository `.env` choose the trust anchor. The CLI does not read `.env` itself.

An agent grant key reads only through the trusted signers in its key file or `MURK_TRUSTED_SIGNERS`.

### Writing secrets

`vault.add(key, value, options?)` works like `murk add`. It encrypts the value, signs the vault when your key can sign, and writes it back to disk under an exclusive lock, so concurrent writers are safe. The loaded `Vault` refreshes, so later reads on the same handle see the write. A secret name must start with a letter or underscore and contain only `A-Z`, `a-z`, `0-9` and `_`.

`options` is an `AddOptions` object. All fields are optional:

- `tier`: where the value lives (see below).
- `desc`: a human-readable description recorded in the schema.
- `tags`: tags recorded on the secret. Tags are the unit the agent allow-tag policy gates on.

`tier` is one of:

- `'everyone'`: encrypted to every recipient except agent grants.
- `'me'`: a private value, encrypted to you only.
- A group name: encrypted to that group's members. You must be a member.

Omit `tier` to keep an existing secret in its tier. A new secret is shared. You cannot update a secret held by a group you are not a member of, except with `'me'`. A secret that holds only other recipients' private values needs an explicit `tier`.

`tier` accepts aliases. `'all'` and `'shared'` mean `'everyone'`. `'self'` and `'mine'` mean `'me'`. These six names are reserved and cannot name a group. Matching is case-sensitive, so `'Everyone'` names a group. Any other string names a group. A misspelled tier fails with `group not found` unless a group with that name exists.

An `everyone` or group write replaces the secret's base value. A group write removes the shared value, and a shared write removes the group assignment. A `me` write leaves the shared value alone. `tags` are added to the secret's existing tags.

`vault.describe(key, description, options?)` works like `murk describe`, without `--rotate-every` and `--expires`. It never touches the value and always replaces the description. `options` is a `DescribeOptions` object with two optional fields:

- `tags`: replaces the existing tags when it is non-empty.
- `example`: the example value. Leaving it out clears the current example.

If the secret does not exist yet, `describe` creates a documented entry with no value.

Trust-changing operations (rotation, adding or removing recipients or group members, and minting agent grants) are deliberately **not** exposed here. Use the CLI for those.

## Memory hygiene

Every decrypted value murk returns is a plain JavaScript string. murk zeroes plaintext from its own memory when a value is dropped. That guarantee ends at the FFI boundary. Once a value crosses into JavaScript, the runtime owns it, and its garbage collector controls its lifetime, not murk. This is inherent to reading secrets into a process (see the [threat model](https://github.com/interrupted-sh/murk/blob/main/THREAT_MODEL.md)). Avoid holding decrypted values longer than you need them.

The write path makes this sharper. To call `vault.add(key, value)`, you already hold the plaintext as a JavaScript string before the call. It lives in V8's heap, is copied across the FFI boundary into a Rust `String`, and is zeroized on neither side. Reads only expose plaintext that murk itself produced during decryption. With a write, the plaintext starts in your process and lingers there under the garbage collector's control. Build the value as late as possible, pass it straight into `add`, and do not keep it around.

## Agent policy

If the loaded key is an agent grant (from `murk agent grant`), the bindings enforce the vault's agent policy on reads, as `murk agent exec` does.

- `get()` and `export()` throw when the policy forbids a secret they can read.
- A grant key cannot write at all. `add()` and `describe()` throw `agent grants are read-only` and leave the vault unchanged, whatever the policy says.
- A plain operator key skips the policy check unless `MURK_SELF_SCOPE` or `MURK_AGENT` is set. With either set, `add()` and `describe()` check the resulting secret against the policy before saving. A forbidden write throws and leaves the vault unchanged.
- `keys()`, `has()` and `length` read only the schema. They never check the policy.
- A grant cannot decrypt out-of-scope secrets, because its key is not a recipient of them. The policy check is a second guard.

`get()` and `export()` use the values and policy from the vault's last load. Policy changes and revocations reach them only after you call `load()` again or write through the handle. `add()` and `describe()` reload the vault from disk first, so they always check the current policy. They refresh the handle afterwards.

Expiry is different. Once the grant's TTL has passed, a fresh `load()` fails. A handle loaded earlier fails on `get()` and `export()`.

## Key lookup

`load()` finds your key the same way the CLI does:

1. `MURK_KEY` (your age secret key) or `MURK_KEY_FILE` (the path to a key file). Set one, not both. murk refuses to load when both are set.
2. The key file that `murk init` stored under `~/.config/murk/keys/`. murk finds it by the vault's path, so a key stored for `.murk` does not open a vault at another path.

`murk init` also writes a `.env` that points `MURK_KEY_FILE` at that file. On the machine where you ran `murk init`, you do not need to source it. Set the variable yourself in CI, in containers and whenever `MURK_STRICT` or `MURK_AGENT` is set, because both turn off step 2.

## Errors

Every failure throws an `Error`. When the trust check refuses the vault, its `code` is `'MURK_TRUST'` (see [Trust](#trust)). Every other error has `code` `'GenericFailure'`. The other causes are:

- No key is found. See [Key lookup](#key-lookup).
- Both `MURK_KEY` and `MURK_KEY_FILE` are set.
- The vault file is missing or invalid. The bindings read `.murk` unless you pass a path. They ignore `MURK_VAULT`, so pass `vaultPath` for any other file.
- The agent policy forbids a read or a write. See [Agent policy](#agent-policy).
- A write names an invalid secret or an unknown group.
- The binding is too old for the vault. See [Unsupported vault version](#unsupported-vault-version).

### Unsupported vault version

murk 0.14 saves vaults in format 3.0. A binding older than 0.14 cannot read a 3.0 vault. It throws a plain `Error` with `code` `'GenericFailure'`, not `'MURK_TRUST'`, because the vault is unsupported, not untrusted. A 0.13 binding says:

```text
vault parse error: unsupported vault version: 3.0. This build of murk supports version 2.x
```

The fix is to upgrade the package:

```bash
npm install @interrupted/murk-secrets@latest
```

From 0.14.1, the message also names the binding and the versions it supports. For a vault with version 99.0, a 0.14.1 binding says:

```text
vault parse error: unsupported vault version: 99.0. murk-secrets node binding 0.14.1 supports vault versions 2.x and 3.x
```

## Requirements

Node.js 18.17 or later on Node 18, or 20.3 or later (not Node 19), the murk CLI, a `.murk` vault in your project and a key (see [Key lookup](#key-lookup)). The addon needs Node-API version 9.

Prebuilt addons cover these platforms:

- macOS on Intel (x64)
- macOS on Apple silicon (arm64)
- Linux x64 (glibc)
- Linux x64 (musl)
- Linux arm64 (glibc)
- Linux arm64 (musl)
- Windows x64

## License

MIT OR Apache-2.0
