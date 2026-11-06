---
title: Library bindings
description: Read murk secrets from Python and Node.js, and write them from Node.js.
sidebar:
  order: 4
---

murk ships Python and Node.js bindings so a program can read its secrets
without shelling out to the CLI. They are published as
[`murk-secrets`](https://pypi.org/project/murk-secrets/) on PyPI and
[`@interrupted/murk-secrets`](https://www.npmjs.com/package/@interrupted/murk-secrets) on
npm.

Both bindings load and decrypt an existing vault. The Node binding can also
store secrets and their descriptions, like `murk add` and `murk describe`.
The Python binding is read-only. Rotation, recipient and group changes, and
agent grants stay in the [CLI](/reference/cli/). Use a binding when a program
needs secrets in memory. If it only needs them as environment variables, use
`murk exec`.

## Prerequisites

The bindings work on a vault the CLI made, so first you need:

1. The [murk CLI](/install/).
2. A `.murk` vault: run `murk init`, then `murk add KEY` for each secret.
3. A key the bindings can find. They look in this order:
   - `MURK_KEY` (your age secret key) or `MURK_KEY_FILE` (a key file path).
     Set one, not both: murk refuses to load when both are set.
   - The key file `murk init` stored under `~/.config/murk/keys/`. murk finds
     it by the vault's path, so a key stored for `.murk` does not open a vault
     at another path.

`murk init` also writes a `.env` that points `MURK_KEY_FILE` at that file. On
the machine where you ran it, you do not need to source it. Set the variable
yourself in CI, in containers and whenever `MURK_STRICT` or `MURK_AGENT` is
set, because both turn off the stored-key lookup. See
[Environment variables](/concepts/env-vars/).

Both packages ship prebuilt native binaries with release provenance. See
[Verifying releases](/security/verifying/) to check it.

## Python

Requires Python 3.9 or later.

```bash
pip install murk-secrets
```

The package is `murk-secrets`. You import it as `murk`.

```python
import murk

# Load the vault (finds your key as described above)
vault = murk.load()

db_url = vault.get("DATABASE_URL")   # str | None
secrets = vault.export()             # dict[str, str] of everything you can read
api_key = vault["API_KEY"]           # dict-style access, raises RuntimeError if the secret is not readable

stripe = vault.get("STRIPE_SECRET")
if stripe is not None:
    charge(stripe)
```

Prebuilt wheels cover these platforms:

- Linux x86_64 (glibc 2.17 or later)
- Linux aarch64 (glibc 2.28 or later)
- macOS 10.12 or later on Intel
- macOS 11 or later on Apple silicon
- Windows x64

On any other platform, pip builds the source distribution, which needs a Rust
toolchain.

### API

> Every decrypted value murk returns is a plain Python `str`. See [Decrypted values in memory](#decrypted-values-in-memory) for the lifetime caveat.

#### Functions

| Function | Returns | Description |
|---|---|---|
| `murk.load(vault_path=".murk")` | `Vault` | Load and decrypt a vault |
| `murk.get(key, vault_path=".murk")` | `str \| None` | One-liner: load, then read one secret |
| `murk.export_all(vault_path=".murk")` | `dict[str, str]` | One-liner: load, then export everything |
| `murk.has_identity()` | `bool` | `True` if murk can find a key for `./.murk` (`MURK_KEY`, `MURK_KEY_FILE` or the stored key file). It does not read the vault, so it does not guarantee that `load` succeeds |

#### The `Vault` object

| Member | Returns | Description |
|---|---|---|
| `vault.get(key)` | `str \| None` | Decrypted value, or `None` if no value is readable for the secret |
| `vault.export()` | `dict[str, str]` | All readable secrets |
| `vault.keys()` | `list[str]` | Names of all secrets in the vault schema, including secrets you cannot read |
| `vault[key]` | `str` | Like `get`, but raises `RuntimeError` (not `KeyError`) if no value is readable |
| `key in vault` | `bool` | `True` if the secret is in the schema, even if you cannot read its value |
| `len(vault)` | `int` | Number of secrets in the schema |
| `vault.warnings` | `list[str]` | Warnings about a vault murk accepted, the ones the CLI prints as `warn …` |

## Node.js

:::caution[Experimental]
Writing from the Node.js binding (`add`, `describe`) is experimental: the write API is new. Reading secrets is stable.
:::

Requires Node.js 18.17 or later on Node 18, or 20.3 or later. Node 19 is not
supported. The addon uses Node-API version 9. TypeScript types are bundled.

```bash
npm install @interrupted/murk-secrets
```

```typescript
import { load, get, exportAll, add } from "@interrupted/murk-secrets";

// Load the vault (finds your key as described above)
const vault = load();

const dbUrl = vault.get("DATABASE_URL");   // string | null
const secrets = vault.export();            // Record<string, string>

const stripe = vault.get("STRIPE_SECRET");
if (stripe !== null) {
  charge(stripe);
}

// Store a secret (encrypted to everyone by default)
vault.add("NEW_TOKEN", "value");
vault.add("MY_TOKEN", "value", { tier: "me" });        // a private value, encrypted to you only
vault.add("TEAM_TOKEN", "value", { tier: "backend" }); // to a named group

// One-liners load the vault on each call
get("DATABASE_URL");
exportAll();
add("NEW_TOKEN", "value");
```

Prebuilt addons cover these platforms:

- macOS on Intel (x64)
- macOS on Apple silicon (arm64)
- Linux x64 (glibc)
- Linux x64 (musl)
- Linux arm64 (glibc)
- Linux arm64 (musl)
- Windows x64

### API

> Every decrypted value murk returns is a plain JavaScript string. See [Decrypted values in memory](#decrypted-values-in-memory) for the lifetime caveat.

#### Functions

| Function | Returns | Description |
|---|---|---|
| `load(vaultPath?)` | `Vault` | Load and decrypt a vault |
| `get(key, vaultPath?)` | `string \| null` | One-liner: load, then read one secret |
| `exportAll(vaultPath?)` | `Record<string, string>` | One-liner: load, then export everything |
| `add(key, value, options?: AddOptions, vaultPath?)` | `void` | One-liner: load, then store a secret |
| `hasIdentity()` | `boolean` | `true` if murk can find a key for `./.murk` (`MURK_KEY`, `MURK_KEY_FILE` or the stored key file). It does not read the vault, so it does not guarantee that `load` succeeds |

#### The `Vault` object

| Member | Returns | Description |
|---|---|---|
| `vault.get(key)` | `string \| null` | Decrypted value, or `null` if no value is readable for the secret |
| `vault.export()` | `Record<string, string>` | All readable secrets |
| `vault.keys()` | `string[]` | Names of all secrets in the vault schema, including secrets you cannot read |
| `vault.has(key)` | `boolean` | `true` if the secret is in the schema, even if you cannot read its value |
| `vault.add(key, value, options?: AddOptions)` | `void` | Store a secret (see [Writing secrets](#writing-secrets-node)) |
| `vault.describe(key, description, options?: DescribeOptions)` | `void` | Set a secret's description, tags, or example |
| `vault.length` | `number` | Number of secrets in the schema |
| `vault.warnings` | `string[]` | Warnings about a vault murk accepted, the ones the CLI prints as `warn …` |

### Writing secrets (Node)

`vault.add(key, value, options?)` works like `murk add`. It encrypts the value,
signs the vault when your key can sign, and writes it back to disk under an
exclusive lock, so concurrent writers are safe. The loaded `Vault` refreshes,
so later reads on the same handle see the write. A secret name must start with
a letter or underscore and contain only `A-Z`, `a-z`, `0-9` and `_`.

`options` is an `AddOptions` object. All fields are optional:

| Option | Type | Description |
|---|---|---|
| `tier` | `string` | Where the value lives: `"everyone"`, `"me"` or a group name. See below |
| `desc` | `string` | Human-readable description recorded in the vault schema |
| `tags` | `string[]` | Tags recorded on the secret. Tags are the unit the agent allow-tag policy gates on |

`tier` is one of:

- `"everyone"`: encrypted to every recipient except agent grants.
- `"me"`: a private value, encrypted to you only.
- A group name: encrypted to that group's members. You must be a member.

Omit `tier` to keep an existing secret in its tier. A new secret is shared.
You cannot update a secret held by a group you are not a member of, except
with `"me"`. A secret that holds only other recipients' private values needs
an explicit `tier`.

`tier` accepts aliases. `"all"` and `"shared"` mean `"everyone"`. `"self"` and
`"mine"` mean `"me"`. These six names are reserved and cannot name a group.
Matching is case-sensitive, so `"Everyone"` names a group. Any other string
names a group, so a misspelled tier fails with `group not found` unless a
group with that name exists.

An `everyone` or group write replaces the secret's base value. A group write
removes the shared value, and a shared write removes the group assignment. A
`me` write leaves the shared value alone. `add` adds `tags` to the secret's
existing tags. It never removes one.

`vault.describe(key, description, options?)` works like `murk describe`,
without `--rotate-every` and `--expires`. It never touches the value. It
always replaces the description. `options` is a `DescribeOptions` object with
two optional fields:

- `tags` replaces the existing tags when it is non-empty.
- `example` sets the example value (for `.env.example`-style docs). Leaving it
  out clears the current one.

If the secret does not exist yet, `describe` creates a documented entry with
no value.

## How reads resolve

Both bindings resolve a secret the way the CLI does. They return your
[private value](/guides/shared-vs-scoped/) first, then a group value you can
read, then the shared value. A private value is one you added with the `me`
tier (`murk add KEY --group me`). `export()` merges the same way and returns
only values you can decrypt.

`keys()`, `len()` (`length` in Node) and `in` (`has()` in Node) read the vault
schema, which is plaintext. They list every secret in the vault, including
secrets you cannot decrypt and secrets documented without a value.

## The vault has to be trusted on this machine

Both bindings load a vault through the same check as the CLI, so they hold
the same line: a vault murk doesn't trust on this machine never decrypts.
Every call that reads the vault fails with the CLI's message when the vault:

- is unsigned and your key could have signed it,
- is signed by a key this machine hasn't accepted,
- has been rolled back,
- is another vault's file, or
- has been tampered with (a bad MAC or signature, or an agent grant bound to
  a teammate's key).

A bare "not trusted on this machine yet" means nobody has run
[`murk trust`](/concepts/recipients-signatures/#murk-trust) for this
vault here.

The error type is `murk.TrustError` in Python and an `Error` with `code`
`'MURK_TRUST'` in Node. See [Errors](#errors).

A binding can't ask you, and has no way around the check. To accept a vault,
run `murk trust` once from a shell. A load updates this machine's trust pin
exactly as the same CLI command would. `vault.add()` and `vault.describe()` in
Node load through the same check first, so they never re-sign content the
machine doesn't trust.

In CI and other environments with no pin, set
[`MURK_TRUSTED_SIGNERS`](/concepts/env-vars/) to the entries of the signers
you allow. `murk trust --print-key` prints one entry per key. Set it only from
a CI secret or the real process environment, never from a file in the
repository or a `.env` that an app's dotenv loader reads, because it decides
which signers this machine trusts.

The bindings read `MURK_TRUSTED_SIGNERS` from the process environment. An app
that calls `load_dotenv()` (Python) or `dotenv.config()` (Node) before
`murk.load()` lets a repository `.env` choose the trust anchor. On a machine
with no pin, such as a fresh container or a CI runner, a `.env` that lists the
vault's signer makes the vault load. The CLI does not read `.env` itself, so
it is not affected.

An agent grant key reads only through the trusted signers in its key file
(the `# murk-trusted-signer:` lines `murk agent grant` writes) or
`MURK_TRUSTED_SIGNERS`. It never reads or writes the pin. A grant key with
neither is refused with a message asking the operator to re-mint the grant.

Some vaults load with a warning instead. The cases are an unsigned vault read
by a key that cannot sign (ssh-rsa, hardware or plugin keys), a legacy MAC,
and a trust pin that could not be written. The CLI prints these as `warn …`.
The bindings put the same text in `vault.warnings`, which is empty for a
clean load.

## Agent policy is enforced on read and write

When the loaded key is an [agent grant](/concepts/grants/) (from
`murk agent grant`), the bindings enforce the vault's agent policy on every
read, the same gate as `murk agent exec`:

- `get()` raises or throws if the grant can read the secret but the policy
  forbids it. For a secret the grant cannot read, it returns `None` or `null`.
- `export()` checks the whole readable set first and rejects the call if any
  secret is out of policy. It never returns partial results.
- A grant key can't write at all. `add()` and `describe()` (Node) throw
  `agent grants are read-only` and leave the vault on disk unchanged, whatever
  the policy says.
- For an operator key under `MURK_SELF_SCOPE` or `MURK_AGENT`, `add()` and
  `describe()` check the resulting secret against the policy before saving. A
  forbidden write fails the same way.
- `keys()`, `len()`/`length` and `in`/`has()` read only the schema. They
  never check the policy.

Python raises `RuntimeError`. Node throws. A plain operator key skips the
check unless `MURK_SELF_SCOPE` or `MURK_AGENT` is set, which holds your own
key to the policy the same way (see
[Environment variables](/concepts/env-vars/)). A grant also cannot decrypt
out-of-scope secrets, because its ephemeral key is not a recipient of them.
The policy check is a backstop, not the only guard. See
[AI agents & MCP](/guides/ai-agents-mcp/) for the full model.

A loaded `Vault` keeps the decrypted values and policy from its last load.
`get()` and `export()` use that snapshot, so policy changes and revocations
reach them only when the program calls `load()` again. In Node, `add()` and
`describe()` reload the vault from disk first, so they always check the
current policy. They then refresh the handle, so later reads see the new
state too.

Expiry is different. Once the grant's TTL has passed, a fresh `load()` fails.
A handle loaded earlier fails on `get()` and `export()`.

## Errors

| Failure | Python | Node.js |
|---|---|---|
| The trust check refuses the vault | `murk.TrustError` (a subclass of `RuntimeError`) | `Error` with `code` `'MURK_TRUST'` |
| Any other failure | `RuntimeError` | `Error` with `code` `'GenericFailure'` |

The other causes are:

- No key is found. See [Prerequisites](#prerequisites).
- Both `MURK_KEY` and `MURK_KEY_FILE` are set.
- The vault file is missing or invalid. The bindings read `.murk` unless you
  pass a path. They ignore `MURK_VAULT`, so pass the path for any other file.
- The agent policy forbids a read or a write.
- A Node write names an invalid secret or an unknown group.
- The binding is too old for the vault. See below.

### Unsupported vault version

murk 0.14 saves vaults in format 3.0. A binding older than 0.14 cannot read a
3.0 vault. The error is a plain `RuntimeError` in Python and an `Error` with
`code` `'GenericFailure'` in Node. It is not `TrustError` or `'MURK_TRUST'`,
because the vault is unsupported, not untrusted. A 0.13 binding says:

```text
vault parse error: unsupported vault version: 3.0. This build of murk supports version 2.x
```

The fix is to upgrade the package:

```bash
pip install --upgrade murk-secrets
npm install @interrupted/murk-secrets@latest
```

From 0.14.1, the message also names the binding and the versions it supports.
For a vault with version 99.0, the 0.14.1 Python binding says:

```text
vault parse error: unsupported vault version: 99.0. murk-secrets python binding 0.14.1 supports vault versions 2.x and 3.x
```

The 0.14.1 Node binding says:

```text
vault parse error: unsupported vault version: 99.0. murk-secrets node binding 0.14.1 supports vault versions 2.x and 3.x
```

## Decrypted values in memory

murk zeroes plaintext from its own memory when a value is dropped, but that
stops at the FFI boundary. `get()` and `export()` return native values: a
Python `str` or `dict`, a JavaScript string or object. Once a value is in your
program, the runtime owns it, and murk can't wipe it. That's unavoidable when
you read secrets into a process. The [threat model](/security/threat-model/)
notes it. It doesn't touch the vault on disk. It only affects how long values
linger in memory, so don't hold them longer than needed.

The Node write path makes this sharper. To call `vault.add(key, value)` you
already hold the plaintext as a JavaScript string before the call. It lives in
V8's heap, is copied across the FFI boundary, and is zeroized on neither side.
Build the value as late as possible, pass it straight into `add()`, and don't
keep it around.
