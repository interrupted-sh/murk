# murk-secrets

[![PyPI](https://img.shields.io/pypi/v/murk-secrets)](https://pypi.org/project/murk-secrets/)

Python bindings for [murk](https://github.com/interrupted-sh/murk), an encrypted secrets manager for developers.

murk stores encrypted secrets in a single `.murk` file safe to commit to git. This package lets Python apps read those secrets at runtime.

## Prerequisites

You need the [murk CLI](https://murk.interrupted.sh/install/) to create and manage vaults. This package only reads them.

```bash
# Install the CLI first
brew install interrupted-sh/tap/murk

# Initialize a vault and add secrets
murk init
murk add DATABASE_URL
murk add API_KEY
```

Then add the Python package to your project:

```bash
pip install murk-secrets
```

The package is `murk-secrets`. You import it as `murk`.

## Quick start

```bash
# Optional on the machine that ran murk init (see "Key lookup").
# POSIX shell syntax.
source .env
```

```python
import murk

# Load the vault (finds your key; see "Key lookup")
vault = murk.load()

# Get a single secret
db_url = vault.get("DATABASE_URL")

# Get all secrets as a dict
secrets = vault.export()

# Dict-style access
api_key = vault["API_KEY"]
```

## API

### `murk.load(vault_path=".murk") -> Vault`

Load and decrypt a murk vault. Finds your key as described in [Key lookup](#key-lookup).

### `murk.get(key, vault_path=".murk") -> str | None`

One-liner: load the vault and get a single value.

### `murk.export_all(vault_path=".murk") -> dict[str, str]`

One-liner: load the vault and export all secrets as a dict.

### `murk.has_identity() -> bool`

Returns `True` if murk can find a key for `./.murk`: `MURK_KEY`, `MURK_KEY_FILE` or the key file `murk init` stored. Returns `False` if no key is found, if both variables are set, or if the key file cannot be read. It does not read the vault, so `True` does not guarantee that `load()` succeeds. It does not check whether a secret exists. Use `key in vault` or `vault.keys()` for that.

### `Vault`

| Method | Returns | Description |
|--------|---------|-------------|
| `vault.get(key)` | `str \| None` | Decrypted value, or `None` if no value is readable for the secret |
| `vault.export()` | `dict[str, str]` | Every secret you can read |
| `vault.keys()` | `list[str]` | Names of all secrets in the vault schema, including secrets you cannot read |
| `vault[key]` | `str` | Like `get`, but raises `RuntimeError` (not `KeyError`) if no value is readable |
| `key in vault` | `bool` | `True` if the secret is in the schema, even if you cannot read its value |
| `len(vault)` | `int` | Number of secrets in the schema |
| `vault.warnings` | `list[str]` | Warnings about an accepted vault, the ones the CLI prints as `warn …` (empty for a clean load) |

`get()`, `vault[key]` and `export()` pick a value in this order: your private value, then a group value you can read, then the shared value. A private value is one you added with the `me` tier (`murk add KEY --group me`).

## Trust

`load()`, `get()` and `export_all()` apply the same trust check as the CLI. The check refuses a vault that this machine does not trust. That means a vault that is unsigned when your key could have signed it, signed by a key this machine has not accepted, rolled back, or tampered with. The binding raises `murk.TrustError` (a subclass of `RuntimeError`) with the CLI's message. Nothing in the binding skips the check.

To accept a vault, run `murk trust` once from a shell. In CI, set `MURK_TRUSTED_SIGNERS` to the signers you allow. Set it only from a CI secret or the real process environment, never from a file in the repository or a `.env` that an app's dotenv loader reads, because it decides which signers this machine trusts.

The binding reads `MURK_TRUSTED_SIGNERS` from the process environment. An app that calls `load_dotenv()` before `murk.load()` lets a repository `.env` choose the trust anchor. The CLI does not read `.env` itself.

An agent grant key reads only through the trusted signers in its key file or `MURK_TRUSTED_SIGNERS`.

## Memory hygiene

Every decrypted value murk returns is a plain Python `str`. murk zeroes plaintext from its own memory when a value is dropped. That guarantee ends at the FFI boundary. Once a value crosses into Python, the interpreter owns it, and its garbage collector controls its lifetime, not murk. This is inherent to reading secrets into a process (see the [threat model](https://github.com/interrupted-sh/murk/blob/main/THREAT_MODEL.md)). Avoid holding decrypted values longer than you need them.

## Agent policy

If the loaded key is an agent grant (from `murk agent grant`), the bindings enforce the vault's agent policy on every read, as `murk agent exec` does.

- `get()` and `export()` raise `RuntimeError` when the policy forbids a secret they can read.
- `keys()`, `len()` and `in` read only the schema. They never check the policy.
- A plain operator key skips the check unless `MURK_SELF_SCOPE` or `MURK_AGENT` is set.
- A grant cannot decrypt out-of-scope secrets, because its key is not a recipient of them. The policy check is a second guard.

A loaded `Vault` keeps the values and policy from its last load. Policy changes and revocations apply only after you call `load()` again.

Expiry is different. Once the grant's TTL has passed, a fresh `load()` fails. A handle loaded earlier fails on `get()` and `export()`.

## Key lookup

`load()` finds your key the same way the CLI does:

1. `MURK_KEY` (your age secret key) or `MURK_KEY_FILE` (the path to a key file). Set one, not both. murk refuses to load when both are set.
2. The key file that `murk init` stored under `~/.config/murk/keys/`. murk finds it by the vault's path, so a key stored for `.murk` does not open a vault at another path.

`murk init` also writes a `.env` that points `MURK_KEY_FILE` at that file. On the machine where you ran `murk init`, you do not need to source it. Set the variable yourself in CI, in containers and whenever `MURK_STRICT` or `MURK_AGENT` is set, because both turn off step 2.

## Errors

A failure raises `RuntimeError`. A trust refusal raises `murk.TrustError`, a subclass of `RuntimeError` (see [Trust](#trust)). The other causes are:

- No key is found. See [Key lookup](#key-lookup).
- Both `MURK_KEY` and `MURK_KEY_FILE` are set.
- The vault file is missing or invalid. The bindings read `.murk` unless you pass a path. They ignore `MURK_VAULT`, so pass `vault_path` for any other file.
- The agent policy forbids a read. See [Agent policy](#agent-policy).
- The binding is too old for the vault. See [Unsupported vault version](#unsupported-vault-version).

### Unsupported vault version

murk 0.14 saves vaults in format 3.0. A binding older than 0.14 cannot read a 3.0 vault. It raises a plain `RuntimeError`, not `TrustError`, because the vault is unsupported, not untrusted. A 0.13 binding says:

```text
vault parse error: unsupported vault version: 3.0. This build of murk supports version 2.x
```

The fix is to upgrade the package:

```bash
pip install --upgrade murk-secrets
```

From 0.14.1, the message also names the binding and the versions it supports. For a vault with version 99.0, a 0.14.1 binding says:

```text
vault parse error: unsupported vault version: 99.0. murk-secrets python binding 0.14.1 supports vault versions 2.x and 3.x
```

## Requirements

Python 3.9 or later, the murk CLI, a `.murk` vault in your project and a key (see [Key lookup](#key-lookup)).

Prebuilt wheels cover these platforms:

- Linux x86_64 (glibc 2.17 or later)
- Linux aarch64 (glibc 2.28 or later)
- macOS 10.12 or later on Intel
- macOS 11 or later on Apple silicon
- Windows x64

On any other platform, pip builds the source distribution, which needs a Rust toolchain.

## License

MIT OR Apache-2.0
