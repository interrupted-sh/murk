# murk_lints

Type-aware secret-handling lints for the murk codebase.
`tests/invariants.rs` scans source text and cannot express type-level rules.
These [dylint](https://github.com/trailofbits/dylint) lints use real rustc
type information instead.

A secret field is a struct field that holds decrypted secret plaintext.

## Lints

- `secret_field_missing_zeroize`: each known secret field (see
  `SECRET_FIELDS` in `src/lib.rs`) must resolve to `zeroize::Zeroizing<_>`,
  `age::secrecy::SecretString`, or a type that implements
  `zeroize::ZeroizeOnDrop`. The type may sit inside `HashMap`, `BTreeMap`,
  `Option` or `Vec`.
- `secret_debug_leak`: no `Debug` impl may print a field whose type is or
  contains `Zeroizing<_>`, or another `ZeroizeOnDrop` type that does not
  redact its own `Debug` output. The lint checks derived impls, and manual
  impls that use the `Formatter::debug_struct(..).field(name, value)` builder
  pattern. `age::secrecy::SecretString` is not in this marker set (see
  [Marker strategy](#marker-strategy)).
- `secret_uncontrolled_escape`: `.clone()` and `.to_string()` may not copy a
  secret wrapper into a plain value that nothing zeroizes. The lint flags
  `(*v).clone()` and `v.to_string()` where `v` is `Zeroizing<_>` or
  `SecretString`.

## Marker strategy

The lints decide what counts as correctly handled from resolved types, not
from text.

- murk wraps decrypted plaintext in `zeroize::Zeroizing<_>`.
- murk wraps key material in `age::secrecy::SecretString`. The code is in
  `env.rs`, `init.rs` and the CLI's key resolution.
- Any type that implements `zeroize::ZeroizeOnDrop` also counts for
  `secret_field_missing_zeroize` and `secret_debug_leak`.
- Plain `Zeroize` does not count. `String` and `Vec<u8>` implement `Zeroize`,
  but nothing calls it for you.
- murk_cli has no hand-rolled `impl Zeroize`, so the two wrappers cover its
  secrets.
- Zeroization is best effort. [THREAT_MODEL.md](../../THREAT_MODEL.md) lists
  the buffers it cannot reach: age internals, serialization, FFI bindings and
  OS copies.

`secret_field_missing_zeroize` needs a list of secret fields. murk_cli has no
marker trait or attribute that says "this field holds a secret". Field names
are a poor guide: `Murk::recipients`, `Murk::groups` and
`MurkIdentity::Plugin::pubkey` hold non-secret metadata next to secret fields
in the same structs. The lint uses an allowlist of exact `(type path, field
name)` pairs instead (`SECRET_FIELDS` in `src/lib.rs`). The allowlist is a
regression guard, not a discovery tool. Add a field by hand when it starts to
hold decrypted plaintext.

`secret_debug_leak` needs no list. The wrapper type, resolved from real field
types, is the marker. Its marker set is narrower than the one for
`secret_field_missing_zeroize`. `Zeroizing<_>` and other `ZeroizeOnDrop` types
count. `age::secrecy::SecretString` (`secrecy::SecretBox<str>`) does not,
although it implements `ZeroizeOnDrop`. The `Debug` impl of `SecretBox`
always prints `SecretBox<str>([REDACTED])`, so deriving `Debug` over a
`SecretString` field is safe. `init::DiscoveredKey` does this: it derives
`Debug` over `secret_key: SecretString`.

`secret_uncontrolled_escape` checks for `Zeroizing<_>` and `SecretString`
themselves. It does not check for other `ZeroizeOnDrop` types.

## Limitations

- `secret_field_missing_zeroize` checks only the fields in its allowlist. It
  does not find new secret fields. A marker attribute or trait on secret
  fields would let the lint find them. murk_cli has none.
- `secret_debug_leak` recognizes a manual `Debug` impl only when it uses the
  `.field(name, &self.field)` builder pattern. It does not see a secret field
  that `write!` or `format!` prints. Matching the arguments that macros
  generate breaks across rustc versions. Every manual `Debug` impl in `src/`
  uses the builder pattern or never reads a secret field, so the check covers
  all of them.

## Running

CI does not run these lints.

One-time setup (external tools, not part of the murk workspace's own build):

```sh
rustup toolchain install nightly-2026-05-28 --profile minimal \
  --component rustc-dev,llvm-tools-preview
rustup run stable cargo install cargo-dylint dylint-link --locked
```

Run the lints over the whole workspace. The `[workspace.metadata.dylint]`
entry in the root `Cargo.toml` points `cargo dylint` at this crate. The
`rust-toolchain.toml` in this directory pins the nightly.

```sh
cargo dylint --all --workspace --no-deps -- --lib --tests --bins
```

Run the UI tests:

```sh
cd lints/murk_lints && cargo test
```

Both commands need a rustup-managed Rust. `cargo` and `rustc` must resolve to
rustup's proxies. The proxies read `rust-toolchain.toml` and export
`RUSTUP_TOOLCHAIN` to child processes. `dylint-link` depends on that
variable, and `cargo-dylint` builds its per-toolchain driver through rustup.
This is [dylint's own prerequisite](https://github.com/trailofbits/dylint).
A non-rustup Rust first on `PATH`, such as Homebrew's, is not supported.
