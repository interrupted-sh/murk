# Test fixtures

Files the integration tests load with `include_str!`. Nothing here is a secret.

## Test-only keys

| File | What it is for |
|------|----------------|
| `v0_13_signed.test-only.key` | The age identity that wrote and signed `v0_13_signed.murk`. `tests/adversarial.rs` uses it to check that a vault from murk 0.13.0 still verifies and decrypts, and is upgraded on the next write. |
| `v0_13_duplicate_ssh.test-only.key` | The age identity ("alice") that wrote and signed `v0_13_duplicate_ssh.murk`. |
| `v0_13_duplicate_ssh_bob.test-only.key` | An OpenSSH ed25519 private key ("bob"), listed twice in `v0_13_duplicate_ssh.murk`. It wrote bob's own override there. `tests/cli_recipients.rs` uses both keys to check that such a vault still loads, that the next save lists bob once, and that revoking him by either spelling removes every copy. |
| `LEGACY_KEY` (a constant in `tests/cli_diagnostics.rs`, commented `// TEST KEY - not secret; only decrypts tests/fixtures/legacy-bidi-description.murk`) | The throwaway age identity that wrote `legacy-bidi-description.murk`. It decrypts nothing else. |
| `fuzz/seeds/fuzz_identity_parse/test-only-age-key` | A throwaway age key that seeds the identity-parser fuzz target. No vault or test uses it. |
| `fuzz/seeds/fuzz_identity_parse/test-only-openssh-key` | The published ssh-ed25519 test key from the rage test suite, a seed for the same target. See `fuzz/README.md`. |
| `v0_13_rollback_alice.test-only.key` | The age identity ("alice") that wrote and signed `v0_13_rollback_leaked.murk` and `v0_13_rollback_rotated.murk`. |
| `v0_13_rollback_bob.test-only.key` | The age identity ("bob") that wrote and signed `v0_13_rollback_staging.murk`, and wrote `API_KEY` in the two prod revisions. `tests/authenticity.rs` uses both keys to check that a plain `git merge` cannot smuggle an older 0.13 revision, or another 0.13 vault, past the merge driver. |
| `v0_15_format3_alice.test-only.key` | The age identity ("alice") that wrote and signed `v0_15_format3_base.murk` and `v0_15_format3_stale_fork.murk`. `tests/authenticity.rs` uses it to give a machine a format-3 vault to adopt and a genuine format-3 file from a stale fork. |
| `v0_15_format3_compat.test-only.key` | The age identity ("alice") that wrote and signed `v0_15_format3_compat.murk`. `tests/format4.rs` uses it to load that vault and to re-sign hand-edited copies of it. |

These keys are published on purpose and are not secret. No real vault lists their public keys (`age13kngcf8z5z2eql0qvk7d4pfz42tvl2swmwlwzap5zvphuy6yzf4qn5e8pe`, `age1jqsm85gqqeuq6tf20xem06z6kpjgkqygwvqny7r8uxad6zvzcvaqd7yfg8`, `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFFMXjwwBOjk5V0rYD2Di9tLG0xGudp2h/CJHkhIPi6Y`, `age1h38fk3pz9vlwzpkl6a3e3j0p7ywss3evcesasqyjvcjyz3msv5gsn3aecr`, `age1ulqv9wf6cgz5j3e7s8spzqu94gr4zajkgrywrmhklctvkga0nqwq846q5n`, `age1jd26gslr2d8ggr907mp2ldfpcvkjz54htx9gvd24hutqklqura6q82kv8w`, `age1v5p78kuas7ccnufrtlexg40ymqv7d00309hxdea5vtsh9kqts5kshkr9eq`) as recipients, and none must: anyone can read a vault encrypted to them. Do not use them, or copy them, for anything except these tests.

## Vaults

| File | What it is |
|------|------------|
| `v0_13_signed.murk` | A vault written by the murk 0.13.0 release binary: header version `2.0`, an older MAC scheme, and a signed-view-1 signature inside the meta. One secret, `API_KEY`, with the value `fixture-secret-value-0123`. |
| `v0_13_duplicate_ssh.murk` | A vault written by a murk 0.13.0 build (v0.13.0, `97e5002`): header version `2.0`, with bob's SSH key listed twice, once with its `bob@laptop` comment and once without (0.13 compared keys as exact strings). Secrets: `API_KEY` (shared `fixture-shared-value`, and bob's own override `bob-override`) and `SECOND` (`fixture-second-value`). |
| `legacy-bidi-description.murk` | A vault written by murk 0.13.0 (`origin/main` at `97e5002`) whose `DB` description holds a bidi override (U+202E). It is decrypted by `LEGACY_KEY` in `tests/cli_diagnostics.rs`. `legacy_bidi_description_loads_shows_escaped_and_can_be_replaced` uses it to check that such a vault still loads, that `info` shows the character escaped, that `verify` names the field, and that a clean description replaces it while new text with the character is refused. |
| `v0_13_rollback_leaked.murk`, `v0_13_rollback_rotated.murk` | Two revisions of one prod vault written by the murk 0.13.0 release binary (header version `2.0`, no vault id), recipients alice and bob. `API_KEY` is `prod-api` (written by bob). `DB_URL` is `LEAKED-db-value` in the first and `ROTATED-db-value` in the second, both signed by alice. |
| `v0_13_rollback_staging.murk` | A separate vault written by the murk 0.13.0 release binary with the same recipients, created two seconds earlier by bob and signed by bob: `DB_URL` `STAGING-db-value`, `API_KEY` `STAGING-api`. |
| `v0_15_format3_base.murk` | A vault written by a murk 0.15.2 build (`279b1cf`): header version `3.0`, a signed-view-2 signature, MAC `blake3v8:`, recipient alice only, generation 3. Secrets: `DB_URL` (`format3-base-db`) and `API_KEY` (`format3-base-api`). A build that writes format 4 never produces this file, so a test that needs a machine to meet format 3 first uses it. |
| `v0_15_format3_stale_fork.murk` | A fork of `v0_15_format3_base.murk` written by the same build and key: the same vault id, five more saves by alice, so generation 8. `DB_URL` is `format3-stale-fork-db`, and `FORK_1` to `FORK_4` are added. Genuine and signed by alice, but it grew from the base alone, so a machine that has accepted a later save of the base has a revision this file does not descend from. |
| `v0_15_format3_compat.murk` | A vault written by a murk 0.15.2 build: header version `3.0`, a signed-view-2 signature, MAC `blake3v8:`, recipient alice only, generation 2. One secret, `TOKEN`, with the value `fixture-token-value-4711`. A build that writes format 4 never produces such a file, so `tests/format4.rs` uses it as the format-3 control for the format-4 rules, and as the vault a newer header or signature view is edited into. |
