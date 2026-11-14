# Contributing

murk is pre-1.0. Contributions are welcome, especially in these areas:

- Bug reports and security issues (see [SECURITY.md](SECURITY.md) for private reporting)
- Test coverage, especially adversarial/edge-case tests
- Documentation improvements
- Platform compatibility fixes (Windows, Linux, macOS)

For a first contribution, pick an issue labelled [good first issue](https://github.com/interrupted-sh/murk/labels/good%20first%20issue) or [help wanted](https://github.com/interrupted-sh/murk/labels/help%20wanted). If none are open, open an issue before you write code.

## Development

```bash
cargo build                                               # Build
cargo nextest run --all-features                          # Run all tests, as CI does
cargo clippy --all-features --all-targets -- -D warnings  # Lint, as CI does
cargo fmt --check                                         # Check formatting (`cargo fmt` fixes it)
cargo run --bin murk -- <command>                         # Run murk with arguments
```

The tests need [cargo-nextest](https://nexte.st) (`cargo install cargo-nextest`).

Run `make hooks` once per clone to install the pre-commit hook, which runs the same fmt and clippy checks as CI.

CI does not run the type-aware lints in `lints/murk_lints/`. See its [README](lints/murk_lints/README.md) to run them.

Run `make release-check` before a release. It builds the workspace (the CLI and the Node binding) with all targets and features. It builds every fuzz target in `fuzz/` with nightly [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (`cargo install cargo-fuzz`). Then it runs the whole test suite without stopping at the first failure. It fails if any step fails.

### Generated documentation

`docs/cli-reference.md`, `docs/env-reference.md`, `docs/permissions.md`, `docs/completions/` and `docs/man/` are generated. Never edit them by hand. Run the generator after you change anything they come from:

```bash
cargo run --features doc-gen --bin gen-docs
```

The sources are the clap model in `src/cli.rs`, the environment variable list in `src/bin/gen-docs.rs`, and the table in `tests/auth_matrix/table.rs`. CI runs the generator with `--check` and fails if a committed file is stale. `--check` cannot notice a new environment variable that is missing from the hand-kept list, so update that list when you add or remove an environment read. The docs site mirrors these files with `docs-site/scripts/sync-generated-docs.mjs`.

### Rust toolchain

`rust-toolchain.toml` pins the exact Rust version CI builds, lints and releases with. If you installed Rust with [rustup](https://rustup.rs), `cargo` in this repository uses the pinned toolchain automatically and rustup installs it, with rustfmt and clippy, on first use (or run `rustup toolchain install`).

Homebrew's `rust` formula and distro packages ignore `rust-toolchain.toml`. Their `cargo` runs whatever version they ship. The pre-commit hook can then fail on lints CI doesn't enforce yet, or pass code CI rejects.

Use rustup to match CI. If both are installed, make sure rustup's `cargo` comes first on your `PATH`. In the repository, `rustup show active-toolchain` should name the pinned version.

Dependabot opens a PR for each new Rust release. Patch releases merge automatically once CI is green. Minor releases wait for a maintainer: fix any new lints on that PR before merging it.

### Security advisories

CI checks dependencies against the RustSec advisory database on pushes to `main`, on tags, and on PRs that change a `Cargo.toml`, a `Cargo.lock` or `deny.toml`. Other PRs skip that check, so a newly published advisory does not fail unrelated PRs.

A daily workflow (`.github/workflows/advisories.yaml`, logic in `scripts/fix-advisories.sh`) updates each affected crate to the lowest semver-compatible patched version. It opens or refreshes one PR from the `deps/rustsec-fixes` branch. Run `scripts/fix-advisories.sh` locally to apply the same fixes.

That PR merges automatically once CI is green only if it changes nothing but `Cargo.lock` and `fuzz/Cargo.lock` and moves no crate that [`scripts/automerge-policy.cjs`](scripts/automerge-policy.cjs) holds for review. Otherwise it waits for a maintainer (see [Roles and responsibilities](#roles-and-responsibilities)).

Once anyone else pushes a commit to the branch, the job stops updating it and leaves the PR for review.

Advisories the job cannot fix this way go to an open issue titled "Unfixable RustSec advisories". A maintainer resolves each one: upgrade by hand, replace the dependency, or add a documented ignore to `deny.toml`.

## Pull Requests

- Keep PRs focused: one logical change per PR
- Run the fmt, clippy and test commands from [Development](#development) before submitting
- Start each commit subject and the PR title with a conventional commit type (`feat:`, `fix:`, `docs:`, `refactor:` …). Each release's list of changes is generated from commit subjects ([`cliff.toml`](cliff.toml)), not from the PR title
- PR descriptions should be a short bullet list of changes
- New features must include tests

## Security

If you find a security vulnerability, **do not open a public issue**. Use [GitHub's private vulnerability reporting](https://github.com/interrupted-sh/murk/security/advisories/new) instead.

## Governance

murk has one maintainer, [@iicky](https://github.com/iicky). The maintainer makes every final decision about the project. No other person holds a project role, so the bus factor is 1.

### Roles and responsibilities

**Maintainer ([@iicky](https://github.com/iicky)):**

- Decides the project's scope and direction, including the [roadmap](ROADMAP.md).
- Triages issues.
- Reviews and merges pull requests. [`.github/CODEOWNERS`](.github/CODEOWNERS) assigns every file to the maintainer.
- Reviews every dependency PR that updates a crate murk's security rests on, even a patch update. [`scripts/automerge-policy.cjs`](scripts/automerge-policy.cjs) lists these crates, among them age, the SSH key, cipher, hash, signature and random-number crates, `zeroize`, `ureq`, `rustls`, `serde` and `rmcp`.
- Lets other dependency PRs merge without a manual review once CI passes, in two cases: a Dependabot update in which every dependency gets a patch release (except updates of the bb plugin's dependencies), and a lockfile-only advisory fix (see [Security advisories](#security-advisories)).
- Cuts murk releases and bb plugin releases (see [Releases](#releases)).
- Handles private vulnerability reports as described in [SECURITY.md](SECURITY.md), and ships the fixes.
- Enforces the [Code of Conduct](CODE_OF_CONDUCT.md).

**Contributors:** anyone who opens an issue or a pull request. Contributors follow the [pull request rules](#pull-requests), certify the [Developer Certificate of Origin](#developer-certificate-of-origin), and report vulnerabilities privately, not in public issues.

### How decisions are made

Decisions are made in the open, in GitHub issues and pull requests. Open an issue to discuss a significant change before you write the code. The maintainer makes the final decision on each issue and pull request, and records it there.

To disagree with a decision, reply on the issue or pull request with your reasoning, or open a new issue. The maintainer can reopen an issue or change a decision. Security reports are the exception: they go through [private reporting](#security) until a fix ships.

### Code review

Every change reaches `main` through a pull request. The maintainer reviews each pull request before merging it, including their own. murk has one maintainer, so the maintainer's own pull requests get no second human review. CI is the independent check on them.

The only changes that merge without a manual review are the automated dependency PRs described in [Roles and responsibilities](#roles-and-responsibilities).

The maintainer checks each pull request for:

- **Correctness and tests.** The change does what its description says and nothing unrelated. New features include tests. Bug fixes include a regression test where the bug can be reproduced in a test.
- **Security impact.** Changes to encryption, signing, the vault format, key and recipient handling, secret output, or the agent and MCP surfaces are checked against [THREAT_MODEL.md](THREAT_MODEL.md). The check uses its [trust boundaries](THREAT_MODEL.md#trust-boundaries) and [common implementation weaknesses](THREAT_MODEL.md#common-implementation-weaknesses).
  - A change that adds an asset, moves a trust boundary or weakens a stated property updates the threat model in the same pull request.
- **Documentation and changelog.** User-visible changes update the README or the docs site. A change to a command or flag regenerates the CLI and env references (`make docs`). CI fails if they are out of date. Commit subjects follow the [pull request rules](#pull-requests), because each release's list of changes comes from them.
- **CI.** Branch protection requires the `Lint`, `Test` and `VHS` checks, and it applies to the maintainer too. CodeQL runs on every pull request. The Node, Python and docs-preview workflows run when their paths change.
  - The `bb plugin` check ([`.github/workflows/bb-plugin.yaml`](.github/workflows/bb-plugin.yaml)) runs the bb plugin's typecheck and tests when the plugin, the murk sources or the Node binding change. It is not required, so a Dependabot update of the plugin's dependencies waits for a review.
  - `Lint` covers formatting, clippy, generated docs, version consistency, guide commands, demo tapes and SPDX headers ([`scripts/spdx-headers.cjs`](scripts/spdx-headers.cjs)).
- **Dependency changes.** A pull request that changes a `Cargo.toml`, a `Cargo.lock` or `deny.toml` runs `cargo deny` (advisories, bans, licenses, sources) and `cargo audit`. For a new dependency, the maintainer also checks that it is needed and maintained.

A pull request does not merge in any of these cases:

- A required check fails.
- The maintainer has requested changes that are not addressed.
- An item in the list above is not met, for example a new feature without tests or a security-relevant change without a threat-model update.

### Releases

The maintainer cuts a release in these steps:

1. Bump the version everywhere it appears with `scripts/bump-version.sh <x.y.z>`.
2. Widen the bb plugin's `@interrupted/murk-secrets` range if the new version falls outside it, as every new minor release does before 1.0. Edit the range in `integrations/bb/package.json` and in `integrations/bb/package-lock.json`, for example from `^0.14.0` to `^0.14.0 || ^0.15.0`.
   - `scripts/bump-version.sh` does not edit this range. It edits every other file, then fails at its last step, `node scripts/check-versions.cjs`, until you widen the range. The `Lint` job runs the same check.
3. Run `make release-check` (see [Development](#development)).
4. Push the release branch and run `gh workflow run ci.yaml --ref <branch>`. When the run finishes, confirm that the `Test (windows-latest)` job ran the whole suite. CI does not stop at the first failing test, so its summary lists every failure.
5. Open a pull request for the release branch and merge it to `main`.
6. Push a signed `vX.Y.Z` tag.

The tag starts [`.github/workflows/release.yaml`](.github/workflows/release.yaml). Its `preflight` job refuses to release unless the tagged commit is on `main`, reached `main` through a merged pull request, and `main`'s branch protection matches the release baseline. The workflow then builds, attests and publishes the release.

The same tag starts the Node and Python workflows (`node.yaml`, `python.yaml`). They publish the npm and PyPI packages. The `preflight` job gates only `release.yaml`, not those two workflows. `node.yaml` can also publish from `main` when it is run by hand. [VERIFYING.md](VERIFYING.md) shows how to verify each release channel.

The bb plugin in `integrations/bb/` has its own version and its own tag. The maintainer releases it in these steps:

1. Set `version` in `integrations/bb/package.json`. `scripts/bump-version.sh` does not change it.
2. Add an entry for the new version to the Changelog section of `integrations/bb/README.md`.
3. Merge the change to `main` through a pull request.
4. Push a signed `bb-plugin/vX.Y.Z` tag on a commit on `main`, for example `bb-plugin/v0.1.1`.

That tag starts no workflow. Nothing builds, attests or publishes the plugin, so the tag is the whole release.

### Repositories

The project is made up of these three repositories, all maintained by the maintainer above:

- [interrupted-sh/murk](https://github.com/interrupted-sh/murk) (this repository): the CLI, the Rust library, the Python and Node bindings, the bb plugin (`integrations/bb/`) and the docs site (`docs-site/`). Active, pre-1.0.
- [interrupted-sh/murk-action](https://github.com/interrupted-sh/murk-action): the GitHub Action that decrypts murk secrets into a CI job's environment. Active, published on the [GitHub Marketplace](https://github.com/marketplace/actions/murk-action) as `interrupted-sh/murk-action@v1`.
- [interrupted-sh/homebrew-tap](https://github.com/interrupted-sh/homebrew-tap): the Homebrew tap for interrupted.sh tools. Active. The `homebrew` job in [`.github/workflows/release.yaml`](.github/workflows/release.yaml) updates `Formula/murk.rb` on each release.

## Developer Certificate of Origin

By contributing, you certify that your contribution is your original work or you have the right to submit it under the project's license, per the [Developer Certificate of Origin](https://developercertificate.org/). You assert this by submitting a pull request. You do not need a `Signed-off-by` line, and no check looks for one.

## License

Contributions are licensed under the same terms as the project (MIT OR Apache-2.0).

Each source file starts with two SPDX tag lines that name the copyright holder and the license. Write them in the file's own comment syntax, such as `//` for Rust and `#` for shell scripts:

```text
SPDX-FileCopyrightText: murk contributors
SPDX-License-Identifier: MIT OR Apache-2.0
```

Run `node scripts/spdx-headers.cjs` to add the header to new files. CI runs it with `--check` and fails if a source file lacks the header. Generated files and non-code files carry no header. The script lists which files get one and which it skips. The lint UI fixtures in `lints/murk_lints/ui/` carry the header too, so their `.stderr` expectations count it in their line numbers.
