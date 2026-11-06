---
title: Verifying releases
description: Verify the authenticity of murk releases.
sidebar:
  order: 2
---

murk releases are built and published by GitHub Actions workflows in `interrupted-sh/murk`, on GitHub-hosted runners. The maintainer signs the source tag with an SSH key. Each channel also has signed build provenance that you can check. This page shows how, per distribution channel. Older releases have gaps on some channels, and each section says which.

See [Install](/install/) to get murk in the first place, and the [threat model](/security/threat-model/)'s [supply chain](/security/threat-model/#supply-chain) section for how release verification fits into murk's broader security story.

| Channel | What is signed or pinned | Signed by | Verify with |
| --- | --- | --- | --- |
| Source: git tag `vX.Y.Z` | The annotated tag (v0.3.1 and later) | Maintainer's SSH signing key | [`git verify-tag`](#release-tag) |
| GitHub release archives and `SHA256SUMS` | Sigstore build provenance per file (v0.3.1 and later) | `release.yaml` in `interrupted-sh/murk` | [`gh attestation verify`](#github-release-binaries) |
| Homebrew tap | The formula pins the SHA-256 of the attested GitHub release archives | Inherits the GitHub release attestation | `brew` checks the hash. Run [`gh attestation verify`](#github-release-binaries) on the archive |
| `install.sh` | The archive against `SHA256SUMS`, then its Sigstore build provenance | Same as the GitHub release archives | The script checks both. If `gh` is logged in, it runs `gh attestation verify`. Otherwise it asks on a terminal (default no) or stops. `MURK_SKIP_ATTESTATION=1` skips the provenance check |
| crates.io: `murk-cli` | Sigstore build provenance for the exact `.crate` file (0.13.0 and later) | `release.yaml` in `interrupted-sh/murk` | [`gh attestation verify`](#cratesio-murk-cli) on the `.crate` |
| npm: `@interrupted/murk-secrets` | npm registry signatures and Sigstore provenance | `node.yaml` in `interrupted-sh/murk` | [`npm audit signatures`](#npm-interruptedmurk-secrets) shows that attestations exist. [Read the attestation](#npm-interruptedmurk-secrets) to see whose they are |
| PyPI: `murk-secrets` | PEP 740 Sigstore attestations per wheel and sdist | `python.yaml` in `interrupted-sh/murk` | [`pypi-attestations verify`](#pypi-murk-secrets) |

In this page, `vX.Y.Z` is a release tag, such as `v0.14.1`. `X.Y.Z` is the same version without the `v`, as it appears in package names. Replace both with the release you check.

The Sigstore signatures are keyless. Each signing key is ephemeral. Fulcio certifies it for the workflow identity that ran: the repository, the workflow file, and the tag. No long-lived key signs the artifacts.

The verifying tools fetch Sigstore's public trust root themselves. You supply one input, the expected identity. Use `--repo interrupted-sh/murk` with `--signer-workflow`. The flag `--owner interrupted-sh` also works, but it accepts any repository of the organization.

## Release tag

Release tags from v0.3.1 onward are signed with the maintainer's SSH key. (Tags v0.2.0 through v0.3.0 are unsigned.)

GitHub publishes the key as an SSH **signing** key at <https://api.github.com/users/iicky/ssh_signing_keys>. Do not use `https://github.com/iicky.keys`. It lists authentication keys, which do not sign tags.

The signing key's fingerprint is `SHA256:rvLxyoK1U/TDmpbh8U76u1GglXPzqZPr5Jnn3ok6CGw`. The fingerprint on this page and the key from GitHub come from two different sources, so each one checks the other.

Write the key to an allowed-signers file and verify the tag you build from. Run the commands in your checkout of murk, but keep the file outside the checkout. Then nothing in the repository can change it. Replace `vX.Y.Z` with the release tag:

```bash
git fetch --tags
curl -fsSL https://api.github.com/users/iicky/ssh_signing_keys \
  | jq -r '.[] | "5324300+iicky@users.noreply.github.com namespaces=\"git\" \(.key)"' \
  > "$HOME/murk-allowed-signers"
git -c gpg.ssh.allowedSignersFile="$HOME/murk-allowed-signers" verify-tag vX.Y.Z
```

The output must contain `Good "git" signature` and the fingerprint above. To make the setting permanent, add the line to your own allowed-signers file and set `git config --global gpg.ssh.allowedSignersFile <path>`.

## GitHub release binaries

The prebuilt binaries and `SHA256SUMS` on the [releases page](https://github.com/interrupted-sh/murk/releases) carry signed build provenance (`actions/attest-build-provenance`, Sigstore/Fulcio).

Each archive is named `murk-vX.Y.Z-<target>.tar.gz`. `<target>` is one of `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `arm-unknown-linux-gnueabihf`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, or `x86_64-pc-windows-msvc`. The Windows archive is a `.zip` instead: `murk-vX.Y.Z-x86_64-pc-windows-msvc.zip`.

The commands below need the [GitHub CLI](https://cli.github.com/), logged in to github.com. Run `gh auth login`, or set `GH_TOKEN`. Then verify a downloaded artifact of murk 0.12.0 or later:

```bash
gh attestation verify murk-vX.Y.Z-<target>.tar.gz --repo interrupted-sh/murk \
  --signer-workflow interrupted-sh/murk/.github/workflows/release.yaml \
  --source-ref refs/tags/vX.Y.Z
```

This confirms that the release workflow of `interrupted-sh/murk` produced the artifact, from the tag you named. `--repo` and `--signer-workflow` pin the identity. `--owner` alone would accept an attestation from any repository of the organization.

`--source-ref` pins the tag. The attestation covers the digest of the file, not its name. Without `--source-ref`, a genuine older archive renamed to the name of a newer release also verifies.

Provenance names the repository that built the release. The repository has moved twice, so older releases name an older one:

| Releases | Repository named in the provenance |
| --- | --- |
| 0.12.0 and later | `interrupted-sh/murk` |
| 0.10.2 to 0.11.0 | `interrupted-inc/murk` |
| 0.3.1 to 0.10.1 | `iicky/murk` |

For 0.10.2 to 0.11.0, fetch the attestation from the current repository, then verify it against the old identity:

```bash
gh attestation download murk-vX.Y.Z-<target>.tar.gz --repo interrupted-sh/murk
gh attestation verify murk-vX.Y.Z-<target>.tar.gz \
  --bundle sha256:<sha256-of-archive>.jsonl --repo interrupted-inc/murk \
  --signer-workflow interrupted-inc/murk/.github/workflows/release.yaml \
  --source-ref refs/tags/vX.Y.Z
```

For 0.3.1 to 0.10.1, fetch the attestation by the old owner instead:

```bash
gh attestation download murk-vX.Y.Z-<target>.tar.gz --owner iicky
gh attestation verify murk-vX.Y.Z-<target>.tar.gz \
  --bundle sha256:<sha256-of-archive>.jsonl --repo iicky/murk \
  --signer-workflow iicky/murk/.github/workflows/release.yaml \
  --source-ref refs/tags/vX.Y.Z
```

For the 0.3.x releases (0.3.1, 0.3.2 and 0.3.4), the workflow file is `release.yml`, so pass `--signer-workflow iicky/murk/.github/workflows/release.yml`. No attestation was found for releases before 0.3.1.

`gh attestation download` prints the bundle file name it wrote.

### Rebuilding a release binary

`rust-toolchain.toml` at the release tag names the exact Rust version that built the release. With [rustup](https://rustup.rs), a build from a checkout of the tag uses that toolchain automatically. `rustup show active-toolchain` confirms it. Releases tagged before `rust-toolchain.toml` was added were built with the then-current stable Rust.

The release workflow ([`release.yaml`](https://github.com/interrupted-sh/murk/blob/main/.github/workflows/release.yaml)) also fixes the other build inputs:

- `SOURCE_DATE_EPOCH` is the commit timestamp.
- `CARGO_INCREMENTAL=0`.
- `--remap-path-prefix` remaps the checkout and the cargo home to `/src` and `/cargo`.
- On Windows, `-Clink-arg=/Brepro`.

Build with the same settings and `cargo build --release --locked --target <target>`. The Linux ARM targets use `cross` 0.2.5. Then compare the binary inside the release archive by SHA-256.

On pushes to `main`, CI's reproducibility job builds one commit twice from different paths. It checks that the two builds are byte-identical on x86_64 Linux and x86_64 Windows. macOS and Linux ARM are not covered. A build on a different OS image or linker can still differ.

## npm (`@interrupted/murk-secrets`)

Published with npm provenance (`npm publish --provenance`). Run the check in the project that installed the package:

```bash
npm audit signatures
```

The command reports that the package has verified registry signatures and verified attestations. This shows that provenance exists. It does not show whose provenance it is, because the command does not check the repository or the workflow.

To see the identity, add `--json --include-attestations` and read the provenance attestation:

```bash
npm audit signatures --json --include-attestations \
  | jq '.verified[] | select(.name == "@interrupted/murk-secrets")
        | .attestationBundles[]
        | select(.predicateType == "https://slsa.dev/provenance/v1")
        | .bundle.dsseEnvelope.payload | @base64d | fromjson
        | .predicate.buildDefinition.externalParameters.workflow'
```

For 0.12.0 and later, the output must name the repository `https://github.com/interrupted-sh/murk`, the path `.github/workflows/node.yaml`, and the ref `refs/tags/vX.Y.Z` of your version.

For 0.10.2 to 0.11.0, the repository is `https://github.com/interrupted-inc/murk` instead. The npm package has no earlier release. Version 0.10.2 names the ref `refs/heads/main`, and later versions name their tag.

## PyPI (`murk-secrets`)

Wheels and the sdist are published through PyPI Trusted Publishing, which attaches [PEP 740](https://peps.python.org/pep-0740/) digital attestations by default. Attestations are shown on each file's entry on PyPI and are available through PyPI's Integrity API.

The [`pypi-attestations`](https://pypi.org/project/pypi-attestations/) CLI is experimental. It verifies a downloaded file against its published provenance:

```bash
pipx run pypi-attestations verify pypi \
  --repository https://github.com/interrupted-sh/murk \
  pypi:murk_secrets-X.Y.Z-<tags>.whl
```

`<tags>` is the rest of the wheel file name, such as `cp39-abi3-macosx_11_0_arm64`.

For murk-secrets 0.10.2 to 0.11.0, pass `--repository https://github.com/interrupted-inc/murk` instead. For 0.10.1 and earlier, pass `--repository https://github.com/iicky/murk`. Those files were published before the repository moved.

`pip` does not verify attestations natively.

## crates.io (`murk-cli`)

crates.io has no signing or attestation support of its own, so the release workflow signs the crate file itself. For murk-cli 0.13.0 and later, the workflow does the following:

1. It packages the crate with `cargo package --locked --no-verify`.
2. It publishes the crate through crates.io **OIDC Trusted Publishing**, so no long-lived registry token exists to steal. This job runs only after the release preflight. The preflight requires the tagged commit to be on `main` and to come from a merged pull request. It also requires `main`'s branch protection to match the release baseline.
3. It confirms that the SHA-256 of the packaged file equals the checksum that the crates.io index records for that version. cargo rejects any download that does not match this checksum.
4. It attests the file with `actions/attest-build-provenance` and attaches it to the [GitHub release](https://github.com/interrupted-sh/murk/releases) as `murk-cli-X.Y.Z.crate`.

The file that cargo downloads is therefore the attested file. To verify it, use a logged-in `gh`, as described under [GitHub release binaries](#github-release-binaries):

```bash
# The file cargo downloads. A copy is also cached in
# ~/.cargo/registry/cache/index.crates.io-*/ after a build or install.
curl -fsSLO https://static.crates.io/crates/murk-cli/murk-cli-X.Y.Z.crate
gh attestation verify murk-cli-X.Y.Z.crate --repo interrupted-sh/murk \
  --signer-workflow interrupted-sh/murk/.github/workflows/release.yaml \
  --source-ref refs/tags/vX.Y.Z

# Optional: the checksum cargo enforces for that version must be the same
curl -fsSL https://index.crates.io/mu/rk/murk-cli \
  | jq -r 'select(.vers == "X.Y.Z") | .cksum'
sha256sum murk-cli-X.Y.Z.crate   # or: shasum -a 256
```

For murk-cli 0.12.0 and earlier there is no crate attestation. Instead, check the crate against the [signed tag](#release-tag). Crate packaging is deterministic, so a checkout of the tag gives back the same bytes. The packaged file must have the checksum that the crates.io index records for that version.

Use the allowed-signers file from [Release tag](#release-tag):

```bash
git fetch --tags
git -c gpg.ssh.allowedSignersFile="$HOME/murk-allowed-signers" verify-tag vX.Y.Z \
  && git checkout vX.Y.Z
cargo package --locked --no-verify
sha256sum target/package/murk-cli-X.Y.Z.crate   # or: shasum -a 256
curl -fsSL https://index.crates.io/mu/rk/murk-cli \
  | jq -r 'select(.vers == "X.Y.Z") | .cksum'
```

The `sha256sum` result must equal the `cksum` that the index prints.
