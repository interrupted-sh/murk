# Security Policy

## Cryptography

murk implements no cryptographic primitives. [age](https://age-encryption.org/) (the [rage](https://github.com/str4d/rage) Rust crate) encrypts and decrypts every value. BLAKE3 and Ed25519 provide the integrity MAC, the signing-key derivation and the vault signatures. The vault format, its keyed MAC and its signature scheme are murk's own (see [THREAT_MODEL.md](THREAT_MODEL.md)). A new key is 32 random bytes from a cryptographically secure random number generator, shown as a 24-word BIP39 recovery phrase.

If you find a vulnerability in the underlying cryptographic primitives, report it to the [age](https://github.com/FiloSottile/age) or [rage](https://github.com/str4d/rage) project directly. Report a flaw in how murk combines them (its MAC, signature or signing-key construction) to murk, as described below.

For a detailed analysis of what murk protects and what it does not, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Known Limitations

- **Not audited.** murk has not had an independent security audit. It is pre-1.0 software. Use good judgment with production secrets.
- **Not a secrets server.** murk is a file-based secrets manager for dev teams. It is not designed for regulated environments, dynamic secrets, automatic provider-side rotation or provable access controls. murk can record rotation intervals and expiry dates and report overdue secrets. If you need a secrets server, use one such as HashiCorp Vault.
- **Revoked recipients can read old git history.** Revoking a recipient re-encrypts the shared values and the group values that the revoker can read. A group value held by a group the revoker is not in keeps the revoked recipient in its ciphertext until a member of that group rotates it. Old `.murk` versions remain in git, and the revoked user can still decrypt any version they had access to. Always rotate secrets after revocation.
- **Plaintext during edit.** `murk edit` writes decrypted values to a temporary file for `$EDITOR`. murk overwrites the file with zeros and deletes it afterward, but the plaintext is on disk for as long as the editor runs. If murk is killed with SIGKILL, crashes or loses power, the file can stay behind. Core dumps, swap or filesystem journaling could also keep fragments. Under `MURK_STRICT`, `murk edit` refuses to run unless its scratch directory is RAM-backed (`XDG_RUNTIME_DIR` or `/dev/shm`).
- **A compromised workstation gives full access.** If an attacker has access to the machine where your key lives, they can decrypt all shared secrets. murk is not a defense against a compromised machine. It protects secrets at rest in git and in transit.
- **Secret names and metadata are public.** The `.murk` header is plaintext. It shows what secrets exist (for example `STRIPE_SECRET_KEY`), and for each one its description, example, tags, created and updated times, rotation interval and expiry. It also shows the recipients' public keys and the names of the groups that hold values. Only values are encrypted, so never put a real value in `--example`. This is a deliberate trade-off for usability (`murk info` without a key, readable git diffs).
- **Agent mode holds only while its variables stay set.** Strict and agent mode (`MURK_STRICT`, `MURK_AGENT`) stop murk from looking up your stored key. They hold only while `MURK_AGENT`, `MURK_STRICT`, `MURK_KEY` and `MURK_KEY_FILE` stay set in the agent's shell. An agent that runs as your user can unset them. Its next `murk` command then finds your stored key from the vault's path, and its grant no longer limits it. A change to this lookup is planned for 0.16. Until then, the boundary is a separate OS user or a container that cannot read `~/.config/murk`.

## Known Issues

**SSH-RSA timing side channel (RUSTSEC-2023-0071).** The `rsa` crate behind age's SSH-RSA support is affected by the Marvin Attack, a timing side channel. There is no upstream fix yet.

murk rejects `ssh-rsa` recipients by default:

- `circle authorize` and `ssh:` paths refuse RSA keys unless you pass `--allow-ssh-rsa`.
- `github:username` skips RSA keys with a warning. It refuses only when every key it finds is RSA.

The risk is low for a local CLI, because the attack needs many decryption queries against a server. The default still keeps weak keys out of the recipient list. Prefer ed25519 keys.

## Supply Chain

Every release artifact is built and published from GitHub Actions on hosted runners. Each channel carries signed provenance, but older releases have gaps on some channels:

- GitHub release archives and `SHA256SUMS`: Sigstore build provenance per file, 0.3.1 and later.
- Homebrew: the formula pins the SHA-256 of the attested GitHub release archives.
- crates.io: Sigstore build provenance for the exact `.crate` file, 0.13.0 and later.
- npm: registry signatures and Sigstore provenance.
- PyPI: PEP 740 Sigstore attestations per wheel and sdist.

Release binaries include [Sigstore artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations). Verify one downloaded binary at a time:

```bash
gh attestation verify murk-v<version>-<target>.tar.gz --repo interrupted-sh/murk \
  --signer-workflow interrupted-sh/murk/.github/workflows/release.yaml \
  --source-ref refs/tags/v<version>
```

This covers murk 0.12.0 and later. Earlier releases name an older repository in their provenance. That is `interrupted-inc/murk` for 0.10.2 to 0.11.0 and `iicky/murk` for 0.3.1 to 0.10.1. [VERIFYING.md](VERIFYING.md) shows how to verify them.

Release tags are signed with SSH. Verify a tag (replace `vX.Y.Z` with the release tag) after adding the maintainer's signing key to your allowed signers, as described in [VERIFYING.md](VERIFYING.md#release-tag):

```bash
git verify-tag vX.Y.Z
```

See [VERIFYING.md](VERIFYING.md) for per-channel verification, including the npm, PyPI, and crates.io packages.

### Repository automation secrets

Release and CI automation uses these long-lived secrets. Each must be held to the minimum scope it needs:

- **`HOMEBREW_TAP_TOKEN`**: a fine-grained personal access token for the `interrupted-sh/homebrew-tap` repository only, with `contents: write` and nothing else. Only the release workflow uses it, to push the Homebrew formula. The tap is shared by all interrupted.sh tools, so the token can write every formula in it.
- **`PREFLIGHT_APP_ID`** and **`PREFLIGHT_APP_PRIVATE_KEY`**: a GitHub App installed on `interrupted-sh/murk` with `administration: read`, `contents: write` and `pull-requests: write`. Each workflow requests a narrower token. The release preflight uses a read-only token to check branch protection. The advisories workflow uses a `contents: write` and `pull-requests: write` token to open dependency fix pull requests.
- **`CODECOV_TOKEN`**: a Codecov repository upload token (not a personal account token), used only to upload coverage for this repository.
- **`CLOUDFLARE_API_TOKEN`** and **`CLOUDFLARE_ACCOUNT_ID`**: used only to deploy the docs site and its previews.

Workflow `GITHUB_TOKEN` permissions follow least privilege: read-only by default, elevated per job only where a step needs it (for example `id-token: write` for OIDC publishing and build provenance, `security-events: write` for code scanning).

## Supported Versions

murk is pre-1.0 software. Only the latest 0.x release receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://github.com/interrupted-sh/murk/security/advisories/new) to submit a report. You'll get a response within 14 days.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

## Scope

In scope:
- Secret values leaking into plaintext (logs, error messages, temp files)
- Bypassing recipient-based access control
- Key material exposure beyond the key file, `MURK_KEY`, or a `.env` that holds an inline `MURK_KEY`
- Bypassing MAC or signature verification, or signer pinning
- Flaws in murk's MAC, signature or signing-key construction
- Bypassing a grant's scope or expiry, or the agent allow-tag policy, inside the murk binary

Out of scope:
- Vulnerabilities in the age or rage primitives (report upstream)
- Attacks that need local access to your key file, `MURK_KEY`, or an `.env` that contains `MURK_KEY` (these hold the secret key by definition). The default `.env` from `murk init` holds only the key file's path
- Limits that [THREAT_MODEL.md](THREAT_MODEL.md) lists under "What murk does not protect", for example values that output masking misses, or a policy bypassed by using age directly
- An agent that runs as your user and unsets `MURK_AGENT`, `MURK_STRICT`, `MURK_KEY` and `MURK_KEY_FILE` to reach your stored key. This is the known limit above. A bypass of a grant's scope while those variables stay set, or by a user that cannot read your key directory, is in scope
- Denial of service against the CLI
