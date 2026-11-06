# Threat Model

This document describes murk's security properties and limits. It is for anyone evaluating murk for team use. Read it before you trust it with production credentials.

murk is pre-1.0 software and has **not been independently audited**. If you find a vulnerability, see [SECURITY.md](SECURITY.md) for how to report it privately.

This document is also murk's assurance case. The sections from [What murk protects](#what-murk-protects) to [Key compromise scenarios](#key-compromise-scenarios) hold the threat model. [Trust boundaries](#trust-boundaries) is one of them. It shows what is public and what is encrypted. [Cryptographic properties](#cryptographic-properties) lists the primitives and formats. [Secure design principles](#secure-design-principles) and [Common implementation weaknesses](#common-implementation-weaknesses) hold the arguments for a secure design and against common weaknesses. Code references in those two sections are paths from the repository root, with the function name.

## Glossary

These terms have one fixed meaning in this document.

- **age**: the open-source encryption tool that murk uses for all encryption and decryption ([age](https://age-encryption.org/)).
- **Vault**: the `.murk` file that you commit to git. It is one JSON document, partly plaintext and partly encrypted.
- **Header**: the plaintext part of the vault. Anyone with read access to the repository can read it.
- **Secret name**: the name of a secret, such as `DATABASE_URL`. Commands write it as `KEY`. This document uses "key" only for cryptographic keys.
- **Recipient**: a public key that the vault encrypts secrets to. It is an age key (`age1…`), an SSH public key or a hardware (age plugin) key. The header lists every recipient.
- **Key file**: the file that holds a recipient's secret key. `murk init` writes it to `~/.config/murk/keys/`, and `MURK_KEY_FILE` can name another file. `MURK_KEY` holds the secret key itself.
- **Operator**: the person who runs murk with their own recipient key, as opposed to an agent.
- **Agent grant**: a temporary identity that `murk agent grant` makes for an AI agent. It reads only the secrets in its scope (`--only`) until its time to live (TTL) ends. The header lists its key as a recipient.
- **Shared layer** (`everyone`): the secrets that the vault encrypts to every recipient except agent grants. Every such recipient can read them.
- **Private secret** (mote): a secret that the vault encrypts to one recipient only. No other recipient can read it. On the CLI it is the `me` tier (`--group me`).
- **Group**: a named set of recipients, such as `prod`. The vault encrypts a secret assigned to a group only to that group's members.
- **Schema**: the header's metadata about each secret: its description, example, tags and dates. It holds no secret values.
- **Policy**: the optional agent allow-list of tags in the header (`murk policy set --allow-tag`).
- **MAC**: a BLAKE3 keyed hash over the vault's contents. It detects corruption. Every recipient except agent grants holds the MAC key.
- **Meta**: the encrypted meta blob in the vault. It holds the MAC key and the data that the header does not show, such as recipient display names and group membership. Every recipient except agent grants can decrypt it.
- **Signer**: a recipient whose key signs the vault when it saves. age keys and `ssh-ed25519` keys can sign. `ssh-rsa` keys and hardware keys cannot.
- **Verifying key**: the Ed25519 public key that checks a signature. An `ssh-ed25519` recipient is its own verifying key. An age recipient has a separate one.
- **Fingerprint**: how murk shows a verifying key for a human to compare. It is `SHA256:` and the unpadded base64 SHA-256 of the verifying key, the `ssh-keygen -l` form.
- **Signer registry** (`signers` in the meta): the list that maps each age recipient to its verifying key.
- **Trusted signer**: a signer that a machine accepts. It is a non-grant recipient of the last vault this machine accepted, or a signer listed in `MURK_TRUSTED_SIGNERS`.
- **Save counter** (`generation` in the header): a number that each save raises. The MAC and the signature cover it.
- **Vault id**: a random 16-byte id (32 hex characters) that `murk init` writes to the header. A vault upgraded from murk 0.13 gets one derived from its creation time and name instead. A machine uses it to refuse another vault's file.
- **Trust pin**: a file on each machine, outside the repository, that records what this machine trusts for one repository. It holds the trusted signers and their verifying keys, the vault id and the highest save counter per git branch (the mark). It lives in `~/.config/murk/signer-pins/`.
- **Mark**: the highest save counter this machine accepted for a git branch, kept in the trust pin. A vault numbered below the mark is refused as rolled back. A branch this machine never accepted has no mark.
- **Trust on first use**: accepting a key the first time you see it, with no earlier record to compare it with.
- **Out of band**: through another channel than the repository, such as a call or a chat with the person.

## What murk protects

**Secrets at rest in git.** The `.murk` file is designed to be committed. Every secret value is individually encrypted with [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305). Anyone with read access to the repository cannot decrypt values without a recipient's private key.

**Secrets in transit via git.** Values are encrypted before they ever reach git, so pushing or pulling over any transport (HTTPS, SSH, or unencrypted) never exposes secret values.

**Cross-value integrity (tamper-evidence).** A BLAKE3 keyed MAC inside the encrypted meta blob binds the independent age ciphertexts together. It covers:

- every secret name and all encrypted values (shared, grouped and private)
- the recipient set
- the vault's schema, group definitions, grants, policy and revocation markers
- the per-grant agent blobs
- the header identity fields (since vault format 3.0): vault name, repo URL, creation time, vault id and save generation.

The MAC is mandatory whenever the vault holds secrets, and it catches accidental corruption and naive tampering. On a vault with no signature (a team entirely on `ssh-rsa` or hardware/plugin keys, which cannot sign), the MAC is the only tamper-evidence murk itself provides, and git remains the anchor.

The MAC alone is **not** a defense against a deliberate attacker with write access to the repo. Its key lives in the meta blob, and age encryption needs only the recipients' *public* keys (which sit in the plaintext header). So anyone who can write the file can mint a fresh MAC key, recompute a valid MAC over tampered content, and re-encrypt the meta blob. age gives you confidentiality, not authentication of who produced a ciphertext.

**Authorship integrity (signatures and trust).** To close that gap, murk signs the vault with the writer's key (see [Vault signatures](#vault-signatures) below). A machine accepts a vault only when its signer is a key **this machine trusts**. That key is recorded in a local trust pin outside the repo, or given in `MURK_TRUSTED_SIGNERS`. A signature alone is not enough: the vault chooses its own recipients, so a repo-writer can list their own key and sign with it. What protects is the pinned set of trusted signers. The MAC remains as a fast corruption check.

**Per-recipient secrets.** Private secrets (motes) are encrypted to a single recipient's public key. No other recipient, authorized or not, can decrypt them.

## What murk does not protect

These are not bugs. They are the edges of the design. Know them before you rely on murk.

### Non-goals

murk does not try to protect against these, or protects against them only in part.

**Compromised machines.** If an attacker gets access to a machine where the secret key lives (`~/.config/murk/keys/`, in memory, or in an environment variable), they can decrypt every shared secret and any private secret belonging to that key.

**Secret names are public.** The `.murk` header stores secret names, descriptions, and examples in plaintext. Anyone with repo access knows you have a `STRIPE_SECRET_KEY` or a `DATABASE_URL`. That is a deliberate trade-off. It is what lets `murk info` work without a key and keeps git diffs readable. If your threat model requires hiding *what services you use*, murk does not address that. The `--example` option of `murk add`, `murk generate`, `murk import` and `murk describe` writes into this public header, so give it a made-up value, never a real one.

**In-memory secret exposure.** Zeroization is best-effort. What murk does:

- Decrypted secret values are wrapped in `zeroize::Zeroizing<String>`, so murk wipes the plaintext from memory when the wrapper drops.
- The secret key uses age's `SecretString`, which zeroizes the same way. Key files are read into a zeroizing buffer. Commands borrow the key from the `SecretString` instead of copying it. The vault's MAC key is zeroized in the decrypted meta.
- Decryption sizes its output buffer once, so it never reallocates and leaves a partial copy of the plaintext behind.
- On Linux the CLI also marks itself non-dumpable, so another process of the same user cannot attach a debugger to it or read its memory or environment through `/proc` (`deny_same_user_inspection` in `src/hardening.rs`).

What it cannot reach:

- Transient buffers inside age's decryption path, the shell-escape output from `murk export`, `serde_json` serialization (including the value the MCP `murk_get` tool returns), and OS-level copies (stdout, child process environments, swap, core dumps) can still retain plaintext.
- murk does not lock memory with `mlock`, so it can be swapped out.
- On macOS and Windows a same-user process with debugging rights can still read a live murk's memory. murk does not use macOS's `PT_DENY_ATTACH`, because it only stops a debugger that cooperates.

If your threat model includes swap forensics or memory dumps of live processes, treat decrypted values as recoverable.

**Library bindings (Python/Node) and the FFI boundary.** The bindings hand plaintext to a host runtime, and murk's zeroization cannot follow it there.

- On a **read** (`get`/`export`), the decrypted value is copied out of `Zeroizing<String>` into a native host string (a Python `str`, a V8 `String`). The host's garbage collector owns that string and frees it on its own schedule. murk never gets to wipe it.
- On a **write** (Node `vault.add` and the write path), the exposure is sharper. The caller builds the plaintext as a host string *before* calling murk, so it already lives in GC-managed memory. It is then copied across the FFI boundary into a Rust `String`, and neither side zeroizes it. The plaintext originated in your process, not in murk's decryption path, and lingers under the GC's control.

This is inherent to moving secrets across a language boundary. Build write values as late as possible, pass them straight in, and keep no long-lived references.

The bindings otherwise inherit every guarantee enforced in the library load/save path (agent policy, grant TTLs, the trust check, the keyed MAC). A vault the CLI refuses, the bindings refuse with the same message. The leak is memory hygiene, not access control.

The bindings apply the same trust rules as the CLI on every call that reads the vault, with the CLI's messages. A refused or tampered vault raises `murk.TrustError` in Python and throws an `Error` with code `MURK_TRUST` in Node. Warnings about an accepted vault are exposed as `vault.warnings`. There is no option to skip the check.

**Historical access after revocation.** Revoking a recipient re-encrypts the shared values going forward, and the group values the revoker can read. It cannot re-encrypt a group value held by a group the revoker is not in. That value keeps the revoked recipient in its current ciphertext until a member of that group rotates it. Old `.murk` versions also stay in git history exactly as they were. The revoked recipient can still decrypt any version they previously had access to. Always rotate credentials after revocation. murk warns about this at revoke time.

**Post-revoke rotation tracking.** Revoking a recipient re-encrypts going forward, but old `.murk` versions in git stay readable with the revoked key, so the exposed values still have to be rotated to actually cut access. When rotation is deferred at revoke time, murk stamps each exposed secret with a `revoked_at` marker in the plaintext header.

- `doctor` flags the marker until a value write clears it. So the obligation survives a declined prompt and stays visible without a key.
- The keyed MAC (`blake3v7:` and every later prefix) covers the marker, so a keyed load catches an attacker clearing it. A keyless read is unverified (see **Keyless reads of the header are unauthenticated** below).

This is a hygiene reminder, not enforcement. It does not and cannot rotate the underlying credential at its provider, and the revoked key keeps working against git history until you do.

**Fine-grained access control.** Every recipient except agent grants can decrypt every *shared* secret. Anything in the shared layer (`everyone`) is readable by all of them. Named recipient groups narrow that. A secret assigned to a group is age-encrypted only to that group's members. So a leaked member key exposes only the groups it belongs to (plus the shared layer), not the whole vault. age enforces this cryptographically. The keyed MAC (`blake3v4:` and every later prefix) covers group membership, so nobody can alter it undetected. Limits:

- Group *names* and which secret belongs to which group are plaintext in the header. Only membership is hidden, in the encrypted meta.
- Managing a group requires being a member of it (you cannot re-encrypt what you cannot read).
- The historical-access caveat above applies per group too: removing a member re-encrypts going forward, but old `.murk` versions in git remain readable, so rotate.

**No admin role (flat trust).** murk has no admin role. Every recipient except agent grants can add and remove recipients (including the vault's creator), create groups, manage the groups they belong to, set the policy and mint grants. Group-only and personal values stay protected from recipients outside the group. Changes are attributable through vault signatures (keys that cannot sign, such as hardware keys, rely on signed git commits).

**Keyless reads of the header are unauthenticated.** The MAC and signature need a key. So `murk ls`, `info`, `circle`, `skeleton`, `agent plan`, `policy show` and `doctor`'s rotation check read the plaintext header without verifying it. Anyone who can write the repository can delete an `expires_at` or `revoked_at`, strip the agent policy, or edit a description, and these commands present the result as fact.

- They print `warn unverified header` when run without a key.
- A run with a key does not check the header either, because these commands do not load the vault.

`murk rotate --list` is the exception.

- With a key it verifies the vault (MAC, signature, trust) before reporting, so an edited header fails the command.
- Without a key it labels its result `verified: false` (`--json` prints `{"verified": …, "issues": […]}`), and `MURK_STRICT` refuses it.

A CI gate that depends on rotation state should run `rotate --list` with a key or a grant key, or under `MURK_STRICT`. It must not treat `doctor` or `ls` output as authenticated.

**Audit logging.** murk has no built-in audit trail beyond git history. It does not log who decrypted what, or when. For regulated environments that require provable access controls, use a dedicated secrets server.

**Admin-change accountability (agents and otherwise).** murk does not commit for you. Once you commit each administrative change to the `.murk` file, **git history is the admin audit trail**. These changes all appear in `git log -p -- .murk`:

- creating or revoking an agent grant
- setting or clearing a policy
- authorizing or revoking a recipient
- rotating a value after an agent session.

Git attributes each one to the commit author (and cryptographically signs it if you use git commit signing).

What the history shows:

- Recipient keys and the policy block are plaintext there.
- A grant shows up as a new recipient key and new scoped ciphertexts. Those show which secrets that key can read.
- Only a keyholder can read the grant record (name, scope list and TTL) with `murk agent ls`. The issuer is recorded in the encrypted meta, but no command prints it.

`murk diff` is the review tool:

- It shows recipients added and removed, signer and signing-key changes, policy, grant and group-member changes, and which secrets were added, removed or changed (their values only with `--show-values`).
- It verifies the MAC and signature of both revisions.
- On a machine with a trust pin or `MURK_TRUSTED_SIGNERS`, it also refuses an old revision whose signer this machine never trusted (see Complete mediation under [Secure design principles](#secure-design-principles) for the exact rules).
- On a machine with neither, it shows the old revision under a "not trusted on this machine" warning, and `MURK_STRICT` refuses that.
- It shows a working vault this machine has not trusted yet with a warning, because `diff` is the review step before `murk trust`.

`git diff -- .murk` remains the raw view of the file.

murk deliberately does **not** keep a second event log inside the vault. It would duplicate git and could drift from it. The integrity MAC also uses a key that every recipient shares, so any keyholder could forge entries. Such a log would be weaker than git on attribution, not stronger.

What cannot be audited at all:

- Secret *reads* on a developer's machine (murk cannot see them).
- Any action taken with age directly or an old murk binary.

The vault signature names only the recipient who wrote last, not who made each change. Per-change attribution comes from git commit identity. A signed per-change log would need new design, which murk has deferred until a concrete requirement exists.

### Agent feature limits

These limits apply to the agent features: grants, `agent exec`, output masking, the agent access policy and the MCP server.

**Agent grants.** `murk agent grant` mints an ephemeral age identity and gives it read access to a fixed set of secrets (`--only`) without ever exposing the operator's own key.

What a grant can read:

- The agent is not a recipient of the encrypted meta blob, and it is deliberately excluded from the shared layer.
- It can decrypt only its own grant record (an `agents` blob encrypted to its key alone) and the private values granted to it. age enforces this cryptographically.
- It cannot check the MAC, so it trusts a vault only by its signature, against the signers named in its key file (see [Vault signatures](#vault-signatures)).
- Grant metadata (scope, TTL, issuer) lives in the encrypted meta, and the keyed MAC (`blake3v5:` and every later prefix) covers it, so nobody can alter it undetected.

A grant key file that survives a revoke keeps trusting the revoked signer.

- When `circle revoke` removes a signer, it revokes every grant whose key file trusts that key (or whose trusted signers were not recorded). It also deletes murk's own copy of that key file.
- A copy elsewhere (written with `--out`, handed to the agent host, or made on another operator's machine) still accepts a vault signed by the revoked key, including one that carries the grant. The agent then reads that signer's values.

A key file carries its grant's name and expiry (`# murk-grant-id:` and `# murk-grant-expires:` lines, written at mint and on `--renew`).

- The grant then ends at the earlier of that expiry and the one in the vault's grant record.
- A record naming another grant is refused. So a copy stops at the TTL it was minted with, even if the revoked signer writes a record with a later expiry.
- A key file without those lines (minted by an older murk, or passed as a bare `AGE-SECRET-KEY-1` line) falls back to the vault's record alone, which the revoked signer can extend. murk warns once to re-mint it.
- A malformed or repeated line is refused.
- The expiry bounds every copy of the file, not its holder: whoever can edit a copy can delete the line. Delete every copy of the key file and re-mint the grant.

Limits to understand:

1. The agent learns only its own grant record, not recipient display names, group membership or other grants. It still sees the plaintext header, including every recipient key and which recipient keys hold private ciphertexts for which secrets.
2. **The TTL is enforced at read time, not cryptographically.** murk refuses to read a value with an expired grant on every value read (get, exec, MCP get and exec, bindings). `murk agent plan` reads no values and needs no key, so it keeps listing every schema entry's secret name, description, example and tags (filtered only by `--tag`) after expiry. It judges expiry by the earlier of the vault's grant record and the key file's own expiry line, and `agent ls` flags it. A running MCP server re-checks expiry on `murk_get` and `murk_exec`, but `murk_plan` keeps listing secret names, descriptions, examples and tags (never values) until the server restarts. age keys cannot self-destruct, and old `.murk` versions stay readable in git, so a leaked grant key works against history with raw age until `agent revoke` plus rotation.
3. The ephemeral key is a bearer credential: whoever holds the key file has the access. Real containment requires OS-level isolation: an agent running as the same user with read access to your home directory can read `~/.config/murk/keys` directly and bypass murk entirely, so run agents in a sandbox, container, or under a separate user. `MURK_STRICT` disables key auto-discovery, so a granted agent does not fall back to the operator's stored key by accident. This holds only while MURK_AGENT, MURK_STRICT, MURK_KEY and MURK_KEY_FILE stay set in the agent's shell: an agent that unsets them gets the stored key from the vault's path, and its grant no longer limits it. A change to this lookup is planned for 0.15. Until then, a separate OS user or a container is the boundary. Also, `murk agent exec` run with a grant key, which injects secret *values* into a child process and hands the agent no key at all, is the safest pattern where it fits.

**`agent exec` and the operator's stored key.** `murk agent exec` decrypts in the parent process, before it marks the child as an agent context. An agent shell with no `MURK_*` set would therefore resolve the operator's personal key from `~/.config/murk/keys`. Then the tag allow-list would be the only gate: no grant, no TTL. So `agent exec` fails closed on any key that is not an agent grant:

- It resolves the key source before loading the vault and refuses an auto-discovered key at that point.
- Once the vault is open, and before it resolves any secret, it refuses any other key that is not a grant, such as an exported `MURK_KEY` or `MURK_KEY_FILE` that names the operator's key.

The operator can lift both refusals with `--allow-operator-key`. The flag prints a warning on every run that uses a non-grant key, in CI or not.

This is a check in the murk binary. An agent that can read `~/.config/murk/keys` can still pass the flag itself. Harnesses should require confirmation for `--allow-operator-key`, and OS-level isolation remains the boundary.

**Output masking.** `murk agent exec` and the MCP `murk_exec` tool replace each injected value in the command's stdout and stderr with `***NAME***`, where NAME is the secret's name. Masking matches raw bytes, longest value first. Values under 4 bytes are not masked. To mask, `agent exec` supervises the child instead of `exec`-ing it, so murk holds the injected values (zeroized on drop) in memory for the child's lifetime.

This is an accident guard, not a security boundary. Masking catches an `env` dump or a debug line, not a determined command. An encoded, transformed, partial, or file-written value is not caught, nor is one split between the two streams. A command that wants to leak a value it was handed can.

**Agent access policy.** `murk policy set --allow-tag TAG` records a tag allow-list in the plaintext header. The MAC covers it, so a keyed load catches it being stripped or weakened. A keyless read is unverified (see **Keyless reads of the header are unauthenticated** under [Non-goals](#non-goals)). In agent mode (`agent exec`, `agent grant`), a secret can be injected or granted only if it carries an allowed tag. Anything else is refused, with no override flag.

This is explicitly NOT access control. It is a machine-enforceable guardrail. Its scope and limits:

- It constrains the *murk binary*. It does nothing against a human insider using age directly, or an older murk build that predates the policy MAC version.
- It gates what reaches agents, not what recipients can decrypt.
- It travels with the repo, so the same constraint applies in CI.

The value is keeping production secrets out of agent reach by accident, or by a misbehaving agent that asks for them. Merging two branches that changed the policy differently raises a conflict rather than silently picking one side.

**Agent MCP server.** `murk mcp` exposes secrets to AI-agent harnesses over the Model Context Protocol on a local stdio pipe, not a network listener. It uses the same checks as every other agent path:

- It refuses to start unless the loaded identity is a scoped grant with `MURK_AGENT=1`, so it can never serve the operator's full read scope.
- `murk_plan` and `murk_get` are limited to the secrets the grant may read and the agent policy allows. They fail closed on anything else.

`murk_exec` (running a command with scoped secrets injected) is off by default and enabled only with `--allow-exec`. `only` bounds the injected *secrets*, but the command itself runs as the server's user with its filesystem and network access. So it is a guardrail, not a sandbox. As with `agent exec`, the real containment boundary is the OS: run the server (and the agent) under a separate user or container.

## Vault signatures

murk signs the vault so that a change by someone with write access to the repo is detectable. It anchors *which* signers count in state the repo cannot write. SPEC.md (Signatures, Trust) has the exact rules.

**Signing.** On save, a signing-capable writer signs the vault file with its `sig` field left out (signed view 2), and stores the signature in the plaintext header (`sig`). That covers every header field (the vault format version, vault id, save counter, vault name, repo URL, creation time, recipients, schema and policy), every ciphertext, and the encrypted meta. Groups, grants, GitHub pins and names are covered through the meta ciphertext.

- **age keys** sign with an Ed25519 key derived from the age key through a domain-separated BLAKE3 KDF, as in 0.13, so the recovery phrase recovers it too. Its verifying key cannot be computed from the `age1…` recipient, so the writer publishes it in the signer registry (`signers` in the encrypted meta).
- **ssh-ed25519 keys** sign with the key itself. The verifying key is in the `ssh-ed25519 …` recipient string.
- `ssh-rsa` and hardware/plugin identities cannot sign (age exposes no signing scalar for them), so their saves are unsigned.

A **present-but-invalid** signature fails the load as tampering. A vault last written by murk 0.13 or earlier carries a v1 signature inside the meta. It does not cover the vault name, repo URL or creation time, and murk replaces it with view 2 on the next save.

**Strict verification.** murk checks every signature with strict Ed25519 verification (`verify_strict`, which also refuses a small-order `R`). Every verifying key passes one check (`checked_verifying_key` in `src/signing.rs`). It refuses non-points, non-canonical encodings (a second spelling of one key) and small-order keys. Without it, a forged signature under a weak key such as the identity point would verify for any message.

What happens to a key that fails the check:

- A signer registry carrying such a key fails the load as tampering before any trust decision, so nothing from it is pinned.
- A signature by a weak ssh-ed25519 signer never verifies, so that load fails as tampering too.
- A trust pin can already hold a 32-byte key that is weak, non-canonical or not on the curve (a `signers` entry, or an ssh-ed25519 key in the trusted set). murk ignores it with a warning that names the pin file, and drops it on the next pin write.
- A pin value that is not a 32-byte key is left alone, because it never verifies a signature.
- A key that fails this check in `MURK_TRUSTED_SIGNERS` or in a grant key file's anchor line is an error naming that source.

*Gap:* keys with a torsion component that are not small-order are still accepted as verifying keys. Strict verification defeats the small-order-`R` forgery they would enable, but murk does not reject them outright the way it rejects such recipients.

**Trust.** murk runs these checks on every keyed load: the CLI, the MCP server, the bindings, and write commands (which load first). It checks the vault against the local trust pin (`~/.config/murk/signer-pins/`, one per repository and shared by its worktrees) or `MURK_TRUSTED_SIGNERS`:

- The signer must be a trusted signer: one of the non-grant recipients of the last vault this machine accepted, or listed in `MURK_TRUSTED_SIGNERS`. A machine with neither refuses until the user runs `murk trust`.
- An unsigned vault is refused when the loading key could have signed it, or when `MURK_TRUSTED_SIGNERS` is set. A key that cannot sign loads it with a warning. A vault this machine accepted signed that is now unsigned is refused for everyone.
- An agent-grant key never counts as a signer, including after it removes its own grant record.
- The vault id must match the pinned one. The save counter must not be below the highest accepted on the checked-out git branch, or the vault is refused as rolled back.
- A change to a group's membership must be signed by a member of that group.
- For an age signer, the verifying key must be the one this machine pinned for that signer, or the one `MURK_TRUSTED_SIGNERS` gives.
  - A trusted signer with no pinned key yet is refused until `murk trust` confirms the key.
  - A different key for a signer whose key is pinned is refused as a forgery, and `murk trust` will not accept it. An age key's verifying key is derived from its secret, so it cannot change.
  - ssh-ed25519 signers need no pinned key.
- A murk 0.13 (view 1) signature verifies only on a 2.x vault without a vault id or save counter.
  - A view-1-signed vault is refused only where this machine has a 0.14 mark. On a git branch that is a mark above 0 for the branch in the pin. Outside git it is the overall mark or a pinned vault id. A detached HEAD has no mark.
  - Worktrees share the pin, but a 0.14 save gives only its own branch a mark. A load never gives a branch its first mark, and a merge does not either. So a branch that merged the upgrade has no mark until this machine saves there.
  - Anywhere else the vault loads as history. It may narrow the pin and never widen it, and every other rule still applies to it.
  - Once this machine has seen the vault in 0.14 form, that history is read-only: every write over it is refused until `murk trust` accepts that copy.

Each machine pins its trusted signers' Ed25519 verifying keys.

- A signer-registry entry (recipient → verifying key) is believed only from a vault signed by a signer this machine already trusts, or one the user confirmed with `murk trust`. A pinned key is never replaced.
- A newly authorized age-key teammate's first signed write carries their key in a registry they wrote themselves, so nothing vouches for it. Every other machine refuses that write once and shows the key's fingerprint.
- To accept it, confirm the fingerprint with the teammate out of band (they run `murk trust --print-key`), then run `murk trust`. This is trust on first use.
- After that, any write by a machine that confirmed the key carries it in a registry signed by a trusted signer, and other machines learn it without a prompt.
- ssh-ed25519 teammates, including ones authorized through GitHub, need no confirmation, because the public key is its own verifying key.
- Nothing is pinned from a refused or unverified vault.

**`murk trust`.** This is the explicit trust step. It is needed:

- once per vault on each machine (a fresh clone, a new laptop, the first run after upgrading from 0.13)
- on each machine when a newly authorized age-key teammate first writes
- after a refusal that a human can accept.

It shows:

- the vault id and save counter
- each signer's recipient key and verifying-key fingerprint (`SHA256:` and the unpadded base64 SHA-256 of the verifying key, the `ssh-keygen -l` form)
- the recipient changes since this machine last trusted the vault.

Then it records the decision. On a fresh clone this is trust on first use: murk cannot tell whether the keys shown are your teammates', so compare the fingerprints out of band.

What it does with each kind of vault:

- On an unsigned or stripped vault it re-signs with the user's key.
- A murk 0.13 vault that is read-only here (see the last item under **Trust** above) is accepted without re-signing. `murk trust` says it is read-only until accepted, asks, and records that exact copy for the branch as a SHA-256 fingerprint. The next write upgrades it. On a detached HEAD it refuses, since there is no branch to record the copy on.
- For a murk 0.13 vault, here or when it is refused as pre-0.14 and re-signed, `murk trust` records only that fingerprint. At that moment the trusted set, the groups and the recorded removals stay as they are. So a member who joined after the copy was written is never recorded as removed.
- The save that follows (the re-sign, or the next write after a read-only accept) is an own save, a save this machine makes itself. It changes the trusted set only by what it adds or removes itself, and it pins the groups the file it writes carries, which are the copy's. Narrower groups only make the group rule stricter. It does encrypt to the copy's recipients, so review the copy first. A real removal is still learned only from a vault this machine accepts as current.
- Suppose `murk trust` accepts an older murk 0.13 copy of this vault for another reason, after this machine saw the vault in 0.14 form. (For example, the copy is signed by a key this machine did not trust yet.) The acceptance then adds what the user accepted: the copy's signer and recipients become trusted. It narrows nothing. Members who joined after the copy was written stay trusted, nobody is recorded as removed, and the pinned groups stay.
- Accepting another vault's file is unchanged: it replaces the trust state for that vault, as before. An unsigned or stripped murk 0.13 file of another vault is the exception. Once the pin has a vault id, it is refused as another vault (not as unsigned or stripped). `murk trust` refuses to accept it at all, so it is never re-signed under this vault's id.
- It refuses a vault signed by a grant key, and refuses to run for a grant identity.

**CI and opting out.** `MURK_TRUSTED_SIGNERS` names the signers allowed to sign, separated by commas or newlines. An age signer is `age1…:<base64 verifying key>`, and an ssh-ed25519 signer is its public key line. `murk trust --print-key` prints your own entry. The variable:

- replaces the pin's trusted set
- pins those verifying keys for the load
- never widens what the pin trusts later
- makes an unsigned vault an error for every key.

A bare age key without its verifying key, or any other invalid entry, is an error.

Set `MURK_TRUSTED_SIGNERS` only from a CI secret or the real process environment. Never set it from a file in the repository, or from a `.env` that an app's dotenv loader reads. The CLI never reads `.env`. The Python and Node bindings read the process environment, so an app that calls `load_dotenv()` or `dotenv.config()` before `murk.load()` lets a repository `.env` choose the trust anchor.

A grant's key file carries the same entries as `# murk-trusted-signer:` header lines, written when the grant is minted or renewed. They are the signers the operator's pin trusts (grant keys excluded, and an age signer whose verifying key this machine has not confirmed left out), plus the key that minted the grant.

- When a grant loads the vault, the signer and its verifying key come only from those lines, plus any `MURK_TRUSTED_SIGNERS` entries. Nothing inside the vault, the registry included, is consulted for the signature check. Only after it passes does the grant decrypt its own values.
- A key file with no such lines and no `MURK_TRUSTED_SIGNERS` is refused, with a message to mint the grant again.

`MURK_NO_SIGNER_PIN` set to any value (even `0` or an empty string), or no home directory, stops murk reading or writing the pin. It does not switch the trust check off. Every signed vault is then refused unless `MURK_TRUSTED_SIGNERS` names its signer, and rollback and stripped-signature detection are off.

**Rollback.** The save counter's high-water mark is kept per git branch. A detached HEAD, a branch this machine has never seen and a runner without a pin have no mark. To revert on purpose:

1. Restore the older file.
2. Run `murk trust`. It shows the counter going back.
3. Make any write. That save is numbered above everything this machine accepted, so teammates accept it as newer.

`git revert` of a vault commit is such a restore: the reverted vault is refused as rolled back until you run `murk trust`.

**Removal is permanent.** When a machine accepts a vault that removes a trusted signer, its trust pin records:

- the key
- the generation it was removed at
- the branch it was made or accepted on.

From then on, this machine refuses a vault signed by that key on every branch, on a detached HEAD and outside git. The merge driver judges removals whichever branch it merges into.

The one exception is that key's own vault from before its removal. The refusal skips it only when all of these hold:

- it is checked out on a branch the removal has not reached
- the checkout is at the commit this machine made or accepted the removal at, or an ancestor of it
- the vault file is exactly as committed
- it is numbered at or below the generation the key was removed at.

Above that generation it is refused everywhere, including in the history of a machine that learned of the removal late.

The exception fails closed. There is none:

- when no commit was recorded (outside git, a removal accepted from an uncommitted vault file, or a pin from before this rule)
- when git no longer has the recorded commit.

murk never infers the commit from branch tips. For a removal this machine makes, the recorded commit is the one checked out when it saves, before the removal is committed. If a removal is abandoned (its branch is never merged), `murk trust --re-add` undoes it on a machine that recorded it.

A vault that passes the exception loads, and it never makes the key trusted again. On a branch this machine never accepted it is read-only: a save that keeps the key is refused.

A vault that lists the key at or below that generation is refused as rolled back where the removal applies:

- on the branch it was made or accepted on
- on any branch where this machine later accepts a vault at or after the removal that no longer lists the key
- on a detached HEAD
- outside git
- on any branch this machine never accepted, because that branch may be a replay.

Only this listing rule is relaxed, on two kinds of branch:

- a branch this machine accepted before the removal reached it
- a never-accepted branch checked out at the commit this machine made or accepted the removal at, or an ancestor of it, while the vault file is exactly the one committed at HEAD. Any uncommitted change to it, for example `git checkout <old> -- .murk`, loses the relaxation.

On such a never-accepted branch, a save that would keep the key is still refused. No vault on a relaxed branch drops the recorded removal. This holds in `MURK_TRUSTED_SIGNERS` mode as well.

A removal made on an unmerged feature branch has these effects:

- It refuses the removed person's new signatures on this machine at once, on main too.
- Main's vaults that still list them keep loading until the removal reaches main.
- Until then they are still a recipient on main, so every secret added or rotated there is encrypted to them, and they can read it.

So merge the removal into main before adding or rotating secrets elsewhere. A `--rotate` on the feature branch protects only the values rotated there.

Merging the removal into a branch the removed member wrote to stops with a conflict naming their side. To recover:

1. Keep the side that removed them (`git checkout --theirs -- .murk`) and `git add` it. That drops every vault change made on the other branch since the two branches split, by anyone, not only by the removed member.
2. Run `murk trust`. The kept vault may read as a rollback or fork. Accepting it never trusts the removed member again.
3. Find that branch's last vault commit not signed by them (`git log -- .murk`).
4. List what differs with `murk diff <that commit> --show-values`, and review it change by change. A later vault signed by a trusted member can still carry the removed member's changes.
5. Make again with murk only the changes trusted members made, and commit.

murk 0.14 has no automatic re-merge for this. The refusal first suggests updating to the vault that removed the key (pull, or merge the removal into this branch).

The key comes back only through one of these:

- a newer vault from a trusted signer that lists it again
- a save that authorizes it again on purpose (`circle authorize`)
- `murk trust --re-add` naming it.

*Residuals:*

- A replay on a branch this machine accepted before the removal is not refused for listing the key. That branch never contained the removal, so its own rollback mark is what protects it. A save there may keep the key. But merging it into a branch with the removal still meets the merge driver's checks. A one-sided removal conflicts, and a result that keeps a removed key without a newer side re-adding it is refused.
- The record is per machine. A machine that never accepted the removal (a fresh clone, or one that first trusts the vault after the removal) has nothing to compare against. There, history is covered only by the rule that reading never widens trust, and by review at `murk trust`.

**Registry entries depend on whoever added them.** A verifying key pinned for a teammate from another signer's registry counts only while that signer is trusted. Removing the signer drops it, so a key the signer bound to a teammate's name stops working.

An entry counts as independently confirmed only when it is one of these:

- the signing key of a vault the user accepted with `murk trust` after seeing its fingerprint
- the machine's own key.

`murk trust` shows every recipient's fingerprint, but it confirms only the signer's. The other entries in that vault stay held on the signer's word.

Two things do not confirm an entry:

- A vault signed with the entry while the adder was trusted does not confirm it (the adder chose that key and may hold it).
- Another signer's registry carrying the same entry does not confirm it either (their machine may have pinned it on the adder's word).

A save never writes a registry entry that its machine holds on another signer's word. It writes only keys that machine confirmed itself, plus the writer's own. So once the adder is removed, the entries they added stop counting on every 0.14 machine, not only on the machine that saw them added.

*Residual:* pins written before 0.14 have no adder record, so their entries count as confirmed, and a machine still on such a pin can keep vouching for them.

**Reading a branch never widens trust unless this machine accepted that branch before.** A load is *current*, and may add trusted signers, verifying keys or group members, only when both of these hold:

- it is newer than everything this machine accepted
- it is outside git or on a branch with a mark from an earlier `murk trust`, an own save or a current load.

A murk 0.13 vault has no counter, so a load of one counts as newer only while the pin holds no 0.14 state (no mark and no vault id). After that, a 0.13 vault that still loads, on a branch with no 0.14 mark, is history, and read-only until `murk trust` accepts that copy.

Any other load is *history* and only narrows the pin:

- a branch this machine never accepted (such as an unmerged pull request, even with the highest counter)
- a detached HEAD
- a branch behind the mark
- a vault with a counter already accepted
- `murk diff`.

Reviewing a pull request from a trusted signer therefore never trusts the people it adds. This matters because branch protection may stop that signer from making the same change on main. A teammate added on such a branch signs there only after the change reaches a branch this machine accepted, or after `murk trust`.

**Counter bounds.**

- A vault more than 1,000,000 generations above the machine's mark is refused until `murk trust`.
- A generation above 2^53 - 1 is refused everywhere, and `murk trust` will not accept it, so no signer can push the counter to where it stops increasing.
- A save or keyed merge never writes such a vault. One that would number it above 2^53 - 1 is refused and writes nothing (a merge stops as a conflict and leaves ours as the working file). A merge without a key never raises the counter itself: it keeps ours'.

To write again, restore an earlier vault (from git, or an earlier copy outside git) and run `murk trust`.

- Outside git that is enough.
- In a git checkout, `murk trust` lowers only the branch's mark, and a save is numbered from the machine's overall mark. So on a machine that accepted a vault at the cap every save stays refused. Only deleting that machine's trust pin (the refusal names the file), then trusting the restored vault again, recovers it.

*Residual:* a trusted signer can still raise the counter by up to 1,000,000 per accepted vault.

A different vault with the generation already accepted on the same branch is a fork, and is refused until `murk trust`. The same counter on two branches is normal, and the merge driver merges it.

**Writing into a vault you are not on.** An outsider with repo write access can replace `.murk` with an empty vault (no secrets, no meta) that lists only their own key. murk refuses to load such a vault for any key the header does not list ("not a recipient"). `save` also refuses whenever the saving key is not a header recipient. So a victim's `add` or `import` cannot encrypt secrets to recipients the attacker chose. As a side effect, you cannot remove your own key from a vault and still be the one who saves it.

**What this prevents.**

- An outsider replacing `.murk` with a vault encrypted to the victims' public keys. Unsigned, it is refused. Signed by the outsider's own key listed as a recipient (self-enrollment), it is refused as an untrusted signer. That holds on a machine that has the vault pinned, and on a fresh clone until a human runs `murk trust` and accepts the key shown.
- An agent grant forging a vault with its own key, with or without its grant record.
- Replaying an older signed revision (re-enrolling a revoked member, reverting rotated values) onto a branch this machine has seen, and copying another vault's file over this one. The exception is two vaults copied from one murk 0.13 vault:
  - They share a vault id derived from its creation time and name, so the id check cannot tell them apart.
  - A load then refuses the other vault's file only through the counter (rolled back or forked), when its generation is at or below this machine's mark. It accepts the file when the generation is higher.
  - The merge driver accepts the other vault's content whenever a signer this vault trusts signed it.
  - A murk 0.13 file has no id of its own and is compared by that derived id, so another vault's 0.13 file is refused on every branch. That holds for an unsigned or stripped 0.13 file too once the pin has a vault id. It is refused as another vault (not as unsigned or stripped). `murk trust` refuses to accept it at all, so it is never re-signed under this vault's id.
  - The creation time and name are covered by neither the 0.13 signature nor the MAC, though. A member of another vault, or two vaults created in the same second under the same name, can make that vault's 0.13 file derive this vault's id. An example is another vault's 0.13 file, signed by a trusted member, whose header someone with repo write edited to match.
  - On a branch with no 0.14 mark such a file loads as history, and its values are READ as this vault's. That read-side limit remains.
  - A write over it is refused until `murk trust` accepts that copy, so a save never gives this vault's id to the other vault's contents and recipients unless the user accepted that file. `murk trust` records only that copy's fingerprint and does not trust its recipients. The next save does encrypt to them, so review the file first.
- Laundering through the merge driver: a side that fails these checks is a conflict, and the driver never re-MACs or signs it.
- Registry poisoning: a registry entry in a vault that no trusted signer signed is ignored. A second spelling of a recipient key surviving `circle revoke` is also prevented.

**What it does not prevent.**

1. A **trusted signer** (a current non-grant recipient) changing values, adding recipients or granting agents. That is authorized by design. Signatures make it attributable, like signed git commits. The malicious-recipient boundary is unchanged.
2. A **compromised trusted key**. Whoever holds it is a trusted signer.
3. The **first trust decision** on a machine (`murk trust` on a fresh clone, after upgrading from 0.13, on a newly authorized age-key teammate's first write, or a CI runner's `MURK_TRUSTED_SIGNERS`). murk shows each signer's recipient key and verifying-key fingerprint. Checking them out of band is the user's job. Signed git commits help here.
4. **Rollback where no mark exists**: this covers
   - a branch this machine never recorded (for example a PR branch checked out for review)
   - a detached HEAD
   - a branch with no 0.14 mark, where an older 0.13 revision loads as history (read-only once this machine has seen the vault in 0.14 form)
   - a runner without a pin.

   A load by an agent grant has no rollback check at all: it reads and writes no trust pin, so an older revision signed by a signer in its key file loads for it.

   A branch gets its first mark only when this machine saves there. A load does not give one, and merging the upgrade does not either. So a branch that merged the upgrade stays in this group until this machine saves there.
5. A team **entirely on keys that cannot sign** gets no signatures, and integrity rests on signed git commits. In a mixed team, such a key's write is refused on teammates' machines until a signing teammate reviews it and runs `murk trust`, which re-signs it. A signed git commit anchors integrity only if its key is a trusted signer of the vault: an ssh-ed25519 key in the set this machine trusts (the local trust pin, or `MURK_TRUSTED_SIGNERS`). A signature by any other key, including one git itself accepts, proves nothing about who landed the commit. `murk verify` checks the last commit touching the vault against that set and reports a signature by any other key as a finding, not as signed.
6. **Header-only commands** (`ls`, `info`, `circle`, `skeleton`, `agent plan`, `policy show` and the rotation check in `doctor`) read the plaintext header without checking the signature, with or without a key. `rotate --list` does the same only when no key resolves. With a key it checks the MAC, signature and trust first.
7. `MURK_NO_SIGNER_PIN` (or no home directory) turns off the pin, as described above.
8. **Cherry-picking** a genuine historical commit replays its change.
9. A vault last written by murk 0.13 or earlier keeps its v1 signature until its next save. Until then, its vault name, repo URL and creation time can be rewritten undetected on a branch where this machine has not seen it in 0.14 form.

**Reserved environment names.** A vault writer could otherwise pick `PATH`, `LD_PRELOAD`, `GIT_SSH_COMMAND`, `PROMPT_COMMAND` or `MURK_STRICT` for everyone who runs `eval "$(murk export)"` or `murk exec`. That would mean code execution on teammates' machines, or murk's own hardening switched off. `export`, `exec` and `agent exec` refuse such names unless `--allow-reserved` is passed, and the MCP `murk_exec` tool always refuses them (the list is in SPEC.md under `murk export`). This is a guardrail for a trusted vault, not a substitute for the trust check.

## Trust boundaries

```
┌─────────────────────────────────────┐
│         Developer machine           │
│                                     │
│  ~/.config/murk/keys/ ── secret key │  ← Trust boundary: local machine
│  MURK_KEY in memory ── during ops   │
│                                     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│          Git repository             │
│                                     │
│  .murk file:                        │
│    Header (plaintext) ── secret     │  ← Public: anyone with repo access
│      names, descriptions, recipient │
│      keys                           │
│    Values (encrypted) ── per-value  │  ← Protected: requires MURK_KEY
│      age ciphertexts                │
│    Meta (encrypted) ── MAC, names,  │  ← Protected: requires MURK_KEY
│      groups, grants, pins, signers  │
│                                     │
└─────────────────────────────────────┘
```

**What crosses the boundary encrypted:**

- secret values
- inside the meta blob: recipient display names, the MAC and its key, group membership, grant metadata (name, scope, TTL, issuer), GitHub key pins, the signer registry and, for a vault last written by murk 0.13 or earlier, its v1 signature
- a separate `agents` blob, encrypted to each grant's key alone, which holds that grant's own record.

**What crosses the boundary in plaintext:**

- secret names, descriptions, example values (set with `--example`) and tags
- each secret's created, updated, rotation-interval, expiry and `revoked_at` values
- the agent allow-tag policy
- group names and which secrets belong to which group
- recipient public keys, including each grant's ephemeral key
- which recipient key holds a private ciphertext for which secret, which also reveals the scope of a grant's key
- vault metadata (name, version, creation date, repo URL, vault id, save generation)
- the vault signature.

The vault metadata is readable by anyone but covered by the MAC and the signature, so it cannot be rewritten undetected.

**What the stored key is bound to.** Auto-discovery in `~/.config/murk/keys/` is keyed on the vault's absolute path. A vault copied into another directory finds no key and fails closed. murk will not decrypt an attacker-supplied vault with your key just because it sits in your current directory.

Git worktrees extend that binding, not loosen it. The same vault in a sibling checkout of the same repository resolves to the same key. A `.git` entry is a file any local process can write, so murk treats the worktree relationship as untrusted input. It verifies the relationship in both directions against git's own metadata:

- the vault's checkout must be one the repository records
- each sibling must point back at the same common directory.

A directory that merely claims kinship gets no key.

Discovery is disabled outright under `MURK_STRICT` and in agent context.

## GitHub SSH key onboarding

`murk circle authorize github:USERNAME` fetches SSH public keys from `https://github.com/USERNAME.keys` without authentication. That introduces trust assumptions:

**You trust GitHub as a key directory.** The keys GitHub returns are whatever the user has uploaded to their account. If an attacker compromises a GitHub account and adds their own SSH key, `murk circle authorize github:attacker` would grant them access to vault secrets.

**You trust that the GitHub username belongs to who you think it does.** There is no out-of-band verification. Authorizing `github:alice` means trusting that the GitHub user "alice" is your teammate Alice. For most teams this is reasonable: you already trust teammates' GitHub accounts for code review and merge access.

**TOFU (trust on first use) pinning.** The first successful `murk circle authorize github:USERNAME` records the SHA-256 fingerprints of the fetched keys in the encrypted vault meta. Later `murk circle authorize` runs against the same username refuse to proceed if any fingerprint was added or removed upstream, unless `--force` is passed. This catches GitHub key rotation, benign (a teammate rotated their key) or malicious (an attacker added a key to a compromised account), and surfaces the diff for a human to decide.

- The pin covers the full upstream key set, including `ssh-rsa` keys murk will not authorize, so rotation is still detected even when no new recipient ends up in the vault.
- A fingerprint is the SHA-256 of the decoded key blob, the value `ssh-keygen -l` and GitHub's key settings show, so a key in the diff can be checked against either.
- Pins written before 0.14 hashed the key text instead. They still match, and the next `murk circle authorize` rewrites them.
- Usernames match case-insensitively, as on GitHub.

**SSH keys in the vault are just longer pubkey strings.** The vault format is unchanged: `vault.recipients` stores `ssh-ed25519 AAAA...` strings alongside `age1...` strings. Every existing integrity protection (MAC, per-value encryption) applies equally to SSH recipients.

**Acceptable risk profile.** For a team secrets tool, trusting GitHub as a key directory is a reasonable trade-off. You are already trusting your teammates with code access, CI credentials, and production deployments through the same GitHub accounts. The alternative, manual key exchange, has worse security properties in practice, because teams resort to sharing keys over Slack or email.

## Merge driver

murk includes a git merge driver (`murk merge-driver`) that performs three-way merges on `.murk` vault files at the ciphertext level. It decrypts a secret value only to compare plaintexts when both sides re-keyed (below), and never writes one.

**Trust assumptions:**

- Without a key the merge driver cannot verify anything. With a key it authenticates the common ancestor, ours and theirs first (see **Merge laundering** below). Every result is checked again on the next load.
- When both branches changed the vault, a recipient added or removed on only one side is a merge conflict. Both sides must agree on recipient changes for a clean merge. When only one branch changed the vault, git takes that branch's file and does not run the driver (see below).
- When neither side changed the recipient set, secrets merge secret by secret. A secret that one side adds or changes while the other side leaves it alone is accepted, and the two sides may add or change different secrets. A secret that both sides change is a conflict.
- If both sides changed the recipient set in the same way, every ciphertext differs from the ancestor. So the driver decrypts each secret both sides kept and compares plaintexts, slot by slot.
  - A value changed on one side takes that side.
  - A value changed differently on both sides is a conflict.
  - A value this key cannot read is a conflict, and so is any difference when the ancestor is not one a trusted signer signed.
  - Without a key, every such secret is a conflict.
- If only one side changed the recipient set, that is already a recipient conflict.
- When it can resolve a key (`MURK_KEY`, `MURK_KEY_FILE`, or the stored key for `.murk`, which strict and agent mode do not look up), the driver decrypts the meta blobs of both sides. Then:
  - It merges recipient names as a union (ours wins).
  - Groups, grants, GitHub pins and the signer registry merge three-way: a removal or change on one side wins, and a change on both sides is a conflict.
  - A grant changed on both sides is a conflict and is dropped.
  - An agent key left without a grant after the merge is removed from the recipients, along with its scoped values, and flagged. Its holder must be granted access again.
  - A conflicting GitHub pin or signer entry keeps ours.
  - Names, group members, grants and signers for recipients that are gone are dropped.
  - A grouped value that one side encrypted to a group member the merge removed is a conflict.
  - It then re-encrypts the meta with a new MAC key and a recomputed MAC, and signs the merged vault with the merging key (a key that cannot sign leaves it unsigned).
- Without a key, the driver cannot rewrite the meta, so it keeps ours' meta.
  - If there are no merge conflicts, it exits 1 without writing, and git reports a conflict, when any of these hold:
    - the merged secrets, recipients, schema or policy differ from ours
    - theirs changed the encrypted meta (any murk write re-encrypts it)
    - theirs' save counter or vault id differs from both base and ours
    - the merged save counter is above 2^53 - 1.
  - If there are merge conflicts, it writes the merged result and exits 1, and that result may fail the integrity check.
  - Either way, abort the merge (`git merge --abort`) and run it again with your key available.
  - The merge completes without a key only when all of these hold:
    - the merged secrets, recipients, schema and policy equal ours
    - theirs did not change the encrypted meta
    - theirs' save counter and vault id equal base's or ours'.

**What the merge driver prevents** when both branches changed the vault (git runs a merge driver only then). The merge driver is a safety net for concurrent vault edits, not a substitute for branch protection.

- Silent recipient removal (one-sided removal → conflict)
- Silent recipient injection (one-sided addition → conflict)
- Secret value conflicts from independent edits to the same secret

**What the merge driver does not prevent:**

- A trusted signer's change on one side is merged. The driver cannot tell a teammate's legitimate edit from a malicious one by the same key (see [Vault signatures](#vault-signatures), what it does not prevent, item 1).
- A vault change on one branch only. git runs a merge driver only when both branches changed `.murk`. When the target branch did not change it (the usual pull request flow), git takes the other branch's file as it is. So a recipient added or removed there merges with no conflict. The next load still checks the signature, the signer and the counter, so an outsider gains nothing. Review the change yourself against the commit you had before the merge or pull: `murk diff ORIG_HEAD`. git sets `ORIG_HEAD` to that commit, also when it fast-forwards. Run it right after the pull or merge, before another pull, merge, rebase or reset moves it, or save the commit id beforehand and diff against that.
- A rollback hidden in a merge where both sides are 0.13-era, on a branch with no 0.14 mark on this machine. A 0.13 vault has no save counter and no vault id, so the driver cannot tell an older revision or another 0.13 vault from the current one.
  - The driver judges a 0.13-era side like a load of it on the branch it merges into.
  - It refuses the side where that branch has a 0.14 mark (outside git: where the pin holds a vault id or counter). There only the common ancestor may be 0.13 history.
  - A side with only one of the two fields, or with a vault id that differs from the pinned one, is refused whenever the pin holds a vault id or counter.
  - On a branch with no 0.14 mark, a 0.13-era side is refused only when it changed the vault and the other side has a 0.14 save. An example is a branch that has not saved the upgrade yet (merging it gives no mark).
  - Once the pin holds a vault id or counter, a 0.13-era side is refused too, unless the user accepted that copy on the branch with `murk trust`: it is read-only. That refusal writes nothing to the working file, and git keeps ours.
  - A 0.13 ancestor with two 0.14 sides still merges.
  - So the window stays open only on a machine whose pin holds neither, and for a copy the user accepted.

**Merge laundering.** An attacker with write access to a branch can replace ciphertexts with values encrypted to the (public) recipient keys and recompute the MAC. A keyed merge therefore first authenticates the common ancestor.

- An unsigned ancestor from before 0.14 is accepted as history but is no authority on what changed. The sides' metas merge as if it were unreadable, and re-keyed secrets conflict on any difference.
- *Residual:* the counter check against the ancestor needs an ancestor with a counter, so it is skipped for such an ancestor. A crafted unsigned pre-0.14 ancestor plus an older, genuinely signed 0.14 revision as a side can then merge cleanly and revert values. Such an ancestor can arrive through a cherry-pick or rebase of a commit by someone with repo write and no key. The result is signed by whoever runs the merge.

The keyed merge then checks ours and theirs the way a load does:

- the MAC
- a valid signature
- a signer this machine trusts, not a grant key
- the same vault id
- a counter above the common ancestor's, for a side that changed the vault
- group changes signed by a group member.

A side that fails is a conflict naming it. A group change made by a merging key that is not a member of that group is a conflict too.

A conflicted merge gets no new MAC and no signature and keeps ours' meta, so the written file normally fails the next load. It still holds the failing side's secrets and recipients. Resolve the conflict by taking one side (`git checkout --ours` or `--theirs`) and redoing the other side's changes with murk, not by editing the file.

When both sides pass, the merged vault is signed by the merging key, so it loads without a re-signing step. A key that cannot sign leaves it unsigned, and teammates' machines then refuse it until someone reviews it and runs `murk trust`.

**Merges and removed keys.** A merge side signed by a key this machine recorded as removed is refused. A side that is an older, validly signed revision adding back a removed recipient is refused as a rollback. A merge result that would keep a removed recipient without a side newer than the removal is a conflict.

*Residual:* a merge side that sets a secret back to an older ciphertext, signed by a trusted signer, looks the same as a normal edit by that signer and is accepted. The driver cannot tell a deliberate edit from a replayed older value. Only review of the merged branch catches it.

**Recommendation:** Protect your main branch with required reviews and commit signing. Run `murk setup-merge-driver` again after upgrading to 0.14 so git passes the vault path (`%P`).

**Merge `.murk` locally, with your key.** Server-side merges (the GitHub merge button, merge queues, bot merges) run a plain text merge and never invoke the murk merge driver. When both branches changed `.murk`, they either conflict or produce a vault whose integrity or signature check fails, and murk 0.14.0 and later refuse to load it. Do not resolve `.murk` conflicts in the GitHub web editor.

## Supply chain

**Binary distribution:** Release binaries are built in GitHub Actions, checksummed (`SHA256SUMS`), and signed with Sigstore build provenance attestation ([SLSA Level 2](https://slsa.dev)). Provenance is in [in-toto/SLSA v1](https://slsa.dev/provenance/v1) format, covering the release binaries and `SHA256SUMS`. The npm and PyPI packages carry their own provenance. The crates.io `.crate` is attested by the release workflow (from 0.13.0) and attached to the GitHub release. Earlier crates can be reproduced from the signed tag. See [VERIFYING.md](VERIFYING.md) for per-channel details and the tag-signing key. Verify one downloaded binary at a time with:

```bash
gh attestation verify murk-v<version>-<target>.tar.gz --repo interrupted-sh/murk \
  --signer-workflow interrupted-sh/murk/.github/workflows/release.yaml \
  --source-ref refs/tags/v<version>
```

`--repo` and `--signer-workflow` pin the repository and the release workflow. `--source-ref` pins the release tag, so a genuine older archive renamed to a newer release name does not verify. `--owner` alone accepts an attestation from any repository of the organization.

Earlier releases name an older repository in their provenance. That is `interrupted-inc/murk` for 0.10.2 to 0.11.0 and `iicky/murk` for 0.3.1 to 0.10.1. See [VERIFYING.md](VERIFYING.md) for how to verify them.

**Install script:** `install.sh` downloads the binary archive and `SHA256SUMS` and checks the checksum before it extracts anything. The checksum comes from the same release as the archive, so it catches corruption, not a tampered release.

- When `gh` is installed and logged in, the script runs `gh attestation verify` pinned with `--repo`, `--signer-workflow`, `--source-ref refs/tags/<tag>` and `--deny-self-hosted-runners`. It checks against the identity that built that tag (`iicky/murk` up to v0.10.1, `interrupted-inc/murk` for v0.10.2 to v0.11.x, `interrupted-sh/murk` from v0.12.0).
- A check that runs and fails always stops the install, with no prompt and no bypass hint.
- If `gh` is missing or no github.com login can be confirmed, the check cannot run. On a terminal the script then asks "Install anyway? [y/N]" (the default is no). Without a terminal (CI, a docker build) it stops unless `MURK_SKIP_ATTESTATION=1` is set.
- Releases before v0.3.1 have no attestation and are refused unless `MURK_SKIP_ATTESTATION=1` is set.
- `MURK_SKIP_ATTESTATION=1` skips the check entirely. It is not recommended. The install smoke test uses it.
- A plain-HTTP `MURK_BASE_URL` is refused.

**Dependencies:** murk depends on [age](https://age-encryption.org/) (via the `age` crate) for encryption, on `blake3` and `ed25519-dalek` for its integrity MAC and signatures, and on standard Rust crates for CLI, serialization, and I/O. `cargo deny` checks licenses, bans and sources on every pull request, and advisories on pushes and dependency changes. Every third-party `uses:` step in CI is pinned to a full commit SHA.

**Cargo.lock:** Committed and used for reproducible builds (`--locked` in release workflows).

## Key compromise scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| `MURK_KEY` leaked | Attacker can decrypt all shared secrets and the owner's private secrets | Revoke the compromised key, rotate all secrets, re-authorize with a new key |
| `.env` containing an inline `MURK_KEY` committed to git | Same as key leak, but the key is now in git history | Remove from history (`git filter-repo`), revoke, rotate |
| Recovery phrase exposed | Attacker can derive the secret key | Same as key leak |
| Repository made public | Secret names and encrypted values exposed. Values remain safe if keys are secure | Rotate secrets as a precaution if secret names alone are sensitive |
| Recipient revoked | Revoked user retains access to historical versions in git | Rotate all secrets that the revoked user had access to |
| GitHub account compromised | Attacker could be authorized via `github:USERNAME` if the vault owner runs `murk circle authorize github:USERNAME` after compromise. TOFU pinning detects later key changes for an already-authorized user | Verify teammate identity before the first authorize. Investigate the diff when `murk circle authorize github:USERNAME` reports pinned-key changes. Revoke and rotate if compromise is suspected |
| SSH private key leaked | Attacker can decrypt all secrets the SSH key was a recipient for | Revoke the compromised SSH key from the vault, rotate secrets |

`murk init` writes only a `MURK_KEY_FILE` path to `.env`, not the key. Committing that file exposes a local path, not a key. An existing `.env` may still hold other secrets.

## Cryptographic properties

murk uses age for all encryption and decryption. It does not implement custom cryptographic primitives. It defines a vault format and a BLAKE3 keyed integrity layer on top of age.

- **Encryption:** age v1 (X25519 key agreement, ChaCha20-Poly1305 payload encryption)
- **Per-value encryption:** each secret value is encrypted independently with a fresh age file key
- **Recipient types:** age x25519 keys (`age1...`), SSH keys (`ssh-ed25519`, `ssh-rsa`) and age plugin identities such as YubiKey or Secure Enclave (`age1yubikey1...`). age handles all three natively. murk refuses `ssh-rsa` unless `--allow-ssh-rsa` is passed.
- **Integrity (tamper-evidence):** BLAKE3 keyed MAC, stored inside an age-encrypted meta blob. It covers secret names, all encrypted values (shared, grouped, private), the recipient set, schema, group definitions, grants, policy, revocation markers and the header identity fields. Older MAC versions, including legacy SHA-256, are accepted on load for vaults written before 3.0.
- **Integrity (authorship):** Ed25519 signature over the vault file without its `sig` field (signed view 2). Age keys sign with an Ed25519 key derived from the age key through a domain-separated BLAKE3 KDF (`blake3::derive_key`). Its verifying key is published in the meta's signer registry. ssh-ed25519 keys sign natively. murk 0.13 and earlier wrote v1 signatures with the same derived key. Those are still verified, against a pinned verifying key.
- **Trust anchor:** a per-repository local trust pin (trusted signers and their verifying keys, grant keys, group membership, vault id, per-branch save counters, and the pre-0.14 copies the user accepted), or `MURK_TRUSTED_SIGNERS`. Never derived from the vault being checked.
- **Key derivation:** BIP39 mnemonic (256 bits of entropy) → direct Bech32 encoding → age identity. There is no intermediate hash: the same bytes make the same key. The Ed25519 signing key derives from those same bytes, so the recovery phrase recovers both. SSH keys use their native format.

The MAC binds independent age ciphertexts together, so accidental corruption or naive tampering is caught. Because its key travels in the (re-encryptable) meta blob, it does not stop a deliberate repo-writer. The signature does, together with the trust pin that decides whose signature counts.

## Secure design principles

This section applies the eight design principles of Saltzer and Schroeder ("The Protection of Information in Computer Systems", 1975) to murk. Each entry says what murk does, where in the code it does it, and where the principle is only partly met.

**Economy of mechanism.** murk implements no cryptographic primitives. Encryption and decryption go through the `age` crate (`src/crypto.rs`), the integrity MAC is keyed BLAKE3 (`src/mac.rs`), and signatures are Ed25519 (`src/signing.rs`). The vault is one JSON file, parsed in one function (`vault::parse` in `src/vault.rs`). The CLI and the Python and Node bindings all load a vault through the same function (`load_vault` in `src/load.rs`, called from `src/python.rs` and `node/src/lib.rs`).

*Partly met:*

- The format carries several MAC versions for backward compatibility. These include unkeyed legacy `sha256:` and `sha256v2:` MACs that are still accepted on load and flagged as legacy (`verify_mac` in `src/mac.rs`, `resolve_meta_state` in `src/load.rs`).
- The agent features (grants, policy, MCP server, output masking) add mechanism that the core encrypt/decrypt path does not need.

**Fail-safe defaults.** When murk cannot establish that an operation is safe, it refuses it:

- Key resolution returns an error instead of guessing. If `MURK_KEY` and `MURK_KEY_FILE` are both set, murk stops and asks you to unset one. It does not pick one (`env_key` in `src/env.rs`). A `MURK_KEY_FILE` that is set but unreadable is an error, not a fallback to auto-discovery. `.env` is never read at runtime. In strict or agent context (`MURK_STRICT`, `MURK_AGENT`), auto-discovery of the operator's stored key is off (`resolve_key_with_source` in `src/env.rs`, `strict_mode` in `src/hardening.rs`).
- Loading fails in these cases (`resolve_meta_state`, `check_signature`, `decrypt_vault` and `load_vault` in `src/load.rs`, `check_grant_expiry` in `src/policy.rs`, `vault::parse`):
  - the vault has secrets but no meta or an empty MAC
  - the MAC does not match
  - a signature is present but invalid
  - a pinned signer's verifying key changed
  - a grant bound to the loading key has expired or has an unreadable expiry
  - the vault's major version is unknown.
- `murk agent exec` refuses a key that is not an agent grant unless `--allow-operator-key` is passed.
  - It refuses an auto-discovered operator key before the vault loads (`cmd_agent_exec` in `src/commands/grants.rs`).
  - It refuses any other full-recipient key once the vault is open and before a secret is resolved (`cmd_exec` in `src/commands/exec.rs`).
- The MCP server's `murk_exec` tool is removed unless `--allow-exec` is passed (`MurkMcp::new` in `src/mcp.rs`).
- `ssh-rsa` recipients are refused unless `--allow-ssh-rsa` is passed (see [SECURITY.md](SECURITY.md)).
- Under an agent policy, a secret without an allowed tag is refused, and an empty allow-list refuses every secret (`check_agent_keys` in `src/policy.rs`).

An unsigned vault, a stripped signature, a signer this machine does not trust, a grant-key signer, a rolled-back counter and another vault's id are all refusals in the library load path. There is no flag to accept them other than the explicit `murk trust` step (`assess` in `src/trust.rs`, `load_vault` in `src/load.rs`).

*Partly met:* a key that cannot sign loads an unsigned vault with a warning, and `MURK_NO_SIGNER_PIN` turns off the pin (trust then comes only from `MURK_TRUSTED_SIGNERS`). See [Vault signatures](#vault-signatures).

**Complete mediation.** murk checks integrity again on every load. It keeps no record that a vault already passed. The trusted `load_vault` path checks integrity before it returns decrypted values:

- For a non-grant key, `decrypt_vault` verifies the MAC and the signature before it decrypts any secret value.
- A grant key cannot read the meta, so it verifies only the signature, against the signers in its key file, before it decrypts its own record and values.
- Either way the expiry of every grant bound to the loading key is checked.
- `load_vault` then applies the trust check (`src/load.rs`, `src/trust.rs`), and write commands load through it too.

`murk agent exec` always checks the agent policy before any value reaches the child process. Plain `murk exec` checks it only under self-scope (`MURK_SELF_SCOPE`, or an agent context) (`cmd_exec` in `src/commands/exec.rs`, `self_scope` in `src/hardening.rs`). The MCP server calls `enforce_agent_policy` (`src/policy.rs`) on every `murk_get` and `murk_exec` call (`src/mcp.rs`). That call re-checks grant expiry against the current time and the policy's tag allow-list.

*Partly met:*

- The MCP server's checks run against the vault it loaded at startup (`McpState` in `src/mcp.rs`). It does not re-read the vault, so a later revocation, policy change or tampering on disk takes effect only when the server restarts.
- Plain `murk exec` with the operator's own key, outside self-scope, applies no agent policy.
- Without a key, the merge driver verifies nothing. The next load checks its result ([Merge driver](#merge-driver)).
- `murk diff REF` verifies the `REF` revision's MAC and signature before it decrypts anything, and always refuses a revision that fails either. It then judges the signer by looser rules than a load.
  - With a trust pin, the signer only has to be one this machine has ever trusted, so a teammate revoked since still verifies.
  - With `MURK_TRUSTED_SIGNERS`, the signer must be listed there.
  - There is no rollback, group-change or downgrade check.
  - When this machine has a pin or `MURK_TRUSTED_SIGNERS`, a revision whose signer fails is refused. When it has neither, `diff` shows the revision under a "not trusted on this machine" warning, and `MURK_STRICT` refuses that.
  - An unsigned revision from before 0.14 is shown with a warning.
  - `diff` reads the trust pin but never extends it.
- Every check is in the murk binary and library, so a recipient who uses `age` directly, or an older murk, is not mediated.

**Open design.** murk's security does not depend on its design being secret. The source is public, the vault format is specified in [SPEC.md](SPEC.md), and this document states what murk does not protect. The only secrets are recipients' private keys. Secret names and the recipient list are public in the vault header by design (see **Secret names are public** under [Non-goals](#non-goals)).

**Separation of privilege.** *Partly met.* murk has no m-of-n control: one recipient's private key is enough to decrypt every shared secret and to write a validly signed vault. Where murk does require two conditions:

- `murk mcp` needs both an agent context (`MURK_AGENT=1`) and a key that is a grant of this vault (`cmd_mcp` in `src/commands/grants.rs`).
- When both branches of a merge changed the vault, a recipient added or removed on only one side is a conflict, so both sides must agree (`src/merge.rs`, see [Merge driver](#merge-driver)). A vault changed on one branch only merges without the driver.
- The GitHub release, the Homebrew tap update and the crates.io publish need a tag on a commit that reached `main` through a merged pull request, under the branch protection that the release workflow checks (`preflight` job in `.github/workflows/release.yaml`). The npm and PyPI publish jobs are separate workflows and do not run it.

**Least privilege.**

- Named groups and private secrets limit decryption to their members, and age enforces this.
- An agent grant is an ephemeral identity that can decrypt only its own grant record and the secrets it was granted. It is excluded from the shared layer and from the meta (`decrypt_vault`, see [Agent grants](#agent-feature-limits)).
- `murk agent exec` and the MCP `murk_exec` tool clear the child's environment and keep only `PATH`, `HOME` and `TERM` on Unix (`cmd_exec` in `src/commands/exec.rs`, `run_command` in `src/mcp.rs`). `run_command` also gives the child a null stdin, a 1 MiB output cap on each of stdout and stderr (a stream past the cap kills the child), and a 120-second timeout.
- Key files are written `0600` through a temporary file renamed into place, so a key never takes the mode of a file it replaces (`stage_key_file` and `write_key_to_file` in `src/env.rs`).
- `murk agent grant --out` and `murk agent init --out` refuse an existing file unless `--force` is passed, before the vault changes (`mint_grant` in `src/commands/grants.rs`, test `agent_grant_key_files_are_never_clobbered_and_always_owner_only`).
- A grant's key file is renamed into place only after the vault is saved, so a failed save leaves an existing key untouched.
- `.env` is created `0600`, and an existing `.env` is set to `0600` before murk writes to it (`write_secret_file` in `src/env.rs`).
- The `~/.config/murk` directories are set to `0700` (`config_subdir` in `src/env.rs`).
- The vault's temporary file is set to `0600` before it is written (`vault::write`).
- The GitHub key fetch follows no redirects, ignores proxy environment variables, times out after 30 seconds and reads at most 1 MiB (`fetch_keys` in `src/github.rs`).
- CI workflow tokens are read-only by default and elevated per job ([SECURITY.md](SECURITY.md)).

*Partly met:* child processes run with the user's full OS privileges. `HOME` is kept, so a child can read `~/.config/murk/keys` directly. Plain `murk exec` without `--clean-env` passes the whole parent environment except `MURK_KEY` and `MURK_KEY_FILE`.

**Least common mechanism.** Mechanisms that users share are kept apart:

- Each value is a separate age ciphertext with a fresh file key.
- A stored key is bound to one vault path (`vault_hash` and `discover_key_file` in `src/env.rs`), so a vault copied elsewhere finds no key.
- Grant keys are stored in a separate `agent-keys/` directory that auto-discovery never reads (`agent_key_file_path` in `src/env.rs`).
- Trust pins are kept per repository and vault path (`pin_path` in `src/pins.rs`) and record the vault id. So a pin never vouches for another vault's file, unless both were copied from one murk 0.13 vault and share its derived id.
- The MCP server uses a stdio pipe, not a network listener.

*Partly met:* all recipients except agent grants share the shared layer and the MAC key, which is why the MAC proves integrity but not authorship ([Audit logging](#non-goals)). Sibling git worktrees of one repository share a stored key by design. The worktree relationship is verified against git's metadata in both directions first (`sibling_worktrees` in `src/git.rs`).

**Psychological acceptability.** The secure path is the default path. `murk init` stores the key where auto-discovery finds it, and signs and trusts the vault it creates. `murk add` and `murk rotate` read values from a prompt that does not echo, or from stdin, never from the command line (`resolve_value` in `src/commands/mod.rs`). Errors give one action per line (`resolve_key_with_source`). A trust refusal names the signer's key, the recipient changes, what to review and the `murk trust` step. The trade-offs made for usability are stated in this document: public secret names, sign-when-capable, and a human trust decision on each new machine. *Partly met:* the strictest settings are opt-in. These include `MURK_STRICT`, running agents as a separate OS user, and signed git commits.

## Common implementation weaknesses

This section covers common implementation weaknesses that apply to a local Rust CLI and its bindings, drawn from the CWE Top 25 and OWASP Top 10 and from CWE entries specific to handling secrets. For each one, it gives murk's countermeasure, the evidence, and the known gaps. Denial of service against the CLI is out of scope ([SECURITY.md](SECURITY.md)).

**OS command and argument injection (CWE-78, CWE-88).** murk starts child processes with an argument vector through `std::process::Command` or `tokio::process::Command`. These run without a shell: the user's command in `murk exec` (`cmd_exec` in `src/commands/exec.rs`), the MCP `murk_exec` tool (`run_command` in `src/mcp.rs`) and `git` (`src/git.rs`, `src/init.rs`, `src/commands/git.rs`, `src/commands/verify.rs`).

The editor is the one exception:

- On Unix, `murk edit` runs `sh -c` with the `EDITOR` (or `VISUAL`) value in the script, as git does, so the value can carry arguments (`code --wait`) and leading assignments (`FOO=bar vim`).
- The scratch-file path reaches the editor as a positional argument, not as script text (`run_editor` in `src/commands/editor.rs`).
- The value comes from the user's own environment and carries the same trust as `PATH`.

Vault content never reaches the shell.

The ref given to `murk diff` cannot become a git option. A ref that starts with `-` is refused, it is resolved with `git rev-parse --verify --end-of-options`, and only the resulting commit id reaches later git commands (`vault_at_revision` in `src/git.rs`, test `diff_refuses_a_ref_that_is_a_git_option`).

A repository's own `.git/config` is not trusted, because a working tree unpacked from an archive or a shared volume brings whatever config its author wrote. git is started with `core.fsmonitor` off, hooks pointed at `/dev/null` and no pager. `murk verify` does not check commit signatures when the repository's own config sets `gpg.*`, since that config names the verification program and the allowed signers (`git_command` and `last_commit_signature` in `src/git.rs`, test `repo_git_config_runs_no_program`).

For output that a shell evaluates:

- `murk export` single-quotes each value and escapes embedded quotes (`export_secrets` in `src/export.rs`, test `export_secrets_shell_escaping`). It skips any secret name that is not a valid identifier (`cmd_export` in `src/commands/secrets.rs`, `is_valid_key_name` in `src/lib.rs`).
- The vault name written to `.envrc` is quoted by `shell_escape` (`src/env.rs`, test `write_envrc_escapes_vault_name`).
- Before `cmd_exec` injects variables, it refuses empty secret names, secret names with `=` or NUL, and values with NUL.

*Gap:* the reserved-name list is finite, and `--allow-reserved` lifts it. `murk export`, `murk exec` and `murk agent exec` refuse a secret named like a loader, shell, git or murk setting (`PATH`, `BASH_ENV`, `GIT_*`, `MURK_*` and others, see `is_reserved_env_name` in `src/lib.rs`), and `murk mcp` always refuses it. A recipient who can write the vault can still add a variable that is not on the list, for example `SSH_AUTH_SOCK`, `GNUPGHOME` or `KUBECONFIG`. `murk export` and `murk exec` then set it for the reader.

**Path traversal and link following (CWE-22, CWE-59).** Untrusted names do not become paths:

- A GitHub username must be 1 to 39 ASCII letters, digits or hyphens before it goes into the URL (`fetch_keys` in `src/github.rs`).
- Stored key file names are hashes of the vault path (`vault_hash` in `src/env.rs`).
- Grant names are limited to letters, digits, `-` and `_` (`validate_short_name` in `src/grants.rs`).

Symlinks are refused:

- At the vault path (`vault::read_with_raw`).
- At key files read through `MURK_KEY_FILE` or auto-discovery. Key files are also refused if they are group- or world-accessible (`read_secret_file` in `src/env.rs`, test `world_readable_key_file_rejected`).
- At key files and `.env` on write. On Unix, `.env` is also opened with `O_NOFOLLOW` (`write_secret_file` in `src/env.rs`). A key file is written to a temporary file and renamed into place, which replaces a link planted after the check instead of following it (`stage_key_file` and `write_key_to_file` in `src/env.rs`). `murk init` refuses to replace an existing key file.
- At the lock file, which is opened with `O_NOFOLLOW` (`vault::lock`, test `lock_file_symlink_rejected`).
- At signer-pin files on write. The pin is written to a `0600` temporary file in the same directory and renamed into place, so the write never goes through a link planted after the check (`write_pin_file` in `src/pins.rs`, test `symlinked_pin_is_refused_and_its_target_untouched`).

Auto-discovery hashes the literal vault path, without resolving symlinks, so a symlinked `.murk` does not borrow another project's key (`absolute_vault_path` in `src/env.rs`). *Gaps:*

- The symlink checks look only at the final path component.
- On non-Unix platforms there is no `O_NOFOLLOW` and no file-permission hardening.
- The `.envrc` append and the zero-overwrite in `overwrite_and_remove` (`src/commands/secrets.rs`) open without `O_NOFOLLOW`. The `.envrc` append is guarded only by a prior symlink check.

**Race conditions, TOCTOU (CWE-367).** Vault writes are atomic. The vault goes to a temporary file in the same directory, which is set to `0600`, fsynced and renamed over the vault, and then the directory is fsynced (`vault::write`). Read-modify-write cycles hold an exclusive lock on `.murk.lock` (`vault::lock`). `.env` writes use `O_NOFOLLOW` at open time, so a symlink planted after the check is still refused. Key files are written to a temporary file and renamed into place, which replaces such a link instead of following it. *Gaps:* reads check for a symlink and then open the file by path (`read_with_raw`, `read_secret_file`), which leaves a window between the check and the open. The lock on non-Unix platforms is check-then-create, as `vault::lock` notes.

**Insecure temporary files (CWE-377).** `murk edit` writes the plaintext to a `0600` file made with the `tempfile` crate.

- The file goes in `$XDG_RUNTIME_DIR` if it is set, then in `/dev/shm` if that is RAM-backed, then in the system temporary directory (`cmd_edit` in `src/commands/secrets.rs`, `edit_in_scratch_file` in `src/commands/editor.rs`). When the chosen directory is not RAM-backed, murk warns that the wipe is best effort and suggests a tmpfs or `MURK_STRICT=1`.
- Every return from the editor session overwrites the file with zeros and deletes it (`ScratchFile` in `src/commands/editor.rs`, `overwrite_and_remove` in `src/commands/secrets.rs`). That covers a clean exit, a non-zero exit, an editor that fails to start, a failed read-back, a caught SIGINT, SIGTERM, SIGHUP or SIGQUIT, and an unwinding panic.
- On Unix, murk first stops everything left in the editor's process group (SIGTERM, then SIGKILL after 2 seconds), so no leftover process can save the file again.
- Under `MURK_STRICT`, `murk edit` refuses to run unless the directory is RAM-backed (`is_ram_backed` in `src/hardening.rs`). On macOS only a tmpfs mount counts, so set `XDG_RUNTIME_DIR` to one.
- Before it saves, `murk edit` checks that the vault file has not changed on disk while the editor was open. If it has, murk saves nothing, so a `git pull` during the edit is not silently undone.

*Gaps:*

- The plaintext is on disk for as long as the editor runs, as [SECURITY.md](SECURITY.md) states.
- SIGKILL, a crash, an out-of-memory kill or power loss stops murk before the wipe.
- A process that leaves the editor's group (a daemon, or a hand-off to an already running app instance) can keep or rewrite the file.
- Editors can leave their own swap, backup and undo files.
- The overwrite cannot defeat journaling or copy-on-write file systems.

**Exposure of secrets in output, logs, arguments and environment (CWE-200, CWE-532, CWE-214).**

- Secret values are never taken from the command line. `murk add` and `murk rotate` read them from a prompt that does not echo, or from stdin (`resolve_value` in `src/commands/mod.rs`).
- The key reaches murk only through `MURK_KEY`, `MURK_KEY_FILE` or a key file.
- The commands that `murk exec`, `murk agent exec` and the MCP `murk_exec` tool run do not inherit `MURK_KEY` or `MURK_KEY_FILE`: `cmd_exec` either clears the environment or removes both variables, and `run_command` clears the environment.
- `git` and the editor that `murk edit` starts do not inherit `MURK_KEY` or `MURK_KEY_FILE` either. Both are removed by `strip_key_env` in `src/env.rs`, and murk starts every `git` process through `git_command` in `src/git.rs` (test `git_does_not_inherit_the_key`). The merge driver is not affected: git starts `murk merge-driver` with the user's own environment.
- Library modules must not print to stdout, and only `src/env.rs` reads the `MURK_KEY*` variables. Both rules are enforced by tests (`library_modules_do_not_print_to_stdout` and `murk_key_is_read_only_in_the_env_module` in `tests/invariants.rs`).
- `dbg!` is denied (`[lints.clippy]` in `Cargo.toml`).
- The `Debug` output of `MurkIdentity` (`src/crypto.rs`) and `DiffEntry` (`src/export.rs`) never prints key material or values.
- Under `MURK_STRICT`, `murk get`, `murk export` and `murk diff --show-values` refuse to write plaintext to stdout when stdout is a regular file (`strict_guard_plaintext_stdout` in `src/commands/secrets.rs`). `murk diff --json` prints values only with `--show-values`.
- The CLI turns off core dumps at startup on Unix (`disable_core_dumps` in `src/hardening.rs`, called from `run` in `src/main.rs`). On Linux it also marks itself non-dumpable, which closes `/proc/<pid>/environ` and `/proc/<pid>/mem` to other processes of the same user (`deny_same_user_inspection`, test `murk_process_is_not_readable_through_proc`).
- `murk agent exec` and the MCP `murk_exec` tool mask injected values in the child's output ([Output masking](#agent-feature-limits)).

*Gaps:*

- Other processes of the same user can see `MURK_KEY` in the environment of the shell that exported it, and, except on Linux, in murk's own environment.
- CodeQL's `rust/cleartext-logging` query is excluded repo-wide as a false positive for a local CLI (`.github/codeql/codeql-config.yml`), so CodeQL does not check this class.
- The invariant tests scan source text, not types. The type-aware lints in `lints/murk_lints` are run by hand and are not part of CI.
- The Python and Node bindings do not turn off core dumps or set the non-dumpable flag. The host process owns those settings.

**Memory safety (CWE-787, CWE-125, CWE-416).** murk is written in Rust. Non-test `unsafe` code is in four places:

- `src/hardening.rs`: `setrlimit` in `disable_core_dumps`, `prctl` in `deny_same_user_inspection`, `statfs` in `is_ram_backed`, and borrowing the stdout file descriptor in `stdout_is_regular_file`.
- `src/commands/signals.rs`: `sigaction`, `kill`, `getpgid`, `waitid`, `signal`, `pthread_sigmask`, `raise` and reading the sender from `siginfo`. The signal handler uses only atomics and `kill(2)`.
- `src/commands/editor.rs`: process-group and terminal control for `murk edit` (`setpgid`, `waitpid`, `kill`, `raise`, `isatty`, `getpgrp`, `tcgetpgrp`, `tcsetpgrp`, `pthread_sigmask`, and a `pre_exec` hook that makes only async-signal-safe calls).
- `src/mcp.rs`: `killpg` in `ExecChild::kill`, which sends SIGKILL to the process group of an MCP `murk_exec` child.

Each block has a comment that explains why it is sound. All other `unsafe` in `src/` is in tests (`std::env::set_var` and `remove_var`). The Python bindings (`src/python.rs`) and Node bindings (`node/src/`) have no hand-written `unsafe`. *Gaps:* there is no `forbid(unsafe_code)` or `deny(unsafe_code)` lint, so review is what stops new `unsafe` code. Dependencies contain their own `unsafe`. CI runs `cargo audit --deny unsound` on dependency changes (`.github/workflows/ci.yaml`).

**Parsing untrusted input (CWE-20, CWE-502).** Anyone with write access to the repository controls the `.murk` file, so murk treats it as untrusted input. Every loader goes through `vault::parse`:

- It refuses a file over 64 MiB.
- It deserializes the JSON into fixed types (a step that runs no code from the input).
- It checks every field against an allow-list (`src/validate.rs`): the version (an unknown major version is rejected), timestamps, secret names, recipients, group and grant names, base64 ciphertexts and GitHub fingerprints.

The decrypted meta blob gets the same checks, and `vault::write` applies them before it writes. Error messages escape control characters in the rejected value, so a hostile vault cannot put terminal escapes in murk's output.

Header free text is the vault name, repo URL, descriptions, examples, tags, recipient names and policy tags. The rules for it:

- On load, it may contain no control characters other than tab, CR and LF.
- Writes are stricter. Text that is new or changed in a write (a command argument, or a change through the bindings) must hold no control character other than tab, no bidi control, no zero-width space and no byte-order mark. Only descriptions may contain LF.
- A command-line argument that breaks the rule is refused with exit 2, and the message names the argument and never echoes the text. Any other write that would add such text fails and names the field.
- Text a vault already held in the same place is exempt, so an existing vault with such text still loads and stays writable.
- `murk verify` reports each such field as a finding. `info`, `circle`, `circle revoke`, `init`, `trust` and `diff` escape these characters when they print header text.
- `murk get` escapes control characters when stdout is a terminal. `murk diff --show-values` prints each value on one line with control characters escaped.

Malformed base64, JSON or age data in the meta blob gives an integrity error, not a panic (`resolve_meta_state` in `src/load.rs`).

The evidence:

- Six fuzz targets in `fuzz/fuzz_targets/` cover vault parsing, the three-way merge driver, `.env` parsing, recipient and identity parsing, and recovery phrases. CI runs them for 90 seconds per target on pull requests that change `src/`, `fuzz/` or the Cargo manifests, and for 300 seconds per target every night (`.github/workflows/fuzz.yaml`).
- Adversarial tests include `load_vault_not_json`, `load_vault_wrong_version` and `load_vault_huge_key_name` in `tests/adversarial.rs`.
- The property test `any_tamper_fails_the_load` is in `src/property_tests.rs`.
- The GitHub response body is capped at 1 MiB (`fetch_keys`).

*Gaps:* unknown JSON fields are ignored, not rejected. No fuzz target reaches the decryption and verification path (`decrypt_vault`), which needs a key.

**Cryptographic weaknesses (CWE-327, CWE-208).** murk uses no custom primitives ([Cryptographic properties](#cryptographic-properties)). It compares MACs in constant time (`constant_time_eq` in `verify_mac`, `src/mac.rs`). The `rsa` crate's timing side channel (RUSTSEC-2023-0071) is handled by refusing `ssh-rsa` recipients by default ([SECURITY.md](SECURITY.md)). *Gap:* legacy unkeyed `sha256:` and `sha256v2:` MACs are still accepted on load. They are flagged as legacy (`legacy_mac` in `resolve_meta_state`).

**Vulnerable and untrusted dependencies, and build integrity (CWE-1395, CWE-494, OWASP A06, A08).**

- `Cargo.lock` is committed, and release builds use `--locked`.
- `cargo deny` checks licenses, bans and sources on every pull request. It denies wildcard versions and unknown registries and git sources (`deny.toml`).
- On dependency changes and pushes, CI also checks RustSec advisories, with `cargo deny` and with `cargo audit --deny unmaintained --deny unsound` (`.github/workflows/ci.yaml`).
- A daily workflow opens fix pull requests for new advisories (`.github/workflows/advisories.yaml`). Dependabot proposes updates (`.github/dependabot.yml`).
- Actions are pinned to full commit SHAs.
- CodeQL scans Rust, Python, JavaScript/TypeScript and the workflows on pull requests, on pushes to `main` and weekly (`.github/workflows/codeql.yaml`). OpenSSF Scorecard runs on pushes to `main` and weekly (`.github/workflows/scorecard.yaml`).
- A CI job on `main` builds twice on Linux x86-64 and Windows x86-64 and checks that the output is reproducible (`reproducibility` in `.github/workflows/ci.yaml`).
- The GitHub release, the Homebrew tap update and the crates.io publish run only from a tag on a commit that reached `main` through a merged pull request, under a checked branch-protection baseline (`preflight` in `.github/workflows/release.yaml`). The npm and PyPI publish jobs (`node.yaml`, `python.yaml`) run on any `v*` tag push without it, and the npm job can also be started by hand from `main`. Release artifacts carry Sigstore provenance ([Supply chain](#supply-chain)).

*Gaps:*

- RUSTSEC-2023-0071, RUSTSEC-2026-0374 (unmaintained `basic-toml`, used only at compile time by age) and RUSTSEC-2026-0387 (`crypto-bigint` timing, used only by age's native P-256 tag recipients, which murk never parses) are ignored, with the reasons in `deny.toml`.
- The reproducibility job builds on Linux x86-64 and Windows x86-64 only. The release also ships macOS and ARM Linux binaries, and a build on another OS image or linker can differ ([VERIFYING.md](VERIFYING.md)).
- The npm native builds run in container images pinned by tag, not digest.
- crates.io has no attestation support of its own. From 0.13.0, the release workflow attests the exact `.crate` published to crates.io, checks it against the crates.io index checksum, and attaches it to the GitHub release. Crates for 0.12.0 and earlier have no attestation and can only be checked by rebuilding from the signed tag ([VERIFYING.md](VERIFYING.md)).
- The release workflow does not run the test suite again. It relies on CI having passed on `main`.

## Scope

murk is appropriate for dev teams and small organizations. It replaces sharing `.env` files over Slack, email, or shared documents, a meaningful improvement over that baseline.

murk is not designed for regulated environments handling PII, financial data, or healthcare data, where audit trails, key management infrastructure, and provable access controls are required.
