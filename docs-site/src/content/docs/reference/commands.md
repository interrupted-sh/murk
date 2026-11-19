---
title: Command behavior
description: What each murk command does beyond its help text, with links to the rules in SPEC.md.
sidebar:
  order: 1
---

This page states what each command does beyond its help text. The [CLI reference](/reference/cli/), generated from the CLI, lists every flag, default and exit-code convention. The rules for the vault format, signatures, trust, agent grants and merges are in [SPEC.md](https://github.com/interrupted-sh/murk/blob/main/SPEC.md), and this page links to them instead of repeating them. Environment variables, strict mode and the names a vault may not set are on [Environment variables](/concepts/env-vars/).

## `murk init`

Interactive setup. Prompts for a display name. Then:

1. Finds your key. It looks at `MURK_KEY` or `MURK_KEY_FILE` from the environment first. Then it looks at the key stored at `~/.config/murk/keys/<vault-hash>` for this checkout or for the same vault in a sibling worktree (the lookup under [Discovery](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#discovery)). Then it looks for keys stored for other vaults in the same directory (see [Several vaults in one directory](#several-vaults-in-one-directory)). Only when none of these exists does it generate an age keypair via BIP39 (a 24-word mnemonic encodes the key directly) and write the secret key to `~/.config/murk/keys/<vault-hash>` with mode 0600. The key file is created exclusively, so init never overwrites one.
2. For a newly generated key, prints the BIP39 24-word recovery phrase to stderr. A reused key prints none (use `murk recover`).
3. Writes `export MURK_KEY_FILE='<path>'` to `.env` (creates it if missing). It never writes an inline `MURK_KEY`, and in strict or agent mode it never writes `.env` at all and prints no key-store path (not even the `MURK_KEY_FILE` it uses). If `.env` already has a `MURK_KEY` or `MURK_KEY_FILE` line, a reused key leaves that line as it is. If init must generate a new key, it asks before replacing that line and aborts unless you answer yes. A key for a second vault in the same directory never touches `.env`.
4. Creates the `.murk` vault with your pubkey as the first recipient, a fresh `vault_id` and `generation` 1, signed by your key when that key can sign, and records it in the local trust pin with the creator as its trusted signer.

To use a non-default vault name, add `export MURK_VAULT=prod.murk` to `.env` or your shell yourself. `murk init` does not write it.

If the vault already exists, init does not change it. It uses the same key lookup and writes `.env` by the same rules. Then it reports whether the key is a recipient:

- A recipient is told to run `murk trust` once per machine if this machine has no trust pin for the vault yet.
- A key that is not a recipient prints its public key and, for an age or ssh-ed25519 key, its signing-key fingerprint, to send to someone who can authorize it.

init never replaces a stored key file. To get a new identity, move the key file away first. In strict or agent mode, init neither uses nor replaces a stored key. With no key in the environment and a stored key present (here or in a sibling worktree), it refuses without printing where the key is stored.

### Several vaults in one directory

A repository can hold one vault for each environment (`.murk`, `staging.murk`, `prod.murk`). When the vault has no stored key of its own, init looks for keys stored for the other vaults in its directory: a regular file (not a symlink) of that name in this checkout, or at the same relative directory of a sibling worktree, for which the Discovery lookup finds a key. It reads no vault file. Keys with the same public key count as one offer.

- On a terminal, with no flag, init asks once: reuse one of the offered keys (the default vault's key first, and it is the default answer), or make a separate key.
- `--reuse-key` reuses the offered key without asking. It refuses when the offered keys differ, and when there is nothing to reuse (it never generates a key instead).
- `--separate-key` generates a new key without asking.
- Without a terminal and without a flag, init refuses and names the two flags.
- In strict or agent mode init never reads an offered key and never asks. With no flag or with `--reuse-key` it refuses, and it prints no key-store path. `--separate-key` still generates a new key.

Reuse stores the same secret key for the new vault, with the same exclusive 0600 write as a generated key. Both choices leave `.env` unchanged, and both print how commands find the key (`--vault` or `MURK_VAULT`). A `MURK_KEY` or `MURK_KEY_FILE` in the environment whose key is one of the offered keys (for example from the first vault's `.env`) narrows the offer to that key. It does not decide for the new vault, so the new vault still gets a stored key of its own.

The recipients, trust pin, grants and policy of each vault stay separate.

## `murk recover`

An SSH key or a plugin identity makes the command exit 1 without printing a recovery phrase.

## `murk restore`

Derives the secret key from a BIP39 recovery phrase and prints it to stdout. It saves nothing. Prompts for the phrase interactively (hidden input) or reads from stdin when piped. When the vault (`--vault`, default `.murk`) is readable and the restored key is not one of its recipients, murk warns that the phrase may be wrong. The warning never fails the restore.

## `murk add`

Piped input is the whole of stdin with one trailing newline removed, so a multi-line value such as a PEM key arrives intact (`cat key.pem | murk add TLS_KEY`).

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

Key names are validated as shell identifiers. Invalid names are rejected. A name that `export`/`exec` treat as reserved (see [`murk export`](#murk-export)) is accepted with a warning.

## `murk generate`

Generates a cryptographically random value and stores it, output as URL-safe base64 (no padding) unless you pass `--hex`. `--group`, `--desc`, `--example` and `--tag` work as for `murk add`. Uses the same RNG as key generation.

## `murk rotate`

Replaces a secret value (`KEY`, or every secret with `--all`). Use after revoking a recipient to ensure they can no longer use the old value.

Rotation keeps each value in its tier and never widens who can read it:

- A shared value stays shared.
- A group value stays in its group (encrypted to the group's current members).
- A key held only as your personal override stays your override.

A personal override on top of a shared or group value is left unchanged. You cannot rotate a key held by a group you are not a member of: `rotate KEY` refuses it, and `--all` skips it with a warning. The same goes for a key that holds only other recipients' overrides. Other recipients' overrides are never touched.

`murk rotate --all` rotates every secret in the vault, prompting for each in sequence. `--generate` is not allowed with `--all`, because external credentials (database passwords, API keys from third-party services) require manual rotation at the source.

A prompt can wait for minutes, and a `git pull` or checkout meanwhile does not take murk's lock. If the vault file changed on disk between the load and the save, `rotate` saves nothing and exits 1, as `murk edit` does. The message is:

```
<vault> changed on disk while murk waited for the new values — nothing saved
```

Re-run `rotate` on the current vault. `circle revoke` and `agent revoke` refuse the same way.

Piped stdin works the same way when the batch takes one value (e.g. `murk rotate KEY`): all of stdin is the value. A batch of several values reads one value per line, matched to keys by position, so values cannot span lines. Input with more lines than values is refused before anything is written. If anything would be skipped, or a key would take more than one value, the batch is refused before any value is read, since later values would land on the wrong keys.

`--values-from FILE` (`-` for stdin) matches values by name instead. It reads the file with the same `.env` parsing as `murk import`: `KEY=value` lines, with an optional `export` prefix and single- or double-quoted values that may span lines. These abort with nothing rotated:

- an unclosed quote or other parse error,
- a file that names a key more than once, and
- a file with any line that is not blank, a comment or a `KEY=value` entry (an invalid or `MURK_*` name, or a line without `=`, such as the body of an unquoted multi-line value).

murk reports the lines of that last kind, and unquoted values containing ` #`, by line number, never by value. Every key the file names must be one this command can rotate, with exactly one value to replace. Otherwise the whole batch is refused before anything is written, naming the keys. Keys the file does not name are left unrotated and reported.

`--values-from` cannot be combined with `--generate`. A values file that is a symlink is refused, and one readable by others gets a warning. `--values-from -` keeps the new values off disk.

### `murk rotate --list`

Reports the keys that need rotating: the same overdue/expiry/post-revoke signals `doctor` evaluates, scoped to rotation. Human output exits 1 when anything needs rotating (usable as a script gate). For a verified listing, `--list --json` exits 0 even when keys need rotation. A failed load exits non-zero, and an unverified listing exits 1 in strict or agent mode (see [Header reads](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#header-reads)).

The result is verified whenever a key can verify it. [Header reads](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#header-reads) in SPEC.md states what happens with and without a key, and under `MURK_STRICT`.

`--json` prints an object, `{"verified": bool, "issues": [...]}`. `issues` is the `reason`-tagged array (`overdue`, `no_baseline`, `expired`, `expiring_soon`, `revoke_pending`). `verified` is `true` when a key verified the vault and `false` otherwise. Before 0.14 the array was printed alone ([B12](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#b12-rotate---list---json-before-014) in SPEC.md).

## `murk rm`

Removes a key from the vault (shared value, schema entry, and all private entries). No confirmation prompt: git is your safety net. Refused when the key has a value in a group you are not a member of, or holds only other recipients' personal overrides. Those values would stay in the vault, so only their owners can remove them.

## `murk get`

Prints a single decrypted value to stdout. Scoped values take priority over shared values. Exits with code 1 if key not found. On a terminal, control and invisible characters in the value are escaped, except tabs and newlines. Piped output is the exact bytes of the value followed by one newline.

## `murk edit`

Opens secrets in `$EDITOR`. With KEY, edits a single value. Without KEY, edits all secrets as `KEY=VALUE` lines. With `--scoped`, edits private overrides (motes) instead of shared values. With `--group NAME`, edits the values for that named group (you must be a member). An edited value stays in the tier you edited it in. If a group you are not a member of also holds the key, murk refuses to change its shared or group value, as `murk add` does. A new line for a key that is in a different tier is written as `murk add` writes it: without a tier flag, the key keeps its tier. With a tier flag, the key moves to that tier.

murk writes the plaintext buffer to a temp file (mode 0600 on Unix). It uses `XDG_RUNTIME_DIR` when that is a directory, then `/dev/shm` when it is RAM-backed, then the system temp directory. If that directory is not RAM-backed, murk warns that the wipe is best effort.

murk runs the editor (`EDITOR`, then `VISUAL`, then `vi`). The editor does not receive `MURK_KEY` or `MURK_KEY_FILE`. On Unix, murk runs it through `sh`, as git does, so the value can carry arguments such as `code --wait`, and the editor runs in its own process group. On Unix, after the editor exits, murk stops any process left in that group (SIGTERM, then SIGKILL after two seconds). Then murk overwrites the file with zeros and deletes it. The wipe also runs when murk returns an error or unwinds a panic, including editor failure and signals murk catches. SIGKILL, an abort or a power loss skip it. For a single key, an empty value or a non-zero editor exit aborts without saving. In bulk mode a non-zero exit aborts.

The buffer uses `.env` quoting. The bulk buffer has one `KEY=VALUE` line per secret. murk writes a value bare when that is safe, and otherwise in double quotes on one line, with newlines, control characters, invisible characters and whitespace other than a space escaped. Double-quoted values decode `\\`, `\"`, `\n`, `\r`, `\t` and `\u{HEX}`, and single-quoted values are literal.

The single-key buffer has a header that ends with the line `# ---- the value starts below this line ----`. Everything after that line is the value, `#` lines included. The value may be quoted, or pasted as is (trimmed, and it may span lines). `""` sets an empty value.

murk refuses to save a buffer it cannot read (a line without `=`, an invalid or duplicate key, or an unclosed quote), and the error names only the line number. It also refuses to save if the vault file changed on disk while the editor was open.

The wipe is best effort. It cannot undo a write to a journaled or copy-on-write disk, and editors may leave swap files. With `MURK_STRICT` set, `edit` aborts before it starts the editor unless the scratch file is on a RAM-backed filesystem (tmpfs or ramfs). Without `MURK_STRICT`, murk uses the best-effort wipe on any filesystem. A default macOS setup has no RAM-backed temp directory, so strict `edit` fails there. To avoid the editor altogether, pipe values into `add` or `rotate`, or load them from a file with `import`.

## `murk ls`

Lists key names, one per line. Without a key the list is unchecked, and the command says so on stderr (see [Header reads](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#header-reads)).

## `murk export`

Prints all secrets as `export KEY=VALUE` statements to stdout. Scoped values override shared values for the current identity. Errors go to stderr. Both the shell and `--json` forms skip keys that are not valid shell identifiers.

**Reserved names.** A key named like a variable that changes how a program, its loader, its shell, git or murk runs is refused, and the whole export fails before anything is printed. `--allow-reserved` lifts the refusal. murk compares names case-insensitively. Whoever can write the vault must not get to run code in the shell that evaluates it, redirect its traffic or the tools it runs, or switch off murk's own settings there. The full list, and the names that are not reserved, are in [Variable names a vault may not set](/concepts/env-vars/#variable-names-a-vault-may-not-set). `exec`, `agent exec` and the MCP `murk_exec` tool apply the same list. `murk_exec` has no override.

When `MURK_STRICT` is set, `export` refuses to run if stdout is a regular file (e.g. `murk export > .env`), since that persists plaintext secrets to disk. Piping to a process (the direnv flow) and printing to a terminal are still allowed. `get` and `diff --show-values` are guarded the same way. This is a guardrail against accidental redirects, not an airtight control: an explicit `murk export | tee .env` still writes the file.

Primary usage via direnv:

```bash
# .envrc
eval "$(murk export)"
```

## `murk import`

Imports secrets from a `.env` file. Each entry is `KEY=VALUE`, optionally prefixed with `export `. Bare values are taken literally and trimmed. Double-quoted values decode `\\`, `\"`, `\n`, `\r`, `\t` and `\u{HEX}`, single-quoted values are literal, and both may span lines. A bare value that contains ` #` keeps the `#` as part of the value, and murk prints a notice for that line. An unclosed quote aborts the import with nothing imported.

murk skips every `MURK_*` name, lines without `=` and invalid key names, with a notice that gives the line number and never the value. If a key appears twice, murk keeps the later value and prints `line N: KEY is already set on line M; the later value is kept`, again without the value. If keys already exist, murk refuses the import unless you give `--force`.

`--example` replaces an existing example. `--group` assigns all imported secrets to a tier, as for `murk add`. If murk refuses any key (for example, a key that a group you are not a member of holds), it imports nothing.

## `murk describe`

Sets metadata for a key in the plaintext schema. Does not touch encrypted values. Refused for a key held by a group you are not a member of, since its tags and policy belong to that group's members.

`--rotate-every` takes a day count (`90` or `90d`) and `--expires` takes a date (`2026-09-01`) or RFC 3339 timestamp. Pass `never` to either to clear it. Both are sticky: a later `describe` that omits the flag leaves the existing value untouched. `doctor` reports keys that are overdue for rotation or past/near their expiry.

## `murk info`

Prints the public schema. Works without `MURK_KEY`. With a valid key, also shows recipient names and count.

Each key's row shows any rotation interval and expiry as a trailing `rotate 90d  expires 2026-09-01` segment (public, shown without a key). `--json` includes `rotation_interval_days` and `expires_at` per entry. `murk doctor` evaluates these against the clock, and `info` just shows the policy. Without a key none of it is integrity-checked, and `info` says so on stderr (see [Header reads](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#header-reads)).

## `murk skeleton`

Exports a schema-only copy of the vault: key names, descriptions, examples, and tags, with no secrets and no recipients. `-o` refuses a path that already exists, a file or a symlink.

## `murk exec`

Runs a command with decrypted secrets injected as environment variables. Scoped values override shared values. Reserved names (see [`murk export`](#murk-export)) are refused unless `--allow-reserved` is passed. On Unix, murk replaces itself with the command via `exec`.

## `murk agent plan`

Emits schema-only context safe to paste into an AI agent prompt: key names, descriptions, examples, and tags. No decryption and no `MURK_KEY` required. The output contains no secret values, recipient pubkeys, vault name, or meta blob. `-o` refuses a path that already exists, a file or a symlink. Without a key the schema is unchecked and the command says so on stderr (see [Header reads](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#header-reads)).

## `murk agent exec`

`murk exec` with strict agent-safe defaults: clears the inherited environment, strips `MURK_KEY` so the child process cannot read the vault, and requires explicit `--only` keys (repeatable). Agent mode fails closed: there is no inject-everything path.

The key must be an agent grant key, handed over through `MURK_KEY` or `MURK_KEY_FILE`. An auto-discovered key from `~/.config/murk/keys` is refused before the vault is loaded. Any other key that is a full recipient of the vault, including your own key set through `MURK_KEY` or `MURK_KEY_FILE`, is refused once the vault is open and before any secret is resolved. `--allow-operator-key` lifts both refusals. It prints a warning on every run that decrypts with a non-grant key. A grant key never triggers it.

The child runs supervised, not `exec`-ed: its stdout and stderr are pipes, and every injected value of 4 bytes or more is replaced with `***NAME***` (the secret's name) before it is written out. murk forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to it by another process, and exits with the child's code or re-raises its terminating signal. Reserved names (see [`murk export`](#murk-export)) are refused unless `--allow-reserved` is passed. See [AI agents & MCP](/guides/ai-agents-mcp/).

## `murk agent grant`

Mints a fresh ephemeral age identity and gives it read access to exactly the `--only` keys (repeatable, required), never the operator's own key. The agent becomes a vault recipient. It gets a private (per-recipient) ciphertext of each `--only` key's shared value and its own record in `agents`. It is excluded from the `everyone` layer and is not a recipient of the meta. murk records grant metadata (scope, TTL, issuer) in the encrypted meta. See [Agent grants](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#agent-grants) in SPEC.md.

`--renew` revokes the existing key and mints the replacement in one vault write. `--ttl` takes a positive number with a unit of `s`, `m`, `h` or `d`, such as `30m`, `2h` or `7d`, at most `365d`. A longer TTL is refused. Reads fail closed after expiry, though the enforcement is binary-level, not cryptographic (see the [threat model](/security/threat-model/)).

The agent key is written to murk's own slot for the grant, `~/.config/murk/agent-keys/<vault-hash>-NAME` (or `--out PATH`, or `--out -` to stream it to stdout). It is always owner-only (`0600`). murk writes it to a temporary file beside the destination and renames it into place only after the vault is saved, so a failed save leaves an existing key file untouched. `--out PATH` refuses a file that already exists (it may be the operator's own key) unless `--force` is passed, and it refuses before the vault changes. The default path is replaced on renewal. The key file is headed by `# murk-trusted-signer:` lines (see [The key file and its anchor](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#the-key-file-and-its-anchor)).

Run the agent with `MURK_KEY_FILE` pointing at that key and `MURK_AGENT=1`. `MURK_AGENT=1` forces strict mode, so the process cannot fall back to the operator's stored key.

## `murk agent init`

One-step onboarding. With `--allow-tag`, it first sets the agent allow-list, as `murk policy set` does. Then it mints a grant as `murk agent grant` does, with the same `--name`, `--only`, `--ttl`, `--out` and `--force` rules. When it writes a key file, it prints the command to run the agent with that key and a note to run the agent as an identity that cannot read `~/.config/murk`.

## `murk agent ls`

Lists active grants: name, truncated pubkey, scope, and TTL status (time remaining, or how long expired). Works offline. `--json` outputs structured data including an `expired` flag.

## `murk agent revoke`

Removes the grant and its ephemeral recipient (clearing the agent's private ciphertexts).

The handed-off key can still decrypt old `.murk` versions from git history. So murk marks every key it could read as owing a rotation (`revoked_at`), as `circle revoke` does. Those keys are its scope, any key holding a private copy for it, and keys in groups it belonged to. A key is marked if it still has a shared value or a value in one of those groups. `agent grant --renew` marks the previous key's keys the same way.

Rotation is the real close. `--rotate` (or the interactive prompt) re-prompts for a new value for each of those keys, in its own tier. The revoke and the rotated values are written together in one save. So a refused, short, or aborted batch writes nothing, and the grant is not revoked either. The error says how to revoke now and rotate afterwards. Nothing is saved either if the vault file changed on disk while murk waited for the values (see [`murk rotate`](#murk-rotate)). `--values-from FILE` supplies the values by name, as for `murk rotate`.

## `murk agent connect`

Adds a `murk mcp` server entry to an AI client's MCP config and mints a grant for it. Without `CLIENT`, connect configures every client that already has a config file or marker directory (such as `.cursor/`) next to the vault, and fails when it finds none. `--allow-tag` sets the allow-list before the grant is minted. `--allow-exec` writes `--allow-exec` into the server entry, which enables `murk_exec`. A non-default vault is passed to the server with `--vault`.

A second connect with the same `--name` reuses the grant when `--only` names the same keys, and refuses when the scope differs. It also refuses when the grant exists but its key file is gone. connect renders every config before it changes anything, so a config it cannot parse or that is a symlink fails before a grant is minted. If a write fails after that, connect restores the configs it already wrote and revokes the grant it minted in this run. A grant key cannot run connect. See [AI agents & MCP](/guides/ai-agents-mcp/) for each client's config path.

## `murk agent disconnect`

Removes murk's server entry from an AI client's MCP config. Without `CLIENT`, it removes the entry from every client config it knows. With `--rotate` it runs `murk agent revoke NAME --rotate` for the grant named by `--name`. With `--rotate`, a grant key is refused before any config changes. Exits 1 if any config could not be changed.

## `murk mcp`

Runs an in-process MCP (Model Context Protocol) stdio server so AI-agent harnesses can read murk secrets on the capability-not-credential model. It calls the murk-cli library directly, with no subprocess and no Node. It fails closed unless the loaded identity is a scoped agent grant with `MURK_AGENT=1`. It refuses to start with the operator's stored key, a plain recipient, or no grant. stdout is the JSON-RPC channel (never written to otherwise). All logs go to stderr.

Before every tool call the server hashes the vault file (BLAKE3). When the bytes changed, it first verifies their signature against the signers in the grant's key file (and `MURK_TRUSTED_SIGNERS`). The server keeps a floor: the highest `generation` it has seen with a valid signature, and that vault's signature (signer canonicalised), even when the grant could not load that vault (a revoke). It refuses a vault with another `vault_id`, a lower `generation`, or the floor's `generation` with another signature (a fork). Otherwise it loads those bytes again through the full load path with the grant key it started with, and uses the new state only if that load passes. Any failure fails the call, and until a load passes the cached state is not served again, even for the bytes it came from. A revoke, a policy change or a tampered file therefore applies to the next call, and an older or forked copy written back after a call has seen the newer vault is refused. Every call also re-checks the grant's expiry, so an expired grant fails every tool, `murk_plan` included.

The floor is held in memory and starts from the vault the server opens. A copy written back before any call saw the newer vault is accepted, as a grant load accepts it, so anyone who can write the vault file can keep a running server from seeing a revoke. Restart the server after a revoke to be sure, since a server that starts on the revoked vault refuses to run. The floor also refuses a vault moved back on purpose (a branch switch, a checkout of an older commit) until the server restarts, and the refusal says so.

Tools, all bounded to the grant:

- `murk_plan`: the schema (key names, descriptions, examples, tags) of the secrets this grant may read, as JSON, with an optional `tags` filter. No values, and no keys outside the grant's scope or the agent policy.
- `murk_get { key }`: one secret value, if the grant may read it. A forbidden or out-of-scope key returns an error result, never the value.
- `murk_exec { only, command }`: opt-in via `--allow-exec` (off by default). Runs a command with the named secrets injected into its environment (no shell), returning captured stdout/stderr and the exit code. Every key must be in scope and policy-allowed, and output and runtime are bounded. `only` scopes the injected secrets, not the command, so it is not a sandbox.

See [AI agents & MCP](/guides/ai-agents-mcp/) for setup (`murk agent init`) and a verify snippet.

## `murk policy show`

Prints the agent access policy. Works without a key, because the policy is in the plaintext header. Without a key it is unchecked, and the command says so on stderr (see [Header reads](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#header-reads)). Shows the allowed tags, or notes that agent mode is unrestricted (no policy) or locked out (empty allow-list).

## `murk policy set`

Sets the agent allow-list. Default-deny once set (see [Policy](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#policy) in SPEC.md). Writes the policy into the header, where the MAC and signature cover it.

## `murk circle`

Lists all recipients. With `MURK_KEY`, shows display names from the encrypted meta and marks the current user with `◆`. `--json` prints an array of objects with `pubkey`, `name` and `is_self`.

## `murk circle authorize`

Adds a new recipient. Re-encrypts all shared secrets to include the new public key. Accepts `age1...`, `ssh-ed25519 ...`, `ssh:PATH` (the first non-empty line of an SSH public key file), `ssh:` (`~/.ssh/id_ed25519.pub`) or `github:username`. With `--group`, also adds the new recipient(s) to that group in the same step (you must be a member of the group). murk refuses `ssh-rsa` recipients, however the key is spaced or commented, unless you pass `--allow-ssh-rsa` (see RUSTSEC-2023-0071). For `github:username`, it skips RSA keys with a warning and refuses only when every key is RSA. When a GitHub user's keys differ from the pinned set (see `github_pins` under [Meta](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#meta)), authorize stops unless you pass `--force`.

## `murk circle revoke`

Removes a recipient by pubkey, display name or `github:username`. Re-encrypts all shared secrets without their key. Removes their private entries. murk refuses to revoke your own key, whether you name it directly or through your display name, before it prompts or writes anything. Another recipient has to revoke you. When the name covers several keys (a GitHub user with more than one key), murk lists them and asks before it revokes them all. Without a terminal it refuses unless you pass `--force`.

Revoking a recipient also revokes the agent grants whose key files trust it. [Revoking a recipient revokes the grants that trust it](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#revoking-a-recipient-revokes-the-grants-that-trust-it) in SPEC.md lists which grants, what murk deletes, and what it prints.

Lists the secrets the revoked recipient had access to.

With `--rotate`, murk prompts for a new value for each value they could read, in the same session, and re-encrypts it in its own tier. The shared value stays shared. A value in a group they belonged to stays in that group, encrypted to its remaining members. Values they could not read (other groups, your personal overrides) are not prompted for.

A group value the revoked recipient could read but you cannot (you are not in that group) cannot be re-encrypted by you. Its current ciphertext still opens with their key until a member of that group rotates it. The revoke says so, and the key keeps its pending-rotation marker. A key they reached only through their own personal override is not marked, since nothing of it is left to rotate.

The revoke and the rotated values are written together in one save. So input that is refused, runs short, or is aborted writes nothing, and the recipient is not revoked either. The error says how to revoke now (`murk circle revoke RECIPIENT` without `--rotate`) and rotate afterwards (`murk rotate --all --values-from FILE`). Nothing is saved either if the vault file changed on disk while murk waited for input (see [`murk rotate`](#murk-rotate)). Piped values and `--values-from FILE` follow the rules of `murk rotate`. Keys `--values-from` does not name stay marked, and `murk rotate --list` keeps listing them.

Without the flag on an interactive terminal, murk offers to rotate. Otherwise it prints a hint. The recipient can still decrypt previous versions from git history, so rotation is the only way to close the exposure.

## `murk group create`

Creates a new named recipient group, seeded with you as its first member so you can always read and re-encrypt it. Reserved names (`everyone`, `me`, `all`, `self`, `mine`, `shared`) are rejected.

## `murk group ls`

Lists groups and their members, resolved to display names. The current user is marked with `*`. Requires `MURK_KEY` to decrypt membership. An agent grant cannot open the meta, so it lists no groups and warns on stderr that a grant cannot read group membership.

## `murk group add`

Adds a recipient (by pubkey or display name) to a group. You must already be a member. The group's secrets are re-encrypted to include the new member on save.

## `murk group rm`

With `--member`, removes a recipient from the group and re-encrypts its secrets so the removed member loses access to current values. Git history stays readable, so each of the group's secrets is marked as owing a rotation (`revoked_at`) and listed. `murk rotate --list` and `doctor` flag them until they are rotated. Without `--member`, deletes the group entirely. The delete is refused if any secret is still assigned to the group. You must be a member to modify a group, or to delete one that has members.

## `murk verify`

Verifies vault integrity (MAC and signature), reports whether this machine trusts the signer and why not (the same reasons a load refuses with), checks who signed the last git commit that touched the vault, and runs safety checks without exporting secrets. Exits 1 on any finding.

**Commit check.** Only when the vault has git history. A signed commit proves nothing about who the signer is: git vouches for any key it is told about, an attacker's throwaway key included.

So verify reports the commit as ok only when git verified the signature and the signing key is a trusted signer of this vault. The key must be an ssh-ed25519 key in the set the Trust rules used (`MURK_TRUSTED_SIGNERS` and a grant key file's anchor when either is given, otherwise the pin's trusted set, and grant keys never count), matched by its `ssh-keygen -l` fingerprint. Only an ssh-ed25519 key can match, because it is the only key type that both signs git commits and is a murk signer. The line then reads `ok commit  last .murk commit signed by <name> with key <fingerprint>, a trusted signer of this vault`. Every other outcome is a finding, and exits 1:

- **Signed by another key**: a gpg key, or an ssh key that is not a trusted signer. The message is `signed by key <id>, which is not a trusted signer of this vault`, naming the recipient when the key is one. The vault's own recipients are not trusted by being listed. Trust comes from the pin or the environment.
- **Not vouched for by git**: the signature could not be checked, has expired, or was made with an expired key.
- **Bad**: the signature does not match the commit, or the key is revoked in the user's `gpg.ssh.revocationFile`.
- **Unsigned.**

verify runs git with `gpg.ssh.allowedSignersFile` set to a temporary file listing the trusted ssh-ed25519 signers, so the result does not depend on the user's own allowed-signers list. Without one git cannot check an ssh signature and reports a signed commit as unsigned.

**Signature only.** `murk verify --signature-only` checks the vault signature without a key, for a pull-request check in CI that holds no secret. murk does not resolve or read a key (`MURK_KEY`, `MURK_KEY_FILE` or a stored key), does not read the trust pin, and decrypts nothing. Only the flag selects this check. Without it, `murk verify` with no key fails as before.

The check reads and validates the vault, reads the trusted signers from `MURK_TRUSTED_SIGNERS`, and verifies the top-level (view 2) signature against the trusted key for its signer only, as an agent grant load does. The signature covers every vault field except the signature itself, the ciphertexts included. A text merge of two changed vaults (GitHub's conflict editor, `git merge -X ours` or `-X theirs`) makes a file that neither side signed, so the check fails it. A union merge makes a file that does not parse.

It exits 0 and prints `ok signature verified by trusted signer <key>` only when the vault parses and a trusted signer signed it. Every other result exits 1 with one reason:

- **Parse error.** The hint names a merge without the murk merge driver and tells you to merge locally after `murk setup-merge-driver`.
- **No trusted signers.** `MURK_TRUSTED_SIGNERS` is unset or empty. An invalid entry is an error that names the variable.
- **Format 2.x.** The signature is inside the encrypted meta, so the check cannot verify it without a key.
- **Unsigned.**
- **Signer not trusted.** The signer is not in `MURK_TRUSTED_SIGNERS`.
- **Signature does not verify.** The file changed after it was signed, or an age signer's entry has a different verifying key. The hint names the merge cause and the local merge.

It does not decrypt, so it does not check the MAC over the values, grant expiry, rollback against earlier saves, the last commit's signature, or the safety checks above. `murk verify` with a key checks those. All lines go to stderr.

## `murk trust`

Shows who signed the vault, then asks before it records the vault in the local trust pin. What it shows, what accepting records, and what it refuses are in [Accepting a vault: `murk trust`](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#accepting-a-vault-murk-trust) in SPEC.md.

`--yes` accepts without asking. Without a terminal and without `--yes`, it only shows and exits 1.

`--print-key` prints your own trusted-signer entry to stdout (`age1…:<verifying key>`, or the ssh-ed25519 key line) and your fingerprint to stderr, then exits.

## `murk doctor`

Checks the surrounding repo for hygiene issues: inline keys in `.env`, key files sitting next to the vault, state that would be bad to commit. If a vault is present it also reads the plaintext schema and reports keys overdue for rotation or past/near their `expires_at`. That read is never integrity-checked. With no key `doctor` says so on stderr (see [Header reads](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#header-reads)), and with one it still does not load the vault, so use `murk rotate --list` or `murk verify` where the result must be trusted. Exits 1 on findings.

## `murk scan`

Decrypts the vault and searches text files under the given paths for value substrings. Skips hidden directories, `target/` and `node_modules/`, files ending in `.lock` or `.murk`, and unreadable or binary (non-UTF-8) files. It ignores values shorter than 8 bytes to avoid false positives. Exits 1 if any leak is found. A given path that does not exist or cannot be read exits 2 before scanning. A file or directory under it that cannot be read is reported, and the scan exits 1 as incomplete instead of reporting no leaks.

## `murk diff`

Shows which secrets changed between the current vault and a git ref, and what changed in who can read or sign it: recipients added or removed, a changed signer, a changed signing key for a recipient, the policy, agent grants and group members.

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

How `diff` verifies the working vault and the revision at the ref, and when it refuses one, is in [Historical revisions](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#historical-revisions) in SPEC.md.

`diff` also exits non-zero when the ref does not name a commit or git fails. The vault path is resolved inside the repository that holds it, so `diff` works from a subdirectory. Only a vault that git shows is absent from the ref (or a repository with no commits yet) counts as empty, and then every secret shows as added. A ref that starts with `-` is refused, so it can never reach git as an option.

## `murk merge-driver`

Git merge driver for vault files, called by git (the command is hidden from help). Its rules are in [Merge](https://github.com/interrupted-sh/murk/blob/main/SPEC.md#merge) in SPEC.md.

## `murk setup-merge-driver`

Configures git to use `murk merge-driver -- %O %A %B %P` for vault files via `.gitattributes` and `.git/config`. The `--` keeps a vault named like a flag (`-h.murk`) a path.

It replaces `merge.murk.driver` lines that murk wrote (also several of them), but refuses, writing nothing, when any `merge.murk.driver` value git reads here is a command murk did not write, and says how to remove it.

It also refuses, writing nothing, when an attributes line would be overridden by a line it adds:

- It reads every attributes file git reads (the system file, `core.attributesFile`, each `.gitattributes` in the working tree, tracked or not, and `.git/info/attributes`).
- A line counts when it sets, unsets or resets `merge` to anything but `murk`, directly or through a macro such as `binary`, and its pattern could match a name that a missing line matches, whether or not such a file exists.
- Quoted patterns are decoded as git decodes them. Patterns match case-sensitively, as git matches them, unless `core.ignorecase` is set. Then case is ignored, and a negated character class counts whenever git could match a vault name with it.
- A pattern whose file-name part starts with `*` counts for `.murk.*` names only when it names a merge driver: `*.prod merge=custom` refuses, because it covers a `.murk.prod` vault, but `*.png binary`, `*.png -merge` and `*.png !merge` do not. Against `*.murk` names every merge setting counts.
- The refusal names each such line with its file and line number.

It adds the lines `*.murk merge=murk` (`.murk`, `prod.murk`) and `.murk.* merge=murk` (`.murk.prod`), each only if it is missing, to the `.gitattributes` at the root of the working tree, also when run from a subdirectory, and prints that file's path (made safe for the terminal). It sets git config before it writes `.gitattributes`. When git config fails, `.gitattributes` is unchanged and the error says so. Outside a git working tree it fails with git's own error and writes nothing. It also refuses, writing nothing, when git's working tree does not contain the current directory (a repository whose `core.worktree` points elsewhere).

## `murk completion`

Prints shell completions to stdout (`generate`) or installs them to the shell's standard completion path (`install`). See [Shell completions and man pages](/reference/completions-man/).
