// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI command model: the clap `Parser`/`Subcommand` types.
//!
//! Defined in the library (not `main.rs`) so both the `murk` binary and the
//! `doc-gen` tool build the exact same command tree from `Cli::command()`.

use clap::{Parser, Subcommand};

/// Value parser for text a command writes into the vault header
/// ([`crate::new_text`]). Its error names the argument, never echoes the
/// value: the value is the very text that could drive the terminal.
#[derive(Clone, Copy)]
pub struct NewText {
    /// Allow newlines (descriptions).
    pub multiline: bool,
}

impl NewText {
    pub const LINE: NewText = NewText { multiline: false };
    pub const BLOCK: NewText = NewText { multiline: true };
}

impl clap::builder::TypedValueParser for NewText {
    type Value = String;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<String, clap::Error> {
        use clap::error::ErrorKind;
        let name = arg.map_or_else(|| "value".to_string(), ToString::to_string);
        let Some(text) = value.to_str() else {
            return Err(clap::Error::raw(
                ErrorKind::InvalidUtf8,
                format!("{name} is not valid UTF-8\n"),
            )
            .with_cmd(cmd));
        };
        crate::new_text(text, self.multiline)
            .map(|()| text.to_string())
            .map_err(|why| {
                clap::Error::raw(ErrorKind::InvalidValue, format!("{name} {why}\n")).with_cmd(cmd)
            })
    }
}

/// Encrypted secrets manager for developers.
#[derive(Parser)]
#[command(name = "murk", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    // Setup & recovery
    /// Initialize a vault or reuse its existing key
    Init {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Write a .envrc for direnv integration
    ///
    /// Creates `.envrc` in the current directory with a line that runs
    /// `murk export`. If `.envrc` already exists, murk appends the line. If it
    /// already has a `murk export` line, murk changes nothing. Run
    /// `direnv allow` afterward.
    Env {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Print the key encoded by a BIP39 recovery phrase (saves nothing)
    Restore {
        /// Vault filename, for the restored-identity recipient check
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Print the BIP39 recovery phrase for your age key
    ///
    /// murk uses the key from `MURK_KEY`, `MURK_KEY_FILE` or the stored key for
    /// `.murk`. SSH keys and plugin identities have no recovery phrase.
    Recover,

    // Secrets
    /// Add or update a secret
    ///
    /// On a terminal, murk asks for the value with a hidden prompt. When stdin
    /// is piped, murk reads all of it as the value and drops one trailing
    /// newline.
    Add {
        /// Name of the secret
        key: String,
        /// Description of the secret
        #[arg(long, value_parser = NewText::BLOCK)]
        desc: Option<String>,
        /// Example value
        #[arg(long, value_parser = NewText::LINE)]
        example: Option<String>,
        /// Who can read the secret: `everyone`, `me` (a private value for you
        /// only) or a group name (experimental). Omit it to keep an existing
        /// secret's tier. A new secret is shared with everyone
        #[arg(long)]
        group: Option<String>,
        /// Deprecated alias for `--group me`
        #[arg(long, hide = true)]
        scoped: bool,
        /// Tag for grouping (repeatable)
        #[arg(long, value_parser = NewText::LINE)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Generate a random secret and store it
    Generate {
        /// Name of the secret
        key: String,
        /// Length in bytes
        #[arg(long, default_value = "32")]
        length: usize,
        /// Encode the value as hex instead of URL-safe base64
        #[arg(long)]
        hex: bool,
        /// Description of the secret
        #[arg(long, value_parser = NewText::BLOCK)]
        desc: Option<String>,
        /// Example value
        #[arg(long, value_parser = NewText::LINE)]
        example: Option<String>,
        /// Who can read the secret: `everyone`, `me` (a private value for you
        /// only) or a group name (experimental). Omit it to keep an existing
        /// secret's tier. A new secret is shared with everyone
        #[arg(long)]
        group: Option<String>,
        /// Tag for grouping (repeatable)
        #[arg(long, value_parser = NewText::LINE)]
        tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Rotate secrets with new values
    ///
    /// New values come from a hidden prompt on a terminal, or from piped
    /// stdin. With a KEY, murk reads all of stdin as the value. With `--all`,
    /// it reads one line per secret, in name order. `--generate` and
    /// `--values-from` supply values another way. murk refuses `--generate`
    /// with `--all`.
    Rotate {
        /// Secret to rotate. Omit it when you use `--all`
        key: Option<String>,
        /// Rotate all secrets in the vault
        #[arg(long)]
        all: bool,
        /// Generate random values instead of prompting (refused with `--all`)
        #[arg(long)]
        generate: bool,
        /// Length in bytes for generated values
        #[arg(long, default_value = "32")]
        length: usize,
        /// Encode generated values as hex instead of URL-safe base64
        #[arg(long)]
        hex: bool,
        /// Read new values from a dotenv file of KEY=value lines (`-` for stdin), matched by secret name
        #[arg(long, value_name = "FILE", conflicts_with_all = ["generate", "list"])]
        values_from: Option<String>,
        /// List the secrets that need rotation instead of rotating (exits 1 if any do)
        #[arg(long, conflicts_with_all = ["key", "all", "generate", "hex"])]
        list: bool,
        /// Print the listing as a JSON object with `verified` and `issues`. The exit code is then 0 even when secrets need rotation
        #[arg(long, requires = "list", conflicts_with_all = ["key", "all", "generate", "hex"])]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a secret
    Rm {
        /// Name of the secret
        key: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Get a single decrypted value
    Get {
        /// Name of the secret
        key: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Edit secrets in $EDITOR (experimental)
    Edit {
        /// Edit one secret. Omit it to edit all
        key: Option<String>,
        /// Deprecated alias for `--group me`. Edits your private values instead of shared secrets
        #[arg(long)]
        scoped: bool,
        /// Edit this group's values instead of shared secrets. `me` means your private values. A group name is experimental
        #[arg(long)]
        group: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// List all secret names
    Ls {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Export all secrets as shell export statements
    Export {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Allow secrets named like loader, shell or tool variables (PATH, LD_*, GIT_*, MURK_*, ...)
        #[arg(long)]
        allow_reserved: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Import secrets from a .env file
    Import {
        /// Path to the .env file to import
        #[arg(default_value = ".env")]
        file: String,
        /// Overwrite existing secrets. Without it, import stops if any secret already exists
        #[arg(long)]
        force: bool,
        /// Who can read the imported secrets: `everyone`, `me` (private values
        /// for you only) or a group name (experimental). Omit it to keep each
        /// existing secret's tier. New secrets are shared with everyone
        #[arg(long)]
        group: Option<String>,
        /// Example value applied to every imported secret
        #[arg(long, value_parser = NewText::LINE)]
        example: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Metadata & inspection
    /// Set a secret's description, example, tags and rotation or expiry policy
    ///
    /// Each call replaces the description. It also replaces the example:
    /// omitting `--example` clears it. `--tag` replaces the tags only when
    /// given. `--rotate-every` and `--expires` change only when given.
    Describe {
        /// Name of the secret
        key: String,
        /// Description text (replaces the current one)
        #[arg(value_parser = NewText::BLOCK)]
        description: String,
        /// Example value. Omitting it clears the current example
        #[arg(long, value_parser = NewText::LINE)]
        example: Option<String>,
        /// Tag for grouping (repeatable, replaces existing tags)
        #[arg(long, value_parser = NewText::LINE)]
        tag: Vec<String>,
        /// Rotation interval, e.g. `90d` or `90` (days). `never` clears it
        #[arg(long, value_name = "DAYS")]
        rotate_every: Option<String>,
        /// Hard expiry date, e.g. `2026-09-01`. `never` clears it
        #[arg(long, value_name = "DATE")]
        expires: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Show public schema and key info
    Info {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Export schema-only vault with no secrets or recipients
    Skeleton {
        /// New output file. murk refuses a path that already exists. Without this option, murk prints to stdout
        #[arg(long, short)]
        output: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Run
    /// Run a command with secrets injected as environment variables
    #[command(trailing_var_arg = true)]
    Exec {
        /// Inject only these secrets (repeatable)
        #[arg(long)]
        only: Vec<String>,
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Start the command with only the injected secrets plus PATH, HOME and TERM on Unix
        ///
        /// On Windows, murk keeps PATH and a fixed set of system variables.
        #[arg(long)]
        clean_env: bool,
        /// Allow secrets named like loader, shell or tool variables (PATH, LD_*, GIT_*, MURK_*, ...)
        #[arg(long)]
        allow_reserved: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
        /// Command and arguments to run
        ///
        /// Put murk options such as `--only` before the command. murk passes
        /// everything after the command name to the command, so
        /// `murk exec echo hi --only FOO` runs `echo hi --only FOO` and injects
        /// every secret.
        #[arg(required = true)]
        command: Vec<String>,
    },

    // Agents
    /// Give AI agents scoped, time-limited access to secrets (experimental)
    Agent {
        #[command(subcommand)]
        sub: AgentCommand,
    },

    /// Run an MCP (Model Context Protocol) stdio server for AI agents (experimental)
    Mcp {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
        /// Enable the murk_exec tool, which runs commands with the grant's
        /// secrets injected
        ///
        /// Off by default. The tool runs arbitrary commands as this user. The
        /// injected secrets are limited to the grant, but the command itself is
        /// not sandboxed.
        #[arg(long = "allow-exec")]
        allow_exec: bool,
    },

    /// Manage the agent access policy (experimental)
    Policy {
        #[command(subcommand)]
        sub: PolicyCommand,
    },

    // Recipients & groups
    /// Manage recipients
    ///
    /// With no subcommand, lists the vault's recipients.
    #[command(alias = "recipients")]
    Circle {
        #[command(subcommand)]
        sub: Option<CircleCommand>,
        /// Output the recipient list as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Hidden: `murk authorize` exists for old scripts. Use `murk circle authorize`.
    /// Add a recipient to the vault
    #[command(hide = true)]
    Authorize {
        /// Public key (age1...), ssh:path, ssh: (default ~/.ssh/id_ed25519.pub), or github:username (experimental)
        pubkey: String,
        /// Display name for this recipient
        #[arg(long, value_parser = NewText::LINE)]
        name: Option<String>,
        /// Accept changed GitHub keys. Without it, authorize stops when a user's keys differ from the pinned set
        #[arg(long)]
        force: bool,
        /// Allow ssh-rsa keys. They are refused or skipped by default, so prefer ed25519
        #[arg(long)]
        allow_ssh_rsa: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Hidden: `murk revoke` exists for old scripts. Use `murk circle revoke`.
    /// Remove a recipient from the vault
    #[command(hide = true)]
    Revoke {
        /// Recipient pubkey, display name, or github:username
        recipient: String,
        /// Rotate the secrets they had access to in the same session
        #[arg(long)]
        rotate: bool,
        /// With --rotate, read new values from a dotenv file of KEY=value lines (`-` for stdin)
        #[arg(long, value_name = "FILE", requires = "rotate")]
        values_from: Option<String>,
        /// Revoke every key of a multi-key GitHub user without confirmation
        #[arg(long)]
        force: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Manage recipient groups (experimental)
    Group {
        #[command(subcommand)]
        sub: GroupCommand,
    },

    // Checks
    /// Verify vault integrity without exporting secrets
    Verify {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Review who signed the vault and what changed, then trust it on this machine
    ///
    /// Needed once per vault on a new clone, whenever a teammate's first
    /// signed write arrives, and whenever murk refuses a vault (an unfamiliar
    /// signer, an unsigned or rolled-back vault). Shows the signer's key and
    /// signing-key fingerprint, the recipient changes since this machine last
    /// trusted the vault, and asks before recording it. An unsigned vault is
    /// signed with your key.
    Trust {
        /// Accept without asking, for scripts. Review the vault first
        #[arg(long)]
        yes: bool,
        /// Print your own trusted-signer entry (for MURK_TRUSTED_SIGNERS) and
        /// signing-key fingerprint (for teammates to confirm), then exit
        #[arg(long, conflicts_with = "yes")]
        print_key: bool,
        /// Trust a key this machine recorded as removed from the vault again
        /// (its public key, or its name in the vault). Repeat for each key.
        /// A vault signed by or listing a removed key is never trusted
        /// without it
        #[arg(long = "re-add", value_name = "KEY", conflicts_with = "print_key")]
        re_add: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Check the surrounding repo for hygiene issues
    Doctor {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Scan files for leaked secret values
    Scan {
        /// Files or directories to scan (defaults to current directory)
        paths: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    // Git integration
    /// Show secret and access changes vs a git ref (experimental)
    ///
    /// Lists recipients, signer, signing keys, policy, grants and group members
    /// that changed, then the secrets. The vault at the ref is verified first.
    /// murk never shows a revision that this machine's trust pin refuses.
    Diff {
        /// Git ref to compare against
        #[arg(default_value = "HEAD")]
        git_ref: String,
        /// Show actual values (not just secret names)
        #[arg(long)]
        show_values: bool,
        /// Output JSON: {"secrets": [...], "changes": [...]} (values only with --show-values)
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Configure git to use murk's merge driver for .murk files (experimental)
    #[command(name = "setup-merge-driver")]
    SetupMergeDriver,

    /// Git merge driver for .murk vault files (called by git, experimental)
    #[command(name = "merge-driver", hide = true)]
    MergeDriver {
        /// Path to base version (%O)
        base: String,
        /// Path to ours version (%A). murk writes the result here
        ours: String,
        /// Path to theirs version (%B)
        theirs: String,
        /// The vault's path in the work tree (%P), whose trust pin both sides are checked against
        path: Option<String>,
    },

    // Shell
    /// Generate or install shell completions
    Completion {
        #[command(subcommand)]
        action: CompletionAction,
    },
}

#[derive(Subcommand)]
pub enum CompletionAction {
    /// Print completions to stdout
    Generate {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Install completions under your home directory
    ///
    /// Writes `~/.zfunc/_murk` for zsh,
    /// `~/.local/share/bash-completion/completions/murk` for bash,
    /// `~/.config/fish/completions/murk.fish` for fish,
    /// `~/.config/elvish/lib/murk.elv` for elvish and
    /// `~/.config/powershell/_murk.ps1` for PowerShell. It replaces a file that
    /// is already there and needs HOME. For zsh and bash, murk then prints the
    /// lines to add to your shell startup file.
    Install {
        /// Shell to install completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Emit schema-only context safe to paste into an AI agent prompt (experimental)
    Plan {
        /// Filter by tag (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// New output file. murk refuses a path that already exists. Without this option, murk prints to stdout
        #[arg(long, short)]
        output: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Run a command with strict agent-safe defaults (experimental)
    ///
    /// On Unix the command keeps only PATH, HOME and TERM from the inherited
    /// environment. On Windows it keeps PATH and a fixed set of system
    /// variables. murk strips MURK_KEY, requires `--only` and masks the
    /// injected values in the output.
    #[command(trailing_var_arg = true)]
    Exec {
        /// Inject only these secrets (repeatable, required)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Decrypt with a key that is not an agent grant: your own stored key
        /// from ~/.config/murk/keys, or a full recipient's MURK_KEY or
        /// MURK_KEY_FILE. Without this, agent exec needs an agent grant key
        #[arg(long)]
        allow_operator_key: bool,
        /// Allow secrets named like loader, shell or tool variables (PATH, LD_*, GIT_*, MURK_*, ...)
        #[arg(long)]
        allow_reserved: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
        /// Command and arguments to run
        ///
        /// Put murk options such as `--only` before the command. murk passes
        /// everything after the command name to the command, so
        /// `murk agent exec echo hi --only FOO` fails with a missing `--only`.
        #[arg(required = true)]
        command: Vec<String>,
    },

    /// Mint a scoped ephemeral key that can read only the named secrets (experimental)
    Grant {
        /// Grant name (used to revoke it later)
        #[arg(long)]
        name: String,
        /// Secrets this grant can read (repeatable, required)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Time to live, e.g. 30m, 2h or 7d, up to 365d. Reads fail closed after expiry
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// Replace the grant with this name: revoke its key, mint a fresh one. Without this, murk
        /// refuses a name that still has a grant record, and an expired grant keeps its record
        /// until the next vault write
        #[arg(long)]
        renew: bool,
        /// Where to write the agent key: a path, or `-` for stdout
        #[arg(long)]
        out: Option<String>,
        /// Replace a file already at --out (refused by default)
        #[arg(long, requires = "out")]
        force: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Mint a scoped grant and print how to run the agent safely (experimental)
    ///
    /// With `--allow-tag`, murk first sets the agent allow-list to those tags.
    Init {
        /// Grant name (used to revoke it later)
        #[arg(long)]
        name: String,
        /// Secrets the agent can read (repeatable, required)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Set the agent allow-list to these tags before granting (repeatable)
        #[arg(long = "allow-tag", value_parser = NewText::LINE)]
        allow_tag: Vec<String>,
        /// Time to live, e.g. 30m, 2h or 7d, up to 365d. Reads fail closed after expiry
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// Where to write the agent key: a path, or `-` for stdout
        #[arg(long)]
        out: Option<String>,
        /// Replace a file already at --out (refused by default)
        #[arg(long, requires = "out")]
        force: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// List active agent grants and their TTLs (experimental)
    Ls {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Revoke an agent grant (experimental)
    ///
    /// The grant's key can still decrypt old versions of the vault from git
    /// history, so rotate the secrets it could read: pass `--rotate`, or answer
    /// the prompt on a terminal.
    Revoke {
        /// Grant name
        name: String,
        /// Rotate the secrets the grant could read, in the same run. murk stores
        /// a new value for each. It does not rotate them at the provider
        #[arg(long)]
        rotate: bool,
        /// With --rotate, read new values from a dotenv file of KEY=value lines (`-` for stdin)
        #[arg(long, value_name = "FILE", requires = "rotate")]
        values_from: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Add `murk mcp` to an AI client's MCP config and mint a scoped grant for it (experimental)
    Connect {
        /// Client to configure: claude, cursor, vscode, zed, gemini, omp or codex.
        /// Omit it to configure every client that already has a config file or
        /// marker directory (such as `.cursor/`) next to the vault
        client: Option<String>,
        /// Secrets the agent may read (repeatable, required)
        #[arg(long, required = true)]
        only: Vec<String>,
        /// Set the agent allow-list to these tags before granting (repeatable)
        #[arg(long = "allow-tag", value_parser = NewText::LINE)]
        allow_tag: Vec<String>,
        /// Also enable the `murk_exec` tool in the MCP server (writes `--allow-exec` into the client config)
        #[arg(long)]
        allow_exec: bool,
        /// Grant time to live, e.g. 30m, 2h or 7d, up to 365d. Reads fail closed after expiry
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// Grant name (used to disconnect/revoke it later)
        #[arg(long, default_value = "mcp")]
        name: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove murk's entry from an AI editor's MCP config (experimental)
    ///
    /// With no CLIENT, murk clears every configured editor. The grant stays
    /// live unless you pass `--rotate`, which also revokes the grant named by
    /// `--name` and rotates the secrets it could read.
    Disconnect {
        /// Editor to disconnect. Omit for every configured editor
        client: Option<String>,
        /// Revoke the grant and rotate the secrets it could read
        #[arg(long)]
        rotate: bool,
        /// Grant name to revoke with --rotate
        #[arg(long, default_value = "mcp")]
        name: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}

#[derive(Subcommand)]
pub enum CircleCommand {
    /// Add a recipient to the vault
    Authorize {
        /// Public key (age1...), ssh:path, ssh: (default ~/.ssh/id_ed25519.pub), or github:username (experimental)
        pubkey: String,
        /// Display name for this recipient
        #[arg(long, value_parser = NewText::LINE)]
        name: Option<String>,
        /// Also add the new recipient to this group (experimental)
        #[arg(long)]
        group: Option<String>,
        /// Accept changed GitHub keys. Without it, authorize stops when a user's keys differ from the pinned set
        #[arg(long)]
        force: bool,
        /// Allow ssh-rsa keys. They are refused or skipped by default, so prefer ed25519
        #[arg(long)]
        allow_ssh_rsa: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a recipient from the vault
    Revoke {
        /// Recipient pubkey, display name, or github:username
        recipient: String,
        /// Rotate the secrets they had access to in the same session
        #[arg(long)]
        rotate: bool,
        /// With --rotate, read new values from a dotenv file of KEY=value lines (`-` for stdin)
        #[arg(long, value_name = "FILE", requires = "rotate")]
        values_from: Option<String>,
        /// Revoke every key of a multi-key GitHub user without confirmation
        #[arg(long)]
        force: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// Create a new recipient group (you become its first member)
    Create {
        /// Group name
        name: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// List groups and their members
    Ls {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Add a member to a group
    Add {
        /// Group name
        name: String,
        /// Recipient pubkey or display name to add
        #[arg(long)]
        member: String,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove a member from a group, or delete the group entirely
    Rm {
        /// Group name
        name: String,
        /// Recipient pubkey or display name to remove (omit to delete the group)
        #[arg(long)]
        member: Option<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Show the agent access policy (works without a key)
    Show {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Set the agent allow-list: agents may only receive secrets carrying one of these tags
    Set {
        /// Tag agents are allowed to receive (repeatable, required)
        #[arg(long = "allow-tag", required = true, value_parser = NewText::LINE)]
        allow_tag: Vec<String>,
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },

    /// Remove the policy. Agent mode becomes unrestricted again
    Clear {
        /// Vault filename
        #[arg(long, env = "MURK_VAULT", default_value = ".murk")]
        vault: String,
    },
}
