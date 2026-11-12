// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use age::secrecy::{ExposeSecret, SecretString};
use colored::Colorize;
use murk_cli::{KeySource, recovery, vault};
use std::path::Path;
use std::process;

/// Store `secret_key` as this machine's key for `vault_name`, in
/// `~/.config/murk/keys/<hash>`: a `0600` file, created exclusively, so a key
/// that another init stored since the caller looked is never replaced. Under
/// MURK_STRICT or MURK_AGENT no message names the key store.
fn store_key(vault_name: &str, secret_key: &str) -> std::path::PathBuf {
    let key_path = try_or_die(murk_cli::key_file_path(vault_name));
    let strict = murk_cli::hardening::strict_mode();
    let shown = key_path.display().to_string();
    let redact = |msg: String| {
        if strict {
            msg.replace(&shown, "the key file")
        } else {
            msg
        }
    };
    let staged = match murk_cli::stage_key_file(&key_path, secret_key, false) {
        Ok(staged) => staged,
        Err(e) => die(&redact(e), 1),
    };
    if let Err(e) = staged.commit() {
        // `die` exits without running destructors: drop the staged key first.
        let (already_exists, reason) = (e.already_exists, e.reason.clone());
        drop(e);
        let msg = if already_exists {
            [
                format!("a key is already stored at {shown}"),
                "murk init never replaces a stored key".into(),
                "run murk init again to use it".into(),
            ]
            .join("\n")
        } else {
            reason
        };
        die(&redact(msg), 1);
    }
    if strict {
        eprintln!("{} key saved", "◆".magenta());
    } else {
        eprintln!("{} key saved to {}", "◆".magenta(), shown.dimmed());
    }
    key_path
}

/// Generate a BIP39 keypair and store the key for `vault_name` (see
/// [`store_key`]). With `point_dotenv`, `.env` then references it. Returns
/// the secret key, wrapped in `Zeroizing` so the plaintext clears when the
/// caller drops it.
///
/// Callers check for a stored key first, so the key file this writes never
/// already exists: generation never replaces a stored identity.
fn generate_and_write_key(vault_name: &str, point_dotenv: bool) -> zeroize::Zeroizing<String> {
    // A key line in .env here names a key murk could not find in the
    // environment or ~/.config/murk/keys: an inline MURK_KEY, or a MURK_KEY_FILE
    // somewhere else. Replacing the line drops that reference, so ask first.
    if point_dotenv
        && murk_cli::dotenv_has_murk_key()
        && !confirm(
            ".env already has a MURK_KEY or MURK_KEY_FILE line, but murk found no stored key for this vault.\n\
             Generate a new key and replace that line? An inline MURK_KEY value in .env is lost; copy it out first if you need it.",
        )
    {
        eprintln!("Aborted.");
        process::exit(1);
    }

    eprintln!("{} generating keypair...", "◆".magenta());
    let (phrase, secret_key, _pubkey) = try_or_die(recovery::generate());
    let key_path = store_key(vault_name, &secret_key);

    // Print recovery phrase.
    eprintln!();
    eprintln!(
        "{} {}",
        "⚠".yellow(),
        "RECOVERY WORDS — WRITE THESE DOWN AND STORE SAFELY:"
            .yellow()
            .bold()
    );
    eprintln!("  {}", phrase.as_str().bold());
    eprintln!();

    if point_dotenv {
        // Reference the key in .env only after the phrase is shown: if this
        // write fails, a retry reuses the stored key and would print no phrase.
        try_or_die(murk_cli::write_key_ref_to_dotenv(&key_path));
        eprintln!(
            "  {}",
            ".env holds only the path to your key file; keep both out of git".dimmed()
        );
    }

    secret_key
}

/// Report a reused key and, for a key file, point `.env` at it when `.env` has
/// no key line yet. An existing key line is left alone: it is the user's
/// choice. Inline `MURK_KEY` is never written to `.env`, and neither is a
/// strict-mode `MURK_KEY_FILE`: that is an agent or CI key, not the operator's
/// identity.
fn reuse_key(source: &KeySource) {
    let key_path = match source {
        KeySource::EnvVar => {
            eprintln!("{} using existing key from MURK_KEY", "◆".magenta());
            return;
        }
        KeySource::EnvFile(path) | KeySource::Auto(path) => path,
    };
    eprintln!(
        "{} using existing key {}",
        "◆".magenta(),
        key_path.display().to_string().dimmed()
    );
    let strict_env_key =
        matches!(source, KeySource::EnvFile(_)) && murk_cli::hardening::strict_mode();
    if !strict_env_key && !murk_cli::dotenv_has_murk_key() {
        try_or_die(murk_cli::write_key_ref_to_dotenv(key_path));
        eprintln!("{} added MURK_KEY_FILE reference to .env", "◆".magenta());
    }
}

/// What `murk init` does when the vault has no key of its own on this
/// machine but another vault in the same directory has one (`.murk.prod`
/// next to `.murk`): the `--reuse-key` / `--separate-key` flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyChoice {
    /// No flag: ask on a terminal, refuse anywhere else.
    Ask,
    /// `--reuse-key`: store the other vault's key for this one too.
    Reuse,
    /// `--separate-key`: make a new key for this vault.
    Separate,
}

impl KeyChoice {
    /// clap makes the two flags conflict, so at most one is set.
    pub(crate) fn from_flags(reuse: bool, separate: bool) -> Self {
        match (reuse, separate) {
            (true, _) => Self::Reuse,
            (false, true) => Self::Separate,
            (false, false) => Self::Ask,
        }
    }
}

/// The decision for a vault whose neighbours have stored keys.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Prompt,
    Reuse,
    Separate,
    Refuse(Refusal),
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// MURK_STRICT or MURK_AGENT: stored keys are never read, nothing is asked.
    Strict,
    /// No terminal to ask on, and no flag.
    NoTerminal,
    /// `--reuse-key`, but the neighbours use different keys.
    Ambiguous,
}

/// Decide without side effects. `offers` is the number of distinct keys
/// stored for neighbour vaults (at least one; strict mode reads none and
/// passes what it saw). Strict mode never prompts and never reuses a stored
/// key, even with `--reuse-key`: an agent must not be able to turn the
/// operator's key into the identity of a vault it creates. Without a
/// terminal nothing is asked and only a flag decides. `--reuse-key` never
/// guesses between different keys.
fn plan(choice: KeyChoice, strict: bool, terminal: bool, offers: usize) -> Plan {
    match choice {
        KeyChoice::Separate => Plan::Separate,
        _ if strict => Plan::Refuse(Refusal::Strict),
        KeyChoice::Reuse if offers == 1 => Plan::Reuse,
        KeyChoice::Reuse => Plan::Refuse(Refusal::Ambiguous),
        KeyChoice::Ask if terminal => Plan::Prompt,
        KeyChoice::Ask => Plan::Refuse(Refusal::NoTerminal),
    }
}

/// Where the key for `murk init` comes from, decided before anything is
/// written.
enum KeyPlan {
    /// A key the environment names, or the one stored for this vault.
    Existing(murk_cli::DiscoveredKey),
    /// No key anywhere: generate one and point `.env` at it, as always.
    Generate,
    /// Store another vault's key for this vault too; `.env` is left alone.
    Reuse(murk_cli::NeighbourKey),
    /// A new key for this vault only; `.env` is left alone.
    Separate,
}

/// Comma-separated vault names, made safe for the terminal.
fn vault_list(names: &[String]) -> String {
    names
        .iter()
        .map(|n| murk_cli::terminal_text(n, false).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Find the key `murk init` should use for `vault_name`, asking only when
/// another vault in this directory has a key stored and nothing says which.
///
/// In order: a key the environment names (`MURK_KEY`, `MURK_KEY_FILE`); the
/// key stored for this vault here or in a sibling worktree; the keys stored
/// for other vaults in this directory (see [`plan`]); otherwise a new key.
/// An environment key that *is* one of those neighbour keys (direnv loaded
/// the first vault's `.env`) does not decide for this vault: it narrows the
/// offer to that key, so the new vault still gets a stored key of its own
/// and works where the environment does not reach (a fresh worktree).
fn plan_key(vault_name: &str, choice: KeyChoice) -> KeyPlan {
    let strict = murk_cli::hardening::strict_mode();
    let env_key = try_or_die(murk_cli::discover_existing_key());

    if strict {
        // Unchanged strict behaviour: the environment's key, else refuse a
        // stored one (discover_stored_key errors), else a new key.
        if let Some(dk) = env_key {
            return KeyPlan::Existing(dk);
        }
        try_or_die(murk_cli::discover_stored_key(vault_name));
        let neighbours = murk_cli::neighbour_vaults_with_keys(vault_name);
        if neighbours.is_empty() {
            return no_neighbour_key(vault_name, choice);
        }
        return match plan(choice, true, false, neighbours.len()) {
            Plan::Separate => KeyPlan::Separate,
            _ => refuse(vault_name, Refusal::Strict, &neighbours),
        };
    }

    if murk_cli::has_stored_key(vault_name) {
        return KeyPlan::Existing(match env_key {
            Some(dk) => dk,
            None => try_or_die(murk_cli::discover_stored_key(vault_name))
                .unwrap_or_else(|| die(&"the stored key for this vault disappeared", 1)),
        });
    }

    let (mut offers, skipped) = try_or_die(murk_cli::discover_neighbour_keys(vault_name));
    for (name, reason) in &skipped {
        eprintln!(
            "{} skipped the stored key of {}: {}",
            "warn".yellow().bold(),
            vault_list(std::slice::from_ref(name)),
            reason
        );
    }
    if let Some(dk) = env_key {
        match offers.iter().position(|o| o.key.pubkey == dk.pubkey) {
            None => return KeyPlan::Existing(dk),
            Some(i) => offers = vec![offers.swap_remove(i)],
        }
    }
    if offers.is_empty() {
        return no_neighbour_key(vault_name, choice);
    }
    // The default vault's key first: it is the one a team usually shares.
    offers.sort_by_key(|o| !o.vaults.iter().any(|v| v == ".murk"));

    let terminal = std::io::stdin().is_terminal();
    match plan(choice, false, terminal, offers.len()) {
        Plan::Reuse => KeyPlan::Reuse(offers.swap_remove(0)),
        Plan::Separate => KeyPlan::Separate,
        Plan::Prompt => prompt_key_choice(vault_name, offers),
        Plan::Refuse(why) => {
            let names: Vec<String> = offers.into_iter().flat_map(|o| o.vaults).collect();
            refuse(vault_name, why, &names)
        }
    }
}

/// No other vault here has a stored key: generate one as before. A
/// `--reuse-key` that has nothing to reuse is an error, not a new identity.
fn no_neighbour_key(vault_name: &str, choice: KeyChoice) -> KeyPlan {
    if choice == KeyChoice::Reuse {
        die(
            &format!(
                "--reuse-key: no other vault next to {} has a key stored on this machine",
                vault_list(&[vault_name.to_string()])
            ),
            1,
        );
    }
    KeyPlan::Generate
}

fn refuse(vault_name: &str, why: Refusal, neighbours: &[String]) -> ! {
    let vault = vault_list(&[vault_name.to_string()]);
    let others = vault_list(neighbours);
    let lines = match why {
        Refusal::Strict => vec![
            format!("another vault in this directory ({others}) has a key stored on this machine"),
            "strict mode (MURK_STRICT or MURK_AGENT) neither uses stored keys nor asks".into(),
            format!("run murk init --vault {vault} in your own terminal"),
            "or pass --separate-key to make a new key for it".into(),
        ],
        Refusal::NoTerminal => vec![
            format!("another vault in this directory ({others}) has a key stored on this machine"),
            format!("rerun with --reuse-key to use that key for {vault} too"),
            format!("or with --separate-key to make a new key for {vault}"),
        ],
        Refusal::Ambiguous => vec![
            format!("vaults in this directory use different keys ({others})"),
            "--reuse-key cannot choose between them".into(),
            "run murk init in a terminal to choose".into(),
            "or set MURK_KEY_FILE to the key to reuse and run it again".into(),
        ],
    };
    die(&lines.join("\n"), 1)
}

/// Ask once on the terminal: reuse one of the stored keys (the first is the
/// default) or make a separate key.
fn prompt_key_choice(vault_name: &str, mut offers: Vec<murk_cli::NeighbourKey>) -> KeyPlan {
    let vault = vault_list(&[vault_name.to_string()]);
    eprintln!("another vault in this directory has a key stored on this machine");
    for (i, offer) in offers.iter().enumerate() {
        let default = if i == 0 { " (default)" } else { "" };
        eprintln!(
            "  {}) use the key of {} for {vault} too{default}",
            i + 1,
            vault_list(&offer.vaults)
        );
    }
    let separate = offers.len() + 1;
    eprintln!("  {separate}) make a separate key for {vault}");
    eprint!("choose [1]: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line).unwrap_or(0);
    let answer = line.trim();
    let picked = match answer {
        "" if read > 0 => 1,
        _ => answer.parse::<usize>().unwrap_or(0),
    };
    match picked {
        n if n == separate => KeyPlan::Separate,
        n if (1..separate).contains(&n) => KeyPlan::Reuse(offers.swap_remove(n - 1)),
        _ => {
            eprintln!("Aborted.");
            process::exit(1);
        }
    }
}

/// Carry out `plan` and return the key. Run after the vault name is checked,
/// so nothing is stored for a name init then refuses.
fn apply_key_plan(vault_name: &str, plan: KeyPlan) -> SecretString {
    let vault = vault_list(&[vault_name.to_string()]);
    let found_by = format!(
        "commands find it with --vault {vault} or MURK_VAULT={vault}, also in git worktrees of this checkout"
    );
    match plan {
        KeyPlan::Existing(dk) => {
            reuse_key(&dk.source);
            dk.secret_key
        }
        KeyPlan::Generate => SecretString::from(generate_and_write_key(vault_name, true).as_str()),
        KeyPlan::Reuse(offer) => {
            eprintln!(
                "{} using the key of {} for {vault} too",
                "◆".magenta(),
                vault_list(&offer.vaults)
            );
            store_key(vault_name, offer.key.secret_key.expose_secret());
            eprintln!("  {}", format!(".env is unchanged; {found_by}").dimmed());
            offer.key.secret_key
        }
        KeyPlan::Separate => {
            let key = generate_and_write_key(vault_name, false);
            // A MURK_KEY / MURK_KEY_FILE in the environment (direnv exports
            // the one .env names) wins over a stored key, so say so.
            eprintln!(
                "  {}",
                format!(
                    ".env is unchanged; {found_by}, when MURK_KEY and MURK_KEY_FILE are not set"
                )
                .dimmed()
            );
            SecretString::from(key.as_str())
        }
    }
}

pub(crate) fn cmd_init(vault_name: &str, choice: KeyChoice) {
    let vault_path = Path::new(vault_name);

    // If vault already exists, handle onboarding flow.
    if vault_path.exists() {
        let vault = try_or_die(vault::read(vault_path));

        eprintln!("{}", format!("{vault_name} already exists").dimmed());

        // Reuse a key the environment names, then one stored for this vault
        // (here or in a sibling worktree), then offer one stored for another
        // vault in this directory. Only a newcomer with none gets a new key.
        let plan = plan_key(vault_name, choice);
        let generates = matches!(plan, KeyPlan::Generate | KeyPlan::Separate);
        let secret_key = apply_key_plan(vault_name, plan);
        if generates {
            eprintln!();
        }

        let status = try_or_die(murk_cli::check_init_status(
            &vault,
            secret_key.expose_secret(),
        ));
        if status.authorized {
            let name_display = match &status.display_name {
                Some(name) if !name.is_empty() => {
                    format!("  {}", murk_cli::terminal_text(name, false).bold())
                }
                _ => String::new(),
            };
            eprintln!(
                "{} authorized  {}{}",
                "◆".magenta(),
                status.pubkey.dimmed(),
                name_display
            );
            let trusted = murk_cli::pins::read(vault_name)
                .ok()
                .flatten()
                .is_some_and(|p| p.has_trust());
            if !trusted {
                eprintln!(
                    "  {}",
                    "next: review who signed the vault and run `murk trust` (once per machine)"
                        .dimmed()
                );
            }
        } else {
            eprintln!(
                "{} {}",
                "⚠".yellow(),
                "not authorized \u{2014} share your public key to get added:".yellow()
            );
            eprintln!("  {}", status.pubkey.bold());
            print_signing_fingerprint(secret_key.expose_secret());
        }
        return;
    }

    // --- New vault flow ---

    // Same lookup as above, so an explicit MURK_KEY / MURK_KEY_FILE becomes the
    // first recipient, and a key already stored for this vault path (here, say
    // after the vault file was deleted, or in a sibling worktree) is reused
    // rather than overwritten or shadowed. Decided before the name prompt,
    // carried out after the name checks.
    let plan = plan_key(vault_name, choice);

    // Prompt for display name.
    let name = prompt("Enter your name or email", None);
    if name.is_empty() {
        die(&"name is required", 1);
    }
    for (what, text) in [("name", name.as_str()), ("vault name", vault_name)] {
        if let Err(why) = murk_cli::new_text(text, false) {
            die(&format_args!("{what} {why}"), 1);
        }
    }

    let secret_key = apply_key_plan(vault_name, plan);
    let identity = try_or_die(murk_cli::crypto::parse_identity(secret_key.expose_secret()));

    let v = try_or_die(murk_cli::create_vault(vault_name, &identity, &name));
    // Create exclusively: a vault that appeared while init waited at the
    // prompt (a `git pull` in another terminal) must not be replaced.
    match vault::create(vault_path, &v) {
        Ok(()) => {}
        Err(vault::VaultError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => die(
            &format!(
                "{vault_name} appeared while murk init was running; it was left unchanged\n\
                 run murk init again to use it"
            ),
            1,
        ),
        Err(e) => die(&e, 1),
    }
    try_or_die(murk_cli::pin_created_vault(vault_name, &v, &identity));

    eprintln!();
    eprintln!(
        "{} vault initialized — added {} as recipient",
        "◆".magenta(),
        name.bold()
    );
    eprintln!("  {}", "run: murk add KEY".dimmed());
}

/// The fingerprint teammates' `murk trust` shows for this key's first signed
/// write, so the person who authorizes it can confirm it.
fn print_signing_fingerprint(secret_key: &str) {
    let Some(sk) = murk_cli::crypto::parse_identity(secret_key)
        .ok()
        .and_then(|id| id.signing_key())
    else {
        return;
    };
    if let Some(fp) = murk_cli::signing::fingerprint(&sk.verifying_key()) {
        eprintln!(
            "  {}",
            format!("signing key {fp} — teammates confirm this on your first write").dimmed()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyChoice, Plan, Refusal, plan};

    /// Strict mode never asks and never reuses; without a terminal only a
    /// flag decides; `--reuse-key` never guesses between different keys.
    #[test]
    fn plan_for_a_vault_whose_neighbours_have_stored_keys() {
        use KeyChoice::{Ask, Reuse, Separate};
        for terminal in [false, true] {
            for offers in [1, 2] {
                assert_eq!(plan(Separate, true, terminal, offers), Plan::Separate);
                assert_eq!(plan(Separate, false, terminal, offers), Plan::Separate);
                for choice in [Ask, Reuse] {
                    assert_eq!(
                        plan(choice, true, terminal, offers),
                        Plan::Refuse(Refusal::Strict),
                        "{choice:?} terminal={terminal} offers={offers}"
                    );
                }
                assert_eq!(
                    plan(Reuse, false, terminal, offers),
                    if offers == 1 {
                        Plan::Reuse
                    } else {
                        Plan::Refuse(Refusal::Ambiguous)
                    }
                );
                assert_eq!(
                    plan(Ask, false, terminal, offers),
                    if terminal {
                        Plan::Prompt
                    } else {
                        Plan::Refuse(Refusal::NoTerminal)
                    }
                );
            }
        }
    }
}
