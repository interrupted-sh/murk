// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk trust`: the explicit step that records a vault as trusted on this
//! machine after showing who signed it and what changed.

use super::*;
use colored::Colorize;
use murk_cli::trust::{Refusal, Verdict};
use murk_cli::types;
use std::io::IsTerminal;

pub(crate) fn cmd_trust(yes: bool, re_add: &[String], shares_with: Option<&str>, vault_path: &str) {
    // Hold the vault lock: accepting an unsigned vault re-signs it. Lock
    // order: this vault lock first, then the trust pin lock, which each pin
    // update below and the re-signing save take and release in turn (see
    // `murk_cli::pins::LOCK_ORDER`).
    let _lock = try_or_die(
        murk_cli::vault::lock(std::path::Path::new(vault_path)).map_err(murk_cli::MurkError::Vault),
    );
    let mut inspected = try_or_die(murk_cli::inspect_vault(vault_path));
    let pubkey = inspected
        .identity
        .pubkey_string()
        .unwrap_or_else(|e| die(&e, 1));
    let me = murk_cli::canonical_recipient(&pubkey).into_owned();
    let pinned_grant = inspected
        .assessment
        .pin
        .as_ref()
        .is_some_and(|p| p.grants.contains(&me));
    if pinned_grant
        || inspected
            .murk
            .grants
            .values()
            .any(|g| murk_cli::canonical_recipient(&g.pubkey).into_owned() == me)
    {
        die(
            &"an agent grant key cannot trust a vault\nask the operator to re-mint the grant",
            1,
        );
    }

    // Keys this machine recorded as removed that the vault lists or is signed
    // by: trusted again only when named with --re-add.
    let removed = murk_cli::trust::removed_keys_in(
        &inspected.loaded(),
        inspected.assessment.pin.as_ref(),
        &murk_cli::trust::Checkout::of(vault_path, inspected.assessment.pin.as_ref()),
    );
    let readmit = readmitted_keys(re_add, &removed, &inspected.murk.recipients);
    let other = shares_with.map(|q| other_file_of_vault(vault_path, q, &inspected.vault));
    if !readmit.is_empty() || other.is_some() {
        try_or_die(inspected.judge_for_trust(
            vault_path,
            &readmit,
            other.as_ref().map(|o| o.path.as_str()),
        ));
    }

    print_summary(vault_path, &inspected);
    if let Some(other) = &other {
        print_other_file(vault_path, &inspected.vault, other);
    }
    if let Verdict::Refused(Refusal::SharedVaultId { .. }) = &inspected.assessment.verdict {
        let reason = inspected.refusal_message(vault_path).unwrap_or_default();
        die(&reason, 1);
    }

    decide(
        yes,
        vault_path,
        inspected,
        &removed,
        &readmit,
        other.is_some(),
    );
    if let Some(other) = other {
        retire_other_path(vault_path, &other);
    }
}

/// The rest of `murk trust` once the vault is judged: accept it or refuse
/// it. `sharing` says the user named another path of the vault with
/// `--shares-identity-with`, which `murk trust` retires after this returns.
fn decide(
    yes: bool,
    vault_path: &str,
    inspected: murk_cli::InspectedVault,
    removed: &std::collections::BTreeMap<String, u64>,
    readmit: &std::collections::BTreeSet<String>,
    sharing: bool,
) {
    let head = murk_cli::trust::head_of(vault_path);
    let read_only = murk_cli::trust::pre_upgrade_read_only(
        inspected.assessment.pin.as_ref(),
        &head,
        &inspected.vault,
    );
    let refusal = match &inspected.assessment.verdict {
        Verdict::Trusted if readmit.is_empty() && read_only => {
            // A murk 0.13 copy that loads as history here is read-only until
            // the user accepts it; then the next write upgrades it.
            if head == murk_cli::trust::HeadState::Detached {
                die(
                    &format_args!(
                        "{vault_path} is in the pre-0.14 format and HEAD is detached, so there is no branch to accept it on\ncheck out a branch, then run `murk trust --vault {vault_path}`"
                    ),
                    1,
                );
            }
            eprintln!(
                "{} {vault_path} is in the pre-0.14 format on a branch that hasn't taken the upgrade: it loads, but is read-only until you accept this copy",
                "⚠".yellow()
            );
            if !yes
                && !confirmed("accept this copy on this machine, so the next write upgrades it?")
            {
                die(&"not trusted", 1);
            }
            try_or_die(inspected.record_pre_upgrade_copy(vault_path));
            eprintln!(
                "{} accepted {vault_path} on this machine — the next write upgrades it to the 0.14 format; commit the result",
                "◆".magenta()
            );
            return;
        }
        Verdict::Trusted | Verdict::UnsignedAllowed if readmit.is_empty() && sharing => {
            // Trusted here already: only the other path is retired.
            if !yes
                && !confirmed(
                    "trust this vault at this path only, and refuse the other path on this machine?",
                )
            {
                die(&"not trusted", 1);
            }
            return;
        }
        Verdict::Trusted if readmit.is_empty() => {
            eprintln!(
                "{} {vault_path} is already trusted on this machine",
                "ok".green().bold()
            );
            return;
        }
        Verdict::Trusted => None,
        Verdict::UnsignedAllowed => {
            eprintln!(
                "{} {vault_path} is unsigned and your key cannot sign it — nothing to record; rely on signed git commits",
                "warn".yellow().bold()
            );
            return;
        }
        Verdict::Refused(r) => Some(r.clone()),
    };
    if refusal.is_some()
        && let Some((key, at)) = removed.iter().find(|(k, _)| !readmit.contains(*k))
    {
        die(
            &format_args!(
                "{} was removed from this vault at generation {at} on this machine, and this vault lists them or is signed by them\nrefusing to trust it; to trust them again on purpose, review it and run `murk trust --vault {vault_path} --re-add {key}`",
                murk_cli::trust::label(&inspected.murk.recipients, key)
            ),
            1,
        );
    }
    let Some(refusal) = refusal else {
        // Trusted once the named keys are re-added: record that decision.
        if !yes && !confirmed("trust this vault and re-add the named keys on this machine?") {
            die(&"not trusted", 1);
        }
        try_or_die(inspected.record_trust(vault_path, false, readmit));
        eprintln!("{} trusted {vault_path} on this machine", "◆".magenta());
        return;
    };
    let reason = inspected.refusal_message(vault_path).unwrap_or_default();
    eprintln!(
        "{} {}",
        "⚠".yellow(),
        reason.lines().next().unwrap_or_default()
    );
    if !refusal.acceptable() {
        die(
            &format_args!("refusing to trust it\nrestore {vault_path} from git"),
            1,
        );
    }
    // Another vault's unsigned murk 0.13 file: nothing signed shows whose it
    // is, and accepting it would record its recipients (or re-sign it) under
    // this vault's id. Never.
    if matches!(refusal, Refusal::OtherVault { .. })
        && murk_cli::trust::written_by_0_13(&inspected.vault)
        && matches!(inspected.murk.signature, types::SignatureState::Unsigned)
    {
        die(
            &format_args!(
                "refusing to trust it: an unsigned pre-0.14 file of another vault can't be accepted as this one\nrestore {vault_path} from git"
            ),
            1,
        );
    }

    // A murk 0.13 (v1) revision accepted where this machine saw the vault in
    // 0.14 form can only be pinned by moving it to v2: re-sign it.
    let needs_signature = matches!(
        refusal,
        Refusal::Unsigned | Refusal::Downgraded | Refusal::PreUpgrade { .. }
    );
    let resign = needs_signature && inspected.identity.is_signing_capable();
    if needs_signature && !resign && !matches!(refusal, Refusal::Downgraded) {
        die(
            &"this vault must be re-signed to be trusted, and your key cannot sign\nask a teammate with an age or ssh-ed25519 key to review it and run `murk trust`",
            1,
        );
    }
    // A key that cannot sign accepting a stripped vault: judge it as if no
    // signed version had been seen, so the user sees and accepts everything
    // else it changes (a rollback, another vault id, a recipient, grant or
    // group this machine has not accepted) in this one step.
    let beneath = (matches!(refusal, Refusal::Downgraded) && !resign).then(|| {
        let pin = inspected.assessment.pin.clone().map(|mut p| {
            p.was_signed = false;
            p.removed.retain(|k, _| !readmit.contains(k));
            p
        });
        let loaded = inspected.loaded();
        match murk_cli::trust::reassess(vault_path, &loaded, &inspected.assessment, pin.as_ref()) {
            Verdict::Refused(r) => {
                let msg = murk_cli::trust::refusal_message(vault_path, &r, &loaded, pin.as_ref());
                eprintln!(
                    "{} {}",
                    "⚠".yellow(),
                    msg.lines().next().unwrap_or_default()
                );
                if !r.acceptable() {
                    die(
                        &format_args!("refusing to trust it\nrestore {vault_path} from git"),
                        1,
                    );
                }
                Some(r)
            }
            Verdict::Trusted | Verdict::UnsignedAllowed => None,
        }
    });
    let question = if resign {
        "sign this vault with your key and trust it?"
    } else {
        "trust this vault on this machine?"
    };
    if !yes && !confirmed(question) {
        die(&"not trusted", 1);
    }

    if resign {
        if !readmit.is_empty() {
            // The re-signed vault lists the named keys: they are re-added on
            // purpose, so take them out of the removed set before the save.
            try_or_die(murk_cli::pins::update(vault_path, |fresh| {
                let mut pin = fresh.cloned().unwrap_or_default();
                pin.removed.retain(|k, _| !readmit.contains(k));
                Ok(Some(pin))
            }));
        }
        if read_only {
            // A murk 0.13 file that is read-only here (refused as pre-0.14,
            // unsigned or stripped): record this copy as accepted first, so
            // the re-signing save below is allowed. Only the copy is
            // recorded; the save itself changes the trusted set only by what
            // it adds or removes.
            try_or_die(inspected.record_pre_upgrade_copy(vault_path));
        }
        // Re-sign exactly the current content: save with no changes.
        let murk_cli::InspectedVault {
            mut vault, murk, ..
        } = inspected;
        save_vault(vault_path, &mut vault, &murk, &murk);
        eprintln!(
            "{} signed {vault_path} and trusted it — commit the result so teammates get the signed version",
            "◆".magenta()
        );
        return;
    }
    let reset_counter = matches!(
        beneath
            .as_ref()
            .and_then(Option::as_ref)
            .unwrap_or(&refusal),
        Refusal::RolledBack { .. } | Refusal::OtherVault { .. } | Refusal::Forked { .. }
    );
    if beneath.is_some() {
        // Record the vault as an accepted decision (recipients, groups,
        // grants and marks), then forget that a signed version was seen, so
        // this machine loads it with a warning and still refuses an unsigned
        // file that widens it further.
        let loaded = inspected.loaded();
        try_or_die(murk_cli::pins::update(vault_path, |fresh| {
            let mut pin = murk_cli::trust::accepted_pin(
                &loaded,
                fresh,
                murk_cli::trust::Acceptance::Trust {
                    reset_counter,
                    readmit,
                },
                &head,
                murk_cli::trust::accepted_commit_of(vault_path).as_deref(),
            );
            pin.was_signed = false;
            Ok(Some(pin))
        }));
    } else {
        try_or_die(inspected.record_trust(vault_path, reset_counter, readmit));
    }
    eprintln!("{} trusted {vault_path} on this machine", "◆".magenta());
}

/// Ask `question` on a terminal; without one, stop and point at `--yes`.
fn confirmed(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        die(
            &"murk trust needs confirmation\nreview the output above, then rerun with --yes",
            1,
        );
    }
    confirm(question)
}

/// The other path of the vault that `murk trust --shares-identity-with`
/// names: the path as given, its `/`-separated path in the checkout, and the
/// vault file there.
struct OtherFile {
    arg: String,
    path: String,
    vault: types::Vault,
}

/// Check that `arg` is another vault file in the same checkout as
/// `vault_path`, with the vault id of `vault`. Stops with a message
/// otherwise.
fn other_file_of_vault(vault_path: &str, arg: &str, vault: &types::Vault) -> OtherFile {
    let here = murk_cli::pins::vault_location(vault_path);
    let there = murk_cli::pins::vault_location(arg);
    let (Some((repo, path)), Some((other_repo, other_path))) = (here, there) else {
        die(
            &format_args!(
                "--shares-identity-with needs {vault_path} and {arg} in one git checkout"
            ),
            1,
        );
    };
    if repo != other_repo || path == other_path {
        die(
            &format_args!(
                "{arg} is not another path in the checkout of {vault_path}\nname the other vault file with the same vault id"
            ),
            1,
        );
    }
    let other = murk_cli::vault::read(std::path::Path::new(arg))
        .unwrap_or_else(|e| die(&format_args!("cannot read {arg}: {e}"), 1));
    if murk_cli::trust::header_vault_id(&other) != murk_cli::trust::header_vault_id(vault) {
        die(
            &format_args!(
                "{arg} does not have the vault id of {vault_path}, so it is not another path of this vault\nnothing was recorded"
            ),
            1,
        );
    }
    OtherFile {
        arg: arg.to_string(),
        path: other_path,
        vault: other,
    }
}

/// Show the other file's header next to the summary of the vault being
/// trusted, so the user can compare the two before this machine refuses
/// one of them.
fn print_other_file(vault_path: &str, vault: &types::Vault, other: &OtherFile) {
    let revision = |v: &types::Vault| {
        let fp = murk_cli::trust::vault_fingerprint(v);
        if fp.is_empty() {
            "(none)".to_string()
        } else {
            fp
        }
    };
    eprintln!("  revision    {}", revision(vault));
    eprintln!(
        "{} {} (refused on this machine after this step)",
        "other file".bold(),
        other.arg
    );
    eprintln!(
        "  id          {}",
        murk_cli::trust::header_vault_id(&other.vault)
    );
    eprintln!("  generation  {}", other.vault.generation);
    match &other.vault.sig {
        Some(sig) => eprintln!("  signed by   {} (not checked)", sig.signer.dimmed()),
        None => eprintln!("  signed by   (unsigned)"),
    }
    eprintln!("  revision    {}", revision(&other.vault));
    eprintln!(
        "{} after this step, this machine trusts the vault at {vault_path} only",
        "⚠".yellow()
    );
}

/// Record `other` as another path of the vault at `vault_path` in its pin,
/// so murk refuses `other` on this machine, and remove the pin and sidecar of
/// `other` when they record the same vault id.
fn retire_other_path(vault_path: &str, other: &OtherFile) {
    try_or_die(murk_cli::pins::update(vault_path, |fresh| {
        let mut pin = fresh
            .cloned()
            .ok_or_else(|| format!("no trust pin for {vault_path}"))?;
        pin.sidecar.identity_siblings.insert(other.path.clone());
        Ok(Some(pin))
    }));
    let id = murk_cli::trust::header_vault_id(&other.vault);
    let pinned_there =
        try_or_die(murk_cli::pins::read(&other.arg)).is_some_and(|p| p.vault_id == id);
    if pinned_there && let Some(file) = murk_cli::pins::existing_pin_path(&other.arg) {
        try_or_die(murk_cli::pins::remove(&file));
    }
    eprintln!(
        "{} this machine trusts the vault at {vault_path} only, and refuses {} from now on",
        "◆".magenta(),
        other.arg
    );
}

/// The removed keys `re_add` names — each a public key or a recipient's name
/// in the vault — in canonical form. A name that is not a removed key this
/// vault lists is an error, so a typo never passes silently.
fn readmitted_keys(
    re_add: &[String],
    removed: &std::collections::BTreeMap<String, u64>,
    names: &std::collections::HashMap<String, String>,
) -> std::collections::BTreeSet<String> {
    re_add
        .iter()
        .map(|arg| {
            let canonical = murk_cli::canonical_recipient(arg).into_owned();
            if removed.contains_key(&canonical) {
                return canonical;
            }
            names
                .iter()
                .filter(|(_, name)| *name == arg)
                .map(|(pk, _)| murk_cli::canonical_recipient(pk).into_owned())
                .find(|pk| removed.contains_key(pk))
                .unwrap_or_else(|| {
                    die(
                        &format_args!(
                            "{} is not a key this machine recorded as removed that this vault lists",
                            murk_cli::terminal_text(arg, false)
                        ),
                        1,
                    )
                })
        })
        .collect()
}

/// `murk trust --print-key`: this machine's own trusted-signer entry and
/// signing-key fingerprint. Teammates compare the fingerprint with what their
/// `murk trust` shows for your first write; CI sets the entry in
/// `MURK_TRUSTED_SIGNERS`. Both are public.
pub(crate) fn cmd_trust_print_key(vault_path: &str) {
    use age::secrecy::ExposeSecret;
    let secret = try_or_die(murk_cli::resolve_key_for_vault(vault_path));
    let identity = try_or_die(murk_cli::crypto::parse_identity(secret.expose_secret()));
    let pubkey = identity.pubkey_string().unwrap_or_else(|e| die(&e, 1));
    let Some(sk) = identity.signing_key() else {
        die(
            &"this key cannot sign (ssh-rsa or hardware), so it has no signing key",
            1,
        );
    };
    let vk = sk.verifying_key();
    let registered = identity.registers_verifying_key();
    println!(
        "{}",
        murk_cli::trust::format_trusted_signer(&pubkey, registered.then_some(vk.as_str()))
    );
    eprintln!(
        "signing key {}",
        murk_cli::signing::fingerprint(&vk).unwrap_or_default()
    );
}

/// Show what the user is being asked to trust: the vault's identity and
/// counter, the signer's full key (its name is chosen by whoever wrote the
/// file), and every recipient with its change since this machine last trusted
/// the vault.
fn print_summary(vault_path: &str, inspected: &murk_cli::InspectedVault) {
    let vault = &inspected.vault;
    let murk = &inspected.murk;
    let pin = inspected.assessment.pin.as_ref().filter(|p| p.has_trust());

    eprintln!("{} {}", "vault".bold(), vault_path);
    eprintln!(
        "  id          {}",
        if vault.vault_id.is_empty() {
            "(none — written by murk 0.13 or older)"
        } else {
            &vault.vault_id
        }
    );
    let seen = pin.map_or_else(
        || "never trusted here".to_string(),
        |p| format!("highest trusted here: {}", p.generation),
    );
    eprintln!("  generation  {} ({seen})", vault.generation);
    let signer_vk = inspected.loaded().signer_vk.map(str::to_string);
    match &murk.signature {
        types::SignatureState::Signed { signer, .. } => {
            let name = murk_cli::trust::label(&murk.recipients, signer);
            eprintln!("  signed by   {name}");
            eprintln!("              {}", signer.dimmed());
            if let Some(vk) = &signer_vk {
                let pinned = pin.and_then(|p| {
                    p.signers
                        .get(&murk_cli::canonical_recipient(signer).into_owned())
                });
                let fp = murk_cli::signing::fingerprint(vk).unwrap_or_default();
                eprintln!("  signing key {fp}");
                if pinned.is_none() && inspected.assessment.env_signers.is_none() {
                    eprintln!(
                        "              {}",
                        "not confirmed on this machine — trust on first use: check this fingerprint with them (`murk trust --print-key` on their machine)"
                            .yellow()
                    );
                }
            }
            if inspected.assessment.env_signers.is_none()
                && pin.is_some_and(|p| {
                    !p.trusted
                        .contains(&murk_cli::canonical_recipient(signer).into_owned())
                })
            {
                eprintln!(
                    "              {}",
                    "not a trusted signer on this machine — the name above is chosen by whoever wrote the file"
                        .yellow()
                );
            }
        }
        types::SignatureState::Unsigned => {
            eprintln!("  signed by   {}", "nobody (unsigned)".yellow())
        }
    }

    let grants: std::collections::BTreeSet<String> = murk
        .grants
        .values()
        .map(|g| murk_cli::canonical_recipient(&g.pubkey).into_owned())
        .collect();
    eprintln!("{}", "recipients".bold());
    let mut shown = std::collections::BTreeSet::new();
    for r in &vault.recipients {
        let canon = murk_cli::canonical_recipient(r).into_owned();
        shown.insert(canon.clone());
        let label = murk_cli::trust::label(&murk.recipients, r);
        // The signing key each recipient's writes will be checked against —
        // pinned here, or the one this vault's registry claims.
        let fp = pin
            .and_then(|p| p.signers.get(&canon))
            .or_else(|| {
                murk.signers
                    .iter()
                    .find(|(pk, _)| murk_cli::canonical_recipient(pk).into_owned() == canon)
                    .map(|(_, vk)| vk)
            })
            .and_then(|vk| murk_cli::signing::fingerprint(vk))
            .map(|fp| format!("  signing key {fp}").dimmed().to_string())
            .unwrap_or_default();
        if grants.contains(&canon) {
            eprintln!("    {label} (agent grant, never a signer)");
        } else if pin.is_some_and(|p| !p.trusted.contains(&canon)) {
            eprintln!("  {} {label}{fp}", "+".magenta().bold());
        } else {
            eprintln!("    {label}{fp}");
        }
    }
    if let Some(p) = pin {
        // An older 0.13 copy of this vault that is read-only here is accepted
        // without narrowing trust: members it doesn't list stay trusted. A
        // file of another vault (its derived id differs), whatever else it
        // is refused for, replaces the trust state instead.
        let older_copy = murk_cli::trust::pre_upgrade_read_only(
            inspected.assessment.pin.as_ref(),
            &murk_cli::trust::head_of(vault_path),
            vault,
        ) && murk_cli::trust::pre_upgrade_is_this_vault(
            inspected.assessment.pin.as_ref(),
            vault,
        );
        for gone in p.trusted.difference(&shown) {
            if older_copy {
                eprintln!(
                    "    {} {}",
                    murk_cli::truncate_pubkey(gone),
                    "(not in this copy; stays trusted)".dimmed()
                );
            } else {
                eprintln!("  {} {}", "-".red().bold(), murk_cli::truncate_pubkey(gone));
            }
        }
    }
}
