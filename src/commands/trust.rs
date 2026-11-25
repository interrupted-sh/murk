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

    // Revoked agent grants the user names with --re-add: shown, confirmed and
    // re-admitted first, so the vault is judged below with them re-admitted.
    let grant_keys = revoked_grant_keys(re_add, &inspected);
    let re_add: Vec<String> = re_add
        .iter()
        .filter(|arg| {
            let key = resolve_key(arg, &inspected.murk.recipients, |k| grant_keys.contains(k));
            let removed = inspected
                .assessment
                .pin
                .as_ref()
                .is_some_and(|p| key.as_ref().is_some_and(|k| p.removed.contains_key(k)));
            key.is_none() || removed
        })
        .cloned()
        .collect();
    if !grant_keys.is_empty() {
        readmit_grants(yes, vault_path, &inspected, &grant_keys);
        inspected = try_or_die(murk_cli::inspect_vault(vault_path));
        if re_add.is_empty() && shares_with.is_none() {
            return;
        }
    }

    // Keys this machine recorded as removed that the vault lists or is signed
    // by: trusted again only when named with --re-add.
    let removed = murk_cli::trust::removed_keys_in(
        &inspected.loaded(),
        inspected.assessment.pin.as_ref(),
        &murk_cli::trust::Checkout::of(vault_path, inspected.assessment.pin.as_ref()),
    );
    let recorded = inspected
        .assessment
        .pin
        .as_ref()
        .map(|p| p.removed.clone())
        .unwrap_or_default();
    let (readmit, unlisted): (std::collections::BTreeSet<String>, _) =
        readmitted_keys(&re_add, &recorded, &inspected.murk.recipients)
            .into_iter()
            .partition(|k| removed.contains_key(k));
    if !unlisted.is_empty() {
        let listed: std::collections::BTreeSet<String> = inspected
            .vault
            .recipients
            .iter()
            .map(|k| murk_cli::canonical_recipient(k).into_owned())
            .collect();
        clear_removal_records(yes, vault_path, &unlisted, &listed);
        if readmit.is_empty() && shares_with.is_none() {
            // Consent given before the vault lists them: nothing else to do.
            return;
        }
    }
    let other = shares_with.map(|q| other_file_of_vault(vault_path, q, &inspected.vault));
    if !readmit.is_empty() || other.is_some() {
        try_or_die(inspected.judge_for_trust(
            vault_path,
            &readmit,
            other.as_ref().map(|o| o.path.as_str()),
        ));
    }

    // `decide` leaves a vault that already loads here as it is (with
    // `--shares-identity-with` it only retires the other path), so the
    // recipient changes the summary shows are not recorded: say so on each.
    let already_trusted = readmit.is_empty()
        && matches!(inspected.assessment.verdict, Verdict::Trusted)
        && !murk_cli::trust::pre_upgrade_read_only(
            inspected.assessment.pin.as_ref(),
            &murk_cli::trust::head_of(vault_path),
            &inspected.vault,
        );
    print_summary(vault_path, &inspected, already_trusted);
    // `murk trust` accepts the vault as current, so a revoked grant it holds
    // is refused here even where a load reads it as history.
    if let Some(refusal) = murk_cli::trust::tombstone_refusal(
        &inspected.loaded(),
        inspected.assessment.pin.as_ref(),
        true,
    ) {
        let loaded = inspected.loaded();
        let reason = murk_cli::trust::refusal_message(
            vault_path,
            &refusal,
            &loaded,
            inspected.assessment.pin.as_ref(),
        );
        die(&format_args!("refusing to trust it: {reason}"), 1);
    }
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
                "{} was removed from this vault at generation {at} on this machine, and this vault lists them or is signed by them\nrefusing to trust it; to trust them again on purpose, review it and run `murk trust --vault {vault_path} --re-add {key}` ({})",
                murk_cli::trust::label(&inspected.murk.recipients, key),
                murk_cli::trust::READD_SCOPE
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

/// The removed keys `re_add` names — each a public key, or the name of a
/// recipient the vault lists — in canonical form. Each must be a key this
/// machine recorded as removed (`recorded`); the vault need not list it. A
/// name that is not is an error, so a typo never passes silently.
fn readmitted_keys(
    re_add: &[String],
    recorded: &std::collections::BTreeMap<String, u64>,
    names: &std::collections::HashMap<String, String>,
) -> std::collections::BTreeSet<String> {
    re_add
        .iter()
        .map(|arg| {
            let canonical = murk_cli::canonical_recipient(arg).into_owned();
            if recorded.contains_key(&canonical) {
                return canonical;
            }
            names
                .iter()
                .filter(|(_, name)| *name == arg)
                .map(|(pk, _)| murk_cli::canonical_recipient(pk).into_owned())
                .find(|pk| recorded.contains_key(pk))
                .unwrap_or_else(|| {
                    die(
                        &format_args!(
                            "{} is not a key this machine recorded as removed or as a revoked agent grant",
                            murk_cli::terminal_text(arg, false)
                        ),
                        1,
                    )
                })
        })
        .collect()
}

/// The canonical key `arg` names: a public key for which `wanted` holds, or
/// the name of a recipient whose key it holds for.
fn resolve_key(
    arg: &str,
    names: &std::collections::HashMap<String, String>,
    wanted: impl Fn(&String) -> bool,
) -> Option<String> {
    let canonical = murk_cli::canonical_recipient(arg).into_owned();
    if wanted(&canonical) {
        return Some(canonical);
    }
    names
        .iter()
        .filter(|(_, name)| *name == arg)
        .map(|(pk, _)| murk_cli::canonical_recipient(pk).into_owned())
        .find(|pk| wanted(pk))
}

/// The keys `re_add` names that this machine holds as revoked agent grants:
/// a key with a revocation id it has not re-admitted (see
/// [`murk_cli::trust::tombstoned`]), or a key it recorded as a grant
/// (`pin.grants`) that is not a trusted signer.
fn revoked_grant_keys(
    re_add: &[String],
    inspected: &murk_cli::InspectedVault,
) -> std::collections::BTreeSet<String> {
    let pin = inspected.assessment.pin.as_ref();
    let tombstones = murk_cli::trust::tombstoned(&inspected.murk.revoked_grants, pin);
    let is_grant = |k: &String| {
        tombstones.contains_key(k)
            || pin.is_some_and(|p| p.grants.contains(k) && !p.trusted.contains(k))
    };
    re_add
        .iter()
        .filter_map(|arg| resolve_key(arg, &inspected.murk.recipients, is_grant))
        .collect()
}

/// `murk trust --re-add` for revoked agent grants `keys`. Shows each key,
/// the vault's signer and every revocation id this machine holds for the
/// key, with where it comes from. After confirmation, it re-admits exactly
/// those ids (a later revocation gets a new id, which still counts), takes
/// the key out of `pin.grants`, and forgets where this machine saw it live.
/// When the vault lists a key and its own set holds an id for it, the vault
/// is signed again without those ids; a key that cannot sign is refused.
/// When the vault does not list a key, the vault file is not written.
fn readmit_grants(
    yes: bool,
    vault_path: &str,
    inspected: &murk_cli::InspectedVault,
    keys: &std::collections::BTreeSet<String>,
) {
    let pin = inspected.assessment.pin.as_ref();
    let own = murk_cli::trust::tombstoned(&inspected.murk.revoked_grants, None);
    let held = murk_cli::trust::tombstoned(&own, pin);
    let signer = match &inspected.murk.signature {
        types::SignatureState::Signed { signer, .. } => {
            murk_cli::trust::label(&inspected.murk.recipients, signer)
        }
        types::SignatureState::Unsigned => "(unsigned)".to_string(),
    };
    let listed: std::collections::BTreeSet<String> = inspected
        .vault
        .recipients
        .iter()
        .map(|r| murk_cli::canonical_recipient(r).into_owned())
        .collect();
    for key in keys {
        eprintln!(
            "{} {} was an agent grant in {vault_path}, and this machine holds it as revoked",
            "⚠".yellow(),
            murk_cli::trust::label(&inspected.murk.recipients, key)
        );
        eprintln!("  key          {key}");
        eprintln!("  vault signer {signer}");
        let ids = held.get(key).cloned().unwrap_or_default();
        for id in &ids {
            let from = if own.get(key).is_some_and(|o| o.contains(id)) {
                "in the vault's revoked grant set"
            } else {
                "seen on this machine"
            };
            eprintln!(
                "  revocation   {} ({from})",
                murk_cli::trust::show_ids(std::iter::once(id))
            );
        }
        if ids.is_empty() {
            eprintln!("  this machine recorded it as an agent grant, and no revocation id");
        }
    }
    let resign: Vec<&String> = keys
        .iter()
        .filter(|k| listed.contains(*k) && own.contains_key(*k))
        .collect();
    if !resign.is_empty() && !inspected.identity.is_signing_capable() {
        die(
            &"this vault must be re-signed to re-admit them, and your key cannot sign\nask a teammate with an age or ssh-ed25519 key to review it and run `murk trust --re-add`",
            1,
        );
    }
    if !yes
        && !confirmed(
            "re-admit these agent grant keys on this machine, for the revocations shown only?",
        )
    {
        die(&"not trusted", 1);
    }
    try_or_die(murk_cli::pins::update(vault_path, |fresh| {
        let mut pin = fresh.cloned().unwrap_or_default();
        for key in keys {
            let ids = held.get(key).cloned().unwrap_or_default();
            pin.sidecar
                .readmitted_grants
                .entry(key.clone())
                .or_default()
                .extend(ids);
            pin.sidecar
                .readmitted_grants
                .retain(|_, ids| !ids.is_empty());
            pin.grants.remove(key);
            pin.sidecar.grants_live_on.remove(key);
        }
        Ok(Some(pin))
    }));
    if resign.is_empty() {
        eprintln!(
            "{} re-admitted the revocations shown on this machine. The vault file is unchanged",
            "◆".magenta()
        );
        return;
    }
    // Sign again, so the vault's own set no longer holds the ids re-admitted
    // (a save writes the set less them).
    let again = try_or_die(murk_cli::inspect_vault(vault_path));
    if let Some(reason) = again.refusal_message(vault_path) {
        die(
            &format_args!(
                "re-admitted the revocations shown on this machine, but {vault_path} is refused for another reason, so it was not signed again:\n{reason}"
            ),
            1,
        );
    }
    let murk_cli::InspectedVault {
        mut vault, murk, ..
    } = again;
    save_vault(vault_path, &mut vault, &murk, &murk);
    eprintln!(
        "{} re-admitted the revocations shown and signed {vault_path} again — commit the result so teammates get it",
        "◆".magenta()
    );
}

/// `murk trust --re-add` for removed keys whose removal does not apply to
/// this vault here (the vault does not list them, or lists them on a branch
/// the removal has not reached): after confirmation, take them out of this
/// machine's removal records, so that a vault that lists them loads here on
/// every branch. `listed` holds the vault's canonical recipients. The vault
/// file is not written.
fn clear_removal_records(
    yes: bool,
    vault_path: &str,
    keys: &std::collections::BTreeSet<String>,
    listed: &std::collections::BTreeSet<String>,
) {
    let shown = |ks: Vec<&String>| -> Vec<String> {
        ks.into_iter()
            .map(|k| murk_cli::truncate_pubkey(k))
            .collect()
    };
    let (on, off): (Vec<&String>, Vec<&String>) = keys.iter().partition(|k| listed.contains(*k));
    if !off.is_empty() {
        eprintln!(
            "{} {vault_path} does not list {}. This machine recorded them as removed",
            "⚠".yellow(),
            shown(off).join(", ")
        );
    }
    if !on.is_empty() {
        eprintln!(
            "{} {vault_path} lists {}, whom this machine recorded as removed; the removal does not apply on this branch",
            "⚠".yellow(),
            shown(on).join(", ")
        );
    }
    eprintln!("  {}", murk_cli::trust::READD_SCOPE);
    let shown: Vec<String> = keys.iter().map(|k| murk_cli::truncate_pubkey(k)).collect();
    if !yes
        && !confirmed(
            "trust them again on every branch on this machine, so a vault that lists them can load anywhere here?",
        )
    {
        die(&"not trusted", 1);
    }
    try_or_die(murk_cli::pins::update(vault_path, |fresh| {
        let Some(mut pin) = fresh.cloned() else {
            return Ok(None);
        };
        for k in keys {
            pin.removed.remove(k);
            pin.removed_on.remove(k);
            pin.removed_at_commit.remove(k);
        }
        Ok(Some(pin))
    }));
    eprintln!(
        "{} {} can be listed again in {vault_path} on this machine. The vault file is unchanged",
        "◆".magenta(),
        shown.join(", ")
    );
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
/// the vault. With `already_trusted` (the vault already loads here, so
/// `murk trust` records nothing), each change is marked as not recorded.
fn print_summary(vault_path: &str, inspected: &murk_cli::InspectedVault, already_trusted: bool) {
    let vault = &inspected.vault;
    let murk = &inspected.murk;
    let pin = inspected.assessment.pin.as_ref().filter(|p| p.has_trust());
    let unrecorded = if already_trusted {
        format!(" {}", "(not recorded: already trusted)".dimmed())
    } else {
        String::new()
    };

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
            eprintln!("  {} {label}{fp}{unrecorded}", "+".magenta().bold());
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
                eprintln!(
                    "  {} {}{unrecorded}",
                    "-".red().bold(),
                    murk_cli::truncate_pubkey(gone)
                );
            }
        }
    }
}
