// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The local trust pin: what this machine last accepted for a vault.
//!
//! A vault carries its own recipient list, so "signed by a recipient" proves
//! nothing against someone who can write the file: they list their own key and
//! sign with it. Trust has to be anchored outside the repo. The pin is that
//! anchor — a per-vault record under `~/.config/murk/signer-pins/` holding:
//!
//! - `trusted`: the keys allowed to sign the next version (the non-grant
//!   recipients of the last vault this machine accepted);
//! - `grants`: every agent-grant key ever seen, which never count as signers;
//! - `groups`: group membership as last accepted, so a membership change by a
//!   non-member is refused;
//! - `vault_id` and `generation`: the vault's identity and the highest save
//!   counter accepted, so another vault's file or an older revision is refused;
//! - `was_signed`: whether a signed version was ever accepted, so a stripped
//!   signature is refused;
//! - `signers`: confirmed verifying keys of age signers, and `added_by`: for
//!   an entry pinned on another signer's word, that signer — the entry stops
//!   counting once they are removed;
//! - `removed`: keys removed from the vault, with the generation they were
//!   removed at, so an older revision cannot bring them back;
//! - `head` and `branch_heads`: fingerprints of the vaults accepted at the
//!   marks, so a different vault with the same counter is seen as a fork;
//! - `accepted_pre_upgrade`: per branch, the murk 0.13 file the user accepted
//!   there with `murk trust` once this machine had seen the vault in 0.14
//!   form, so that copy, and only it, may be written (upgraded) there.
//!
//! Fields new in this release live in a sidecar file next to the pin (see
//! [`Sidecar`]), which murk 0.15 never opens.
//!
//! The pin is written only by an accepted load, an explicit `murk trust`, or
//! this machine's own save — never from an unverified vault. See
//! [`crate::trust`] for the rules applied against it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Format version of a trust pin. Pins without it (murk ≤ 0.13 trust-on-first-
/// use registry pins) carry no trust decision; only their `was_signed` bit is
/// kept.
pub const PIN_VERSION: u32 = 2;

/// What this machine last accepted for one vault. See the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPin {
    #[serde(default)]
    pub v: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vault_id: String,
    #[serde(default)]
    pub generation: u64,
    /// Highest counter accepted per git branch. The rollback check compares
    /// with the branch the vault is checked out on, so moving to an older
    /// branch is not a rollback but a branch going backwards is. `generation`
    /// is the highest overall, used for vaults outside a repository and to
    /// number the next save.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub branches: BTreeMap<String, u64>,
    /// Every key that was ever a trusted signer here. A historical revision
    /// (`murk diff` against a git ref) verifies if its signer is in this set,
    /// so a teammate revoked since still verifies for their old revisions.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub ever_trusted: BTreeSet<String>,
    /// Canonical recipient keys (see [`crate::recipients::canonical_recipient`])
    /// trusted to sign this vault.
    #[serde(default)]
    pub trusted: BTreeSet<String>,
    /// Canonical keys of every agent grant seen on an accepted version.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub grants: BTreeSet<String>,
    /// Group name → canonical member keys, as last accepted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, BTreeSet<String>>,
    /// Canonical pubkey → base64 verifying key of an age signer.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signers: BTreeMap<String, String>,
    /// For a `signers` entry this machine pinned from a signer registry on
    /// another signer's word: canonical recipient → that signer. The entry
    /// counts only while that signer is trusted (see [`TrustPin::pinned_key`]).
    /// An entry without one was confirmed here: with `murk trust`, or as this
    /// machine's own key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub added_by: BTreeMap<String, String>,
    /// Keys an accepted vault removed: canonical key → the generation of the
    /// vault that removed it. Where the removal applies (see `removed_on`), a
    /// vault listing the key, at any generation, or signed by it, is refused.
    /// Only this machine's own save that adds the key again (`circle
    /// authorize`) or `murk trust --re-add` takes it out: a load never does.
    /// The sidecar keeps a copy (see [`Sidecar::removals`]), so a murk 0.15
    /// component that clears an entry here does not undo it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub removed: BTreeMap<String, u64>,
    /// The branches whose accepted history contains each removal: the branch
    /// it was made or accepted on, and every branch where an accepted vault at
    /// or after the removal no longer lists the key. A removal also applies
    /// outside git, on a detached HEAD and on a branch this machine has no
    /// mark for (unless the vault is from before the removal, see
    /// `removed_at_commit`); a key in `removed` with no entry here applies
    /// everywhere.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub removed_on: BTreeMap<String, BTreeSet<String>>,
    /// The commit checked out when this machine made or accepted each
    /// removal: canonical key → full commit id. A vault the key signed, or
    /// one listing it on a branch the removal has not reached, counts as
    /// from before the removal only when git shows its commit is this one or
    /// an ancestor of it and the vault file is as committed there. A removal
    /// with no entry here (outside git, or recorded by an older murk) has no
    /// such exception.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub removed_at_commit: BTreeMap<String, String>,
    /// Fingerprint ([`crate::trust::vault_fingerprint`]) of the vault accepted
    /// at `generation`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub head: String,
    /// Fingerprint of the vault accepted at each branch's mark.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub branch_heads: BTreeMap<String, String>,
    /// Branch → fingerprint ([`crate::trust::pre_upgrade_fingerprint`]) of
    /// the murk 0.13 file `murk trust` accepted there (`""` outside git).
    /// Once this machine has seen the vault in 0.14 form, a 0.13 file that
    /// loads as history is read-only: a save or keyed merge over it is
    /// refused unless it is the copy recorded here for the branch. A pin
    /// written by murk 0.14.0 has no such entries, which refuses those writes
    /// until `murk trust`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub accepted_pre_upgrade: BTreeMap<String, String>,
    /// Whether a signed version of this vault was ever accepted here.
    #[serde(default)]
    pub was_signed: bool,
    /// The fields kept in the sidecar file (see [`Sidecar`]), never in the
    /// pin file.
    #[serde(skip)]
    pub sidecar: Sidecar,
}

/// Format version of a sidecar file.
pub const SIDECAR_VERSION: u32 = 1;

/// The pin fields new in this release. They live in a sidecar file next to
/// the pin, `<hash>.lineage.json`, which murk 0.15 never opens: a murk 0.15
/// component that shares `HOME` and rewrites the pin (a binding, or an older
/// `murk` on `PATH`) drops the fields it does not know, so they cannot live
/// in the pin file. murk reads and writes the sidecar with the pin, under the
/// pin's lock, the sidecar first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sidecar {
    #[serde(default)]
    pub v: u32,
    /// The pin's vault id when this release last wrote the sidecar. When it
    /// differs from the pin's, an older murk accepted another vault at this
    /// path, and murk drops the sidecar.
    #[serde(default)]
    pub vault_id: String,
    /// The repository's common git directory. Empty outside git.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo_dir: String,
    /// This pin's vault path in the checkout, `/`-separated. Empty outside
    /// git.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Paths the user named with `murk trust --shares-identity-with` as
    /// holding this vault's id too. murk refuses each of them on this
    /// machine.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub identity_siblings: BTreeSet<String>,
    /// Groups an accepted vault deleted: group name → canonical members when
    /// it was deleted. A vault that creates the group again is judged as a
    /// change from these members.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deleted_groups: BTreeMap<String, BTreeSet<String>>,
    /// A copy of the pin's removal records: canonical key → its entries in
    /// `removed`, `removed_on` and `removed_at_commit`. Every pin write
    /// copies them here, and so does every read that finds a record the
    /// sidecar lacks. A read lays them over the pin file (see [`read`]), so a
    /// murk 0.15 component that clears a record in the pin file does not
    /// undo it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub removals: BTreeMap<String, RemovalRecord>,
    /// Every revoked grant set (see [`crate::types::Meta::revoked_grants`])
    /// this machine accepted for the vault on a current load, an own save or
    /// `murk trust`: canonical grant key → revocation ids. A save writes them
    /// back, so a murk 0.15 save that dropped the vault's set does not undo
    /// a revocation here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revoked_grants_seen: crate::types::RevokedGrants,
    /// The revocation ids the user re-admitted with `murk trust --re-add`:
    /// canonical grant key → the ids that command showed. Only those ids
    /// stop counting; a later revocation of the key has a new id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub readmitted_grants: crate::types::RevokedGrants,
    /// Where this machine saw each grant live: canonical grant key → branch
    /// (`""` outside git) → the commit checked out at the latest current
    /// load, own save or `murk trust` that held the key's grant record (`""`
    /// with no commit). A save on that branch, on related history, that no
    /// longer holds the record gives the key a revocation id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub grants_live_on: BTreeMap<String, BTreeMap<String, String>>,
}

/// One removal record as the sidecar keeps it (see [`Sidecar::removals`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovalRecord {
    /// The pin's `removed` entry.
    pub at: u64,
    /// The pin's `removed_on` entry, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<BTreeSet<String>>,
    /// The pin's `removed_at_commit` entry, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_commit: Option<String>,
}

impl TrustPin {
    /// Whether this pin records a trust decision (a `murk trust`, an accepted
    /// load, or an own save), as opposed to a legacy or empty record.
    pub fn has_trust(&self) -> bool {
        self.v >= PIN_VERSION && !self.trusted.is_empty()
    }

    /// The verifying key pinned for `key` (canonical), if it still counts: an
    /// entry pinned on another signer's word counts only while that signer is
    /// trusted here.
    pub fn pinned_key(&self, key: &str) -> Option<&String> {
        let vk = self.signers.get(key)?;
        match self.added_by.get(key) {
            Some(adder) if !self.trusted.contains(adder) => None,
            _ => Some(vk),
        }
    }

    /// The pin's removal records, as the sidecar keeps them.
    pub fn removal_records(&self) -> BTreeMap<String, RemovalRecord> {
        self.removed
            .iter()
            .map(|(k, &at)| {
                let record = RemovalRecord {
                    at,
                    on: self.removed_on.get(k).cloned(),
                    at_commit: self.removed_at_commit.get(k).cloned(),
                };
                (k.clone(), record)
            })
            .collect()
    }

    /// Lay the removal records `records` over this pin. A record the pin
    /// lacks is added. For a record it has, the larger generation wins, the
    /// branches where it applies are the union (no entry on either side
    /// means every branch), and the pin's commit is kept when it has one.
    /// Every removed key then leaves `trusted`. Only narrows. Returns the
    /// keys the pin did not record as removed, or trusted.
    fn overlay_removals(&mut self, records: &BTreeMap<String, RemovalRecord>) -> Vec<String> {
        let mut restored = Vec::new();
        for (k, r) in records {
            match self.removed.get_mut(k) {
                None => {
                    self.removed.insert(k.clone(), r.at);
                    match &r.on {
                        Some(on) => self.removed_on.insert(k.clone(), on.clone()),
                        None => self.removed_on.remove(k),
                    };
                    match &r.at_commit {
                        Some(c) => self.removed_at_commit.insert(k.clone(), c.clone()),
                        None => self.removed_at_commit.remove(k),
                    };
                    restored.push(k.clone());
                }
                Some(at) => {
                    *at = (*at).max(r.at);
                    match (self.removed_on.get_mut(k), &r.on) {
                        (Some(on), Some(more)) => on.extend(more.iter().cloned()),
                        _ => {
                            self.removed_on.remove(k);
                        }
                    }
                    if let Some(c) = &r.at_commit {
                        self.removed_at_commit
                            .entry(k.clone())
                            .or_insert_with(|| c.clone());
                    }
                    if self.trusted.contains(k) {
                        restored.push(k.clone());
                    }
                }
            }
        }
        let removed = &self.removed;
        self.trusted.retain(|k| !removed.contains_key(k));
        restored
    }

    /// Whether the sidecar lacks a removal record the pin holds (after the
    /// overlay), so a read must copy it.
    fn copy_due(&self) -> bool {
        self.v >= PIN_VERSION && self.removal_records() != self.sidecar.removals
    }
}

/// Path to the pin file for a vault: `~/.config/murk/signer-pins/<hash>.json`.
///
/// Inside a git checkout the hash is over the repository's common git
/// directory plus the vault's path in the checkout, so every worktree of the
/// repository shares one pin. Elsewhere it is over the vault's absolute path
/// with its directory resolved (`fs::canonicalize`), so `.murk`, `./.murk` and
/// a path through a symlinked directory share one pin.
pub fn pin_path(vault_path: &str) -> Option<PathBuf> {
    pin_paths(vault_path).into_iter().next()
}

/// The pin file murk reads for `vault_path`: the first of the candidate
/// paths (see [`pin_path`]) that exists, if any.
pub fn existing_pin_path(vault_path: &str) -> Option<PathBuf> {
    pin_paths(vault_path).into_iter().find(|p| p.exists())
}

/// Where a pin for `vault_path` may live, preferred first: the repository
/// identity (see [`pin_path`]), then the resolved absolute path, then the
/// lexical absolute path murk ≤ 0.13 used. Reads take the first that exists,
/// so a vault that was created before `git init`, or pinned by an older
/// release, keeps its pin; writes always go to the first.
fn pin_paths(vault_path: &str) -> Vec<PathBuf> {
    let Some(dir) = pin_dir() else {
        return Vec::new();
    };
    let p = std::path::Path::new(vault_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            Err(_) => return Vec::new(),
        }
    };
    // The vault's directory resolved to its real path, in the plain form (see
    // `git::real_dir`): on Windows, `fs::canonicalize`'s verbatim `\\?\` form
    // matched no other spelling, so neither the work-tree root nor a sibling
    // checkout was ever found from it.
    let resolved = crate::git::real_parent(&abs);
    let mut identities = Vec::new();
    if let Some(repo) = crate::git::repository_vault_identity(&resolved) {
        identities.push(repo);
    }
    // The same vault in a sibling worktree, pinned by path before the
    // repository existed (or by murk ≤ 0.13): accept that pin too, under the
    // same real-path spelling it was written with (git records a sibling's
    // path in its own spelling, `/`-separated on Windows).
    let siblings: Vec<PathBuf> = crate::git::worktree_root(resolved.parent().unwrap_or(&resolved))
        .and_then(|root| {
            let relative = resolved.strip_prefix(&root).ok()?.to_path_buf();
            Some(
                crate::git::sibling_worktrees(&root)
                    .into_iter()
                    .map(|w| crate::git::real_parent(&w.join(&relative)))
                    .collect(),
            )
        })
        .unwrap_or_default();
    identities.push(resolved);
    identities.push(abs);
    identities.extend(siblings);
    identities.dedup();
    identities
        .iter()
        .map(|identity| dir.join(format!("{}.json", short_hash(identity))))
        .collect()
}

fn short_hash(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(path.to_string_lossy().as_bytes());
    hash.iter().take(8).fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether `MURK_NO_SIGNER_PIN` is set (any value). murk then still reads an
/// existing pin and applies every rule against it, but never creates or
/// writes one.
pub fn pin_writes_off() -> bool {
    std::env::var_os("MURK_NO_SIGNER_PIN").is_some()
}

/// Whether a trust pin can be stored on this machine — false when opted out
/// ([`pin_writes_off`]) or when there is no home directory. A pin that
/// already exists is still read under the opt-out.
pub fn signer_pin_available() -> bool {
    !pin_writes_off()
        && (std::env::var_os("HOME").is_some() || std::env::var_os("USERPROFILE").is_some())
}

/// The pin file a write goes to, or why no pin can be written.
fn writable_pin_path(vault_path: &str) -> Result<PathBuf, String> {
    if pin_writes_off() {
        return Err(
            "MURK_NO_SIGNER_PIN is set, so murk does not write the trust pin. Unset it to record trust here, or set MURK_TRUSTED_SIGNERS".to_string(),
        );
    }
    pin_path(vault_path).ok_or_else(|| {
        "no trust pin can be stored because there is no HOME. Set MURK_TRUSTED_SIGNERS instead"
            .to_string()
    })
}

/// Read the pin for `vault_path`, with its sidecar (see [`Sidecar`]), and
/// the sidecar's removal records laid over the pin file's.
/// `Ok(None)` when there is no home directory or no pin exists yet.
/// `MURK_NO_SIGNER_PIN` does not stop the read. A pin or sidecar that exists
/// but cannot be read or parsed is an error: silently treating it as empty
/// would forget a rollback high-water mark or a recorded deletion.
///
/// When the pin file holds a removal record that the sidecar lacks (one
/// made before this release, or by a murk 0.15 component), the read copies
/// it into the sidecar under the pin lock, so a murk 0.15 component that
/// later clears the pin file's record does not undo it. The pin file stays
/// as it is. When nothing is missing, the read takes no lock and writes
/// nothing. Under `MURK_NO_SIGNER_PIN` nothing is copied. A copy that
/// cannot be written only warns: this read already applies the pin file's
/// records. A caller that holds the pin lock must not call this (see
/// [`LOCK_ORDER`]).
pub fn read(vault_path: &str) -> Result<Option<TrustPin>, String> {
    check_lock_order()?;
    let raw = read_raw(vault_path)?;
    let pin = parse_raw(vault_path, &raw)?;
    if let (Some(first), Some((pin_file, _))) = (&pin, &raw.file)
        && first.copy_due()
        && !pin_writes_off()
    {
        #[cfg(test)]
        test_hooks::run(&test_hooks::BEFORE_COPY);
        if let Err(e) = copy_removals(vault_path, first) {
            warn_copy_failed(vault_path, &sidecar_path(pin_file), &e);
        }
    }
    Ok(pin)
}

/// The copy step of [`read`]: under the pin lock, read the pin file and the
/// sidecar again and write the sidecar with the removal records of both
/// reads, so a record cleared between the two reads is kept.
fn copy_removals(vault_path: &str, first: &TrustPin) -> Result<(), String> {
    let _lock = lock(vault_path)?;
    let raw = read_raw(vault_path)?;
    let (Some(mut pin), Some((pin_file, _))) = (parse_raw(vault_path, &raw)?, &raw.file) else {
        return Ok(());
    };
    pin.overlay_removals(&first.removal_records());
    if pin.copy_due() {
        write_sidecar(vault_path, pin_file, &pin)?;
    }
    Ok(())
}

/// Say once per process that the removal records for `vault_path` could not
/// be copied into `sidecar`.
fn warn_copy_failed(vault_path: &str, sidecar: &Path, error: &str) {
    static WARNED: std::sync::Mutex<BTreeSet<PathBuf>> = std::sync::Mutex::new(BTreeSet::new());
    if WARNED
        .lock()
        .map_or(true, |mut w| w.insert(sidecar.to_path_buf()))
    {
        eprintln!(
            "warn cannot copy the removal records for {vault_path} into {}: {error}. An older murk component under this HOME can still erase them",
            sidecar.display()
        );
    }
}

/// The pin file and sidecar bytes for one vault, as read from disk: the
/// part of a publish token (see [`Snapshot`]) that covers the trust state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RawPin {
    /// The pin file that exists (see [`pin_paths`]) and its bytes.
    file: Option<(PathBuf, Vec<u8>)>,
    /// The bytes of that pin file's sidecar, or of the sidecar a write would
    /// go to when no pin file exists.
    sidecar: Option<Vec<u8>>,
}

/// Read the pin file and its sidecar for `vault_path` as bytes. Takes no lock.
fn read_raw(vault_path: &str) -> Result<RawPin, String> {
    let read_opt = |path: &Path| match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read trust pin {}: {e}", path.display())),
    };
    let paths = pin_paths(vault_path);
    let mut file = None;
    for path in &paths {
        if let Some(bytes) = read_opt(path)? {
            file = Some((path.clone(), bytes));
            break;
        }
    }
    let sidecar = match file.as_ref().map(|(p, _)| p).or(paths.first()) {
        Some(pin_file) => read_opt(&sidecar_path(pin_file))?,
        None => None,
    };
    Ok(RawPin { file, sidecar })
}

/// The pin that `raw` holds for `vault_path`, as [`read`] returns it: the
/// sidecar's removal records laid over the pin file's. With no pin file, a
/// sidecar that records removals for the vault id of the vault file at
/// `vault_path` still applies (see [`sidecar_without_pin`]).
fn parse_raw(vault_path: &str, raw: &RawPin) -> Result<Option<TrustPin>, String> {
    let Some((path, contents)) = &raw.file else {
        return sidecar_without_pin(vault_path, raw);
    };
    let mut pin: TrustPin = serde_json::from_slice(contents).map_err(|e| {
        format!(
            "trust pin {} is corrupt ({e}) — delete it and run `murk trust`",
            path.display()
        )
    })?;
    if pin.v < PIN_VERSION {
        // A murk ≤ 0.13 pin: its registry entries were recorded trust-on-first-
        // use from unverified vaults, so they carry no trust. Keep only the
        // downgrade bit.
        pin = TrustPin {
            was_signed: pin.was_signed,
            ..TrustPin::default()
        };
    } else {
        pin.sidecar = parse_sidecar(path, raw.sidecar.as_deref(), &pin.vault_id)?;
        let records = pin.sidecar.removals.clone();
        for key in pin.overlay_removals(&records) {
            warn_divergence(vault_path, path, &key);
        }
    }
    drop_unusable_signer_keys(&mut pin, path);
    Ok(Some(pin))
}

/// The pin for `vault_path` when its pin file is missing but its sidecar is
/// not. No murk version deletes a pin file, so a missing one is the user's
/// own act, and the removal records must not go with it. When the sidecar's
/// vault id is the id of the vault file at `vault_path`, the result is a pin
/// with no trust decision that holds only the sidecar's removal records: a
/// load needs `murk trust` as on a new machine, and that names each removed
/// key the vault lists. A sidecar of another vault, or with no records,
/// applies to nothing.
fn sidecar_without_pin(vault_path: &str, raw: &RawPin) -> Result<Option<TrustPin>, String> {
    let (Some(contents), Some(pin_file)) = (&raw.sidecar, pin_path(vault_path)) else {
        return Ok(None);
    };
    let sidecar = parse_sidecar(&pin_file, Some(contents), "")?;
    let same_vault = crate::vault::read(Path::new(vault_path))
        .is_ok_and(|v| !v.vault_id.is_empty() && v.vault_id == sidecar.vault_id);
    if sidecar.removals.is_empty() || !same_vault {
        return Ok(None);
    }
    let mut pin = TrustPin {
        v: PIN_VERSION,
        vault_id: sidecar.vault_id.clone(),
        ..TrustPin::default()
    };
    pin.overlay_removals(&sidecar.removals);
    pin.sidecar = sidecar;
    Ok(Some(pin))
}

/// Say once per process that the pin file `pin_file` for `vault_path` no
/// longer records `key` as removed, but the sidecar's copy does.
fn warn_divergence(vault_path: &str, pin_file: &Path, key: &str) {
    static WARNED: std::sync::Mutex<BTreeSet<(PathBuf, String)>> =
        std::sync::Mutex::new(BTreeSet::new());
    if WARNED.lock().map_or(true, |mut w| {
        w.insert((pin_file.to_path_buf(), key.to_string()))
    }) {
        eprintln!(
            "warn the trust pin for {vault_path} no longer records {} as removed, but the copy of this release does. An older murk component (0.15 or earlier) under this HOME probably accepted a vault that lists them: a murk CLI earlier on PATH, the merge driver that git runs, or a binding. murk keeps them removed. Upgrade every murk component on this machine. If you re-added them on purpose with the older component, run `murk trust --vault {vault_path} --re-add {key}` with this release",
            crate::truncate_pubkey(key)
        );
    }
}

/// The sidecar file of the pin file `pin_file`: `<hash>.lineage.json`.
pub fn sidecar_path(pin_file: &Path) -> PathBuf {
    pin_file.with_extension("lineage.json")
}

/// The sidecar of the pin file `pin_file`, whose vault id is `pin_id`, from
/// its bytes `contents`. A missing sidecar reads as empty, and so does one
/// that records another vault id: an older murk accepted another vault at
/// this path, so the sidecar's records are not this vault's. murk says so
/// once, and the next pin write replaces the sidecar.
fn parse_sidecar(
    pin_file: &Path,
    contents: Option<&[u8]>,
    pin_id: &str,
) -> Result<Sidecar, String> {
    static WARNED: std::sync::Mutex<BTreeSet<PathBuf>> = std::sync::Mutex::new(BTreeSet::new());

    let path = sidecar_path(pin_file);
    let Some(contents) = contents else {
        return Ok(Sidecar::default());
    };
    let sidecar: Sidecar = serde_json::from_slice(contents).map_err(|e| {
        format!(
            "trust pin {} is corrupt ({e}) — delete it and run `murk trust`",
            path.display()
        )
    })?;
    if !sidecar.vault_id.is_empty() && !pin_id.is_empty() && sidecar.vault_id != pin_id {
        let first = WARNED.lock().map_or(true, |mut w| w.insert(path.clone()));
        if first {
            eprintln!(
                "warn trust pin {} records vault id {}, but the pin records {pin_id}. An older murk accepted another vault at this path. murk ignores this file and writes a new one",
                path.display(),
                sidecar.vault_id
            );
        }
        return Ok(Sidecar::default());
    }
    Ok(sidecar)
}

/// Where `vault_path` sits in its git repository: the repository's common
/// git directory and the vault's `/`-separated path in the checkout. `None`
/// outside git.
pub fn vault_location(vault_path: &str) -> Option<(String, String)> {
    let p = Path::new(vault_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(p)
    };
    let resolved = crate::git::real_parent(&abs);
    let root = crate::git::worktree_root(resolved.parent()?)?;
    let relative = resolved.strip_prefix(&root).ok()?;
    // The repository identity is `<common dir>/murk-vault/<relative>`.
    let mut common = crate::git::repository_vault_identity(&resolved)?;
    for _ in relative.components() {
        common.pop();
    }
    common.pop();
    let path: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Some((common.to_string_lossy().into_owned(), path.join("/")))
}

/// Every sidecar on this machine whose pin file exists and records the same
/// vault id, with that pin file. Read without the pin lock: both files are
/// replaced by an atomic rename, so a read sees one whole version. A file
/// that cannot be read or parsed is left out.
pub fn peek_sidecars() -> Vec<(PathBuf, Sidecar)> {
    let Some(dir) = pin_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| {
            let path = e.ok()?.path();
            let name = path.file_name()?.to_str()?;
            let hash = name.strip_suffix(".lineage.json")?;
            let pin_file = dir.join(format!("{hash}.json"));
            let pin: TrustPin = serde_json::from_slice(&std::fs::read(&pin_file).ok()?).ok()?;
            let sidecar: Sidecar = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
            (pin.v >= PIN_VERSION && !pin.vault_id.is_empty() && pin.vault_id == sidecar.vault_id)
                .then_some((pin_file, sidecar))
        })
        .collect()
}

/// Remove the pin file `pin_file` and its sidecar, under the pin's lock:
/// `murk trust --shares-identity-with` retires another path of the vault on
/// this machine.
pub fn remove(pin_file: &Path) -> Result<(), String> {
    if pin_writes_off() {
        return Err(
            "MURK_NO_SIGNER_PIN is set, so murk does not write the trust pin. Unset it to record trust here".to_string(),
        );
    }
    let _lock = open_lock(pin_file)?;
    [pin_file.to_path_buf(), sidecar_path(pin_file)]
        .iter()
        .try_for_each(|path| match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("cannot remove {}: {e}", path.display()))
            }
            _ => Ok(()),
        })
}

/// The directory that holds the pins: `~/.config/murk/signer-pins`.
fn pin_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(
        Path::new(&home)
            .join(".config")
            .join("murk")
            .join("signer-pins"),
    )
}

/// Drop from `pin` every 32-byte signing key [`crate::signing::checked_verifying_key`]
/// refuses (weak, non-canonical or off the curve: a pinned verifying key, or
/// an ssh-ed25519 signer, whose key is its own verifying key), warning once
/// per pin file. murk never pins such a key, so one here was written by
/// something else; trusting it would let a forged signature verify. The next
/// pin write leaves it out. A value that is not a 32-byte key at all is left
/// alone: it never verifies a signature.
fn drop_unusable_signer_keys(pin: &mut TrustPin, path: &std::path::Path) {
    use crate::signing::is_refused_signing_key as refused;
    static WARNED: std::sync::Mutex<BTreeSet<PathBuf>> = std::sync::Mutex::new(BTreeSet::new());

    let refused_ssh = |k: &String| k.starts_with("ssh-ed25519 ") && refused(k);
    let mut dropped: BTreeSet<String> = pin
        .trusted
        .iter()
        .chain(&pin.ever_trusted)
        .filter(|k| refused_ssh(k))
        .cloned()
        .collect();
    pin.trusted.retain(|k| !refused_ssh(k));
    pin.ever_trusted.retain(|k| !refused_ssh(k));
    pin.signers.retain(|k, vk| {
        let bad = refused(vk);
        if bad {
            dropped.insert(k.clone());
        }
        !bad
    });
    if dropped.is_empty() {
        return;
    }
    let first = WARNED
        .lock()
        .map_or(true, |mut w| w.insert(path.to_path_buf()));
    if first {
        let keys: Vec<String> = dropped.iter().map(|k| crate::truncate_pubkey(k)).collect();
        eprintln!(
            "warn trust pin {} holds a weak or invalid signing key for {}; ignoring it — run `murk trust` to re-pin",
            path.display(),
            keys.join(", ")
        );
    }
}

/// Write the pin for `vault_path` and its sidecar, the sidecar first: a
/// crash between the two leaves the newer records in the sidecar, which only
/// narrows. A crash after a cleared record reaches the sidecar leaves it in
/// the pin file, and the next read copies it back. Errors when pinning is
/// unavailable or the write fails, so a caller recording an explicit trust
/// decision can say so.
pub fn write(vault_path: &str, pin: &TrustPin) -> Result<(), String> {
    let path = writable_pin_path(vault_path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid trust pin path {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // ~/.config/murk should stay 0700 like the key dirs.
        if let Some(murk_dir) = parent.parent() {
            let _ = std::fs::set_permissions(murk_dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let mut pin = pin.clone();
    pin.v = PIN_VERSION;
    write_sidecar(vault_path, &path, &pin)?;
    #[cfg(test)]
    test_hooks::fail_after_sidecar()?;
    let json = serde_json::to_string_pretty(&pin).map_err(|e| format!("trust pin: {e}"))?;
    write_pin_file(&path, json.as_bytes())
        .map_err(|e| format!("cannot write trust pin {}: {e}", path.display()))
}

/// Write the sidecar of the pin file `pin_file` from `pin`: its sidecar
/// fields, the pin's vault id, the pin's removal records, and this vault's
/// place in its repository.
fn write_sidecar(vault_path: &str, pin_file: &Path, pin: &TrustPin) -> Result<(), String> {
    let (repo_dir, rel) = vault_location(vault_path).unwrap_or_default();
    let sidecar = Sidecar {
        v: SIDECAR_VERSION,
        vault_id: pin.vault_id.clone(),
        repo_dir,
        path: rel,
        removals: pin.removal_records(),
        ..pin.sidecar.clone()
    };
    let sidecar_file = sidecar_path(pin_file);
    let json = serde_json::to_string_pretty(&sidecar).map_err(|e| format!("trust pin: {e}"))?;
    write_pin_file(&sidecar_file, json.as_bytes())
        .map_err(|e| format!("cannot write trust pin {}: {e}", sidecar_file.display()))
}

/// Read, change and write the pin for `vault_path` and its sidecar under an
/// exclusive lock (`<pin>.lock`), so concurrent murk processes — worktrees of
/// one repository share a pin — never write from a stale read: a lowered
/// rollback mark, or keys and grants another process just learned, lost. `f`
/// gets the pin as it is now and returns the pin to write, or `None` to leave
/// it, or an error to report. With `None`, the sidecar still gets a copy of
/// any removal record it lacks (see [`read`]). A caller may hold the vault
/// lock, never the pin lock (see [`LOCK_ORDER`]).
pub fn update<F>(vault_path: &str, f: F) -> Result<(), String>
where
    F: FnOnce(Option<&TrustPin>) -> Result<Option<TrustPin>, String>,
{
    let path = writable_pin_path(vault_path)?;
    let _lock = open_lock(&path)?;
    let current = read_held(vault_path)?;
    if let Some(pin) = f(current.as_ref())? {
        return write(vault_path, &pin);
    }
    if let Some(pin) = current.filter(TrustPin::copy_due)
        && let Some(pin_file) = existing_pin_path(vault_path)
        && let Err(e) = write_sidecar(vault_path, &pin_file, &pin)
    {
        warn_copy_failed(vault_path, &sidecar_path(&pin_file), &e);
    }
    Ok(())
}

/// [`read`] for a caller that holds the pin lock: it takes no lock and
/// copies nothing.
fn read_held(vault_path: &str) -> Result<Option<TrustPin>, String> {
    parse_raw(vault_path, &read_raw(vault_path)?)
}

/// The lock order, which every write path follows:
///
/// 1. A thread takes the vault lock (`<vault>.lock`, [`crate::vault::lock`])
///    before the pin lock (`<hash>.lock`, next to the pin), never the
///    reverse.
/// 2. A thread holds at most one vault lock and at most one pin lock.
/// 3. While a thread holds the pin lock, it calls nothing that takes a lock:
///    not `vault::lock`, [`update`], [`remove`] or [`Snapshot::publish`]. It
///    reads with [`read_held`] and writes with [`write`]. The only
///    subprocesses it runs are read-only git commands (`symbolic-ref`,
///    `rev-parse`, `merge-base --is-ancestor`, `cat-file -e`,
///    `diff --quiet HEAD --`), which take no `index.lock`.
/// 4. The pin lock is never held across a signature, a confirmation prompt
///    or an editor session.
///
/// A flock lock belongs to the open file description, so a second lock of
/// the same lock file by the same thread would block for ever. A
/// thread-local count of held pin locks makes every lock request on a
/// thread that holds one fail with this error instead, in release builds
/// too.
pub const LOCK_ORDER: &str =
    "internal error: lock order (a lock was requested while the trust pin lock is held)";

thread_local! {
    /// How many pin locks this thread holds (see [`LOCK_ORDER`]).
    static PIN_LOCKS_HELD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Refuse a lock request on a thread that holds the pin lock (see
/// [`LOCK_ORDER`]). `vault::lock` and every pin-lock entry call this first.
pub(crate) fn check_lock_order() -> Result<(), String> {
    if PIN_LOCKS_HELD.with(std::cell::Cell::get) > 0 {
        return Err(LOCK_ORDER.to_string());
    }
    Ok(())
}

/// A held pin lock: `<pin>.lock`, released when dropped.
pub(crate) struct PinLock {
    file: std::fs::File,
}

impl Drop for PinLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
        PIN_LOCKS_HELD.with(|n| n.set(n.get().saturating_sub(1)));
    }
}

/// Why the pin lock could not be taken.
#[derive(Debug)]
pub(crate) struct LockError {
    message: String,
    /// The pin directory or the lock file cannot be created or opened for
    /// writing: permission denied, or a read-only file system.
    read_only: bool,
}

impl From<LockError> for String {
    fn from(e: LockError) -> Self {
        e.message
    }
}

impl LockError {
    fn io(what: &str, path: &Path, e: &std::io::Error) -> Self {
        Self {
            message: format!("cannot {what} {}: {e}", path.display()),
            read_only: matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ),
        }
    }
}

/// Take the pin lock for `vault_path`. Errors when there is no home
/// directory, or when this thread already holds a pin lock.
pub(crate) fn lock(vault_path: &str) -> Result<PinLock, LockError> {
    let path = pin_path(vault_path).ok_or_else(|| LockError {
        message: "no home directory to keep the trust pin in".to_string(),
        read_only: false,
    })?;
    open_lock(&path)
}

/// Open and take the exclusive lock of the pin file `path`: `<pin>.lock`.
fn open_lock(path: &Path) -> Result<PinLock, LockError> {
    use fs2::FileExt;

    check_lock_order().map_err(|message| LockError {
        message,
        read_only: false,
    })?;
    let parent = path.parent().ok_or_else(|| LockError {
        message: format!("invalid trust pin path {}", path.display()),
        read_only: false,
    })?;
    std::fs::create_dir_all(parent).map_err(|e| LockError::io("create", parent, &e))?;
    let lock_path = path.with_extension("lock");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts
        .open(&lock_path)
        .map_err(|e| LockError::io("open", &lock_path, &e))?;
    file.lock_exclusive().map_err(|e| LockError {
        message: format!("cannot lock {}: {e}", lock_path.display()),
        read_only: false,
    })?;
    PIN_LOCKS_HELD.with(|n| n.set(n.get() + 1));
    Ok(PinLock { file })
}

/// How many times a save or a merge prepares its result when the trust
/// state changes before it can publish (see [`Snapshot`]). Sibling
/// worktrees share one pin, and each save there rewrites it, so with
/// several worktrees saving at once an attempt often loses the race; the
/// wait before the next one ([`backoff`]) spreads the attempts out.
pub const PUBLISH_ATTEMPTS: u32 = 16;

/// Wait before publish attempt `next` (2 to [`PUBLISH_ATTEMPTS`]) after the
/// trust state changed: a random time up to 25 ms × 2^(next − 2), at most
/// 400 ms. The waits of one save or merge add up to at most 4.8 s. A full
/// random range spreads the waiting saves apart best. The caller holds no
/// pin lock while it waits.
pub fn backoff(next: u32) {
    let cap_ms: u64 = (25 << next.saturating_sub(2).min(4)).min(400);
    let ms = rand::random_range(0..=cap_ms);
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// What a save, a keyed merge or a `murk trust` re-sign decided against:
/// the pin and sidecar bytes, the target file's bytes, and the branch and
/// commit checked out. The writer runs its checks against [`Snapshot::pin`],
/// prepares and signs its result without the pin lock, and then publishes
/// it with [`Snapshot::publish`], which renames the result over the target
/// only if all of this is unchanged.
pub struct Snapshot {
    vault_path: String,
    target: PathBuf,
    token: Token,
    pin: Option<TrustPin>,
}

/// What must be unchanged for a publish (see [`Snapshot`]).
#[derive(Debug, PartialEq, Eq)]
struct Token {
    pin: RawPin,
    target: Option<Vec<u8>>,
    head: crate::git::HeadState,
    commit: Option<String>,
}

/// How a publish ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publish {
    /// The result replaced the target.
    Published,
    /// The pin, the sidecar, the branch or the commit changed since the
    /// snapshot. Nothing was written. The caller decides again from a new
    /// snapshot.
    TrustChanged,
    /// The target file changed since the snapshot. Nothing was written, and
    /// a new attempt cannot help: the caller's change was made to the file
    /// as it was.
    TargetChanged,
}

impl Snapshot {
    /// Read the trust state for `vault_path` and the target file `target`
    /// (the vault file for a save, git's `%A` for the merge driver). The
    /// first read is [`read`], so a removal record the sidecar lacks is
    /// copied before the token is taken.
    pub fn take(vault_path: &str, target: &Path) -> Result<Self, String> {
        read(vault_path)?;
        let raw = read_raw(vault_path)?;
        let pin = parse_raw(vault_path, &raw)?;
        let token = Token {
            pin: raw,
            target: read_target(target)?,
            head: crate::trust::head_of(vault_path),
            commit: crate::trust::commit_of(vault_path),
        };
        Ok(Self {
            vault_path: vault_path.to_string(),
            target: target.to_path_buf(),
            token,
            pin,
        })
    }

    /// The pin the checks run against.
    pub fn pin(&self) -> Option<&TrustPin> {
        self.pin.as_ref()
    }

    /// Publish `staged` over the target under the pin lock, if the pin, the
    /// sidecar, the target file, the branch and the commit are as the
    /// snapshot read them. Then, still under the lock, write the pin that
    /// `record` makes from the pin as it is now, the branch and the commit,
    /// unless pin writes are off. A failed pin write only warns: the vault
    /// is already written. Without a pin and without pin writes there is no
    /// pin lock: only the target file is compared.
    ///
    /// When the pin directory is not writable (permission denied, or a
    /// read-only file system) and no pin or sidecar exists for the vault,
    /// the publish goes on without the pin lock, writes no pin and no
    /// sidecar, and warns once the target is written. When a pin or sidecar
    /// exists, it fails and writes nothing.
    ///
    /// The rename is the only write to the target, so a crash leaves the
    /// old file or the new one. A crash before the pin write leaves the pin
    /// as it was, which records nothing that was not published.
    pub fn publish<F>(
        &self,
        staged: crate::vault::Staged,
        record: Option<F>,
    ) -> Result<Publish, String>
    where
        F: FnOnce(Option<&TrustPin>, &crate::git::HeadState, Option<&str>) -> TrustPin,
    {
        #[cfg(test)]
        test_hooks::run(&test_hooks::BEFORE_LOCK);
        let mut writes = signer_pin_available();
        let needs_lock = pin_path(&self.vault_path).is_some()
            && (writes || self.token.pin.file.is_some() || self.token.pin.sidecar.is_some());
        // Lock order: the caller may hold the vault lock; this takes the
        // pin lock after it, and nothing below takes another lock.
        let mut unlocked = None;
        let _lock = match needs_lock.then(|| lock(&self.vault_path)).transpose() {
            Ok(lock) => lock,
            // No pin and no sidecar for this vault: the decision rests on no
            // recorded trust state, so no concurrent writer (a host process
            // sharing a read-only bind mount, say) can change what it was
            // made against. Publish as murk 0.15.2 did, without the lock and
            // without a pin write. The comparison below still refuses a
            // target, or a pin or sidecar, that appeared since the snapshot.
            Err(e)
                if e.read_only
                    && self.token.pin.file.is_none()
                    && self.token.pin.sidecar.is_none() =>
            {
                unlocked = Some((e.message, writes && record.is_some()));
                writes = false;
                None
            }
            // A pin or sidecar exists: another process that shares the
            // directory may still write it (a revocation from the host of a
            // read-only bind mount), so the publish needs the lock.
            Err(e) if e.read_only => {
                let dir = pin_path(&self.vault_path)
                    .and_then(|p| p.parent().map(Path::to_path_buf))
                    .unwrap_or_default();
                return Err(format!(
                    "{}. The trust pin directory {} is read-only, and it holds a trust pin for {}, so murk cannot write the vault under the pin's lock. Nothing was written. Run murk with a writable HOME. (MURK_NO_SIGNER_PIN helps only on a machine that has no pin for this vault.)",
                    e.message,
                    dir.display(),
                    self.vault_path
                ));
            }
            Err(e) => return Err(e.into()),
        };
        if read_target(&self.target)? != self.token.target {
            return Ok(Publish::TargetChanged);
        }
        let raw = read_raw(&self.vault_path)?;
        let head = crate::trust::head_of(&self.vault_path);
        let commit = crate::trust::commit_of(&self.vault_path);
        if raw != self.token.pin || head != self.token.head || commit != self.token.commit {
            return Ok(Publish::TrustChanged);
        }
        #[cfg(test)]
        test_hooks::run(&test_hooks::UNDER_LOCK);
        staged.persist(&self.target).map_err(|e| e.to_string())?;
        match unlocked {
            Some((cause, true)) => eprintln!(
                "warn {cause}. {} is written, but the trust pin is not updated: the trusted signers, groups, grants, rollback mark, branch and commit of this save are not recorded",
                self.target.display()
            ),
            Some((cause, false)) => eprintln!(
                "warn {cause}. {} is written without the trust pin lock",
                self.target.display()
            ),
            None => {}
        }
        if let Some(record) = record.filter(|_| writes) {
            let pin = record(self.pin.as_ref(), &head, commit.as_deref());
            if let Err(e) = write(&self.vault_path, &pin) {
                eprintln!("warn {e}");
            }
        }
        Ok(Publish::Published)
    }
}

/// The bytes of the target file, or `None` when it does not exist.
fn read_target(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Test hooks around the publish section: each runs once per publish, on
/// the thread that publishes, while it is set.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;

    pub(crate) type Hook = RefCell<Option<Box<dyn FnMut()>>>;

    thread_local! {
        /// After the result is prepared and before the pin lock is taken.
        pub(crate) static BEFORE_LOCK: Hook = const { RefCell::new(None) };
        /// Under the pin lock, after the token matched, before the rename.
        pub(crate) static UNDER_LOCK: Hook = const { RefCell::new(None) };
        /// In a save, just before the vault is signed.
        pub(crate) static BEFORE_SIGN: Hook = const { RefCell::new(None) };
        /// In [`super::read`], after the unlocked read found a record to
        /// copy, before the pin lock is taken.
        pub(crate) static BEFORE_COPY: Hook = const { RefCell::new(None) };
        /// Whether [`super::write`] fails after it wrote the sidecar and
        /// before it writes the pin file.
        pub(crate) static FAIL_AFTER_SIDECAR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// The injected failure of [`FAIL_AFTER_SIDECAR`].
    pub(crate) fn fail_after_sidecar() -> Result<(), String> {
        if FAIL_AFTER_SIDECAR.with(std::cell::Cell::get) {
            return Err("injected failure after the sidecar write".into());
        }
        Ok(())
    }

    /// Set `hook` on this thread.
    pub(crate) fn set(hook: &'static std::thread::LocalKey<Hook>, f: impl FnMut() + 'static) {
        hook.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    /// Run `hook` if it is set on this thread.
    pub(crate) fn run(hook: &'static std::thread::LocalKey<Hook>) {
        let Some(mut f) = hook.with(|h| h.borrow_mut().take()) else {
            return;
        };
        f();
        hook.with(|h| {
            let mut slot = h.borrow_mut();
            if slot.is_none() {
                *slot = Some(f);
            }
        });
    }
}

/// Write the pin file atomically: a `0600` temp file in the same directory,
/// fsynced, then renamed over `path`. A symlink at `path` is refused outright —
/// pins are integrity data, and writing through a planted link would clobber
/// its target and let whoever controls that target steer the pin. The rename
/// replaces a directory entry and never follows a link, so a symlink planted
/// after the check cannot redirect the write either.
fn write_pin_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the pin is a symlink — refusing to follow it",
        ));
    }
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sandbox HOME so the pin lands in a temp dir, and serialize with other
    /// tests that mutate HOME.
    fn with_home<T>(f: impl FnOnce(&str) -> T) -> T {
        use crate::testutil::ENV_LOCK;
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", dir.path()) };
        unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };
        let out = f(dir.path().to_str().unwrap());
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        out
    }

    #[test]
    fn legacy_pin_keeps_only_the_downgrade_bit() {
        with_home(|_| {
            let path = pin_path("/proj/.murk").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                r#"{"signers":{"age1mallory":"vkMALLORY"},"was_signed":true}"#,
            )
            .unwrap();
            let pin = read("/proj/.murk").unwrap().unwrap();
            assert!(pin.was_signed);
            assert!(
                pin.signers.is_empty(),
                "TOFU registry entries carry no trust"
            );
            assert!(!pin.has_trust());
        });
    }

    #[test]
    fn corrupt_pin_is_an_error_not_an_empty_pin() {
        with_home(|_| {
            let path = pin_path("/proj/.murk").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "{not json").unwrap();
            assert!(read("/proj/.murk").unwrap_err().contains("corrupt"));
        });
    }

    #[test]
    fn dot_prefixed_paths_share_one_pin() {
        with_home(|home| {
            let dir = std::path::Path::new(home).join("repo");
            std::fs::create_dir_all(&dir).unwrap();
            let a = dir.join(".murk");
            let b = dir.join(".").join(".murk");
            assert_eq!(pin_path(a.to_str().unwrap()), pin_path(b.to_str().unwrap()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_pin_is_refused_and_its_target_untouched() {
        with_home(|home| {
            let path = pin_path("/proj/.murk").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let target = std::path::Path::new(home).join("victim");
            std::fs::write(&target, "original").unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();

            assert!(write("/proj/.murk", &TrustPin::default()).is_err());

            assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
            assert!(
                std::fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn new_pin_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        with_home(|_| {
            write("/proj/.murk", &TrustPin::default()).unwrap();
            let mode = std::fs::metadata(pin_path("/proj/.murk").unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        });
    }

    #[test]
    fn opt_out_reads_an_existing_pin_and_never_writes_it() {
        with_home(|_| {
            let pin = TrustPin {
                generation: 7,
                ..TrustPin::default()
            };
            write("/proj/.murk", &pin).unwrap();
            let file = pin_path("/proj/.murk").unwrap();
            let before = std::fs::read(&file).unwrap();

            unsafe { std::env::set_var("MURK_NO_SIGNER_PIN", "1") };
            let read_back = read("/proj/.murk");
            let wrote = write("/proj/.murk", &TrustPin::default());
            let updated = update("/proj/.murk", |_| Ok(Some(TrustPin::default())));
            let created = write("/other/.murk", &TrustPin::default());
            unsafe { std::env::remove_var("MURK_NO_SIGNER_PIN") };

            assert_eq!(read_back.unwrap().unwrap().generation, 7);
            assert!(wrote.unwrap_err().contains("MURK_NO_SIGNER_PIN"));
            assert!(updated.unwrap_err().contains("MURK_NO_SIGNER_PIN"));
            assert!(created.is_err());
            assert_eq!(std::fs::read(&file).unwrap(), before);
            assert!(!pin_path("/other/.murk").unwrap().exists());
        });
    }

    /// The pin file as murk 0.15 parses it: the fields it knows, each kept
    /// as written. serde drops every other field, as 0.15 does.
    #[derive(Serialize, Deserialize)]
    struct Pin015 {
        #[serde(default)]
        v: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        vault_id: serde_json::Value,
        #[serde(default)]
        generation: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        branches: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        ever_trusted: serde_json::Value,
        #[serde(default)]
        trusted: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        grants: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        groups: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        signers: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        added_by: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        removed: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        removed_on: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        removed_at_commit: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        head: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        branch_heads: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        accepted_pre_upgrade: serde_json::Value,
        #[serde(default)]
        was_signed: serde_json::Value,
    }

    /// A murk 0.15 component that shares `HOME` rewrites the pin: it parses
    /// the pin into its own struct, moves the counter, and writes it back.
    /// The fields new in this release live in the sidecar, which it never
    /// opens, so they survive: the sidecar's bytes are unchanged, and this
    /// release reads the recorded deletion and the identity fields back.
    #[test]
    fn row_r_l_oldpin_sidecar() {
        with_home(|home| {
            let repo = Path::new(home).join("repo");
            std::fs::create_dir_all(&repo).unwrap();
            let init = crate::git::git_command()
                .args(["init", "-q"])
                .current_dir(&repo)
                .status()
                .unwrap();
            assert!(init.success());
            let vault = repo.join(".murk");
            let vault = vault.to_str().unwrap();

            let mut pin = TrustPin {
                vault_id: "id-1".into(),
                generation: 3,
                trusted: BTreeSet::from(["age1alice".to_string()]),
                ..TrustPin::default()
            };
            pin.sidecar.deleted_groups.insert(
                "ops".into(),
                BTreeSet::from(["age1alice".to_string(), "age1bob".to_string()]),
            );
            pin.sidecar.identity_siblings.insert("copy.murk".into());
            pin.sidecar.revoked_grants_seen.insert(
                "age1grant".into(),
                BTreeSet::from(["00112233445566778899aabbccddeeff".to_string()]),
            );
            pin.sidecar.readmitted_grants.insert(
                "age1other".into(),
                BTreeSet::from(["ffeeddccbbaa99887766554433221100".to_string()]),
            );
            pin.sidecar.grants_live_on.insert(
                "age1live".into(),
                BTreeMap::from([("main".to_string(), String::new())]),
            );
            write(vault, &pin).unwrap();
            let written = read(vault).unwrap().unwrap();
            eprintln!("ROW R-L-oldpin:sidecar DECISIVE");
            assert_eq!(
                written.sidecar.path, ".murk",
                "the sidecar records the path"
            );
            assert!(
                !written.sidecar.repo_dir.is_empty(),
                "the sidecar records the repository"
            );

            let pin_file = existing_pin_path(vault).unwrap();
            let sidecar_file = sidecar_path(&pin_file);
            let sidecar_before = std::fs::read(&sidecar_file).unwrap_or_default();
            let mut old: Pin015 =
                serde_json::from_slice(&std::fs::read(&pin_file).unwrap()).unwrap();
            old.generation = serde_json::json!(4);
            std::fs::write(&pin_file, serde_json::to_string_pretty(&old).unwrap()).unwrap();

            let after = read(vault).unwrap().unwrap();
            assert_eq!(after.generation, 4, "the older component's write took");
            assert_eq!(
                std::fs::read(&sidecar_file).unwrap_or_default(),
                sidecar_before,
                "the sidecar's bytes are unchanged"
            );
            assert_eq!(
                after.sidecar.deleted_groups, written.sidecar.deleted_groups,
                "the recorded deletion survives"
            );
            assert_eq!(
                after.sidecar.identity_siblings, written.sidecar.identity_siblings,
                "the identity siblings survive"
            );
            assert_eq!(
                (&after.sidecar.repo_dir, &after.sidecar.path),
                (&written.sidecar.repo_dir, &written.sidecar.path),
                "the repository and path survive"
            );
            assert_eq!(
                (
                    &after.sidecar.revoked_grants_seen,
                    &after.sidecar.readmitted_grants,
                    &after.sidecar.grants_live_on
                ),
                (
                    &written.sidecar.revoked_grants_seen,
                    &written.sidecar.readmitted_grants,
                    &written.sidecar.grants_live_on
                ),
                "the revoked grants seen, the re-admitted ids and the live sightings survive"
            );
            assert!(
                !written.sidecar.revoked_grants_seen.is_empty(),
                "the sidecar holds the revoked grants seen"
            );
        });
    }

    /// A sidecar that records another vault id than the pin's is dropped:
    /// an older murk accepted another vault at this path, so the records
    /// belong to the old vault. The next write records the pin's id.
    #[test]
    fn a_sidecar_of_another_vault_id_is_dropped() {
        with_home(|_| {
            let mut pin = TrustPin {
                vault_id: "id-1".into(),
                ..TrustPin::default()
            };
            pin.sidecar
                .deleted_groups
                .insert("ops".into(), BTreeSet::from(["age1bob".to_string()]));
            write("/proj/.murk", &pin).unwrap();
            let pin_file = pin_path("/proj/.murk").unwrap();
            let mut other: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&pin_file).unwrap()).unwrap();
            other["vault_id"] = serde_json::json!("id-2");
            std::fs::write(&pin_file, other.to_string()).unwrap();

            let read_back = read("/proj/.murk").unwrap().unwrap();
            assert_eq!(read_back.sidecar, Sidecar::default());
            write("/proj/.murk", &read_back).unwrap();
            let sidecar: Sidecar =
                serde_json::from_slice(&std::fs::read(sidecar_path(&pin_file)).unwrap()).unwrap();
            assert_eq!(sidecar.vault_id, "id-2");
            assert!(sidecar.deleted_groups.is_empty());
        });
    }

    // -- publication under the pin lock --

    /// A vault file at `<home>/work/.murk` holding `old`, and its path.
    fn old_target(home: &str) -> String {
        let dir = Path::new(home).join("work");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join(".murk");
        std::fs::write(&target, b"old").unwrap();
        target.to_str().unwrap().to_string()
    }

    type Record = fn(Option<&TrustPin>, &crate::git::HeadState, Option<&str>) -> TrustPin;

    #[test]
    fn row_r_i5_race_reentrant() {
        // The real publish section runs to completion while it holds the
        // pin lock: the rename, then the sidecar and pin writes, which take
        // no lock. It never asks for the lock it holds.
        with_home(|home| {
            let vp = old_target(home);
            let (tx, rx) = std::sync::mpsc::channel();
            let thread_vp = vp.clone();
            std::thread::spawn(move || {
                let target = Path::new(&thread_vp);
                let snapshot = Snapshot::take(&thread_vp, target).unwrap();
                let staged = crate::vault::stage(target, &crate::testutil::empty_vault()).unwrap();
                let record: Record = |prior, _, _| TrustPin {
                    v: PIN_VERSION,
                    vault_id: "00112233445566778899aabbccddeeff".into(),
                    generation: 7,
                    ..prior.cloned().unwrap_or_default()
                };
                let published = snapshot.publish(staged, Some(record));
                let held = PIN_LOCKS_HELD.with(std::cell::Cell::get);
                let _ = tx.send((published, held));
            });
            let (published, held) = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the publish completes within 5 seconds");
            assert_eq!(published, Ok(Publish::Published));
            assert_eq!(held, 0, "the pin lock is released");
            assert!(
                crate::vault::read(Path::new(&vp)).is_ok(),
                "the result replaced the vault file"
            );
            eprintln!("ROW R-I5-race:reentrant DECISIVE");
            let pin = read(&vp).unwrap().expect("the own-save pin is written");
            assert_eq!(pin.generation, 7);
            let sidecar: Sidecar = serde_json::from_slice(
                &std::fs::read(sidecar_path(&pin_path(&vp).unwrap())).unwrap(),
            )
            .unwrap();
            assert_eq!(sidecar.vault_id, "00112233445566778899aabbccddeeff");
        });
    }

    #[test]
    fn row_r_i5_lockorder() {
        // Under the pin lock, a request for the vault lock or the pin lock
        // fails at once with the lock-order error. Neither blocks.
        with_home(|home| {
            let vp = old_target(home);
            let (tx, rx) = std::sync::mpsc::channel();
            let thread_vp = vp.clone();
            std::thread::spawn(move || {
                let target = Path::new(&thread_vp);
                let results = std::rc::Rc::new(std::cell::RefCell::new(None));
                let (seen, hook_vp) = (results.clone(), thread_vp.clone());
                test_hooks::set(&test_hooks::UNDER_LOCK, move || {
                    let vault_lock = crate::vault::lock(Path::new(&hook_vp))
                        .map(drop)
                        .map_err(|e| e.to_string());
                    let pin_update = update(&hook_vp, |_| {
                        Ok(Some(TrustPin {
                            v: PIN_VERSION,
                            generation: 99,
                            ..TrustPin::default()
                        }))
                    });
                    *seen.borrow_mut() = Some((vault_lock, pin_update));
                });
                let snapshot = Snapshot::take(&thread_vp, target).unwrap();
                let staged = crate::vault::stage(target, &crate::testutil::empty_vault()).unwrap();
                snapshot.publish(staged, None::<Record>).unwrap();
                let _ = tx.send(results.borrow_mut().take());
            });
            eprintln!("ROW R-I5-lockorder DECISIVE");
            let (vault_lock, pin_update) = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("neither lock request blocks")
                .expect("the hook ran under the pin lock");
            assert!(
                vault_lock.as_ref().is_err_and(|e| e.contains(LOCK_ORDER)),
                "{vault_lock:?}"
            );
            assert_eq!(pin_update, Err(LOCK_ORDER.to_string()));
            assert_eq!(read(&vp).unwrap(), None, "nothing wrote a pin");
        });
    }

    // -- the sidecar copy of the removal records --

    const BOB: &str = "age1bob";

    /// A pin for `/proj/.murk` whose file records bob as removed at 4 on
    /// `main`, as murk 0.15 writes it: no sidecar.
    fn pin_without_copy() -> PathBuf {
        let pin = TrustPin {
            v: PIN_VERSION,
            vault_id: "id-1".into(),
            generation: 4,
            trusted: BTreeSet::from(["age1alice".to_string()]),
            removed: BTreeMap::from([(BOB.to_string(), 4)]),
            removed_on: BTreeMap::from([(BOB.to_string(), BTreeSet::from(["main".to_string()]))]),
            removed_at_commit: BTreeMap::from([(BOB.to_string(), "c0ffee".to_string())]),
            ..TrustPin::default()
        };
        let file = pin_path("/proj/.murk").unwrap();
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, serde_json::to_string_pretty(&pin).unwrap()).unwrap();
        file
    }

    /// The sidecar of `pin_file` as written, or `None`.
    fn sidecar_on_disk(pin_file: &Path) -> Option<Sidecar> {
        let bytes = std::fs::read(sidecar_path(pin_file)).ok()?;
        Some(serde_json::from_slice(&bytes).unwrap())
    }

    /// How many times [`read`] went on to copy (the pin lock is taken only
    /// then), counted on this thread.
    fn count_copies() -> std::rc::Rc<std::cell::Cell<u32>> {
        let copies = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = copies.clone();
        test_hooks::set(&test_hooks::BEFORE_COPY, move || seen.set(seen.get() + 1));
        copies
    }

    #[test]
    fn row_r_l_oldpin_copy() {
        // (a) The first read copies a pin-file record into the sidecar and
        // leaves the pin file. (b) The next read finds nothing to copy: it
        // takes no lock and writes nothing.
        with_home(|_| {
            let file = pin_without_copy();
            let pin_bytes = std::fs::read(&file).unwrap();
            let copies = count_copies();
            read("/proj/.murk").unwrap().unwrap();
            eprintln!("ROW R-L-oldpin:copy DECISIVE");
            assert_eq!(copies.get(), 1);
            let sidecar = sidecar_on_disk(&file).expect("the first read writes the sidecar");
            let pin: TrustPin = serde_json::from_slice(&pin_bytes).unwrap();
            assert_eq!(sidecar.removals, pin.removal_records());
            assert_eq!(
                sidecar.vault_id, "id-1",
                "the copy records the pin's vault id"
            );
            assert_eq!(
                std::fs::read(&file).unwrap(),
                pin_bytes,
                "the pin file is unchanged"
            );

            let meta = std::fs::metadata(sidecar_path(&file)).unwrap();
            read("/proj/.murk").unwrap().unwrap();
            assert_eq!(copies.get(), 1, "the second read does not copy");
            let again = std::fs::metadata(sidecar_path(&file)).unwrap();
            assert_eq!(meta.modified().unwrap(), again.modified().unwrap());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(meta.ino(), again.ino(), "the sidecar was not rewritten");
            }
        });
    }

    #[test]
    fn row_r_l_oldpin_copy_union() {
        // A murk 0.15 component clears the record between the unlocked read
        // and the copy under the lock: the copy keeps it.
        with_home(|_| {
            let file = pin_without_copy();
            let hook_file = file.clone();
            test_hooks::set(&test_hooks::BEFORE_COPY, move || {
                let mut pin: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&hook_file).unwrap()).unwrap();
                pin["removed"] = serde_json::json!({});
                pin["removed_on"] = serde_json::json!({});
                pin["removed_at_commit"] = serde_json::json!({});
                std::fs::write(&hook_file, pin.to_string()).unwrap();
            });
            read("/proj/.murk").unwrap().unwrap();
            eprintln!("ROW R-L-oldpin:copy-union DECISIVE");
            let sidecar = sidecar_on_disk(&file).expect("the copy was written");
            assert_eq!(sidecar.removals.get(BOB).map(|r| r.at), Some(4));
            let pin = read("/proj/.murk").unwrap().unwrap();
            assert_eq!(pin.removed.get(BOB), Some(&4), "the record still applies");
        });
    }

    #[test]
    fn row_r_l_oldpin_held() {
        // A pin update that writes no pin still copies the record.
        with_home(|_| {
            let file = pin_without_copy();
            let pin_bytes = std::fs::read(&file).unwrap();
            update("/proj/.murk", |_| Ok(None)).unwrap();
            eprintln!("ROW R-L-oldpin:held DECISIVE");
            let sidecar = sidecar_on_disk(&file).expect("the update copies the record");
            assert_eq!(sidecar.removals.get(BOB).map(|r| r.at), Some(4));
            assert_eq!(
                std::fs::read(&file).unwrap(),
                pin_bytes,
                "the pin file is unchanged"
            );
        });
    }

    #[test]
    fn row_r_l_oldpin_removals() {
        // A murk 0.15 component clears bob's record in the pin file and
        // trusts him again. The sidecar, which it never opens, keeps the
        // copy, and a read lays it over the pin file.
        with_home(|_| {
            let file = pin_without_copy();
            read("/proj/.murk").unwrap().unwrap();
            let sidecar_bytes = std::fs::read(sidecar_path(&file)).unwrap();
            let mut old: Pin015 = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            old.removed = serde_json::json!({});
            old.removed_on = serde_json::json!({"age1bob": ["feature"]});
            old.removed_at_commit = serde_json::Value::Null;
            old.trusted = serde_json::json!(["age1alice", BOB]);
            old.generation = serde_json::json!(13);
            std::fs::write(&file, serde_json::to_string_pretty(&old).unwrap()).unwrap();

            let pin = read("/proj/.murk").unwrap().unwrap();
            eprintln!("ROW R-L-oldpin:removals DECISIVE");
            assert_eq!(pin.removed.get(BOB), Some(&4));
            assert_eq!(
                pin.removed_on.get(BOB),
                Some(&BTreeSet::from(["main".to_string()])),
                "the copy's branches replace those of a cleared record"
            );
            assert_eq!(
                pin.removed_at_commit.get(BOB).map(String::as_str),
                Some("c0ffee")
            );
            assert!(!pin.trusted.contains(BOB), "bob is not trusted");
            assert_eq!(std::fs::read(sidecar_path(&file)).unwrap(), sidecar_bytes);
        });
    }

    #[test]
    fn the_overlay_takes_the_wider_removal() {
        let mut pin = TrustPin {
            removed: BTreeMap::from([(BOB.to_string(), 4), ("age1carol".to_string(), 6)]),
            removed_on: BTreeMap::from([
                (BOB.to_string(), BTreeSet::from(["main".to_string()])),
                (
                    "age1carol".to_string(),
                    BTreeSet::from(["main".to_string()]),
                ),
            ]),
            trusted: BTreeSet::from([BOB.to_string()]),
            ..TrustPin::default()
        };
        let records = BTreeMap::from([
            (
                BOB.to_string(),
                RemovalRecord {
                    at: 7,
                    on: Some(BTreeSet::from(["dev".to_string()])),
                    at_commit: Some("c1".into()),
                },
            ),
            (
                "age1carol".to_string(),
                RemovalRecord {
                    at: 2,
                    on: None,
                    at_commit: None,
                },
            ),
        ]);
        let restored = pin.overlay_removals(&records);
        assert_eq!(
            restored,
            vec![BOB.to_string()],
            "bob was trusted in the pin file"
        );
        assert_eq!(
            pin.removed,
            BTreeMap::from([(BOB.to_string(), 7), ("age1carol".into(), 6)])
        );
        assert_eq!(
            pin.removed_on.get(BOB),
            Some(&BTreeSet::from(["dev".to_string(), "main".to_string()]))
        );
        assert_eq!(
            pin.removed_on.get("age1carol"),
            None,
            "no entry applies everywhere"
        );
        assert!(pin.trusted.is_empty());
    }

    #[test]
    fn row_r_l_oldpin_order() {
        // The sidecar is written before the pin file. (a) A write that adds
        // a record and fails after the sidecar leaves the record in the
        // sidecar, so it applies. (b) A write that clears it and fails there
        // leaves it in the pin file: the next read keeps it and copies it
        // back, and the user runs the command again.
        with_home(|_| {
            let file = pin_path("/proj/.murk").unwrap();
            let pin = TrustPin {
                v: PIN_VERSION,
                vault_id: "id-1".into(),
                trusted: BTreeSet::from(["age1alice".to_string()]),
                ..TrustPin::default()
            };
            write("/proj/.murk", &pin).unwrap();
            let mut added = pin.clone();
            added.removed.insert(BOB.to_string(), 4);
            test_hooks::FAIL_AFTER_SIDECAR.with(|f| f.set(true));
            let failed = write("/proj/.murk", &added);
            test_hooks::FAIL_AFTER_SIDECAR.with(|f| f.set(false));
            assert!(failed.is_err());
            eprintln!("ROW R-L-oldpin:order DECISIVE");
            assert!(sidecar_on_disk(&file).unwrap().removals.contains_key(BOB));
            let on_disk: TrustPin = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            assert!(
                !on_disk.removed.contains_key(BOB),
                "the pin file was not written"
            );
            let read_back = read("/proj/.murk").unwrap().unwrap();
            assert_eq!(
                read_back.removed.get(BOB),
                Some(&4),
                "(a) the record applies"
            );

            write("/proj/.murk", &read_back).unwrap();
            let mut cleared = read("/proj/.murk").unwrap().unwrap();
            cleared.removed.remove(BOB);
            test_hooks::FAIL_AFTER_SIDECAR.with(|f| f.set(true));
            let failed = write("/proj/.murk", &cleared);
            test_hooks::FAIL_AFTER_SIDECAR.with(|f| f.set(false));
            assert!(failed.is_err());
            assert!(sidecar_on_disk(&file).unwrap().removals.is_empty());
            let pin = read("/proj/.murk").unwrap().unwrap();
            assert_eq!(
                pin.removed.get(BOB),
                Some(&4),
                "(b) the record still applies"
            );
            let copy = sidecar_on_disk(&file).unwrap();
            assert_eq!(copy.removals.get(BOB).map(|r| r.at), Some(4));
            write("/proj/.murk", &pin).unwrap();
            let on_disk: TrustPin = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            assert_eq!(
                on_disk.removed.get(BOB),
                Some(&4),
                "the next write mirrors it"
            );
        });
    }

    #[test]
    fn row_r_l_oldpin_other_vault() {
        // An older murk accepted another vault at this path: the pin records
        // id-2, the sidecar id-1 with bob's removal. The sidecar is dropped,
        // so the new vault is judged with no record for bob.
        with_home(|_| {
            let file = pin_without_copy();
            read("/proj/.murk").unwrap().unwrap();
            let mut pin: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            pin["vault_id"] = serde_json::json!("id-2");
            pin["removed"] = serde_json::json!({});
            pin["removed_on"] = serde_json::json!({});
            pin["removed_at_commit"] = serde_json::json!({});
            std::fs::write(&file, pin.to_string()).unwrap();
            let read_back = read("/proj/.murk").unwrap().unwrap();
            assert_eq!(read_back.vault_id, "id-2");
            eprintln!("ROW R-L-oldpin:other-vault DECISIVE");
            assert!(
                read_back.removed.is_empty(),
                "no record of the old vault applies"
            );
            assert_eq!(read_back.sidecar, Sidecar::default());
        });
    }

    #[test]
    fn row_r_l_oldpin_no_pin() {
        // The pin file is gone, its sidecar is not. The sidecar's records
        // apply to the vault of its id, with no trust decision, and to no
        // other vault.
        with_home(|home| {
            let dir = Path::new(home).join("proj");
            std::fs::create_dir_all(&dir).unwrap();
            let vault_file = dir.join(".murk");
            let vp = vault_file.to_str().unwrap();
            let mut vault = crate::testutil::empty_vault();
            vault.vault_id = "00112233445566778899aabbccddeeff".into();
            std::fs::write(&vault_file, serde_json::to_string(&vault).unwrap()).unwrap();
            let pin = TrustPin {
                v: PIN_VERSION,
                vault_id: "00112233445566778899aabbccddeeff".into(),
                trusted: BTreeSet::from(["age1alice".to_string()]),
                removed: BTreeMap::from([(BOB.to_string(), 4)]),
                ..TrustPin::default()
            };
            write(vp, &pin).unwrap();
            std::fs::remove_file(pin_path(vp).unwrap()).unwrap();

            eprintln!("ROW R-L-oldpin:no-pin DECISIVE");
            let read_back = read(vp).unwrap().expect("the sidecar applies");
            assert_eq!(read_back.removed.get(BOB), Some(&4));
            assert!(!read_back.has_trust(), "no trust decision comes with it");

            vault.vault_id = "ffeeddccbbaa99887766554433221100".into();
            std::fs::write(&vault_file, serde_json::to_string(&vault).unwrap()).unwrap();
            assert_eq!(read(vp).unwrap(), None, "another vault's file reads no pin");
        });
    }

    #[test]
    fn a_read_under_the_pin_lock_is_a_lock_order_error() {
        with_home(|_| {
            pin_without_copy();
            let held = lock("/proj/.murk").unwrap();
            eprintln!("ROW R-I5-lockorder:read DECISIVE");
            assert_eq!(read("/proj/.murk"), Err(LOCK_ORDER.to_string()));
            drop(held);
            assert!(read("/proj/.murk").unwrap().is_some());
        });
    }
}
