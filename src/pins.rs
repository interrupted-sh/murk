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
    /// vault listing the key at that generation or below, or signed by it, is
    /// refused; a newer vault from a trusted signer that lists it again there,
    /// or `murk trust --re-add`, takes it out.
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

/// Read the pin for `vault_path`, with its sidecar (see [`Sidecar`]).
/// `Ok(None)` when there is no home directory or no pin exists yet.
/// `MURK_NO_SIGNER_PIN` does not stop the read. A pin or sidecar that exists
/// but cannot be read or parsed is an error: silently treating it as empty
/// would forget a rollback high-water mark or a recorded deletion.
pub fn read(vault_path: &str) -> Result<Option<TrustPin>, String> {
    let mut found = None;
    for path in pin_paths(vault_path) {
        match std::fs::read_to_string(&path) {
            Ok(c) => {
                found = Some((path, c));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot read trust pin {}: {e}", path.display())),
        }
    }
    let Some((path, contents)) = found else {
        return Ok(None);
    };
    let mut pin: TrustPin = serde_json::from_str(&contents).map_err(|e| {
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
        pin.sidecar = read_sidecar(&path, &pin.vault_id)?;
    }
    drop_unusable_signer_keys(&mut pin, &path);
    Ok(Some(pin))
}

/// The sidecar file of the pin file `pin_file`: `<hash>.lineage.json`.
pub fn sidecar_path(pin_file: &Path) -> PathBuf {
    pin_file.with_extension("lineage.json")
}

/// The sidecar of the pin file `pin_file`, whose vault id is `pin_id`. A
/// missing sidecar reads as empty, and so does one that records another
/// vault id: an older murk accepted another vault at this path, so the
/// sidecar's records are not this vault's. murk says so once, and the next
/// pin write replaces the sidecar.
fn read_sidecar(pin_file: &Path, pin_id: &str) -> Result<Sidecar, String> {
    static WARNED: std::sync::Mutex<BTreeSet<PathBuf>> = std::sync::Mutex::new(BTreeSet::new());

    let path = sidecar_path(pin_file);
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Sidecar::default()),
        Err(e) => return Err(format!("cannot read trust pin {}: {e}", path.display())),
    };
    let sidecar: Sidecar = serde_json::from_str(&contents).map_err(|e| {
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
    use fs2::FileExt;

    if pin_writes_off() {
        return Err(
            "MURK_NO_SIGNER_PIN is set, so murk does not write the trust pin. Unset it to record trust here".to_string(),
        );
    }
    let lock = open_lock(pin_file)?;
    let removed = [pin_file.to_path_buf(), sidecar_path(pin_file)]
        .iter()
        .try_for_each(|path| match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("cannot remove {}: {e}", path.display()))
            }
            _ => Ok(()),
        });
    let _ = FileExt::unlock(&lock);
    removed
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
/// narrows. The sidecar takes the pin's vault id and this vault's place in
/// its repository. Errors when pinning is unavailable or the write fails, so
/// a caller recording an explicit trust decision can say so.
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
    let (repo_dir, rel) = vault_location(vault_path).unwrap_or_default();
    let sidecar = Sidecar {
        v: SIDECAR_VERSION,
        vault_id: pin.vault_id.clone(),
        repo_dir,
        path: rel,
        ..std::mem::take(&mut pin.sidecar)
    };
    let sidecar_file = sidecar_path(&path);
    let json = serde_json::to_string_pretty(&sidecar).map_err(|e| format!("trust pin: {e}"))?;
    write_pin_file(&sidecar_file, json.as_bytes())
        .map_err(|e| format!("cannot write trust pin {}: {e}", sidecar_file.display()))?;
    let json = serde_json::to_string_pretty(&pin).map_err(|e| format!("trust pin: {e}"))?;
    write_pin_file(&path, json.as_bytes())
        .map_err(|e| format!("cannot write trust pin {}: {e}", path.display()))
}

/// Read, change and write the pin for `vault_path` and its sidecar under an
/// exclusive lock (`<pin>.lock`), so concurrent murk processes — worktrees of
/// one repository share a pin — never write from a stale read: a lowered
/// rollback mark, or keys and grants another process just learned, lost. `f`
/// gets the pin as it is now and returns the pin to write, or `None` to leave
/// it, or an error to report.
pub fn update<F>(vault_path: &str, f: F) -> Result<(), String>
where
    F: FnOnce(Option<&TrustPin>) -> Result<Option<TrustPin>, String>,
{
    use fs2::FileExt;

    let path = writable_pin_path(vault_path)?;
    let lock = open_lock(&path)?;
    let current = read(vault_path)?;
    let result = match f(current.as_ref())? {
        Some(pin) => write(vault_path, &pin),
        None => Ok(()),
    };
    let _ = FileExt::unlock(&lock);
    result
}

/// Open and take the exclusive lock of the pin file `path`: `<pin>.lock`.
fn open_lock(path: &Path) -> Result<std::fs::File, String> {
    use fs2::FileExt;

    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid trust pin path {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    let lock_path = path.with_extension("lock");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = opts
        .open(&lock_path)
        .map_err(|e| format!("cannot open {}: {e}", lock_path.display()))?;
    lock.lock_exclusive()
        .map_err(|e| format!("cannot lock {}: {e}", lock_path.display()))?;
    Ok(lock)
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
            write(vault, &pin).unwrap();
            let written = read(vault).unwrap().unwrap();
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
}
