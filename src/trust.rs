// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Whether this machine trusts a loaded vault.
//!
//! A valid signature only proves that *some* recipient listed in the file
//! signed it, and the file chooses its own recipients and, for age keys, the
//! verifying key each recipient signs with (the signer registry). So
//! acceptance is anchored in state the repo cannot touch: the local trust pin
//! ([`crate::pins`]) or the `MURK_TRUSTED_SIGNERS` environment variable. The
//! rules, applied on every keyed load before any secret is handed out or
//! re-encrypted:
//!
//! 1. An unsigned vault is refused when the loading key could sign it. Only a
//!    key that cannot sign (ssh-rsa, hardware/plugin) loads it, with a warning.
//! 2. A vault this machine accepted signed that is now unsigned is refused.
//! 3. The signer must be a trusted signer: in `MURK_TRUSTED_SIGNERS` when set,
//!    otherwise in the pin's set (the non-grant recipients of the last vault
//!    accepted here). With neither, the vault is refused until `murk trust`.
//! 4. An age signer's verifying key (from the registry) must be the one pinned
//!    for it, or the one `MURK_TRUSTED_SIGNERS` gives. A trusted signer with no
//!    pinned key yet (a teammate's first write) is refused until `murk trust`
//!    confirms the key: trust on first use. A different key for a pinned
//!    signer is refused outright — an age key's verifying key is derived from
//!    its secret, so it cannot legitimately change. ssh-ed25519 signers carry
//!    their verifying key in the recipient string.
//! 5. An agent-grant key never counts as a signer, and a key seen as a grant
//!    that now sits in the recipients without its grant is refused.
//! 6. The vault id must match the pinned one, and the save counter must not be
//!    below the highest accepted ("rolled back"). A murk ≤ 0.13 signature is
//!    refused where this machine has seen the vault in 0.14 form: on the
//!    branch checked out, or outside git (see [`upgraded_at`]). Elsewhere it
//!    loads as history.
//! 7. A group membership change must be signed by a member of that group as
//!    pinned (removing a member who left the vault entirely is exempt).
//! 8. A key an accepted vault removed stays removed: a vault signed by it is
//!    refused everywhere, and a vault listing it, at any generation, is
//!    refused where the removal applies (see [`removal_applies`]). Only this
//!    machine's own save that adds it (`circle authorize`) or `murk trust
//!    --re-add` brings it back. The pin's sidecar keeps a copy of each
//!    record, so a murk 0.15 component that clears it does not undo it.
//! 9. The generation may rise at most [`MAX_GENERATION_STEP`] above the mark
//!    and never past [`MAX_GENERATION`]; a different vault with the counter
//!    this machine accepted on the branch is a fork.
//!
//! An accepted vault that is the newest this machine has seen, on a branch it
//! accepted before (or outside git), replaces the pin's trusted set, grants
//! and groups with its own, and raises the counter; any other accepted load
//! is history and only narrows the pin (see [`Acceptance`]). Its registry
//! entries for trusted recipients are pinned where no key was pinned before —
//! believed because the vault carrying them was signed by an already-trusted
//! signer (or confirmed by `murk trust`), and only while that signer stays
//! trusted. A pinned key is never replaced. `murk trust` accepts a refused
//! vault on the user's say-so after showing what changed.

use std::collections::{BTreeMap, BTreeSet};

pub use crate::git::HeadState;
use crate::pins::{self, TrustPin};
use crate::recipients::canonical_recipient;
use crate::types;

/// Environment variable naming the keys trusted to sign, comma or newline
/// separated. When set it replaces the pin's trusted set (for CI runners and
/// other machines without a pin). Grant keys listed here still never count.
/// See [`parse_trusted_signer`] for the entry format.
pub const TRUSTED_SIGNERS_VAR: &str = "MURK_TRUSTED_SIGNERS";

/// Environment variable naming the vault a process expects and the oldest
/// revision of it the process may load: `<vault id>:<minimum generation>`.
/// A runner with no pin (CI) sets it from a protected variable to get an id
/// and a rollback check. When set, every keyed load, grant load and merge
/// side checks it, with or without a pin. See [`env_expected_vault`].
pub const EXPECTED_VAULT_VAR: &str = "MURK_EXPECTED_VAULT";

/// The value of [`EXPECTED_VAULT_VAR`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedVault {
    pub vault_id: String,
    pub min_generation: u64,
}

impl ExpectedVault {
    /// Why a vault whose id is `found_id` (the id a load judges it by)
    /// and whose counter is `found_generation` is not the one expected: the
    /// id first, then the minimum.
    pub fn mismatch(&self, found_id: &str, found_generation: u64) -> Option<ExpectedMismatch> {
        if found_id != self.vault_id {
            return Some(ExpectedMismatch::OtherVault {
                expected: self.vault_id.clone(),
                found: found_id.to_string(),
            });
        }
        (found_generation < self.min_generation).then_some(ExpectedMismatch::BelowMinimum {
            minimum: self.min_generation,
            found: found_generation,
        })
    }
}

/// How a vault differs from what [`EXPECTED_VAULT_VAR`] names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedMismatch {
    /// The vault id differs from the expected one.
    OtherVault { expected: String, found: String },
    /// The generation is below the expected minimum.
    BelowMinimum { minimum: u64, found: u64 },
}

impl ExpectedMismatch {
    /// The refusal message for the vault at `vault_path`.
    pub fn message(&self, vault_path: &str) -> String {
        match self {
            ExpectedMismatch::OtherVault { expected, found } => format!(
                "vault {vault_path} is not the vault that {EXPECTED_VAULT_VAR} names: its vault id is {}, and {EXPECTED_VAULT_VAR} expects {expected} — another vault's file may have been copied over it\ncheck out the correct vault file, or set {EXPECTED_VAULT_VAR} again from the correct vault",
                if found.is_empty() {
                    "empty".to_string()
                } else {
                    crate::validate::show(found)
                }
            ),
            ExpectedMismatch::BelowMinimum { minimum, found } => format!(
                "vault {vault_path} is older than {EXPECTED_VAULT_VAR} allows: its generation is {found}, and the minimum is {minimum} — an older revision may have been replayed\ncheck out the current vault, or set {EXPECTED_VAULT_VAR} again from the current vault"
            ),
        }
    }
}

/// The largest generation accepted: 2^53 − 1, the largest integer every JSON
/// reader holds exactly. A vault above it is refused as tampering, so no
/// signer can push the counter to where it stops increasing.
pub const MAX_GENERATION: u64 = (1 << 53) - 1;

/// How far above this machine's mark a loaded vault's generation may be.
/// Every save adds one and a merge one past its sides, so a team needs a
/// million saves between two loads here to reach it; a vault that jumps
/// further is refused until `murk trust`.
pub const MAX_GENERATION_STEP: u64 = 1_000_000;

/// The generation of a new vault written over `highest` (the higher of the
/// vault's counter and this machine's mark): one past it, or `None` when that
/// is above [`MAX_GENERATION`]. Every machine would refuse such a vault, so
/// the save or merge must refuse to write it instead.
pub(crate) fn next_generation(highest: u64) -> Option<u64> {
    highest.checked_add(1).filter(|&g| g <= MAX_GENERATION)
}

/// How to recover when [`next_generation`] refuses a write to `vault_path`,
/// given this machine's pin for it. Restoring an earlier vault and trusting
/// it lowers the mark a save is numbered from outside git, and on a branch
/// whose mark is below the cap. Inside a git checkout, `murk trust` lowers only
/// the branch's mark, so a machine whose overall mark is at the cap must
/// delete its pin first.
pub(crate) fn counter_limit_recovery(vault_path: &str, pin: Option<&TrustPin>) -> String {
    let in_git = head_of(vault_path) != HeadState::NotARepo;
    if !in_git {
        return format!("restore an earlier copy of {vault_path} and run `murk trust`");
    }
    let restore = format!("restore an earlier {vault_path} from git and run `murk trust`");
    let at_cap = pin.is_some_and(|p| p.generation >= MAX_GENERATION);
    match pins::existing_pin_path(vault_path) {
        Some(file) if at_cap => format!(
            "this machine accepted a vault at generation {MAX_GENERATION}, which `murk trust` does not undo in a git checkout: delete this vault's trust pin ({}), then {restore}",
            file.display()
        ),
        _ => restore,
    }
}

/// Trusted signers supplied from outside the vault and the pin: canonical
/// recipient → the verifying key its signatures must verify under (`None` for
/// ssh-ed25519, whose recipient string is its verifying key).
pub type TrustedSigners = BTreeMap<String, Option<String>>;

/// Group name → member pubkeys, as stored in the meta.
pub type Groups = BTreeMap<String, Vec<String>>;

/// The parts of a decrypted vault the trust rules look at.
pub struct Loaded<'a> {
    pub vault: &'a types::Vault,
    pub signature: &'a types::SignatureState,
    /// For an age signature, the registry verifying key it verified against.
    /// `None` for ssh-ed25519 signers and unsigned vaults.
    pub signer_vk: Option<&'a str>,
    /// The signer registry (age pubkey → verifying key) carried in the meta.
    /// Written by the vault's author: its entries are pinned only once the
    /// vault is accepted, and never replace a pinned key.
    pub registry: &'a BTreeMap<String, String>,
    /// Pubkey → display name (attacker-chosen: always shown next to the key).
    pub names: &'a std::collections::HashMap<String, String>,
    pub groups: &'a BTreeMap<String, Vec<String>>,
    pub grants: &'a BTreeMap<String, types::GrantEntry>,
    /// The vault's own revoked grant set (see
    /// [`types::Meta::revoked_grants`]): canonical grant key → revocation ids.
    pub revoked: &'a types::RevokedGrants,
    /// Whether the loading identity can sign (age or ssh-ed25519).
    pub loader_can_sign: bool,
    /// The loading key, when it is known to be an operator and so can never be
    /// an agent grant: an ssh or plugin identity (grants are minted age keys).
    pub operator_key: Option<String>,
}

/// Why a vault was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Signed, but this machine has no trust decision for the vault yet.
    NotYetTrusted { signer: String },
    /// Signed by a key outside the trusted set.
    UntrustedSigner { signer: String },
    /// Signed by a key this machine has seen as an agent grant.
    GrantSigner { signer: String },
    /// A key seen as an agent grant is a recipient again without its grant.
    GrantWithoutRecord { key: String },
    /// No signature, and the loading key could have signed it.
    Unsigned,
    /// No signature, but a signed version was accepted here before.
    Downgraded,
    /// No signature, and this machine has no trust decision for the vault.
    UnsignedNotYetTrusted,
    /// No signature, and it lists a recipient that is not in the pin's
    /// trusted set (nor a recorded grant whose record it carries).
    UnsignedRecipient { key: String },
    /// No signature, and it carries a grant this machine has not recorded.
    UnsignedGrant { key: String },
    /// No signature, and a group's membership differs from the pinned one.
    UnsignedGroupChange { group: String },
    /// The save counter is below the highest accepted here.
    RolledBack { pinned: u64, found: u64 },
    /// A vault with a murk 0.13 (view 1) signature where this machine has
    /// already seen the vault written by murk 0.14 (see [`upgraded_at`]): on
    /// the branch checked out (`on_branch`), or outside git. View 1 covers
    /// neither the vault id nor the counter, so there it can only be an older
    /// revision.
    PreUpgrade { on_branch: bool },
    /// The vault id differs from the pinned one.
    OtherVault { pinned: String, found: String },
    /// A group's membership was changed by someone who was not a member.
    GroupChange { group: String, signer: String },
    /// An age signature by a trusted signer whose verifying key this machine
    /// has not confirmed yet.
    UnconfirmedSignerKey { signer: String, vk: String },
    /// An age signature whose verifying key differs from the one pinned (or
    /// given in `MURK_TRUSTED_SIGNERS`) for its signer.
    SignerKeyChanged { signer: String },
    /// An agent grant record names a key that is an operator: a signer this
    /// machine trusts (or trusted), or a key with a signing-key registry
    /// entry. Grants get freshly minted keys, so this is tampering — and
    /// recording it would mark the operator as a grant here.
    GrantBindsOperator { grant: String, key: String },
    /// The vault is signed by, or lists, a key this machine recorded as
    /// removed (`removed_at`), whatever its generation `found`. Only this
    /// machine's own save that adds the key or `murk trust --re-add` naming
    /// the key brings it back.
    RemovedKey {
        key: String,
        removed_at: u64,
        found: u64,
        signer: bool,
    },
    /// A different vault with the generation this machine accepted on the
    /// branch (or outside git): the branch was rewritten, or another save
    /// with the same counter replaced the accepted one.
    Forked { generation: u64 },
    /// The generation is more than [`MAX_GENERATION_STEP`] above the mark.
    GenerationJump { pinned: u64, found: u64 },
    /// The generation is above [`MAX_GENERATION`].
    GenerationOutOfRange { found: u64 },
    /// The vault is not the one `MURK_EXPECTED_VAULT` names, or is older
    /// than its minimum.
    NotExpected(ExpectedMismatch),
    /// Another vault file tracked in this checkout, or another path's pin on
    /// this machine, carries the same vault id, and this path is not the one
    /// this machine trusts for it (see [`shared_identity`]). `others` are
    /// those paths. `retired_by` is the path whose pin names this one in its
    /// `identity_siblings`. Plain `murk trust` never accepts it: only `murk
    /// trust --shares-identity-with` after review.
    SharedVaultId {
        others: Vec<String>,
        retired_by: Option<String>,
    },
    /// The vault lists `key` as a recipient without a grant record for it,
    /// and this machine holds `key` as a revoked agent grant (`ids`, see
    /// [`tombstoned`]). Refused on every load.
    RevokedGrantRecipient { key: String, ids: Vec<String> },
    /// The vault holds a grant record or an `agents` entry for `key`, which
    /// this machine holds as a revoked agent grant (`ids`). Refused on a load
    /// accepted as current (see [`is_current`]); a history load warns.
    RevokedGrant { key: String, ids: Vec<String> },
}

impl Refusal {
    /// Whether `murk trust` may accept this refusal. Grant-signed vaults never
    /// are: an agent grant is read-only by design. Nor is a changed verifying
    /// key: an age key's verifying key is derived from its secret, so a
    /// different one for the same recipient is a forgery. Nor a grant bound
    /// to an operator key, which is tampering, nor a generation past
    /// [`MAX_GENERATION`], nor a vault `MURK_EXPECTED_VAULT` refuses (the
    /// variable, not this machine, decides it), nor a vault that shares its
    /// id with another path (only `murk trust --shares-identity-with`
    /// accepts it). A removed key is accepted only when named (see
    /// [`Refusal::RemovedKey`]). A revoked agent grant is accepted only
    /// after `murk trust --re-add` re-admits its revocation ids.
    pub fn acceptable(&self) -> bool {
        !matches!(
            self,
            Refusal::GrantSigner { .. }
                | Refusal::GrantWithoutRecord { .. }
                | Refusal::SignerKeyChanged { .. }
                | Refusal::GrantBindsOperator { .. }
                | Refusal::GenerationOutOfRange { .. }
                | Refusal::NotExpected(_)
                | Refusal::SharedVaultId { .. }
                | Refusal::RevokedGrantRecipient { .. }
                | Refusal::RevokedGrant { .. }
        )
    }
}

/// The outcome of checking a loaded vault against this machine's trust state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Signed by a trusted signer and consistent with the pin.
    Trusted,
    /// Unsigned, loaded by a key that cannot sign: allowed with a warning.
    UnsignedAllowed,
    Refused(Refusal),
}

/// A verdict plus what it was computed against.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub verdict: Verdict,
    /// The pin as read (`None` when absent or pinning is unavailable).
    pub pin: Option<TrustPin>,
    /// Trusted signers from the environment, when set.
    pub env_signers: Option<TrustedSigners>,
    /// The signer set the verdict used in place of the pin's (environment
    /// and anchor together), when either was given.
    pub external: Option<TrustedSigners>,
    /// `MURK_EXPECTED_VAULT`, when set: the verdict refuses another vault
    /// and a revision below its minimum.
    pub expected: Option<ExpectedVault>,
    /// Other tracked vault files with the same vault id as this one, which
    /// this machine trusts at this path: a load warns about each (see
    /// [`shared_identity_warning`]).
    pub shared_with: Vec<String>,
}

impl Assessment {
    /// The ssh-ed25519 keys (canonical `ssh-ed25519 <blob>` form) this
    /// assessment treats as trusted signers of the vault: the environment and
    /// anchor set when there is one, otherwise the pin's trusted set, minus
    /// every agent-grant key (`grants` are the vault's own; the pin knows the
    /// ones seen before). Empty when nothing is trusted yet. Only these keys
    /// can sign a git commit, so this is the set a commit's signer is judged
    /// against.
    pub fn trusted_ssh_signers(&self, grants: &BTreeMap<String, types::GrantEntry>) -> Vec<String> {
        let keys: Vec<&String> = match (&self.external, self.pin.as_ref().filter(|p| p.has_trust()))
        {
            (Some(external), _) => external.keys().collect(),
            (None, Some(pin)) => pin.trusted.iter().collect(),
            (None, None) => return Vec::new(),
        };
        let mut grant = grant_keys(grants);
        if let Some(pin) = &self.pin {
            grant.extend(pin.grants.iter().cloned());
        }
        keys.into_iter()
            .map(|k| canonical_recipient(k).into_owned())
            .filter(|k| k.starts_with("ssh-ed25519 ") && !grant.contains(k))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Parse one trusted-signer entry, the format `MURK_TRUSTED_SIGNERS` and a
/// grant key file's anchor use:
///
/// - an age signer is `age1…:<verifying key>`: the recipient, a colon, and the
///   base64 Ed25519 verifying key (`murk trust --print-key` prints this line);
/// - an ssh-ed25519 signer is its public key line (`ssh-ed25519 AAAA… [comment]`),
///   which is its own verifying key.
pub fn parse_trusted_signer(entry: &str) -> Result<(String, Option<String>), String> {
    let entry = entry.trim();
    let (key, vk) = match entry.rsplit_once(':') {
        Some((key, vk)) if !key.starts_with("ssh-") => (key.trim(), Some(vk.trim())),
        _ => (entry, None),
    };
    if crate::crypto::parse_recipient(key).is_err() {
        return Err(format!("not a public key: {}", crate::truncate_pubkey(key)));
    }
    let is_ssh = key.starts_with("ssh-");
    if is_ssh && !key.starts_with("ssh-ed25519 ") {
        return Err(format!(
            "{} cannot sign, so it cannot be a trusted signer",
            crate::truncate_pubkey(key)
        ));
    }
    if is_ssh && let Err(why) = crate::signing::ed25519_verifying_key_b64_from_ssh_recipient(key) {
        return Err(format!(
            "{} cannot be a trusted signer: {why}",
            crate::truncate_pubkey(key)
        ));
    }
    match vk {
        Some(vk) => match crate::signing::check_verifying_key(vk) {
            Ok(_) => Ok((canonical_recipient(key).into_owned(), Some(vk.to_string()))),
            Err(why) => Err(format!(
                "{}: unusable verifying key: {why}",
                crate::truncate_pubkey(key)
            )),
        },
        None if is_ssh => Ok((canonical_recipient(key).into_owned(), None)),
        None => Err(format!(
            "{} needs its verifying key: write it as `age1…:<verifying key>` (`murk trust --print-key` prints it)",
            crate::truncate_pubkey(key)
        )),
    }
}

/// Parse `MURK_TRUSTED_SIGNERS`. `Ok(None)` when unset or empty; an invalid
/// entry is an error (fail closed rather than trust less than the operator
/// meant and confuse them, or more than they meant).
pub fn env_trusted_signers() -> Result<Option<TrustedSigners>, String> {
    let Ok(raw) = std::env::var(TRUSTED_SIGNERS_VAR) else {
        return Ok(None);
    };
    let mut out = TrustedSigners::new();
    for entry in raw
        .split([',', '\n'])
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        let (key, vk) =
            parse_trusted_signer(entry).map_err(|e| format!("{TRUSTED_SIGNERS_VAR}: {e}"))?;
        out.insert(key, vk);
    }
    Ok((!out.is_empty()).then_some(out))
}

/// Parse a value of [`EXPECTED_VAULT_VAR`]: `<vault id>:<minimum generation>`,
/// the id as 32 lowercase hex characters and the generation as a decimal
/// number no larger than [`MAX_GENERATION`]. A third part (a revision) is an
/// error: this release does not check revisions, and a value that names one
/// must not seem to give that check. An empty value is an error too: it
/// usually comes from a CI secret that is missing, and must not turn the
/// check off.
pub fn parse_expected_vault(value: &str) -> Result<ExpectedVault, String> {
    let usage = "set it to <vault id>:<minimum generation>";
    if value.trim().is_empty() {
        return Err(format!(
            "{EXPECTED_VAULT_VAR} is set but empty — a CI secret or variable is usually missing\n{usage}, or unset {EXPECTED_VAULT_VAR} to turn the check off"
        ));
    }
    let parts: Vec<&str> = value.trim().split(':').collect();
    let (id, generation) = match parts.as_slice() {
        [id, generation] => (*id, *generation),
        [_, _, _] => {
            return Err(format!(
                "{EXPECTED_VAULT_VAR} has three parts, but this release of murk does not check a revision — {usage}"
            ));
        }
        _ => {
            return Err(format!(
                "{EXPECTED_VAULT_VAR} is not <vault id>:<minimum generation> — {usage}"
            ));
        }
    };
    if id.len() != 32 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!(
            "{EXPECTED_VAULT_VAR}: the vault id is not 32 lowercase hex characters — {usage}"
        ));
    }
    let min_generation = generation
        .parse::<u64>()
        .ok()
        .filter(|g| *g <= MAX_GENERATION && generation.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| {
            format!(
                "{EXPECTED_VAULT_VAR}: the minimum generation is not a whole number from 0 to {MAX_GENERATION} — {usage}"
            )
        })?;
    Ok(ExpectedVault {
        vault_id: id.to_string(),
        min_generation,
    })
}

/// Parse `MURK_EXPECTED_VAULT`. `Ok(None)` only when unset. A value that does
/// not parse, an empty one included, is an error (fail closed rather than
/// check less than the operator meant).
pub fn env_expected_vault() -> Result<Option<ExpectedVault>, String> {
    match std::env::var(EXPECTED_VAULT_VAR) {
        Ok(raw) => parse_expected_vault(&raw).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{EXPECTED_VAULT_VAR} is not valid UTF-8 — set it to <vault id>:<minimum generation>"
        )),
    }
}

/// Canonical keys of the grants in `grants`.
fn grant_keys(grants: &BTreeMap<String, types::GrantEntry>) -> BTreeSet<String> {
    grants
        .values()
        .map(|g| canonical_recipient(&g.pubkey).into_owned())
        .collect()
}

/// One trusted-signer entry in the [`parse_trusted_signer`] format: the
/// ssh-ed25519 key line, or `age1…:<verifying key>`.
pub fn format_trusted_signer(recipient: &str, vk: Option<&str>) -> String {
    match vk {
        Some(vk) if !recipient.starts_with("ssh-") => format!("{recipient}:{vk}"),
        _ => recipient.to_string(),
    }
}

/// The signers this machine's pin trusts for `vault_path`, with their pinned
/// verifying keys — what an anchor written on this machine (a grant key file)
/// should carry. An age signer with no confirmed key yet is left out: nothing
/// here could check its signatures.
pub fn pinned_trusted_signers(vault_path: &str) -> Result<TrustedSigners, String> {
    let Some(pin) = pins::read(vault_path)?.filter(TrustPin::has_trust) else {
        return Ok(TrustedSigners::new());
    };
    Ok(pin
        .trusted
        .iter()
        .filter(|k| !pin.grants.contains(*k))
        .filter_map(|k| {
            if k.starts_with("ssh-ed25519 ") {
                Some((k.clone(), None))
            } else {
                pin.pinned_key(k).map(|vk| (k.clone(), Some(vk.clone())))
            }
        })
        .collect())
}

/// A short fingerprint of a signed vault — the SHA-256 of its signature, as
/// hex — that tells two vaults with the same generation apart. Empty for an
/// unsigned vault or one with a murk ≤ 0.13 signature in its meta.
pub fn vault_fingerprint(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};
    let Some(sig) = &vault.sig else {
        return String::new();
    };
    Sha256::digest(sig.sig.as_bytes())
        .iter()
        .take(16)
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Where a load happens, as the removal rule sees it: the git HEAD state;
/// the removed keys whose recorded removal commit (see
/// [`TrustPin::removed_at_commit`]) is the commit checked out or a descendant
/// of it, with the vault file as committed there — the vault is from before
/// those removals; and the removed keys whose removal is in the history of
/// the commit checked out (see [`removal_in_history`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout {
    pub head: HeadState,
    before: BTreeSet<String>,
    reached: BTreeSet<String>,
}

impl Checkout {
    /// `head` with no history information: no vault counts as from before a
    /// removal, and no removal as reached by history alone.
    pub fn at(head: HeadState) -> Self {
        Self {
            head,
            before: BTreeSet::new(),
            reached: BTreeSet::new(),
        }
    }

    /// The checkout holding `vault_path`, judged against `pin`. Asks git only
    /// on a branch: once per recorded removal commit, and for each removal
    /// that does not apply on this branch by name, to find whether the
    /// removal is in HEAD's history.
    pub fn of(vault_path: &str, pin: Option<&TrustPin>) -> Self {
        Self::judged(vault_path, pin, true)
    }

    /// The checkout holding `vault_path` for a save's check against `pin`:
    /// as [`Checkout::of`], except that no vault counts as from before a
    /// removal (a save writes a vault numbered past it).
    pub fn for_save(vault_path: &str, pin: &TrustPin) -> Self {
        Self::judged(vault_path, Some(pin), false)
    }

    fn judged(vault_path: &str, pin: Option<&TrustPin>, with_before: bool) -> Self {
        let head = head_of(vault_path);
        let (HeadState::Branch(branch), Some(pin)) = (&head, pin) else {
            return Self::at(head);
        };
        let abs = absolute(vault_path);
        let mut by_commit: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
        for (key, commit) in pin.removed_at_commit.iter().filter(|_| with_before) {
            by_commit.entry(commit).or_default().push(key);
        }
        let before = by_commit
            .into_iter()
            .filter(|(commit, _)| crate::git::committed_vault_at_or_before(&abs, commit))
            .flat_map(|(_, keys)| keys.into_iter().cloned())
            .collect();
        let reached = if pin.branches.contains_key(branch) {
            pin.removed_on
                .iter()
                .filter(|(key, on)| pin.removed.contains_key(*key) && !on.contains(branch))
                .filter(|(key, on)| removal_in_history(&abs, pin, key, on))
                .map(|(key, _)| key.clone())
                .collect()
        } else {
            BTreeSet::new()
        };
        Self {
            head,
            before,
            reached,
        }
    }
}

/// Whether the removal of `key` (canonical) is in the history of the commit
/// checked out in the checkout holding `abs_vault`: a commit that holds the
/// removal (its vault no longer lists the key) is HEAD or an ancestor of it.
/// That commit is the recorded removal commit `C` (see
/// [`TrustPin::removed_at_commit`]) when the vault at `C` does not list the
/// key: a removal accepted from another signer's committed vault. When the
/// vault at `C` still lists the key, `C` is the parent of this machine's own
/// save that removed it, so `C` being in HEAD's history says nothing (every
/// branch cut before the removal has it). Then the tips of the local branches
/// the removal is recorded on (`on`) are tried: a tip that is HEAD or an
/// ancestor of it, has `C` as an ancestor, and whose vault does not list the
/// key holds the removal.
///
/// Stated limit: when git cannot tell (a shallow clone without `C`, a
/// missing object, a git failure), or the branch the removal was saved on
/// was deleted or rewritten since, this answers no, so the removal applies
/// where it did by name alone.
fn removal_in_history(
    abs_vault: &std::path::Path,
    pin: &TrustPin,
    key: &str,
    on: &BTreeSet<String>,
) -> bool {
    let Some(commit) = pin.removed_at_commit.get(key) else {
        return false;
    };
    let Some(dir) = abs_vault.parent() else {
        return false;
    };
    let lists_key = |at: &str| {
        crate::git::vault_at_commit(abs_vault, at)
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|vault| {
                let recipients = vault.get("recipients")?.as_array()?;
                Some(
                    recipients
                        .iter()
                        .any(|r| r.as_str().is_some_and(|r| canonical_recipient(r) == key)),
                )
            })
    };
    if !crate::git::is_ancestor(dir, commit, "HEAD") {
        return false;
    }
    match lists_key(commit) {
        Some(false) => true,
        None => false,
        Some(true) => on.iter().any(|branch| {
            crate::git::branch_tip(dir, branch).is_some_and(|tip| {
                tip != *commit
                    && crate::git::is_ancestor(dir, &tip, "HEAD")
                    && crate::git::is_ancestor(dir, commit, &tip)
                    && lists_key(&tip) == Some(false)
            })
        }),
    }
}

/// Whether the listing part of the removal rule applies to `key` (canonical)
/// at `checkout`: whether a vault listing the key, at any generation, is
/// refused there. It applies on a branch whose accepted history contains the
/// removal (see [`TrustPin::removed_on`]), on a branch whose git history
/// holds the removal (see [`removal_in_history`]), on a detached HEAD,
/// outside git, and on a branch this machine has no mark for (its history is
/// unknown, so it may be a replay) unless its vault is from before the
/// removal: committed at the commit this machine made or accepted the
/// removal at, or an ancestor of it. On a branch this machine accepted before
/// the removal reached it, the vault may still list the key. A vault signed
/// by a removed key is judged by [`signed_before_removal`] instead.
pub fn removal_applies(pin: &TrustPin, key: &str, checkout: &Checkout) -> bool {
    match &checkout.head {
        HeadState::Branch(b) if pin.branches.contains_key(b) => {
            pin.removed_on
                .get(key)
                .is_none_or(|branches| branches.contains(b))
                || checkout.reached.contains(key)
        }
        HeadState::Branch(_) => !checkout.before.contains(key),
        HeadState::Detached | HeadState::NotARepo => true,
    }
}

/// Whether a vault signed by removed key `key` (canonical), at `generation`,
/// is that key's own history from before its removal at `checkout`: the
/// commit checked out is the one this machine made or accepted the removal
/// at, or an ancestor of it, with the vault file as committed there; the
/// removal has not reached this branch; and the vault's generation is at or
/// below the one the key was removed at. Everywhere else, and above that
/// generation on every branch, a vault signed by a removed key is refused.
/// A vault passing this is at or below the removal, so a save over it that
/// keeps the key is refused where the listing rule applies.
pub fn signed_before_removal(
    pin: &TrustPin,
    key: &str,
    generation: u64,
    checkout: &Checkout,
) -> bool {
    let HeadState::Branch(b) = &checkout.head else {
        return false;
    };
    pin.removed.get(key).is_some_and(|&at| generation <= at)
        && checkout.before.contains(key)
        && pin.removed_on.get(key).is_none_or(|on| !on.contains(b))
        && !checkout.reached.contains(key)
}

/// The removed keys (canonical, with the generation each was removed at)
/// that `loaded` is signed by (unless it is that key's history from before
/// the removal, see [`signed_before_removal`]), or lists where the removal
/// applies at `checkout` (see [`removal_applies`]), whatever its generation.
/// `murk trust` re-trusts a vault carrying any of them only when the user
/// names each one.
pub fn removed_keys_in(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    checkout: &Checkout,
) -> BTreeMap<String, u64> {
    let Some(pin) = pin.filter(|p| p.v >= pins::PIN_VERSION) else {
        return BTreeMap::new();
    };
    let canonical = |k: &String| canonical_recipient(k).into_owned();
    let signer = match loaded.signature {
        types::SignatureState::Signed { signer, .. } => Some(canonical(signer))
            .filter(|k| !signed_before_removal(pin, k, loaded.vault.generation, checkout)),
        types::SignatureState::Unsigned => None,
    };
    let listed = loaded
        .vault
        .recipients
        .iter()
        .map(canonical)
        .filter(|k| removal_applies(pin, k, checkout));
    signer
        .into_iter()
        .chain(listed)
        .filter_map(|k| pin.removed.get(&k).map(|&at| (k, at)))
        .collect()
}

/// Rule 8 for a load: the vault is signed by a removed key (refused on every
/// branch, unless it is that key's own history from before the removal, see
/// [`signed_before_removal`]), or lists one where the removal applies (see
/// [`removal_applies`]), at any generation. A newer revision that lists the
/// key may re-add them on purpose, or be a stale fork that still lists them:
/// this machine cannot tell, so only `murk trust --re-add` here accepts it.
fn removal_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    checkout: &Checkout,
) -> Option<Refusal> {
    let pin = pin.filter(|p| p.v >= pins::PIN_VERSION)?;
    let found = loaded.vault.generation;
    if let types::SignatureState::Signed { signer, .. } = loaded.signature
        && let key = canonical_recipient(signer)
        && let Some(&removed_at) = pin.removed.get(key.as_ref())
        && !signed_before_removal(pin, &key, found, checkout)
    {
        return Some(Refusal::RemovedKey {
            key: signer.clone(),
            removed_at,
            found,
            signer: true,
        });
    }
    loaded.vault.recipients.iter().find_map(|r| {
        let key = canonical_recipient(r);
        let removed_at = *pin.removed.get(key.as_ref())?;
        removal_applies(pin, &key, checkout).then(|| Refusal::RemovedKey {
            key: r.clone(),
            removed_at,
            found,
            signer: false,
        })
    })
}

/// Rule 9 for a load: a generation more than [`MAX_GENERATION_STEP`] above
/// the mark, or a different vault with the generation accepted on this
/// branch (outside git: overall). A detached HEAD has no mark to fork from.
fn counter_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    head: &HeadState,
) -> Option<Refusal> {
    let pin = pin.filter(|p| p.v >= pins::PIN_VERSION)?;
    let found = loaded.vault.generation;
    if pin.generation > 0 && found > pin.generation.saturating_add(MAX_GENERATION_STEP) {
        return Some(Refusal::GenerationJump {
            pinned: pin.generation,
            found,
        });
    }
    let fingerprint = vault_fingerprint(loaded.vault);
    let (mark, seen) = match head {
        HeadState::Branch(b) => (pin.branches.get(b).copied(), pin.branch_heads.get(b)),
        HeadState::NotARepo => (Some(pin.generation), Some(&pin.head)),
        HeadState::Detached => (None, None),
    };
    let forked = mark == Some(found)
        && !fingerprint.is_empty()
        && seen.is_some_and(|s| !s.is_empty() && *s != fingerprint);
    forked.then_some(Refusal::Forked { generation: found })
}

/// The revocation ids this machine holds for each agent grant key of a vault
/// whose own revoked grant set is `own` (see [`types::Meta::revoked_grants`]):
/// canonical key → ids. They are the vault's own ids and, with a pin, the
/// ids its sidecar saw (`revoked_grants_seen`), less the ids the user
/// re-admitted with `murk trust --re-add` (`readmitted_grants`). A key with
/// at least one id is tombstoned here: murk refuses it as a recipient, a
/// grant record or an `agents` entry. Without a pin only the vault's own set
/// counts.
pub fn tombstoned(own: &types::RevokedGrants, pin: Option<&TrustPin>) -> types::RevokedGrants {
    let seen = pin
        .filter(|p| p.v >= pins::PIN_VERSION)
        .map(|p| &p.sidecar.revoked_grants_seen);
    let mut out = types::RevokedGrants::new();
    for (key, ids) in own.iter().chain(seen.into_iter().flatten()) {
        out.entry(canonical_recipient(key).into_owned())
            .or_default()
            .extend(ids.iter().cloned());
    }
    without_readmitted(out, pin)
}

/// `set` (canonical keys) less the revocation ids `pin` records as
/// re-admitted (`readmitted_grants`), with every key left without an id
/// taken out.
pub fn without_readmitted(
    mut set: types::RevokedGrants,
    pin: Option<&TrustPin>,
) -> types::RevokedGrants {
    if let Some(readmitted) = pin
        .filter(|p| p.v >= pins::PIN_VERSION)
        .map(|p| &p.sidecar.readmitted_grants)
    {
        for (key, ids) in &mut set {
            if let Some(consented) = readmitted.get(key) {
                ids.retain(|id| !consented.contains(id));
            }
        }
    }
    set.retain(|_, ids| !ids.is_empty());
    set
}

/// The canonical keys `loaded` holds a grant for: a grant record in the
/// meta, or an `agents` entry.
fn granted_keys(loaded: &Loaded<'_>) -> BTreeSet<String> {
    grant_keys(loaded.grants)
        .into_iter()
        .chain(
            loaded
                .vault
                .agents
                .keys()
                .map(|k| canonical_recipient(k).into_owned()),
        )
        .collect()
}

/// The tombstone rule (see [`tombstoned`]). A tombstoned key that `loaded`
/// lists as a recipient without a grant for it is refused on every load. A
/// tombstoned key that `loaded` holds a grant for (a grant record, which
/// comes with the key's recipient entry, or an `agents` entry) is refused
/// when `current` (a load accepted as the vault's next state, a save, a
/// keyed merge result); a history load only warns (see
/// [`history_grant_warnings`]).
pub fn tombstone_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    current: bool,
) -> Option<Refusal> {
    let tombstones = tombstoned(loaded.revoked, pin);
    if tombstones.is_empty() {
        return None;
    }
    let granted = granted_keys(loaded);
    let ids = |key: &str| tombstones.get(key).map(|ids| ids.iter().cloned().collect());
    let plain = loaded.vault.recipients.iter().find_map(|r| {
        let key = canonical_recipient(r).into_owned();
        let ids = (!granted.contains(&key)).then(|| ids(&key)).flatten()?;
        Some(Refusal::RevokedGrantRecipient { key, ids })
    });
    plain.or_else(|| {
        current.then(|| {
            granted.iter().find_map(|key| {
                Some(Refusal::RevokedGrant {
                    key: key.clone(),
                    ids: ids(key)?,
                })
            })
        })?
    })
}

/// The warnings for a history load (see [`is_current`]) of `loaded`, one for
/// each tombstoned key it holds a grant for (see [`tombstone_refusal`]).
/// Such a load succeeds: `git bisect`, tags and release branches from before
/// a revocation stay readable.
pub fn history_grant_warnings(
    vault_path: &str,
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
) -> Vec<String> {
    let tombstones = tombstoned(loaded.revoked, pin);
    granted_keys(loaded)
        .into_iter()
        .filter_map(|key| {
            let ids = tombstones.get(&key)?;
            Some(format!(
                "{vault_path} holds a grant for {}, which this machine holds as revoked (revocation ids {}). It was read as history. A save, a merge or `murk trust` that keeps this grant is refused. To re-admit it after review, run `murk trust --vault {vault_path} --re-add {key}`",
                label(loaded.names, &key),
                show_ids(ids.iter())
            ))
        })
        .collect()
}

/// Revocation ids for a message, each escaped (an id is vault content).
pub fn show_ids<'a>(ids: impl Iterator<Item = &'a String>) -> String {
    ids.map(|id| crate::validate::show(id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether an accepted load of `vault` is its current state on this machine,
/// and not history: the next state of a branch this machine accepted before,
/// or of the vault outside git, with a counter above every counter this
/// machine accepted (`prior`). A load with no trust decision (no pin) is
/// current. A branch this machine has never accepted (an unmerged pull
/// request), a detached HEAD, a branch behind the mark, the vault already
/// accepted, or a different vault with that counter is history. Generation
/// 0 is murk ≤ 0.13: no order, so every such load is current until this
/// machine has seen the vault written by murk 0.14 (a counter or an id);
/// after that a 0.13 vault that still loads (on a branch not upgraded here)
/// is history.
pub fn is_current(vault: &types::Vault, prior: Option<&TrustPin>, head: &HeadState) -> bool {
    let found = vault.generation;
    prior
        .filter(|p| p.v >= pins::PIN_VERSION && p.has_trust())
        .is_none_or(|p| {
            let newer =
                found > p.generation || (found == 0 && p.generation == 0 && p.vault_id.is_empty());
            newer
                && match head {
                    HeadState::NotARepo => true,
                    HeadState::Branch(b) => p.branches.contains_key(b),
                    HeadState::Detached => false,
                }
        })
}

/// The verdict for a load of the working vault: the core rules, then the
/// tombstone rule, the removal rule, `MURK_EXPECTED_VAULT` (`expected`) and
/// the counter rule. A refusal `murk trust` can never accept comes first; a
/// revoked grant or a removed key next, so a vault that is also refused for
/// another reason still needs the key named. A refusal by the pin comes
/// before one by `expected`, so a machine with a pin names what its pin
/// recorded. `grant_rule` says whether the tombstone rule refuses a grant
/// (not only a plain recipient): `None` when the load is current (see
/// [`is_current`]).
fn load_verdict(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
    expected: Option<&ExpectedVault>,
    checkout: &Checkout,
    grant_rule: Option<bool>,
) -> Verdict {
    let head = &checkout.head;
    // A vault a removed key signed before its removal (see
    // `signed_before_removal`) is judged as signed by the member it was then.
    // Only this verdict sees it: the pin's trusted set is never changed by it.
    let before = pin.and_then(|p| match loaded.signature {
        types::SignatureState::Signed { signer, .. } => {
            let key = canonical_recipient(signer).into_owned();
            (p.removed.contains_key(&key)
                && signed_before_removal(p, &key, loaded.vault.generation, checkout))
            .then(|| {
                let mut view = p.clone();
                view.trusted.insert(key);
                view
            })
        }
        types::SignatureState::Unsigned => None,
    });
    let core = verdict(loaded, before.as_ref().or(pin), external_signers, head);
    if let Verdict::Refused(r) = &core
        && !r.acceptable()
    {
        return core;
    }
    let current = grant_rule.unwrap_or_else(|| is_current(loaded.vault, pin, head));
    if let Some(refusal) = tombstone_refusal(loaded, pin, current) {
        return Verdict::Refused(refusal);
    }
    if let Some(refusal) = removal_refusal(loaded, pin, checkout) {
        return Verdict::Refused(refusal);
    }
    if matches!(core, Verdict::Refused(_)) {
        return core;
    }
    if let Some(mismatch) =
        expected.and_then(|e| e.mismatch(&judged_vault_id(loaded), loaded.vault.generation))
    {
        return Verdict::Refused(Refusal::NotExpected(mismatch));
    }
    match counter_refusal(loaded, pin, head) {
        Some(refusal) => Verdict::Refused(refusal),
        None => core,
    }
}

/// Verify `vault`'s signature against `anchor` alone, for a loader that
/// cannot read the meta (an agent grant): the top-level (view 2) signature
/// must be by a signer in `anchor` and verify under the anchor's key for it.
/// Nothing inside the vault — the signer registry in particular — is read.
/// Returns the signer.
pub fn verify_anchored(vault: &types::Vault, anchor: &TrustedSigners) -> Result<String, Refusal> {
    let Some(sig) = &vault.sig else {
        return Err(Refusal::Unsigned);
    };
    let signer = canonical_recipient(&sig.signer).into_owned();
    let Some(expected) = anchor.get(&signer) else {
        return Err(Refusal::UntrustedSigner {
            signer: sig.signer.clone(),
        });
    };
    let registry = expected
        .as_ref()
        .map(|vk| BTreeMap::from([(signer.clone(), vk.clone())]))
        .unwrap_or_default();
    let verified = sig.v == crate::signature::SIGNED_VIEW_VERSION
        && crate::signature::verify_vault_signature(
            vault,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &std::collections::HashMap::new(),
            &registry,
            sig,
        )
        .is_some();
    if verified {
        Ok(signer)
    } else {
        Err(Refusal::SignerKeyChanged {
            signer: sig.signer.clone(),
        })
    }
}

/// Canonical non-grant recipients of a vault: who may sign its next version.
pub fn signers_of(
    vault: &types::Vault,
    grants: &BTreeMap<String, types::GrantEntry>,
) -> BTreeSet<String> {
    let grants = grant_keys(grants);
    vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .filter(|r| !grants.contains(r))
        .collect()
}

/// `groups` with every member key in canonical spelling.
pub fn canonical_groups(groups: &Groups) -> BTreeMap<String, BTreeSet<String>> {
    groups
        .iter()
        .map(|(g, members)| {
            (
                g.clone(),
                members
                    .iter()
                    .map(|m| canonical_recipient(m).into_owned())
                    .collect(),
            )
        })
        .collect()
}

/// Check `loaded` against the pin for `vault_path` and the environment.
///
/// `anchor` is a trusted-signer set supplied from outside the vault and the
/// pin (an agent grant's key file). When it or `MURK_TRUSTED_SIGNERS` is
/// given, their union is the trusted set and the pin's set is ignored; the
/// pin still supplies the rollback, vault-id and downgrade checks.
///
/// `readmit` names removed keys (canonical) the user is re-adding with
/// `murk trust --re-add`: they are judged as if never removed.
///
/// The vault is then checked against the other vault files in its checkout
/// and the other paths' pins on this machine (see [`shared_identity`]).
/// `shares_with` is the path the user named with `murk trust
/// --shares-identity-with`, which does not refuse the vault.
pub fn assess(
    vault_path: &str,
    loaded: &Loaded<'_>,
    anchor: Option<&TrustedSigners>,
    readmit: &BTreeSet<String>,
    shares_with: Option<&str>,
) -> Result<Assessment, String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let expected = env_expected_vault()?;
    let external: Option<TrustedSigners> = match (anchor, &env_signers) {
        (None, None) => None,
        (a, e) => Some(
            a.into_iter()
                .chain(e.iter())
                .flatten()
                .map(|(k, vk)| (canonical_recipient(k).into_owned(), vk.clone()))
                .collect(),
        ),
    };
    let checkout = Checkout::of(vault_path, pin.as_ref());
    let judged = pin.clone().map(|mut p| {
        p.removed.retain(|k, _| !readmit.contains(k));
        p
    });
    let mut verdict = load_verdict(
        loaded,
        judged.as_ref(),
        external.as_ref(),
        expected.as_ref(),
        &checkout,
        None,
    );
    let shared = shared_identity(
        vault_path,
        &judged_vault_id(loaded),
        pin.as_ref(),
        shares_with,
    );
    let mut shared_with = Vec::new();
    let final_refusal = matches!(&verdict, Verdict::Refused(r) if !r.acceptable());
    if shared.refuses() {
        if !final_refusal {
            verdict = Verdict::Refused(Refusal::SharedVaultId {
                others: shared.refused,
                retired_by: shared.retired_by,
            });
        }
    } else {
        shared_with = shared.warned;
    }
    Ok(Assessment {
        verdict,
        pin,
        env_signers,
        external,
        expected,
        shared_with,
    })
}

/// What other vault files and pins say about the vault id of `vault_path`
/// (see [`shared_identity`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedIdentity {
    /// Other paths that make murk refuse this one: a tracked vault file with
    /// the same id while this machine does not trust the vault at this path,
    /// or another path's pin for the same id while its file is tracked.
    pub refused: Vec<String>,
    /// Other tracked vault files with the same id, while this machine trusts
    /// the vault at this path: a warning only.
    pub warned: Vec<String>,
    /// The path whose pin names this one as sharing its vault id (`murk
    /// trust --shares-identity-with`): this path is refused.
    pub retired_by: Option<String>,
}

impl SharedIdentity {
    /// Whether murk refuses the vault at this path.
    pub fn refuses(&self) -> bool {
        !self.refused.is_empty() || self.retired_by.is_some()
    }
}

/// Two files of one vault id in one checkout. murk cannot tell such files
/// apart (a copy of a vault keeps its id), so it loads at most one path per
/// id here. Paths are `/`-separated paths in the checkout. For the vault id
/// `id` at `vault_path`, with its pin `pin`:
///
/// - Another git-tracked vault file (`.murk`, `.murk.*`, `*.murk`) with the
///   same id warns when the pin records `id` at this path, and refuses
///   otherwise.
/// - Another path's sidecar on this machine that records `id` in the same
///   repository refuses, while that path is a tracked vault file with `id`.
///   An untracked one (after `git mv`, or on a branch without it) does not.
/// - A path that another path's sidecar names in `identity_siblings` is
///   refused.
///
/// `shares_with` (`murk trust --shares-identity-with`) refuses nothing.
/// Outside git, and for a vault with no id, nothing applies.
pub fn shared_identity(
    vault_path: &str,
    id: &str,
    pin: Option<&TrustPin>,
    shares_with: Option<&str>,
) -> SharedIdentity {
    let mut out = SharedIdentity::default();
    if id.is_empty() {
        return out;
    }
    let Some((repo_dir, path)) = pins::vault_location(vault_path) else {
        return out;
    };
    let tracked: Vec<String> = tracked_vault_files(vault_path)
        .into_iter()
        .filter(|(other, other_id)| *other != path && other_id == id)
        .map(|(other, _)| other)
        .collect();
    let pinned_here = pin.is_some_and(|p| p.v >= pins::PIN_VERSION && p.vault_id == id);
    for other in &tracked {
        if pinned_here || shares_with == Some(other.as_str()) {
            out.warned.push(other.clone());
        } else {
            out.refused.push(other.clone());
        }
    }
    for (_, sidecar) in pins::peek_sidecars() {
        if sidecar.repo_dir != repo_dir
            || sidecar.vault_id != id
            || sidecar.path == path
            || shares_with == Some(sidecar.path.as_str())
        {
            continue;
        }
        if sidecar.identity_siblings.contains(&path) {
            out.retired_by = Some(sidecar.path.clone());
        }
        if tracked.contains(&sidecar.path) && !out.refused.contains(&sidecar.path) {
            out.warned.retain(|w| *w != sidecar.path);
            out.refused.push(sidecar.path);
        }
    }
    out
}

/// The vault id a vault file's header stands for: its `vault_id`, or for a
/// murk 0.13 file the id its first 0.14 save takes.
pub fn header_vault_id(vault: &types::Vault) -> String {
    if vault.vault_id.is_empty() && written_by_0_13(vault) {
        crate::save::derived_vault_id(vault)
    } else {
        vault.vault_id.clone()
    }
}

/// The git-tracked vault files (`.murk`, `.murk.*`, `*.murk`) in the
/// checkout that holds `vault_path`, as `/`-separated paths in the checkout,
/// each with the vault id its file in the working tree carries. A file that
/// does not parse is left out.
fn tracked_vault_files(vault_path: &str) -> Vec<(String, String)> {
    let abs = absolute(vault_path);
    let resolved = crate::git::real_parent(&abs);
    let Some(root) = resolved.parent().and_then(crate::git::worktree_root) else {
        return Vec::new();
    };
    let Ok(out) = crate::git::git_command()
        .args([
            "ls-files",
            "-z",
            "--",
            ":(glob)**/.murk",
            ":(glob)**/.murk.*",
            ":(glob)**/*.murk",
        ])
        .current_dir(&root)
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let vault = crate::vault::read(&root.join(p)).ok()?;
            Some((p.to_string(), header_vault_id(&vault)))
        })
        .collect()
}

/// The warning for a load of `vault_path`, which this machine trusts, while
/// the tracked file `other` carries the same vault id.
pub fn shared_identity_warning(vault_path: &str, other: &str) -> String {
    format!(
        "{other} has the same vault id as {vault_path}. This machine trusts this vault at {vault_path} only. Remove {other} if it is a copy"
    )
}

/// The verdict for `loaded` against `pin` as it is now (re-read under the
/// pin lock), with the external signers and expected vault `assessment` was
/// computed with. Used to confirm an acceptance just before it is recorded:
/// another process may have raised the rollback mark or learned keys since
/// the first read.
pub fn reassess(
    vault_path: &str,
    loaded: &Loaded<'_>,
    assessment: &Assessment,
    pin: Option<&TrustPin>,
) -> Verdict {
    load_verdict(
        loaded,
        pin,
        assessment.external.as_ref(),
        assessment.expected.as_ref(),
        &Checkout::of(vault_path, pin),
        None,
    )
}

/// `vault_path` made absolute against the working directory.
fn absolute(vault_path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(vault_path);
    match std::env::current_dir() {
        Ok(cwd) if !p.is_absolute() => cwd.join(p),
        _ => p.to_path_buf(),
    }
}

/// The git HEAD state of the checkout holding `vault_path`.
pub fn head_of(vault_path: &str) -> HeadState {
    crate::git::head_state(&absolute(vault_path))
}

/// The commit to record a removal this machine makes at (see
/// [`accepted_pin`]): the one checked out, so every commit at or before it
/// existed before the removal, whether or not the removal is committed yet.
pub fn commit_of(vault_path: &str) -> Option<String> {
    crate::git::head_commit(&absolute(vault_path))
}

/// The commit to record a removal this machine accepts from another signer
/// at (see [`accepted_pin`]): the one checked out, only when it holds the
/// vault that made the removal exactly as committed. A removal accepted from
/// an uncommitted vault file gets no commit, so it has no pre-removal
/// exception.
pub fn accepted_commit_of(vault_path: &str) -> Option<String> {
    crate::git::head_commit_holding_vault(&absolute(vault_path))
}

/// Rule 4: an age signer's registry key must be the one pinned for it (or
/// given in the environment). `None` when it is, or the signer is ssh.
fn signer_key_refusal(
    loaded: &Loaded<'_>,
    signer: &str,
    external_signers: Option<&TrustedSigners>,
    trusted_pin: Option<&TrustPin>,
) -> Option<Refusal> {
    let vk = loaded.signer_vk?;
    let signer_c = canonical_recipient(signer).into_owned();
    let expected = match external_signers {
        Some(external) => external.get(&signer_c).cloned().flatten(),
        None => trusted_pin.and_then(|p| p.pinned_key(&signer_c).cloned()),
    };
    match expected {
        Some(expected) if expected == vk => None,
        Some(_) => Some(Refusal::SignerKeyChanged {
            signer: signer.to_string(),
        }),
        None => Some(Refusal::UnconfirmedSignerKey {
            signer: signer.to_string(),
            vk: vk.to_string(),
        }),
    }
}

/// Whether a grant record in `loaded` names an operator key: a signer this
/// machine trusts or ever trusted (on an operator's own machine, that includes
/// their own key), a signer named in `MURK_TRUSTED_SIGNERS` or an anchor, a
/// key with a signing-key registry entry (grants never sign), or the loading
/// key when it is known to be an operator. The first such grant is tampering.
fn grant_binding_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
) -> Option<Refusal> {
    let operator = loaded
        .operator_key
        .as_deref()
        .map(|k| canonical_recipient(k).into_owned());
    let registry: BTreeSet<String> = loaded
        .registry
        .keys()
        .map(|k| canonical_recipient(k).into_owned())
        .collect();
    loaded.grants.iter().find_map(|(name, grant)| {
        let key = canonical_recipient(&grant.pubkey).into_owned();
        let operator = operator.as_ref() == Some(&key)
            || registry.contains(&key)
            || external_signers.is_some_and(|e| e.contains_key(&key))
            || pin.is_some_and(|p| {
                !p.grants.contains(&key)
                    && (p.trusted.contains(&key) || p.ever_trusted.contains(&key))
            });
        operator.then(|| Refusal::GrantBindsOperator {
            grant: name.clone(),
            key,
        })
    })
}

/// Rule 5 for a signed vault: the signer is not a grant here or in the pin,
/// and no key the pin knows as a grant is back as a plain recipient. A pinned
/// grant entry never overrides signer trust this machine recorded.
fn grant_signer_refusal(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    signer: &str,
) -> Option<Refusal> {
    let signer_c = canonical_recipient(signer).into_owned();
    let current_grants = grant_keys(loaded.grants);
    let pinned_grants: BTreeSet<&String> = pin
        .map(|p| {
            p.grants
                .iter()
                .filter(|k| !p.trusted.contains(*k))
                .collect()
        })
        .unwrap_or_default();
    if current_grants.contains(&signer_c) || pinned_grants.contains(&signer_c) {
        return Some(Refusal::GrantSigner {
            signer: signer.to_string(),
        });
    }
    let recipients: BTreeSet<String> = loaded
        .vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    pinned_grants
        .into_iter()
        .find(|k| recipients.contains(*k) && !current_grants.contains(*k))
        .map(|key| Refusal::GrantWithoutRecord { key: key.clone() })
}

/// Whether this machine has seen the vault written by murk 0.14 where `head`
/// is checked out, so that a murk 0.13 (view 1) signature there can only be
/// an older revision. On a branch: a mark above 0 for it. Every 0.14 save is
/// numbered from 1 and a view-1 vault is always at 0, so a mark of 0 is from
/// an acceptance of the 0.13 vault (or a `murk trust` of one), not from 0.14.
/// Outside git: an overall mark or a pinned vault id. A detached HEAD has no
/// mark. Worktrees share the pin, so a branch counts only once it saw 0.14
/// itself: one worktree's upgrade leaves the others' 0.13 vaults loading as
/// history until the upgrade reaches their branch.
pub(crate) fn upgraded_at(pin: &TrustPin, head: &HeadState) -> bool {
    match head {
        HeadState::Branch(b) => pin.branches.get(b).is_some_and(|&mark| mark > 0),
        HeadState::NotARepo => pin.generation > 0 || !pin.vault_id.is_empty(),
        HeadState::Detached => false,
    }
}

/// Whether `loaded` carries a murk 0.13 (view 1) signature.
fn signed_v1(loaded: &Loaded<'_>) -> bool {
    matches!(
        loaded.signature,
        types::SignatureState::Signed { v, .. } if *v == crate::signature::LEGACY_SIGNED_VIEW_VERSION
    )
}

/// Whether `vault` was written by murk 0.13: no vault id and no counter.
pub fn written_by_0_13(vault: &types::Vault) -> bool {
    vault.vault_id.is_empty() && vault.generation == 0
}

/// Whether a murk 0.13 `vault` stands for the vault `pin` holds: the pin has
/// no id, or the id the file's first 0.14 save takes is the pinned one.
pub fn pre_upgrade_is_this_vault(pin: Option<&TrustPin>, vault: &types::Vault) -> bool {
    pin.is_none_or(|p| p.vault_id.is_empty() || crate::save::derived_vault_id(vault) == p.vault_id)
}

/// Where an accepted murk 0.13 copy is recorded for `head` (see
/// [`TrustPin::accepted_pre_upgrade`]): the branch name, `""` outside git.
/// A detached HEAD has no place to record one.
fn acceptance_key(head: &HeadState) -> Option<String> {
    match head {
        HeadState::Branch(b) => Some(b.clone()),
        HeadState::NotARepo => Some(String::new()),
        HeadState::Detached => None,
    }
}

/// The fingerprint of a murk 0.13 vault file as `murk trust` accepted it:
/// SHA-256 over its serialization, so any change to the file is a different
/// copy.
pub fn pre_upgrade_fingerprint(vault: &types::Vault) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(vault).expect("a vault serializes");
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Whether a write over `vault` (a save, or a keyed merge with it as a side)
/// at `head` must be refused: it is a murk 0.13 file, this machine has seen
/// the vault in 0.14 form (so the file loaded, at most, as history), and it
/// is not the copy `murk trust` accepted at `head`. The file's id rests on
/// header fields nothing signs (see `verdict`), so until the user accepts
/// it, writing it would give another vault's contents and recipients this
/// vault's id and counter.
pub fn pre_upgrade_read_only(
    pin: Option<&TrustPin>,
    head: &HeadState,
    vault: &types::Vault,
) -> bool {
    let Some(pin) = pin.filter(|p| p.v >= pins::PIN_VERSION) else {
        return false;
    };
    written_by_0_13(vault)
        && (pin.generation > 0 || !pin.vault_id.is_empty())
        && acceptance_key(head)
            .and_then(|k| pin.accepted_pre_upgrade.get(&k))
            .is_none_or(|fp| *fp != pre_upgrade_fingerprint(vault))
}

/// `prior` with `vault`, a murk 0.13 file, recorded as the copy the user
/// accepted at `head` (see [`TrustPin::accepted_pre_upgrade`]), and nothing
/// else changed. Accepting an older copy is reading history on purpose: it
/// makes the copy writable here, but the trusted set, groups and removals are
/// left alone, so a member who joined after the copy was written is never
/// recorded as removed. `None` on a detached HEAD (no branch to record it on).
pub fn accept_pre_upgrade_copy(
    prior: Option<&TrustPin>,
    head: &HeadState,
    vault: &types::Vault,
) -> Option<TrustPin> {
    let key = acceptance_key(head)?;
    let mut pin = prior.cloned().unwrap_or_default();
    pin.accepted_pre_upgrade
        .insert(key, pre_upgrade_fingerprint(vault));
    Some(pin)
}

/// The refusal for a write [`pre_upgrade_read_only`] refuses.
pub fn pre_upgrade_read_only_message(vault_path: &str, head: &HeadState) -> String {
    let accept = if *head == HeadState::Detached {
        format!(
            "check out a branch, review it (`git log -p -- {vault_path}`, `murk diff`) and run `murk trust --vault {vault_path}` to accept it, then retry"
        )
    } else {
        format!(
            "review it (`git log -p -- {vault_path}`, `murk diff`) and run `murk trust --vault {vault_path}` to accept it, then retry"
        )
    };
    format!(
        "vault {vault_path} is in the pre-0.14 format on a branch that hasn't taken the upgrade, and this machine hasn't accepted this copy, so it is read-only here\nnothing was written\n{accept}; or merge the upgrade from the default branch"
    )
}

fn verdict(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
    head: &HeadState,
) -> Verdict {
    if loaded.vault.generation > MAX_GENERATION {
        return Verdict::Refused(Refusal::GenerationOutOfRange {
            found: loaded.vault.generation,
        });
    }
    if let Some(refusal) = grant_binding_refusal(loaded, pin, external_signers) {
        return Verdict::Refused(refusal);
    }
    let refusal = match loaded.signature {
        types::SignatureState::Unsigned => {
            match unsigned_verdict(loaded, pin, external_signers, head) {
                None => return Verdict::UnsignedAllowed,
                refusal => refusal,
            }
        }
        types::SignatureState::Signed { signer, .. } => {
            signer_verdict(loaded, pin, external_signers, signer).or_else(|| {
                pin.filter(|p| p.v >= pins::PIN_VERSION)
                    .and_then(|p| pinned_state_verdict(loaded, p, head, Some(signer.as_str())))
            })
        }
    };
    refusal.map_or(Verdict::Trusted, Verdict::Refused)
}

/// The rules for an unsigned vault. Nothing in it shows who wrote it, so it
/// loads only for a key that cannot sign, with no `MURK_TRUSTED_SIGNERS`, on
/// a machine that holds a trust decision for the vault (an accepted load,
/// `murk trust`, `murk init` or an own save). It then meets the same id and
/// rollback checks as a signed vault, and it may not widen what this machine
/// encrypts to: every recipient, grant and group membership must be one the
/// pin already holds. A change there needs `murk trust` after review.
fn unsigned_verdict(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
    head: &HeadState,
) -> Option<Refusal> {
    // An unsigned murk 0.13 file is still judged by the id its first 0.14
    // save takes, so another vault's file never reads as unsigned or
    // stripped (which `murk trust` would re-sign under this vault's id).
    if written_by_0_13(loaded.vault)
        && let Some(refusal) = pin
            .filter(|p| p.v >= pins::PIN_VERSION)
            .and_then(|p| id_refusal(loaded, p))
    {
        return Some(refusal);
    }
    if pin.is_some_and(|p| p.was_signed) {
        return Some(Refusal::Downgraded);
    }
    // A key that can sign, or an operator who named the signers they
    // require, never loads an unsigned vault.
    if loaded.loader_can_sign || external_signers.is_some() {
        return Some(Refusal::Unsigned);
    }
    let Some(p) = pin.filter(|p| p.has_trust()) else {
        return Some(Refusal::UnsignedNotYetTrusted);
    };
    pinned_state_verdict(loaded, p, head, None).or_else(|| unsigned_widening(loaded, p))
}

/// The signer rules for a signed vault: not a grant key, in the trusted set
/// (the environment's or anchor's when given, else the pin's), and signed
/// under the verifying key pinned or given for it.
fn signer_verdict(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
    external_signers: Option<&TrustedSigners>,
    signer: &str,
) -> Option<Refusal> {
    if let Some(refusal) = grant_signer_refusal(loaded, pin, signer) {
        return Some(refusal);
    }
    let signer_c = canonical_recipient(signer).into_owned();
    let trusted_pin = pin.filter(|p| p.has_trust());
    let is_trusted = match (external_signers, trusted_pin) {
        (Some(external), _) => external.contains_key(&signer_c),
        (None, Some(p)) => p.trusted.contains(&signer_c),
        (None, None) => {
            return Some(Refusal::NotYetTrusted {
                signer: signer.to_string(),
            });
        }
    };
    if !is_trusted {
        return Some(Refusal::UntrustedSigner {
            signer: signer.to_string(),
        });
    }
    signer_key_refusal(loaded, signer, external_signers, trusted_pin)
}

/// The vault id `loaded` is judged by. A v1 vault, and an unsigned murk 0.13
/// file, has no id of its own: it is judged by the id its first 0.14 save
/// takes (`save::derived_vault_id`, from `created` and `vault_name`), which
/// is how a vault upgraded from 0.13 got the id pinned here. Those two fields
/// are not covered by the v1 signature or the MAC, so a check by this id
/// catches another vault's file, not one whose header was edited to match.
/// Such a file is read-only where it loads (see `pre_upgrade_read_only`).
fn judged_vault_id(loaded: &Loaded<'_>) -> String {
    let derived = signed_v1(loaded)
        || (matches!(loaded.signature, types::SignatureState::Unsigned)
            && written_by_0_13(loaded.vault));
    if derived {
        crate::save::derived_vault_id(loaded.vault)
    } else {
        loaded.vault.vault_id.clone()
    }
}

/// The vault id check against the pin (see [`judged_vault_id`]).
fn id_refusal(loaded: &Loaded<'_>, pin: &TrustPin) -> Option<Refusal> {
    let found = judged_vault_id(loaded);
    (!pin.vault_id.is_empty() && found != pin.vault_id).then(|| Refusal::OtherVault {
        pinned: pin.vault_id.clone(),
        found,
    })
}

/// The checks against what this machine accepted before, for a signed vault
/// (`signer`) and an unsigned one alike: the vault id, the 0.13 format where
/// the vault was upgraded, rollback, and (for a signed vault) who may change
/// a group. An unsigned vault may not change a group at all (see
/// [`unsigned_widening`]).
fn pinned_state_verdict(
    loaded: &Loaded<'_>,
    p: &TrustPin,
    head: &HeadState,
    signer: Option<&str>,
) -> Option<Refusal> {
    // The id comes first, so `murk trust` never re-signs another vault's
    // file under this vault's id.
    if let Some(refusal) = id_refusal(loaded, p) {
        return Some(refusal);
    }
    // A v1 signature covers neither the vault id nor the counter. Where
    // this machine has seen the vault written by murk 0.14 (see
    // `upgraded_at`), such a vault can only be an older revision. Anywhere
    // else — a branch not upgraded here yet, a detached HEAD — it is
    // pre-0.14 history: every other rule still applies, and its load only
    // narrows the pin (see `accepted_pin`).
    if signed_v1(loaded) && upgraded_at(p, head) {
        return Some(Refusal::PreUpgrade {
            on_branch: matches!(head, HeadState::Branch(_)),
        });
    }
    // Rollback is judged per branch: checking out an older branch is
    // normal, a branch going backwards is not. A detached HEAD (rebase,
    // bisect, CI checkout of a commit) and a branch never seen here have
    // no high-water mark to compare with.
    let high = match head {
        HeadState::NotARepo => Some(p.generation),
        HeadState::Branch(b) => p.branches.get(b).copied(),
        HeadState::Detached => None,
    };
    if let Some(high) = high
        && loaded.vault.generation < high
    {
        return Some(Refusal::RolledBack {
            pinned: high,
            found: loaded.vault.generation,
        });
    }
    let signer = signer?;
    if p.has_trust()
        && let Some(group) = unauthorised_group_change(loaded, p, signer)
    {
        return Some(Refusal::GroupChange {
            group,
            signer: signer.to_string(),
        });
    }
    None
}

/// Rule R3 for an unsigned vault: the first recipient, grant or group
/// membership in `loaded` that `pin` has not accepted. A recipient must be a
/// trusted signer in the pin, or a grant key the pin recorded whose record
/// this vault still carries. Every grant must be one the pin recorded. Every
/// group must have the pinned membership. Removing a recipient or a grant
/// only narrows, so it passes.
fn unsigned_widening(loaded: &Loaded<'_>, pin: &TrustPin) -> Option<Refusal> {
    let grants = grant_keys(loaded.grants);
    if let Some(key) = grants.iter().find(|k| !pin.grants.contains(*k)) {
        return Some(Refusal::UnsignedGrant { key: key.clone() });
    }
    if let Some(key) = loaded.vault.recipients.iter().find(|r| {
        let key = canonical_recipient(r);
        !pin.trusted.contains(key.as_ref()) && !grants.contains(key.as_ref())
    }) {
        return Some(Refusal::UnsignedRecipient { key: key.clone() });
    }
    let groups = canonical_groups(loaded.groups);
    groups
        .keys()
        .chain(pin.groups.keys())
        .find(|g| groups.get(*g) != pin.groups.get(*g))
        .map(|group| Refusal::UnsignedGroupChange {
            group: group.clone(),
        })
}

/// Check one side of a merge (ours or theirs) before its content is merged
/// and re-signed. The same rules as a load, except that the counter is
/// compared with the common ancestor rather than the pin (merging an older
/// branch is normal), and group changes are judged against the ancestor's
/// membership. `changed` says whether the side differs from the ancestor.
/// `upgraded` says whether the merge has a side written by murk 0.14 (one
/// with a vault id or a counter).
///
/// A side written by murk 0.13 carries no authenticated identity or order,
/// so its content cannot be checked for rollback or for being another vault.
/// Such a side is judged like a load of it on the branch being merged into:
/// where this machine has seen the vault written by murk 0.14 there (see
/// [`upgraded_at`]), it is refused. Elsewhere it is pre-0.14 history, as a
/// load is, but once the other side is 0.14 it may only stand for history it
/// shares with the ancestor: if it changed anything it is refused, rather
/// than letting an old signed revision (or another 0.13 vault of the team)
/// override newer content. A side with only one of the two fields is judged
/// against any 0.14 state in the pin. `MURK_EXPECTED_VAULT`, when set, is
/// checked last, as for a load. Returns the reason a side is refused.
pub fn check_merge_side(
    vault_path: &str,
    side: &Loaded<'_>,
    base: Option<(&types::Vault, Option<&Groups>)>,
    changed: bool,
    upgraded: bool,
) -> Result<(), String> {
    let pin = pins::read(vault_path)?;
    let pre_upgrade = side.vault.vault_id.is_empty() && side.vault.generation == 0;
    let legacy = side.vault.vault_id.is_empty() || side.vault.generation == 0;
    let pin_v2 = pin.as_ref().filter(|p| p.v >= pins::PIN_VERSION);
    let pinned_id = pin_v2
        .filter(|p| !p.vault_id.is_empty())
        .map(|p| p.vault_id.as_str());
    let pin_upgraded = pin_v2.is_some_and(|p| {
        if pre_upgrade {
            upgraded_at(p, &head_of(vault_path))
        } else {
            p.generation > 0 || !p.vault_id.is_empty()
        }
    });
    if legacy && (pin_upgraded || (changed && upgraded)) {
        return Err(
            "rolled back: it is a murk 0.13 revision (no vault id or counter), and this vault has since been saved by murk 0.14, so it cannot be checked for rollback or for being another vault — apply its intended change with murk after merging"
                .into(),
        );
    }
    // A 0.13 side has no id to compare; it passed above only as history.
    if let Some(id) = pinned_id
        && !pre_upgrade
        && side.vault.vault_id != id
    {
        return Err(format!(
            "it is a different vault (id {}, this machine pinned {id})",
            crate::validate::show(&side.vault.vault_id)
        ));
    }
    // Two files of one vault id in this checkout: judged as for a load.
    let shared = shared_identity(vault_path, &judged_vault_id(side), pin.as_ref(), None);
    if shared.refuses() {
        let refusal = Refusal::SharedVaultId {
            others: shared.refused,
            retired_by: shared.retired_by,
        };
        let msg = refusal_message(vault_path, &refusal, side, pin.as_ref());
        return Err(msg.lines().next().unwrap_or_default().to_string());
    }
    // Only an authority ancestor says that a side kept a key rather than
    // added it (see `merge_side_counter_or_removal`).
    let authority = base.filter(|(_, groups)| groups.is_some()).map(|(b, _)| b);
    if let Some(refusal) = merge_side_counter_or_removal(
        vault_path,
        side,
        base.map(|(b, _)| b),
        authority,
        pin.as_ref(),
    ) {
        return Err(refusal);
    }
    let env_signers = env_trusted_signers()?;
    let side_pin = pin.map(|mut p| {
        p.generation = 0;
        p.branches.clear();
        if let Some((base, groups)) = base {
            if let Some(groups) = groups {
                p.groups = canonical_groups(groups);
            }
            // A side that forked before the vault got its id (murk 0.13) and
            // changed nothing is the ancestor's state, not another vault. A
            // view-1 side is judged by its derived id instead (see `verdict`).
            if side.vault.vault_id.is_empty() && base.vault_id.is_empty() && !signed_v1(side) {
                p.vault_id.clear();
            }
        }
        p
    });
    match verdict(
        side,
        side_pin.as_ref(),
        env_signers.as_ref(),
        &HeadState::Detached,
    ) {
        Verdict::Trusted | Verdict::UnsignedAllowed => {}
        Verdict::Refused(r) => {
            let msg = refusal_message(vault_path, &r, side, side_pin.as_ref());
            return Err(msg.lines().next().unwrap_or_default().to_string());
        }
    }
    if let Some((base, _)) = base
        && changed
        && base.generation > 0
        && side.vault.generation <= base.generation
    {
        return Err(format!(
            "rolled back: it changed the vault but its generation {} is not above the common ancestor's {}",
            side.vault.generation, base.generation
        ));
    }
    // As for a load, the checks against this machine's pin speak first.
    if let Some(mismatch) = env_expected_vault()?
        .and_then(|e| e.mismatch(&judged_vault_id(side), side.vault.generation))
    {
        let msg = mismatch.message(vault_path);
        return Err(msg.lines().next().unwrap_or_default().to_string());
    }
    Ok(())
}

/// Rules 8 and 9 for a merge side. A side signed by a removed key is refused.
/// A side that lists a removed key that `authority`, the ancestor when it is
/// an authority for this merge, does not list is refused at any generation:
/// it may re-add them on purpose, or be a stale fork, and only `murk trust
/// --re-add` on this machine accepts that. Without an authority ancestor no
/// side may list such a key, so a forged ancestor that lists it exempts
/// nothing. A side that lists the key because the authority ancestor did (a
/// branch forked before the removal) passes here: the recipient merge stops
/// on the one-sided removal, and [`removed_key_kept_by_merge`] refuses a
/// result that keeps the key. The counter may be at most
/// [`MAX_GENERATION_STEP`] above both the mark and `base`, the ancestor;
/// unlike a load it may be below the mark, since a merged branch is
/// legitimately older.
fn merge_side_counter_or_removal(
    vault_path: &str,
    side: &Loaded<'_>,
    base: Option<&types::Vault>,
    authority: Option<&types::Vault>,
    pin: Option<&TrustPin>,
) -> Option<String> {
    let pin = pin.filter(|p| p.v >= pins::PIN_VERSION)?;
    let found = side.vault.generation;
    let in_base: BTreeSet<String> = authority
        .map(|b| {
            b.recipients
                .iter()
                .map(|r| canonical_recipient(r).into_owned())
                .collect()
        })
        .unwrap_or_default();
    if let types::SignatureState::Signed { signer, .. } = side.signature
        && let Some(at) = pin.removed.get(canonical_recipient(signer).as_ref())
    {
        return Some(format!(
            "rolled back: it is signed by {}, who was removed from this vault at generation {at} on this machine — keep the other side's vault, which carries the removal (`git checkout --ours` or `--theirs` on the vault file). That drops every vault change made on this side since the branches split, by anyone, not only by them: run `murk trust` (the vault you keep may read as a rollback or fork of this branch; accepting it never re-trusts them), find this side's last vault commit not signed by them (`git log` on the vault file), list what differs with `murk diff <that commit> --show-values`, and review it change by change — a later vault signed by someone else can still carry their changes — then make only the changes trusted members made again with murk before committing",
            label(side.names, signer)
        ));
    }
    for r in &side.vault.recipients {
        let canonical = canonical_recipient(r).into_owned();
        if let Some(&at) = pin.removed.get(&canonical)
            && !in_base.contains(&canonical)
        {
            if found <= at {
                return Some(format!(
                    "rolled back: it adds {} again, who was removed from this vault at generation {at} on this machine, in a revision numbered {found}, not newer",
                    label(side.names, r)
                ));
            }
            return Some(format!(
                "it lists {}, who was removed from this vault at generation {at} on this machine. This revision (generation {found}) may re-add them on purpose, or it may be a stale fork that still lists them. To accept a deliberate re-add, abort the merge (`git merge --abort`) and review the change with `murk diff`. Then do one of these: merge again, keep this side (`git checkout --theirs -- {vault_path}`), run `murk trust --vault {vault_path} --re-add {canonical}`, and make the other side's vault changes again with murk. Or run `murk circle authorize` for them on this branch, commit, and merge again",
                label(side.names, r)
            ));
        }
    }
    let mark = pin.generation.max(base.map_or(0, |b| b.generation));
    (mark > 0 && found > mark.saturating_add(MAX_GENERATION_STEP)).then(|| {
        format!(
            "its generation {found} jumps more than {MAX_GENERATION_STEP} past {mark}, the highest this machine accepted or the common ancestor's"
        )
    })
}

/// Rule 8 for a merge result at `checkout`: where the removal of a key the
/// merged recipients list applies (see [`removal_applies`]), the result is
/// refused, whatever the sides' generations. Elsewhere (a branch this
/// machine accepted before the removal reached it) a side numbered above the
/// removal must list the key, so the result never brings it back from older
/// revisions alone. Returns the key and the generation it was removed at.
pub fn removed_key_kept_by_merge(
    pin: Option<&TrustPin>,
    merged: &types::Vault,
    sides: &[&types::Vault],
    checkout: &Checkout,
) -> Option<(String, u64)> {
    let pin = pin.filter(|p| p.v >= pins::PIN_VERSION)?;
    merged.recipients.iter().find_map(|r| {
        let canonical = canonical_recipient(r).into_owned();
        let at = *pin.removed.get(&canonical)?;
        let readded = !removal_applies(pin, &canonical, checkout)
            && sides.iter().any(|side| {
                side.generation > at
                    && side
                        .recipients
                        .iter()
                        .any(|s| canonical_recipient(s) == canonical)
            });
        (!readded).then(|| (r.clone(), at))
    })
}

/// The first group whose membership changed relative to the pin without the
/// signer being entitled to change it, if any.
fn unauthorised_group_change(loaded: &Loaded<'_>, pin: &TrustPin, signer: &str) -> Option<String> {
    group_change_violation(
        &loaded.vault.recipients,
        loaded.groups,
        &pin.groups,
        &pin.sidecar.deleted_groups,
        signer,
    )
}

/// The first group in `after` (membership with `recipients` as the vault's
/// recipients) that differs from `before` in a way `signer` may not make:
/// adding or removing a member of a group they are not in, creating a group
/// they are not in, or deleting a group with members left that they are not
/// in. Removing a member who left the vault entirely is allowed, because
/// `circle revoke` does that and any recipient may revoke.
///
/// `deleted` holds groups this machine saw deleted, with their members at
/// deletion. A group absent from `before` and present in `deleted` is
/// judged as a change from those members: only one of them may create it
/// again, unless none of them is still a recipient.
pub fn group_change_violation(
    recipients: &[String],
    after: &Groups,
    before: &BTreeMap<String, BTreeSet<String>>,
    deleted: &BTreeMap<String, BTreeSet<String>>,
    signer: &str,
) -> Option<String> {
    let signer = canonical_recipient(signer).into_owned();
    let recipients: BTreeSet<String> = recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    let current = canonical_groups(after);
    for (group, members) in &current {
        let was = match (before.get(group), deleted.get(group)) {
            (Some(was), _) => was,
            (None, Some(was)) if was.intersection(&recipients).next().is_some() => was,
            _ => {
                // A new group: its creator must be in it (the CLI requires that).
                if !members.contains(&signer) {
                    return Some(group.clone());
                }
                continue;
            }
        };
        let added = members.difference(was).next().is_some();
        let removed = was.difference(members).any(|m| recipients.contains(m));
        if (added || removed) && !was.contains(&signer) {
            return Some(group.clone());
        }
    }
    for (group, was) in before {
        if !current.contains_key(group) {
            let remaining = was.intersection(&recipients).next().is_some();
            if remaining && !was.contains(&signer) {
                return Some(group.clone());
            }
        }
    }
    None
}

/// How an accepted vault came to be accepted, which decides what it may
/// change in the pin.
#[derive(Debug, Clone, Copy)]
pub enum Acceptance<'a> {
    /// A load the trust rules accepted. It is the vault's current state, and
    /// replaces the trusted set, groups and registry, only when it is newer
    /// than everything this machine accepted and checked out on a branch this
    /// machine accepted before (or outside git). Any other accepted load — a
    /// branch never accepted here (an unmerged pull request), a detached HEAD,
    /// a branch behind the mark, the vault already accepted, or a different
    /// vault with that counter — is history: it only narrows the pin (marks
    /// of branches accepted before, grants seen, the signed bit), so reading
    /// history never adds trust.
    Load,
    /// The user's decision: `murk trust`, or `murk init` creating the vault.
    /// `reset_counter` lowers this branch's mark to the vault's counter (a
    /// rollback or fork accepted on purpose). `readmit` names the removed
    /// keys (canonical) the user re-adds with `--re-add`; any other removed
    /// key stays removed.
    Trust {
        reset_counter: bool,
        readmit: &'a BTreeSet<String>,
    },
    /// This machine's own signed save of a vault that listed `before`
    /// (canonical recipients; `None` for a new file). It changes the trusted
    /// set only by what the save itself added or removed, so saving over a
    /// vault read as history does not trust the keys it carried.
    OwnSave {
        before: Option<&'a BTreeSet<String>>,
    },
}

/// The pin to store once `loaded` is accepted (see [`Acceptance`]) while
/// `head` is checked out, at `commit` (`None` outside git or on an unborn
/// branch). Keeps the higher counters unless `reset_counter`.
///
/// A key the trusted set loses is recorded in `removed` with the vault's
/// generation — when the vault is this branch's next accepted state (a
/// branch seen here before, or outside git), the user's decision, or this
/// machine's own save — and `commit` in `removed_at_commit`. A load that is
/// its branch's next state but not above every counter this machine
/// accepted (another branch saved here more) records the removals the vault
/// holds against the branch's previous mark (see [`branch_removals`]). A
/// load never takes a record out, whatever the vault's generation: only the
/// user re-adding the key (`murk trust --re-add`) or this machine's own save
/// adding it does.
/// A registry entry for a recipient with no pinned key is pinned on the
/// signer's word and recorded in `added_by`; when that signer leaves the
/// trusted set the entry is dropped (see SPEC, Trust: "independently
/// confirmed").
pub fn accepted_pin(
    loaded: &Loaded<'_>,
    prior: Option<&TrustPin>,
    how: Acceptance<'_>,
    head: &HeadState,
    commit: Option<&str>,
) -> TrustPin {
    let prior_v2 = prior.filter(|p| p.v >= pins::PIN_VERSION);
    let had_trust = prior_v2.is_some_and(TrustPin::has_trust);
    let reset_counter = matches!(
        how,
        Acceptance::Trust {
            reset_counter: true,
            ..
        }
    );
    let found = loaded.vault.generation;
    // Only the next state of a branch this machine accepted before (or of
    // the vault outside git) is current (see `is_current`): history only
    // narrows the pin.
    let current = match how {
        Acceptance::Load => is_current(loaded.vault, prior_v2, head),
        Acceptance::Trust { .. } | Acceptance::OwnSave { .. } => true,
    };
    let dropped_on_branch = match how {
        Acceptance::Load if !current => branch_removals(loaded.vault, prior_v2, head),
        _ => BTreeSet::new(),
    };
    let mut pin = prior_v2.cloned().unwrap_or_default();
    pin.v = pins::PIN_VERSION;
    // A key this machine trusts (or trusted) as a signer is never recorded as
    // a grant: that would lock its owner out here for good.
    let new_grants: Vec<String> = grant_keys(loaded.grants)
        .into_iter()
        .filter(|k| !pin.trusted.contains(k) && !pin.ever_trusted.contains(k))
        .collect();
    pin.grants.extend(new_grants.iter().cloned());
    advance_marks(&mut pin, loaded.vault, current, reset_counter, head);
    record_pre_upgrade_acceptance(&mut pin, loaded.vault, how, current, head);

    let prior_id = std::mem::take(&mut pin.vault_id);
    pin.vault_id = accepted_vault_id(loaded, &prior_id);
    // Removals belong to one vault: another vault's counters do not compare.
    // So do the sidecar's records.
    let other_vault = !prior_id.is_empty() && prior_id != pin.vault_id;
    if other_vault {
        pin.removed.clear();
        pin.removed_on.clear();
        pin.removed_at_commit.clear();
        pin.sidecar = pins::Sidecar::default();
        // Grants belong to one vault too: the old vault's grant keys would
        // refuse members of this one.
        pin.grants = new_grants.into_iter().collect();
    }

    let mut dropped = replace_trusted(&mut pin, loaded.vault, how, had_trust, current);
    // `murk trust` of an older 0.13 copy only widens trust (see
    // `older_pre_upgrade_copy`): nobody it predates is dropped or removed.
    let older_copy = older_pre_upgrade_copy(prior_v2, loaded.vault, how, other_vault);
    if older_copy {
        pin.trusted.extend(std::mem::take(&mut dropped));
    }
    dropped.extend(dropped_on_branch);
    // Another vault's acceptance records nothing about this one.
    if !other_vault {
        for k in dropped {
            let at = pin.removed.entry(k.clone()).or_insert(found);
            *at = (*at).max(found);
            match commit {
                Some(c) => pin.removed_at_commit.insert(k.clone(), c.to_string()),
                None => pin.removed_at_commit.remove(&k),
            };
            pin.removed_on.entry(k).or_default();
        }
    }
    // Who comes back: the user naming the key, or this machine's own save
    // adding it. A load never re-trusts a removed key.
    let trusted = std::mem::take(&mut pin.trusted);
    match how {
        Acceptance::Load => {}
        Acceptance::Trust { readmit, .. } => pin.removed.retain(|k, _| !readmit.contains(k)),
        Acceptance::OwnSave { before } => pin
            .removed
            .retain(|k, _| !(trusted.contains(k) && before.is_none_or(|b| !b.contains(k)))),
    }
    pin.trusted = trusted;
    record_removal_reach(&mut pin, loaded.vault, head);
    let removed = pin.removed.clone();
    pin.trusted.retain(|k| !removed.contains_key(k));

    pin_signing_keys(&mut pin, loaded, current);
    if current && !older_copy {
        replace_groups(&mut pin, canonical_groups(loaded.groups), other_vault);
    }
    let trusted = pin.trusted.clone();
    pin.ever_trusted.extend(trusted);
    pin.was_signed = matches!(loaded.signature, types::SignatureState::Signed { .. })
        || prior.is_some_and(|p| p.was_signed);
    if current {
        record_grant_state(&mut pin, loaded, head, commit);
    }
    pin
}

/// Record what a current acceptance of `loaded` (a current load, `murk
/// trust`, an own save) shows about agent grants, at `head` and `commit`:
/// its revoked grant set joins `revoked_grants_seen`, and each key it holds
/// a grant record for is seen live on the branch (`""` outside git) at
/// `commit` (`""` when there is none). A detached HEAD records no
/// sighting: it is no branch.
fn record_grant_state(
    pin: &mut TrustPin,
    loaded: &Loaded<'_>,
    head: &HeadState,
    commit: Option<&str>,
) {
    for (key, ids) in loaded.revoked {
        pin.sidecar
            .revoked_grants_seen
            .entry(canonical_recipient(key).into_owned())
            .or_default()
            .extend(ids.iter().cloned());
    }
    let branch = match head {
        HeadState::Branch(b) => b.clone(),
        HeadState::NotARepo => String::new(),
        HeadState::Detached => return,
    };
    for key in grant_keys(loaded.grants) {
        pin.sidecar
            .grants_live_on
            .entry(key)
            .or_default()
            .insert(branch.clone(), commit.unwrap_or_default().to_string());
    }
}

/// Set the pinned groups to `groups`, those of a vault accepted as current.
/// Each pinned group that `groups` no longer holds is recorded in the
/// sidecar with its members as pinned, unless `groups` belongs to another
/// vault (`other_vault`). A group that `groups` holds again leaves the
/// record.
fn replace_groups(
    pin: &mut TrustPin,
    groups: BTreeMap<String, BTreeSet<String>>,
    other_vault: bool,
) {
    let deleted = &mut pin.sidecar.deleted_groups;
    if !other_vault {
        for (name, members) in &pin.groups {
            if !groups.contains_key(name) {
                deleted.insert(name.clone(), members.clone());
            }
        }
    }
    deleted.retain(|name, _| !groups.contains_key(name));
    pin.groups = groups;
}

/// Whether `how` is `murk trust` of an older murk 0.13 copy of this vault
/// after this machine saw the vault in 0.14 form (the pin holds a counter or
/// an id; not another vault). Such a copy can't show what changed since it
/// was written, so accepting it adds what the user accepted (its signer and
/// recipients) and narrows nothing: members who joined later stay trusted,
/// none is recorded as removed, and the pinned groups stay. A real removal is
/// learned only from a vault accepted as current.
fn older_pre_upgrade_copy(
    prior: Option<&TrustPin>,
    vault: &types::Vault,
    how: Acceptance<'_>,
    other_vault: bool,
) -> bool {
    matches!(how, Acceptance::Trust { .. })
        && written_by_0_13(vault)
        && !other_vault
        && prior.is_some_and(|p| p.generation > 0 || !p.vault_id.is_empty())
}

/// Keep `removed_on` and `removed_at_commit` in step with `removed`, and mark
/// the removals the vault just accepted on branch `head` shows: a vault at or
/// after a removal that does not list the key means the removal has reached
/// this branch (it was made here, or merged or pulled into it).
fn record_removal_reach(pin: &mut TrustPin, vault: &types::Vault, head: &HeadState) {
    let TrustPin {
        removed,
        removed_on,
        removed_at_commit,
        ..
    } = pin;
    removed_on.retain(|k, _| removed.contains_key(k));
    removed_at_commit.retain(|k, _| removed.contains_key(k));
    let HeadState::Branch(branch) = head else {
        return;
    };
    let listed: BTreeSet<String> = vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    for (key, &at) in removed.iter() {
        if vault.generation >= at && !listed.contains(key) {
            removed_on
                .entry(key.clone())
                .or_default()
                .insert(branch.clone());
        }
    }
}

/// The vault id to pin for an accepted `loaded` over `prior` (the pinned
/// one). A murk 0.13 vault has no id of its own; once this machine pinned one
/// it stands for the id its first 0.14 save takes (see `verdict`), so
/// accepting another vault's 0.13 file with `murk trust` pins that id.
fn accepted_vault_id(loaded: &Loaded<'_>, prior: &str) -> String {
    if !loaded.vault.vault_id.is_empty() {
        loaded.vault.vault_id.clone()
    } else if !prior.is_empty() && signed_v1(loaded) {
        crate::save::derived_vault_id(loaded.vault)
    } else {
        prior.to_string()
    }
}

/// Record, or drop, the murk 0.13 copy accepted for `head` (see
/// [`TrustPin::accepted_pre_upgrade`]): the copy the user accepted with
/// `murk trust` is the one that may be written there (see
/// [`pre_upgrade_read_only`]); any other current acceptance there supersedes
/// it.
fn record_pre_upgrade_acceptance(
    pin: &mut TrustPin,
    vault: &types::Vault,
    how: Acceptance<'_>,
    current: bool,
    head: &HeadState,
) {
    let Some(key) = acceptance_key(head) else {
        return;
    };
    if written_by_0_13(vault) && matches!(how, Acceptance::Trust { .. }) {
        pin.accepted_pre_upgrade
            .insert(key, pre_upgrade_fingerprint(vault));
    } else if !written_by_0_13(vault) && current {
        pin.accepted_pre_upgrade.remove(&key);
    }
}

/// Raise the counters for an accepted `vault`: the overall mark (and the
/// fingerprint of the vault at it) only for a current acceptance, the
/// branch's mark for any. `reset_counter` lowers them to the vault's. Where
/// a branch's mark moves to this vault, its recipients are kept as the
/// members at that mark (see [`pins::Sidecar::members_at_mark`]).
fn advance_marks(
    pin: &mut TrustPin,
    vault: &types::Vault,
    current: bool,
    reset_counter: bool,
    head: &HeadState,
) {
    let found = vault.generation;
    let fingerprint = vault_fingerprint(vault);
    if current
        && (found > pin.generation
            || (reset_counter && (*head == HeadState::NotARepo || found == pin.generation)))
    {
        pin.generation = found;
        pin.head.clone_from(&fingerprint);
    }
    if let HeadState::Branch(b) = head {
        let old = pin.branches.get(b).copied();
        // History never gives a branch its first mark: the mark is what
        // makes the branch's next state current.
        if old.is_none() && !current {
            return;
        }
        let mark = match old {
            Some(m) if !reset_counter => m.max(found),
            _ => found,
        };
        pin.branches.insert(b.clone(), mark);
        if reset_counter || old.is_none_or(|m| found > m) {
            pin.branch_heads.insert(b.clone(), fingerprint);
            let members = vault
                .recipients
                .iter()
                .map(|r| canonical_recipient(r).into_owned())
                .collect();
            pin.sidecar.members_at_mark.insert(b.clone(), members);
        }
    }
}

/// The removals a load of `vault` on branch `head` holds when it is that
/// branch's next state (above the branch's mark) but not current (see
/// [`is_current`]: another branch has a higher counter here): the keys
/// `prior` trusts that the vault accepted at the branch's previous mark
/// listed (see [`pins::Sidecar::members_at_mark`]) and `vault` no longer
/// lists. A key added on another branch that has not reached this one is
/// not among them. With no members recorded for the branch (a mark set by
/// an older murk), nothing is recorded, as before.
fn branch_removals(
    vault: &types::Vault,
    prior: Option<&TrustPin>,
    head: &HeadState,
) -> BTreeSet<String> {
    let (HeadState::Branch(b), Some(prior)) = (head, prior.filter(|p| p.has_trust())) else {
        return BTreeSet::new();
    };
    let (Some(&mark), Some(members)) =
        (prior.branches.get(b), prior.sidecar.members_at_mark.get(b))
    else {
        return BTreeSet::new();
    };
    if vault.generation <= mark {
        return BTreeSet::new();
    }
    let listed: BTreeSet<String> = vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    members
        .iter()
        .filter(|k| prior.trusted.contains(*k) && !prior.grants.contains(*k))
        .filter(|k| !listed.contains(*k))
        .cloned()
        .collect()
}

/// Set the pin's trusted set for an accepted `vault` and return the keys it
/// lost. A first decision, or a current acceptance, takes the vault's non-
/// grant recipients; history leaves the set alone; an own save applies only
/// what it added and removed relative to the file it replaced. Where a grant
/// record names a key this machine trusts as a signer, that key stays a
/// signer.
fn replace_trusted(
    pin: &mut TrustPin,
    vault: &types::Vault,
    how: Acceptance<'_>,
    had_trust: bool,
    current: bool,
) -> BTreeSet<String> {
    let recipients: BTreeSet<String> = vault
        .recipients
        .iter()
        .map(|r| canonical_recipient(r).into_owned())
        .collect();
    let vault_signers: BTreeSet<String> = recipients
        .iter()
        .filter(|r| !pin.grants.contains(*r))
        .cloned()
        .collect();
    if !had_trust {
        pin.trusted = vault_signers;
        return BTreeSet::new();
    }
    match how {
        Acceptance::Load if !current => BTreeSet::new(),
        Acceptance::OwnSave {
            before: Some(before),
        } => {
            let dropped: BTreeSet<String> = pin
                .trusted
                .iter()
                .filter(|k| before.contains(*k) && !recipients.contains(*k))
                .cloned()
                .collect();
            let grants = &pin.grants;
            pin.trusted
                .retain(|k| !dropped.contains(k) && !grants.contains(k));
            pin.trusted
                .extend(vault_signers.into_iter().filter(|k| !before.contains(k)));
            dropped
        }
        _ => {
            let dropped = pin.trusted.difference(&vault_signers).cloned().collect();
            pin.trusted = vault_signers;
            dropped
        }
    }
}

/// Update the verifying keys for an accepted vault. An entry pinned on a
/// signer's word (`added_by`) goes when that signer is no longer trusted, so
/// a key they bound to a teammate's name stops counting. A current acceptance
/// then pins the signer's own key and the registry entries of the vault's
/// trusted recipients where none is pinned — believed because the vault
/// carrying them is accepted, and recorded as added by the signer. A pinned
/// key is never replaced, and is kept after its owner is revoked so their old
/// revisions still verify.
fn pin_signing_keys(pin: &mut TrustPin, loaded: &Loaded<'_>, current: bool) {
    let TrustPin {
        trusted,
        signers,
        added_by,
        groups: pinned_groups,
        ..
    } = pin;
    // Dropped here for good: the vault that removes the adder may still carry
    // the entry (its writer vouched for it while the adder was trusted), and
    // that must not pin it again under a new name.
    let mut dropped = BTreeSet::new();
    added_by.retain(|pk, adder| {
        let stands = trusted.contains(adder);
        if !stands {
            signers.remove(pk);
            dropped.insert(pk.clone());
        }
        stands
    });
    let types::SignatureState::Signed { signer, .. } = loaded.signature else {
        return;
    };
    if !current {
        return;
    }
    let signer = canonical_recipient(signer).into_owned();
    if let Some(vk) = loaded.signer_vk
        && !dropped.contains(&signer)
    {
        signers
            .entry(signer.clone())
            .or_insert_with(|| vk.to_string());
    }
    // Binding another recipient's key lets the signer speak as them, so it
    // must not reach further than the signer could itself: an entry for a
    // member of a group (as pinned, or in this vault) is believed only from a
    // member of that group. Otherwise a trusted non-member could bind a
    // member's name to their own key, then sign as that member to change the
    // group.
    let groups = canonical_groups(loaded.groups);
    let may_bind = |pk: &str| {
        groups
            .values()
            .chain(pinned_groups.values())
            .all(|members| !members.contains(pk) || members.contains(&signer))
    };
    for (pk, vk) in loaded.registry {
        let pk = canonical_recipient(pk).into_owned();
        if !trusted.contains(&pk) || signers.contains_key(&pk) || dropped.contains(&pk) {
            continue;
        }
        if pk == signer {
            signers.insert(pk, vk.clone());
        } else if may_bind(&pk) {
            signers.insert(pk.clone(), vk.clone());
            added_by.insert(pk, signer.clone());
        }
    }
}

/// Check a historical revision of the vault (`murk diff` against a git ref)
/// without writing anything. Unlike a load there is no rollback or
/// group-change check — an older revision is expected — and the signer must
/// be one this machine *ever* trusted, so a teammate revoked since still
/// verifies for the revisions they signed. The signer's key must still be the
/// pinned one, and a grant key or a signer never trusted is refused. The
/// vault id must match, except that a revision with none is pre-0.14
/// history: it predates the id (and the counter), so neither its missing id
/// nor its 0.13 signature makes it a rollback. A view-1 revision is compared
/// by the id its first 0.14 save takes (see `verdict`), so another vault's
/// 0.13 file is still another vault. The merge driver judges its common
/// ancestor by the stricter [`ancestor_verdict`].
pub fn assess_revision(vault_path: &str, revision: &Loaded<'_>) -> Result<Verdict, String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let historical = pin.map(|mut p| {
        p.trusted = p.ever_trusted.clone();
        p.generation = 0;
        p.branches.clear();
        p.groups.clear();
        if revision.vault.vault_id.is_empty() && !signed_v1(revision) {
            p.vault_id.clear();
        }
        // History predating the pin may be unsigned without that being a
        // downgrade of the revision itself.
        p.was_signed = false;
        p
    });
    let mut verdict = verdict(
        revision,
        historical.as_ref(),
        env_signers.as_ref(),
        &HeadState::Detached,
    );
    // Groups were cleared above, so a pinned group would read as "new" for
    // every revision; group authority is a property of the working vault.
    // So is the rule that an unsigned vault never widens the pin: a revision
    // read as history changes nothing here, and differs from the pin by
    // nature.
    verdict = match verdict {
        Verdict::Refused(Refusal::GroupChange { .. }) => Verdict::Trusted,
        Verdict::Refused(
            Refusal::UnsignedRecipient { .. }
            | Refusal::UnsignedGrant { .. }
            | Refusal::UnsignedGroupChange { .. },
        ) => Verdict::UnsignedAllowed,
        other => other,
    };
    Ok(verdict)
}

/// Whether the common ancestor of a merge is an authority on what changed:
/// `Trusted` only when it is signed by a key in the current anchor (the
/// pin's trusted set, or `MURK_TRUSTED_SIGNERS` when set) under the verifying
/// key pinned or given for it, by a key this machine has not recorded as
/// removed, and when it is the vault the pin and both `sides` name. A key
/// this machine only ever trusted does not count, and nor does a removed
/// key's own history from before its removal: a revision a removed member
/// signed never decides a merge. Its counter is not judged, since an
/// ancestor is older than the sides by nature, and nor are its groups, since
/// group authority is a property of the working vault. An unsigned ancestor
/// never gets `Trusted`.
pub fn ancestor_verdict(
    vault_path: &str,
    ancestor: &Loaded<'_>,
    sides: [&types::Vault; 2],
) -> Result<Verdict, String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let found = ancestor.vault.generation;
    if let types::SignatureState::Signed { signer, .. } = ancestor.signature
        && let Some(&removed_at) = pin
            .as_ref()
            .filter(|p| p.v >= pins::PIN_VERSION)
            .and_then(|p| p.removed.get(canonical_recipient(signer).as_ref()))
    {
        return Ok(Verdict::Refused(Refusal::RemovedKey {
            key: signer.clone(),
            removed_at,
            found,
            signer: true,
        }));
    }
    let id = judged_vault_id(ancestor);
    if let Some(side) = sides
        .iter()
        .find(|s| !s.vault_id.is_empty() && s.vault_id != id)
    {
        return Ok(Verdict::Refused(Refusal::OtherVault {
            pinned: side.vault_id.clone(),
            found: id,
        }));
    }
    let judged = pin.map(|mut p| {
        p.generation = 0;
        p.branches.clear();
        p.groups.clear();
        p
    });
    Ok(
        match verdict(
            ancestor,
            judged.as_ref(),
            env_signers.as_ref(),
            &HeadState::Detached,
        ) {
            Verdict::Refused(Refusal::GroupChange { .. }) => Verdict::Trusted,
            other => other,
        },
    )
}

/// Why this machine would refuse a merge result (see
/// [`merge_result_refusal`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultRefusal {
    /// The refusal's first line.
    pub reason: String,
    /// The signer whose signing key this machine has not confirmed, when
    /// that is the refusal (canonical). The merge driver compares it with
    /// the merging key: its own key is confirmed by one ordinary save.
    pub unconfirmed_signer: Option<String>,
}

/// The refusal a load of a merge result would get on this machine, if any:
/// the full load verdict with the pin as it is, the environment's anchor and
/// `MURK_EXPECTED_VAULT`, at the checkout being merged into. The merge driver
/// signs a result only when this is `None`. A grant this machine holds as
/// revoked is the merge's own result check (`merge.rs`), which runs before
/// the result is signed; here the tombstone rule refuses only a plain
/// recipient, as on any load.
pub fn merge_result_refusal(
    vault_path: &str,
    merged: &Loaded<'_>,
) -> Result<Option<ResultRefusal>, String> {
    let pin = pins::read(vault_path)?;
    let env_signers = env_trusted_signers()?;
    let expected = env_expected_vault()?;
    let checkout = Checkout::of(vault_path, pin.as_ref());
    Ok(
        match load_verdict(
            merged,
            pin.as_ref(),
            env_signers.as_ref(),
            expected.as_ref(),
            &checkout,
            Some(false),
        ) {
            Verdict::Refused(r) => {
                let msg = refusal_message(vault_path, &r, merged, pin.as_ref());
                Some(ResultRefusal {
                    reason: msg.lines().next().unwrap_or_default().to_string(),
                    unconfirmed_signer: match &r {
                        Refusal::UnconfirmedSignerKey { signer, .. } => {
                            Some(canonical_recipient(signer).into_owned())
                        }
                        _ => None,
                    },
                })
            }
            Verdict::Trusted | Verdict::UnsignedAllowed => None,
        },
    )
}

/// Recipient-set changes of `loaded` against the pinned trusted set, as
/// `(added, removed)` canonical keys. With no pin, every recipient is "added".
pub fn recipient_changes(
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
) -> (Vec<String>, Vec<String>) {
    let now = signers_of(loaded.vault, loaded.grants);
    let before = pin
        .filter(|p| p.has_trust())
        .map(|p| p.trusted.clone())
        .unwrap_or_default();
    (
        now.difference(&before).cloned().collect(),
        before.difference(&now).cloned().collect(),
    )
}

/// `name (age1abc…wxyz)` for a key, or just the truncated key. The name is
/// chosen by whoever wrote the vault, so the key is always shown with it, and
/// the name is escaped with [`crate::validate::terminal_text`] (a `\r` that
/// would overwrite the line, a `\n` that would cut the message, a bidi
/// override).
pub fn label(names: &std::collections::HashMap<String, String>, key: &str) -> String {
    let name = names
        .iter()
        .find(|(pk, _)| crate::recipients::same_recipient(pk, key))
        .map(|(_, n)| n.as_str())
        .filter(|n| !n.is_empty());
    let short = crate::truncate_pubkey(key);
    match name {
        Some(n) => format!("{} ({short})", crate::validate::terminal_text(n, false)),
        None => short,
    }
}

/// The lines `refusal_message` adds for the recipients `loaded` adds or
/// removes against `pin`.
fn recipient_change_lines(loaded: &Loaded<'_>, pin: Option<&TrustPin>) -> String {
    use std::fmt::Write;
    let has_pin = pin.is_some_and(TrustPin::has_trust);
    let (added, removed) = recipient_changes(loaded, pin);
    let mut lines = String::new();
    for k in added {
        let what = if has_pin {
            "recipient added"
        } else {
            "recipient"
        };
        let _ = write!(lines, "\n{what}: {}", label(loaded.names, &k));
    }
    for k in removed {
        let _ = write!(lines, "\nrecipient removed: {}", label(loaded.names, &k));
    }
    lines
}

/// The error a secret-handling load reports for `refusal`: what happened, what
/// to review, and how to accept it if it is legitimate.
pub fn refusal_message(
    vault_path: &str,
    refusal: &Refusal,
    loaded: &Loaded<'_>,
    pin: Option<&TrustPin>,
) -> String {
    let review = format!(
        "review `git log -p -- {vault_path}` and `murk diff`, then run `murk trust --vault {vault_path}` if you accept it"
    );
    let changes = || recipient_change_lines(loaded, pin);
    match refusal {
        Refusal::NotYetTrusted { signer } => format!(
            "vault {vault_path} is not trusted on this machine yet — signed by {}{}\n{review}\nfor CI, set {TRUSTED_SIGNERS_VAR} to the expected signer keys",
            label(loaded.names, signer),
            changes()
        ),
        Refusal::UntrustedSigner { signer } => format!(
            "vault {vault_path} is signed by {}, which is not a trusted signer on this machine{}\n{review}",
            label(loaded.names, signer),
            changes()
        ),
        Refusal::GrantSigner { signer } => format!(
            "vault {vault_path} is signed by agent grant key {}, and agent grants are read-only — it may have been tampered with\nrestore {vault_path} from git",
            crate::truncate_pubkey(signer)
        ),
        Refusal::GrantWithoutRecord { key } => format!(
            "vault {vault_path} lists former agent grant key {} as a recipient without its grant — it may have been tampered with\nrestore {vault_path} from git",
            crate::truncate_pubkey(key)
        ),
        Refusal::Unsigned => format!(
            "vault {vault_path} is unsigned, so nothing shows who wrote it\nreview `git diff -- {vault_path}` and `murk diff`, then run `murk trust --vault {vault_path}` to sign it"
        ),
        Refusal::Downgraded => format!(
            "vault {vault_path} was signed when this machine last accepted it and is now unsigned — the signature was stripped, or a merge or a hardware-key write left it unsigned\nreview `git diff -- {vault_path}` and `murk diff`, then run `murk trust --vault {vault_path}` to accept and re-sign it"
        ),
        Refusal::UnsignedNotYetTrusted
        | Refusal::UnsignedRecipient { .. }
        | Refusal::UnsignedGrant { .. }
        | Refusal::UnsignedGroupChange { .. } => {
            unsigned_refusal_message(vault_path, refusal, loaded, &changes(), &review)
        }
        Refusal::RolledBack { pinned, found } => format!(
            "vault {vault_path} rolled back: generation {found}, but this machine accepted generation {pinned} — an older revision may have been replayed\nif you switched to an older branch, switch back; for a deliberate revert, {review}"
        ),
        Refusal::PreUpgrade { on_branch: true } => format!(
            "vault {vault_path} is in the pre-0.14 format, but this repository's vault has already been upgraded on this branch\nif this is an older revision, switch back to the newer one; to accept this copy, run `murk trust --vault {vault_path}` (it re-signs it)"
        ),
        Refusal::PreUpgrade { on_branch: false } => format!(
            "vault {vault_path} is in the pre-0.14 format, but this vault has already been upgraded on this machine\nif this is an older copy, restore the newer one; otherwise run `murk trust --vault {vault_path}` to accept this copy"
        ),
        Refusal::OtherVault { pinned, found } => format!(
            "vault {vault_path} is a different vault (id {}, expected {pinned}) — another vault's file may have been copied over it\n{review}",
            if found.is_empty() { "none" } else { found }
        ),
        Refusal::GroupChange { group, signer } => format!(
            "vault {vault_path} changes the membership of group {group}, but the signer {} was not a member of it\n{review}",
            label(loaded.names, signer)
        ),
        Refusal::UnconfirmedSignerKey { signer, vk } => format!(
            "vault {vault_path} is signed by {}, a trusted recipient whose signing key this machine has not confirmed yet (their first signed write seen here)\nsigning key fingerprint: {}\nask them to confirm it (they run `murk trust --print-key`), then run `murk trust --vault {vault_path}`",
            label(loaded.names, signer),
            crate::signing::fingerprint(vk).unwrap_or_else(|| "(invalid)".into())
        ),
        Refusal::SignerKeyChanged { signer } => format!(
            "vault {vault_path} is signed by {} with a signing key that is not theirs — an age key's signing key cannot change, so this is a forgery\nrestore {vault_path} from git",
            label(loaded.names, signer)
        ),
        Refusal::GrantBindsOperator { grant, key } => format!(
            "vault {vault_path} binds agent grant {} to {}, which signs this vault as a teammate — agent grants get freshly minted keys, so it has been tampered with\nnothing from it was recorded; restore {vault_path} from git",
            crate::validate::show(grant),
            label(loaded.names, key)
        ),
        Refusal::RemovedKey {
            key,
            removed_at,
            found,
            signer,
        } => removed_key_message(vault_path, loaded, key, *removed_at, *found, *signer),
        Refusal::Forked { generation } => format!(
            "vault {vault_path} forked: generation {generation} is not the vault this machine accepted at that generation here — the branch was rewritten, or another save with the same counter replaced it\nmerge the two saves with the murk merge driver, or {review}"
        ),
        Refusal::GenerationJump { pinned, found } => format!(
            "vault {vault_path} jumps from generation {pinned} to {found}, more than {MAX_GENERATION_STEP} saves at once — a signer may be running the counter up\n{review}"
        ),
        Refusal::GenerationOutOfRange { found } => format!(
            "vault {vault_path} has generation {found}, above the largest murk accepts ({MAX_GENERATION}) — it may have been tampered with to exhaust the counter\nrestore {vault_path} from git"
        ),
        Refusal::NotExpected(mismatch) => mismatch.message(vault_path),
        Refusal::SharedVaultId { others, retired_by } => {
            shared_vault_id_message(vault_path, others, retired_by.as_ref())
        }
        Refusal::RevokedGrantRecipient { key, ids } => format!(
            "vault {vault_path} lists {} as a recipient. It was an agent grant in this vault and was revoked (revocation ids {}), and an agent grant key never reads this vault again\nif it was revoked by mistake, review it and run `murk trust --vault {vault_path} --re-add {key}`; otherwise restore {vault_path} from git",
            label(loaded.names, key),
            show_ids(ids.iter())
        ),
        Refusal::RevokedGrant { key, ids } => format!(
            "vault {vault_path} holds a grant for {}, which this machine holds as revoked (revocation ids {}). An agent grant that was revoked never reads this vault again\nupdate to the vault that revoked it (pull, or merge the revocation into this branch). If it was revoked by mistake, review it and run `murk trust --vault {vault_path} --re-add {key}`",
            label(loaded.names, key),
            show_ids(ids.iter())
        ),
    }
}

/// The message for [`Refusal::SharedVaultId`].
fn shared_vault_id_message(
    vault_path: &str,
    others: &[String],
    retired_by: Option<&String>,
) -> String {
    if let Some(by) = retired_by
        && others.iter().all(|o| o == by)
    {
        return format!(
            "vault {vault_path} has the same vault id as {by}, and this machine trusts that vault at {by} only (`murk trust --shares-identity-with`). murk cannot tell two files with one vault id apart\nuse {by}, or review both files and run `murk trust --vault {vault_path} --shares-identity-with {by}` to trust the vault at {vault_path} instead"
        );
    }
    let mut paths = others.to_vec();
    paths.extend(retired_by.filter(|b| !others.contains(b)).cloned());
    let first = paths.first().map_or("", String::as_str);
    format!(
        "vault {vault_path} has the same vault id as {}. murk cannot tell two files with one vault id apart, so this machine loads only one of them\nremove the other file, or review both files and run `murk trust --vault {vault_path} --shares-identity-with {first}`",
        paths.join(", ")
    )
}

/// The message for an unsigned vault refused by rule R1 (no trust decision
/// here yet) or R3 (it widens what this machine encrypts to).
fn unsigned_refusal_message(
    vault_path: &str,
    refusal: &Refusal,
    loaded: &Loaded<'_>,
    changes: &str,
    review: &str,
) -> String {
    let what = match refusal {
        Refusal::UnsignedRecipient { key } => format!(
            "lists {}, a recipient this machine has not accepted",
            label(loaded.names, key)
        ),
        Refusal::UnsignedGrant { key } => format!(
            "carries an agent grant for {}, which this machine has not accepted",
            crate::truncate_pubkey(key)
        ),
        Refusal::UnsignedGroupChange { group } => {
            format!("changes the membership of group {group}")
        }
        _ => {
            return format!(
                "vault {vault_path} is unsigned, and this machine has not accepted it yet — nothing shows who wrote it{changes}\n{review}"
            );
        }
    };
    format!(
        "vault {vault_path} is unsigned and {what} — nothing shows who made this change{changes}\nmurk does not encrypt to it until you accept it\n{review}"
    )
}

/// The message for [`Refusal::RemovedKey`].
fn removed_key_message(
    vault_path: &str,
    loaded: &Loaded<'_>,
    key: &str,
    removed_at: u64,
    found: u64,
    signer: bool,
) -> String {
    let who = label(loaded.names, key);
    let what = if signer {
        format!(
            "it is signed by {who}, who was removed from this vault at generation {removed_at} on this machine\nif the branch that removed them is not merged here yet, merge it with the murk merge driver; when the merge stops on this vault, keep the side that removed them (`git checkout --theirs -- {vault_path}` when you merged that branch in) and `git add {vault_path}`. That drops every vault change made on this branch since the two branches split, by anyone, not only by them: run `murk trust --vault {vault_path}` (the vault you keep may read as a rollback or fork of this branch; accepting it never re-trusts them), find this branch's last vault commit not signed by them (`git log -- {vault_path}`), list what differs with `murk diff <that commit> --show-values`, and review it change by change — a later vault signed by someone else can still carry their changes — then make only the changes trusted members made again with murk, and commit. If the branch that removed them will not be merged (the removal was abandoned), `murk trust --vault {vault_path} --re-add {}` restores them on this machine. Otherwise restore {vault_path} from git",
            canonical_recipient(key)
        )
    } else if found > removed_at {
        return format!(
            "vault {vault_path} lists {who}, who was removed from this vault at generation {removed_at} on this machine. This revision (generation {found}) may re-add them on purpose, or it may be a stale fork that still lists them\nreview it (`murk diff`). To trust them again on this machine, run `murk trust --vault {vault_path} --re-add {}`",
            canonical_recipient(key)
        );
    } else {
        format!(
            "it lists {who}, who was removed from this vault at generation {removed_at} on this machine, and its generation {found} is not newer — an older revision may have been replayed\nupdate to the vault that removed them (pull, or merge the removal into this branch)"
        )
    };
    format!(
        "vault {vault_path} rolled back: {what}; to re-add them on purpose, review it and run `murk trust --vault {vault_path} --re-add {}`",
        canonical_recipient(key)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The rules outside a git checkout (one counter for the vault).
    fn verdict(
        loaded: &Loaded<'_>,
        pin: Option<&TrustPin>,
        env: Option<&TrustedSigners>,
    ) -> Verdict {
        super::verdict(loaded, pin, env, &HeadState::NotARepo)
    }

    /// A trusted load, or (`reset`) an explicit `murk trust` of a rollback.
    fn accepted_pin(loaded: &Loaded<'_>, prior: Option<&TrustPin>, reset: bool) -> TrustPin {
        static NONE: BTreeSet<String> = BTreeSet::new();
        let how = if reset {
            Acceptance::Trust {
                reset_counter: true,
                readmit: &NONE,
            }
        } else {
            Acceptance::Load
        };
        super::accepted_pin(loaded, prior, how, &HeadState::NotARepo, None)
    }

    #[test]
    fn rollback_is_judged_per_branch() {
        let main = HeadState::Branch("main".into());
        let feature = HeadState::Branch("feature".into());
        let at = |g| Case::new(&[A], g, A);
        // main accepted at 5, then this machine saved feature at 6.
        let pin = super::accepted_pin(&at(5).loaded(), None, Acceptance::Load, &main, None);
        let pin = super::accepted_pin(
            &at(6).loaded(),
            Some(&pin),
            Acceptance::OwnSave { before: None },
            &feature,
            None,
        );
        // Switching back to main (still 5) is fine; main going back to 4 is not.
        assert_eq!(
            super::verdict(&at(5).loaded(), Some(&pin), None, &main),
            Verdict::Trusted
        );
        assert!(matches!(
            super::verdict(&at(4).loaded(), Some(&pin), None, &main),
            Verdict::Refused(Refusal::RolledBack {
                pinned: 5,
                found: 4
            })
        ));
        // The next save is numbered past everything seen on any branch.
        assert_eq!(pin.generation, 6);
        // A detached HEAD has no branch to compare with.
        assert_eq!(
            super::verdict(&at(1).loaded(), Some(&pin), None, &HeadState::Detached),
            Verdict::Trusted
        );
    }

    /// A vault written by murk 0.13: no id, no counter, a view-1 signature.
    fn pre_upgrade(recipients: &[&str], by: &str) -> Case {
        let mut c = Case::new(recipients, 0, by);
        c.vault.vault_id.clear();
        c.sig = types::SignatureState::Signed {
            signer: by.into(),
            v: crate::signature::LEGACY_SIGNED_VIEW_VERSION,
        };
        c
    }

    #[test]
    fn a_pre_upgrade_vault_is_judged_per_branch() {
        let main = HeadState::Branch("main".into());
        let feature = HeadState::Branch("feature".into());
        let fresh = HeadState::Branch("fresh".into());
        let old = pre_upgrade(&[A], A);
        // main accepted the 0.13 vault: a mark of 0, from before 0.14.
        let pin = super::accepted_pin(&old.loaded(), None, Acceptance::Load, &main, None);
        assert_eq!(pin.branches.get("main"), Some(&0));
        // Then this machine made the first 0.14 save, on feature.
        let pin = super::accepted_pin(
            &Case::new(&[A], 1, A).loaded(),
            Some(&pin),
            Acceptance::OwnSave { before: None },
            &feature,
            None,
        );
        assert_eq!((pin.generation, pin.branches.get("feature")), (1, Some(&1)));

        // Where this machine has a 0.14 mark the old format is an older
        // revision: refused, with its own refusal.
        assert_eq!(
            super::verdict(&old.loaded(), Some(&pin), None, &feature),
            Verdict::Refused(Refusal::PreUpgrade { on_branch: true })
        );
        // main's mark of 0 is from before 0.14, so main's committed 0.13
        // vault still loads; so does it on a branch never accepted here and
        // on a detached HEAD.
        for head in [&main, &fresh, &HeadState::Detached] {
            assert_eq!(
                super::verdict(&old.loaded(), Some(&pin), None, head),
                Verdict::Trusted,
                "{head:?}"
            );
        }
        // It loads as history: a recipient it lists that the pin does not
        // trust stays untrusted, and no mark or id changes.
        let wider = pre_upgrade(&[A, M], A);
        for head in [&main, &fresh, &HeadState::Detached] {
            assert_eq!(
                super::verdict(&wider.loaded(), Some(&pin), None, head),
                Verdict::Trusted
            );
            let after =
                super::accepted_pin(&wider.loaded(), Some(&pin), Acceptance::Load, head, None);
            assert!(!after.trusted.contains(M), "{head:?} widened trust");
            assert_eq!(
                (&after.vault_id, after.generation, &after.branches),
                (&pin.vault_id, pin.generation, &pin.branches),
                "{head:?}"
            );
        }
        // Every other rule still applies: a signer the pin does not trust.
        assert_eq!(
            super::verdict(&pre_upgrade(&[A, M], M).loaded(), Some(&pin), None, &main),
            Verdict::Refused(Refusal::UntrustedSigner { signer: M.into() })
        );
        // A save on main is numbered past the overall mark and gives main a
        // 0.14 mark: from then on the old format is refused there too.
        let pin = super::accepted_pin(
            &Case::new(&[A], 2, A).loaded(),
            Some(&pin),
            Acceptance::OwnSave { before: None },
            &main,
            None,
        );
        assert_eq!(pin.branches.get("main"), Some(&2));
        assert_eq!(
            super::verdict(&old.loaded(), Some(&pin), None, &main),
            Verdict::Refused(Refusal::PreUpgrade { on_branch: true })
        );
        // Outside git the overall mark applies, as before.
        assert_eq!(
            super::verdict(&old.loaded(), Some(&pin), None, &HeadState::NotARepo),
            Verdict::Refused(Refusal::PreUpgrade { on_branch: false })
        );
    }

    #[test]
    fn trusting_an_older_0_13_copy_never_records_a_later_member_removed() {
        // A and B trusted (B joined in 0.14). `side` carries an older 0.13
        // copy that lists A and M, signed by M, whom the user now trusts.
        let main = HeadState::Branch("main".into());
        let side = HeadState::Branch("side".into());
        let pin = super::accepted_pin(
            &pre_upgrade(&[A], A).loaded(),
            None,
            Acceptance::Load,
            &main,
            None,
        );
        let mut upgrade = Case::new(&[A, B], 1, A);
        upgrade
            .groups
            .insert("ops".into(), vec![A.into(), B.into()]);
        let pin = super::accepted_pin(
            &upgrade.loaded(),
            Some(&pin),
            Acceptance::OwnSave { before: None },
            &main,
            None,
        );
        assert!(pin.trusted.contains(B));
        let mut copy = pre_upgrade(&[A, M], M);
        copy.groups.insert("ops".into(), vec![A.into()]);
        assert_eq!(
            super::verdict(&copy.loaded(), Some(&pin), None, &side),
            Verdict::Refused(Refusal::UntrustedSigner { signer: M.into() })
        );
        let none = BTreeSet::new();
        let trusted = super::accepted_pin(
            &copy.loaded(),
            Some(&pin),
            Acceptance::Trust {
                reset_counter: false,
                readmit: &none,
            },
            &side,
            None,
        );
        assert!(trusted.trusted.contains(M), "the signer the user accepted");
        assert!(trusted.trusted.contains(B), "a later member stays trusted");
        assert!(trusted.removed.is_empty(), "{:?}", trusted.removed);
        assert_eq!(trusted.groups, pin.groups, "the pinned groups stay");
        assert_eq!(
            super::verdict(
                &Case::new(&[A, B], 2, B).loaded(),
                Some(&trusted),
                None,
                &main
            ),
            Verdict::Trusted
        );
    }

    #[test]
    fn only_an_older_copy_of_this_vault_after_its_upgrade_only_adds() {
        let main = HeadState::Branch("main".into());
        let side = HeadState::Branch("side".into());
        let none = BTreeSet::new();
        let trust = |copy: &Case, prior: &TrustPin| {
            super::accepted_pin(
                &copy.loaded(),
                Some(prior),
                Acceptance::Trust {
                    reset_counter: true,
                    readmit: &none,
                },
                &side,
                None,
            )
        };
        // Before this machine saw the vault in 0.14 form, trusting a 0.13
        // vault is the ordinary full decision: one that drops B removes B.
        let old = super::accepted_pin(
            &pre_upgrade(&[A, B], A).loaded(),
            None,
            Acceptance::Load,
            &main,
            None,
        );
        let trusted = trust(&pre_upgrade(&[A], A), &old);
        assert!(!trusted.trusted.contains(B));
        assert!(trusted.removed.contains_key(B));
        // After the upgrade, accepting another vault's 0.13 file replaces the
        // trust state for it: B, a member of this vault only, is not kept.
        let upgraded = super::accepted_pin(
            &Case::new(&[A, B], 1, A).loaded(),
            Some(&old),
            Acceptance::OwnSave { before: None },
            &main,
            None,
        );
        let mut other = pre_upgrade(&[A], A);
        other.vault.created = "2019-01-01T00:00:00Z".into();
        let trusted = trust(&other, &upgraded);
        assert_eq!(
            trusted.vault_id,
            crate::save::derived_vault_id(&other.vault)
        );
        assert!(!trusted.trusted.contains(B));
    }

    #[test]
    fn a_0_13_load_after_0_14_state_is_history_even_with_no_counter() {
        // A pin with this vault's id and an overall mark of 0 (outside git,
        // `murk trust` of another vault's 0.13 file resets the mark to 0 and
        // pins that file's id). A 0.13 vault an unsigned load accepts there is
        // history: it does not take over the trusted set.
        let pin = TrustPin {
            v: pins::PIN_VERSION,
            vault_id: crate::save::derived_vault_id(&pre_upgrade(&[A], A).vault),
            trusted: [A.to_string()].into(),
            ..Default::default()
        };
        let mut wider = pre_upgrade(&[A, M], A);
        wider.sig = types::SignatureState::Unsigned;
        let after = super::accepted_pin(
            &wider.loaded(),
            Some(&pin),
            Acceptance::Load,
            &HeadState::NotARepo,
            None,
        );
        assert!(!after.trusted.contains(M), "{:?}", after.trusted);
    }

    #[test]
    fn an_accepted_0_13_copy_is_the_latest_one_until_the_branch_upgrades() {
        let main = HeadState::Branch("main".into());
        let side = HeadState::Branch("side".into());
        let pin = super::accepted_pin(
            &pre_upgrade(&[A], A).loaded(),
            None,
            Acceptance::Load,
            &main,
            None,
        );
        let pin = super::accepted_pin(
            &Case::new(&[A], 1, A).loaded(),
            Some(&pin),
            Acceptance::OwnSave { before: None },
            &main,
            None,
        );
        let copy = pre_upgrade(&[A], A);
        let mut edited = pre_upgrade(&[A], A);
        edited
            .vault
            .schema
            .insert("EDITED".into(), types::SchemaEntry::default());
        // `murk trust` of a copy makes that copy, and only it, writable here;
        // accepting another copy supersedes it.
        let accepted = accept_pre_upgrade_copy(Some(&pin), &side, &copy.vault).unwrap();
        assert!(!pre_upgrade_read_only(Some(&accepted), &side, &copy.vault));
        assert!(pre_upgrade_read_only(Some(&accepted), &side, &edited.vault));
        let accepted = accept_pre_upgrade_copy(Some(&accepted), &side, &edited.vault).unwrap();
        assert!(pre_upgrade_read_only(Some(&accepted), &side, &copy.vault));
        assert!(!pre_upgrade_read_only(
            Some(&accepted),
            &side,
            &edited.vault
        ));
        // The same through `accepted_pin`, for a `murk trust` that goes
        // through it (here one that resets the counter).
        let none = BTreeSet::new();
        let trusted = super::accepted_pin(
            &copy.loaded(),
            Some(&accepted),
            Acceptance::Trust {
                reset_counter: true,
                readmit: &none,
            },
            &side,
            None,
        );
        assert!(!pre_upgrade_read_only(Some(&trusted), &side, &copy.vault));
        assert!(pre_upgrade_read_only(Some(&trusted), &side, &edited.vault));
        // The branch's upgrade drops its entry: nothing 0.13 stays writable
        // there on the strength of an old acceptance.
        let upgraded = super::accepted_pin(
            &Case::new(&[A], 2, A).loaded(),
            Some(&trusted),
            Acceptance::OwnSave { before: None },
            &side,
            None,
        );
        assert!(!upgraded.accepted_pre_upgrade.contains_key("side"));
        // A detached HEAD has no branch to record a copy on.
        assert!(accept_pre_upgrade_copy(Some(&pin), &HeadState::Detached, &copy.vault).is_none());
        assert!(pre_upgrade_read_only(
            Some(&pin),
            &HeadState::Detached,
            &copy.vault
        ));
    }

    #[test]
    fn a_pre_upgrade_vault_is_judged_by_the_id_its_upgrade_takes() {
        let main = HeadState::Branch("main".into());
        let feature = HeadState::Branch("feature".into());
        let fresh = HeadState::Branch("fresh".into());
        let old = pre_upgrade(&[A], A);
        let pin = super::accepted_pin(&old.loaded(), None, Acceptance::Load, &main, None);
        // The first 0.14 save, on feature, takes the id derived from the 0.13
        // vault's creation stamp and name.
        let upgraded = Case::new(&[A], 1, A);
        assert_eq!(
            upgraded.vault.vault_id,
            crate::save::derived_vault_id(&old.vault)
        );
        let pin = super::accepted_pin(
            &upgraded.loaded(),
            Some(&pin),
            Acceptance::OwnSave { before: None },
            &feature,
            None,
        );
        // Another vault's 0.13 file, signed by a trusted member: its upgrade
        // would take another id, so it is another vault on every branch.
        let mut other = pre_upgrade(&[A, M], A);
        other.vault.created = "2020-01-01T00:00:00Z".into();
        for head in [&main, &fresh, &HeadState::Detached] {
            assert_eq!(
                super::verdict(&other.loaded(), Some(&pin), None, head),
                Verdict::Refused(Refusal::OtherVault {
                    pinned: pin.vault_id.clone(),
                    found: crate::save::derived_vault_id(&other.vault),
                }),
                "{head:?}"
            );
        }
        // A different 0.13 revision of this vault (same stamp and name) is
        // this vault, and loads as history.
        let revision = pre_upgrade(&[A, B], A);
        assert_eq!(
            super::verdict(&revision.loaded(), Some(&pin), None, &main),
            Verdict::Trusted
        );
        // So does a vault copied from it under 0.13 (`cp .murk staging.murk`):
        // the copies share the stamp and name, so the id can't tell them apart.
        let mut copy = pre_upgrade(&[A], A);
        copy.vault
            .schema
            .insert("STAGING_ONLY".into(), types::SchemaEntry::default());
        assert_eq!(
            super::verdict(&copy.loaded(), Some(&pin), None, &fresh),
            Verdict::Trusted
        );
        // A pin with no id yet (the vault never seen in 0.14 form) has nothing
        // to compare with.
        let mut no_id = pin.clone();
        no_id.vault_id.clear();
        assert_eq!(
            super::verdict(&other.loaded(), Some(&no_id), None, &main),
            Verdict::Trusted
        );
    }

    fn vault(recipients: &[&str], generation: u64) -> types::Vault {
        let mut v = crate::testutil::empty_vault();
        v.recipients = recipients.iter().map(|r| (*r).to_string()).collect();
        v.generation = generation;
        // The id a 0.14 save gives this vault when it comes from 0.13, so a
        // `pre_upgrade` copy of it is the same vault.
        v.vault_id = crate::save::derived_vault_id(&v);
        v
    }

    fn signed(by: &str) -> types::SignatureState {
        types::SignatureState::Signed {
            signer: by.into(),
            v: crate::signature::SIGNED_VIEW_VERSION,
        }
    }

    struct Case {
        vault: types::Vault,
        sig: types::SignatureState,
        groups: BTreeMap<String, Vec<String>>,
        grants: BTreeMap<String, types::GrantEntry>,
        revoked: types::RevokedGrants,
        names: HashMap<String, String>,
        registry: BTreeMap<String, String>,
        /// The registry key the signature verified against (age signers).
        vk: Option<String>,
    }

    /// Trusted signers without verifying keys (as for ssh-ed25519 keys).
    fn env(keys: &[&str]) -> TrustedSigners {
        keys.iter().map(|k| ((*k).to_string(), None)).collect()
    }

    impl Case {
        fn new(recipients: &[&str], generation: u64, by: &str) -> Self {
            Self {
                vault: vault(recipients, generation),
                sig: signed(by),
                groups: BTreeMap::new(),
                grants: BTreeMap::new(),
                revoked: BTreeMap::new(),
                names: HashMap::new(),
                registry: BTreeMap::new(),
                vk: None,
            }
        }
        /// An age-style signature: `vk` is the signer's registry key.
        fn with_vk(mut self, vk: &str) -> Self {
            self.vk = Some(vk.into());
            self
        }
        fn loaded(&self) -> Loaded<'_> {
            Loaded {
                vault: &self.vault,
                signature: &self.sig,
                registry: &self.registry,
                signer_vk: self.vk.as_deref(),
                names: &self.names,
                groups: &self.groups,
                grants: &self.grants,
                revoked: &self.revoked,
                loader_can_sign: true,
                operator_key: None,
            }
        }
    }

    const A: &str = "age1alice";
    const B: &str = "age1bob";
    const M: &str = "age1mallory";

    fn pin_for(c: &Case) -> TrustPin {
        accepted_pin(&c.loaded(), None, false)
    }

    #[test]
    fn self_enrolled_signer_is_refused_against_the_pin() {
        let pin = pin_for(&Case::new(&[A], 3, A));
        let forged = Case::new(&[A, M], 4, M);
        assert_eq!(
            verdict(&forged.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::UntrustedSigner { signer: M.into() })
        );
    }

    #[test]
    fn a_trusted_signer_adding_a_recipient_extends_the_pin() {
        let pin = pin_for(&Case::new(&[A], 3, A));
        let next = Case::new(&[A, B], 4, A);
        assert_eq!(verdict(&next.loaded(), Some(&pin), None), Verdict::Trusted);
        let pin = accepted_pin(&next.loaded(), Some(&pin), false);
        let by_bob = Case::new(&[A, B], 5, B);
        assert_eq!(
            verdict(&by_bob.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
    }

    #[test]
    fn a_revoked_recipient_loses_signing_trust() {
        let pin = pin_for(&Case::new(&[A, B], 3, A));
        let revoked = Case::new(&[A], 4, A);
        let pin = accepted_pin(&revoked.loaded(), Some(&pin), false);
        let back = Case::new(&[A, B], 5, B);
        assert!(matches!(
            verdict(&back.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::UntrustedSigner { .. })
        ));
    }

    #[test]
    fn rollback_below_the_high_water_mark_is_refused_equal_is_not() {
        let pin = pin_for(&Case::new(&[A], 7, A));
        assert_eq!(
            verdict(&Case::new(&[A], 6, A).loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::RolledBack {
                pinned: 7,
                found: 6
            })
        );
        assert_eq!(
            verdict(&Case::new(&[A], 7, A).loaded(), Some(&pin), None),
            Verdict::Trusted
        );
    }

    #[test]
    fn another_vaults_file_is_refused() {
        let pin = pin_for(&Case::new(&[A], 1, A));
        let mut other = Case::new(&[A], 9, A);
        other.vault.vault_id = "ffeeddccbbaa99887766554433221100".into();
        eprintln!("ROW R-I8-a DECISIVE");
        assert!(matches!(
            verdict(&other.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::OtherVault { .. })
        ));
    }

    #[test]
    fn env_signers_replace_the_pin_and_no_trust_at_all_refuses() {
        let c = Case::new(&[A, B], 1, B);
        assert_eq!(
            verdict(&c.loaded(), None, None),
            Verdict::Refused(Refusal::NotYetTrusted { signer: B.into() })
        );
        let env = super::tests::env(&[B]);
        assert_eq!(verdict(&c.loaded(), None, Some(&env)), Verdict::Trusted);
        let env = super::tests::env(&[A]);
        assert!(matches!(
            verdict(&c.loaded(), None, Some(&env)),
            Verdict::Refused(Refusal::UntrustedSigner { .. })
        ));
    }

    #[test]
    fn unsigned_is_refused_for_a_signing_loader_and_after_a_signed_load() {
        let mut c = Case::new(&[A], 1, A);
        c.sig = types::SignatureState::Unsigned;
        assert_eq!(
            verdict(&c.loaded(), None, None),
            Verdict::Refused(Refusal::Unsigned)
        );
        let mut hw = c.loaded();
        hw.loader_can_sign = false;
        assert_eq!(
            verdict(&hw, None, None),
            Verdict::Refused(Refusal::UnsignedNotYetTrusted)
        );
        let pin = pin_for(&Case::new(&[A], 1, A));
        assert_eq!(
            verdict(&hw, Some(&pin), None),
            Verdict::Refused(Refusal::Downgraded)
        );
    }

    #[test]
    fn an_unsigned_vault_never_widens_the_pin() {
        // A non-signing member's machine: it accepted A and B, then its own
        // unsigned save cleared the signed bit.
        let mut pin = pin_for(&Case::new(&[A, B], 1, A));
        pin.was_signed = false;
        let judge = |c: &Case| {
            let mut l = c.loaded();
            l.loader_can_sign = false;
            verdict(&l, Some(&pin), None)
        };
        let unsigned = |recipients: &[&str], generation| {
            let mut c = Case::new(recipients, generation, A);
            c.sig = types::SignatureState::Unsigned;
            c
        };
        assert_eq!(judge(&unsigned(&[A, B], 2)), Verdict::UnsignedAllowed);
        // Dropping a recipient only narrows.
        assert_eq!(judge(&unsigned(&[A], 2)), Verdict::UnsignedAllowed);
        assert_eq!(
            judge(&unsigned(&[A, B, M], 2)),
            Verdict::Refused(Refusal::UnsignedRecipient { key: M.into() })
        );
        let mut grouped = unsigned(&[A, B], 2);
        grouped.groups.insert("ops".into(), vec![A.into()]);
        assert_eq!(
            judge(&grouped),
            Verdict::Refused(Refusal::UnsignedGroupChange {
                group: "ops".into()
            })
        );
        let mut granted = unsigned(&[A, B, "age1grant"], 2);
        granted.grants.insert(
            "g".into(),
            types::GrantEntry {
                pubkey: "age1grant".into(),
                ..Default::default()
            },
        );
        assert_eq!(
            judge(&granted),
            Verdict::Refused(Refusal::UnsignedGrant {
                key: "age1grant".into()
            })
        );
        // The id and rollback checks apply as to a signed vault.
        let mut other = unsigned(&[A, B], 2);
        other.vault.vault_id = "other".into();
        assert!(matches!(
            judge(&other),
            Verdict::Refused(Refusal::OtherVault { .. })
        ));
        let older = unsigned(&[A, B], 0);
        assert!(matches!(
            judge(&older),
            Verdict::Refused(Refusal::RolledBack { .. })
        ));
    }

    #[test]
    fn a_grant_bound_to_a_trusted_signer_is_tampering_and_never_pinned() {
        let pin = pin_for(&Case::new(&[A, B], 1, A));
        let mut ghost = Case::new(&[A, B], 2, B);
        ghost.grants.insert(
            "ghost".into(),
            types::GrantEntry {
                pubkey: A.into(),
                ..Default::default()
            },
        );
        let v = verdict(&ghost.loaded(), Some(&pin), None);
        assert_eq!(
            v,
            Verdict::Refused(Refusal::GrantBindsOperator {
                grant: "ghost".into(),
                key: A.into()
            })
        );
        let Verdict::Refused(r) = v else {
            unreachable!()
        };
        assert!(!r.acceptable());
        // Even if such a vault were recorded (an own save, a re-sign), the
        // pin keeps A a signer and never a grant.
        let recorded = accepted_pin(&ghost.loaded(), Some(&pin), false);
        assert!(!recorded.grants.contains(A));
        assert!(recorded.trusted.contains(A), "A stays a trusted signer");
        // A pinned grant entry for a trusted signer does not override trust.
        let mut stale = pin.clone();
        stale.grants.insert(A.into());
        assert_eq!(
            verdict(&Case::new(&[A, B], 2, A).loaded(), Some(&stale), None),
            Verdict::Trusted
        );

        // A fresh machine (no pin) whose loading key is an operator for sure
        // (ssh or plugin, never a grant) refuses a grant bound to that key.
        let ssh = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDb";
        let mut to_loader = Case::new(&[A, ssh], 3, A);
        to_loader.grants.insert(
            "ghost".into(),
            types::GrantEntry {
                pubkey: ssh.into(),
                ..Default::default()
            },
        );
        let mut as_operator = to_loader.loaded();
        as_operator.operator_key = Some(ssh.into());
        assert_eq!(
            verdict(&as_operator, None, None),
            Verdict::Refused(Refusal::GrantBindsOperator {
                grant: "ghost".into(),
                key: ssh.into()
            })
        );
        // An age loader may be the grant itself: only the pin can tell.
        assert!(matches!(
            verdict(&to_loader.loaded(), None, None),
            Verdict::Refused(Refusal::NotYetTrusted { .. })
        ));

        // A runner with no pin that trusts both through MURK_TRUSTED_SIGNERS:
        // B binds a grant to A and leaves A out of the registry. A is a named
        // signer there, so this is still tampering.
        let mut ghost_ci = Case::new(&[A, B], 2, B);
        ghost_ci.grants.insert(
            "ghost".into(),
            types::GrantEntry {
                pubkey: A.into(),
                ..Default::default()
            },
        );
        assert_eq!(
            verdict(&ghost_ci.loaded(), None, Some(&env(&[A, B]))),
            Verdict::Refused(Refusal::GrantBindsOperator {
                grant: "ghost".into(),
                key: A.into()
            })
        );
    }

    #[test]
    fn a_grant_key_never_signs_even_after_dropping_its_record() {
        let mut with_grant = Case::new(&[A, "age1agent"], 1, A);
        with_grant.grants.insert(
            "bot".into(),
            types::GrantEntry {
                pubkey: "age1agent".into(),
                ..Default::default()
            },
        );
        let pin = pin_for(&with_grant);
        assert!(!pin.trusted.contains("age1agent"));
        // The grant deletes its own record and signs.
        let forged = Case::new(&[A, "age1agent"], 2, "age1agent");
        eprintln!("ROW R-I17-a DECISIVE");
        assert!(matches!(
            verdict(&forged.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::GrantSigner { .. })
        ));
        // Or keeps a trusted signature but re-lists itself as a plain recipient.
        let demoted = Case::new(&[A, "age1agent"], 2, A);
        assert!(matches!(
            verdict(&demoted.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::GrantWithoutRecord { .. })
        ));
    }

    #[test]
    fn a_v1_vault_is_refused_once_the_vault_was_seen_in_v2_form() {
        // Upgrade: a v1 vault (no id, no counter) is pinned once...
        let mut v1 = Case::new(&[A], 0, A);
        v1.vault.vault_id.clear();
        v1.sig = types::SignatureState::Signed {
            signer: A.into(),
            v: crate::signature::LEGACY_SIGNED_VIEW_VERSION,
        };
        let pin = pin_for(&v1);
        assert_eq!(verdict(&v1.loaded(), Some(&pin), None), Verdict::Trusted);
        // ...then the first 0.14 save lands (id + counter)...
        let pin = accepted_pin(&Case::new(&[A], 1, A).loaded(), Some(&pin), false);
        // ...and outside git the old v1 revision is now refused.
        assert_eq!(
            verdict(&v1.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::PreUpgrade { on_branch: false })
        );
    }

    #[test]
    fn named_signers_refuse_an_unsigned_vault_even_for_a_key_that_cannot_sign() {
        let mut c = Case::new(&[A], 1, A);
        c.sig = types::SignatureState::Unsigned;
        let mut hw = c.loaded();
        hw.loader_can_sign = false;
        let env = super::tests::env(&[A]);
        assert_eq!(
            verdict(&hw, None, Some(&env)),
            Verdict::Refused(Refusal::Unsigned)
        );
    }

    #[test]
    fn a_merging_key_outside_a_group_may_not_carry_its_membership_change() {
        let before = canonical_groups(&BTreeMap::from([("ops".to_string(), vec![A.to_string()])]));
        let after = BTreeMap::from([("ops".to_string(), vec![A.to_string(), M.to_string()])]);
        let recipients = [A.to_string(), B.to_string(), M.to_string()];
        assert_eq!(
            group_change_violation(&recipients, &after, &before, &BTreeMap::new(), B),
            Some("ops".into())
        );
        assert_eq!(
            group_change_violation(&recipients, &after, &before, &BTreeMap::new(), A),
            None
        );
    }

    /// A group this machine saw deleted is judged, when it comes back, as a
    /// change from its members at deletion: a non-member who re-creates it
    /// (on load, or as the merging key) is refused, a recorded member is not,
    /// and once every recorded member has left the vault it is a new group.
    #[test]
    fn a_deleted_group_comes_back_only_through_one_of_its_members() {
        let deleted = canonical_groups(&BTreeMap::from([(
            "ops".to_string(),
            vec![A.to_string(), B.to_string()],
        )]));
        let none = BTreeMap::new();
        let by_m = BTreeMap::from([("ops".to_string(), vec![M.to_string()])]);
        let by_a = BTreeMap::from([("ops".to_string(), vec![A.to_string()])]);
        let all = [A.to_string(), B.to_string(), M.to_string()];
        assert_eq!(
            group_change_violation(&all, &by_m, &none, &deleted, M),
            Some("ops".into())
        );
        assert_eq!(group_change_violation(&all, &by_m, &none, &none, M), None);
        assert_eq!(
            group_change_violation(&all, &by_a, &none, &deleted, A),
            None
        );
        assert_eq!(
            group_change_violation(&[M.to_string()], &by_m, &none, &deleted, M),
            None
        );
    }

    #[test]
    fn group_self_add_by_a_non_member_is_refused() {
        let mut base = Case::new(&[A, B, M], 1, A);
        base.groups.insert("prod".into(), vec![A.into(), B.into()]);
        let pin = pin_for(&base);
        let mut forged = Case::new(&[A, B, M], 2, M);
        forged
            .groups
            .insert("prod".into(), vec![A.into(), B.into(), M.into()]);
        let env = super::tests::env(&[A, B, M]);
        // Even with M trusted to sign, it may not change a group it is not in.
        assert_eq!(
            verdict(&forged.loaded(), Some(&pin), Some(&env)),
            Verdict::Refused(Refusal::GroupChange {
                group: "prod".into(),
                signer: M.into()
            })
        );
        // A member may.
        let mut by_member = Case::new(&[A, B, M], 2, A);
        by_member
            .groups
            .insert("prod".into(), vec![A.into(), B.into(), M.into()]);
        assert_eq!(
            verdict(&by_member.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
        // A non-member revoking B from the vault strips B from the group.
        let mut revoke = Case::new(&[A, M], 2, M);
        revoke.groups.insert("prod".into(), vec![A.into()]);
        assert_eq!(
            verdict(&revoke.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
    }

    // Two distinct, well-formed verifying keys for the key-pinning tests.
    fn vks() -> (String, String) {
        let a = crate::signing::age_signing_key(&[1u8; 32]).verifying_key();
        let b = crate::signing::age_signing_key(&[2u8; 32]).verifying_key();
        (a, b)
    }

    /// Run `f` with a sandboxed HOME holding `pin` for `vault_path`.
    fn with_pin<T>(vault_path: &str, pin: &TrustPin, f: impl FnOnce() -> T) -> T {
        let _lock = crate::testutil::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::remove_var("MURK_NO_SIGNER_PIN");
            std::env::remove_var("MURK_TRUSTED_SIGNERS");
            std::env::remove_var(EXPECTED_VAULT_VAR);
        }
        pins::write(vault_path, pin).unwrap();
        let out = f();
        match prev {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        out
    }

    #[test]
    fn a_pinned_vault_refuses_an_id_less_merge_side_even_unchanged() {
        // The pin has seen the vault in 0.14 form, and outside git the
        // overall mark applies. A side without a vault id (a 0.13 revision)
        // is refused even when it equals the ancestor.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".murk");
        let path = path.to_str().unwrap();
        let pin = pin_for(&Case::new(&[A], 3, A));
        let mut legacy = Case::new(&[A], 0, A);
        legacy.vault.vault_id.clear();
        let base = legacy.vault.clone();
        let refused = with_pin(path, &pin, || {
            check_merge_side(path, &legacy.loaded(), Some((&base, None)), false, false)
        });
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("murk 0.13 revision")),
            "{refused:?}"
        );
    }

    #[test]
    fn a_0_13_merge_side_is_judged_by_the_branch_merged_into() {
        // A checkout of branch `fresh`, which this machine has no 0.14 mark
        // for; the pin's 0.14 state comes from `feature`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let head = dir.path().join(".git/HEAD");
        let path = dir.path().join(".murk");
        let path = path.to_str().unwrap();
        let mut pin = pin_for(&Case::new(&[A], 3, A));
        pin.branches = [("feature".to_string(), 3), ("fresh".to_string(), 0)].into();
        let side = pre_upgrade(&[A], A);
        let base = side.vault.clone();
        let changed = pre_upgrade(&[A, B], A);
        let check = |branch: &str, side: &Case, changed: bool, upgraded: bool| {
            std::fs::write(&head, format!("ref: refs/heads/{branch}\n")).unwrap();
            with_pin(path, &pin, || {
                check_merge_side(path, &side.loaded(), Some((&base, None)), changed, upgraded)
            })
        };
        // On `fresh` a 0.13 side is history, as a load there is: merged,
        // changed or not, while the other side is 0.13 too.
        assert_eq!(check("fresh", &side, false, false), Ok(()));
        assert_eq!(check("fresh", &changed, true, false), Ok(()));
        // One that changed the vault still never overrides a 0.14 side.
        assert!(
            check("fresh", &changed, true, true).is_err_and(|e| e.contains("murk 0.13 revision"))
        );
        // On `feature`, upgraded here, it is refused even unchanged.
        assert!(
            check("feature", &side, false, false).is_err_and(|e| e.contains("murk 0.13 revision"))
        );
        // Every other rule still applies: a signer this machine does not trust.
        assert!(check("fresh", &pre_upgrade(&[A, M], M), true, false).is_err());
        // So does the vault id: another vault's 0.13 file (its first save would
        // derive another id) is refused on `fresh` too, as a side...
        let mut other = pre_upgrade(&[A], A);
        other.vault.created = "2020-01-01T00:00:00Z".into();
        assert!(check("fresh", &other, true, false).is_err_and(|e| e.contains("different vault")),);
        // ...and as the ancestor (`assess_revision`).
        let revision = with_pin(path, &pin, || assess_revision(path, &other.loaded()));
        assert!(
            matches!(revision, Ok(Verdict::Refused(Refusal::OtherVault { .. }))),
            "{revision:?}"
        );
        let own = with_pin(path, &pin, || assess_revision(path, &side.loaded()));
        assert_eq!(own, Ok(Verdict::Trusted));
    }

    #[test]
    fn a_pinned_vault_refuses_a_merge_side_from_another_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".murk");
        let path = path.to_str().unwrap();
        let pin = pin_for(&Case::new(&[A], 3, A));
        let mut other = Case::new(&[A], 5, A);
        other.vault.vault_id = "ffeeddccbbaa99887766554433221100".into();
        let base = Case::new(&[A], 3, A).vault;
        let refused = with_pin(path, &pin, || {
            check_merge_side(path, &other.loaded(), Some((&base, None)), true, true)
        });
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("different vault")),
            "{refused:?}"
        );
        // The pinned vault's own side is accepted.
        let own = Case::new(&[A], 5, A);
        let accepted = with_pin(path, &pin, || {
            check_merge_side(path, &own.loaded(), Some((&base, None)), true, true)
        });
        assert_eq!(accepted, Ok(()));
    }

    #[test]
    fn a_merge_side_meets_murk_expected_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".murk");
        let path = path.to_str().unwrap();
        let pin = pin_for(&Case::new(&[A], 3, A));
        let base = Case::new(&[A], 3, A).vault;
        let side = Case::new(&[A], 5, A);
        let id = side.vault.vault_id.clone();
        let check = |expected: String| {
            with_pin(path, &pin, || {
                unsafe { std::env::set_var(EXPECTED_VAULT_VAR, &expected) };
                let out = check_merge_side(path, &side.loaded(), Some((&base, None)), true, true);
                unsafe { std::env::remove_var(EXPECTED_VAULT_VAR) };
                out
            })
        };
        assert_eq!(check(format!("{id}:5")), Ok(()));
        let other = check("ffeeddccbbaa99887766554433221100:5".into());
        assert!(
            other
                .as_ref()
                .is_err_and(|e| e.contains("not the vault that MURK_EXPECTED_VAULT names")),
            "{other:?}"
        );
        let older = check(format!("{id}:6"));
        assert!(
            older
                .as_ref()
                .is_err_and(|e| e.contains("generation is 5, and the minimum is 6")),
            "{older:?}"
        );
        let malformed = check(format!("{id}:5:abc"));
        assert!(
            malformed
                .as_ref()
                .is_err_and(|e| e.contains("does not check a revision")),
            "{malformed:?}"
        );
    }

    #[test]
    fn murk_expected_vault_takes_an_id_and_a_minimum_only() {
        let id = "00112233445566778899aabbccddeeff";
        assert_eq!(
            parse_expected_vault(&format!(" {id}:12\n")),
            Ok(ExpectedVault {
                vault_id: id.into(),
                min_generation: 12,
            })
        );
        // A revision part is refused, never ignored: this release does not
        // check it, and a value that names one must not seem to.
        let three = parse_expected_vault(&format!("{id}:12:{}", "ab".repeat(32)));
        assert!(
            three
                .as_ref()
                .is_err_and(|e| e.contains("does not check a revision")
                    && e.contains("<vault id>:<minimum generation>")),
            "{three:?}"
        );
        // Set but empty is refused, not read as unset: a missing CI secret
        // expands to nothing and must not turn the check off.
        for empty in ["", "  \n"] {
            let refused = parse_expected_vault(empty);
            assert!(
                refused.as_ref().is_err_and(
                    |e| e.contains("set but empty") && e.contains("unset MURK_EXPECTED_VAULT")
                ),
                "{empty:?}: {refused:?}"
            );
        }
        for bad in [
            id.to_string(),
            format!("{id}:"),
            format!("{id}:-1"),
            format!("{id}:+1"),
            format!("{id}:{}", MAX_GENERATION + 1),
            format!("{}:1", id.to_uppercase()),
            "0011:1".to_string(),
            format!("{id}:1:2:3"),
        ] {
            assert!(parse_expected_vault(&bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn a_trusted_signers_first_key_waits_for_confirmation_then_is_pinned() {
        let (vk_a, vk_b) = vks();
        // Alice's vault (her key pinned) adds Bob, who has not signed yet.
        let pin = pin_for(&Case::new(&[A], 3, A).with_vk(&vk_a));
        let next = Case::new(&[A, B], 4, A).with_vk(&vk_a);
        assert_eq!(verdict(&next.loaded(), Some(&pin), None), Verdict::Trusted);
        let pin = accepted_pin(&next.loaded(), Some(&pin), false);
        // Bob's first write registers his key himself: not believed.
        let by_bob = Case::new(&[A, B], 5, B).with_vk(&vk_b);
        let refusal = verdict(&by_bob.loaded(), Some(&pin), None);
        assert_eq!(
            refusal,
            Verdict::Refused(Refusal::UnconfirmedSignerKey {
                signer: B.into(),
                vk: vk_b.clone()
            })
        );
        let Verdict::Refused(r) = refusal else {
            unreachable!()
        };
        assert!(r.acceptable());
        // `murk trust` confirms it; from then on Bob's writes load.
        let pin = accepted_pin(&by_bob.loaded(), Some(&pin), true);
        assert_eq!(pin.signers.get(B), Some(&vk_b));
        let again = Case::new(&[A, B], 6, B).with_vk(&vk_b);
        assert_eq!(verdict(&again.loaded(), Some(&pin), None), Verdict::Trusted);
    }

    #[test]
    fn a_registry_entry_is_believed_from_a_trusted_signers_vault_and_never_replaced() {
        let (vk_a, vk_b) = vks();
        let mut by_alice = Case::new(&[A, B], 3, A).with_vk(&vk_a);
        by_alice.registry = BTreeMap::from([(A.into(), vk_a.clone()), (B.into(), vk_b.clone())]);
        let pin = pin_for(&by_alice);
        assert_eq!(pin.signers.get(B), Some(&vk_b));
        // Bob's key arrived through Alice's signed vault: his write loads.
        let by_bob = Case::new(&[A, B], 4, B).with_vk(&vk_b);
        assert_eq!(
            verdict(&by_bob.loaded(), Some(&pin), None),
            Verdict::Trusted
        );
        // A vault claiming another key for Bob (a forger poisoning the
        // registry under Bob's name) is refused, and `murk trust` cannot
        // accept it.
        let forged = Case::new(&[A, B], 5, B).with_vk(&vk_a);
        let v = verdict(&forged.loaded(), Some(&pin), None);
        assert_eq!(
            v,
            Verdict::Refused(Refusal::SignerKeyChanged { signer: B.into() })
        );
        let Verdict::Refused(r) = v else {
            unreachable!()
        };
        assert!(!r.acceptable());
        // Nor does a later accepted vault's registry overwrite a pinned key.
        let mut rewrite = Case::new(&[A, B], 5, A).with_vk(&vk_a);
        rewrite.registry = BTreeMap::from([(B.into(), vk_a.clone())]);
        let pin = accepted_pin(&rewrite.loaded(), Some(&pin), false);
        assert_eq!(pin.signers.get(B), Some(&vk_b));
    }

    #[test]
    fn a_non_member_cannot_bind_a_group_members_key_then_sign_as_them() {
        // Pinned: ops = [bob], Alice and Mallory trusted with confirmed keys,
        // Bob has never signed. Revision 1 by Mallory changes no group but
        // registers her own key under Bob's name; revision 2 is "signed by
        // Bob" with that key and adds Mallory to ops.
        let (vk_a, vk_m) = vks();
        let ops = |members: &[&str]| {
            BTreeMap::from([(
                "ops".to_string(),
                members.iter().map(|m| (*m).to_string()).collect::<Vec<_>>(),
            )])
        };
        let mut start = Case::new(&[A, B, M], 1, A).with_vk(&vk_a);
        start.groups = ops(&[B]);
        start.registry = BTreeMap::from([(A.into(), vk_a.clone()), (M.into(), vk_m.clone())]);
        let pin = pin_for(&start);

        let mut bind = Case::new(&[A, B, M], 2, M).with_vk(&vk_m);
        bind.groups = ops(&[B]);
        bind.registry = BTreeMap::from([(M.into(), vk_m.clone()), (B.into(), vk_m.clone())]);
        assert_eq!(verdict(&bind.loaded(), Some(&pin), None), Verdict::Trusted);
        let pin = accepted_pin(&bind.loaded(), Some(&pin), false);
        assert_eq!(pin.signers.get(B), None, "Mallory may not bind Bob's key");

        // The self-add is refused, so nothing of it reaches the pin: the
        // pinned membership stays ops = [bob].
        let mut self_add = Case::new(&[A, B, M], 3, B).with_vk(&vk_m);
        self_add.groups = ops(&[B, M]);
        assert_eq!(
            verdict(&self_add.loaded(), Some(&pin), None),
            Verdict::Refused(Refusal::UnconfirmedSignerKey {
                signer: B.into(),
                vk: vk_m.clone()
            })
        );
        assert_eq!(pin.groups, canonical_groups(&ops(&[B])));

        // A member of ops may vouch for Bob's key.
        let vk_b = crate::signing::age_signing_key(&[3u8; 32]).verifying_key();
        let mut by_member = Case::new(&[A, B, M], 2, A).with_vk(&vk_a);
        by_member.groups = ops(&[A, B]);
        by_member.registry = BTreeMap::from([(B.into(), vk_b.clone())]);
        let mut member_pin = pin_for(&start);
        member_pin.groups = canonical_groups(&ops(&[A, B]));
        let member_pin = accepted_pin(&by_member.loaded(), Some(&member_pin), false);
        assert_eq!(member_pin.signers.get(B), Some(&vk_b));
    }

    #[test]
    fn env_signers_pin_the_verifying_key_of_age_signers() {
        let (vk_a, vk_b) = vks();
        let c = Case::new(&[A], 1, A).with_vk(&vk_a);
        let good = TrustedSigners::from([(A.to_string(), Some(vk_a.clone()))]);
        assert_eq!(verdict(&c.loaded(), None, Some(&good)), Verdict::Trusted);
        let wrong = TrustedSigners::from([(A.to_string(), Some(vk_b))]);
        assert_eq!(
            verdict(&c.loaded(), None, Some(&wrong)),
            Verdict::Refused(Refusal::SignerKeyChanged { signer: A.into() })
        );
    }

    #[test]
    fn trusted_signer_entries_need_a_verifying_key_for_age_keys() {
        let (secret, age) = crate::testutil::generate_keypair();
        let _ = secret;
        let (vk, _) = vks();
        assert_eq!(
            parse_trusted_signer(&format!("{age}:{vk}")),
            Ok((age.clone(), Some(vk.clone())))
        );
        assert!(
            parse_trusted_signer(&age)
                .unwrap_err()
                .contains("needs its verifying key")
        );
        assert!(parse_trusted_signer(&format!("{age}:nope")).is_err());
        let ssh = crate::testutil::SSH_ED25519_PK;
        assert_eq!(
            parse_trusted_signer(&format!("{ssh} me@host")),
            Ok((ssh.to_string(), None))
        );
        assert!(parse_trusted_signer("not-a-key").is_err());
    }

    /// The format `MURK_TRUSTED_SIGNERS` and anchors share refuses a weak
    /// verifying key, a weak ssh-ed25519 key, and a non-canonical encoding of
    /// a point (y = p + 1, the identity spelled another way).
    #[test]
    fn trusted_signer_entries_refuse_weak_and_non_canonical_keys() {
        use base64::Engine;
        let b64 = |b: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(b);
        let (_, age) = crate::testutil::generate_keypair();
        for (name, point) in crate::testutil::WEAK_ED25519_KEYS {
            for entry in [
                format!("{age}:{}", b64(&point)),
                crate::testutil::ssh_ed25519_line(&point),
            ] {
                let err = parse_trusted_signer(&entry).unwrap_err();
                assert!(err.contains("weak (small-order)"), "{name}: {err}");
            }
        }
        let mut p_plus_one = [0xffu8; 32];
        p_plus_one[0] = 0xee;
        p_plus_one[31] = 0x7f;
        let err = parse_trusted_signer(&format!("{age}:{}", b64(&p_plus_one))).unwrap_err();
        assert!(err.contains("non-canonical"), "{err}");
    }

    fn assessment(pin: Option<TrustPin>, external: Option<TrustedSigners>) -> Assessment {
        Assessment {
            verdict: Verdict::Trusted,
            pin,
            env_signers: None,
            external,
            expected: None,
            shared_with: Vec::new(),
        }
    }

    #[test]
    fn trusted_ssh_signers_are_the_pins_ssh_keys_without_grants() {
        let ssh = crate::testutil::SSH_ED25519_PK;
        let other =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJI7KsDGxx+I8XZQwtbgoEYDfuNd9fQ4MzcHHUmtIau9";
        let pin = TrustPin {
            v: pins::PIN_VERSION,
            trusted: [A, ssh, other, "ssh-rsa AAAAB3xyz"]
                .iter()
                .map(|k| (*k).to_string())
                .collect(),
            grants: [other.to_string()].into(),
            ..TrustPin::default()
        };
        // Only ssh-ed25519 keys, and a grant key never counts.
        let got = assessment(Some(pin.clone()), None).trusted_ssh_signers(&BTreeMap::new());
        assert_eq!(got, vec![ssh.to_string()]);

        // A grant the vault carries now excludes its key too, even where the
        // pin has not seen the grant yet.
        let mut grants = BTreeMap::new();
        grants.insert(
            "bot".to_string(),
            types::GrantEntry {
                pubkey: format!("{ssh} bot@host"),
                ..Default::default()
            },
        );
        assert_eq!(
            assessment(Some(pin), None).trusted_ssh_signers(&grants),
            Vec::<String>::new()
        );
    }

    #[test]
    fn trusted_ssh_signers_prefer_the_external_set_over_the_pin() {
        let ssh = crate::testutil::SSH_ED25519_PK;
        let other =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJI7KsDGxx+I8XZQwtbgoEYDfuNd9fQ4MzcHHUmtIau9";
        let pin = TrustPin {
            v: pins::PIN_VERSION,
            trusted: [ssh.to_string()].into(),
            ..TrustPin::default()
        };
        let external = env(&[&format!("{other} ci@runner")]);
        let got =
            assessment(Some(pin), Some(external.clone())).trusted_ssh_signers(&BTreeMap::new());
        assert_eq!(got, vec![other.to_string()]);
        // With no pin at all the external set still applies.
        let got = assessment(None, Some(external)).trusted_ssh_signers(&BTreeMap::new());
        assert_eq!(got, vec![other.to_string()]);
    }

    #[test]
    fn trusted_ssh_signers_are_empty_without_a_trust_decision() {
        // No pin, or a legacy pin that records no decision.
        assert_eq!(
            assessment(None, None).trusted_ssh_signers(&BTreeMap::new()),
            Vec::<String>::new()
        );
        let legacy = TrustPin {
            trusted: [crate::testutil::SSH_ED25519_PK.to_string()].into(),
            ..TrustPin::default()
        };
        assert_eq!(
            assessment(Some(legacy), None).trusted_ssh_signers(&BTreeMap::new()),
            Vec::<String>::new()
        );
    }

    /// A merge result that lists a key removed where the removal applies is
    /// refused, even when both sides list it above the removal. Where the
    /// removal does not apply (a branch accepted before it), a side above the
    /// removal that lists the key still re-adds it.
    #[test]
    fn row_r_i10_h_merge_result() {
        let mut pin = TrustPin {
            v: pins::PIN_VERSION,
            removed: BTreeMap::from([("age1bob".to_string(), 4)]),
            removed_on: BTreeMap::from([("age1bob".to_string(), BTreeSet::from(["main".into()]))]),
            branches: BTreeMap::from([("main".to_string(), 4), ("old".to_string(), 3)]),
            ..TrustPin::default()
        };
        let mut side = crate::testutil::empty_vault();
        side.recipients = vec!["age1alice".into(), "age1bob".into()];
        side.generation = 9;
        let merged = side.clone();
        let on = |b: &str| Checkout::at(HeadState::Branch(b.into()));
        eprintln!("ROW R-I10-h:merge-result DECISIVE");
        assert_eq!(
            removed_key_kept_by_merge(Some(&pin), &merged, &[&side, &side], &on("main")),
            Some(("age1bob".to_string(), 4))
        );
        assert_eq!(
            removed_key_kept_by_merge(Some(&pin), &merged, &[&side, &side], &on("old")),
            None
        );
        pin.removed_on.clear();
        assert!(
            removed_key_kept_by_merge(Some(&pin), &merged, &[&side, &side], &on("old")).is_some(),
            "with no branch entry the removal applies everywhere"
        );
    }

    /// `murk trust` of another vault at the same path clears the agent
    /// grant keys the pin recorded for the old vault, and its sidecar's
    /// grant records, so the old vault's grants never refuse members of the
    /// new one.
    #[test]
    fn row_r_i16_c_other_vault() {
        let old = Case::new(&["age1alice"], 3, "age1alice");
        let mut prior = accepted_pin(&old.loaded(), None, false);
        prior.grants.insert("age1grant".into());
        prior
            .sidecar
            .revoked_grants_seen
            .insert("age1grant".into(), BTreeSet::from(["00".repeat(16)]));
        let mut other = Case::new(&["age1alice", "age1grant"], 1, "age1alice");
        other.vault.vault_id = "ffeeddccbbaa99887766554433221100".into();
        let pin = accepted_pin(&other.loaded(), Some(&prior), true);
        assert_eq!(pin.vault_id, other.vault.vault_id);
        eprintln!("ROW R-I16-c:other-vault DECISIVE");
        assert!(pin.grants.is_empty(), "pin.grants: {:?}", pin.grants);
        assert!(pin.sidecar.revoked_grants_seen.is_empty());
    }
}
