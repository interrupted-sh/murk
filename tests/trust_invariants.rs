// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault trust invariants over random multi-machine histories.
//!
//! Four people share a git remote: alice (two machines), bob, carol, and dave,
//! who starts outside the vault. Each machine is its own clone with its own
//! `HOME`, so its own trust pin. A CI runner loads with a fresh `HOME` and
//! `MURK_TRUSTED_SIGNERS`, and an agent grant loads with its key-file anchor.
//! Each case runs a random sequence of: saves, `circle authorize` / `revoke`,
//! vouching (a member registers a signing key they control for another
//! recipient), `git merge` through the murk driver, `murk trust`, pushes of a
//! branch, loads of the branch tip, an older revision, a new branch, a pushed
//! branch or a detached HEAD, `murk diff` against an older revision, an agent
//! grant, forgeries (a vault rebuilt from any revision the attacker could
//! open, with a chosen generation, signed by their own key or as a recipient
//! whose registry entry holds a key they control), replays of old
//! revisions, and two composite removal shapes: a revoke on a topic branch
//! fast-forwarded into `main` before a stale fork lands there
//! ([`Op::PrFlow`]), and a revoke loaded on `main` below the machine's own
//! highest counter ([`Op::BranchCurrent`]). Each counts a decisive kind
//! with a floor in a long run.
//!
//! Every vault in the run is traced to who produced it and when. Each random
//! case starts from a world with a revoke that only alice's machine has seen
//! and a pushed branch, and runs up to 24 steps. After every step the harness
//! checks:
//!
//! - **Revoked signers stay out.** Once an observer (a machine, CI, the agent,
//!   which follows the machine that minted it) has accepted a vault that
//!   removes X, it never accepts (by a load, `murk trust`, `murk diff` or the
//!   merge driver), at a commit whose history contains that vault, a vault X
//!   produced after that revoke, whichever key signed it, nor a vault
//!   produced after the revoke that lists X again without a `circle
//!   authorize` of X since. Until the removal reaches a branch, X is still a
//!   member there.
//! - **No reads after removal.** X never decrypts a value first written in a
//!   vault that did not list X, unless X was authorized again afterwards.
//! - **Value lineage.** A machine never accepts, on a branch, a value older
//!   than the latest it accepted there for the same key, or one that a later
//!   deletion removed, unless it ran `murk trust` on exactly that file. (Values
//!   name the step that wrote them.) A genuine file from a stale fork, with a
//!   counter above the mark, gets past every rollback rule today, so the
//!   oracle fails a step only once row `R-L-load` is enforced; until then each
//!   hit is counted and printed as a known open violation.
//! - The access invariants for the commands a member runs: a refused command
//!   leaves the vault byte-for-byte unchanged; after an accepted write the
//!   writer's machine loads the vault again; and a saved value is readable by
//!   exactly the people the harness's own authorize, revoke and merge steps say
//!   the vault lists (no widening, no drop), never by the vault's own
//!   recipient list.
//! - **A revoke takes its grants with it.** The vault a revoke of X writes
//!   keeps no agent grant whose anchor trusts X.
//! - **An environment-anchored observer only narrows its pin.** A CI runner
//!   that keeps its `HOME` loads with `MURK_TRUSTED_SIGNERS`; its pin may
//!   change in counters and marks, the signed bit, the grants seen and an
//!   empty vault id, and nothing else.
//!
//! Stored sequences run first. Each is scripted: every step must run, a load
//! of an honest vault must be accepted before the decisive step, and the
//! decisive step must be accepted or refused as the scenario requires, so a
//! sequence cannot pass without making its attack.
//!
//! Every stored sequence counts the decisive steps it ran and fails when that
//! is fewer than its script names. The random sequences count what they skip:
//! forgeries (one the child process or murk turned down, or that no revision
//! allowed), grants, agent loads and every other step that did not apply, and
//! how many cases each oracle judged where it could have failed. The counts
//! print once per run with the proptest seed (`MURK_TRUST_SEED` replays it). A
//! run with enough forgeries to judge that skips every one of them fails, as
//! the nightly soak relies on, and so does a run of twenty cases or more in
//! which an oracle fell below its floor.
//!
//! The generator also has constructors for the cases a plain history never
//! reaches: a second vault path (`CopyVault`), erin's unsigned saves and an
//! unsigned forgery with the pinned id, a forged ancestor under a genuine
//! revision with a deleted secret and a cherry-pick, and a former grant key
//! listed as a recipient. Each is drawn only while the rows that cover it are
//! enforced in `tests/invariant_rows.tsv`, so an open bug does not turn the
//! random run red; the run prints which constructors are gated off.
//! `MURK_TRUST_ASSUME_FIXED` (`all`, or a list of row ids) draws them anyway
//! and makes the oracles that wait for a fix fail, to see what today's murk
//! does with them.
//!
//! The rows of the trust and merge harness (`tests/invariant_rows.tsv`) that
//! need several machines are `row_*` tests here, each running its own scripted
//! scenario through `common::rows::check`. The team is mixed: besides the age
//! members there is erin, who works on an ssh-rsa key. That key cannot sign,
//! so everything erin saves is unsigned. She is not one of [`PEOPLE`], and the
//! random sequences act as her only through her own constructors.
//!
//! `MURK_TRUST_CASES` sets the number of cases (default 8, sized for CI);
//! `.github/workflows/invariants.yaml` runs a nightly soak with many more.

mod common;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use common::cast::{self, Who};
use common::machines::{Machine, copy_dir, git_in};
use common::rows::Probe;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed, TestCaseError, TestRunner};

const PEOPLE: [&str; 4] = ["alice", "bob", "carol", "dave"];
/// Machines and the person each belongs to.
const MACHINES: [(&str, usize); 5] = [
    ("alice-1", 0),
    ("alice-2", 0),
    ("bob-1", 1),
    ("carol-1", 2),
    ("dave-1", 3),
];
const KEYS: [&str; 3] = ["K1", "K2", "K3"];
/// The largest vault generation murk accepts: 2^53 - 1.
const GENERATION_CAP: u64 = (1 << 53) - 1;

/// The one machine of the person who works on an ssh-rsa key.
const ERIN: &str = "erin-1";

/// The place of the CI key in a set of expected readers, after the people.
const CI_READER: usize = PEOPLE.len();
/// The place of erin among the machines whose accepted values the value
/// oracle follows, after the age machines.
const ERIN_M: usize = MACHINES.len();

/// A throwaway ssh-rsa key (test only; `tests/authenticity.rs` holds the same
/// one). Like a hardware or plugin key, it cannot sign.
const RSA_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA5jkmGpN5TpKvfi9DRPmuKqW0wW1gVy8ZS/ShQ1rhBeVsHf7v+1aM
yH/c4nkmE5LyH3OVDURX5mkdbKPCwwa8DvIkzzP8XO+VBd0U3tz/Xug0pLToqDM8Bd7JAr
BXGAX+78RlDrRkCFf4xMS0sZOMcIN7hyK5NeIoye4dThmgSConD/lk6/Hd5ahvvIMRAJVI
x4AUMnVAEzOF7lVbMWI9vPaUeCnggOjUxKr1n7n55bjtCzDG/AcVijE7WZZ0tC2u5lTS/Y
fLtsa54ZfF6koVUZuiztHdva86CFqopmqKIkzcB7uUYawz18eL7ad2tcIjOClnBAOd4JqO
WcrVukeGEQAAA8BCAaNiQgGjYgAAAAdzc2gtcnNhAAABAQDmOSYak3lOkq9+L0NE+a4qpb
TBbWBXLxlL9KFDWuEF5Wwd/u/7VozIf9zieSYTkvIfc5UNRFfmaR1so8LDBrwO8iTPM/xc
75UF3RTe3P9e6DSktOioMzwF3skCsFcYBf7vxGUOtGQIV/jExLSxk4xwg3uHIrk14ijJ7h
1OGaBIKicP+WTr8d3lqG+8gxEAlUjHgBQydUATM4XuVVsxYj289pR4KeCA6NTEqvWfufnl
uO0LMMb8BxWKMTtZlnS0La7mVNL9h8u2xrnhl8XqShVRm6LO0d29rzoIWqimaooiTNwHu5
RhrDPXx4vtp3a1wiM4KWcEA53gmo5ZytW6R4YRAAAAAwEAAQAAAQATOAwdRdhnnck2sH1e
IbXPa5vmVdooDQ+AjsBznf+Q/XEEJAcmpTgFeN8YrOJn2emKhJyZye3Il1fUfOtCWqqSWN
aH0aAspfd70NPwMuTCqIHUiiGuAPDu0IVZSx1KLR32KCADlT2QkL98tasb8+RSdDd4tYZe
oC2lhdI+ddcyjuG+ZS2FJ9dcBAeVb9J6MWH+PFyiisrY51MZDT5xFZcB7jtTtJitWympWz
OtISSTyvIwMpbmwLDcVfK1Gs+n0MrxHJxpXblycg/fASo2muJaOHdpxouu+CUXIK3+pozJ
MHfDm3Xly34PVZefn2Ykwag+aHhlcevhVUZz5AFa7JFNAAAAgQCea2fencESK6AwmQl18u
yZTZDSk1vDWsUl+9oNAvmkL0yteuU3f9VsttC2wjtJ+tYE5M/rUBf/PirEqKCHEKzo/1ag
67mIhkGBzHQYviZdfzxKbkUW/+4DJ82nxbaeyRfMatmIs7sLSCGLY1N9oiUicAqsiIbiG6
OvINjmXinvGgAAAIEA+LJ8tuKlCWu0p8BX/R3fQW8BBVk8TcZVn7Dnf4Ssu6U+tjIuK8a3
mHIuqiTYMrR58u3WUHxsje5N/V/He2Je1HW7YCa1htX+4Gk4ypcwXZDhzmT8B/U8XHvkdx
UUl4thRvTUEZkUEJUzUSYts0s4MEwHw1tEL/E+KrHUpoTXVtMAAACBAOz7yeQQ0RZdz90R
BMJHggiseL9CcCSdtzPBycgZo8UHJIH0kYRAujIM6XWfzzcfTNQQ3slZ9Ht9D4Fmn3G7uX
sI+cTp5/1HL1bGywPCCkdCcTm1CEFtfiO5ZJgS7LELv5mP+CUv8KDnuZJdNaUWanUwUiwD
+kddyH0+YIgSBSkLAAAAB2h3QHRlc3QBAgM=
-----END OPENSSH PRIVATE KEY-----
";

#[derive(Clone, Copy)]
struct P(usize);
impl fmt::Debug for P {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PEOPLE[self.0])
    }
}

#[derive(Clone, Copy)]
struct M(usize);
impl fmt::Debug for M {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(MACHINES[self.0].0)
    }
}

#[derive(Clone, Copy)]
struct K(usize);
impl fmt::Debug for K {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(KEYS[self.0])
    }
}

/// What a machine checks out before it loads.
#[derive(Clone, Copy, Debug)]
enum At {
    /// Its local `main`.
    Main,
    /// A detached HEAD at the n-th commit it knows (newest first, wrapping).
    Detached(usize),
    /// A new branch at the n-th commit it knows.
    NewBranch(usize),
    /// A detached HEAD at the n-th pushed branch.
    Pushed(usize),
    /// A local branch named after the n-th pushed branch, at its tip: a pull
    /// request checked out for review.
    PushedBranch(usize),
    /// A detached HEAD at the remote's `main`, as a fresh pull would see it.
    OriginMain,
}

/// Whom a revoke names.
#[derive(Clone, Copy, Debug)]
enum Target {
    Person(P),
    /// The n-th (wrapping) other person the machine's vault lists.
    OtherMember(usize),
}

/// Who forges.
#[derive(Clone, Copy, Debug)]
enum Attacker {
    Person(P),
    /// The person most recently revoked (the step is skipped before any).
    Revoked,
}

/// The signing key a vouch registers for someone else.
#[derive(Clone, Copy, Debug)]
enum Planted {
    /// A key the voucher holds.
    Sock,
    /// A low-order Ed25519 point (the identity), under which a signature of
    /// all zeros except `R` = identity checks for any message unless the
    /// verifier rejects weak keys.
    Weak,
}

/// How a forgery is signed.
#[derive(Clone, Copy, Debug)]
enum Sign {
    /// With the attacker's own key, as themselves.
    Own,
    /// As a recipient whose registry entry is the planted key.
    AsPlanted(Planted),
    /// As another recipient the base lists, after setting their registry
    /// entry to the planted key in the forgery itself. A weak key can only
    /// arrive this way: no vault murk opens carries one.
    Plants(Planted),
    /// With the attacker's own key, as themselves, in the murk 0.13 format
    /// (header 2.0, no vault id or counter, a view-1 signature in the meta),
    /// as a member's murk 0.13 wrote it: the generation is not carried. Only
    /// stored sequences set it.
    Legacy,
    /// As [`Sign::Legacy`], with another creation stamp: another vault's 0.13
    /// file, whose upgrade would take another id.
    LegacyOther,
}

/// The identity point, compressed: a weak verifying key.
const WEAK_VK: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
};

fn weak_vk_b64() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(WEAK_VK)
}

/// Which old revision a replay commits again.
#[derive(Clone, Copy, Debug)]
enum Old {
    /// The n-th commit on the remote, newest first (wrapping).
    Nth(usize),
    /// The newest commit whose vault lists the person most recently revoked.
    ListingRevoked,
}

/// Which revision a forgery starts from.
#[derive(Clone, Copy, Debug)]
enum Base {
    /// The n-th commit on the remote, newest first (wrapping).
    Nth(usize),
    /// The newest commit whose vault lists the attacker.
    NewestOpenable,
}

/// A ref on the remote that CI or the agent checks out.
#[derive(Clone, Copy, Debug)]
enum Ref {
    Main,
    Pushed(usize),
}

/// The generation a forgery claims.
#[derive(Clone, Copy, Debug)]
enum Gen {
    /// One past the base revision's, as a save makes it.
    Next,
    /// A thousand past the base revision's.
    Jump,
    /// The largest generation murk accepts (2^53 - 1, exact in a JSON
    /// number), so the counter cannot move past it.
    Max,
    /// `u64::MAX`, above what murk accepts.
    AboveCap,
}

/// Where an attacker pushes.
#[derive(Clone, Copy, Debug)]
enum Dest {
    Main,
    Branch,
}

/// What a [`Op::Group`] step does.
#[derive(Clone, Copy, Debug)]
enum GroupAct {
    /// `murk group create`: the machine's person is its first member.
    Create(&'static str),
    /// `murk group add --member`.
    Add(&'static str, P),
    /// `murk group rm` with no member: the group is deleted.
    Delete(&'static str),
}

#[derive(Clone, Debug)]
enum Op {
    /// `murk add KEY` on a machine, committed there.
    Save {
        m: M,
        key: K,
    },
    Authorize {
        m: M,
        who: P,
    },
    Revoke {
        m: M,
        who: Target,
    },
    /// The machine's person authorizes `who` (if needed) and registers a
    /// signing key the machine's person controls as `who`'s, signed as
    /// themselves. Library code: murk has no command for it.
    Vouch {
        m: M,
        who: P,
        key: Planted,
    },
    /// Fetch, merge `origin/main` into `main` (the murk driver runs on a
    /// conflict), push.
    Sync {
        m: M,
    },
    /// `murk trust --yes`, run only where a person reviewing it would accept:
    /// a vault no observer rule forbids. With `forgery`, that includes a
    /// vault a member wrote with their own code, as a reviewer who takes the
    /// hint to override a refusal would (only stored sequences set it).
    Trust {
        m: M,
        forgery: bool,
    },
    /// Check out and load (`murk export`).
    Load {
        m: M,
        at: At,
    },
    /// `murk diff <rev> --show-values` against the n-th commit the machine knows.
    Diff {
        m: M,
        rev: usize,
    },
    /// `murk agent grant --only K1`, committed; the agent then loads with the
    /// key file murk keeps on the minting machine.
    ///
    /// A key file handed off with `--out` to an agent that runs elsewhere is
    /// left out on purpose: the revoke cannot delete that copy, so its anchor
    /// still trusts the revoked signer, who can sign a vault from before the
    /// revoke in which the grant is live. That is an accepted, documented
    /// limit (the grant's TTL bounds it), not an invariant this harness holds.
    Grant {
        m: M,
    },
    AgentLoad {
        at: Ref,
    },
    CiLoad {
        at: Ref,
    },
    /// `by` rebuilds the n-th revision on the remote (one they can open) with
    /// a changed K1 and the chosen generation, signs it (as themselves, or as
    /// a recipient whose registry entry holds a key they control) and pushes.
    Forge {
        by: Attacker,
        base: Base,
        generation: Gen,
        sign: Sign,
        to: Dest,
    },
    /// Someone with push access commits the n-th revision's vault again.
    Replay {
        rev: Old,
        to: Dest,
    },
    /// Merge the n-th pushed branch into the machine's current checkout (the
    /// murk driver runs on a conflict). With `take_theirs`, a refused merge
    /// is resolved as murk's hint says: take the branch's vault and commit
    /// (only stored sequences set it).
    MergeBranch {
        m: M,
        branch: usize,
        take_theirs: bool,
    },
    /// Push the machine's current checkout to a new branch on the remote,
    /// as a pull request would.
    Push {
        m: M,
    },
    /// A group command on a machine, committed there.
    Group {
        m: M,
        act: GroupAct,
    },
    /// `murk policy set --allow-tag nothing` on a machine, committed there.
    Policy {
        m: M,
    },
    /// `by`, a recipient who is not a member of `group`, writes a vault that
    /// lists them as one with their own code (the CLI refuses the change),
    /// signs it as themselves and pushes it. Only stored sequences set it.
    Join {
        by: P,
        group: &'static str,
        to: Dest,
    },
    /// A CI runner that keeps its `HOME`, and so its pin, between loads, with
    /// `MURK_TRUSTED_SIGNERS`: an environment-anchored load must only narrow
    /// the pin.
    CiKeepLoad {
        at: Ref,
    },
    /// `murk rm KEY` on a machine, committed there. Only drawn with the forged
    /// ancestors, which make a deleted secret come back.
    Rm {
        m: M,
        key: K,
    },
    /// `by` pushes a branch of two commits: a forged ancestor (see
    /// [`Ancestor`]) and, on top of it, the genuine n-th revision.
    AncestorBranch {
        by: P,
        kind: Ancestor,
        rev: usize,
    },
    /// `git cherry-pick` of the n-th pushed branch's tip onto a machine's
    /// main: the merge driver runs with the tip's parent as the ancestor.
    CherryPick {
        m: M,
        branch: usize,
    },
    /// Copy the machine's vault to `copy.murk` beside it and commit: a second
    /// vault path with the same vault id.
    CopyVault {
        m: M,
    },
    /// `murk trust --vault copy.murk`: accept the byte copy of a vault this
    /// machine has pinned.
    TrustCopy {
        m: M,
    },
    /// erin saves a value, committed on her machine. Her key cannot sign, so
    /// the vault she writes is unsigned.
    ErinSave {
        key: K,
    },
    /// erin merges `origin/main` and pushes hers.
    ErinSync,
    /// erin checks out and loads.
    ErinLoad {
        at: At,
    },
    /// `by` pushes an unsigned vault with the team vault's id, a generation
    /// three above the newest they read, and dave as one more recipient.
    ForgeUnsigned {
        by: P,
        to: Dest,
    },
    /// `by` pushes a vault in which the agent grant's key is an ordinary
    /// recipient with no grant record, as it reads once the grant is revoked
    /// and the key authorized again.
    ListGrantKey {
        by: P,
        to: Dest,
    },
    /// The agent loads with its key presented as `how`, then tries to read
    /// outside its scope and to write.
    AgentProbe {
        at: Ref,
        how: Presented,
    },
    /// `murk trust --re-add <who's key> --yes` on machine `m` at its
    /// checked-out HEAD: this machine's consent to trust `who` again. It
    /// re-adds someone `m` holds a record for, favouring one the vault
    /// checked out lists again (see the step for the order).
    ReAdd {
        m: M,
        who: P,
    },
    /// Machine `m` holds a removal record for a person: another machine
    /// (`by`, or the next one that fits) syncs, authorizes them again and
    /// pushes; `m` then loads the tip (refused) and runs `ReAdd` for them.
    AuthorizeAgain {
        m: M,
        by: M,
    },
    /// The pull-request removal (row R-I10-h:pr-flow): machine `m` syncs
    /// and loads `main`; it revokes the n-th fitting member on a topic
    /// branch off `main`; a teammate's machine then saves twice on a branch
    /// off the same commit (a stale fork that still lists them); `m` merges
    /// the topic into `main` (a fast-forward), a repo writer commits the
    /// stale fork there, and `m` loads `main`.
    PrFlow {
        m: M,
        n: usize,
    },
    /// A removal loaded as the branch's next state (row
    /// R-I10-h:branch-current): machine `m` syncs and loads `main`, then
    /// saves three times on a feature branch; a teammate's machine revokes
    /// the n-th fitting member over the same `main` and pushes it; `m` saves
    /// a stale fork twice off that `main`, fast-forwards its `main` to the
    /// revoke and loads it (below its own highest counter), then a repo
    /// writer commits the stale fork on `main` and `m` loads it.
    BranchCurrent {
        m: M,
        n: usize,
    },
}

/// The forged commit an [`Op::AncestorBranch`] puts under a genuine revision.
#[derive(Clone, Copy, Debug)]
enum Ancestor {
    /// The oldest revision with its signature removed: its id and MAC are
    /// intact.
    Stripped,
    /// A vault of the same id with no secrets, unsigned, written by `by`'s own
    /// code.
    Empty,
}

/// How the agent's key reaches murk.
#[derive(Clone, Copy, Debug)]
enum Presented {
    /// The key file without its comment lines (anchor, grant id, expiry).
    StrippedLines,
    /// The secret alone in `MURK_KEY`, on a runner with no pin.
    RawKey,
}

/// A family of generator constructors the random run draws only while every
/// row that covers it is enforced, so an open bug does not turn the random run
/// red. The rows are stored sequences elsewhere (and here); once they are
/// enforced the constructor is one more way to reach the same property.
struct Constructor {
    name: &'static str,
    rows: &'static [&'static str],
}

const CONSTRUCTORS: [Constructor; 5] = [
    // A byte copy of a pinned vault at a second path.
    Constructor {
        name: "copy-vault",
        rows: &["R-I8-e:a", "R-I8-b:c"],
    },
    // The member whose key cannot sign: own unsigned saves, and an unsigned
    // forgery with the pinned id.
    Constructor {
        name: "unsigned-erin",
        rows: &["R-I21-a", "R-I21-b", "R-I6-b", "R-I6-c", "R-I8-d"],
    },
    // A genuine first vault with its signature removed (id and MAC intact) as
    // the parent of a genuine revision, with a secret ours deleted and a
    // cherry-pick: the merge driver refuses such an ancestor, but any
    // cherry-pick of a revision ours already contains re-applies what ours
    // undid, which the superseded-pair rows cover.
    Constructor {
        name: "stripped-ancestor",
        rows: &["R-I11-d:stripped", "R-I11-f:a", "R-I11-f:b", "R-I11-f:c"],
    },
    // An empty forged pre-0.14 ancestor under a genuine revision, with a
    // deleted secret to resurrect.
    Constructor {
        name: "forged-ancestor",
        rows: &[
            "R-I11-a:1",
            "R-I11-a:2",
            "R-I11-c:1",
            "R-I11-c:2",
            "R-I11-d:two-way",
            "R-I11-f:a",
            "R-I11-f:b",
            "R-I11-f:c",
        ],
    },
    // A former grant key listed as a recipient, presented without its key-file
    // lines or as `MURK_KEY`.
    Constructor {
        name: "grant-recipient",
        rows: &["R-I16-a"],
    },
];

impl Constructor {
    /// Whether every covering row is enforced (or the test acts as if all
    /// open rows were fixed).
    fn open(&self) -> bool {
        self.rows.iter().all(|row| row_enforced(row))
    }

    /// The rows still keeping it out of the random run.
    fn waiting_for(&self) -> Vec<&'static str> {
        self.rows
            .iter()
            .copied()
            .filter(|row| !row_enforced(row))
            .collect()
    }
}

fn m() -> impl Strategy<Value = M> {
    prop_oneof![
        3 => Just(M(0)),
        1 => Just(M(1)),
        2 => Just(M(2)),
        2 => Just(M(3)),
        1 => Just(M(4)),
    ]
}

fn p() -> impl Strategy<Value = P> {
    (0..PEOPLE.len()).prop_map(P)
}

fn at() -> impl Strategy<Value = At> {
    prop_oneof![
        // Loads of `main` are what the rollback rules and the value oracle
        // judge; a detached HEAD or a new branch has no mark to compare with.
        8 => Just(At::Main),
        2 => (0..8usize).prop_map(At::Detached),
        2 => (0..8usize).prop_map(At::NewBranch),
        1 => (0..4usize).prop_map(At::Pushed),
        1 => (0..4usize).prop_map(At::PushedBranch),
        3 => Just(At::OriginMain),
    ]
}

fn reference() -> impl Strategy<Value = Ref> {
    prop_oneof![3 => Just(Ref::Main), 1 => (0..4usize).prop_map(Ref::Pushed)]
}

fn dest() -> impl Strategy<Value = Dest> {
    prop_oneof![3 => Just(Dest::Main), 1 => Just(Dest::Branch)]
}

fn op() -> BoxedStrategy<Op> {
    let mut arms: Vec<(u32, BoxedStrategy<Op>)> = vec![
        (
            3,
            (m(), (0..KEYS.len()).prop_map(K))
                .prop_map(|(m, key)| Op::Save { m, key })
                .boxed(),
        ),
        (
            1,
            (m(), p())
                .prop_map(|(m, who)| Op::Authorize { m, who })
                .boxed(),
        ),
        (
            3,
            (
                m(),
                prop_oneof![1 => p().prop_map(Target::Person), 3 => (0..3usize).prop_map(Target::OtherMember)],
            )
                .prop_map(|(m, who)| Op::Revoke { m, who })
                .boxed(),
        ),
        (
            1,
            (m(), p(), prop_oneof![2 => Just(Planted::Sock), 1 => Just(Planted::Weak)])
                .prop_map(|(m, who, key)| Op::Vouch { m, who, key })
                .boxed(),
        ),
        (3, m().prop_map(|m| Op::Sync { m }).boxed()),
        (1, m().prop_map(|m| Op::Trust { m, forgery: false }).boxed()),
        (
            3,
            (m(), at())
                .prop_map(|(m, at)| Op::Load { m, at })
                .boxed(),
        ),
        (
            1,
            (m(), 0..8usize)
                .prop_map(|(m, rev)| Op::Diff { m, rev })
                .boxed(),
        ),
        (2, m().prop_map(|m| Op::Grant { m }).boxed()),
        (1, reference().prop_map(|at| Op::AgentLoad { at }).boxed()),
        (2, reference().prop_map(|at| Op::CiLoad { at }).boxed()),
        (2, reference().prop_map(|at| Op::CiKeepLoad { at }).boxed()),
        (
            3,
            (
                prop_oneof![1 => p().prop_map(Attacker::Person), 2 => Just(Attacker::Revoked)],
                prop_oneof![1 => (0..8usize).prop_map(Base::Nth), 2 => Just(Base::NewestOpenable)],
                prop_oneof![
                    3 => Just(Gen::Next),
                    1 => Just(Gen::Jump),
                    1 => Just(Gen::Max),
                    1 => Just(Gen::AboveCap),
                ],
                prop_oneof![
                    3 => Just(Sign::Own),
                    1 => Just(Sign::AsPlanted(Planted::Sock)),
                    1 => Just(Sign::AsPlanted(Planted::Weak)),
                    1 => Just(Sign::Plants(Planted::Sock)),
                    1 => Just(Sign::Plants(Planted::Weak)),
                ],
                dest(),
            )
                .prop_map(|(by, base, generation, sign, to)| Op::Forge {
                    by,
                    base,
                    generation,
                    sign,
                    to,
                })
                .boxed(),
        ),
        (
            2,
            (
                prop_oneof![1 => (0..8usize).prop_map(Old::Nth), 1 => Just(Old::ListingRevoked)],
                dest(),
            )
                .prop_map(|(rev, to)| Op::Replay { rev, to })
                .boxed(),
        ),
        (
            1,
            (m(), 0..4usize)
                .prop_map(|(m, branch)| Op::MergeBranch {
                    m,
                    branch,
                    take_theirs: false,
                })
                .boxed(),
        ),
        (1, m().prop_map(|m| Op::Push { m }).boxed()),
        (
            2,
            (m(), p())
                .prop_map(|(m, who)| Op::ReAdd { m, who })
                .boxed(),
        ),
        (
            2,
            (m(), m())
                .prop_map(|(m, by)| Op::AuthorizeAgain { m, by })
                .boxed(),
        ),
        (
            2,
            (m(), 0..4usize)
                .prop_map(|(m, n)| Op::PrFlow { m, n })
                .boxed(),
        ),
        (
            2,
            (m(), 0..4usize)
                .prop_map(|(m, n)| Op::BranchCurrent { m, n })
                .boxed(),
        ),
    ];
    let [copy, unsigned, stripped, forged, grants] = &CONSTRUCTORS;
    if copy.open() {
        arms.push((1, m().prop_map(|m| Op::CopyVault { m }).boxed()));
        arms.push((2, m().prop_map(|m| Op::TrustCopy { m }).boxed()));
    }
    if unsigned.open() {
        arms.push((
            2,
            (0..KEYS.len())
                .prop_map(|key| Op::ErinSave { key: K(key) })
                .boxed(),
        ));
        arms.push((1, Just(Op::ErinSync).boxed()));
        arms.push((2, at().prop_map(|at| Op::ErinLoad { at }).boxed()));
        arms.push((
            2,
            (p(), dest())
                .prop_map(|(by, to)| Op::ForgeUnsigned { by, to })
                .boxed(),
        ));
    }
    // The kinds of forged ancestor whose rows are enforced. A deleted secret
    // (`Rm`) and a cherry-pick are what make either one reach a resurrection.
    let mut kinds = Vec::new();
    if stripped.open() {
        kinds.push((1, Just(Ancestor::Stripped).boxed()));
    }
    if forged.open() {
        kinds.push((1, Just(Ancestor::Empty).boxed()));
    }
    if !kinds.is_empty() {
        arms.push((
            2,
            (m(), 0..KEYS.len())
                .prop_map(|(m, key)| Op::Rm { m, key: K(key) })
                .boxed(),
        ));
        arms.push((
            2,
            (
                p(),
                proptest::strategy::Union::new_weighted(kinds),
                0..8usize,
            )
                .prop_map(|(by, kind, rev)| Op::AncestorBranch { by, kind, rev })
                .boxed(),
        ));
        arms.push((
            2,
            (m(), 0..4usize)
                .prop_map(|(m, branch)| Op::CherryPick { m, branch })
                .boxed(),
        ));
    }
    if grants.open() {
        arms.push((
            3,
            (p(), dest())
                .prop_map(|(by, to)| Op::ListGrantKey { by, to })
                .boxed(),
        ));
        arms.push((
            4,
            (
                reference(),
                prop_oneof![1 => Just(Presented::StrippedLines), 1 => Just(Presented::RawKey)],
            )
                .prop_map(|(at, how)| Op::AgentProbe { at, how })
                .boxed(),
        ));
    }
    proptest::strategy::Union::new_weighted(arms).boxed()
}

/// Who produced a vault file, and at which step.
#[derive(Clone, Copy, Debug)]
struct Origin {
    producer: Option<usize>,
    step: usize,
    /// Written by an attacker's code (a forgery).
    forged: bool,
    /// Written by library code rather than a murk command (a forgery or a
    /// vouch), so murk's own write checks never ran on it.
    custom: bool,
}

/// The identities and the starting state, built once per test binary.
struct Fixture {
    dir: tempfile::TempDir,
    people: Vec<Who>,
    socks: Vec<Who>,
    ci: Who,
    origins: HashMap<u64, Origin>,
}

fn blob_id(bytes: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// The vault id a vault file carries (empty when it has none: murk 0.13).
fn vault_id_of(bytes: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v["vault_id"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The generation a vault file carries (0 when it has none or does not parse).
fn generation_of(bytes: &[u8]) -> u64 {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v["generation"].as_u64())
        .unwrap_or(0)
}

fn key_path(root: &Path, label: &str) -> PathBuf {
    root.join("keys").join(format!("{label}.key"))
}

/// The trusted-signer entry for an age identity (`age1…:<verifying key>`).
fn signer_entry(who: &Who) -> String {
    format!("{}:{}", who.pubkey, verifying_key(who))
}

/// Write a key file only its owner can read (murk refuses anything looser).
fn write_key(path: &Path, secret: &str) {
    fs::write(path, secret).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn verifying_key(who: &Who) -> String {
    murk_cli::crypto::parse_identity(&who.secret)
        .unwrap()
        .signing_key()
        .expect("age keys sign")
        .verifying_key()
}

fn machine(root: &Path, i: usize) -> Machine {
    let (name, person) = MACHINES[i];
    Machine {
        name: name.to_string(),
        dir: root.join(name),
        home: root.join(format!("{name}-home")),
        key_file: key_path(root, PEOPLE[person]),
    }
}

/// erin's machine, the clone of the person on the ssh-rsa key.
fn erin_machine(root: &Path) -> Machine {
    Machine {
        name: ERIN.to_string(),
        dir: root.join(ERIN),
        home: root.join(format!("{ERIN}-home")),
        key_file: key_path(root, "erin"),
    }
}

/// erin's public key, as `circle authorize` takes it.
fn rsa_pubkey() -> String {
    murk_cli::crypto::parse_identity(RSA_SK)
        .unwrap()
        .pubkey_string()
        .unwrap()
}

/// Clones that never sign: the attacker's push clone, CI's and the agent's.
fn bystander(root: &Path, name: &str) -> Machine {
    Machine {
        name: name.to_string(),
        dir: root.join(name),
        home: root.join(format!("{name}-home")),
        key_file: key_path(root, "ci"),
    }
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("live");
    fs::create_dir_all(root.join("keys")).unwrap();
    let out = git_in(&root, &root, None)
        .args(["init", "-q", "--bare", "-b", "main", "origin.git"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");

    // alice's key comes from `murk init`; everyone else's is generated.
    let a1_home = root.join("alice-1-home");
    let first = Machine::clone(&root, "alice-1", &root.join("unused.key"));
    let mut init = common::murk_bin(&a1_home);
    init.current_dir(&first.dir)
        .arg("init")
        .write_stdin("alice\n")
        .assert()
        .success();
    let env = fs::read_to_string(first.dir.join(".env")).unwrap();
    let stored = env
        .lines()
        .find_map(|l| l.strip_prefix("export MURK_KEY_FILE="))
        .expect("init writes MURK_KEY_FILE")
        .trim_matches('\'');
    let alice = Who::from_secret("alice", &fs::read_to_string(stored).unwrap());
    fs::remove_file(first.dir.join(".env")).unwrap();
    let mut people = vec![alice];
    people.extend(PEOPLE[1..].iter().map(|n| Who::generate(n)));
    let socks: Vec<Who> = PEOPLE
        .iter()
        .map(|n| Who::generate(&format!("sock:{n}")))
        .collect();
    let ci = Who::generate("ci");
    for who in people.iter().chain(std::iter::once(&ci)) {
        write_key(&key_path(&root, &who.label), &who.secret);
    }
    write_key(&key_path(&root, "erin"), RSA_SK);

    let a1 = machine(&root, 0);
    a1.murk().arg("setup-merge-driver").assert().success();
    // The vault starts as murk 0.13 wrote it, as a team that upgraded did:
    // alice trusts the 0.13 file, and her first 0.14 save below gives it the
    // id derived from its creation stamp and name.
    let path = first.dir.join(".murk");
    let mut legacy = murk_cli::read_vault(path.to_str().unwrap()).unwrap();
    let alice_id = murk_cli::crypto::parse_identity(&people[0].secret).unwrap();
    common::forgery::reseal_v1(&mut legacy, &alice_id);
    murk_cli::vault::write(&path, &legacy).unwrap();
    fs::remove_dir_all(a1_home.join(".config/murk/signer-pins")).unwrap();
    a1.murk().args(["trust", "--yes"]).assert().success();
    for who in [&people[1], &people[2], &ci] {
        a1.murk()
            .args(["circle", "authorize", &who.pubkey, "--name", &who.label])
            .assert()
            .success();
    }
    // erin's ssh-rsa key is a recipient too; murk wants the flag for it.
    a1.murk()
        .args([
            "circle",
            "authorize",
            &rsa_pubkey(),
            "--name",
            "erin",
            "--allow-ssh-rsa",
        ])
        .assert()
        .success();
    a1.murk()
        .args(["add", "K1"])
        .write_stdin("init-K1\n")
        .assert()
        .success();
    assert!(a1.commit("p0"));
    a1.git_ok(&["push", "-q", "origin", "main"]);

    for i in 1..MACHINES.len() {
        let mach = Machine::clone(
            &root,
            MACHINES[i].0,
            &key_path(&root, PEOPLE[MACHINES[i].1]),
        );
        mach.murk().arg("setup-merge-driver").assert().success();
        if MACHINES[i].1 != 3 {
            mach.murk().args(["trust", "--yes"]).assert().success();
        }
    }
    let erin = Machine::clone(&root, ERIN, &key_path(&root, "erin"));
    erin.murk().arg("setup-merge-driver").assert().success();
    erin.murk().args(["trust", "--yes"]).assert().success();
    for name in ["attacker", "ci-runner", "ci-keep", "agent"] {
        Machine::clone(&root, name, &key_path(&root, "ci"));
    }

    // bob and carol each write once, and every member machine confirms their
    // signing keys, so the run starts from a settled team.
    for (i, key) in [(2, "K2"), (3, "K3")] {
        let mach = machine(&root, i);
        mach.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        // Confirm the writes pulled in (carol confirms bob's key first).
        mach.murk().args(["trust", "--yes"]).assert().success();
        mach.murk()
            .args(["add", key])
            .write_stdin(format!("init-{key}\n"))
            .assert()
            .success();
        assert!(mach.commit(&format!("p{}", MACHINES[i].1)));
        mach.git_ok(&["push", "-q", "origin", "main"]);
    }
    for i in 0..4 {
        let mach = machine(&root, i);
        mach.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        mach.murk().args(["trust", "--yes"]).assert().success();
        mach.murk().arg("export").assert().success();
    }
    machine(&root, 4).git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
    let erin = erin_machine(&root);
    erin.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
    erin.murk().args(["trust", "--yes"]).assert().success();
    erin.murk().arg("export").assert().success();

    // Every commit so far, by the person named in its message.
    let attacker = bystander(&root, "attacker");
    attacker.git_ok(&["fetch", "-q", "origin"]);
    let mut origins = HashMap::new();
    for rev in attacker.revisions() {
        let msg = attacker.git_ok(&["log", "-1", "--format=%s", &rev]);
        let producer = msg.strip_prefix('p').and_then(|n| n.parse().ok());
        origins.insert(
            blob_id(&attacker.vault_at(&rev)),
            Origin {
                producer,
                step: 0,
                forged: false,
                custom: false,
            },
        );
    }

    copy_dir(&root, &dir.path().join("snapshot"));
    Fixture {
        dir,
        people,
        socks,
        ci,
        origins,
    }
}

static FIXTURE: std::sync::LazyLock<Fixture> = std::sync::LazyLock::new(build_fixture);

/// Worlds share one directory: each clone records its remote's absolute path
/// and each pin is keyed by its checkout's path, so a world cannot move. Tests
/// that run in parallel threads take turns.
static WORLDS: Mutex<()> = Mutex::new(());

/// What one murk command printed, for a row that asserts a value never
/// reached its output.
#[derive(Clone, Debug, Default)]
struct Printed {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Printed {
    fn of(out: &std::process::Output) -> Self {
        Self {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }
}

/// The kind of a step, for the counts of what ran and what did not apply.
fn kind(op: &Op) -> &'static str {
    match op {
        Op::Save { .. } => "save",
        Op::Authorize { .. } => "authorize",
        Op::Revoke { .. } => "revoke",
        Op::Vouch { .. } => "vouch",
        Op::Sync { .. } => "sync",
        Op::Trust { .. } => "trust",
        Op::Load { .. } => "load",
        Op::Diff { .. } => "diff",
        Op::Grant { .. } => "grant",
        Op::AgentLoad { .. } => "agent-load",
        Op::CiLoad { .. } => "ci-load",
        Op::Forge { .. } => "forge",
        Op::Replay { .. } => "replay",
        Op::MergeBranch { .. } => "merge-branch",
        Op::Push { .. } => "push",
        Op::Group { .. } => "group",
        Op::Policy { .. } => "policy",
        Op::Join { .. } => "join",
        Op::CiKeepLoad { .. } => "ci-keep-load",
        Op::Rm { .. } => "rm",
        Op::AncestorBranch { .. } => "ancestor-branch",
        Op::CherryPick { .. } => "cherry-pick",
        Op::CopyVault { .. } => "copy-vault",
        Op::TrustCopy { .. } => "trust-copy",
        Op::ErinSave { .. } => "erin-save",
        Op::ErinSync => "erin-sync",
        Op::ErinLoad { .. } => "erin-load",
        Op::ForgeUnsigned { .. } => "forge-unsigned",
        Op::ListGrantKey { .. } => "list-grant-key",
        Op::AgentProbe { .. } => "agent-probe",
        Op::ReAdd { .. } => "re-add",
        Op::AuthorizeAgain { .. } => "authorize-again",
        Op::PrFlow { .. } => "pr-flow",
        Op::BranchCurrent { .. } => "branch-current",
    }
}

/// The steps that ran and the steps that did not apply, per kind. A step that
/// does not apply is skipped without a word, so a harness whose forgeries
/// always skip would pass without attacking anything: the counts are printed
/// once per run, and a run that skips every forgery fails.
#[derive(Clone, Debug, Default)]
struct Stats {
    ran: BTreeMap<&'static str, usize>,
    skipped: BTreeMap<&'static str, usize>,
    /// Forgeries whose child process skipped them (it cannot open the base, or
    /// no recipient carries the planted key). Each also counts as a skipped
    /// `forge` or `vouch` step.
    forge_child_skips: usize,
    /// Forgeries and vouches murk itself refused to save.
    forge_refusals: usize,
    /// What each oracle judged in a case where it could have failed: its
    /// inputs gave it something to compare with (an accepted removal, an
    /// earlier accepted value, the readers a vault should have).
    judged: BTreeMap<&'static str, usize>,
    /// Violations of rows that are still open, which an oracle counted
    /// instead of failing on.
    open_hits: usize,
    /// The first few of them, for the report.
    open_examples: Vec<String>,
}

impl Stats {
    fn count(&mut self, kind: &'static str, ran: bool) {
        let map = if ran {
            &mut self.ran
        } else {
            &mut self.skipped
        };
        *map.entry(kind).or_default() += 1;
    }

    fn add(&mut self, other: &Stats) {
        for (k, n) in &other.ran {
            *self.ran.entry(k).or_default() += n;
        }
        for (k, n) in &other.skipped {
            *self.skipped.entry(k).or_default() += n;
        }
        for (k, n) in &other.judged {
            *self.judged.entry(k).or_default() += n;
        }
        self.forge_child_skips += other.forge_child_skips;
        self.forge_refusals += other.forge_refusals;
        self.open_hits += other.open_hits;
        for example in &other.open_examples {
            if self.open_examples.len() < 6 {
                self.open_examples.push(example.clone());
            }
        }
    }

    fn ran_of(&self, kind: &str) -> usize {
        self.ran.get(kind).copied().unwrap_or(0)
    }

    fn skipped_of(&self, kind: &str) -> usize {
        self.skipped.get(kind).copied().unwrap_or(0)
    }

    fn judged_of(&self, oracle: &str) -> usize {
        self.judged.get(oracle).copied().unwrap_or(0)
    }

    /// `kind ran/skipped` for every kind that was drawn, then what each
    /// oracle judged and the known open violations it counted.
    fn report(&self) -> String {
        let kinds: BTreeSet<&str> = self
            .ran
            .keys()
            .chain(self.skipped.keys())
            .copied()
            .collect();
        let steps: Vec<String> = kinds
            .into_iter()
            .map(|k| format!("{k} {}/{}", self.ran_of(k), self.skipped_of(k)))
            .collect();
        let oracles: Vec<String> = self
            .judged
            .iter()
            .map(|(oracle, n)| format!("{oracle} {n}"))
            .collect();
        let mut out = format!(
            "{} (ran/skipped); forgeries skipped by the child: {}, refused by murk: {}; \
             oracles judged where they could fail: {}; known open violations counted, not failed \
             on: {}",
            steps.join(", "),
            self.forge_child_skips,
            self.forge_refusals,
            oracles.join(", "),
            self.open_hits
        );
        for example in &self.open_examples {
            out.push_str(&format!("\n  known open: {example}"));
        }
        out
    }
}

/// The steps of every random run in this process.
static TOTALS: Mutex<Option<Stats>> = Mutex::new(None);

/// An observer whose acceptances the invariants constrain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Obs {
    Machine(usize),
    /// erin's machine.
    Erin,
    /// A CI runner with a fresh `HOME` for every load.
    Ci,
    /// A CI runner that keeps its `HOME`, and so its pin, between loads.
    CiKept,
    Agent,
}

/// How an observer's trust pin took a vault it accepted, as `accepted_pin`
/// sees it: a load, `murk trust`, the machine's own save over the file it
/// replaced, or a file another program wrote that murk has not read yet.
#[derive(Clone, Copy)]
enum Took<'a> {
    Load,
    Trust,
    OwnSave(&'a [u8]),
    Custom,
}

/// What the oracle knows of a pinned observer's trust pin, so that it
/// expects a removal record only where murk makes one: when the pin drops a
/// person it trusted, on a current load (newer than the pin's counter, on a
/// branch it has a mark for, never on a detached HEAD), on `murk trust`, or
/// on the machine's own save that takes them out; and on a load that is its
/// branch's next state (above that branch's mark) but not current, for the
/// people it trusts that the vault at the branch's mark listed and this one
/// does not.
#[derive(Clone, Debug)]
struct PinModel {
    generation: u64,
    /// Branch → its mark, and the people the vault accepted at it listed.
    marks: BTreeMap<String, (u64, BTreeSet<usize>)>,
    trusted: BTreeSet<usize>,
    /// The vault id it accepted (empty before any).
    vault_id: String,
}

impl PinModel {
    /// Move `branch`'s mark for an accepted vault at `found` listing
    /// `listed`, as `advance_marks` does: history never gives a branch its
    /// first mark, and the members change only where the mark moves up.
    fn advance(
        &mut self,
        branch: Option<String>,
        found: u64,
        listed: &BTreeSet<usize>,
        current: bool,
    ) {
        let Some(branch) = branch else {
            return;
        };
        match self.marks.get_mut(&branch) {
            Some((mark, members)) => {
                if found > *mark {
                    *mark = found;
                    members.clone_from(listed);
                }
            }
            None if current => {
                self.marks.insert(branch, (found, listed.clone()));
            }
            None => {}
        }
    }
}

struct Agent {
    key_file: PathBuf,
    minted_on: usize,
}

/// One case's world.
struct World<'f> {
    fx: &'f Fixture,
    root: PathBuf,
    origins: HashMap<u64, Origin>,
    /// Accepted `circle revoke` / `authorize` (and vouch) steps, per person.
    revokes: Vec<(usize, usize)>,
    authorizes: Vec<(usize, usize)>,
    /// Per observer: person → the revoke step whose removal it accepted, and
    /// the commit holding the vault it accepted it in.
    removed: BTreeMap<Obs, BTreeMap<usize, (usize, String)>>,
    /// Per pinned observer (a machine, erin): what its trust pin holds (see
    /// [`PinModel`]). dave's machine has no pin until it first accepts.
    pins: BTreeMap<Obs, PinModel>,
    /// People whose entries the CI secret lists.
    ci_signers: BTreeSet<usize>,
    agent: Option<Agent>,
    /// Plaintext → (step written, people the writing vault did not list).
    written: HashMap<String, (usize, BTreeSet<usize>)>,
    branches: Vec<String>,
    /// Grants the last revoke had to take with it.
    last_cascade: usize,
    /// What the last load step printed.
    last_load: Option<Printed>,
    /// Merges whose driver said so on stderr (its merged line or its
    /// conflict list), rather than git merging the file as text.
    driver_said: usize,
    /// Forgeries the child process skipped, and ones murk refused to save.
    forge_skips: Cell<usize>,
    forge_refusals: Cell<usize>,
    /// The value-lineage oracle's record: per machine (erin is `ERIN_M`) and
    /// branch, each key's latest accepted write, as the step that wrote it
    /// and whether it was a deletion.
    lineage: BTreeMap<(usize, String), BTreeMap<String, (usize, bool)>>,
    /// The files a machine accepted with `murk trust`: its own decision, so
    /// older values in them are not a rollback.
    trusted_files: BTreeSet<(usize, u64)>,
    /// Who each vault file a harness step wrote should list: people, and the
    /// CI key as `CI_READER`. Worked out from the steps (authorize, revoke,
    /// merge) and never from the vault's own recipient list.
    expected: HashMap<u64, BTreeSet<usize>>,
    /// Vault files an attacker's own code made with a recipient the team never
    /// authorized (the extra one of an unsigned forgery). That the attacker's
    /// recipient reads them is the attack's point, not a violation by a
    /// member, so the no-reads check skips them; what a member then writes
    /// on top is judged by the readers oracle.
    attacker_listed: BTreeSet<u64>,
    /// Violations of open rows the oracles counted instead of failing on.
    open_hits: Vec<String>,
    /// What each oracle judged where it could fail.
    judged: RefCell<BTreeMap<&'static str, usize>>,
    stats: Stats,
    _lock: MutexGuard<'static, ()>,
}

impl<'f> World<'f> {
    fn new(fx: &'f Fixture) -> Self {
        let lock = WORLDS.lock().unwrap_or_else(PoisonError::into_inner);
        let root = fx.dir.path().join("live");
        let _ = fs::remove_dir_all(&root);
        copy_dir(&fx.dir.path().join("snapshot"), &root);
        let fixture_values =
            ["init-K1", "init-K2", "init-K3"].map(|v| (v.to_string(), (0, BTreeSet::from([3]))));
        // Every revision the fixture was built from lists alice, bob, carol
        // and the CI key: its authorize steps are all in the first commit.
        let listed = BTreeSet::from([0, 1, 2, CI_READER]);
        let mut world = Self {
            fx,
            root,
            origins: fx.origins.clone(),
            revokes: Vec::new(),
            authorizes: Vec::new(),
            removed: BTreeMap::new(),
            ci_signers: BTreeSet::from([0, 1, 2]),
            agent: None,
            written: fixture_values.into_iter().collect(),
            branches: Vec::new(),
            last_cascade: 0,
            last_load: None,
            driver_said: 0,
            forge_skips: Cell::new(0),
            forge_refusals: Cell::new(0),
            // Every machine but dave's loaded the fixture's last revision when
            // the fixture was built: that is what it has accepted on `main`.
            lineage: (0..=ERIN_M)
                .filter(|&machine| machine != 4)
                .map(|machine| {
                    let fixture = KEYS.map(|key| (key.to_string(), (0, false)));
                    ((machine, "main".to_string()), fixture.into_iter().collect())
                })
                .collect(),
            trusted_files: BTreeSet::new(),
            expected: fx
                .origins
                .keys()
                .map(|&blob| (blob, listed.clone()))
                .collect(),
            open_hits: Vec::new(),
            attacker_listed: BTreeSet::new(),
            judged: RefCell::new(BTreeMap::new()),
            stats: Stats::default(),
            _lock: lock,
            pins: BTreeMap::new(),
        };
        // Every machine but dave's, and erin's, trusted the fixture's last
        // revision on `main` when the fixture was built.
        for obs in (0..MACHINES.len())
            .filter(|&m| m != 4)
            .map(Obs::Machine)
            .chain([Obs::Erin])
        {
            let bytes = world.clone_of(&obs).vault();
            let model = PinModel {
                generation: generation_of(&bytes),
                marks: BTreeMap::from([(
                    "main".to_string(),
                    (generation_of(&bytes), world.listed(&bytes)),
                )]),
                trusted: world.listed(&bytes),
                vault_id: vault_id_of(&bytes),
            };
            world.pins.insert(obs, model);
        }
        world
    }

    /// Count one case the oracle `name` judged where it could have failed.
    fn judge(&self, name: &'static str) {
        *self.judged.borrow_mut().entry(name).or_default() += 1;
    }

    /// A violation the oracle found. It fails the step when `enforced`; where
    /// the row that covers it is still open, it is counted and reported as a
    /// known open violation instead, so the random run does not turn red for
    /// a bug that is documented.
    fn open_or_fail(&mut self, enforced: bool, what: String) -> Result<(), String> {
        if enforced {
            return Err(what);
        }
        self.open_hits.push(what);
        Ok(())
    }

    /// Who the result of a merge should list, from what the harness knows of
    /// each side and the ancestor: what either side added, and what either
    /// side removed from the ancestor stays out. `None` when a file's history
    /// was not followed (a forged side).
    fn merged_listing(
        &self,
        ours: &[u8],
        theirs: &[u8],
        ancestor: &[u8],
    ) -> Option<BTreeSet<usize>> {
        let ours = self.expected.get(&blob_id(ours))?;
        let theirs = self.expected.get(&blob_id(theirs))?;
        let ancestor = self.expected.get(&blob_id(ancestor))?;
        Some(
            ours.union(theirs)
                .filter(|p| !(ancestor.contains(p) && (!ours.contains(p) || !theirs.contains(p))))
                .copied()
                .collect(),
        )
    }

    fn machine(&self, i: usize) -> Machine {
        machine(&self.root, i)
    }

    fn record(&mut self, bytes: &[u8], producer: Option<usize>, step: usize, forged: bool) {
        self.record_origin(bytes, producer, step, forged, forged);
    }

    fn record_origin(
        &mut self,
        bytes: &[u8],
        producer: Option<usize>,
        step: usize,
        forged: bool,
        custom: bool,
    ) {
        if bytes.is_empty() {
            return;
        }
        self.origins.entry(blob_id(bytes)).or_insert(Origin {
            producer,
            step,
            forged,
            custom,
        });
    }

    /// The people a vault file lists as recipients.
    fn listed(&self, bytes: &[u8]) -> BTreeSet<usize> {
        let vault: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
        let recipients: BTreeSet<&str> = vault["recipients"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        (0..PEOPLE.len())
            .filter(|&i| recipients.contains(self.fx.people[i].pubkey.as_str()))
            .collect()
    }

    fn authorized_between(&self, who: usize, after: usize, upto: usize) -> bool {
        self.authorizes
            .iter()
            .any(|&(p, a)| p == who && after < a && a <= upto)
    }

    /// The removals `obs` has accepted (the agent follows the machine that
    /// minted it, and its own loads). A runner that keeps its pin but loads
    /// only with `MURK_TRUSTED_SIGNERS` records none (see `note_accept`).
    fn removals(&self, obs: &Obs) -> BTreeMap<usize, (usize, String)> {
        let mut all = self.removed.get(obs).cloned().unwrap_or_default();
        if let (Obs::Agent, Some(agent)) = (obs, &self.agent) {
            for (who, v) in self
                .removed
                .get(&Obs::Machine(agent.minted_on))
                .cloned()
                .unwrap_or_default()
            {
                all.entry(who).or_insert(v);
            }
        }
        all
    }

    /// The clone `obs` loads in.
    fn clone_of(&self, obs: &Obs) -> Machine {
        match obs {
            Obs::Machine(i) => self.machine(*i),
            Obs::Erin => erin_machine(&self.root),
            Obs::Ci => bystander(&self.root, "ci-runner"),
            Obs::CiKept => bystander(&self.root, "ci-keep"),
            Obs::Agent => bystander(&self.root, "agent"),
        }
    }

    /// Whether the removal `obs` accepted in commit `removal` has reached
    /// commit `at`: `at`'s history contains it.
    fn reaches(&self, obs: &Obs, removal: &str, at: &str) -> bool {
        self.clone_of(obs)
            .git(&["merge-base", "--is-ancestor", removal, at])
            .status
            .success()
    }

    /// Whether accepting `bytes`, the vault at commit `at`, on `obs` breaks
    /// the revoked-signer invariant.
    ///
    /// A removal binds a branch once its history contains the commit in which
    /// `obs` accepted it. Until an offboarding change reaches a branch, the
    /// person is still a member there, and their vaults on it may load.
    fn check_accept(&self, obs: &Obs, bytes: &[u8], how: &str, at: &str) -> Result<(), String> {
        let Some(origin) = self.origins.get(&blob_id(bytes)) else {
            return Ok(());
        };
        let listed = self.listed(bytes);
        let generation = serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|v| v["generation"].as_u64())
            .unwrap_or(0);
        if generation > GENERATION_CAP {
            return Err(format!(
                "{obs:?} {how} a vault with generation {generation}, above the cap \
                 {GENERATION_CAP}"
            ));
        }
        // CI's secret drops a revoked signer as soon as the revoke is made,
        // so CI must refuse their later vaults whether or not it has loaded
        // the revoke yet.
        let mut judged = false;
        if matches!(obs, Obs::Ci | Obs::CiKept)
            && let Some(p) = origin.producer
            && !self.ci_signers.contains(&p)
            && let Some(&(_, v)) = self.revokes.iter().rev().find(|&&(r, _)| r == p)
        {
            judged = true;
            if origin.step > v {
                return Err(format!(
                    "CI {how} a vault {} produced at step {}, after the CI secret dropped them at \
                     step {v}",
                    PEOPLE[p], origin.step
                ));
            }
        }
        let removals: BTreeMap<usize, usize> = self
            .removals(obs)
            .into_iter()
            .filter(|(_, (_, commit))| self.reaches(obs, commit, at))
            .map(|(who, (v, _))| (who, v))
            .collect();
        // A vault produced after a removal this observer accepted is one the
        // removal rules can fail on.
        judged |= removals.values().any(|&v| origin.step > v);
        if judged {
            self.judge(match obs {
                Obs::Machine(_) | Obs::Erin => "revoked-signer:machine",
                Obs::Ci | Obs::CiKept => "revoked-signer:ci",
                Obs::Agent => "revoked-signer:agent",
            });
        }
        // A member this observer still trusts may list anyone with their own
        // code: they could have run `circle authorize` instead. A machine
        // with a pin keeps its own record of a removal, though: it refuses a
        // vault that lists the person until it re-adds them itself.
        let insider = origin.custom && origin.producer.is_some_and(|p| !removals.contains_key(&p));
        let pinned = matches!(obs, Obs::Machine(_) | Obs::Erin);
        for (who, v) in removals {
            if origin.step <= v {
                continue;
            }
            // A runner has no pin to remember a removal in: its secret decides
            // whom it trusts. Once the operator lists the person again (a
            // `circle authorize` of them adds them back) it accepts what they
            // signed; while the secret leaves them out, the check above applies.
            if matches!(obs, Obs::Ci | Obs::CiKept) && self.ci_signers.contains(&who) {
                continue;
            }
            if origin.producer == Some(who) {
                return Err(format!(
                    "{obs:?} {how} a vault {} produced at step {} (forged: {}), after accepting \
                     their removal at step {v}",
                    PEOPLE[who], origin.step, origin.forged
                ));
            }
            if listed.contains(&who)
                && (pinned || (!insider && !self.authorized_between(who, v, origin.step)))
            {
                return Err(format!(
                    "{obs:?} {how} a vault produced at step {} that lists {} again, revoked at \
                     step {v}, while its record of the removal stands",
                    origin.step, PEOPLE[who]
                ));
            }
        }
        Ok(())
    }

    /// Record that `obs` accepted `bytes`, the vault at commit `at`, taken by
    /// its pin as `took`: removals it now knows. A load never clears a record:
    /// only the machine's own `circle authorize` of the person or its `murk
    /// trust --re-add` does. A pinned observer records a removal only where
    /// its pin drops someone it trusted (see [`PinModel`]): a read of history,
    /// a detached HEAD included, records nothing, and neither does a vault
    /// leaving out someone this machine never trusted. A runner that keeps its
    /// pin but loads only with `MURK_TRUSTED_SIGNERS` records no removal: a
    /// stated limit.
    fn note_accept(&mut self, obs: Obs, bytes: &[u8], at: &str, took: Took<'_>) {
        if obs == Obs::CiKept {
            return;
        }
        let dropped = self.pin_takes(&obs, bytes, took);
        let Some(origin) = self.origins.get(&blob_id(bytes)).copied() else {
            return;
        };
        // The step a removal of `who` counts from: their latest revoke at or
        // before this vault, unless they were authorized again since; else
        // this vault's own step (a member's own code that drops them, or a
        // `murk trust` of a revision without them).
        let revoked_at = |who: usize| {
            self.revokes
                .iter()
                .filter(|&&(p, v)| p == who && v <= origin.step)
                .map(|&(_, v)| v)
                .max()
                .filter(|&v| !self.authorized_between(who, v, origin.step))
        };
        // A pinned observer records exactly whom its pin drops, as murk does;
        // an observer with no model, whom a harness revoke took out.
        let records: Vec<(usize, usize)> = match &dropped {
            Some(dropped) => dropped
                .iter()
                .map(|&who| (who, revoked_at(who).unwrap_or(origin.step)))
                .collect(),
            None => {
                let listed = self.listed(bytes);
                (0..PEOPLE.len())
                    .filter(|who| !listed.contains(who))
                    .filter_map(|who| revoked_at(who).map(|v| (who, v)))
                    .collect()
            }
        };
        for (who, v) in records {
            let removed = self.removed.entry(obs.clone()).or_default();
            let known = removed.entry(who).or_insert_with(|| (v, at.to_string()));
            if v > known.0 {
                *known = (v, at.to_string());
            }
        }
        if let Some(pin) = self.pins.get_mut(&obs)
            && let Some(removed) = self.removed.get(&obs)
        {
            pin.trusted.retain(|p| !removed.contains_key(p));
        }
    }

    /// Apply an acceptance to `obs`'s [`PinModel`] as `accepted_pin` does,
    /// and return the people its trusted set lost: the removals murk records.
    /// `None` for an observer with no model (a CI runner, the agent), whose
    /// removals follow every vault it accepts.
    fn pin_takes(&mut self, obs: &Obs, bytes: &[u8], took: Took<'_>) -> Option<BTreeSet<usize>> {
        if !matches!(obs, Obs::Machine(_) | Obs::Erin) {
            return None;
        }
        let listed = self.listed(bytes);
        let found = generation_of(bytes);
        let branch = branch_of(&self.clone_of(obs));
        let before = match took {
            Took::OwnSave(before) => Some((self.listed(before), generation_of(before))),
            _ => None,
        };
        let Some(pin) = self.pins.get_mut(obs) else {
            // A first acceptance trusts the vault's recipients and drops nobody.
            if !matches!(took, Took::Custom) {
                self.pins.insert(
                    obs.clone(),
                    PinModel {
                        generation: found,
                        marks: branch
                            .into_iter()
                            .map(|b| (b, (found, listed.clone())))
                            .collect(),
                        trusted: listed,
                        vault_id: vault_id_of(bytes),
                    },
                );
            }
            return Some(BTreeSet::new());
        };
        let mut other_vault = false;
        let (dropped, current) = match took {
            // murk has not read it yet: the pin is unchanged.
            Took::Custom => return Some(BTreeSet::new()),
            Took::Load => {
                let mark = branch.as_ref().and_then(|b| pin.marks.get(b));
                // `is_current`: a pin with no trust decision yet takes any
                // load as current; a murk 0.13 vault (generation 0) is newer
                // only while the pin has seen no 0.14 state. Every observer
                // here loads in a git checkout, so the product's
                // outside-git arm never applies (a detached HEAD has no
                // branch, so no mark).
                let newer = found > pin.generation
                    || (found == 0 && pin.generation == 0 && pin.vault_id.is_empty());
                let current = pin.trusted.is_empty() || (newer && mark.is_some());
                if current {
                    let dropped = pin.trusted.difference(&listed).copied().collect();
                    pin.trusted.clone_from(&listed);
                    (dropped, true)
                } else {
                    // The branch's next state, below another branch's
                    // counter: only who the branch's mark listed counts.
                    let dropped: BTreeSet<usize> = match mark {
                        Some((m, members)) if found > *m => members
                            .iter()
                            .filter(|p| pin.trusted.contains(p) && !listed.contains(p))
                            .copied()
                            .collect(),
                        _ => BTreeSet::new(),
                    };
                    pin.trusted.retain(|p| !dropped.contains(p));
                    (dropped, false)
                }
            }
            Took::Trust => {
                let id = vault_id_of(bytes);
                if id.is_empty() {
                    // A murk 0.13 copy only widens trust
                    // (`older_pre_upgrade_copy`): nobody is dropped.
                    pin.trusted.extend(listed.iter().copied());
                    (BTreeSet::new(), true)
                } else if !pin.vault_id.is_empty() && id != pin.vault_id {
                    // Another vault at this path: murk clears every removal
                    // record and drops nobody.
                    other_vault = true;
                    pin.vault_id = id;
                    pin.trusted.clone_from(&listed);
                    (BTreeSet::new(), true)
                } else {
                    pin.vault_id = id;
                    let dropped = pin.trusted.difference(&listed).copied().collect();
                    pin.trusted.clone_from(&listed);
                    (dropped, true)
                }
            }
            Took::OwnSave(_) => {
                let (was, was_generation) = before.expect("an own save has the file it replaced");
                // The save loaded the file it replaced first.
                pin.generation = pin.generation.max(was_generation);
                let dropped: BTreeSet<usize> = pin
                    .trusted
                    .iter()
                    .filter(|p| was.contains(p) && !listed.contains(p))
                    .copied()
                    .collect();
                pin.trusted.retain(|p| !dropped.contains(p));
                pin.trusted.extend(listed.difference(&was));
                (dropped, true)
            }
        };
        if current {
            pin.generation = pin.generation.max(found);
        }
        pin.advance(branch, found, &listed, current);
        if other_vault {
            self.removed.remove(obs);
        }
        Some(dropped)
    }

    fn accept(
        &mut self,
        obs: Obs,
        bytes: &[u8],
        how: &str,
        at: &str,
        took: Took<'_>,
    ) -> Result<(), String> {
        self.check_accept(&obs, bytes, how, at)?;
        self.lineage_accept(&obs, bytes, how)?;
        self.note_accept(obs, bytes, at, took);
        Ok(())
    }

    /// The value-lineage oracle for a machine that accepted `bytes`.
    fn lineage_accept(&mut self, obs: &Obs, bytes: &[u8], how: &str) -> Result<(), String> {
        let Obs::Machine(i) = obs else {
            return Ok(());
        };
        let Some(branch) = branch_of(&self.machine(*i)) else {
            return Ok(());
        };
        let values = self.read_values(bytes, MACHINES[*i].1);
        let produced = self.origins.get(&blob_id(bytes)).map(|o| o.step);
        self.lineage_values(*i, &branch, blob_id(bytes), &values, produced, how)
    }

    /// What person `who` reads for each shared key of a vault file, straight
    /// through age.
    fn read_values(&self, bytes: &[u8], who: usize) -> BTreeMap<String, String> {
        let path = self.root.join("values.murk");
        fs::write(&path, bytes).unwrap();
        let person = &self.people()[who];
        cast::cells(&path, std::slice::from_ref(person))
            .into_iter()
            .filter(|((_, tier), _)| *tier == cast::Tier::Shared)
            .filter_map(|((key, _), by)| by.get(&person.label).map(|v| (key, v.clone())))
            .collect()
    }

    /// What the value-lineage oracle finds in `values`, the shared values of
    /// the vault file `blob` (made at step `produced`), if `machine` accepted
    /// it on `branch` now: the first value older than the latest accepted
    /// write, and whether the oracle had anything to compare. Changes
    /// nothing.
    fn lineage_flag(
        &self,
        machine: usize,
        branch: &str,
        blob: u64,
        values: &BTreeMap<String, String>,
        produced: Option<usize>,
    ) -> (Option<String>, bool) {
        let Some(record) = self.lineage.get(&(machine, branch.to_string())) else {
            return (None, false);
        };
        if self.trusted_files.contains(&(machine, blob)) {
            return (None, false);
        }
        let mut hit = None;
        let mut judged = false;
        for (k, v) in values {
            if let Some(w) = written_step(v)
                && let Some(&(latest, gone)) = record.get(k)
            {
                judged = true;
                if w < latest && hit.is_none() {
                    hit = Some(format!(
                        "{k} is the value written at step {w}, but the {} at step {latest} was \
                         accepted on {branch} before",
                        if gone { "deletion" } else { "write" }
                    ));
                }
            }
        }
        for (k, &(latest, gone)) in record {
            if !gone
                && !values.contains_key(k)
                && let Some(made) = produced
            {
                judged = true;
                if made < latest && hit.is_none() {
                    hit = Some(format!(
                        "the vault lacks {k}, which was written at step {latest} and accepted on \
                         {branch}, though it was made at step {made}"
                    ));
                }
            }
        }
        (hit, judged)
    }

    /// What the value-lineage oracle would say if `machine` accepted `bytes`
    /// on `main` now.
    fn would_flag(&self, machine: usize, bytes: &[u8]) -> Option<String> {
        let values = self.read_values(bytes, MACHINES[machine].1);
        let produced = self.origins.get(&blob_id(bytes)).map(|o| o.step);
        self.lineage_flag(machine, "main", blob_id(bytes), &values, produced)
            .0
    }

    /// The value-lineage oracle: a machine never accepts, on a branch, a
    /// value older than the latest one it accepted there for the same key
    /// (or one that a later deletion removed), unless it ran `murk trust` on
    /// exactly that file. Values name the step that wrote them (`s<step>-K`,
    /// `forged-s<step>`, `init-K` for step 0), so "older" needs no clock.
    /// `machine` is an index into the machines, or `ERIN_M`; `produced` is the
    /// step that made the file.
    ///
    /// It fails a step only once the row for its S1 case is enforced (a
    /// genuine stale fork, with a counter above the mark, loads over main
    /// today); until then each hit is a known open violation.
    fn lineage_values(
        &mut self,
        machine: usize,
        branch: &str,
        blob: u64,
        values: &BTreeMap<String, String>,
        produced: Option<usize>,
        how: &str,
    ) -> Result<(), String> {
        let state: BTreeMap<String, (usize, bool)> = values
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), (written_step(v)?, false))))
            .collect();
        let trusted = how == "trusted";
        if trusted {
            self.trusted_files.insert((machine, blob));
        }
        let exact = self.trusted_files.contains(&(machine, blob));
        let key = (machine, branch.to_string());
        let (hit, judged) = if trusted {
            (None, false)
        } else {
            self.lineage_flag(machine, branch, blob, values, produced)
        };
        if judged && how != "wrote" {
            self.judge("value-lineage");
        }
        let record = self.lineage.entry(key).or_default();
        if hit.is_some() || trusted || exact {
            // The file is what the machine holds now: later loads compare
            // with it, so one rollback is one hit.
            *record = state;
        } else {
            for (k, v) in state {
                let latest = record.get(&k).map_or(0, |r| r.0);
                if v.0 >= latest || !record.contains_key(&k) {
                    record.insert(k, v);
                }
            }
            if let Some(made) = produced {
                let gone: Vec<String> = record
                    .iter()
                    .filter(|(k, (latest, gone))| {
                        !gone && !values.contains_key(*k) && made >= *latest
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in gone {
                    record.insert(k, (made, true));
                }
            }
        }
        match hit {
            Some(what) => self.open_or_fail(
                lineage_enforced(),
                format!("machine {machine} {how}: {what}"),
            ),
            None => Ok(()),
        }
    }

    /// Every value-reading identity, labelled by person index.
    fn people(&self) -> Vec<Who> {
        self.fx
            .people
            .iter()
            .enumerate()
            .map(|(i, w)| Who {
                label: i.to_string(),
                ..w.clone()
            })
            .collect()
    }

    /// No person reads a value first written in a vault that did not list
    /// them, unless they were authorized again since.
    fn check_reads(&self, what: &str, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || self.attacker_listed.contains(&blob_id(bytes)) {
            return Ok(());
        }
        let path = self.root.join("check.murk");
        fs::write(&path, bytes).unwrap();
        let mut judged = false;
        for ((key, tier), by) in cast::cells(&path, &self.people()) {
            for (label, plaintext) in by {
                let who: usize = label.parse().unwrap();
                let Some((w, excluded)) = self.written.get(&plaintext) else {
                    continue;
                };
                // A value written where someone was not a recipient is one
                // they must not read.
                judged |= !excluded.is_empty();
                if excluded.contains(&who) && !self.authorized_between(who, *w, usize::MAX) {
                    return Err(format!(
                        "{} can read {plaintext:?} ({key}, {tier:?}) in {what}, written at step \
                         {w} in a vault that did not list them",
                        PEOPLE[who]
                    ));
                }
            }
        }
        if judged {
            self.judge("no-reads");
        }
        Ok(())
    }

    /// A value a member saved is readable by exactly the vault's recipients.
    fn check_saved(&self, bytes: &[u8], key: &str, value: &str) -> Result<(), String> {
        let path = self.root.join("check.murk");
        fs::write(&path, bytes).unwrap();
        let mut ids = self.people();
        ids.push(Who {
            label: "ci".into(),
            ..self.fx.ci.clone()
        });
        let cells = cast::cells(&path, &ids);
        let readers: BTreeMap<String, String> = cells
            .get(&(key.to_string(), cast::Tier::Shared))
            .cloned()
            .unwrap_or_default();
        // The readers the harness's own authorize, revoke and merge steps
        // say the vault lists, not the vault's recipient list. A file whose
        // history the harness did not follow (the merge of a forged side) is
        // not judged.
        let Some(members) = self.expected.get(&blob_id(bytes)) else {
            return Ok(());
        };
        self.judge("readers");
        let expected: BTreeSet<String> = members
            .iter()
            .map(|&p| {
                if p == CI_READER {
                    "ci".to_string()
                } else {
                    p.to_string()
                }
            })
            .collect();
        let got: BTreeSet<String> = readers.keys().cloned().collect();
        if got != expected || readers.values().any(|v| v != value) {
            return Err(format!(
                "{key} saved as {value:?}: readers {readers:?}, expected exactly {expected:?}"
            ));
        }
        Ok(())
    }

    fn origin_tip(&self, branch: &str) -> Vec<u8> {
        let attacker = bystander(&self.root, "attacker");
        attacker.git_ok(&["fetch", "-q", "origin"]);
        attacker.vault_at(&format!("origin/{branch}"))
    }

    fn pushed(&self, i: usize) -> Option<String> {
        (!self.branches.is_empty()).then(|| self.branches[i % self.branches.len()].clone())
    }

    /// Whether a forgery may start from `base`. A forgery's child process
    /// saves straight through the library, without the load a member's murk
    /// runs first. On a file an attacker's own code listed a recipient in (an
    /// unsigned forgery, which no signing key loads), a member's signature
    /// would be that member authorizing the recipient, which the authorize
    /// step covers. So no forgery starts there.
    fn forgeable(&self, base: &[u8]) -> bool {
        !self.attacker_listed.contains(&blob_id(base))
    }

    /// Run the library forgery in a child process with its own environment:
    /// `None` when it does not apply, `Some(Err(why))` when murk refused the
    /// save.
    fn forge(&self, base: &[u8], vars: &[(&str, String)]) -> Option<Result<Vec<u8>, String>> {
        let input = self.root.join("forge-in.murk");
        let output = self.root.join("forge-out.murk");
        let home = self.root.join("forge-home");
        fs::write(&input, base).unwrap();
        let _ = fs::remove_file(&output);
        fs::create_dir_all(&home).unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "forge_child", "--ignored", "--nocapture"])
            .env("FORGE_IN", &input)
            .env("FORGE_OUT", &output)
            .env("HOME", &home);
        for var in common::MURK_CONTEXT_VARS {
            cmd.env_remove(var);
        }
        for (k, v) in vars {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some((_, why)) = text.split_once("FORGE-REFUSED ") {
            self.forge_refusals.set(self.forge_refusals.get() + 1);
            return Some(Err(why.lines().next().unwrap_or_default().to_string()));
        }
        if text.contains("FORGE-SKIP") || !text.contains("FORGE-OK") {
            self.forge_skips.set(self.forge_skips.get() + 1);
            return None;
        }
        Some(Ok(fs::read(&output).unwrap()))
    }

    /// Commit `bytes` as the vault on top of `origin/main` and push it.
    fn push_as_attacker(&mut self, bytes: &[u8], to: Dest, step: usize) {
        let attacker = bystander(&self.root, "attacker");
        attacker.git_ok(&["fetch", "-q", "origin"]);
        attacker.git_ok(&["checkout", "-q", "-f", "-B", "work", "origin/main"]);
        fs::write(attacker.dir.join(".murk"), bytes).unwrap();
        attacker.commit(&format!("s{step} attacker"));
        match to {
            Dest::Main => {
                attacker.git_ok(&["push", "-q", "origin", "HEAD:main"]);
            }
            Dest::Branch => {
                let name = format!("attack-{step}");
                attacker.git_ok(&["push", "-q", "origin", &format!("HEAD:refs/heads/{name}")]);
                self.branches.push(name);
            }
        }
    }

    /// Check out `rev` (or a branch at it) in a bystander clone for CI/agent.
    fn checkout_ref(&self, clone: &Machine, at: Ref) -> Option<()> {
        clone.git_ok(&["fetch", "-q", "origin"]);
        let target = match at {
            Ref::Main => "origin/main".to_string(),
            Ref::Pushed(i) => format!("origin/{}", self.pushed(i)?),
        };
        clone.git_ok(&["checkout", "-q", "-f", "--detach", &target]);
        Some(())
    }

    /// Check out what `at` names in `mach`, as a load there would: `None` when
    /// there is no such pushed branch yet.
    fn checkout_at(&self, mach: &Machine, at: &At, step: usize) -> Option<()> {
        mach.git_ok(&["fetch", "-q", "origin"]);
        let revs = mach.revisions();
        let checkout: Vec<String> = match at {
            At::Main => vec!["main".into()],
            At::Detached(i) => vec!["--detach".into(), revs[i % revs.len()].clone()],
            At::NewBranch(i) => {
                vec![
                    "-B".into(),
                    format!("b{step}"),
                    revs[i % revs.len()].clone(),
                ]
            }
            At::Pushed(i) => {
                vec!["--detach".into(), format!("origin/{}", self.pushed(*i)?)]
            }
            At::PushedBranch(i) => {
                let name = self.pushed(*i)?;
                vec!["-B".into(), name.clone(), format!("origin/{name}")]
            }
            At::OriginMain => vec!["--detach".into(), "origin/main".into()],
        };
        let mut args = vec!["checkout", "-q", "-f"];
        args.extend(checkout.iter().map(String::as_str));
        mach.git_ok(&args);
        Some(())
    }

    /// Commit `parent` and then `tip` as the vault, one commit each, on a
    /// branch off `origin/main`, and push it: a pull request whose first
    /// commit is a forged ancestor of a genuine revision.
    fn push_two_commits(&mut self, parent: &[u8], tip: &[u8], step: usize) -> String {
        let attacker = bystander(&self.root, "attacker");
        attacker.git_ok(&["fetch", "-q", "origin"]);
        attacker.git_ok(&["checkout", "-q", "-f", "-B", "work", "origin/main"]);
        fs::write(attacker.dir.join(".murk"), parent).unwrap();
        attacker.commit(&format!("s{step} attacker: ancestor"));
        fs::write(attacker.dir.join(".murk"), tip).unwrap();
        attacker.commit(&format!("s{step} attacker: revision"));
        let name = format!("anc-{step}");
        attacker.git_ok(&["push", "-q", "origin", &format!("HEAD:refs/heads/{name}")]);
        self.branches.push(name.clone());
        name
    }

    /// `git cherry-pick` of `theirs_ref`'s tip onto `main`. The merge driver
    /// runs, with the tip's parent as the ancestor; a clean result is
    /// accepted like a merge's.
    fn cherry_pick(&mut self, step: usize, m: usize, theirs_ref: &str) -> Result<Ran, String> {
        let mach = self.machine(m);
        mach.git_ok(&["checkout", "-q", "-f", "main"]);
        mach.git_ok(&["fetch", "-q", "origin"]);
        let ours = mach.vault();
        let ours_head = head(&mach);
        let theirs = mach.vault_at(theirs_ref);
        let ancestor = mach.vault_at(&format!("{theirs_ref}~1"));
        let picked = mach.git(&["cherry-pick", theirs_ref]);
        if driver_said(&picked.stderr) {
            self.driver_said += 1;
        }
        if !picked.status.success() {
            let _ = mach.git(&["cherry-pick", "--abort"]);
            mach.git_ok(&["reset", "-q", "--hard", &ours_head]);
            return refused(&ours, &mach.vault(), "refused cherry-pick", &picked);
        }
        let result = mach.vault();
        // git takes theirs' file without the driver when ours has not changed
        // since the ancestor: nothing is accepted until it is loaded.
        let driver_ran = ours != ancestor && theirs != ancestor && ours != theirs;
        if driver_ran {
            self.check_accept(
                &Obs::Machine(m),
                &theirs,
                "cherry-picked (driver)",
                &ours_head,
            )?;
            self.record(&result, Some(MACHINES[m].1), step, false);
            if let Some(listed) = self.merged_listing(&ours, &theirs, &ancestor) {
                self.expected.insert(blob_id(&result), listed);
            }
            // The driver writes no pin: murk takes the result at the next
            // load, under the load rules.
            self.accept(
                Obs::Machine(m),
                &result,
                "wrote (merge result)",
                &head(&mach),
                Took::Custom,
            )?;
        }
        Ok(Ran::Accepted)
    }

    /// erin accepted `bytes` (what she read is `values`): a vault an attacker
    /// forged unsigned is never accepted, and the usual oracles apply.
    fn accept_erin(
        &mut self,
        bytes: &[u8],
        values: BTreeMap<String, String>,
        how: &str,
        at: &str,
        took: Took<'_>,
    ) -> Result<(), String> {
        let origin = self.origins.get(&blob_id(bytes)).copied();
        if let Some(origin) = origin
            && origin.forged
            && !has_sig(bytes)
        {
            return Err(format!(
                "erin {how} an unsigned vault forged at step {}, which lists someone she never \
                 accepted",
                origin.step
            ));
        }
        self.check_accept(&Obs::Erin, bytes, how, at)?;
        if let Some(branch) = branch_of(&self.erin()) {
            let produced = origin.map(|o| o.step);
            self.lineage_values(ERIN_M, &branch, blob_id(bytes), &values, produced, how)?;
        }
        self.note_accept(Obs::Erin, bytes, at, took);
        Ok(())
    }

    /// An environment-anchored load only narrows the pin: it may move the
    /// counters and marks, the signed bit, the grants seen and an empty vault
    /// id, and nothing else, whether the load was accepted or refused. The
    /// fields that open rows still leave alone are counted instead.
    fn pin_env_check(
        &mut self,
        before: Option<&serde_json::Value>,
        after: Option<&serde_json::Value>,
    ) -> Result<(), String> {
        use serde_json::Value;
        let Some(after) = after.and_then(Value::as_object) else {
            return Ok(());
        };
        let nothing = serde_json::Map::new();
        let before = before.and_then(Value::as_object).unwrap_or(&nothing);
        self.judge("pin-bytes");
        const MOVES: [&str; 8] = [
            "v",
            "generation",
            "branches",
            "head",
            "branch_heads",
            "grants",
            "was_signed",
            "vault_id",
        ];
        // The pin omits empty fields, so absent and empty are the same.
        let empty = |v: Option<&Value>| match v {
            None | Some(Value::Null) | Some(Value::Bool(false)) => true,
            Some(Value::Array(a)) => a.is_empty(),
            Some(Value::Object(o)) => o.is_empty(),
            Some(Value::String(s)) => s.is_empty(),
            Some(Value::Number(n)) => n.as_u64() == Some(0),
            _ => false,
        };
        let fields: BTreeSet<&str> = before
            .keys()
            .chain(after.keys())
            .map(String::as_str)
            .collect();
        for field in fields {
            let (b, a) = (before.get(field), after.get(field));
            let same = b == a || (empty(b) && empty(a));
            let may_move = if field == "vault_id" {
                empty(b)
            } else {
                MOVES.contains(&field)
            };
            if same || may_move {
                continue;
            }
            let row = if field == "accepted_pre_upgrade" {
                "R-I4-a:pre-upgrade"
            } else {
                "R-I4-a"
            };
            self.open_or_fail(
                row_enforced(row),
                format!(
                    "an environment-anchored load changed the pin's `{field}`: {b:?} became {a:?}"
                ),
            )?;
        }
        Ok(())
    }

    /// A step's result: `None` when it does not apply and did not run.
    fn step(&mut self, step: usize, op: &Op) -> Option<Result<Ran, String>> {
        let value = |key: &str| format!("s{step}-{key}");
        match op {
            Op::Save { m, key } => {
                let mach = self.machine(m.0);
                let key = KEYS[key.0];
                let before = mach.vault();
                let out = mach
                    .murk()
                    .args(["add", key])
                    .write_stdin(format!("{}\n", value(key)))
                    .output()
                    .unwrap();
                Some(
                    self.after_write(step, m.0, &before, out, Delta::Same, |w, bytes| {
                        let excluded = (0..PEOPLE.len())
                            .filter(|p| !w.listed(bytes).contains(p))
                            .collect();
                        w.written.insert(value(key), (step, excluded));
                        w.check_saved(bytes, key, &value(key))
                    }),
                )
            }
            Op::Authorize { m, who } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let w = &self.fx.people[who.0];
                let out = mach
                    .murk()
                    .args(["circle", "authorize", &w.pubkey, "--name", &w.label])
                    .output()
                    .unwrap();
                let who = who.0;
                Some(self.after_write(
                    step,
                    m.0,
                    &before,
                    out,
                    Delta::Authorize(who),
                    |world, _| {
                        world.authorizes.push((who, step));
                        world.ci_signers.insert(who);
                        // This machine's own save that adds them clears its
                        // record of their removal.
                        if !world.listed(&before).contains(&who)
                            && let Some(records) = world.removed.get_mut(&Obs::Machine(m.0))
                        {
                            records.remove(&who);
                        }
                        Ok(())
                    },
                ))
            }
            Op::Revoke { m, who } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let who = match who {
                    Target::Person(p) => p.0,
                    Target::OtherMember(n) => {
                        let others: Vec<usize> = self
                            .listed(&before)
                            .into_iter()
                            .filter(|&p| p != MACHINES[m.0].1)
                            .collect();
                        *others.get(n % others.len().max(1))?
                    }
                };
                let revoker = MACHINES[m.0].1;
                let cascaded = self.grants_anchored_on(&before, revoker, who);
                self.last_cascade = cascaded.len();
                let out = mach
                    .murk()
                    .args(["circle", "revoke", &self.fx.people[who].pubkey])
                    .output()
                    .unwrap();
                // The revoke is known before the writer's own acceptance is
                // noted, so the writer's machine records the removal.
                if out.status.success() {
                    self.revokes.push((who, step));
                    // The operator drops them from the CI secret too.
                    self.ci_signers.remove(&who);
                }
                Some(self.after_write(
                    step,
                    m.0,
                    &before,
                    out,
                    Delta::Revoke(who),
                    |world, bytes| world.check_cascade(bytes, revoker, &cascaded, who),
                ))
            }
            Op::Vouch { m, who, key } => {
                let mach = self.machine(m.0);
                let person = MACHINES[m.0].1;
                let w = &self.fx.people[who.0];
                // A vouch is this member's own code (a forge with no pin), not
                // murk on this machine, so writing it accepts nothing here.
                // The machine then loads it, as its next command would, and
                // that load is what is judged: murk refuses a vault that lists
                // someone it recorded as removed where the removal applies,
                // and loads it where the removal has not reached the checkout.
                let forged = self.forge(
                    &mach.vault(),
                    &[
                        ("FORGE_KEY", self.fx.people[person].secret.clone()),
                        ("FORGE_AUTHORIZE", format!("{} {}", w.pubkey, w.label)),
                        (
                            "FORGE_REGISTRY",
                            format!("{}={}", w.pubkey, self.planted_vk(*key, person)),
                        ),
                    ],
                )?;
                // murk refused the save (a counter at its limit, say): nothing
                // was written.
                let forged = match forged {
                    Ok(forged) => forged,
                    Err(why) => return Some(Ok(Ran::Refused(why))),
                };
                let before = mach.vault();
                let newly = !self.listed(&before).contains(&who.0);
                fs::write(mach.dir.join(".murk"), &forged).unwrap();
                mach.commit(&format!("s{step} vouch"));
                self.record_origin(&forged, Some(person), step, false, true);
                if let Some(mut listed) = self.expected.get(&blob_id(&before)).cloned() {
                    listed.insert(who.0);
                    self.expected.insert(blob_id(&forged), listed);
                }
                if newly {
                    self.authorizes.push((who.0, step));
                    self.ci_signers.insert(who.0);
                }
                // The step is the vouch's write; the load only judges. A
                // refused load must leave the file as it is.
                let out = mach.murk().args(["export", "--json"]).output().unwrap();
                self.last_load = Some(Printed::of(&out));
                if !out.status.success() {
                    return Some(
                        refused(&forged, &mach.vault(), "murk export (after a vouch)", &out)
                            .map(|_| Ran::Accepted),
                    );
                }
                Some(self.accepted(Obs::Machine(m.0), &forged, "loaded (after a vouch)"))
            }
            Op::Sync { m } => Some(self.sync(step, m.0)),
            Op::MergeBranch {
                m,
                branch,
                take_theirs,
            } => {
                let branch = format!("origin/{}", self.pushed(*branch)?);
                let merged = self.merge(step, m.0, &branch, false);
                if !take_theirs || !matches!(merged, Ok(Ran::Refused(_))) {
                    return Some(merged);
                }
                let mach = self.machine(m.0);
                let _ = mach.git(&["merge", "-q", "--no-edit", &branch]);
                mach.git_ok(&["checkout", "--theirs", "--", ".murk"]);
                mach.git_ok(&["add", ".murk"]);
                mach.git_ok(&["commit", "-q", "--no-edit"]);
                Some(Ok(Ran::Accepted))
            }
            Op::Trust { m, forgery } => {
                let mach = self.machine(m.0);
                let bytes = mach.vault();
                let origin = self.origins.get(&blob_id(&bytes)).copied()?;
                // A reviewer accepts only what no rule here forbids.
                if (origin.forged && !forgery)
                    || self
                        .check_accept(&Obs::Machine(m.0), &bytes, "", &head(&mach))
                        .is_err()
                {
                    return None;
                }
                let out = mach.murk().args(["trust", "--yes"]).output().unwrap();
                if !out.status.success() {
                    return Some(refused(&bytes, &mach.vault(), "murk trust", &out));
                }
                let now = mach.vault();
                self.record(&now, MACHINES[m.0].1.into(), step, false);
                Some(self.accepted(Obs::Machine(m.0), &now, "trusted"))
            }
            Op::Load { m, at } => {
                let mach = self.machine(m.0);
                self.checkout_at(&mach, at, step)?;
                let bytes = mach.vault();
                let out = mach.murk().args(["export", "--json"]).output().unwrap();
                self.last_load = Some(Printed::of(&out));
                if !out.status.success() {
                    return Some(refused(&bytes, &mach.vault(), "murk export", &out));
                }
                Some(self.accepted(Obs::Machine(m.0), &bytes, "loaded"))
            }
            Op::Diff { m, rev } => {
                let mach = self.machine(m.0);
                let revs = mach.revisions();
                let rev = revs[rev % revs.len()].clone();
                let at_rev = mach.vault_at(&rev);
                let out = mach
                    .murk()
                    .args(["diff", &rev, "--show-values", "--json"])
                    .output()
                    .unwrap();
                if !out.status.success() {
                    return Some(Ok(Ran::Refused(stderr(&out))));
                }
                // diff never extends the pin: check, but note nothing.
                Some(
                    self.check_accept(&Obs::Machine(m.0), &at_rev, "showed (murk diff)", &rev)
                        .map(|()| Ran::Accepted),
                )
            }
            Op::Grant { m } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let keys_dir = mach.home.join(".config").join("murk").join("agent-keys");
                let kept: BTreeSet<PathBuf> = fs::read_dir(&keys_dir)
                    .map(|d| d.map(|e| e.unwrap().path()).collect())
                    .unwrap_or_default();
                let mut cmd = mach.murk();
                cmd.args([
                    "agent",
                    "grant",
                    "--name",
                    &format!("g{step}"),
                    "--only",
                    "K1",
                ]);
                let out = cmd.output().unwrap();
                if out.status.success() {
                    let key_file = fs::read_dir(&keys_dir)
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .find(|p| !kept.contains(p))
                        .expect("agent grant keeps a key file");
                    self.agent = Some(Agent {
                        key_file,
                        minted_on: m.0,
                    });
                    self.removed.remove(&Obs::Agent);
                }
                Some(self.after_write(step, m.0, &before, out, Delta::Same, |_, _| Ok(())))
            }
            Op::AgentLoad { at } => {
                let agent = self.agent.as_ref()?;
                let clone = bystander(&self.root, "agent");
                self.checkout_ref(&clone, *at)?;
                let bytes = clone.vault();
                let out = common::murk_bin(&clone.home)
                    .current_dir(&clone.dir)
                    .env("MURK_KEY_FILE", &agent.key_file)
                    .args(["get", "K1"])
                    .output()
                    .unwrap();
                self.last_load = Some(Printed::of(&out));
                if !out.status.success() {
                    return Some(Ok(Ran::Refused(stderr(&out))));
                }
                Some(self.accepted(Obs::Agent, &bytes, "loaded"))
            }
            Op::CiLoad { at } => {
                let clone = bystander(&self.root, "ci-runner");
                self.checkout_ref(&clone, *at)?;
                let bytes = clone.vault();
                // A fresh runner: no pin survives between loads.
                let _ = fs::remove_dir_all(&clone.home);
                fs::create_dir_all(&clone.home).unwrap();
                let signers: Vec<String> = self
                    .ci_signers
                    .iter()
                    .map(|&p| signer_entry(&self.fx.people[p]))
                    .collect();
                let out = common::murk_bin(&clone.home)
                    .current_dir(&clone.dir)
                    .env("MURK_KEY_FILE", key_path(&self.root, "ci"))
                    .env("MURK_TRUSTED_SIGNERS", signers.join(","))
                    .args(["export", "--json"])
                    .output()
                    .unwrap();
                self.last_load = Some(Printed::of(&out));
                if !out.status.success() {
                    return Some(Ok(Ran::Refused(stderr(&out))));
                }
                Some(self.accepted(Obs::Ci, &bytes, "loaded"))
            }
            Op::CiKeepLoad { at } => {
                let clone = bystander(&self.root, "ci-keep");
                self.checkout_ref(&clone, *at)?;
                let bytes = clone.vault();
                let before = pin_of(&clone, false);
                let signers: Vec<String> = self
                    .ci_signers
                    .iter()
                    .map(|&p| signer_entry(&self.fx.people[p]))
                    .collect();
                // The runner's `HOME` stays, so what the last load left in its
                // pin is what this one starts from.
                let out = common::murk_bin(&clone.home)
                    .current_dir(&clone.dir)
                    .env("MURK_KEY_FILE", key_path(&self.root, "ci"))
                    .env("MURK_TRUSTED_SIGNERS", signers.join(","))
                    .args(["export", "--json"])
                    .output()
                    .unwrap();
                self.last_load = Some(Printed::of(&out));
                if let Err(e) = self.pin_env_check(before.as_ref(), pin_of(&clone, false).as_ref())
                {
                    return Some(Err(e));
                }
                if !out.status.success() {
                    return Some(Ok(Ran::Refused(stderr(&out))));
                }
                Some(self.accepted(Obs::CiKept, &bytes, "loaded"))
            }
            Op::Rm { m, key } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let out = mach.murk().args(["rm", KEYS[key.0]]).output().unwrap();
                Some(self.after_write(step, m.0, &before, out, Delta::Same, |_, _| Ok(())))
            }
            Op::AncestorBranch { by, kind, rev } => {
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let revs = attacker.revisions();
                let tip = attacker.vault_at(&revs[rev % revs.len()]);
                let oldest = attacker.vault_at(revs.last()?);
                if tip.is_empty() || oldest.is_empty() {
                    return None;
                }
                let parent = match kind {
                    Ancestor::Stripped => unsigned(&oldest),
                    Ancestor::Empty => {
                        let base = revs
                            .iter()
                            .map(|r| attacker.vault_at(r))
                            .find(|v| self.listed(v).contains(&by.0) && self.opens(v, by.0))?;
                        let vars = [
                            ("FORGE_KEY", self.fx.people[by.0].secret.clone()),
                            ("FORGE_GEN", generation(&base).saturating_add(1).to_string()),
                            ("FORGE_CLEAR", "1".to_string()),
                            ("FORGE_LEGACY", "same".to_string()),
                            ("FORGE_STRIP_V1", "1".to_string()),
                        ];
                        self.forge(&base, &vars)?.ok()?
                    }
                };
                self.record(&parent, Some(by.0), step, true);
                self.push_two_commits(&parent, &tip, step);
                Some(Ok(Ran::Accepted))
            }
            Op::CherryPick { m, branch } => {
                let branch = format!("origin/{}", self.pushed(*branch)?);
                Some(self.cherry_pick(step, m.0, &branch))
            }
            Op::CopyVault { m } => {
                let mach = self.machine(m.0);
                fs::copy(mach.dir.join(".murk"), mach.dir.join("copy.murk")).unwrap();
                mach.commit(&format!("s{step} copy"));
                Some(Ok(Ran::Accepted))
            }
            Op::TrustCopy { m } => {
                let mach = self.machine(m.0);
                if !mach.dir.join("copy.murk").exists() {
                    // A copy is made first when there is none.
                    fs::copy(mach.dir.join(".murk"), mach.dir.join("copy.murk")).unwrap();
                    mach.commit(&format!("s{step} copy"));
                }
                let out = mach
                    .murk()
                    .args(["trust", "--vault", "copy.murk", "--yes"])
                    .output()
                    .unwrap();
                if out.status.success() {
                    // The copy shares the vault id of a vault this machine
                    // pinned at another path: murk must not accept it.
                    return Some(Err(
                        "murk trust accepted a byte copy of a pinned vault at a second path".into(),
                    ));
                }
                Some(Ok(Ran::Refused(stderr(&out))))
            }
            Op::ErinSave { key } => {
                let erin = self.erin();
                let key = KEYS[key.0];
                let before = erin.vault();
                let out = erin
                    .murk()
                    .args(["add", key])
                    .write_stdin(format!("{}\n", value(key)))
                    .output()
                    .unwrap();
                if let Err(e) = self.write_load(Obs::Erin, &erin, &before, out.status.success()) {
                    return Some(Err(e));
                }
                if !out.status.success() {
                    return Some(refused(&before, &erin.vault(), "refused write", &out));
                }
                erin.commit(&format!("s{step} erin"));
                let now = erin.vault();
                self.record(&now, None, step, false);
                if let Some(listed) = self.expected.get(&blob_id(&before)).cloned() {
                    self.expected.insert(blob_id(&now), listed);
                }
                let excluded = (0..PEOPLE.len())
                    .filter(|p| !self.listed(&now).contains(p))
                    .collect();
                self.written.insert(value(key), (step, excluded));
                if let Err(e) = self.check_saved(&now, key, &value(key)) {
                    return Some(Err(e));
                }
                let reload = export(&erin);
                if !reload.ok {
                    return Some(Err(format!(
                        "erin's machine refuses her own write: {}",
                        reload.stderr
                    )));
                }
                let at = head(&erin);
                Some(
                    self.accept_erin(
                        &now,
                        values_of(&reload),
                        "wrote",
                        &at,
                        Took::OwnSave(&before),
                    )
                    .map(|()| Ran::Accepted),
                )
            }
            Op::ErinSync => {
                let erin = self.erin();
                erin.git_ok(&["checkout", "-q", "-f", "main"]);
                erin.git_ok(&["fetch", "-q", "origin"]);
                let ours = erin.vault();
                let merged = erin.git(&["merge", "-q", "--no-edit", "origin/main"]);
                if driver_said(&merged.stderr) {
                    self.driver_said += 1;
                }
                if !merged.status.success() {
                    let _ = erin.git(&["merge", "--abort"]);
                    let _ = erin.git(&["reset", "-q", "--hard", "HEAD"]);
                    return Some(refused(&ours, &erin.vault(), "refused merge", &merged));
                }
                let result = erin.vault();
                if result != ours {
                    self.record(&result, None, step, false);
                }
                let _ = erin.git(&["push", "-q", "origin", "main"]);
                Some(Ok(Ran::Accepted))
            }
            Op::ErinLoad { at } => {
                let erin = self.erin();
                self.checkout_at(&erin, at, step)?;
                let bytes = erin.vault();
                let out = export(&erin);
                self.last_load = Some(out.clone());
                if !out.ok {
                    return Some(
                        unchanged(&bytes, &erin.vault(), "murk export")
                            .map(|()| Ran::Refused(out.stderr.trim().to_string())),
                    );
                }
                let at = head(&erin);
                Some(
                    self.accept_erin(&bytes, values_of(&out), "loaded", &at, Took::Load)
                        .map(|()| Ran::Accepted),
                )
            }
            Op::ForgeUnsigned { by, to } => {
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let base = attacker
                    .revisions()
                    .iter()
                    .map(|r| attacker.vault_at(r))
                    .find(|v| self.listed(v).contains(&by.0) && self.opens(v, by.0))?;
                let dave = &self.fx.people[3];
                let vars = [
                    ("FORGE_KEY", self.fx.people[by.0].secret.clone()),
                    ("FORGE_VALUE", format!("K1=forged-s{step}")),
                    ("FORGE_GEN", generation(&base).saturating_add(3).to_string()),
                    ("FORGE_AUTHORIZE", format!("{} {}", dave.pubkey, dave.label)),
                    ("FORGE_UNSIGNED", "1".to_string()),
                ];
                let forged = self.forge(&base, &vars)?.ok()?;
                // What the team's vault should list, which the forgery's extra
                // recipient is not: whoever saves on top of it is judged by
                // that.
                if let Some(listed) = self.expected.get(&blob_id(&base)).cloned() {
                    self.expected.insert(blob_id(&forged), listed);
                }
                self.record(&forged, Some(by.0), step, true);
                self.attacker_listed.insert(blob_id(&forged));
                self.push_as_attacker(&forged, *to, step);
                Some(Ok(Ran::Accepted))
            }
            Op::ListGrantKey { by, to } => {
                // The grant is minted first when there is none.
                if self.agent.is_none() {
                    match self.step(step, &Op::Grant { m: M(0) }) {
                        Some(Ok(Ran::Accepted)) => {}
                        other => return other,
                    }
                }
                let agent = self.agent.as_ref()?;
                let key = Who::from_secret("agent", &fs::read_to_string(&agent.key_file).ok()?);
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let base = attacker
                    .revisions()
                    .iter()
                    .map(|r| attacker.vault_at(r))
                    .find(|v| {
                        self.forgeable(v) && self.listed(v).contains(&by.0) && self.opens(v, by.0)
                    })?;
                let vars = [
                    ("FORGE_KEY", self.fx.people[by.0].secret.clone()),
                    ("FORGE_GEN", generation(&base).saturating_add(1).to_string()),
                    ("FORGE_AUTHORIZE", format!("{} botop", key.pubkey)),
                    ("FORGE_DROP_GRANTS", "1".to_string()),
                ];
                let forged = self.forge(&base, &vars)?.ok()?;
                self.record(&forged, Some(by.0), step, true);
                self.push_as_attacker(&forged, *to, step);
                Some(Ok(Ran::Accepted))
            }
            Op::ReAdd { m, who } => {
                let obs = Obs::Machine(m.0);
                let records = self.removals(&obs);
                // A machine re-adds someone it holds a record for. It favours
                // a person the checked-out vault lists again (a load it just
                // refused), then a person another machine authorized since,
                // whose vaults it would otherwise refuse.
                let mach = self.machine(m.0);
                let bytes = mach.vault();
                let in_vault = self.listed(&bytes);
                let recorded: Vec<usize> = records.keys().copied().collect();
                let who = [who.0]
                    .into_iter()
                    .chain(recorded.iter().copied())
                    .filter(|p| records.contains_key(p))
                    .find(|p| in_vault.contains(p))
                    .or_else(|| records.contains_key(&who.0).then_some(who.0))
                    .or_else(|| {
                        recorded
                            .iter()
                            .copied()
                            .find(|&p| self.authorized_between(p, records[&p].0, usize::MAX))
                    })
                    .or_else(|| recorded.first().copied())?;
                let listed = in_vault.contains(&who);
                let saved = self.removed.get_mut(&obs).and_then(|r| r.remove(&who));
                // A reviewer re-adds them only when nothing else here forbids
                // the vault that lists them.
                if listed
                    && let Some(origin) = self.origins.get(&blob_id(&bytes)).copied()
                    && (origin.forged || self.check_accept(&obs, &bytes, "", &head(&mach)).is_err())
                {
                    self.removed
                        .entry(obs)
                        .or_default()
                        .extend(saved.map(|s| (who, s)));
                    return None;
                }
                let out = mach
                    .murk()
                    .args([
                        "trust",
                        "--vault",
                        ".murk",
                        "--re-add",
                        &self.fx.people[who].pubkey,
                        "--yes",
                    ])
                    .output()
                    .unwrap();
                if !out.status.success() {
                    self.removed
                        .entry(obs)
                        .or_default()
                        .extend(saved.map(|s| (who, s)));
                    return Some(refused(&bytes, &mach.vault(), "murk trust --re-add", &out));
                }
                let now = mach.vault();
                if !listed {
                    return Some(
                        unchanged(&bytes, &now, "murk trust --re-add of an unlisted key")
                            .map(|()| Ran::Accepted),
                    );
                }
                self.record(&now, MACHINES[m.0].1.into(), step, false);
                let accepted = self.accepted(obs, &now, "trusted");
                if matches!(accepted, Ok(Ran::Accepted)) {
                    self.stats.count(DECISIVE_READD, true);
                }
                Some(accepted)
            }
            Op::AuthorizeAgain { m, by } => {
                // m holds a record for `who`; another machine authorizes
                // them again and pushes; m checks out the tip (its load is
                // refused) and consents with `murk trust --re-add`.
                let records = self.removals(&Obs::Machine(m.0));
                let who = *records.keys().next()?;
                let by = [by.0].into_iter().chain(0..MACHINES.len()).find(|&i| {
                    i != m.0 && MACHINES[i].1 != who && MACHINES[i].1 != MACHINES[m.0].1
                })?;
                for op in [
                    Op::Sync { m: M(by) },
                    Op::Authorize {
                        m: M(by),
                        who: P(who),
                    },
                    Op::Sync { m: M(by) },
                ] {
                    match self.step(step, &op)? {
                        Ok(Ran::Accepted) => {}
                        other => return Some(other),
                    }
                }
                if let Err(e) = self.step(
                    step,
                    &Op::Load {
                        m: *m,
                        at: At::OriginMain,
                    },
                )? {
                    return Some(Err(e));
                }
                self.step(step, &Op::ReAdd { m: *m, who: P(who) })
            }
            Op::PrFlow { m, n } => self.pr_flow(step, m.0, *n),
            Op::BranchCurrent { m, n } => self.branch_current(step, m.0, *n),
            Op::AgentProbe { at, how } => {
                let agent = self.agent.as_ref()?;
                let secret = fs::read_to_string(&agent.key_file).ok()?;
                let who = Who::from_secret("agent", &secret);
                let clone = bystander(&self.root, "agent");
                self.checkout_ref(&clone, *at)?;
                let signers: Vec<String> = self
                    .ci_signers
                    .iter()
                    .map(|&p| signer_entry(&self.fx.people[p]))
                    .collect();
                let key_file = self.root.join("agent-bare.key");
                // A runner that names its signers (as CI does) and has no pin.
                let _ = fs::remove_dir_all(&clone.home);
                fs::create_dir_all(&clone.home).unwrap();
                let run = |args: &[&str], stdin: &str| {
                    let mut cmd = common::murk_bin(&clone.home);
                    cmd.current_dir(&clone.dir)
                        .env("MURK_TRUSTED_SIGNERS", signers.join(","));
                    match how {
                        Presented::StrippedLines => {
                            write_key(&key_file, &format!("{}\n", who.secret));
                            cmd.env("MURK_KEY_FILE", &key_file);
                        }
                        Presented::RawKey => {
                            cmd.env("MURK_KEY", &who.secret);
                        }
                    }
                    Printed::of(
                        &cmd.args(args)
                            .write_stdin(stdin.to_string())
                            .output()
                            .unwrap(),
                    )
                };
                // The grant covers K1 only: a read of another key, or any
                // write, is a grant key acting as an operator. This runner
                // has no pin, so only the vault's own revoked grant set can
                // refuse the key: a vault a trusted signer wrote without the
                // key in that set (a modified murk that drops the set, or a
                // grant never revoked by this release) reads, a stated
                // residual of the grant tombstone.
                let read = run(&["get", "K2"], "");
                let write = run(&["add", "PLANTED", "--desc", "x"], "planted\n");
                if read.ok || write.ok {
                    if !self.revokes_grant(&clone.vault(), &who.pubkey) {
                        return Some(Ok(Ran::Accepted));
                    }
                    return Some(Err(format!(
                        "a grant key presented as {how:?} acted as an operator (read outside its \
                         scope: {}, wrote: {})",
                        read.ok, write.ok
                    )));
                }
                Some(Ok(Ran::Refused(read.stderr.trim().to_string())))
            }
            Op::Forge {
                by,
                base,
                generation,
                sign,
                to,
            } => {
                let revoked = matches!(by, Attacker::Revoked);
                let by = match by {
                    Attacker::Person(p) => p.0,
                    Attacker::Revoked => self.revokes.last()?.0,
                };
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let revs = attacker.revisions();
                let base = match base {
                    Base::Nth(n) => attacker.vault_at(&revs[n % revs.len()]),
                    Base::NewestOpenable => {
                        revs.iter().map(|r| attacker.vault_at(r)).find(|v| {
                            self.forgeable(v) && self.listed(v).contains(&by) && self.opens(v, by)
                        })?
                    }
                };
                if !self.forgeable(&base) {
                    return None;
                }
                let base_gen =
                    serde_json::from_slice::<serde_json::Value>(&base).ok()?["generation"]
                        .as_u64()
                        .unwrap_or(0);
                let claimed = match generation {
                    Gen::Next => base_gen.saturating_add(1),
                    Gen::Jump => base_gen.saturating_add(1000),
                    Gen::Max => GENERATION_CAP,
                    Gen::AboveCap => u64::MAX,
                };
                let mut vars = vec![
                    ("FORGE_KEY", self.fx.people[by].secret.clone()),
                    ("FORGE_VALUE", format!("K1=forged-s{step}")),
                    ("FORGE_GEN", claimed.to_string()),
                ];
                let (planted, plants) = match *sign {
                    Sign::Own | Sign::Legacy | Sign::LegacyOther => (None, false),
                    Sign::AsPlanted(key) => (Some(key), false),
                    Sign::Plants(key) => (Some(key), true),
                };
                match sign {
                    Sign::Legacy => vars.push(("FORGE_LEGACY", "same".into())),
                    Sign::LegacyOther => vars.push(("FORGE_LEGACY", "other".into())),
                    _ => {}
                }
                if let Some(key) = planted {
                    if plants {
                        let as_whom = self.listed(&base).into_iter().find(|&p| p != by)?;
                        vars.push((
                            "FORGE_REGISTRY",
                            format!(
                                "{}={}",
                                self.fx.people[as_whom].pubkey,
                                self.planted_vk(key, by)
                            ),
                        ));
                    }
                    vars.push((
                        "FORGE_SIGN_AS",
                        match key {
                            Planted::Sock => format!("sock:{}", self.fx.socks[by].secret),
                            Planted::Weak => "weak".into(),
                        },
                    ));
                    // A removed member signing as someone else leaves
                    // themselves out: a vault that lists them is refused for
                    // that alone.
                    if revoked && !plants {
                        vars.push(("FORGE_DROP_SELF", "1".into()));
                    }
                }
                // A save murk refused is the attacker's to work around; this
                // forgery does not apply.
                let forged = self.forge(&base, &vars)?.ok()?;
                self.record(&forged, Some(by), step, true);
                self.push_as_attacker(&forged, *to, step);
                Some(Ok(Ran::Accepted))
            }
            Op::Replay { rev, to } => {
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let revs = attacker.revisions();
                let old = match rev {
                    Old::Nth(n) => attacker.vault_at(&revs[n % revs.len()]),
                    Old::ListingRevoked => {
                        let who = self.revokes.last()?.0;
                        revs.iter()
                            .map(|r| attacker.vault_at(r))
                            .find(|v| self.listed(v).contains(&who))?
                    }
                };
                if old.is_empty() {
                    return None;
                }
                self.push_as_attacker(&old, *to, step);
                Some(Ok(Ran::Accepted))
            }
            Op::Push { m } => {
                let mach = self.machine(m.0);
                let name = format!("push-{step}");
                mach.git_ok(&["push", "-q", "origin", &format!("HEAD:refs/heads/{name}")]);
                self.branches.push(name);
                Some(Ok(Ran::Accepted))
            }
            Op::Group { m, act } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let mut cmd = mach.murk();
                match *act {
                    GroupAct::Create(name) => cmd.args(["group", "create", name]),
                    GroupAct::Add(name, who) => cmd.args([
                        "group",
                        "add",
                        name,
                        "--member",
                        &self.fx.people[who.0].pubkey,
                    ]),
                    GroupAct::Delete(name) => cmd.args(["group", "rm", name]),
                };
                let out = cmd.output().unwrap();
                Some(self.after_write(step, m.0, &before, out, Delta::Same, |_, _| Ok(())))
            }
            Op::Policy { m } => {
                let mach = self.machine(m.0);
                let before = mach.vault();
                let out = mach
                    .murk()
                    .args(["policy", "set", "--allow-tag", "nothing"])
                    .output()
                    .unwrap();
                Some(self.after_write(step, m.0, &before, out, Delta::Same, |_, _| Ok(())))
            }
            Op::Join { by, group, to } => {
                let attacker = bystander(&self.root, "attacker");
                attacker.git_ok(&["fetch", "-q", "origin"]);
                let base = attacker
                    .revisions()
                    .iter()
                    .map(|r| attacker.vault_at(r))
                    .find(|v| {
                        self.forgeable(v) && self.listed(v).contains(&by.0) && self.opens(v, by.0)
                    })?;
                let vars = [
                    ("FORGE_KEY", self.fx.people[by.0].secret.clone()),
                    ("FORGE_GEN", generation(&base).saturating_add(1).to_string()),
                    (
                        "FORGE_GROUP",
                        format!("{group}={}", self.fx.people[by.0].pubkey),
                    ),
                ];
                let forged = self.forge(&base, &vars)?.ok()?;
                self.record(&forged, Some(by.0), step, true);
                self.push_as_attacker(&forged, *to, step);
                Some(Ok(Ran::Accepted))
            }
        }
    }

    /// The grant keys in `before` that a revoke of `who` must revoke with
    /// them: grants whose anchor names `who`, or that have no anchor.
    fn grants_anchored_on(&self, before: &[u8], revoker: usize, who: usize) -> Vec<String> {
        self.meta(before, revoker)
            .map(|meta| {
                meta.grants
                    .values()
                    .filter(|g| self.anchored_on(g, who))
                    .map(|g| g.pubkey.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn anchored_on(&self, grant: &murk_cli::types::GrantEntry, who: usize) -> bool {
        grant.anchors.is_empty() || grant.anchors.contains(&self.fx.people[who].pubkey)
    }

    /// The revoke cascade: the vault a revoke of `who` wrote keeps no grant
    /// that trusts them, as a grant record or as a recipient.
    ///
    /// This checks the vault, not the grant's key file. murk deletes the key
    /// file in its default slot on this machine, but a copy handed off with
    /// `--out` survives and still trusts the revoked signer until its TTL
    /// ends: an accepted, documented limit that this harness does not hold.
    fn check_cascade(
        &self,
        bytes: &[u8],
        revoker: usize,
        cascaded: &[String],
        who: usize,
    ) -> Result<(), String> {
        let meta = self
            .meta(bytes, revoker)
            .ok_or("the revoker cannot open the meta it wrote")?;
        let vault: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let recipients: BTreeSet<&str> = vault["recipients"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let mut kept = meta
            .grants
            .values()
            .filter(|g| self.anchored_on(g, who))
            .map(|g| &g.pubkey)
            .chain(
                cascaded
                    .iter()
                    .filter(|pk| recipients.contains(pk.as_str())),
            );
        if let Some(pubkey) = kept.next() {
            return Err(format!(
                "the revoke of {} kept the grant {pubkey} that trusts them in the vault",
                PEOPLE[who]
            ));
        }
        Ok(())
    }

    /// Whether person `who` can open a vault file with murk's library.
    fn opens(&self, bytes: &[u8], who: usize) -> bool {
        let path = self.root.join("opens.murk");
        fs::write(&path, bytes).unwrap();
        let Ok(vault) = murk_cli::read_vault(path.to_str().unwrap()) else {
            return false;
        };
        let identity = murk_cli::crypto::parse_identity(&self.fx.people[who].secret).unwrap();
        murk_cli::decrypt_vault(&vault, &identity).is_ok()
    }

    /// Whether the vault `bytes` holds a revocation id for agent grant key
    /// `key` in its own revoked grant set, read by any person who opens it.
    fn revokes_grant(&self, bytes: &[u8], key: &str) -> bool {
        let path = self.root.join("revokes.murk");
        fs::write(&path, bytes).unwrap();
        let Ok(vault) = murk_cli::read_vault(path.to_str().unwrap()) else {
            return false;
        };
        self.fx.people.iter().any(|p| {
            let identity = murk_cli::crypto::parse_identity(&p.secret).unwrap();
            murk_cli::decrypt_meta(&vault, &identity)
                .ok()
                .flatten()
                .is_some_and(|meta| {
                    meta.revoked_grants
                        .get(key)
                        .is_some_and(|ids| !ids.is_empty())
                })
        })
    }

    /// The verifying key a `key` plant registers, for person `holder`.
    fn planted_vk(&self, key: Planted, holder: usize) -> String {
        match key {
            Planted::Sock => verifying_key(&self.fx.socks[holder]),
            Planted::Weak => weak_vk_b64(),
        }
    }

    /// The meta of a vault file, as person `reader` opens it.
    fn meta(&self, bytes: &[u8], reader: usize) -> Option<murk_cli::types::Meta> {
        let path = self.root.join("meta.murk");
        fs::write(&path, bytes).ok()?;
        let vault = murk_cli::read_vault(path.to_str()?).ok()?;
        let identity = murk_cli::crypto::parse_identity(&self.fx.people[reader].secret).ok()?;
        murk_cli::decrypt_meta(&vault, &identity).ok()?
    }

    /// Accept `bytes`, the vault checked out in `obs`'s clone, as a step's
    /// outcome: a load, or `murk trust` (`how` is `trusted`).
    fn accepted(&mut self, obs: Obs, bytes: &[u8], how: &str) -> Result<Ran, String> {
        let at = head(&self.clone_of(&obs));
        let took = if how == "trusted" {
            Took::Trust
        } else {
            Took::Load
        };
        self.accept(obs, bytes, how, &at, took)
            .map(|()| Ran::Accepted)
    }

    /// The load every CLI write runs first (`load_vault_locked`): murk takes
    /// `before`, the file the write replaces, under the load rules, so the
    /// pin can drop and record someone before the save. A write that
    /// succeeded loaded it; for a refused one, a load of the same, unchanged
    /// file says whether that first load was accepted (a repeat of an
    /// accepted load changes nothing in the pin). Run before the write is
    /// committed, so the checkout is still the commit `before` is from.
    fn write_load(
        &mut self,
        obs: Obs,
        clone: &Machine,
        before: &[u8],
        wrote: bool,
    ) -> Result<(), String> {
        if !wrote && !export(clone).ok {
            return Ok(());
        }
        let at = head(clone);
        self.check_accept(&obs, before, "loaded (before a write)", &at)?;
        self.note_accept(obs, before, &at, Took::Load);
        Ok(())
    }

    /// After a member's write: a refusal changed nothing; an accepted write
    /// is committed, recorded, accepted by the writer's machine, passes
    /// `extra`, and loads again there.
    fn after_write(
        &mut self,
        step: usize,
        m: usize,
        before: &[u8],
        out: std::process::Output,
        delta: Delta,
        extra: impl FnOnce(&mut Self, &[u8]) -> Result<(), String>,
    ) -> Result<Ran, String> {
        let mach = self.machine(m);
        let now = mach.vault();
        self.write_load(Obs::Machine(m), &mach, before, out.status.success())?;
        if !out.status.success() {
            return refused(before, &now, "refused write", &out);
        }
        mach.commit(&format!("s{step} p{}", MACHINES[m].1));
        self.record(&now, Some(MACHINES[m].1), step, false);
        if let Some(mut listed) = self.expected.get(&blob_id(before)).cloned() {
            match delta {
                Delta::Same => {}
                Delta::Authorize(p) => {
                    listed.insert(p);
                }
                Delta::Revoke(p) => {
                    listed.remove(&p);
                }
            }
            self.expected.insert(blob_id(&now), listed);
        }
        extra(self, &now)?;
        self.accept(
            Obs::Machine(m),
            &now,
            "wrote",
            &head(&mach),
            Took::OwnSave(before),
        )?;
        let reload = mach.murk().args(["export", "--json"]).output().unwrap();
        if !reload.status.success() {
            return Err(format!(
                "the writer's machine refuses its own write: {}",
                String::from_utf8_lossy(&reload.stderr)
            ));
        }
        Ok(Ran::Accepted)
    }

    /// Play `op` as one part of a composite step, at `step`. `Err` holds
    /// what the composite step returns when the part did not apply or was
    /// not accepted.
    fn part(&mut self, step: usize, op: &Op) -> Result<(), Option<Result<Ran, String>>> {
        match self.step(step, op) {
            Some(Ok(Ran::Accepted)) => Ok(()),
            other => Err(other),
        }
    }

    /// For a composite removal step on machine `m`, at the vault it has
    /// checked out: the n-th (wrapping) pair of a teammate's machine and a
    /// member to remove. Both people are listed and trusted by `m`'s pin, the
    /// member is neither `m`'s person nor the teammate's, and the
    /// teammate's clone has `m`'s commit. `None` when no pair fits.
    fn removal_pair(&self, m: usize, n: usize) -> Option<(usize, usize)> {
        let trusted = &self.pins.get(&Obs::Machine(m))?.trusted;
        let mach = self.machine(m);
        let listed = self.listed(&mach.vault());
        let base = head(&mach);
        let person = MACHINES[m].1;
        let pairs: Vec<(usize, usize)> = (0..MACHINES.len())
            .filter(|&b| {
                b != m && trusted.contains(&MACHINES[b].1) && listed.contains(&MACHINES[b].1)
            })
            .flat_map(|b| {
                listed
                    .iter()
                    .copied()
                    .filter(move |&p| p != person && p != MACHINES[b].1 && trusted.contains(&p))
                    .map(move |p| (b, p))
            })
            .collect();
        let (by, who) = *pairs.get(n % pairs.len().max(1))?;
        let fork = self.machine(by);
        fork.git_ok(&["fetch", "-q", "origin"]);
        fork.git(&["cat-file", "-e", &format!("{base}^{{commit}}")])
            .status
            .success()
            .then_some((by, who))
    }

    /// [`Op::PrFlow`]. Counts [`PR_FLOW_DECISIVE`] when `m` holds the record
    /// and refuses the replay.
    fn pr_flow(&mut self, step: usize, m: usize, n: usize) -> Option<Result<Ran, String>> {
        let mach = self.machine(m);
        if let Err(r) = self.part(step, &Op::Sync { m: M(m) }) {
            return r;
        }
        if let Err(r) = self.part(
            step + 1,
            &Op::Load {
                m: M(m),
                at: At::Main,
            },
        ) {
            return r;
        }
        let (by, who) = self.removal_pair(m, n)?;
        let base = head(&mach);
        let topic = format!("pr{step}");
        mach.git_ok(&["checkout", "-q", "-f", "-B", &topic, &base]);
        let revoke = Op::Revoke {
            m: M(m),
            who: Target::Person(P(who)),
        };
        if let Err(r) = self.part(step + 2, &revoke) {
            return r;
        }
        // A teammate who has not seen the revoke saves on a branch off the
        // same commit: a stale fork, still listing the member.
        let fork = self.machine(by);
        fork.git_ok(&["checkout", "-q", "-f", "-B", &format!("stale{step}"), &base]);
        for key in [K(0), K(1)] {
            if let Err(r) = self.part(step + 3 + key.0, &Op::Save { m: M(by), key }) {
                return r;
            }
        }
        let stale = fork.vault();
        // The pull request merges (a fast-forward); a repo writer then
        // commits the stale fork on main.
        mach.git_ok(&["checkout", "-q", "-f", "main"]);
        mach.git_ok(&["merge", "-q", "--ff-only", &topic]);
        fs::write(mach.dir.join(".murk"), &stale).unwrap();
        mach.commit(&format!("s{step} replay"));
        let decisive = self.removals(&Obs::Machine(m)).contains_key(&who);
        let loaded = self.step(
            step + 5,
            &Op::Load {
                m: M(m),
                at: At::Main,
            },
        )?;
        if decisive && matches!(loaded, Ok(Ran::Refused(_))) {
            self.stats.count(PR_FLOW_DECISIVE, true);
        }
        mach.git_ok(&["reset", "-q", "--hard", &topic]);
        Some(loaded)
    }

    /// [`Op::BranchCurrent`]. Counts [`BRANCH_CURRENT_DECISIVE`] when `m`
    /// loaded the revoke below its highest counter, holds the record, and
    /// refuses the replay.
    fn branch_current(&mut self, step: usize, m: usize, n: usize) -> Option<Result<Ran, String>> {
        let mach = self.machine(m);
        if let Err(r) = self.part(step, &Op::Sync { m: M(m) }) {
            return r;
        }
        if let Err(r) = self.part(
            step + 1,
            &Op::Load {
                m: M(m),
                at: At::Main,
            },
        ) {
            return r;
        }
        let (by, who) = self.removal_pair(m, n)?;
        let base = head(&mach);
        let revoked = format!("rv{step}");
        let revoker = self.machine(by);
        revoker.git_ok(&["checkout", "-q", "-f", "-B", &revoked, &base]);
        // m saves ahead on a feature branch.
        mach.git_ok(&["checkout", "-q", "-f", "-B", &format!("feat{step}"), &base]);
        for key in [K(0), K(1), K(2)] {
            if let Err(r) = self.part(step + 2 + key.0, &Op::Save { m: M(m), key }) {
                return r;
            }
        }
        // The teammate revokes over the same main and pushes it.
        let revoke = Op::Revoke {
            m: M(by),
            who: Target::Person(P(who)),
        };
        if let Err(r) = self.part(step + 5, &revoke) {
            return r;
        }
        revoker.git_ok(&["push", "-q", "-f", "origin", &revoked]);
        // m saves a stale fork off main before it has seen the revoke.
        mach.git_ok(&["checkout", "-q", "-f", "-B", &format!("stale{step}"), &base]);
        for key in [K(0), K(1)] {
            if let Err(r) = self.part(step + 6 + key.0, &Op::Save { m: M(m), key }) {
                return r;
            }
        }
        let stale = mach.vault();
        // m fast-forwards main to the revoke and loads it: main's next
        // state, below m's highest counter.
        mach.git_ok(&["checkout", "-q", "-f", "main"]);
        mach.git_ok(&["fetch", "-q", "origin"]);
        mach.git_ok(&["merge", "-q", "--ff-only", &format!("origin/{revoked}")]);
        let below = self.pins.get(&Obs::Machine(m)).map(|p| p.generation)
            > Some(generation_of(&mach.vault()));
        if let Err(r) = self.part(
            step + 8,
            &Op::Load {
                m: M(m),
                at: At::Main,
            },
        ) {
            return r;
        }
        fs::write(mach.dir.join(".murk"), &stale).unwrap();
        mach.commit(&format!("s{step} replay"));
        let decisive = below && self.removals(&Obs::Machine(m)).contains_key(&who);
        let loaded = self.step(
            step + 9,
            &Op::Load {
                m: M(m),
                at: At::Main,
            },
        )?;
        if decisive && matches!(loaded, Ok(Ran::Refused(_))) {
            self.stats.count(BRANCH_CURRENT_DECISIVE, true);
        }
        mach.git_ok(&["reset", "-q", "--hard", &format!("origin/{revoked}")]);
        Some(loaded)
    }

    /// Fetch, merge `origin/main` into `main`, push.
    fn sync(&mut self, step: usize, m: usize) -> Result<Ran, String> {
        let mach = self.machine(m);
        mach.git_ok(&["checkout", "-q", "-f", "main"]);
        self.merge(step, m, "origin/main", true)
    }

    /// Merge `theirs` into the current checkout. When both sides changed the
    /// vault, the murk driver accepted `theirs` and produced the result.
    fn merge(
        &mut self,
        step: usize,
        m: usize,
        theirs_ref: &str,
        push: bool,
    ) -> Result<Ran, String> {
        let mach = self.machine(m);
        mach.git_ok(&["fetch", "-q", "origin"]);
        let ours = mach.vault();
        let ours_head = head(&mach);
        let theirs = mach.vault_at(theirs_ref);
        let base_rev = mach.git(&["merge-base", "HEAD", theirs_ref]);
        let base = String::from_utf8_lossy(&base_rev.stdout).trim().to_string();
        let ancestor = mach.vault_at(&base);
        let merged = mach.git(&["merge", "-q", "--no-edit", theirs_ref]);
        if driver_said(&merged.stderr) {
            self.driver_said += 1;
        }
        if !merged.status.success() {
            let _ = mach.git(&["merge", "--abort"]);
            let _ = mach.git(&["reset", "-q", "--hard", "HEAD"]);
            return refused(&ours, &mach.vault(), "refused merge", &merged);
        }
        let driver_ran = ours != ancestor && theirs != ancestor && ours != theirs;
        if driver_ran {
            // The driver judges theirs on this branch, as it was.
            self.check_accept(&Obs::Machine(m), &theirs, "merged (driver)", &ours_head)?;
            let result = mach.vault();
            self.record(&result, Some(MACHINES[m].1), step, false);
            if let Some(listed) = self.merged_listing(&ours, &theirs, &ancestor) {
                self.expected.insert(blob_id(&result), listed);
            }
            // The driver writes no pin: murk takes the result at the next
            // load, under the load rules.
            self.accept(
                Obs::Machine(m),
                &result,
                "wrote (merge result)",
                &head(&mach),
                Took::Custom,
            )?;
        }
        if push {
            let _ = mach.git(&["push", "-q", "origin", "main"]);
        }
        Ok(Ran::Accepted)
    }

    /// The no-reads check over every working vault and the remote tip.
    fn check_all_reads(&self) -> Result<(), String> {
        for (i, (name, _)) in MACHINES.iter().enumerate() {
            self.check_reads(name, &self.machine(i).vault())?;
        }
        self.check_reads("origin/main", &self.origin_tip("main"))
    }

    /// erin's machine.
    fn erin(&self) -> Machine {
        erin_machine(&self.root)
    }

    /// A vault `signer` (a key file's label) builds in a scratch directory of
    /// its own, as anyone with a key of their own can: `murk init`, a recipient
    /// for each of `listing` (public key, name), and `DB` set to `value`. The
    /// vault is signed by `signer` and has an id of its own.
    fn built_vault(
        &self,
        tag: &str,
        signer: &str,
        listing: &[(&str, &str)],
        value: &str,
    ) -> Vec<u8> {
        let scratch = self.scratch(tag, signer);
        let run = |args: &[&str], stdin: String| {
            scratch
                .murk()
                .args(args)
                .write_stdin(stdin)
                .assert()
                .success();
        };
        run(&["init"], "builder\n".into());
        for (pubkey, name) in listing {
            run(
                &[
                    "circle",
                    "authorize",
                    pubkey,
                    "--name",
                    name,
                    "--allow-ssh-rsa",
                ],
                String::new(),
            );
        }
        run(&["add", "DB"], format!("{value}\n"));
        scratch.vault()
    }

    /// A directory and `HOME` of their own (outside git, with no pin) where
    /// `key` (a key file's label) runs murk: a fresh machine, or the scratch
    /// place where someone builds a vault of their own.
    fn scratch(&self, tag: &str, key: &str) -> Machine {
        let machine = Machine {
            name: tag.to_string(),
            dir: self.root.join(format!("scratch-{tag}")),
            home: self.root.join(format!("scratch-{tag}-home")),
            key_file: key_path(&self.root, key),
        };
        fs::create_dir_all(&machine.dir).unwrap();
        fs::create_dir_all(&machine.home).unwrap();
        machine
    }

    /// Commit `bytes` as the vault on a branch off `parent` (a commit the
    /// remote has) and push it, as someone with push access builds a pull
    /// request whose parent is a genuine revision. Returns the branch name.
    fn push_branch_off(&mut self, parent: &str, bytes: &[u8], step: usize) -> String {
        let attacker = bystander(&self.root, "attacker");
        attacker.git_ok(&["fetch", "-q", "origin"]);
        attacker.git_ok(&["checkout", "-q", "-f", "-B", "work", parent]);
        fs::write(attacker.dir.join(".murk"), bytes).unwrap();
        attacker.commit(&format!("s{step} attacker"));
        let name = format!("attack-{step}");
        attacker.git_ok(&["push", "-q", "origin", &format!("HEAD:refs/heads/{name}")]);
        self.branches.push(name.clone());
        name
    }
}

/// The commit checked out in `clone`.
fn head(clone: &Machine) -> String {
    clone.git_ok(&["rev-parse", "HEAD"]).trim().to_string()
}

/// `murk export` on `mach`'s working vault.
fn export(mach: &Machine) -> Printed {
    Printed::of(&mach.murk().args(["export", "--json"]).output().unwrap())
}

/// Put `bytes` over `mach`'s working vault for the length of `f`, which loads
/// or writes there, and put the file as it was back afterwards: a vault
/// replaced on a checkout with no merge, as a pull of rewritten history or a
/// copied file leaves it.
fn with_file<T>(mach: &Machine, bytes: &[u8], f: impl FnOnce(&Machine) -> T) -> T {
    let path = mach.dir.join(".murk");
    let kept = fs::read(&path).unwrap();
    fs::write(&path, bytes).unwrap();
    let out = f(mach);
    fs::write(&path, kept).unwrap();
    out
}

/// `murk export` of `bytes` laid over `mach`'s working vault.
fn load_file(mach: &Machine, bytes: &[u8]) -> Printed {
    with_file(mach, bytes, export)
}

/// `mach`'s pin for its vault, or with `sidecar` the lineage sidecar next to
/// it (this release has none yet).
fn pin_of(mach: &Machine, sidecar: bool) -> Option<serde_json::Value> {
    let dir = mach.home.join(".config").join("murk").join("signer-pins");
    fs::read_dir(dir).ok()?.find_map(|entry| {
        let path = entry.ok()?.path();
        let name = path.file_name()?.to_str()?;
        (name.ends_with(".json") && name.ends_with(".lineage.json") == sidecar)
            .then(|| serde_json::from_slice(&fs::read(&path).ok()?).ok())?
    })
}

/// A vault file as JSON (null when it is not).
fn vault_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or_default()
}

/// The generation a vault file carries.
fn generation(bytes: &[u8]) -> u64 {
    vault_json(bytes)["generation"].as_u64().unwrap_or(0)
}

/// Whether a vault file carries a signature.
fn has_sig(bytes: &[u8]) -> bool {
    !vault_json(bytes)["sig"].is_null()
}

/// The major version of a vault file's header (`3` for `3.0`).
fn major(bytes: &[u8]) -> u64 {
    vault_json(bytes)["version"]
        .as_str()
        .and_then(|v| v.split('.').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// A vault file without its signature, as a repo writer leaves it: the MAC
/// does not cover the signature, so the file still verifies.
fn unsigned(bytes: &[u8]) -> Vec<u8> {
    let mut vault = vault_json(bytes);
    vault.as_object_mut().unwrap().remove("sig");
    serde_json::to_vec_pretty(&vault).unwrap()
}

/// A vault file built by `by`, who reads it, re-numbered to `generation` and
/// given the id `vault_id`, with a MAC and signature that hold: the same
/// file with another counter, as a key holder's own code writes it.
fn retargeted(bytes: &[u8], by: &Who, vault_id: &str, generation: u64) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retargeted.murk");
    fs::write(&path, bytes).unwrap();
    let mut vault = murk_cli::read_vault(path.to_str().unwrap()).unwrap();
    vault.vault_id = vault_id.to_string();
    vault.generation = generation;
    common::forgery::reseal(
        &mut vault,
        &murk_cli::crypto::parse_identity(&by.secret).unwrap(),
    );
    murk_cli::vault::write(&path, &vault).unwrap();
    fs::read(&path).unwrap()
}

/// Whether the murk merge driver ran: its merged line, its conflict list or
/// one of its refusals is on `stderr`. git's own text conflict says none.
fn driver_said(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    [
        "vault merged cleanly",
        " conflict:",
        " conflicts:",
        "nothing was written",
        "already contains",
    ]
    .iter()
    .any(|line| text.contains(line))
}

fn unchanged(before: &[u8], after: &[u8], what: &str) -> Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!("{what} changed the working vault"))
    }
}

/// What a step that ran did.
#[derive(Debug)]
enum Ran {
    Accepted,
    /// Refused, with the command's error output.
    Refused(String),
}

/// What a step that wrote the vault did to who it lists.
#[derive(Clone, Copy, Debug)]
enum Delta {
    Same,
    Authorize(usize),
    Revoke(usize),
}

/// The branch checked out in `mach`, or `None` on a detached HEAD.
fn branch_of(mach: &Machine) -> Option<String> {
    let out = mach.git(&["rev-parse", "--abbrev-ref", "HEAD"]);
    let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && branch != "HEAD").then_some(branch)
}

/// The step a value was written at, from its text: `s<step>-<key>` for a save,
/// `forged-s<step>` for a forgery and `init-<key>` (step 0) for the fixture's.
fn written_step(value: &str) -> Option<usize> {
    if value.starts_with("init-") {
        return Some(0);
    }
    let value = value.strip_prefix("forged-").unwrap_or(value);
    value.strip_prefix('s')?.split('-').next()?.parse().ok()
}

/// Whether the test acts as if the row `id` were fixed, for looking at what
/// the harness finds in today's murk: the oracles that wait for a fix fail
/// instead of counting, and the constructors it covers are drawn.
/// `MURK_TRUST_ASSUME_FIXED` is `all` (or `1`), or a comma-separated list of
/// row ids.
fn assume_fixed(id: &str) -> bool {
    std::env::var("MURK_TRUST_ASSUME_FIXED")
        .is_ok_and(|v| v == "1" || v == "all" || v.split(',').any(|row| row.trim() == id))
}

/// Whether the row `id` is enforced in the table (or the test acts as if it
/// were). An id that is not in the table is never enforced.
fn row_enforced(id: &str) -> bool {
    assume_fixed(id)
        || common::rows::table()
            .iter()
            .any(|row| row.id == id && row.state == common::rows::State::Enforced)
}

/// The value-lineage oracle fails a step only once its S1 row is enforced.
fn lineage_enforced() -> bool {
    row_enforced("R-L-load")
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_string()
}

/// A refused command: it must have left the working vault unchanged.
fn refused(
    before: &[u8],
    after: &[u8],
    what: &str,
    out: &std::process::Output,
) -> Result<Ran, String> {
    unchanged(before, after, what).map(|()| Ran::Refused(stderr(out)))
}

/// What a stored sequence requires of one of its steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// It runs; either outcome.
    Runs,
    /// It runs and is accepted.
    Accepts,
    /// It runs and is refused.
    Refuses,
}

/// A step of a stored sequence.
#[derive(Clone, Debug)]
struct Scripted {
    op: Op,
    expect: Expect,
    /// The step the sequence exists to exercise.
    decisive: bool,
}

fn runs(op: Op) -> Scripted {
    Scripted {
        op,
        expect: Expect::Runs,
        decisive: false,
    }
}

fn accepts(op: Op) -> Scripted {
    Scripted {
        expect: Expect::Accepts,
        ..runs(op)
    }
}

fn refuses(op: Op) -> Scripted {
    Scripted {
        expect: Expect::Refuses,
        ..runs(op)
    }
}

impl Scripted {
    fn decisive(self) -> Self {
        Self {
            decisive: true,
            ..self
        }
    }
}

fn is_load(op: &Op) -> bool {
    matches!(
        op,
        Op::Load { .. } | Op::AgentLoad { .. } | Op::CiLoad { .. }
    )
}

/// A world and the steps played in it.
struct Run {
    world: World<'static>,
    steps: usize,
}

/// What a step of a row did, as the world saw it: its outcome, or the
/// invariant the harness found it had broken.
struct Played(Result<Ran, String>);

impl Played {
    fn refused(&self) -> bool {
        matches!(self.0, Ok(Ran::Refused(_)))
    }

    fn accepted(&self) -> bool {
        matches!(self.0, Ok(Ran::Accepted))
    }

    /// The harness's own checks (revoked signers stay out, no reads after
    /// removal, a refused command leaves the vault alone, ...) held.
    fn invariants_hold(&self) -> bool {
        self.0.is_ok()
    }

    /// Why the step was refused, or what it broke.
    fn why(&self) -> &str {
        match &self.0 {
            Ok(Ran::Refused(why)) | Err(why) => why,
            Ok(Ran::Accepted) => "accepted",
        }
    }
}

impl Run {
    fn new() -> Self {
        Self {
            world: World::new(&FIXTURE),
            steps: 0,
        }
    }

    /// Play `op` as the next step, then check that nobody reads what they
    /// should not. `None`: the step did not apply, and did not run.
    fn play(&mut self, op: &Op) -> Option<Result<Ran, String>> {
        self.steps += 1;
        let result = self.world.step(self.world_step(), op);
        self.world.stats.count(kind(op), result.is_some());
        let result = result?;
        Some(result.and_then(|ran| self.world.check_all_reads().map(|()| ran)))
    }

    /// The world's step for the step last played (see [`SUBSTEPS`]).
    fn world_step(&self) -> usize {
        self.steps * SUBSTEPS
    }

    /// The world's step the next step will play at.
    fn next_world_step(&self) -> usize {
        (self.steps + 1) * SUBSTEPS
    }

    /// Everything this run ran and skipped.
    fn stats(&self) -> Stats {
        let mut open_examples: Vec<String> = self.world.open_hits.iter().take(6).cloned().collect();
        open_examples.truncate(6);
        Stats {
            forge_child_skips: self.world.forge_skips.get(),
            forge_refusals: self.world.forge_refusals.get(),
            judged: self.world.judged.borrow().clone(),
            open_hits: self.world.open_hits.len(),
            open_examples,
            ..self.world.stats.clone()
        }
    }

    /// A run for the random sequences. Its world starts after a revoke that
    /// only alice's machine has seen and a branch pushed to the remote, so even
    /// a short random history has a removal to judge and a ref to load. The
    /// seasoning steps are not counted.
    fn seasoned() -> Self {
        let mut run = Self::new();
        for op in [
            Op::Authorize { m: M(0), who: P(3) },
            Op::Revoke {
                m: M(0),
                who: Target::Person(P(3)),
            },
            Op::Push { m: M(0) },
            Op::Sync { m: M(0) },
        ] {
            run.play(&op)
                .unwrap_or_else(|| panic!("the seasoning step {op:?} did not run"))
                .unwrap_or_else(|e| panic!("the seasoning step {op:?} broke an invariant: {e}"));
        }
        run.world.stats = Stats::default();
        run.world.forge_skips.set(0);
        run.world.forge_refusals.set(0);
        run.world.judged.borrow_mut().clear();
        run.world.open_hits.clear();
        run
    }

    /// A row's setup: each step must run and meet its expectation, so a row
    /// cannot reach its decisive step through a broken scenario.
    fn setup(&mut self, steps: &[Scripted]) -> Result<(), String> {
        for s in steps {
            let step = self.steps + 1;
            let fail = |e: String| format!("step {step} {:?}: {e}", s.op);
            let ran = self
                .play(&s.op)
                .ok_or_else(|| fail("did not run: it could not be built here".into()))?
                .map_err(fail)?;
            match (s.expect, &ran) {
                (Expect::Accepts, Ran::Refused(why)) => {
                    return Err(fail(format!("expected it to be accepted, refused: {why}")));
                }
                (Expect::Refuses, Ran::Accepted) => {
                    return Err(fail("expected it to be refused, accepted".into()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// A step of a row that is neither setup nor decisive: it must run, and
    /// what it did is the row's to judge.
    fn attempt(&mut self, op: &Op) -> Result<Played, String> {
        let step = self.steps + 1;
        let result = self.play(op).ok_or_else(|| {
            format!("step {step} {op:?}: did not run: it could not be built here")
        })?;
        Ok(Played(result))
    }

    /// A row's decisive step: it must run. What it did is the row's to judge.
    fn decisive(&mut self, p: &mut Probe, op: &Op) -> Result<Played, String> {
        let played = self.attempt(op)?;
        p.reached();
        Ok(played)
    }
}

/// Run `ops`, checking the invariants after every step. With `script`, every
/// step must run and meet its expectation; without, a step that does not
/// apply is skipped, and what was skipped is counted. Returns the number of
/// decisive steps that ran.
fn run_sequence(ops: &[Op], script: Option<&[Scripted]>) -> Result<usize, TestCaseError> {
    let mut run = if script.is_some() {
        Run::new()
    } else {
        Run::seasoned()
    };
    let result = play_all(&mut run, ops, script);
    if script.is_none() {
        TOTALS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(Stats::default)
            .add(&run.stats());
    }
    result
}

fn play_all(
    run: &mut Run,
    ops: &[Op],
    script: Option<&[Scripted]>,
) -> Result<usize, TestCaseError> {
    let mut decisive_reached = 0;
    for (i, op) in ops.iter().enumerate() {
        let step = i + 1;
        let fail = |e: String| TestCaseError::fail(format!("step {step} {op:?}: {e}"));
        let expect = script.map(|s| s[i].expect);
        let Some(result) = run.play(op) else {
            if expect.is_some() {
                return Err(fail("did not run: it could not be built here".into()));
            }
            continue;
        };
        let ran = result.map_err(fail)?;
        // A decisive revoke is there for its cascade: it must have had a
        // grant to take with it, or the cascade check proved nothing.
        if script.is_some_and(|s| s[i].decisive)
            && matches!(op, Op::Revoke { .. })
            && run.world.last_cascade == 0
        {
            return Err(fail(
                "no grant trusted the revoked signer: nothing to cascade".into(),
            ));
        }
        match (expect, &ran) {
            (Some(Expect::Accepts), Ran::Refused(why)) => {
                return Err(fail(format!("expected it to be accepted, refused: {why}")));
            }
            (Some(Expect::Refuses), Ran::Accepted) => {
                return Err(fail("expected it to be refused, accepted".into()));
            }
            _ => {}
        }
        if script.is_some_and(|s| s[i].decisive) {
            decisive_reached += 1;
        }
    }
    if let Some(script) = script {
        let named = script.iter().filter(|s| s.decisive).count();
        if decisive_reached == 0 || decisive_reached < named {
            return Err(TestCaseError::fail(format!(
                "only {decisive_reached} of the {named} decisive steps ran"
            )));
        }
    }
    Ok(decisive_reached)
}

/// Run a stored sequence. Its decisive steps must run and meet their
/// expectations, and a load before the first of them must be accepted, so a
/// refusal there comes from the rule under test and not a broken setup.
/// Returns the number of decisive steps that ran.
fn run_scripted(script: &[Scripted]) -> Result<usize, TestCaseError> {
    let first = script
        .iter()
        .position(|s| s.decisive)
        .expect("a stored sequence names its decisive step");
    assert!(
        script
            .iter()
            .all(|s| !s.decisive || s.expect != Expect::Runs),
        "a decisive step expects an outcome"
    );
    assert!(
        script[..first]
            .iter()
            .any(|s| s.expect == Expect::Accepts && is_load(&s.op)),
        "a stored sequence loads an honest vault before its decisive step"
    );
    let ops: Vec<Op> = script.iter().map(|s| s.op.clone()).collect();
    run_sequence(&ops, Some(script))
}

/// Shrunk counterexamples found by this harness, and scenarios a fix must
/// keep, replayed before the random cases (like a fuzz corpus) so a
/// regression fails every run, not only the runs that happen to find it
/// again. Each is scripted: every step must run, and the decisive one must
/// end as expected.
fn known_sequences() -> Vec<(&'static str, Vec<Scripted>)> {
    let (alice, bob_m, carol_m, dave_m) = (M(0), M(2), M(3), M(4));
    let (bob, dave) = (P(1), P(3));
    let forge = |sign| Op::Forge {
        by: Attacker::Revoked,
        base: Base::NewestOpenable,
        generation: Gen::Next,
        sign,
        to: Dest::Main,
    };
    let load_tip = Op::Load {
        m: alice,
        at: At::OriginMain,
    };
    // Loaded on `main`, so the branch's rollback mark applies.
    let load_main = Op::Load {
        m: alice,
        at: At::Main,
    };
    let revoke_bob = Op::Revoke {
        m: alice,
        who: Target::Person(bob),
    };
    let forge_max = Op::Forge {
        by: Attacker::Person(bob),
        base: Base::NewestOpenable,
        generation: Gen::Max,
        sign: Sign::Own,
        to: Dest::Main,
    };
    // bob, a trusted member, writes the vault with murk 0.13.
    let legacy_by_bob = |to| Op::Forge {
        by: Attacker::Person(bob),
        base: Base::NewestOpenable,
        generation: Gen::Next,
        sign: Sign::Legacy,
        to,
    };
    let vouched = |key| {
        vec![
            accepts(Op::Vouch {
                m: bob_m,
                who: dave,
                key,
            }),
            accepts(Op::Sync { m: bob_m }),
            accepts(Op::Sync { m: alice }),
            runs(load_main.clone()),
            accepts(revoke_bob.clone()),
            accepts(load_main.clone()),
            runs(forge(Sign::AsPlanted(key))),
            refuses(load_tip.clone()).decisive(),
        ]
    };
    let older_revision = |at| {
        vec![
            accepts(revoke_bob.clone()),
            runs(Op::Load { m: alice, at }),
            accepts(load_main.clone()),
            runs(forge(Sign::Own)),
            refuses(load_tip.clone()).decisive(),
        ]
    };
    vec![
        (
            "a revoked member signs with a key they vouched for",
            vouched(Planted::Sock),
        ),
        (
            // No vault murk opens carries a weak key: alice refuses bob's
            // vouch, so she revokes him on the vault before it, and his
            // forgery plants the weak key again itself.
            "a revoked member signs under a weak key they vouched for",
            vec![
                accepts(Op::Vouch {
                    m: bob_m,
                    who: dave,
                    key: Planted::Weak,
                }),
                accepts(Op::Sync { m: bob_m }),
                accepts(revoke_bob.clone()),
                accepts(load_main.clone()),
                refuses(load_tip.clone()),
                runs(forge(Sign::Plants(Planted::Weak))),
                refuses(load_tip.clone()).decisive(),
            ],
        ),
        (
            "an older revision on a detached HEAD trusts a revoked member again",
            older_revision(At::Detached(1)),
        ),
        (
            "an older revision on a new branch trusts a revoked member again",
            older_revision(At::NewBranch(1)),
        ),
        (
            // The jump to the cap is refused. A reviewer who overrides that
            // with `murk trust` leaves this machine's mark at the cap, where
            // murk refuses to save: another vault forged at the cap, or an
            // older revision, is still refused.
            "a saturated generation lets a replayed revision through",
            vec![
                accepts(load_main.clone()),
                runs(forge_max.clone()),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
                accepts(Op::Trust {
                    m: alice,
                    forgery: true,
                }),
                accepts(load_main.clone()),
                runs(forge_max),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
                runs(Op::Replay {
                    rev: Old::Nth(3),
                    to: Dest::Main,
                }),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
            ],
        ),
        (
            // A save over a vault at the cap would be numbered above it, and
            // every machine would refuse the vault written. murk refuses the
            // save instead.
            "a save over a vault at the cap writes a vault nobody accepts",
            vec![
                accepts(Op::Load {
                    m: bob_m,
                    at: At::Main,
                }),
                runs(Op::Forge {
                    by: Attacker::Person(P(0)),
                    base: Base::Nth(0),
                    generation: Gen::Max,
                    sign: Sign::Plants(Planted::Sock),
                    to: Dest::Main,
                }),
                accepts(Op::Sync { m: bob_m }),
                refuses(Op::Vouch {
                    m: bob_m,
                    who: P(0),
                    key: Planted::Sock,
                })
                .decisive(),
            ],
        ),
        (
            // CI keeps no counter, so only the cap refuses there; on a
            // machine the jump bound refuses it too.
            "a generation above the cap is accepted",
            vec![
                accepts(load_main.clone()),
                accepts(Op::CiLoad { at: Ref::Main }),
                runs(Op::Forge {
                    by: Attacker::Person(bob),
                    base: Base::NewestOpenable,
                    generation: Gen::AboveCap,
                    sign: Sign::Own,
                    to: Dest::Main,
                }),
                refuses(Op::CiLoad { at: Ref::Main }).decisive(),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
            ],
        ),
        (
            "a save on an older revision writes a revoked member back",
            vec![
                accepts(revoke_bob.clone()),
                accepts(load_main.clone()),
                runs(load_tip.clone()),
                refuses(Op::Save {
                    m: alice,
                    key: K(1),
                })
                .decisive(),
            ],
        ),
        (
            "CI keeps trusting a signer dropped from its secret",
            vec![
                accepts(revoke_bob.clone()),
                accepts(Op::CiLoad { at: Ref::Main }),
                runs(Op::Forge {
                    by: Attacker::Revoked,
                    base: Base::NewestOpenable,
                    generation: Gen::Jump,
                    sign: Sign::Own,
                    to: Dest::Main,
                }),
                refuses(Op::CiLoad { at: Ref::Main }).decisive(),
            ],
        ),
        (
            // The decisive check is the revoke cascade in the vault (see
            // `check_cascade`). The agent's last load is refused because the
            // revoke deleted the key file in murk's default slot; a copy
            // handed off with `--out` would still accept the forgery until
            // its TTL ends, an accepted, documented limit left out here.
            "an agent grant keeps trusting a revoked member",
            vec![
                accepts(Op::Grant { m: alice }),
                accepts(Op::Sync { m: alice }),
                accepts(Op::AgentLoad { at: Ref::Main }),
                accepts(revoke_bob.clone()).decisive(),
                runs(Op::Forge {
                    by: Attacker::Revoked,
                    base: Base::NewestOpenable,
                    generation: Gen::Jump,
                    sign: Sign::Own,
                    to: Dest::Main,
                }),
                runs(Op::AgentLoad { at: Ref::Main }),
            ],
        ),
        (
            "loading an unmerged branch trusts the signer it adds on main",
            vec![
                // bob, a trusted signer, opens a pull request that adds dave
                // and vouches for a signing key as dave's.
                accepts(Op::Load {
                    m: bob_m,
                    at: At::NewBranch(0),
                }),
                accepts(Op::Vouch {
                    m: bob_m,
                    who: dave,
                    key: Planted::Sock,
                }),
                accepts(Op::Push { m: bob_m }),
                // alice checks it out to review it, then goes back to main.
                accepts(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                }),
                accepts(load_main.clone()),
                // The pull request is never merged; a vault signed as dave
                // lands on main.
                runs(Op::Forge {
                    by: Attacker::Person(bob),
                    base: Base::NewestOpenable,
                    generation: Gen::Next,
                    sign: Sign::AsPlanted(Planted::Sock),
                    to: Dest::Main,
                }),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
            ],
        ),
        (
            // Until the removal merges, bob is still a member of main: alice
            // can read it. Once it merges, every machine that accepted the
            // merged main refuses a vault bob signs there, and a save on main
            // cannot keep him. Bob's forgery claims a generation newer than
            // the removal, so only the removal refuses it.
            "a removal saved on a feature branch locks this machine out of main",
            vec![
                accepts(Op::Load {
                    m: alice,
                    at: At::NewBranch(0),
                }),
                accepts(revoke_bob.clone()),
                accepts(Op::Push { m: alice }),
                accepts(load_main.clone()).decisive(),
                // The removal merges into main.
                accepts(Op::MergeBranch {
                    m: alice,
                    branch: 0,
                    take_theirs: false,
                }),
                accepts(Op::Sync { m: alice }),
                accepts(load_main.clone()),
                accepts(Op::Sync { m: carol_m }),
                accepts(Op::Load {
                    m: carol_m,
                    at: At::Main,
                }),
                runs(Op::Forge {
                    by: Attacker::Revoked,
                    base: Base::NewestOpenable,
                    generation: Gen::Jump,
                    sign: Sign::Own,
                    to: Dest::Main,
                }),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
                refuses(Op::Save {
                    m: alice,
                    key: K(1),
                })
                .decisive(),
                accepts(Op::Sync { m: carol_m }),
                refuses(Op::Load {
                    m: carol_m,
                    at: At::Main,
                })
                .decisive(),
            ],
        ),
        (
            // A vault signed by a key this machine removed is refused on
            // every branch from the moment of the removal, even on a main
            // the removal has not reached; merging the removal then leaves a
            // main alice can read.
            "a removed member signs on main before the removal merges",
            vec![
                accepts(Op::Load {
                    m: alice,
                    at: At::NewBranch(0),
                }),
                accepts(revoke_bob.clone()),
                accepts(Op::Push { m: alice }),
                accepts(load_main.clone()),
                runs(forge(Sign::Own)),
                accepts(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
                accepts(Op::MergeBranch {
                    m: alice,
                    branch: 0,
                    take_theirs: true,
                }),
                accepts(load_main.clone()).decisive(),
            ],
        ),
        (
            // Worktrees share one pin, so one branch's 0.14 save must not
            // make every branch refuse its 0.13 vault. A 0.13 file of this
            // vault a member wrote loads as history on a branch this machine
            // has no 0.14 mark for, and is refused on main, which has one.
            "a replayed 0.13 vault is history on a new branch and refused on an upgraded one",
            vec![
                accepts(load_main.clone()),
                runs(legacy_by_bob(Dest::Branch)),
                accepts(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                })
                .decisive(),
                accepts(load_main.clone()),
                runs(legacy_by_bob(Dest::Main)),
                runs(Op::Sync { m: alice }),
                refuses(load_main.clone()).decisive(),
            ],
        ),
        (
            // Accepting an older 0.13 copy on a branch with no 0.14 mark
            // only makes that copy writable there: dave, authorized in 0.14
            // after the copy was written, stays a member, and his signed
            // vault on main still loads once his key is confirmed.
            "accepting an older 0.13 copy keeps a member it predates",
            vec![
                accepts(load_main.clone()),
                accepts(Op::Authorize {
                    m: alice,
                    who: dave,
                }),
                accepts(Op::Sync { m: alice }),
                runs(Op::Forge {
                    by: Attacker::Person(P(0)),
                    base: Base::Nth(1),
                    generation: Gen::Next,
                    sign: Sign::Legacy,
                    to: Dest::Branch,
                }),
                accepts(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                }),
                accepts(Op::Trust {
                    m: alice,
                    forgery: true,
                }),
                accepts(Op::Sync { m: dave_m }),
                accepts(Op::Trust {
                    m: dave_m,
                    forgery: false,
                }),
                accepts(Op::Save {
                    m: dave_m,
                    key: K(2),
                }),
                accepts(Op::Sync { m: dave_m }),
                accepts(Op::Sync { m: alice }),
                accepts(Op::Trust {
                    m: alice,
                    forgery: false,
                })
                .decisive(),
                accepts(load_main.clone()).decisive(),
            ],
        ),
        (
            // A 0.13 file that loaded as history is read-only until this
            // machine accepts it: a save there is refused, and after `murk
            // trust` it goes through and upgrades the file.
            "a write over an unaccepted 0.13 history load",
            vec![
                accepts(load_main.clone()),
                runs(legacy_by_bob(Dest::Branch)),
                accepts(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                }),
                refuses(Op::Save {
                    m: alice,
                    key: K(1),
                })
                .decisive(),
                accepts(Op::Trust {
                    m: alice,
                    forgery: true,
                }),
                accepts(Op::Save {
                    m: alice,
                    key: K(1),
                })
                .decisive(),
            ],
        ),
        (
            // Read as history, a 0.13 vault still meets every other rule: one
            // signed by a member this machine removed is refused on a branch
            // it has never seen.
            "a removed member's 0.13 vault on a new branch",
            vec![
                accepts(revoke_bob.clone()),
                accepts(load_main.clone()),
                runs(Op::Forge {
                    by: Attacker::Revoked,
                    base: Base::NewestOpenable,
                    generation: Gen::Next,
                    sign: Sign::Legacy,
                    to: Dest::Branch,
                }),
                refuses(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                })
                .decisive(),
            ],
        ),
        (
            // Another vault's 0.13 file, signed by a trusted member: its first
            // save would take another id, so it is another vault even on a
            // branch with no 0.14 mark.
            "another vault's 0.13 file on a new branch",
            vec![
                accepts(load_main.clone()),
                runs(Op::Forge {
                    by: Attacker::Person(bob),
                    base: Base::NewestOpenable,
                    generation: Gen::Next,
                    sign: Sign::LegacyOther,
                    to: Dest::Branch,
                }),
                refuses(Op::Load {
                    m: alice,
                    at: At::PushedBranch(0),
                })
                .decisive(),
            ],
        ),
        (
            // bob's machine reads the pushed branch that removes dave on a
            // detached HEAD: history, so its pin records no removal (and it
            // never trusted dave). main then takes the removal and a replay of
            // a revision that lists dave. bob's machine pulls that while it
            // tries to authorize again the member carol's machine removed
            // (refused: still listed there). Its save on main may list dave:
            // no record of his removal stands on that machine.
            "a removal read only as history leaves no record to save against",
            vec![
                accepts(Op::Authorize {
                    m: alice,
                    who: dave,
                }),
                accepts(Op::Revoke {
                    m: alice,
                    who: Target::Person(dave),
                }),
                accepts(Op::Push { m: alice }),
                accepts(Op::Sync { m: alice }),
                accepts(Op::Load {
                    m: bob_m,
                    at: At::Pushed(0),
                }),
                accepts(Op::Revoke {
                    m: carol_m,
                    who: Target::OtherMember(0),
                }),
                accepts(Op::MergeBranch {
                    m: alice,
                    branch: 0,
                    take_theirs: false,
                }),
                accepts(Op::Replay {
                    rev: Old::Nth(6),
                    to: Dest::Main,
                }),
                runs(Op::AuthorizeAgain {
                    m: carol_m,
                    by: alice,
                }),
                accepts(Op::Save {
                    m: bob_m,
                    key: K(0),
                })
                .decisive(),
            ],
        ),
        // R-I10-h:pr-flow: bob revokes carol on a topic branch; it merges
        // into main and a stale fork is committed there before bob's
        // machine loads main. main's history holds the removal: refused.
        (
            "a pull-request removal holds against a stale fork committed on main",
            vec![
                accepts(Op::Load {
                    m: bob_m,
                    at: At::Main,
                }),
                refuses(Op::PrFlow { m: bob_m, n: 0 }).decisive(),
            ],
        ),
        // R-I10-h:branch-current: bob's machine saved ahead on a feature
        // branch, then loads main's revoke of carol below its highest
        // counter; it still records the removal, so the stale fork later
        // committed on main is refused.
        (
            "a removal loaded as main's next state below the machine's counter holds",
            vec![
                accepts(Op::Load {
                    m: bob_m,
                    at: At::Main,
                }),
                refuses(Op::BranchCurrent { m: bob_m, n: 0 }).decisive(),
            ],
        ),
    ]
}

/// How many forgeries a run must have drawn before skipping every one of them
/// fails it. A short run (the default eight cases) may draw few, and every one
/// may fail to apply by chance; a soak with hundreds cannot.
const FORGERIES_TO_JUDGE: usize = 20;

/// The longest random sequence.
const MAX_STEPS: usize = 24;

/// A run of at least this many cases is big enough for the oracle floors. At
/// the default eight, how often an oracle judges a case varies too much with
/// the draw to demand a number.
const FLOOR_FROM_CASES: u32 = 20;

/// The stats kind of a re-add that the vault lists: the machine that
/// recorded the removal consents and then accepts the vault.
const DECISIVE_READD: &str = "re-add:decisive";
/// From this many random cases, at least one must reach [`DECISIVE_READD`]
/// (the `AuthorizeAgain` step builds it).
const DECISIVE_READD_FROM_CASES: u32 = 64;

/// The stats kind of a pull-request removal that ran in full: the machine
/// that revoked on a topic branch holds the record and refuses the stale
/// fork committed on `main` after the fast-forward (see [`Op::PrFlow`]).
const PR_FLOW_DECISIVE: &str = "pr-flow:decisive";
/// The stats kind of a removal loaded as its branch's next state below the
/// machine's highest counter, then held against a stale fork on that branch
/// (see [`Op::BranchCurrent`]).
const BRANCH_CURRENT_DECISIVE: &str = "branch-current:decisive";
/// The fewest of each composite removal shape per random case, in a run of
/// [`FLOOR_FROM_CASES`] cases or more: about a third of the rate a
/// twenty-case run reached (pr-flow 4, branch-current 3).
const DECISIVE_FLOORS: [(&str, f64); 2] =
    [(PR_FLOW_DECISIVE, 0.05), (BRANCH_CURRENT_DECISIVE, 0.05)];

/// The world clock advances this much per step, so the parts of a
/// composite step ([`Op::PrFlow`], [`Op::BranchCurrent`]) each have their
/// own step, in order, before the next step's.
const SUBSTEPS: usize = 16;

/// The fewest cases per random case each oracle must have judged where it
/// could fail (see [`Stats::judged`]), in a run of [`FLOOR_FROM_CASES`] cases
/// or more. Each is about a quarter of the rate three forty-case runs reached
/// (value lineage 14 to 20 judged cases in 40, readers 21 to 37, a runner's
/// pin 16 to 22, a machine's removal rules 63 to 82, no-reads about 2800), so
/// a count below one means an oracle stopped judging, not a short draw: at
/// twenty cases, which has the least headroom, a healthy count falls that low
/// well under once in a hundred runs. The rarer ones (a CI runner's removal
/// rules, the grant cascade) are printed and not floored.
const FLOORS: [(&str, f64); 5] = [
    ("revoked-signer:machine", 0.5),
    ("value-lineage", 0.1),
    ("readers", 0.2),
    ("no-reads", 15.0),
    ("pin-bytes", 0.12),
];

fn cases() -> u32 {
    std::env::var("MURK_TRUST_CASES")
        .ok()
        .map(|n| n.parse().expect("MURK_TRUST_CASES must be a number"))
        .unwrap_or(8)
}

/// The seed of the random sequences: `MURK_TRUST_SEED` (or proptest's
/// `PROPTEST_RNG_SEED`) replays a run; without one, a fresh seed is made and
/// printed so that a failure can be replayed.
fn seed() -> u64 {
    std::env::var("MURK_TRUST_SEED")
        .or_else(|_| std::env::var("PROPTEST_RNG_SEED"))
        .ok()
        .map(|s| s.parse().expect("the seed must be a number"))
        .unwrap_or_else(|| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            nanos ^ (u64::from(std::process::id()) << 32)
        })
}

#[test]
fn trust_invariants_hold_across_machines() {
    let seed = seed();
    let config = Config {
        cases: cases(),
        // Shrunk counterexamples are reported in the failure; don't write
        // regression files into the source tree.
        failure_persistence: None,
        // A case is slow (git and murk processes per step), but a shrunk
        // sequence is what makes a failure readable.
        max_shrink_iters: 512,
        rng_seed: RngSeed::Fixed(seed),
        ..Config::default()
    };
    // Build the fixture outside the runner so a setup failure reads as one.
    std::sync::LazyLock::force(&FIXTURE);
    let failures: Vec<String> = known_sequences()
        .into_iter()
        .filter_map(|(name, script)| {
            let result = run_scripted(&script);
            println!("known sequence: {name}: decisive steps that ran: {result:?}");
            result
                .err()
                .map(|e| format!("{name}:\n  {script:?}\n  {e}"))
        })
        .collect();
    println!(
        "random sequences: seed {seed} (replay with MURK_TRUST_SEED={seed}), {} cases of up to \
         {MAX_STEPS} steps, each from a world with a revoke only alice's machine has seen and a \
         pushed branch",
        cases()
    );
    for constructor in &CONSTRUCTORS {
        println!(
            "constructor {}: {}",
            constructor.name,
            if constructor.open() {
                "drawn".to_string()
            } else {
                format!(
                    "gated off until {} are enforced",
                    constructor.waiting_for().join(", ")
                )
            }
        );
    }
    let mut runner = TestRunner::new(config);
    let result = runner.run(&proptest::collection::vec(op(), 1..=MAX_STEPS), |ops| {
        run_sequence(&ops, None).map(|_| ())
    });
    let totals = TOTALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap_or_default();
    println!("random sequences: {}", totals.report());
    let mut report = failures;
    if let Err(e) = result {
        report.push(format!("random sequences (seed {seed}): {e}"));
    }
    let forgeries = totals.ran_of("forge") + totals.skipped_of("forge");
    if forgeries >= FORGERIES_TO_JUDGE && totals.ran_of("forge") == 0 {
        report.push(format!(
            "every one of the {forgeries} forgeries in the random sequences was skipped, so \
             none of them attacked anything: {}",
            totals.report()
        ));
    }
    // The random runs must reach a re-add that the vault lists: consent on
    // a machine that recorded the removal, then the vault accepted there.
    if cases() >= DECISIVE_READD_FROM_CASES && totals.ran_of(DECISIVE_READD) == 0 {
        report.push(format!(
            "no random case reached a re-add of a person the vault lists again in {} cases \
             (seed {seed}): the re-add oracle path is no longer exercised\n{}",
            cases(),
            totals.report()
        ));
    }
    if cases() >= FLOOR_FROM_CASES {
        for (shape, per_case) in DECISIVE_FLOORS {
            let floor = (per_case * f64::from(cases())).ceil() as usize;
            if totals.ran_of(shape) < floor {
                report.push(format!(
                    "{shape} ran {} times in {} random cases (seed {seed}), below the floor of \
                     {floor}: the generator no longer reaches that removal shape\n{}",
                    totals.ran_of(shape),
                    cases(),
                    totals.report()
                ));
            }
        }
    }
    if cases() >= FLOOR_FROM_CASES {
        for (oracle, per_case) in FLOORS {
            let floor = (per_case * f64::from(cases())).ceil() as usize;
            if totals.judged_of(oracle) < floor {
                report.push(format!(
                    "the {oracle} oracle judged {} cases where it could fail in {} random cases \
                     (seed {seed}), below the floor of {floor}: it is no longer reaching its \
                     decisive loads\n{}",
                    totals.judged_of(oracle),
                    cases(),
                    totals.report()
                ));
            }
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n\n"));
}

// ── Rows ──
//
// Each row below is one scenario of `tests/invariant_rows.tsv`, run through
// `common::rows::check`. Its setup steps and controls go through `require`
// (a failure there is a broken scenario, not a verdict on murk), the decisive
// step calls `reached`, and what murk must do once fixed is a `target`. A row
// that murk breaks today also records the violation as `today` checks.

fn load_main(m: M) -> Op {
    Op::Load { m, at: At::Main }
}

fn load_tip(m: M) -> Op {
    Op::Load {
        m,
        at: At::OriginMain,
    }
}

/// Each of `machines` pulls main, then loads it.
fn catch_up(machines: &[M]) -> Vec<Scripted> {
    machines
        .iter()
        .flat_map(|&m| [accepts(Op::Sync { m }), accepts(load_main(m))])
        .collect()
}

/// The generation `mach`'s pin holds for `branch`.
fn pin_mark(mach: &Machine, branch: &str) -> Option<u64> {
    pin_of(mach, false)?["branches"][branch].as_u64()
}

/// The highest generation `mach`'s pin has accepted.
fn pin_generation(mach: &Machine) -> u64 {
    pin_of(mach, false)
        .and_then(|pin| pin["generation"].as_u64())
        .unwrap_or(0)
}

/// The members `mach`'s pin records for `group`.
fn pin_group(mach: &Machine, group: &str) -> BTreeSet<String> {
    pin_of(mach, false)
        .and_then(|pin| pin["groups"][group].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|member| member.as_str().map(str::to_string))
        .collect()
}

/// A value that a load's `export --json` printed.
fn value_of(printed: &Printed, key: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&printed.stdout).ok()?[key]
        .as_str()
        .map(str::to_string)
}

/// The values a load's `export --json` printed.
fn values_of(printed: &Printed) -> BTreeMap<String, String> {
    serde_json::from_str::<serde_json::Value>(&printed.stdout)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .map(|o| {
            o.into_iter()
                .filter_map(|(k, v)| Some((k, v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// A pinned machine refuses a vault signed by a writer who enrolled their own
/// signing key. bob adds dave, and dave saves with a key of his own, but alice
/// never accepted a vault that lists dave. A CI runner whose secret names
/// dave's key reads the very same vault, so the refusal is the pin's.
#[test]
fn row_r_i1_a() {
    common::rows::check("R-I1-a", |p| {
        let (alice, bob_m, dave_m) = (M(0), M(2), M(4));
        let mut run = Run::new();
        run.setup(&[
            // An honest vault loads first.
            accepts(load_main(alice)),
            accepts(Op::Authorize {
                m: bob_m,
                who: P(3),
            }),
            accepts(Op::Sync { m: bob_m }),
            accepts(Op::Sync { m: dave_m }),
            accepts(Op::Trust {
                m: dave_m,
                forgery: false,
            }),
            // dave's first write enrolls his signing key in the vault.
            accepts(Op::Save {
                m: dave_m,
                key: K(1),
            }),
            accepts(Op::Sync { m: dave_m }),
            accepts(Op::Sync { m: alice }),
            // The writer's key is in the runner's MURK_TRUSTED_SIGNERS: it
            // reads the vault alice refuses below.
            accepts(Op::CiLoad { at: Ref::Main }),
        ])?;
        let poison = run
            .world
            .last_load
            .as_ref()
            .and_then(|printed| value_of(printed, "K2"))
            .ok_or("the runner reads the value dave saved")?;
        let out = run.decisive(p, &load_main(alice))?;
        let printed = run.world.last_load.clone().unwrap_or_default();
        p.target(
            out.refused(),
            format!(
                "alice refuses a vault signed by a key she never accepted: {}",
                out.why()
            ),
        );
        p.target(
            !printed.stdout.contains(&poison),
            "the value dave saved is absent from what alice's load printed",
        );
        p.target(out.invariants_hold(), "the harness's own checks hold");
        p.note(printed.stderr);
        Ok(())
    });
}

/// Stored sequence: a re-add needs this machine's own consent. carol's
/// machine accepts bob's removal. alice authorizes bob again and pushes.
/// carol's next load is refused and points at `--re-add`. After `murk trust
/// --re-add` on carol's machine, the load is accepted and carol's own save
/// lists bob.
#[test]
fn row_r_i10_h_soak() {
    common::rows::check("R-I10-h:soak", |p| {
        let (alice, carol) = (M(0), M(3));
        let bob = P(1);
        let mut run = Run::new();
        run.setup(&[
            accepts(load_main(carol)),
            accepts(Op::Revoke {
                m: alice,
                who: Target::Person(bob),
            }),
            accepts(Op::Sync { m: alice }),
            accepts(Op::Sync { m: carol }),
            accepts(load_main(carol)),
            accepts(Op::Authorize { m: alice, who: bob }),
            accepts(Op::Sync { m: alice }),
            accepts(Op::Sync { m: carol }),
        ])?;
        let refused = run.decisive(p, &load_main(carol))?;
        p.target(
            refused.refused(),
            format!("carol's load is refused: {}", refused.why()),
        );
        p.target(
            refused.why().contains("bob") && refused.why().contains("--re-add"),
            "the refusal names bob and --re-add",
        );
        let steps = [
            accepts(Op::ReAdd { m: carol, who: bob }),
            accepts(load_main(carol)),
            accepts(Op::Save {
                m: carol,
                key: K(0),
            }),
        ];
        let after = run.setup(&steps);
        p.target(
            after.is_ok(),
            format!("carol re-adds bob, loads and saves: {after:?}"),
        );
        let listed = run
            .world
            .listed(&run.world.machine(carol.0).vault())
            .contains(&bob.0);
        p.target(listed, "carol's save lists bob");
        Ok(())
    });
}

/// A registry entry a removed member vouched for stops counting once the
/// voucher is removed. bob vouches a signing key as dave's; while bob is
/// trusted, a vault signed as dave under that key loads. alice removes bob,
/// and a vault bob writes after that, signed as dave under the same key and a
/// thousand generations on (so the removal's generation does not refuse it),
/// does not: only the key decides.
#[test]
fn row_r_i2_a() {
    common::rows::check("R-I2-a", |p| {
        let (alice, bob_m) = (M(0), M(2));
        let (bob, dave) = (P(1), P(3));
        let key = Planted::Sock;
        let signed_as_dave = |by, generation| Op::Forge {
            by,
            base: Base::NewestOpenable,
            generation,
            sign: Sign::AsPlanted(key),
            to: Dest::Main,
        };
        let mut run = Run::new();
        run.setup(&[
            accepts(Op::Vouch {
                m: bob_m,
                who: dave,
                key,
            }),
            accepts(Op::Sync { m: bob_m }),
            accepts(Op::Sync { m: alice }),
            // alice pins the vouched key, on bob's word.
            accepts(load_main(alice)),
            // Control: while bob is trusted, the vouched key counts.
            runs(signed_as_dave(Attacker::Person(bob), Gen::Next)),
            accepts(load_tip(alice)),
            accepts(load_main(alice)),
            accepts(Op::Revoke {
                m: alice,
                who: Target::Person(bob),
            }),
            accepts(load_main(alice)),
            runs(signed_as_dave(Attacker::Revoked, Gen::Jump)),
        ])?;
        let out = run.decisive(p, &load_tip(alice))?;
        p.target(
            out.refused(),
            format!(
                "a vault signed under a key only a removed member vouched for is refused: {}",
                out.why()
            ),
        );
        p.target(out.invariants_hold(), "the harness's own checks hold");
        Ok(())
    });
}

/// A non-member adding themselves to a group is refused on every other
/// machine. alice makes `ops` and adds bob (a member's change, which every
/// machine accepts); carol, who is not in `ops`, writes a vault that lists her
/// as a member and pushes it. alice's two machines and bob's refuse it and
/// keep carol out of the group they record.
#[test]
fn row_r_i19_a() {
    common::rows::check("R-I19-a", |p| {
        let (alice, alice_2, bob_m) = (M(0), M(1), M(2));
        let (bob, carol) = (P(1), P(2));
        let mut setup = vec![
            accepts(Op::Group {
                m: alice,
                act: GroupAct::Create("ops"),
            }),
            accepts(Op::Sync { m: alice }),
        ];
        setup.extend(catch_up(&[alice_2, bob_m]));
        // Control: a member's change is accepted on every machine.
        setup.push(accepts(Op::Group {
            m: alice,
            act: GroupAct::Add("ops", bob),
        }));
        setup.push(accepts(Op::Sync { m: alice }));
        setup.extend(catch_up(&[alice_2, bob_m]));
        setup.push(runs(Op::Join {
            by: carol,
            group: "ops",
            to: Dest::Main,
        }));
        setup.extend([alice, alice_2, bob_m].map(|m| accepts(Op::Sync { m })));
        let mut run = Run::new();
        run.setup(&setup)?;
        let carol_key = run.world.fx.people[carol.0].pubkey.clone();
        let first = run.decisive(p, &load_main(alice))?;
        let second = run.attempt(&load_main(alice_2))?;
        let third = run.attempt(&load_main(bob_m))?;
        for (name, i, out) in [
            ("alice-1", 0, first),
            ("alice-2", 1, second),
            ("bob-1", 2, third),
        ] {
            p.target(
                out.refused(),
                format!(
                    "{name} refuses a group change by a non-member: {}",
                    out.why()
                ),
            );
            p.target(
                !pin_group(&run.world.machine(i), "ops").contains(&carol_key),
                format!("{name}'s pin does not list carol in `ops`"),
            );
            p.target(
                out.invariants_hold(),
                format!("the harness's own checks hold on {name}"),
            );
        }
        Ok(())
    });
}

/// A non-member who re-creates a group a member deleted, with themselves in
/// it, is refused by machines that saw the deletion. alice, a member, deletes
/// `ops` and `dev` (which every machine accepts); alice re-creates `dev`
/// (accepted: she was a member), and carol, who never was, creates `ops` with
/// herself. The pin forgets a deleted group, so today every machine accepts
/// carol's. (A non-member cannot delete a group that has members: the CLI
/// refuses it, and a vault that did would be refused on load.)
#[test]
fn row_r_i19_b() {
    common::rows::check("R-I19-b", |p| {
        let (alice, alice_2, bob_m, carol_m) = (M(0), M(1), M(2), M(3));
        let bob = P(1);
        let mut setup = vec![];
        for group in ["ops", "dev"] {
            setup.push(accepts(Op::Group {
                m: alice,
                act: GroupAct::Create(group),
            }));
            setup.push(accepts(Op::Group {
                m: alice,
                act: GroupAct::Add(group, bob),
            }));
        }
        setup.push(accepts(Op::Sync { m: alice }));
        setup.extend(catch_up(&[alice_2, bob_m]));
        // Control: a non-member cannot delete a group that has members (the
        // CLI refuses, and a vault that did it is refused on load), so the way
        // in is to re-create a group after a member deleted it.
        setup.extend(catch_up(&[carol_m]));
        setup.push(refuses(Op::Group {
            m: carol_m,
            act: GroupAct::Delete("ops"),
        }));
        // A member deletes both: every machine accepts, and records it.
        for group in ["ops", "dev"] {
            setup.push(accepts(Op::Group {
                m: alice,
                act: GroupAct::Delete(group),
            }));
        }
        setup.push(accepts(Op::Sync { m: alice }));
        setup.extend(catch_up(&[alice_2, bob_m]));
        // Control: alice, who was a member, re-creates `dev`.
        setup.push(accepts(Op::Group {
            m: alice,
            act: GroupAct::Create("dev"),
        }));
        setup.push(accepts(Op::Sync { m: alice }));
        setup.extend(catch_up(&[alice_2, bob_m]));
        let mut run = Run::new();
        run.setup(&setup)?;
        // A machine that never saw `ops` has nothing to compare with: it
        // accepts carol's group below as a new one (a stated residual). It
        // knows `dev`, so the group alice made does not stand in its way.
        let erin = run.world.erin();
        erin.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        let seen = export(&erin);
        p.require(
            seen.ok,
            format!(
                "a machine that never saw `ops` loads the vault: {}",
                seen.stderr
            ),
        )?;
        // The attack: carol, who never was, creates `ops` with herself.
        let mut attack = vec![
            accepts(Op::Sync { m: carol_m }),
            accepts(Op::Group {
                m: carol_m,
                act: GroupAct::Create("ops"),
            }),
            accepts(Op::Sync { m: carol_m }),
        ];
        attack.extend([alice, alice_2, bob_m].map(|m| accepts(Op::Sync { m })));
        run.setup(&attack)?;
        let carol_key = run.world.fx.people[P(2).0].pubkey.clone();
        let first = run.decisive(p, &load_main(alice))?;
        let second = run.attempt(&load_main(alice_2))?;
        let third = run.attempt(&load_main(bob_m))?;
        erin.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        let residual = export(&erin);
        p.require(
            residual.ok,
            format!(
                "a machine that never saw `ops` accepts carol's: {}",
                residual.stderr
            ),
        )?;
        for (name, i, out) in [
            ("alice-1", 0, &first),
            ("alice-2", 1, &second),
            ("bob-1", 2, &third),
        ] {
            let listed = pin_group(&run.world.machine(i), "ops").contains(&carol_key);
            p.target(
                out.refused(),
                format!(
                    "{name} refuses carol's `ops` as a group change by a non-member: {}",
                    out.why()
                ),
            );
            p.target(
                !listed,
                format!("{name}'s pin does not list carol in `ops`"),
            );
            p.today(out.accepted(), format!("{name} accepts carol's `ops`"));
            p.today(listed, format!("{name}'s pin lists carol in `ops`"));
        }
        Ok(())
    });
}

/// Stored merge sequences: two machines change the vault apart and one merges
/// the other's work, so the murk driver (not a fast-forward) produces a result.
/// The setup is everything before the merge; the observers load afterwards.
fn merge_sequences() -> Vec<(&'static str, Vec<Scripted>, Vec<Scripted>)> {
    let (alice, alice_2, bob_m, carol_m) = (M(0), M(1), M(2), M(3));
    vec![
        (
            "two members change different values",
            vec![
                accepts(Op::Save {
                    m: alice,
                    key: K(0),
                }),
                accepts(Op::Save {
                    m: bob_m,
                    key: K(1),
                }),
                accepts(Op::Sync { m: bob_m }),
            ],
            [
                vec![accepts(load_main(alice))],
                catch_up(&[alice_2, bob_m, carol_m]),
                vec![accepts(Op::CiLoad { at: Ref::Main })],
            ]
            .concat(),
        ),
        (
            "one member makes a group while another saves, with an agent grant in the vault",
            vec![
                accepts(Op::Grant { m: alice }),
                accepts(Op::Sync { m: alice }),
                accepts(Op::Sync { m: bob_m }),
                accepts(Op::Save {
                    m: alice,
                    key: K(0),
                }),
                accepts(Op::Group {
                    m: alice,
                    act: GroupAct::Create("ops"),
                }),
                accepts(Op::Save {
                    m: bob_m,
                    key: K(2),
                }),
                accepts(Op::Sync { m: bob_m }),
            ],
            [
                vec![accepts(load_main(alice))],
                catch_up(&[alice_2, bob_m, carol_m]),
                vec![
                    accepts(Op::CiLoad { at: Ref::Main }),
                    accepts(Op::AgentLoad { at: Ref::Main }),
                ],
            ]
            .concat(),
        ),
    ]
}

/// Consistency check, not a defence: the merging machine and every observer
/// (the other machines, CI and the agent) accept the result of the murk
/// driver as they would a direct save. Each stored merge sequence ran the
/// driver (its own stderr line, not git's text conflict), or the check proved
/// nothing.
#[test]
fn row_r_i12_a() {
    common::rows::check("R-I12-a", |p| {
        for (name, setup, observers) in merge_sequences() {
            let mut run = Run::new();
            run.setup(&setup)?;
            let before = run.world.driver_said;
            let merged = run.decisive(p, &Op::Sync { m: M(0) })?;
            p.require(
                run.world.driver_said > before,
                format!("{name}: the murk merge driver never ran"),
            )?;
            p.target(
                merged.accepted(),
                format!("{name}: the merge goes through: {}", merged.why()),
            );
            for step in observers {
                let out = run.attempt(&step.op)?;
                p.target(
                    out.accepted(),
                    format!(
                        "{name}: {:?} accepts the merge result as a direct save: {}",
                        step.op,
                        out.why()
                    ),
                );
            }
        }
        Ok(())
    });
}

/// erin saves `key` and commits it. Her key cannot sign, so the vault she
/// writes is unsigned, and the pin's record that the vault was signed goes
/// with it.
fn erin_saves(erin: &Machine, key: &str, value: &str) -> Printed {
    let out = erin
        .murk()
        .args(["add", key])
        .write_stdin(format!("{value}\n"))
        .output()
        .unwrap();
    let printed = Printed::of(&out);
    if printed.ok {
        erin.commit(&format!("erin saves {key}"));
    }
    printed
}

/// What person `who` reads for the shared `key` in a vault file, straight
/// through age, whether or not murk would load the file.
fn read_value(run: &Run, vault: &[u8], who: usize, key: &str) -> Option<String> {
    let path = run.world.root.join("read-value.murk");
    fs::write(&path, vault).unwrap();
    let person = &run.world.fx.people[who];
    cast::cells(&path, std::slice::from_ref(person))
        .get(&(key.to_string(), cast::Tier::Shared))?
        .get(&person.label)
        .cloned()
}

/// Whether `dave`, who is outside the team, can read `key` in `vault`.
fn dave_reads(run: &Run, vault: &[u8], key: &str) -> bool {
    read_value(run, vault, 3, key).is_some()
}

/// A pinned machine on a key that cannot sign refuses an unsigned same-id copy
/// of an older revision. erin loads a revision, then saves (unsigned, so the
/// pin forgets the vault was signed); the unsigned copy of the revision before
/// the one she loaded must not load, and its older value must not show.
#[test]
fn row_r_i6_b() {
    common::rows::check("R-I6-b", |p| {
        let mut run = Run::new();
        let erin = run.world.erin();
        let older = erin.vault();
        run.setup(&[
            accepts(Op::Save { m: M(0), key: K(0) }),
            accepts(Op::Sync { m: M(0) }),
        ])?;
        erin.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        let current = export(&erin);
        p.require(
            current.ok,
            format!("erin loads the newer signed revision: {}", current.stderr),
        )?;
        // The older revision still holds the value alice has since rotated.
        let stale = "init-K1";
        let rotated = value_of(&current, "K1").ok_or("erin reads K1")?;
        let replay = unsigned(&older);
        p.require(
            rotated != stale && generation(&replay) < generation(&erin.vault()),
            "the older revision holds an older K1 and a lower generation",
        )?;
        // Control: while the pin says the vault was signed, the unsigned copy
        // is refused as stripped.
        let stripped = load_file(&erin, &replay);
        p.require(
            !stripped.ok,
            format!("a signed pin refuses an unsigned copy: {}", stripped.stdout),
        )?;
        let saved = erin_saves(&erin, "ERIN_KEY", "erin-value");
        p.require(saved.ok, format!("erin saves: {}", saved.stderr))?;
        p.require(!has_sig(&erin.vault()), "erin's save is unsigned")?;
        let own = export(&erin);
        p.require(own.ok, format!("erin loads her own save: {}", own.stderr))?;
        p.reached();
        let attack = load_file(&erin, &replay);
        p.target(
            !attack.ok && !attack.stdout.contains(stale),
            format!(
                "the unsigned copy of an older revision is refused and its value absent: {}",
                attack.stderr
            ),
        );
        p.target(
            attack.stderr.contains("rolled back"),
            format!(
                "the refusal names the rollback, not another rule: {}",
                attack.stderr
            ),
        );
        p.note(attack.stderr);
        Ok(())
    });
}

/// A non-signing member's own unsigned save advances the branch mark, so a
/// replay of the previous signed file is refused as rolled back.
#[test]
fn row_r_i6_c() {
    common::rows::check("R-I6-c", |p| {
        let run = Run::new();
        let erin = run.world.erin();
        let previous = erin.vault();
        p.require(has_sig(&previous), "the team's vault is signed")?;
        let loaded = export(&erin);
        p.require(loaded.ok, format!("erin loads it: {}", loaded.stderr))?;
        let saved = erin_saves(&erin, "ERIN_KEY", "erin-value");
        p.require(saved.ok, format!("erin saves: {}", saved.stderr))?;
        let own = erin.vault();
        p.require(!has_sig(&own), "erin's save is unsigned")?;
        p.require(
            generation(&own) == generation(&previous) + 1,
            "erin's save is the next generation",
        )?;
        let again = export(&erin);
        p.require(again.ok, format!("erin loads her save: {}", again.stderr))?;
        let mark = pin_mark(&erin, "main");
        let replay = load_file(&erin, &previous);
        p.reached();
        p.target(
            mark == Some(generation(&own)),
            format!(
                "the own save advanced the mark of `main` to {} (it is {mark:?})",
                generation(&own)
            ),
        );
        p.target(
            !replay.ok && replay.stderr.contains("rolled back"),
            format!(
                "the previous signed file is refused as rolled back: {}",
                replay.stderr
            ),
        );
        Ok(())
    });
}

/// A pinned non-signing machine refuses an unsigned file with another vault
/// id. The same file signed (by a member erin trusts) is refused as another
/// vault, which is the id check; unsigned, the same check applies.
#[test]
fn row_r_i8_d() {
    common::rows::check("R-I8-d", |p| {
        let run = Run::new();
        let erin = run.world.erin();
        let saved = erin_saves(&erin, "ERIN_KEY", "erin-value");
        p.require(saved.ok, format!("erin saves: {}", saved.stderr))?;
        let other = run
            .world
            .built_vault("other", "alice", &[(&rsa_pubkey(), "erin")], "POISONED");
        p.require(
            vault_json(&other)["vault_id"] != vault_json(&erin.vault())["vault_id"],
            "the file belongs to another vault",
        )?;
        // Control: signed by a trusted member, it is refused by its id.
        let signed = load_file(&erin, &other);
        p.require(
            !signed.ok && signed.stderr.contains("different vault"),
            format!(
                "the signed file is refused as another vault: {}",
                signed.stderr
            ),
        )?;
        p.reached();
        let attack = load_file(&erin, &unsigned(&other));
        p.target(
            !attack.ok && !attack.stdout.contains("POISONED"),
            format!(
                "the unsigned file of another vault is refused: {}",
                attack.stderr
            ),
        );
        p.target(
            attack.stderr.contains("different vault"),
            format!(
                "the refusal names the vault id, not another rule: {}",
                attack.stderr
            ),
        );
        Ok(())
    });
}

/// An ssh-rsa person refuses a forged unsigned vault until `murk trust`, and
/// their next write does not happen. dave builds a vault of his own that lists
/// erin and strips its signature; erin on a fresh clone (no pin) must not load
/// it, nor write to dave's recipient list. An ed25519 member and a runner that
/// names its signers refuse the same file, and erin's own unsigned vault (made
/// by her `murk init`) loads.
#[test]
fn row_r_i21_a() {
    common::rows::check("R-I21-a", |p| {
        let run = Run::new();
        let w = &run.world;
        let bob_key = w.fx.people[1].pubkey.clone();
        let forged = unsigned(&w.built_vault(
            "forged",
            "dave",
            &[(&rsa_pubkey(), "erin"), (&bob_key, "bob")],
            "POISONED",
        ));
        let place = |m: &Machine| fs::write(m.dir.join(".murk"), &forged).unwrap();
        // Controls: a key that can sign, and a runner that names its signers.
        let ed = w.scratch("ed-victim", "bob");
        place(&ed);
        let by_ed = Printed::of(&ed.murk().args(["get", "DB"]).output().unwrap());
        p.require(
            !by_ed.ok && !by_ed.stdout.contains("POISONED"),
            format!("an ed25519 member refuses it: {}", by_ed.stderr),
        )?;
        let anchored = w.scratch("anchored-victim", "erin");
        place(&anchored);
        let by_runner = Printed::of(
            &anchored
                .murk()
                .env("MURK_TRUSTED_SIGNERS", signer_entry(&w.fx.people[0]))
                .args(["get", "DB"])
                .output()
                .unwrap(),
        );
        p.require(
            !by_runner.ok && !by_runner.stdout.contains("POISONED"),
            format!(
                "a runner that names its signers refuses it: {}",
                by_runner.stderr
            ),
        )?;
        // Control: erin's own vault, made by her own `murk init`, loads.
        let own = w.scratch("erin-own", "erin");
        own.murk()
            .arg("init")
            .write_stdin("erin\n")
            .assert()
            .success();
        own.murk()
            .args(["add", "DB"])
            .write_stdin("own\n")
            .assert()
            .success();
        let mine = Printed::of(&own.murk().args(["get", "DB"]).output().unwrap());
        p.require(
            mine.ok && mine.stdout.trim() == "own",
            format!("erin's own vault loads: {}", mine.stderr),
        )?;
        // Control: erin's pinned machine knows the vault was signed.
        let pinned = load_file(&w.erin(), &forged);
        p.require(!pinned.ok, "a pinned machine refuses the stripped file")?;
        let victim = w.scratch("victim", "erin");
        place(&victim);
        let read = Printed::of(&victim.murk().args(["get", "DB"]).output().unwrap());
        p.reached();
        p.target(
            !read.ok && !read.stdout.contains("POISONED"),
            format!(
                "an ssh-rsa key on a fresh clone refuses the unsigned vault: {}",
                read.stderr
            ),
        );
        let write = Printed::of(
            &victim
                .murk()
                .args(["add", "NEWSEC"])
                .write_stdin("victim-secret\n")
                .output()
                .unwrap(),
        );
        let leaked = dave_reads(&run, &victim.vault(), "NEWSEC");
        p.target(
            !write.ok && !leaked,
            format!("erin's next write does not happen: {}", write.stderr),
        );
        Ok(())
    });
}

/// A mixed team refuses an unsigned file with the pinned id, a counter three
/// above, and one extra recipient. erin saves once (unsigned), which is how the
/// pin forgets the vault was signed; the file then lists dave besides the team.
/// The same file without dave loads (a stated residual: the values of an
/// unsigned vault are not authenticated).
#[test]
fn row_r_i21_b() {
    common::rows::check("R-I21-b", |p| {
        let run = Run::new();
        let w = &run.world;
        let erin = w.erin();
        let (alice, dave) = (&w.fx.people[0], &w.fx.people[3]);
        let id = vault_json(&erin.vault())["vault_id"]
            .as_str()
            .ok_or("the vault has an id")?
            .to_string();
        let team = [(rsa_pubkey(), "erin")];
        let with_dave = w.built_vault(
            "extra",
            "alice",
            &[(&team[0].0, team[0].1), (&dave.pubkey, "dave")],
            "POISONED",
        );
        let without_dave = w.built_vault("same", "alice", &[(&team[0].0, team[0].1)], "POISONED");
        let forged =
            |base: &[u8]| unsigned(&retargeted(base, alice, &id, pin_generation(&erin) + 3));
        // Control: before erin's own save, the pin says the vault was signed,
        // and the file is refused as stripped.
        let stripped = load_file(&erin, &forged(&with_dave));
        p.require(
            !stripped.ok,
            format!(
                "a signed pin refuses the unsigned file: {}",
                stripped.stdout
            ),
        )?;
        let saved = erin_saves(&erin, "ERIN_KEY", "erin-value");
        p.require(saved.ok, format!("erin saves: {}", saved.stderr))?;
        // Control: the file without the extra recipient loads.
        let same = load_file(&erin, &forged(&without_dave));
        p.require(
            same.ok && same.stdout.contains("POISONED"),
            format!(
                "the file with the team's recipients only loads: {}",
                same.stderr
            ),
        )?;
        let attack = forged(&with_dave);
        let (read, write, after) = with_file(&erin, &attack, |m| {
            let read = export(m);
            p.reached();
            let write = erin_saves(m, "NEWSEC", "victim-secret");
            (read, write, m.vault())
        });
        p.target(
            !read.ok && !read.stdout.contains("POISONED"),
            format!(
                "the unsigned file with an extra recipient is refused: {}",
                read.stderr
            ),
        );
        p.target(
            !write.ok && !dave_reads(&run, &after, "NEWSEC"),
            "erin's next write does not happen",
        );
        Ok(())
    });
}

/// A non-signing member accepts a stripped vault that adds a recipient with
/// one `murk trust`, and murk records the whole decision: the vault then
/// loads, and an unsigned file that adds one more recipient is still refused.
#[test]
fn one_murk_trust_accepts_a_stripped_vault_for_a_key_that_cannot_sign() {
    let run = Run::new();
    let w = &run.world;
    let erin = w.erin();
    let (alice, carol, dave) = (&w.fx.people[0], &w.fx.people[2], &w.fx.people[3]);
    let id = vault_json(&erin.vault())["vault_id"]
        .as_str()
        .expect("the vault has an id")
        .to_string();
    let rsa = rsa_pubkey();
    let base = pin_generation(&erin);
    let forged = |name: &str, extra: &[(&str, &str)], generation: u64| {
        let mut recipients = vec![(rsa.as_str(), "erin")];
        recipients.extend_from_slice(extra);
        unsigned(&retargeted(
            &w.built_vault(name, "alice", &recipients, "REVIEWED"),
            alice,
            &id,
            generation,
        ))
    };
    let reviewed = forged("reviewed", &[(&dave.pubkey, "dave")], base + 1);
    let path = erin.dir.join(".murk");
    let kept = fs::read(&path).unwrap();
    fs::write(&path, &reviewed).unwrap();
    let before = export(&erin);
    assert!(
        !before.ok,
        "the stripped vault is refused before murk trust"
    );
    let trusted = Printed::of(&erin.murk().args(["trust", "--yes"]).output().unwrap());
    assert!(trusted.ok, "murk trust accepts it: {}", trusted.stderr);
    let after = export(&erin);
    assert!(
        after.ok && after.stdout.contains("REVIEWED"),
        "one murk trust is enough: {}",
        after.stderr
    );
    let widened = forged(
        "widened",
        &[(&dave.pubkey, "dave"), (&carol.pubkey, "carol")],
        base + 2,
    );
    let attack = load_file(&erin, &widened);
    assert!(
        !attack.ok && !attack.stdout.contains("REVIEWED"),
        "an unsigned file that adds another recipient is still refused: {}",
        attack.stderr
    );
    fs::write(&path, kept).unwrap();
}

/// erin's key cannot sign. A revision alice signed lists dave, whom erin's
/// machine never accepted, and loads on a detached HEAD as history. An
/// unsigned save over it would encrypt to dave with nothing that vouches for
/// him, and erin's machine would then refuse her own write. So the save is
/// refused and writes nothing.
#[test]
fn an_unsigned_save_never_carries_a_recipient_this_machine_did_not_accept() {
    let run = Run::new();
    let w = &run.world;
    let erin = w.erin();
    let (alice, dave) = (&w.fx.people[0], &w.fx.people[3]);
    let id = vault_json(&erin.vault())["vault_id"]
        .as_str()
        .expect("the vault has an id")
        .to_string();
    let rsa = rsa_pubkey();
    let listing = w.built_vault(
        "history",
        "alice",
        &[(rsa.as_str(), "erin"), (&dave.pubkey, "dave")],
        "HISTORY",
    );
    let history = retargeted(&listing, alice, &id, pin_generation(&erin) + 1);
    assert!(has_sig(&history), "alice signed the revision");
    fs::write(erin.dir.join(".murk"), &history).unwrap();
    erin.commit("a revision that lists dave");
    erin.git_ok(&["checkout", "-q", "--detach"]);
    let read = export(&erin);
    assert!(
        read.ok && read.stdout.contains("HISTORY"),
        "erin reads the revision as history: {}",
        read.stderr
    );
    let saved = erin_saves(&erin, "NEWSEC", "erin-secret");
    assert!(
        !saved.ok && saved.stderr.contains("nothing was written"),
        "the unsigned save is refused: {}",
        saved.stderr
    );
    assert_eq!(erin.vault(), history, "the vault file is unchanged");
    assert!(
        !dave_reads(&run, &erin.vault(), "NEWSEC"),
        "dave never gets erin's new value"
    );
}

/// The minimal input of a soak failure, played step by step: alice saves K2
/// and pushes, then code holding alice's key pushes an unsigned file that
/// also lists dave. dave reads K2 in that file because the key holder's own
/// code encrypted it to him, not through murk. alice's murk refuses to write
/// on top of it, so no honest save ever carries dave. A forgery is never
/// built on top of that file, so the next one, from a genuine revision, lists
/// no dave.
#[test]
fn an_unsigned_forgery_listing_dave_is_never_built_on() {
    let mut run = Run::new();
    run.setup(&[
        accepts(Op::Save { m: M(0), key: K(1) }),
        accepts(Op::Push { m: M(0) }),
        runs(Op::ForgeUnsigned {
            by: P(0),
            to: Dest::Main,
        }),
    ])
    .unwrap();
    let forged = run.world.origin_tip("main");
    assert!(!has_sig(&forged), "the forgery is unsigned");
    assert!(
        dave_reads(&run, &forged, "K2"),
        "the key holder's own code encrypted K2 to dave"
    );
    let alice = run.world.machine(0);
    let write = with_file(&alice, &forged, |m| {
        let out = Printed::of(
            &m.murk()
                .args(["add", "NEWSEC"])
                .write_stdin("alice-secret\n")
                .output()
                .unwrap(),
        );
        (out, m.vault())
    });
    assert!(
        !write.0.ok && write.1 == forged,
        "alice's murk refuses to write on the unsigned forgery: {}",
        write.0.stderr
    );
    let next = run
        .attempt(&Op::Forge {
            by: Attacker::Person(P(0)),
            base: Base::NewestOpenable,
            generation: Gen::Next,
            sign: Sign::Own,
            to: Dest::Main,
        })
        .unwrap();
    assert!(next.accepted(), "the forgery runs: {}", next.why());
    let tip = run.world.origin_tip("main");
    assert!(
        has_sig(&tip) && !dave_reads(&run, &tip, "K2"),
        "the signed forgery starts from a genuine revision, which does not list dave"
    );
}

// ── Rows that need lineage ──
//
// These assert the behaviour of a format 4 that does not exist yet (a vault
// that carries the entries of its ancestors, and a reference per branch in a
// sidecar next to the pin), using only the CLI, git and this file's helpers,
// so they compile today. A row that needs a format-4 vault checks the header
// before its decisive step, so that today it reports "did not reach" instead
// of passing without testing anything.

/// The value of K1 that the stale fork still holds and main has rotated away.
const LEAKED: &str = "init-K1";

/// What the stale-fork rows need of the world they build.
struct StaleFork {
    /// alice's genuine file at the end of a fork of six saves that never
    /// reached main. Its K1 is the leaked value, and its generation is above
    /// anything main reaches in the row.
    stale: Vec<u8>,
    /// The same fork one save in: its generation is below main's.
    behind: Vec<u8>,
    /// The commit on main that holds the rotation and the policy.
    parent: String,
    /// K1 as main has rotated it.
    rotated: String,
    /// The index of a teammate's genuine branch off `parent` in the world's
    /// pushed branches.
    teammate: usize,
}

/// A genuine stale fork. alice's second machine saves six times (K3) from the
/// shared revision and never syncs: a fork that keeps the leaked K1 and
/// reaches a higher generation than main will. Meanwhile main rotates K1, sets
/// a policy, and a teammate (bob) branches off that commit with a genuine save
/// of his own (K2); then main moves on (a group). The sides change different
/// things, so any conflict of a merge is about what the stale fork undoes.
fn stale_fork(run: &mut Run) -> Result<StaleFork, String> {
    let (alice, alice_2, bob_m) = (M(0), M(1), M(2));
    let (a1, a2) = (run.world.machine(0), run.world.machine(1));
    let mut behind = Vec::new();
    for i in 0..6 {
        run.setup(&[accepts(Op::Save {
            m: alice_2,
            key: K(2),
        })])?;
        if i == 0 {
            behind = a2.vault();
        }
    }
    let stale = a2.vault();
    run.setup(&[
        accepts(Op::Save {
            m: alice,
            key: K(0),
        }),
        accepts(Op::Policy { m: alice }),
        accepts(Op::Sync { m: alice }),
    ])?;
    let parent = head(&a1);
    run.setup(&[
        accepts(Op::Sync { m: bob_m }),
        accepts(Op::Save {
            m: bob_m,
            key: K(1),
        }),
        accepts(Op::Push { m: bob_m }),
    ])?;
    let teammate = run.world.branches.len() - 1;
    run.setup(&[accepts(Op::Group {
        m: alice,
        act: GroupAct::Create("ops"),
    })])?;
    let main = export(&a1);
    let rotated =
        value_of(&main, "K1").ok_or_else(|| format!("alice reads K1: {}", main.stderr))?;
    if rotated == LEAKED {
        return Err("main has not rotated K1".into());
    }
    Ok(StaleFork {
        stale,
        behind,
        parent,
        rotated,
        teammate,
    })
}

/// The control of both stale-fork rows: the teammate's genuine branch merges
/// into alice's main (the murk driver runs on it), and the result loads, so
/// a descendant of what alice accepted is accepted.
fn merge_teammate(run: &mut Run, fork: &StaleFork) -> Result<(), String> {
    let before = run.world.driver_said;
    run.setup(&[
        accepts(Op::MergeBranch {
            m: M(0),
            branch: fork.teammate,
            take_theirs: false,
        }),
        accepts(load_main(M(0))),
    ])?;
    if run.world.driver_said == before {
        return Err("the murk driver never merged the teammate's branch".into());
    }
    Ok(())
}

/// A genuine file from a stale fork, with a generation above main's, laid
/// over main is refused as not descending from what the machine accepted, and
/// the rotated value stays. Today it loads and the leaked value shows.
#[test]
fn row_r_l_load() {
    common::rows::check("R-L-load", |p| {
        let mut run = Run::new();
        let fork = stale_fork(&mut run)?;
        merge_teammate(&mut run, &fork)?;
        let alice1 = run.world.machine(0);
        // Control: the fork one save in is below main's generation, and the
        // same machine refuses it as rolled back.
        let behind = load_file(&alice1, &fork.behind);
        p.require(
            !behind.ok && behind.stderr.contains("rolled back"),
            format!(
                "the lower fork is refused as rolled back: {}",
                behind.stderr
            ),
        )?;
        p.require(
            generation(&fork.stale) > pin_generation(&alice1),
            "the stale fork's generation is above everything alice accepted",
        )?;
        // Controls for the value oracle: it flags the lower fork as older (so
        // it can fail), stays silent on what alice holds (a genuine
        // descendant of everything she accepted), and has found nothing so
        // far.
        p.require(
            run.world.would_flag(0, &fork.behind).is_some(),
            "the value oracle flags the lower fork as older than what alice accepted",
        )?;
        p.require(
            run.world.would_flag(0, &alice1.vault()).is_none() && run.world.open_hits.is_empty(),
            "the value oracle is silent on a genuine descendant",
        )?;
        let stale = load_file(&alice1, &fork.stale);
        p.reached();
        p.target(
            !stale.ok && stale.stderr.contains("descend"),
            format!(
                "the stale fork is refused as not descending: {}",
                stale.stderr
            ),
        );
        p.target(
            !stale.stdout.contains(LEAKED),
            "the leaked value is absent from what the load printed",
        );
        let rollback = if stale.ok {
            run.world.would_flag(0, &fork.stale)
        } else {
            None
        };
        p.target(
            rollback.is_none(),
            format!("the value oracle finds no older value accepted: {rollback:?}"),
        );
        let kept = Printed::of(&alice1.murk().args(["get", "K1"]).output().unwrap());
        p.target(
            kept.ok && kept.stdout.trim() == fork.rotated,
            format!("the rotated K1 is still read: {}", kept.stderr),
        );
        p.note(stale.stderr);
        Ok(())
    });
}

/// What a `git merge` left in the working vault, before it is undone.
struct MergeProbe {
    printed: Printed,
    working: Vec<u8>,
}

/// Merge `theirs` into `mach`'s checkout, look at the working vault, and put
/// the checkout back as it was.
fn merge_probe(mach: &Machine, theirs: &str) -> MergeProbe {
    mach.git_ok(&["fetch", "-q", "origin"]);
    let ours = head(mach);
    let out = mach.git(&["merge", "-q", "--no-edit", theirs]);
    let working = mach.vault();
    let _ = mach.git(&["merge", "--abort"]);
    mach.git_ok(&["reset", "-q", "--hard", &ours]);
    MergeProbe {
        printed: Printed::of(&out),
        working,
    }
}

/// A merge of a genuine stale-fork revision conflicts, and the rotated value
/// and the policy stay. The pull request's parent is a genuine commit of main
/// and its tip is the stale fork's file, so git's merge base is genuine too.
/// Today the driver merges them cleanly, the leaked K1 comes back and the
/// policy goes, all signed.
#[test]
fn row_r_l_merge() {
    common::rows::check("R-L-merge", |p| {
        let mut run = Run::new();
        let fork = stale_fork(&mut run)?;
        merge_teammate(&mut run, &fork)?;
        let alice1 = run.world.machine(0);
        let ours = alice1.vault();
        let step = run.next_world_step();
        let branch = run.world.push_branch_off(&fork.parent, &fork.stale, step);
        let probe = merge_probe(&alice1, &format!("origin/{branch}"));
        p.require(
            driver_said(probe.printed.stderr.as_bytes()),
            format!("the murk driver ran: {}", probe.printed.stderr),
        )?;
        p.reached();
        let key = read_value(&run, &probe.working, 0, "K1");
        let policy = vault_json(&probe.working)["policy"].clone();
        p.target(
            !probe.printed.ok
                && probe.printed.stderr.contains("secrets.K1")
                && probe.printed.stderr.contains("policy"),
            format!(
                "the merge conflicts on K1 and the policy: {}",
                probe.printed.stderr
            ),
        );
        p.target(
            key.as_deref() == Some(fork.rotated.as_str()),
            format!("K1 stays rotated (the file holds {key:?})"),
        );
        p.target(
            policy == vault_json(&ours)["policy"],
            "the policy stays as main has it",
        );
        p.target(!has_sig(&probe.working), "nothing was signed");
        let rollback = if probe.printed.ok {
            run.world.would_flag(0, &probe.working)
        } else {
            None
        };
        p.target(
            rollback.is_none(),
            format!("the value oracle finds no older value in the merge result: {rollback:?}"),
        );
        p.today(probe.printed.ok, "the driver merges it cleanly");
        p.today(
            key.as_deref() == Some(LEAKED),
            "the leaked K1 is back in the merged file",
        );
        p.today(has_sig(&probe.working), "the merged file is signed");
        Ok(())
    });
}

/// `n` saves on `mach` (one `murk add` each, values `tag-<i>`), not committed.
fn saves(mach: &Machine, key: &str, n: usize, tag: &str) -> Result<(), String> {
    for i in 0..n {
        let out = mach
            .murk()
            .args(["add", key])
            .write_stdin(format!("{tag}-{i}\n"))
            .output()
            .unwrap();
        if !out.status.success() {
            return Err(format!("save {i} on {}: {}", mach.name, stderr(&out)));
        }
    }
    Ok(())
}

/// The entries of a format-4 vault's `prev` (none for an older format).
fn prev_entries(bytes: &[u8]) -> Vec<String> {
    vault_json(bytes)["prev"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The generation of a `prev` entry (`<generation>:<fp>`).
fn entry_generation(entry: &str) -> u64 {
    entry
        .split(':')
        .next()
        .and_then(|generation| generation.parse().ok())
        .unwrap_or(0)
}

/// How far back a vault's lineage is checked. A teammate 256 saves ahead is
/// accepted by a machine whose reference is the revision they started from,
/// and one 257 saves ahead is refused as beyond the window. A lopsided merge
/// (ours 300 saves past the fork point, theirs 3) keeps both sides' own
/// entries, so a teammate whose reference is theirs' tip accepts the result,
/// and theirs' next save merges cleanly.
#[test]
fn row_r_l_window() {
    common::rows::check("R-L-window", |p| {
        const WINDOW: usize = 256;
        let bob_m = M(2);
        // The load arm.
        {
            let mut run = Run::new();
            let (alice1, alice2, bob) = (
                run.world.machine(0),
                run.world.machine(1),
                run.world.machine(2),
            );
            run.setup(&[accepts(Op::Save {
                m: bob_m,
                key: K(1),
            })])?;
            // A vault without `prev` has no window to measure.
            p.require(
                major(&bob.vault()) == 4,
                format!(
                    "this build writes format {}, which carries no lineage",
                    major(&bob.vault())
                ),
            )?;
            saves(&bob, "K2", WINDOW - 1, "inside")?;
            let inside = bob.vault();
            saves(&bob, "K2", 1, "beyond")?;
            let beyond = bob.vault();
            p.require(
                prev_entries(&inside).len() == WINDOW,
                format!("the window is full ({})", prev_entries(&inside).len()),
            )?;
            // alice-1 and alice-2 both hold the revision bob started from.
            let near = load_file(&alice1, &inside);
            let far = load_file(&alice2, &beyond);
            p.reached();
            p.target(
                near.ok,
                format!("a teammate 256 saves ahead is accepted: {}", near.stderr),
            );
            p.target(
                !far.ok && far.stderr.contains("256") && !far.stdout.contains("beyond-0"),
                format!(
                    "one 257 saves ahead is refused as beyond the window: {}",
                    far.stderr
                ),
            );
        }
        // The merge arm.
        let run = Run::new();
        let (alice1, alice2, bob) = (
            run.world.machine(0),
            run.world.machine(1),
            run.world.machine(2),
        );
        saves(&alice1, "K1", 300, "ours")?;
        alice1.commit("ours: 300 saves");
        saves(&bob, "K2", 3, "theirs")?;
        bob.commit("theirs: 3 saves");
        bob.git_ok(&["push", "-q", "origin", "HEAD:refs/heads/theirs"]);
        alice1.git_ok(&["fetch", "-q", "origin"]);
        let ours = alice1.vault();
        let theirs = bob.vault();
        let first = alice1.git(&["merge", "-q", "--no-edit", "origin/theirs"]);
        p.require(
            driver_said(&first.stderr),
            format!("the murk driver ran: {}", stderr(&first)),
        )?;
        let merged = alice1.vault();
        let entries = prev_entries(&merged);
        let generations: BTreeSet<u64> = entries.iter().map(|e| entry_generation(e)).collect();
        p.target(
            first.status.success()
                && entries.len() <= WINDOW
                && generations.contains(&generation(&ours))
                && generations.contains(&generation(&theirs)),
            format!(
                "the merge result keeps ours' and theirs' own entries in a window of at most {WINDOW} (it holds {})",
                entries.len()
            ),
        );
        // alice-2's reference is theirs' tip once she has accepted it.
        let tip = load_file(&alice2, &theirs);
        p.require(
            tip.ok,
            format!("a teammate accepts theirs' tip: {}", tip.stderr),
        )?;
        let accepted = load_file(&alice2, &merged);
        p.target(
            accepted.ok,
            format!(
                "a teammate whose reference is theirs' tip accepts the result: {}",
                accepted.stderr
            ),
        );
        saves(&bob, "K2", 1, "theirs-more")?;
        bob.commit("theirs: one more");
        bob.git_ok(&["push", "-q", "origin", "HEAD:refs/heads/theirs"]);
        alice1.git_ok(&["fetch", "-q", "origin"]);
        let second = alice1.git(&["merge", "-q", "--no-edit", "origin/theirs"]);
        p.target(
            second.status.success() && driver_said(&second.stderr),
            format!("their next save merges cleanly: {}", stderr(&second)),
        );
        Ok(())
    });
}

/// A member's own unsigned save leaves the lineage reference where it was, and
/// a teammate's signed save on top of it is accepted by the member. erin's key
/// cannot sign; alice reviews erin's unsigned vault (a key that signs refuses
/// one until she does) and saves on top, and erin pulls it.
#[test]
fn row_r_l_unsigned() {
    common::rows::check("R-L-unsigned", |p| {
        let mut run = Run::new();
        let erin = run.world.erin();
        let reference = |m: &Machine| {
            pin_of(m, true).and_then(|sidecar| {
                sidecar["lineage_heads"]["main"]
                    .as_str()
                    .map(str::to_string)
            })
        };
        let before = reference(&erin);
        p.require(
            before.is_some() && major(&erin.vault()) == 4,
            "erin has no lineage reference: this build keeps none",
        )?;
        let saved = erin_saves(&erin, "ERIN_KEY", "erin-value");
        p.require(
            saved.ok && !has_sig(&erin.vault()),
            format!("erin saves, unsigned: {}", saved.stderr),
        )?;
        let after_save = reference(&erin);
        erin.git_ok(&["push", "-q", "origin", "HEAD:main"]);
        let step = run.next_world_step();
        run.world.record(&erin.vault(), None, step, false);
        run.setup(&[
            accepts(Op::Sync { m: M(0) }),
            accepts(Op::Trust {
                m: M(0),
                forgery: false,
            }),
            accepts(Op::Save { m: M(0), key: K(0) }),
            accepts(Op::Sync { m: M(0) }),
        ])?;
        erin.git_ok(&["pull", "-q", "--no-rebase", "origin", "main"]);
        let load = export(&erin);
        p.reached();
        p.target(
            load.ok,
            format!(
                "erin accepts the teammate's save on top of hers: {}",
                load.stderr
            ),
        );
        p.target(
            after_save == before,
            format!(
                "her own unsigned save left the reference alone ({before:?} then {after_save:?})"
            ),
        );
        Ok(())
    });
}

// ── The oracles and constructors the random run relies on ──

/// The value-lineage oracle sees a stale fork replayed over main, built only
/// from the random generator's own ops: alice's second machine saves four
/// times and pushes, alice rotates a value on main and loads it, the old fork
/// is replayed onto main, and alice pulls and loads it. Until lineage lands
/// murk accepts the load, and the oracle counts it as a known open violation
/// (its row is not enforced); once the row is enforced the load is refused,
/// and an accepted one fails the step.
#[test]
fn value_oracle_sees_a_stale_fork_replay() {
    let mut run = Run::new();
    let (a1, a2) = (M(0), M(1));
    let mut setup: Vec<Scripted> = [0, 1, 2, 0]
        .map(|key| accepts(Op::Save { m: a2, key: K(key) }))
        .into();
    setup.extend([
        accepts(Op::Push { m: a2 }),
        accepts(Op::Save { m: a1, key: K(0) }),
        accepts(Op::Sync { m: a1 }),
        accepts(load_main(a1)),
    ]);
    run.setup(&setup).unwrap();
    let branch = run.world.branches[0].clone();
    let attacker = bystander(&run.world.root, "attacker");
    attacker.git_ok(&["fetch", "-q", "origin"]);
    let tip = attacker.git_ok(&["rev-parse", &format!("origin/{branch}")]);
    let n = attacker
        .revisions()
        .iter()
        .position(|r| *r == tip)
        .expect("the pushed fork is a revision");
    run.setup(&[
        runs(Op::Replay {
            rev: Old::Nth(n),
            to: Dest::Main,
        }),
        accepts(Op::Sync { m: a1 }),
    ])
    .unwrap();
    assert!(
        run.world.open_hits.is_empty(),
        "the oracle is silent before the replay is loaded"
    );
    let loaded = run.play(&load_main(a1)).expect("the load runs");
    if lineage_enforced() {
        assert!(
            matches!(loaded, Ok(Ran::Refused(_))),
            "the stale fork must be refused: {loaded:?}"
        );
    } else {
        assert!(matches!(loaded, Ok(Ran::Accepted)), "{loaded:?}");
        assert_eq!(run.world.open_hits.len(), 1, "{:?}", run.world.open_hits);
        println!("known open: {}", run.world.open_hits[0]);
    }
}

/// The value-lineage oracle sees a deleted secret come back: alice saves K2
/// and removes it again, so the revision before the removal, with K2's old
/// value, is older than what she accepted; a vault that never held K2 is not
/// (it is just older, and has no value to compare), and a later save of K2 is
/// newer than the deletion.
#[test]
fn value_oracle_sees_a_deleted_secret_come_back() {
    let mut run = Run::new();
    run.setup(&[
        accepts(Op::Save { m: M(0), key: K(1) }),
        accepts(Op::Rm { m: M(0), key: K(1) }),
    ])
    .unwrap();
    let alice = run.world.machine(0);
    let with_k2 = alice.vault_at("HEAD~1");
    assert!(
        run.world
            .would_flag(0, &with_k2)
            .is_some_and(|hit| hit.contains("K2")),
        "the revision before the removal must read as older than the deletion"
    );
    assert_eq!(run.world.would_flag(0, &alice.vault()), None);
    run.setup(&[accepts(Op::Save { m: M(0), key: K(1) })])
        .unwrap();
    assert_eq!(
        run.world.would_flag(0, &alice.vault()),
        None,
        "a save after the deletion is newer than it"
    );
}

/// The readers oracle takes its expectation from the harness's own authorize,
/// revoke and merge history, not from the vault: it agrees with a save the
/// vault's recipients and the history both describe, and objects when the
/// history says someone else should be (or not be) a reader, even though the
/// vault's own recipient list is unchanged.
#[test]
fn readers_oracle_follows_the_harness_history_not_the_vault() {
    let mut run = Run::new();
    run.setup(&[accepts(Op::Save { m: M(0), key: K(0) })])
        .unwrap();
    let saved = run.world.machine(0).vault();
    let value = format!("s{}-K1", run.world_step());
    let blob = blob_id(&saved);
    let history = run.world.expected.get(&blob).cloned();
    assert_eq!(
        history,
        Some(BTreeSet::from([0, 1, 2, CI_READER])),
        "the history says alice, bob, carol and CI read what alice saves"
    );
    assert!(run.world.check_saved(&saved, "K1", &value).is_ok());
    // History that leaves CI out disagrees with the vault, which lists it.
    run.world.expected.insert(blob, BTreeSet::from([0, 1, 2]));
    assert!(
        run.world.check_saved(&saved, "K1", &value).is_err(),
        "a reader the history did not expect must fail the oracle"
    );
    // History that adds dave disagrees with the vault, which does not list him.
    run.world
        .expected
        .insert(blob, BTreeSet::from([0, 1, 2, 3, CI_READER]));
    assert!(
        run.world.check_saved(&saved, "K1", &value).is_err(),
        "a reader the vault does not list must fail the oracle"
    );
}

/// A revoked member's forgery, signed with their own key, that a pull on
/// alice's machine fast-forwards in (no merge driver runs, so murk judges
/// nothing): murk on her machine refuses to load it or write over it, since
/// it is signed by and lists someone it recorded as removed. A vouch over it
/// is drawn: it is a member's own code, so its write is not judged as murk's
/// (seeds 1794831267910282368 and 1794858455667855160 once failed that way),
/// and the load that follows it on her machine is refused.
#[test]
fn a_vouch_over_a_vault_murk_here_refuses_is_judged_by_the_load() {
    let mut run = Run::seasoned();
    run.setup(&[
        runs(Op::Forge {
            by: Attacker::Revoked,
            base: Base::NewestOpenable,
            generation: Gen::Next,
            sign: Sign::Own,
            to: Dest::Main,
        }),
        accepts(Op::Sync { m: M(0) }),
    ])
    .unwrap();
    let alice = run.world.machine(0);
    assert!(
        run.world.listed(&alice.vault()).contains(&3),
        "the pull brought in the forgery, which lists dave"
    );
    let vouched = run.play(&Op::Vouch {
        m: M(0),
        who: P(0),
        key: Planted::Sock,
    });
    assert!(
        matches!(vouched, Some(Ok(Ran::Accepted))),
        "the vouch is drawn, and its write is not judged as murk's: {vouched:?}"
    );
    assert!(
        run.world.last_load.as_ref().is_some_and(|l| !l.ok),
        "murk here refuses to load the vouch"
    );
    run.setup(&[
        refuses(Op::Load {
            m: M(0),
            at: At::Main,
        }),
        refuses(Op::Save { m: M(0), key: K(1) }),
        refuses(Op::Authorize { m: M(0), who: P(3) }),
    ])
    .unwrap();
}

/// The pin oracle of an environment-anchored observer that keeps its `HOME`
/// judges every load that leaves a pin, and fails (or, for an open row,
/// counts) a load that changed more than the counters and marks.
#[test]
fn env_anchored_observer_pin_oracle_judges_and_can_fail() {
    let mut run = Run::new();
    run.setup(&[
        accepts(Op::CiKeepLoad { at: Ref::Main }),
        accepts(Op::Save { m: M(0), key: K(0) }),
        accepts(Op::Sync { m: M(0) }),
        accepts(Op::CiKeepLoad { at: Ref::Main }),
    ])
    .unwrap();
    let judged = run.world.judged.borrow().get("pin-bytes").copied();
    assert!(
        judged.is_some_and(|n| n >= 2),
        "the pin oracle judged {judged:?} loads of a runner that keeps its HOME"
    );
    // It can fail: the same pin with a signer trusted.
    let clone = bystander(&run.world.root, "ci-keep");
    let before = pin_of(&clone, false).expect("the runner's load left a pin");
    let mut widened = before.clone();
    widened["trusted"] = serde_json::json!(["age1widened"]);
    let verdict = run.world.pin_env_check(Some(&before), Some(&widened));
    if row_enforced("R-I4-a") {
        assert!(verdict.is_err(), "a widened pin must fail the oracle");
    } else {
        assert!(verdict.is_ok() && !run.world.open_hits.is_empty());
    }
}

/// Each generator constructor builds its scenario: every step runs, and none
/// is skipped as one that could not be built here. Whether murk or an oracle
/// then objects is for the rows that cover the constructor (it is drawn at
/// random only once they are enforced); what happened is printed.
#[test]
fn constructors_reach_their_scenarios() {
    let (alice, bob) = (M(0), P(1));
    let scenarios: [(&str, Vec<Op>); 5] = [
        (
            "copy-vault",
            vec![Op::CopyVault { m: alice }, Op::TrustCopy { m: alice }],
        ),
        (
            "unsigned-erin",
            vec![
                // erin catches up with main, saves, and pushes; the forgery goes
                // on top of her save, and she pulls and loads it.
                Op::ErinSync,
                Op::ErinSave { key: K(0) },
                Op::ErinSync,
                Op::ForgeUnsigned {
                    by: bob,
                    to: Dest::Main,
                },
                Op::ErinSync,
                Op::ErinLoad { at: At::Main },
            ],
        ),
        (
            "forged-ancestor (empty)",
            vec![
                Op::Save {
                    m: alice,
                    key: K(1),
                },
                Op::Sync { m: alice },
                Op::Rm {
                    m: alice,
                    key: K(1),
                },
                Op::Sync { m: alice },
                Op::AncestorBranch {
                    by: bob,
                    kind: Ancestor::Empty,
                    rev: 1,
                },
                Op::CherryPick {
                    m: alice,
                    branch: 0,
                },
            ],
        ),
        (
            "forged-ancestor (stripped)",
            vec![
                Op::Save {
                    m: alice,
                    key: K(1),
                },
                Op::Sync { m: alice },
                Op::Rm {
                    m: alice,
                    key: K(1),
                },
                Op::Sync { m: alice },
                Op::AncestorBranch {
                    by: bob,
                    kind: Ancestor::Stripped,
                    rev: 1,
                },
                Op::CherryPick {
                    m: alice,
                    branch: 0,
                },
            ],
        ),
        (
            "grant-recipient",
            vec![
                Op::Grant { m: alice },
                Op::Sync { m: alice },
                Op::ListGrantKey {
                    by: bob,
                    to: Dest::Main,
                },
                Op::AgentProbe {
                    at: Ref::Main,
                    how: Presented::StrippedLines,
                },
                Op::AgentProbe {
                    at: Ref::Main,
                    how: Presented::RawKey,
                },
            ],
        ),
    ];
    for (name, ops) in scenarios {
        let mut run = Run::seasoned();
        for op in &ops {
            let result = run.play(op);
            println!("{name}: {op:?}: {result:?}");
            if matches!(op, Op::AncestorBranch { .. }) {
                let attacker = bystander(&run.world.root, "attacker");
                let branch = run.world.branches.last().cloned().unwrap_or_default();
                for (what, rev) in [("ancestor", "~1"), ("revision", "")] {
                    let vault = vault_json(&attacker.vault_at(&format!("origin/{branch}{rev}")));
                    println!(
                        "{name}: the {what} has {} secrets, {} schema entries, id {:?}, signed: {}",
                        vault["secrets"].as_object().map_or(0, |o| o.len()),
                        vault["schema"].as_object().map_or(0, |o| o.len()),
                        vault["vault_id"],
                        !vault["sig"].is_null()
                    );
                }
            }
            assert!(
                result.is_some(),
                "{name}: {op:?} did not run: it could not be built here"
            );
        }
        println!(
            "{name}: known open violations counted: {:?}",
            run.world.open_hits
        );
    }
}

/// The attacker's (or a vouching member's) own code against the library:
/// decrypt a vault they can open, change it, save it with a fresh MAC and
/// their signature, and optionally re-sign it as a recipient whose registry
/// entry holds a key they control. Run in a child process by
/// [`World::forge`]; prints `FORGE-OK` or `FORGE-SKIP`.
#[test]
#[ignore = "spawned by trust_invariants_hold_across_machines"]
fn forge_child() {
    use std::env::var;
    let (Ok(input), Ok(output), Ok(key)) = (var("FORGE_IN"), var("FORGE_OUT"), var("FORGE_KEY"))
    else {
        return;
    };
    let skip = |why: &str| {
        println!("FORGE-SKIP {why}");
        std::process::exit(0);
    };
    fs::copy(&input, &output).unwrap();
    let identity = murk_cli::crypto::parse_identity(&key).unwrap();
    let mut vault = murk_cli::read_vault(&output).unwrap();
    let Ok(original) = murk_cli::decrypt_vault(&vault, &identity) else {
        skip("cannot open this vault");
        return;
    };
    let mut current = original.clone();
    if let Ok(kv) = var("FORGE_VALUE") {
        let (k, v) = kv.split_once('=').unwrap();
        murk_cli::add_secret(&mut vault, &mut current, k, v, None, None, false, &[], None);
    }
    if let Ok(spec) = var("FORGE_AUTHORIZE") {
        let (pk, name) = spec.split_once(' ').unwrap();
        if !vault.recipients.iter().any(|r| r == pk) {
            vault.recipients.push(pk.to_string());
        }
        current.recipients.insert(pk.to_string(), name.to_string());
    }
    // Group membership is part of the meta: the forgery names a member the
    // group did not have, as a recipient who is not in it would write it.
    if let Ok(spec) = var("FORGE_GROUP") {
        let (name, pk) = spec.split_once('=').unwrap();
        let members = current.groups.entry(name.to_string()).or_default();
        if !members.iter().any(|m| m == pk) {
            members.push(pk.to_string());
        }
    }
    // An empty ancestor: every secret gone, the schema left as it was.
    if var("FORGE_CLEAR").is_ok() {
        current.values.clear();
        current.private.clear();
        current.grouped.clear();
    }
    // A grant's key that is still a recipient, with its grant record gone.
    if var("FORGE_DROP_GRANTS").is_ok() {
        current.grants.clear();
        vault.agents.clear();
    }
    // The generation the forged vault carries. murk numbers a save one past
    // the vault's and refuses to write past its limit, so a claim above the
    // limit is written by hand after the save, as the attacker's own code
    // would.
    let generation = var("FORGE_GEN").ok().map(|g| g.parse::<u64>().unwrap());
    if let Some(generation) = generation {
        vault.generation = generation.min(GENERATION_CAP).saturating_sub(1);
    }
    unsafe {
        std::env::set_var("MURK_KEY", &key);
        std::env::set_var("MURK_NO_SIGNER_PIN", "1");
    }
    if let Err(e) = murk_cli::save_vault(&output, &mut vault, &original, &current) {
        println!("FORGE-REFUSED {e}");
        std::process::exit(0);
    }
    // The writer leaves themselves out of the recipients, after murk's own
    // save (which refuses to write a vault its key cannot read back).
    if var("FORGE_DROP_SELF").is_ok() {
        let me = identity.pubkey_string().unwrap();
        let mut vault = murk_cli::read_vault(&output).unwrap();
        vault.recipients.retain(|r| *r != me);
        current.recipients.remove(&me);
        common::forgery::reseal_unchecked(&mut vault, &identity);
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    if let Some(generation) = generation.filter(|&g| g > GENERATION_CAP) {
        let mut vault = murk_cli::read_vault(&output).unwrap();
        vault.generation = generation;
        common::forgery::reseal(&mut vault, &identity);
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    // A registry entry is planted in the meta directly, as the attacker's own
    // code would: murk's save refuses to write some keys (weak ones), and the
    // point is what a loader does with them. The meta is re-encrypted to the
    // vault's non-grant recipients and the vault re-signed by this key.
    if let Ok(spec) = var("FORGE_REGISTRY") {
        let (pk, vk) = spec.split_once('=').unwrap();
        current.signers.insert(pk.to_string(), vk.to_string());
        let mut vault = murk_cli::read_vault(&output).unwrap();
        let mut meta = murk_cli::decrypt_meta(&vault, &identity)
            .unwrap()
            .expect("the writer opens the meta it wrote");
        meta.signers.insert(pk.to_string(), vk.to_string());
        let grants: BTreeSet<&str> = meta.grants.values().map(|g| g.pubkey.as_str()).collect();
        let recipients: Vec<murk_cli::MurkRecipient> = vault
            .recipients
            .iter()
            .filter(|r| !grants.contains(r.as_str()))
            .map(|r| murk_cli::crypto::parse_recipient(r).unwrap())
            .collect();
        vault.meta =
            murk_cli::encrypt_value(&serde_json::to_vec(&meta).unwrap(), &recipients).unwrap();
        vault.sig = None;
        let mut message = b"murk.vault.sig.v2\n".to_vec();
        serde_json::to_writer(&mut message, &vault).unwrap();
        vault.sig = Some(murk_cli::types::VaultSignature {
            signer: identity.pubkey_string().unwrap(),
            v: 2,
            sig: identity.signing_key().unwrap().sign(&message),
        });
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    if let Ok(how) = var("FORGE_SIGN_AS") {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        // The registry key to sign under, and how to sign a message.
        type Signer = Box<dyn Fn(&[u8]) -> String>;
        let (vk, sign): (String, Signer) = match how.strip_prefix("sock:") {
            Some(secret) => {
                let signing = murk_cli::crypto::parse_identity(secret)
                    .unwrap()
                    .signing_key()
                    .unwrap();
                (signing.verifying_key(), Box::new(move |m| signing.sign(m)))
            }
            // R = the identity point, s = 0: [s]B = R + [k]A holds for the
            // identity A whatever k (the message hash) is.
            None => (weak_vk_b64(), {
                let sig: Vec<u8> = WEAK_VK.iter().copied().chain([0u8; 32]).collect();
                let sig = b64.encode(sig);
                Box::new(move |_| sig.clone())
            }),
        };
        let Some(signer) = current
            .signers
            .iter()
            .find(|(_, v)| **v == vk)
            .map(|(pk, _)| pk.clone())
        else {
            skip("no recipient carries the planted key");
            return;
        };
        let mut vault = murk_cli::read_vault(&output).unwrap();
        vault.sig = None;
        let mut message = b"murk.vault.sig.v2\n".to_vec();
        serde_json::to_writer(&mut message, &vault).unwrap();
        vault.sig = Some(murk_cli::types::VaultSignature {
            signer,
            v: 2,
            sig: sign(&message),
        });
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    if let Ok(which) = var("FORGE_LEGACY") {
        let mut vault = murk_cli::read_vault(&output).unwrap();
        if !vault.agents.is_empty() {
            skip("a 0.13 vault carries no grant records");
        }
        if which == "other" {
            vault.created = "2020-01-01T00:00:00Z".into();
        }
        common::forgery::reseal_v1(&mut vault, &identity);
        if var("FORGE_STRIP_V1").is_ok() {
            // No signature at all: the 0.13 one sits inside the meta.
            common::forgery::strip_v1(&mut vault, &identity);
        }
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    // A repo writer's copy: the signature removed, the MAC intact.
    if var("FORGE_UNSIGNED").is_ok() {
        let mut vault = murk_cli::read_vault(&output).unwrap();
        vault.sig = None;
        murk_cli::vault::write(Path::new(&output), &vault).unwrap();
    }
    println!("FORGE-OK");
}
