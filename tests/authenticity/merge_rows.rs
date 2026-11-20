// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Invariant rows about the merge driver (see `tests/invariant_rows.tsv`).
//!
//! Every scenario runs the real driver through git (`git merge`, `git
//! cherry-pick`, `git rebase`, `git revert`) against commits a repo writer
//! could push: a forged ancestor, a genuine revision replayed under another
//! parent, a side whose MAC fails. A row asserts that the murk driver itself
//! ran (its stderr, not git's own text conflict) before it judges the result.

use std::fs;
use std::path::{Path, PathBuf};

use murk_cli::types::{SecretEntry, Vault};
use tempfile::TempDir;

use super::common::rows::{Probe, check};
use super::common::{self, forgery};
use super::{
    Machine, alice_repo, authorize, commit, git, git_merge, git_ok, head_commit, mallory_vault,
    pin_files, use_merge_driver,
};

// ── Helpers ──

/// Run murk as `who` in `repo`; it must succeed.
fn murk_ok(who: &Machine, repo: &Path, args: &[&str]) {
    who.murk(repo).args(args).assert().success();
}

/// A second laptop of `of`: a HOME and trust pin of its own, working in the
/// same repos with the same key file.
struct Laptop {
    machine: Machine,
    key: PathBuf,
}

impl Laptop {
    fn new(base: &Path, name: &str, of: &Machine) -> Self {
        Self {
            machine: Machine::new(base, name),
            key: of.key_file(),
        }
    }

    /// Run murk on this laptop in `repo`; it must succeed.
    fn ok(&self, repo: &Path, args: &[&str]) {
        self.machine
            .with_key(repo, &self.key)
            .args(args)
            .assert()
            .success();
    }

    fn add(&self, repo: &Path, key: &str, value: &str) {
        self.machine
            .with_key(repo, &self.key)
            .args(["add", key])
            .write_stdin(format!("{value}\n"))
            .assert()
            .success();
    }

    /// Run murk on this laptop in `repo` as the grant minter; it must succeed.
    fn command(&self, repo: &Path) -> assert_cmd::Command {
        self.machine.with_key(repo, &self.key)
    }
}

/// `git <args>` in `repo` as `who` (their HOME, their stored key, no murk
/// context variables), with the murk driver configured: (success, stderr).
fn git_as(who: &Machine, repo: &Path, args: &[&str]) -> (bool, String) {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(repo)
        .env("HOME", &who.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_EDITOR", "true")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "t@t");
    for var in common::MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The working `.murk`.
fn working(repo: &Path) -> Vec<u8> {
    fs::read(repo.join(".murk")).unwrap()
}

/// Commit `vault` as `.murk` on the current branch (an empty commit when the
/// file is already that).
fn put(repo: &Path, vault: &[u8], message: &str) {
    fs::write(repo.join(".murk"), vault).unwrap();
    git_ok(repo, &["add", "-A"]);
    git_ok(
        repo,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            message,
        ],
    );
}

/// The commits of someone who holds no key: branch `name` from `from`, with
/// `parent` committed on it and then `tip`. Returns the tip commit and leaves
/// `main` checked out. Cherry-picking the tip hands the driver `parent` as the
/// ancestor, whatever the history says.
fn attack_branch(repo: &Path, name: &str, from: &str, parent: &[u8], tip: &[u8]) -> String {
    git_ok(repo, &["checkout", "-q", "-b", name, from]);
    put(repo, parent, "attacker: parent");
    put(repo, tip, "attacker: change");
    let tip = head_commit(repo);
    git_ok(repo, &["checkout", "-q", "main"]);
    tip
}

fn parse(file: &[u8]) -> Option<Vault> {
    serde_json::from_slice(file).ok()
}

fn to_file(vault: &Vault) -> Vec<u8> {
    let mut text = serde_json::to_string_pretty(vault).unwrap();
    text.push('\n');
    text.into_bytes()
}

/// What a merge left behind.
struct Merged {
    /// Whether git completed the merge (the driver exited 0).
    ok: bool,
    /// The driver's and git's stderr.
    stderr: String,
    /// The working `.murk` afterwards.
    file: Vec<u8>,
}

impl Merged {
    fn of(result: (bool, String), repo: &Path) -> Self {
        Self {
            ok: result.0,
            stderr: result.1,
            file: working(repo),
        }
    }

    /// `git merge <branch>` as `who`.
    fn merge(who: &Machine, repo: &Path, branch: &str) -> Self {
        Self::of(git_merge(who, repo, branch), repo)
    }

    /// `git cherry-pick <rev>` as `who`.
    fn cherry_pick(who: &Machine, repo: &Path, rev: &str) -> Self {
        Self::of(git_as(who, repo, &["cherry-pick", rev]), repo)
    }

    /// Whether the murk driver ran: its own summary line, not git's text
    /// conflict.
    fn ran(&self) -> bool {
        self.stderr.contains("vault merged cleanly")
            || self.stderr.contains("nothing was written")
            || self
                .stderr
                .lines()
                .any(|l| l.contains(" conflict:") || l.contains(" conflicts:"))
    }

    fn vault(&self) -> Option<Vault> {
        parse(&self.file)
    }

    /// The working file holds a signature.
    fn signed(&self) -> bool {
        self.vault().is_some_and(|v| v.sig.is_some())
    }

    /// The working file holds a secret named `key`.
    fn has(&self, key: &str) -> bool {
        self.vault().is_some_and(|v| v.secrets.contains_key(key))
    }

    /// The working file's entry for `key`.
    fn secret(&self, key: &str) -> Option<SecretEntry> {
        self.vault().and_then(|v| v.secrets.get(key).cloned())
    }
}

/// The entry for `key` in `file`.
fn secret_in(file: &[u8], key: &str) -> Option<SecretEntry> {
    parse(file).and_then(|v| v.secrets.get(key).cloned())
}

/// What a repo writer holding no key can build from the public file `like`: a
/// vault as murk 0.13 wrote it (version 2.0, no vault id or counter), unsigned,
/// whose MAC verifies. It lists `like`'s recipients, and the schema and secrets
/// of `like` for the keys in `keep` only; `policy` keeps `like`'s policy.
/// Built here with alice's key, which only supplies the MAC the file needs.
fn forged_ancestor(alice: &Machine, like: &[u8], keep: &[&str], policy: bool) -> Vec<u8> {
    let identity = murk_cli::crypto::parse_identity(&alice.secret_key()).unwrap();
    let mut vault = parse(like).unwrap();
    vault.secrets.retain(|k, _| keep.contains(&k.as_str()));
    vault.schema.retain(|k, _| keep.contains(&k.as_str()));
    if !policy {
        vault.policy = None;
    }
    vault.agents.clear();
    vault.sig = None;
    forgery::reseal_v1(&mut vault, &identity);
    forgery::strip_v1(&mut vault, &identity);
    to_file(&vault)
}

/// A repo writer's ancestor that `reader` cannot open: `like` without
/// `reader` among its recipients, its meta replaced by one from `meta_from`
/// (another vault the writer owns), no signature and no counter. Its secrets
/// are `like`'s, so a key in `like` still reads them.
fn unreadable_ancestor(like: &[u8], reader: &str, meta_from: &[u8]) -> Vec<u8> {
    let mut vault = parse(like).unwrap();
    vault.recipients.retain(|r| r != reader);
    vault.meta = parse(meta_from).unwrap().meta;
    vault.sig = None;
    vault.generation = 0;
    to_file(&vault)
}

/// `p.require`, with the driver's stderr in the message.
fn require_ran(p: &mut Probe, merge: &Merged, what: &str) -> Result<(), String> {
    p.note(format!("{what}: {}", merge.stderr.trim()));
    p.require(
        merge.ran(),
        format!("{what}: the murk driver did not run: {}", merge.stderr),
    )
}

/// A repo whose vault alice and bob share (`DB_URL` and `API_KEY` set, the
/// driver configured and committed on `main`): revision R0.
struct Team {
    alice: Machine,
    bob: Machine,
    repo: PathBuf,
    /// R0, as committed.
    r0: String,
    r0_file: Vec<u8>,
}

impl Team {
    fn new(base: &Path) -> Self {
        let (alice, repo) = alice_repo(base);
        let bob = Machine::new(base, "bob");
        bob.init(&base.join("bob-scratch"), "bob");
        authorize(&alice, &repo, &bob, "bob");
        alice.add(&repo, "API_KEY", "api-key");
        use_merge_driver(&repo);
        Self {
            r0: head_commit(&repo),
            r0_file: working(&repo),
            alice,
            bob,
            repo,
        }
    }

    /// A genuine revision on an unmerged branch `name` off `from`: alice's
    /// second laptop trusts that revision and adds `key`. Leaves `main`
    /// checked out and returns the new revision's file.
    fn fork(&self, base: &Path, name: &str, from: &str, key: &str) -> Vec<u8> {
        let second = Laptop::new(base, &format!("{name}-laptop"), &self.alice);
        git_ok(&self.repo, &["checkout", "-q", "-b", name, from]);
        second.ok(&self.repo, &["trust", "--yes"]);
        second.add(&self.repo, key, &format!("{key}-value"));
        commit(&self.repo, &format!("{name}: add {key}"));
        let file = working(&self.repo);
        git_ok(&self.repo, &["checkout", "-q", "main"]);
        file
    }

    /// Main moves on after R0: `DB_URL` rotated, an agent policy set,
    /// `NEW_K` added. Returns the new tip's file.
    fn rotate(&self) -> Vec<u8> {
        self.alice.add(&self.repo, "DB_URL", "rotated-db");
        murk_ok(
            &self.alice,
            &self.repo,
            &["policy", "set", "--allow-tag", "nothing"],
        );
        self.alice.add(&self.repo, "NEW_K", "new-k");
        commit(&self.repo, "rotate DB_URL, set a policy, add NEW_K");
        working(&self.repo)
    }

    /// Main moves on after R0 with the rotation only: `DB_URL` rotated and an
    /// agent policy set, no new key. Returns the new tip's file.
    fn rotate_only(&self) -> Vec<u8> {
        self.alice.add(&self.repo, "DB_URL", "rotated-db");
        murk_ok(
            &self.alice,
            &self.repo,
            &["policy", "set", "--allow-tag", "nothing"],
        );
        commit(&self.repo, "rotate DB_URL and set a policy");
        working(&self.repo)
    }

    /// `murk get <key>` as alice: the value, or `None` when murk refuses.
    fn get(&self, key: &str) -> Option<String> {
        let out = self
            .alice
            .murk(&self.repo)
            .args(["get", key])
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

// ── R-I11-a, R-I11-c, R-I10-g: an ancestor that is not an authority ──

/// Alice adds `OLD_TOKEN` (revision A) and later removes it (ours). A forged
/// empty ancestor stands under a genuine revision that still holds it.
struct Retired {
    team: Team,
    /// The revision that added `OLD_TOKEN`.
    added: String,
    added_file: Vec<u8>,
    /// Main's tip: `OLD_TOKEN` removed again.
    ours: Vec<u8>,
}

impl Retired {
    fn new(base: &Path) -> Self {
        let team = Team::new(base);
        team.alice.add(&team.repo, "OLD_TOKEN", "old-token");
        commit(&team.repo, "add OLD_TOKEN");
        let added = head_commit(&team.repo);
        let added_file = working(&team.repo);
        murk_ok(&team.alice, &team.repo, &["rm", "OLD_TOKEN"]);
        commit(&team.repo, "remove OLD_TOKEN");
        let ours = working(&team.repo);
        Self {
            team,
            added,
            added_file,
            ours,
        }
    }

    /// The control: a feature branch that adds `NEW_TOKEN` from the genuine
    /// fork point R0 merges cleanly, and `OLD_TOKEN` stays removed.
    fn control(base: &Path) -> Result<(), String> {
        let scene = Self::new(base);
        let repo = &scene.team.repo;
        scene
            .team
            .fork(base, "feature", &scene.team.r0, "NEW_TOKEN");
        let merged = Merged::merge(&scene.team.alice, repo, "feature");
        if !(merged.ran() && merged.ok) {
            return Err(format!(
                "a genuine feature branch should merge: {}",
                merged.stderr
            ));
        }
        if scene.team.get("NEW_TOKEN").as_deref() != Some("NEW_TOKEN-value\n") {
            return Err("the feature's NEW_TOKEN should be merged".into());
        }
        if merged.has("OLD_TOKEN") {
            return Err("OLD_TOKEN should stay removed".into());
        }
        Ok(())
    }
}

/// An empty forged ancestor under the genuine revision that added `OLD_TOKEN`
/// (which ours removed again): `git cherry-pick`. `theirs` is that revision.
fn empty_ancestor_replay(base: &Path, fork: bool) -> (Retired, Merged) {
    let scene = Retired::new(base);
    let repo = scene.team.repo.clone();
    let theirs = if fork {
        // A genuine revision of an unmerged branch that still holds it.
        scene.team.fork(base, "unmerged", &scene.added, "FORK_K")
    } else {
        scene.added_file.clone()
    };
    let forged = forged_ancestor(&scene.team.alice, &scene.ours, &[], false);
    let evil = attack_branch(&repo, "evil", &scene.team.r0, &forged, &theirs);
    let merged = Merged::cherry_pick(&scene.team.alice, &repo, &evil);
    (scene, merged)
}

/// An empty forged ancestor under the genuine revision that added
/// `OLD_TOKEN`, cherry-picked: arm 1, theirs is that revision, which ours
/// contains. The merge must not exit 0 and re-add the removed secret.
#[test]
fn row_r_i11_c_1() {
    check("R-I11-c:1", |p| {
        let control = TempDir::new().unwrap();
        Retired::control(control.path())?;
        let base = TempDir::new().unwrap();
        let (scene, merged) = empty_ancestor_replay(base.path(), false);
        require_ran(p, &merged, "cherry-pick")?;
        p.reached();
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            merged.file == scene.ours,
            "the working file is ours, byte for byte",
        );
        p.target(!merged.has("OLD_TOKEN"), "OLD_TOKEN stays removed");
        p.target(
            merged.stderr.contains("already contains"),
            "the driver says theirs is a revision this branch already contains",
        );
        Ok(())
    });
}

/// As arm 1, with theirs a genuine revision of an unmerged branch that still
/// holds `OLD_TOKEN`: the empty ancestor must not make it a one-sided add.
#[test]
fn row_r_i11_c_2() {
    check("R-I11-c:2", |p| {
        let control = TempDir::new().unwrap();
        Retired::control(control.path())?;
        let base = TempDir::new().unwrap();
        let (_, merged) = empty_ancestor_replay(base.path(), true);
        require_ran(p, &merged, "cherry-pick")?;
        p.reached();
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            merged.stderr.contains("secrets.OLD_TOKEN"),
            "the conflict names OLD_TOKEN",
        );
        p.target(!merged.has("OLD_TOKEN"), "OLD_TOKEN stays removed");
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

/// Arm 1 on format 3, with no lineage to show that ours contains theirs: the
/// empty forged ancestor is no authority, so the merge is two-way. It stops
/// with a conflict, keeps ours' values and policy, and signs nothing.
#[test]
fn row_r_i11_c_1_v3() {
    check("R-I11-c:1-v3", |p| {
        let control = TempDir::new().unwrap();
        Retired::control(control.path())?;
        let base = TempDir::new().unwrap();
        let (scene, merged) = empty_ancestor_replay(base.path(), false);
        require_ran(p, &merged, "cherry-pick")?;
        p.reached();
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(!merged.has("OLD_TOKEN"), "OLD_TOKEN stays removed");
        p.target(
            merged.secret("DB_URL") == secret_in(&scene.ours, "DB_URL"),
            "DB_URL keeps ours' value",
        );
        p.target(
            merged
                .vault()
                .is_some_and(|v| Some(v.policy) == parse(&scene.ours).map(|o| o.policy)),
            "the policy is ours'",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

/// What stands under the replayed revision.
enum Ancestor {
    /// A forged unsigned 0.13-shaped file the key reads.
    Forged,
    /// As `Forged`, numbered at theirs' counter, with a fresh MAC.
    Counted,
    /// A file the key cannot open (its meta belongs to another vault).
    Unreadable,
}

/// Main rotated `DB_URL` and set a policy after R0. A repo writer's commit
/// puts `ancestor` under `theirs` and a maintainer cherry-picks it: `theirs`
/// is R0's file (an older revision ours contains), or, with `fork`, a genuine
/// revision of an unmerged branch off R0.
fn replay_into_rotated(base: &Path, fork: bool, ancestor: &Ancestor) -> Replay {
    let team = Team::new(base);
    let ours = team.rotate();
    let theirs = if fork {
        team.fork(base, "unmerged", &team.r0, "FORK_K")
    } else {
        team.r0_file.clone()
    };
    let forged = || {
        let keys: Vec<String> = parse(&theirs).unwrap().secrets.keys().cloned().collect();
        let keep: Vec<&str> = keys.iter().map(String::as_str).collect();
        forged_ancestor(&team.alice, &ours, &keep, true)
    };
    let ancestor = match ancestor {
        Ancestor::Forged => forged(),
        Ancestor::Counted => {
            let identity = murk_cli::crypto::parse_identity(&team.alice.secret_key()).unwrap();
            let mut vault = parse(&forged()).unwrap();
            vault.generation = parse(&theirs).unwrap().generation;
            forgery::reseal(&mut vault, &identity);
            vault.sig = None;
            to_file(&vault)
        }
        Ancestor::Unreadable => {
            let other = fs::read(mallory_vault(base, &[], &[])).unwrap();
            unreadable_ancestor(&ours, &team.alice.pubkey(), &other)
        }
    };
    let evil = attack_branch(&team.repo, "evil", &team.r0, &ancestor, &theirs);
    let merged = Merged::cherry_pick(&team.alice, &team.repo, &evil);
    Replay {
        team,
        ours,
        theirs,
        merged,
    }
}

struct Replay {
    team: Team,
    /// Main's tip before the cherry-pick.
    ours: Vec<u8>,
    theirs: Vec<u8>,
    merged: Merged,
}

/// The control of the replay rows: a genuine branch off R0 that adds a key
/// merges into the rotated main with its genuine ancestor, and the rotated
/// `DB_URL` survives.
fn genuine_fork_merges(base: &Path) -> Result<(), String> {
    let team = Team::new(base);
    team.rotate();
    team.fork(base, "unmerged", &team.r0, "FORK_K");
    let merged = Merged::merge(&team.alice, &team.repo, "unmerged");
    if !(merged.ran() && merged.ok) {
        return Err(format!(
            "a genuine fork with its genuine ancestor should merge: {}",
            merged.stderr
        ));
    }
    if team.get("DB_URL").as_deref() != Some("rotated-db\n")
        || team.get("FORK_K").as_deref() != Some("FORK_K-value\n")
    {
        return Err("the merge should keep the rotated DB_URL and add FORK_K".into());
    }
    Ok(())
}

/// The older revision, dropped over main as a file, is refused as rolled back.
fn old_revision_is_refused(team: &Team, old: &[u8]) -> Result<(), String> {
    let ours = working(&team.repo);
    fs::write(team.repo.join(".murk"), old).unwrap();
    let out = team
        .alice
        .murk(&team.repo)
        .args(["get", "DB_URL"])
        .output()
        .unwrap();
    fs::write(team.repo.join(".murk"), ours).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() || !stderr.contains("rolled back") {
        return Err(format!("a plain load of the old revision loads: {stderr}"));
    }
    Ok(())
}

/// A forged unsigned ancestor under R0's genuine file, which ours contains
/// (rebase, cherry-pick, root merge): the merge must not exit 0 and revert
/// the rotation. Arm 1 of R-I11-a.
#[test]
fn row_r_i11_a_1() {
    check("R-I11-a:1", |p| {
        let control = TempDir::new().unwrap();
        genuine_fork_merges(control.path())?;
        let base = TempDir::new().unwrap();
        let replay = replay_into_rotated(base.path(), false, &Ancestor::Forged);
        let (merged, ours) = (&replay.merged, &replay.ours);
        require_ran(p, merged, "cherry-pick")?;
        old_revision_is_refused(&replay.team, &replay.theirs)?;
        p.reached();
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            &merged.file == ours,
            "the working file is ours, byte for byte",
        );
        p.target(
            merged.stderr.contains("already contains"),
            "the driver says theirs is a revision this branch already contains",
        );
        Ok(())
    });
}

/// As arm 1, with theirs a genuine revision of an unmerged branch: the forged
/// ancestor must not decide that the rotation and the policy are ours to
/// undo. The merge is two-way, so both conflict and ours is kept.
#[test]
fn row_r_i11_a_2() {
    check("R-I11-a:2", |p| {
        let control = TempDir::new().unwrap();
        genuine_fork_merges(control.path())?;
        let base = TempDir::new().unwrap();
        let replay = replay_into_rotated(base.path(), true, &Ancestor::Forged);
        let (merged, ours) = (&replay.merged, &replay.ours);
        require_ran(p, merged, "cherry-pick")?;
        p.reached();
        let ours_policy = parse(ours).unwrap().policy;
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            merged.stderr.contains("ancestor"),
            "the driver names the ancestor",
        );
        p.target(
            merged.secret("DB_URL") == secret_in(ours, "DB_URL"),
            "DB_URL keeps the rotated value",
        );
        p.target(
            merged.vault().is_some_and(|v| v.policy == ours_policy),
            "the policy is kept",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

/// Arm 1 on format 3, with no lineage to show that ours contains theirs: the
/// forged ancestor is no authority, so the merge is two-way. The cherry-pick
/// stops with a conflict, keeps the rotated `DB_URL` and the policy, and
/// signs nothing.
#[test]
fn row_r_i11_a_1_v3() {
    check("R-I11-a:1-v3", |p| {
        let control = TempDir::new().unwrap();
        genuine_fork_merges(control.path())?;
        let base = TempDir::new().unwrap();
        let replay = replay_into_rotated(base.path(), false, &Ancestor::Forged);
        let (merged, ours, theirs) = (&replay.merged, &replay.ours, &replay.theirs);
        require_ran(p, merged, "cherry-pick")?;
        old_revision_is_refused(&replay.team, theirs)?;
        p.reached();
        let ours_policy = parse(ours).unwrap().policy;
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            merged.secret("DB_URL") == secret_in(ours, "DB_URL"),
            "DB_URL keeps the rotated value",
        );
        p.target(
            merged.vault().is_some_and(|v| v.policy == ours_policy),
            "the policy is kept",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

/// As the format-3 arm 1, with the forged ancestor numbered at theirs'
/// counter: theirs changed the vault but is not numbered above the ancestor,
/// so the driver refuses theirs as rolled back and leaves ours, byte for byte.
#[test]
fn row_r_i11_a_1_v3_counter() {
    check("R-I11-a:1-v3-counter", |p| {
        let base = TempDir::new().unwrap();
        let replay = replay_into_rotated(base.path(), false, &Ancestor::Counted);
        let (merged, ours) = (&replay.merged, &replay.ours);
        require_ran(p, merged, "cherry-pick")?;
        p.reached();
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            merged
                .stderr
                .contains("theirs failed its authenticity check")
                && merged.stderr.contains("rolled back"),
            "stderr names theirs as rolled back",
        );
        p.target(
            &merged.file == ours,
            "the working file is ours, byte for byte",
        );
        Ok(())
    });
}

/// An ancestor this key cannot read is never an authority. A cherry-pick of
/// R0's file over such an ancestor conflicts on the re-keyed secret instead
/// of reverting the rotation; the control, a genuine fork with its genuine
/// ancestor, merges.
#[test]
fn row_r_i11_b() {
    check("R-I11-b", |p| {
        let control = TempDir::new().unwrap();
        genuine_fork_merges(control.path())?;
        let base = TempDir::new().unwrap();
        let replay = replay_into_rotated(base.path(), false, &Ancestor::Unreadable);
        let (merged, ours) = (&replay.merged, &replay.ours);
        require_ran(p, merged, "cherry-pick")?;
        old_revision_is_refused(&replay.team, &replay.theirs)?;
        p.reached();
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            merged.stderr.contains("secrets.DB_URL"),
            "the conflict names the re-keyed DB_URL",
        );
        p.target(
            merged.secret("DB_URL") == secret_in(ours, "DB_URL"),
            "DB_URL keeps the rotated value",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

// ── R-I14-a: a grant both sides changed ──

/// Mint (or, with `renew`, replace) alice's grant `bot` for `only`, key file
/// at `out`.
fn grant_bot(mut cmd: assert_cmd::Command, only: &[&str], renew: bool, out: &Path) {
    cmd.args(["agent", "grant", "--name", "bot"]);
    for key in only {
        cmd.args(["--only", key]);
    }
    if renew {
        cmd.arg("--renew");
    }
    cmd.arg("--out").arg(out).assert().success();
}

/// Recipients `file` lists that `older` does not.
fn recipients_added(file: &[u8], older: &[u8]) -> Vec<String> {
    let older = parse(older).unwrap().recipients;
    parse(file)
        .unwrap()
        .recipients
        .into_iter()
        .filter(|r| !older.contains(r))
        .collect()
}

/// Alice's vault with a grant `bot` is the ancestor. Ours renews the grant
/// (a new key, another scope). Theirs renews it too, differently, or with
/// `theirs_renews` false only adds a secret. Merged with the real driver.
/// Returns the merge, the ancestor's and ours' files and theirs' file.
fn grant_merge(base: &Path, theirs_renews: bool) -> (Merged, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (alice, repo) = alice_repo(base);
    alice.add(&repo, "API_KEY", "api-key");
    grant_bot(
        alice.murk(&repo),
        &["DB_URL"],
        false,
        &base.join("bot0.key"),
    );
    use_merge_driver(&repo);
    let ancestor = working(&repo);

    git_ok(&repo, &["checkout", "-q", "-b", "theirs"]);
    let second = Laptop::new(base, "second", &alice);
    second.ok(&repo, &["trust", "--yes"]);
    if theirs_renews {
        grant_bot(
            second.command(&repo),
            &["API_KEY"],
            true,
            &base.join("bot2.key"),
        );
    } else {
        second.add(&repo, "THEIRS_ONLY", "theirs-only");
    }
    commit(&repo, "theirs");
    let theirs = working(&repo);
    git_ok(&repo, &["checkout", "-q", "main"]);

    grant_bot(
        alice.murk(&repo),
        &["DB_URL", "API_KEY"],
        true,
        &base.join("bot1.key"),
    );
    commit(&repo, "ours renews the grant");
    let ours = working(&repo);
    let merged = Merged::merge(&alice, &repo, "theirs");
    (merged, ancestor, ours, theirs)
}

/// Both sides change the same agent grant differently from a common ancestor
/// (each renews it, with another scope): the merged vault has no such grant,
/// neither side's key stays a recipient, and the merge names the grant. A
/// change on one side only is taken: ours' renewed key stays.
#[test]
fn row_r_i14_a() {
    check("R-I14-a", |p| {
        // Control: only ours renews the grant.
        let one_side = TempDir::new().unwrap();
        let (merged, ancestor, ours, _) = grant_merge(one_side.path(), false);
        p.require(merged.ran(), "the driver ran in the control")?;
        let renewed = recipients_added(&ours, &ancestor);
        p.require(renewed.len() == 1, "ours added one grant key")?;
        let kept = parse(&merged.file).unwrap().recipients;
        p.require(
            kept.contains(&renewed[0]),
            "a one-sided grant change is taken: ours' renewed key stays",
        )?;
        p.require(
            !merged.stderr.contains("grants.bot"),
            "a one-sided change is no conflict on the grant",
        )?;

        // Both sides renew it.
        let both = TempDir::new().unwrap();
        let (merged, ancestor, ours, theirs) = grant_merge(both.path(), true);
        require_ran(p, &merged, "merge")?;
        let ours_key = recipients_added(&ours, &ancestor);
        let theirs_key = recipients_added(&theirs, &ancestor);
        p.require(
            ours_key.len() == 1 && theirs_key.len() == 1 && ours_key != theirs_key,
            "each side minted its own grant key",
        )?;
        p.reached();
        let recipients = parse(&merged.file).unwrap().recipients;
        p.target(!merged.ok, "the merge reports a conflict");
        p.target(
            merged.stderr.contains("grants.bot"),
            "the conflict names the grant",
        );
        p.target(
            !recipients.contains(&ours_key[0]),
            "ours' grant key is not kept",
        );
        p.target(
            !recipients.contains(&theirs_key[0]),
            "theirs' grant key is not kept",
        );
        Ok(())
    });
}

// ── R-I10-g: an ancestor signed by a removed member ──

/// Main's history: alice's vault (`DB_URL`, `K`) with bob a member (C1); bob
/// saves (C2, signed by bob, accepted by alice); alice sets a policy (C2a);
/// alice removes bob (C3); alice adds `O1` (ours).
struct Offboarded {
    alice: Machine,
    repo: PathBuf,
    /// Bob's revision, below the removal's generation.
    c2: String,
    /// Alice's child of it: still lists bob.
    c2a: String,
    c2a_file: Vec<u8>,
    c3: String,
    c3_file: Vec<u8>,
    /// Main's tip.
    ours: Vec<u8>,
}

impl Offboarded {
    fn new(base: &Path) -> Self {
        let (alice, repo) = alice_repo(base);
        alice.add(&repo, "K", "k-value");
        let bob = Machine::new(base, "bob");
        bob.init(&base.join("bob-scratch"), "bob");
        authorize(&alice, &repo, &bob, "bob");
        use_merge_driver(&repo);
        let bob = Laptop {
            key: bob.key_file(),
            machine: bob,
        };
        bob.ok(&repo, &["trust", "--yes"]);
        bob.add(&repo, "PRE", "pre");
        commit(&repo, "bob saves");
        let c2 = head_commit(&repo);
        murk_ok(&alice, &repo, &["trust", "--yes"]);
        murk_ok(&alice, &repo, &["policy", "set", "--allow-tag", "nothing"]);
        commit(&repo, "alice saves");
        let (c2a, c2a_file) = (head_commit(&repo), working(&repo));
        murk_ok(&alice, &repo, &["circle", "revoke", "bob"]);
        commit(&repo, "alice removes bob");
        let (c3, c3_file) = (head_commit(&repo), working(&repo));
        alice.add(&repo, "O1", "o1");
        commit(&repo, "add O1");
        let ours = working(&repo);
        Self {
            alice,
            repo,
            c2,
            c2a,
            c2a_file,
            c3,
            c3_file,
            ours,
        }
    }

    /// A genuine revision on top of C3 (alice's second laptop adds `T1`),
    /// committed on branch `theirs` as a child of `parent`.
    fn theirs_under(&self, base: &Path, parent: &str) -> Vec<u8> {
        let second = Laptop::new(base, "second", &self.alice);
        git_ok(&self.repo, &["checkout", "-q", "-b", "build", &self.c3]);
        second.ok(&self.repo, &["trust", "--yes"]);
        second.add(&self.repo, "T1", "t1");
        commit(&self.repo, "build theirs");
        let file = working(&self.repo);
        git_ok(&self.repo, &["checkout", "-q", "-b", "theirs", parent]);
        put(&self.repo, &file, "theirs, under another parent");
        git_ok(&self.repo, &["checkout", "-q", "main"]);
        file
    }

    fn get(&self, key: &str) -> Option<String> {
        let out = self
            .alice
            .murk(&self.repo)
            .args(["get", key])
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Arm 1: theirs is a revision ours descends from (C2a, a child of the
/// bob-signed C2, on a branch that forks at C2) and the merge base is bob's
/// revision. Ours already contains theirs, so the merge exits 0 with ours
/// kept byte for byte, whoever signed the ancestor.
#[test]
fn row_r_i10_g_1() {
    check("R-I10-g:1", |p| {
        // Control: the same shape over an ancestor alice signed (C2a, with C3,
        // her removal of bob, as theirs) merges.
        let control = TempDir::new().unwrap();
        let scene = Offboarded::new(control.path());
        git_ok(&scene.repo, &["checkout", "-q", "-b", "pr", &scene.c2a]);
        put(&scene.repo, &scene.c3_file, "pr: C3 under C2a");
        git_ok(&scene.repo, &["checkout", "-q", "main"]);
        let merged = Merged::merge(&scene.alice, &scene.repo, "pr");
        p.require(
            merged.ran() && merged.ok,
            format!(
                "a revision ours contains, over an alice-signed ancestor, merges: {}",
                merged.stderr
            ),
        )?;

        let base = TempDir::new().unwrap();
        let scene = Offboarded::new(base.path());
        let repo = &scene.repo;
        git_ok(repo, &["checkout", "-q", "-b", "pr", &scene.c2]);
        put(repo, &scene.c2a_file, "pr: alice's revision under bob's");
        git_ok(repo, &["checkout", "-q", "main"]);
        let merged = Merged::merge(&scene.alice, repo, "pr");
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(merged.ok, "the merge exits 0");
        p.target(
            merged.file == scene.ours,
            "the working file is ours, byte for byte",
        );
        p.target(
            merged.stderr.contains("already contains"),
            "the driver says ours already contains theirs",
        );
        Ok(())
    });
}

/// Arm 2: ours (`O1` added) and a genuine revision of another branch (`T1`
/// added) both descend from C3, but the commit under theirs is bob's C2 and
/// that is the merge base. An ancestor signed by a removed member is no
/// authority: the merge conflicts instead of using it, so every one-sided
/// addition is a conflict. With an ancestor alice signed (C2a) the same merge
/// is clean.
#[test]
fn row_r_i10_g_2() {
    check("R-I10-g:2", |p| {
        // Control: the ancestor is alice's.
        let control = TempDir::new().unwrap();
        let scene = Offboarded::new(control.path());
        scene.theirs_under(control.path(), &scene.c2a);
        let merged = Merged::merge(&scene.alice, &scene.repo, "theirs");
        p.require(
            merged.ran() && merged.ok,
            format!("an alice-signed ancestor merges: {}", merged.stderr),
        )?;
        p.require(
            scene.get("T1").as_deref() == Some("t1\n")
                && scene.get("O1").as_deref() == Some("o1\n"),
            "the control keeps both additions",
        )?;

        // Bob's revision as the ancestor.
        let base = TempDir::new().unwrap();
        let scene = Offboarded::new(base.path());
        scene.theirs_under(base.path(), &scene.c2);
        let merged = Merged::merge(&scene.alice, &scene.repo, "theirs");
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(!merged.ok, "the merge stops with a conflict");
        p.target(
            merged.stderr.contains("secrets.O1") && merged.stderr.contains("secrets.T1"),
            "the conflicts name O1 and T1",
        );
        p.target(
            merged.stderr.contains("ancestor"),
            "the driver names the ancestor",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

/// Arm 1 on format 3, with no lineage to show that ours contains theirs:
/// bob's revision is no authority, so the merge of alice's C2a into main is
/// two-way. It conflicts on recipient bob and on `O1`, keeps ours' values and
/// policy, and signs nothing.
#[test]
fn row_r_i10_g_1_v3() {
    check("R-I10-g:1-v3", |p| {
        let base = TempDir::new().unwrap();
        let scene = Offboarded::new(base.path());
        let repo = &scene.repo;
        git_ok(repo, &["checkout", "-q", "-b", "pr", &scene.c2]);
        put(repo, &scene.c2a_file, "pr: alice's revision under bob's");
        git_ok(repo, &["checkout", "-q", "main"]);
        let merged = Merged::merge(&scene.alice, repo, "pr");
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(!merged.ok, "the merge stops with a conflict");
        p.target(
            merged.stderr.contains("recipients.") && merged.stderr.contains("secrets.O1"),
            "the conflicts name the recipient bob and O1",
        );
        for key in ["DB_URL", "K", "PRE", "O1"] {
            p.target(
                merged.secret(key) == secret_in(&scene.ours, key),
                format!("{key} keeps ours' value"),
            );
        }
        let ours_policy = parse(&scene.ours).unwrap().policy;
        p.target(
            merged.vault().is_some_and(|v| v.policy == ours_policy),
            "the policy is ours'",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

// ── R-I11-d: a merge against an ancestor that is no authority is two-way ──

/// One murk command, with the value it reads from stdin (empty: none).
type Op = (Vec<String>, String);

fn op(args: &[&str]) -> Op {
    (
        args.iter().map(|a| (*a).to_string()).collect(),
        String::new(),
    )
}

fn op_in(args: &[&str], stdin: &str) -> Op {
    (
        args.iter().map(|a| (*a).to_string()).collect(),
        format!("{stdin}\n"),
    )
}

/// A vault file derived from `from` on a laptop of its own: `from` is trusted
/// there, then each of `ops` runs. A fresh directory per `tag`.
fn derive(base: &Path, tag: &str, laptop: &Laptop, from: &[u8], ops: &[Op]) -> Vec<u8> {
    let dir = base.join(tag);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(".murk"), from).unwrap();
    laptop.ok(&dir, &["trust", "--yes"]);
    for (args, stdin) in ops {
        laptop
            .command(&dir)
            .args(args)
            .write_stdin(stdin.as_str())
            .assert()
            .success();
    }
    working(&dir)
}

/// What the merge driver left for one run on three files.
struct Driven {
    ok: bool,
    stderr: String,
    result: Vec<u8>,
}

/// `murk merge-driver` run by `cmd` on the three files (what every git caller
/// runs), in `dir`. `anchor` is a `MURK_TRUSTED_SIGNERS` value.
fn drive(
    mut cmd: assert_cmd::Command,
    dir: &Path,
    files: [&[u8]; 3],
    anchor: Option<&str>,
) -> Driven {
    let [base, ours, theirs] = ["base.murk", "ours.murk", "theirs.murk"].map(|n| dir.join(n));
    for (path, bytes) in [&base, &ours, &theirs].into_iter().zip(files) {
        fs::write(path, bytes).unwrap();
    }
    if let Some(anchor) = anchor {
        cmd.env("MURK_TRUSTED_SIGNERS", anchor);
    }
    let out = cmd
        .arg("merge-driver")
        .args([&base, &ours, &theirs])
        .arg(".murk")
        .output()
        .unwrap();
    Driven {
        ok: out.status.success(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        result: fs::read(&ours).unwrap(),
    }
}

/// `result` holds nothing of theirs: every vault part is ours', and it
/// carries no signature.
fn keeps_ours(result: &[u8], ours: &[u8]) -> bool {
    let (Some(r), Some(o)) = (parse(result), parse(ours)) else {
        return false;
    };
    let sorted = |v: &Vault| {
        let mut recipients = v.recipients.clone();
        recipients.sort();
        recipients
    };
    sorted(&r) == sorted(&o)
        && r.schema == o.schema
        && r.secrets == o.secrets
        && r.policy == o.policy
        && r.agents == o.agents
        && r.meta == o.meta
        && r.sig.is_none()
}

/// `result` carries no signature that `ours` did not already carry: either
/// the driver wrote nothing signed, or it left ours as it was.
fn nothing_new_signed(result: &[u8], ours: &[u8]) -> bool {
    result == ours || parse(result).is_some_and(|v| v.sig.is_none())
}

/// With an ancestor that is not an authority (here a forged unsigned file with
/// no entries), every one-sided change to a vault part conflicts and keeps
/// ours: a secret in each tier, a description, the policy, a recipient, an
/// agent grant, a group. One cell per change, driven through the real merge
/// driver. Every cell is also run over the vault itself with its signature
/// stripped (id and MAC intact): that ancestor is no authority either, so
/// each cell conflicts and nothing new is signed.
#[test]
fn row_r_i11_d_two_way() {
    check("R-I11-d:two-way", |p| {
        let base = TempDir::new().unwrap();
        let team = Team::new(base.path());
        let (carol, dave) = (
            Machine::new(base.path(), "carol"),
            Machine::new(base.path(), "dave"),
        );
        carol.init(&base.path().join("carol-scratch"), "carol");
        dave.init(&base.path().join("dave-scratch"), "dave");
        let (alice, repo) = (&team.alice, &team.repo);
        authorize(alice, repo, &carol, "carol");
        alice
            .murk(repo)
            .args(["add", "API_KEY", "--group", "me"])
            .write_stdin("alices-api-key\n")
            .assert()
            .success();
        murk_ok(
            alice,
            repo,
            &["describe", "DB_URL", "primary database", "--tag", "a"],
        );
        murk_ok(alice, repo, &["policy", "set", "--allow-tag", "a"]);
        murk_ok(alice, repo, &["group", "create", "ops"]);
        murk_ok(alice, repo, &["group", "add", "ops", "--member", "bob"]);
        murk_ok(
            alice,
            repo,
            &[
                "agent", "grant", "--name", "bot", "--only", "DB_URL", "--out", "-",
            ],
        );
        commit(repo, "the vault every cell starts from");
        let vault = working(repo);
        let ancestor = forged_ancestor(alice, &vault, &[], false);
        let stripped = {
            let mut unsigned = parse(&vault).unwrap();
            unsigned.sig = None;
            to_file(&unsigned)
        };
        let second = Laptop::new(base.path(), "second", alice);

        let (dave_key, carol_key) = (dave.pubkey(), carol.pubkey());
        #[rustfmt::skip]
        let cells: Vec<(&str, &str, Vec<Op>, Vec<Op>)> = vec![
            ("secret added", "secrets.NEW_S", vec![], vec![op_in(&["add", "NEW_S"], "new")]),
            ("secret removed", "secrets.DB_URL", vec![], vec![op(&["rm", "DB_URL"])]),
            ("shared value changed", "secrets.DB_URL", vec![], vec![op_in(&["add", "DB_URL"], "changed")]),
            ("private value added", "DB_URL", vec![], vec![op_in(&["add", "DB_URL", "--group", "me"], "mine")]),
            ("private value changed", "API_KEY", vec![], vec![op_in(&["add", "API_KEY", "--group", "me"], "mine-changed")]),
            ("group value added", "secrets.TEAM_K", vec![], vec![op_in(&["add", "TEAM_K", "--group", "ops"], "team")]),
            ("description changed", "schema.DB_URL", vec![], vec![op(&["describe", "DB_URL", "a new description"])]),
            ("policy changed", "policy", vec![], vec![op(&["policy", "set", "--allow-tag", "b"])]),
            ("policy removed", "policy", vec![], vec![op(&["policy", "clear"])]),
            ("policy added", "policy", vec![op(&["policy", "clear"])], vec![op(&["policy", "clear"]), op(&["policy", "set", "--allow-tag", "b"])]),
            ("recipient added", "recipients.", vec![], vec![op(&["circle", "authorize", &dave_key, "--name", "dave"])]),
            ("recipient removed", "recipients.", vec![], vec![op(&["circle", "revoke", &carol_key])]),
            ("grant added", "grants.bot2", vec![], vec![op(&["agent", "grant", "--name", "bot2", "--only", "DB_URL", "--out", "-"])]),
            ("grant removed", "grants.bot", vec![], vec![op(&["agent", "revoke", "bot"])]),
            ("grant changed", "grants.bot", vec![], vec![op(&["agent", "grant", "--name", "bot", "--only", "DB_URL", "--renew", "--out", "-"])]),
            ("group created", "groups.devs", vec![], vec![op(&["group", "create", "devs"])]),
            ("group member added", "groups.ops", vec![], vec![op(&["group", "add", "ops", "--member", "carol"])]),
            ("group member removed", "groups.ops", vec![], vec![op(&["group", "rm", "ops", "--member", "bob"])]),
            ("group deleted", "groups.ops", vec![], vec![op(&["group", "rm", "ops"])]),
        ];

        // Control: with the genuine vault as the ancestor, a secret only
        // theirs added is taken.
        let added = derive(
            base.path(),
            "control-theirs",
            &second,
            &vault,
            &[op_in(&["add", "NEW_S"], "new")],
        );
        let dir = base.path().join("control");
        fs::create_dir_all(&dir).unwrap();
        let run = drive(alice.murk(repo), &dir, [&vault, &vault, &added], None);
        p.require(
            run.ok && parse(&run.result).is_some_and(|v| v.secrets.contains_key("NEW_S")),
            format!(
                "an authority ancestor takes the one-sided add: {}",
                run.stderr
            ),
        )?;

        p.reached();
        for (n, (name, field, ours_ops, theirs_ops)) in cells.iter().enumerate() {
            let tag = format!("cell{n}");
            let ours = derive(
                base.path(),
                &format!("{tag}-ours"),
                &second,
                &vault,
                ours_ops,
            );
            let theirs = derive(
                base.path(),
                &format!("{tag}-theirs"),
                &second,
                &vault,
                theirs_ops,
            );
            let dir = base.path().join(&tag);
            fs::create_dir_all(&dir).unwrap();
            let run = drive(alice.murk(repo), &dir, [&ancestor, &ours, &theirs], None);
            p.require(
                run.ok || run.stderr.contains("conflict"),
                format!("{name}: the merge driver ran: {}", run.stderr),
            )?;
            let conflicts = !run.ok && run.stderr.contains(field) && keeps_ours(&run.result, &ours);
            p.target(
                conflicts,
                format!("{name}: a conflict naming {field}, ours kept"),
            );
            let dir = base.path().join(format!("{tag}-stripped"));
            fs::create_dir_all(&dir).unwrap();
            let run = drive(alice.murk(repo), &dir, [&stripped, &ours, &theirs], None);
            p.require(
                run.ok || run.stderr.contains("conflict"),
                format!("{name}: the merge driver ran: {}", run.stderr),
            )?;
            p.target(
                !run.ok && nothing_new_signed(&run.result, &ours),
                format!(
                    "{name}: over the unsigned vault as ancestor, a conflict and nothing new signed"
                ),
            );
        }
        Ok(())
    });
}

/// Both sides of a merge are murk 0.13 files: the merge runs three-way on the
/// raw ancestor, whatever shape it has (a genuine signed file, an unsigned
/// one, an empty forged one). Run on a machine with no pin, anchored by the
/// environment, so the 0.13 sides are read as history.
#[test]
fn row_r_i11_d_legacy() {
    check("R-I11-d:legacy", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo) = alice_repo(base.path());
        use_merge_driver(&repo);
        let v0 = working(&repo);
        let second = Laptop::new(base.path(), "second", &alice);
        let ours = derive(
            base.path(),
            "ours",
            &second,
            &v0,
            &[op_in(&["add", "OURS_K"], "o")],
        );
        let theirs = derive(
            base.path(),
            "theirs",
            &second,
            &v0,
            &[op_in(&["add", "THEIRS_K"], "t")],
        );

        let id = murk_cli::crypto::parse_identity(&alice.secret_key()).unwrap();
        let legacy = |bytes: &[u8]| {
            let mut vault = parse(bytes).unwrap();
            forgery::reseal_v1(&mut vault, &id);
            vault
        };
        let (genuine, ours, theirs) = (legacy(&v0), legacy(&ours), legacy(&theirs));
        let unsigned = {
            let mut vault = genuine.clone();
            forgery::strip_v1(&mut vault, &id);
            vault
        };
        let empty = parse(&forged_ancestor(&alice, &v0, &[], false)).unwrap();
        let (anchor, _) = alice.signer_entry(&repo);
        p.reached();
        for (shape, ancestor) in [
            ("a genuine signed file", genuine),
            ("an unsigned file", unsigned),
            ("an empty forged file", empty),
        ] {
            let dir = base.path().join(shape.replace(' ', "-"));
            fs::create_dir_all(&dir).unwrap();
            let fresh = Laptop::new(base.path(), &format!("fresh-{}", shape.len()), &alice);
            let run = drive(
                fresh.command(&repo),
                &dir,
                [&to_file(&ancestor), &to_file(&ours), &to_file(&theirs)],
                Some(&anchor),
            );
            p.note(format!("{shape}: {}", run.stderr.trim()));
            p.require(
                run.ok || run.stderr.contains("conflict"),
                format!("{shape}: the merge driver ran: {}", run.stderr),
            )?;
            let merged = parse(&run.result).unwrap();
            p.target(
                run.ok
                    && merged.secrets.contains_key("OURS_K")
                    && merged.secrets.contains_key("THEIRS_K"),
                format!(
                    "with {shape} as the ancestor the merge is three-way and keeps both additions"
                ),
            );
        }
        Ok(())
    });
}

// ── R-I11-e, R-I11-f, R-I11-g: every input genuine ──

/// A branch `pr` off `from` whose only commit holds `tip`, merged into main
/// as alice: the genuine merge base is `from`.
fn merge_graft(team: &Team, from: &str, tip: &[u8]) -> Merged {
    git_ok(&team.repo, &["checkout", "-q", "-b", "pr", from]);
    put(&team.repo, tip, "pr: change");
    git_ok(&team.repo, &["checkout", "-q", "main"]);
    Merged::merge(&team.alice, &team.repo, "pr")
}

/// Main rotates `DB_URL` and sets a policy (M3) and moves on. A branch off M3
/// holds the genuine file of a stale fork of R0 (eight saves by a second
/// laptop, or by alice's own machine with `same_machine`), still holding the
/// leaked value. Merged with the real driver.
fn stale_fork_merge(base: &Path, same_machine: bool) -> (Team, Vec<u8>, Merged) {
    let team = Team::new(base);
    let repo = &team.repo;
    git_ok(repo, &["checkout", "-q", "-b", "stale", &team.r0]);
    if same_machine {
        for i in 1..=8 {
            team.alice.add(repo, &format!("F{i}"), "fork");
        }
    } else {
        let second = Laptop::new(base, "stale-laptop", &team.alice);
        second.ok(repo, &["trust", "--yes"]);
        for i in 1..=8 {
            second.add(repo, &format!("F{i}"), "fork");
        }
    }
    commit(repo, "stale fork, eight saves");
    let stale = working(repo);
    git_ok(repo, &["checkout", "-q", "main"]);
    team.rotate_only();
    let m3 = head_commit(repo);
    team.alice.add(repo, "EXTRA", "extra");
    commit(repo, "main moves on");
    let ours = working(repo);
    let merged = merge_graft(&team, &m3, &stale);
    (team, ours, merged)
}

/// A merge of a genuine stale fork: its counter is above main's, its ancestor
/// (M3) is genuine, and nothing in the files tells it from a fork that
/// rotated nothing. The merge conflicts on `DB_URL` and the policy, keeps the
/// rotated value and signs nothing. The control, the same fork saved on
/// alice's own machine, is refused as rolled back.
#[test]
fn row_r_i11_e() {
    check("R-I11-e", |p| {
        let control = TempDir::new().unwrap();
        let (_, _, merged) = stale_fork_merge(control.path(), true);
        p.require(
            merged.ran() && !merged.ok && merged.stderr.contains("rolled back"),
            format!(
                "the same-machine fork is refused as rolled back: {}",
                merged.stderr
            ),
        )?;
        let base = TempDir::new().unwrap();
        let (_, ours, merged) = stale_fork_merge(base.path(), false);
        require_ran(p, &merged, "merge")?;
        p.reached();
        let ours_policy = parse(&ours).unwrap().policy;
        p.target(!merged.ok, "the merge stops with a conflict");
        p.target(
            merged.stderr.contains("secrets.DB_URL") && merged.stderr.contains("policy"),
            "the conflicts name DB_URL and the policy",
        );
        p.target(
            merged.secret("DB_URL") == secret_in(&ours, "DB_URL"),
            "DB_URL stays rotated",
        );
        p.target(
            merged.vault().is_some_and(|v| v.policy == ours_policy),
            "the policy is kept",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

/// Arm a: main adds `OLD_TOKEN` (A) and removes it again; a branch under A's
/// parent holds A's file. Ours already contains it, so the merge is a forward
/// change: exit 0, ours byte for byte, `OLD_TOKEN` stays absent.
#[test]
fn row_r_i11_f_a() {
    check("R-I11-f:a", |p| {
        let control = TempDir::new().unwrap();
        Retired::control(control.path())?;
        let base = TempDir::new().unwrap();
        let scene = Retired::new(base.path());
        let merged = merge_graft(&scene.team, &scene.team.r0, &scene.added_file);
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(merged.ok, "the merge exits 0");
        p.target(
            merged.file == scene.ours,
            "the working file is ours, byte for byte",
        );
        p.target(!merged.has("OLD_TOKEN"), "OLD_TOKEN stays removed");
        Ok(())
    });
}

/// Arm b: the branch under A's parent holds a genuine revision of an unmerged
/// branch off A, which still has `OLD_TOKEN`. A newer common revision (A)
/// makes the ancestor stale: the merge conflicts on `OLD_TOKEN`.
#[test]
fn row_r_i11_f_b() {
    check("R-I11-f:b", |p| {
        let control = TempDir::new().unwrap();
        Retired::control(control.path())?;
        let base = TempDir::new().unwrap();
        let scene = Retired::new(base.path());
        let unmerged = scene
            .team
            .fork(base.path(), "unmerged", &scene.added, "FORK_K");
        let merged = merge_graft(&scene.team, &scene.team.r0, &unmerged);
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(!merged.ok, "the merge stops with a conflict");
        p.target(
            merged.stderr.contains("secrets.OLD_TOKEN"),
            "the conflict names OLD_TOKEN",
        );
        p.target(!merged.has("OLD_TOKEN"), "OLD_TOKEN stays removed");
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

/// Arm c: as arm a, with an agent grant and its `agents` record in place of
/// `OLD_TOKEN`: ours revoked it, so the replayed grant must not come back.
#[test]
fn row_r_i11_f_c() {
    check("R-I11-f:c", |p| {
        let control = TempDir::new().unwrap();
        Retired::control(control.path())?;
        let base = TempDir::new().unwrap();
        let team = Team::new(base.path());
        let (alice, repo) = (&team.alice, &team.repo);
        murk_ok(
            alice,
            repo,
            &[
                "agent", "grant", "--name", "bot", "--only", "DB_URL", "--out", "-",
            ],
        );
        commit(repo, "grant bot");
        let granted = working(repo);
        murk_ok(alice, repo, &["agent", "revoke", "bot"]);
        commit(repo, "revoke bot");
        let ours = working(repo);
        let grant_key = recipients_added(&granted, &team.r0_file);
        p.require(
            grant_key.len() == 1 && parse(&ours).unwrap().agents.is_empty(),
            "the grant was minted and revoked",
        )?;
        let merged = merge_graft(&team, &team.r0, &granted);
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(merged.ok, "the merge exits 0");
        p.target(
            merged.file == ours,
            "the working file is ours, byte for byte",
        );
        p.target(
            merged
                .vault()
                .is_some_and(|v| v.agents.is_empty() && !v.recipients.contains(&grant_key[0])),
            "the grant's record and key are not back",
        );
        Ok(())
    });
}

/// The long line A (250 saves past P), the short line B (100 saves past P),
/// merged cleanly; then a stale tip of the long line (A90, which still holds
/// `OLD_TOKEN`, added at save 50 and removed at 150) under the old common
/// ancestor P. The old ancestor must not decide what changed: the attack
/// merge conflicts. Many saves: slow.
#[test]
fn row_r_i11_g() {
    check("R-I11-g", |p| {
        let base = TempDir::new().unwrap();
        let team = Team::new(base.path());
        let (alice, repo) = (&team.alice, &team.repo);
        git_ok(repo, &["checkout", "-q", "-b", "short", &team.r0]);
        let second = Laptop::new(base.path(), "second", alice);
        second.ok(repo, &["trust", "--yes"]);
        for i in 1..=100 {
            second.add(repo, &format!("B{i}"), "b");
        }
        commit(repo, "short line, 100 saves");
        git_ok(repo, &["checkout", "-q", "main"]);
        let mut a90 = Vec::new();
        for i in 1..=250 {
            match i {
                50 => alice.add(repo, "OLD_TOKEN", "old-token"),
                150 => murk_ok(alice, repo, &["rm", "OLD_TOKEN"]),
                _ => alice.add(repo, &format!("A{i}"), "a"),
            }
            if i == 90 {
                a90 = working(repo);
            }
        }
        commit(repo, "long line, 250 saves");
        let a250 = working(repo);
        p.require(
            parse(&a90).is_some_and(|v| v.secrets.contains_key("OLD_TOKEN"))
                && parse(&a250).is_some_and(|v| !v.secrets.contains_key("OLD_TOKEN")),
            "A90 holds OLD_TOKEN and A250 does not",
        )?;
        let honest = Merged::merge(alice, repo, "short");
        p.require(
            honest.ran() && honest.ok && honest.has("A250") && honest.has("B100"),
            format!(
                "the honest merge of the two lines is clean: {}",
                honest.stderr
            ),
        )?;
        let attack = merge_graft(&team, &team.r0, &a90);
        require_ran(p, &attack, "attack merge")?;
        p.reached();
        p.target(!attack.ok, "the attack merge conflicts");
        p.target(!attack.has("OLD_TOKEN"), "OLD_TOKEN stays removed");
        p.target(!attack.signed(), "nothing is signed");
        Ok(())
    });
}

// ── R-I12-b, R-I13-b: a refused input leaves ours as it was ──

/// Every pin and sidecar file of `who` with its bytes.
fn pin_state(who: &Machine) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files: Vec<_> = pin_files(who)
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    files.sort();
    files
}

/// What `murk verify` says as alice: (success, stdout and stderr).
fn verify_of(alice: &Machine, repo: &Path) -> (bool, String) {
    let out = alice.murk(repo).arg("verify").output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// What alice's machine shows before a merge, to compare with after.
struct Before {
    ours: Vec<u8>,
    pins: Vec<(PathBuf, Vec<u8>)>,
    verify: (bool, String),
}

impl Before {
    fn of(alice: &Machine, repo: &Path) -> Result<Self, String> {
        let loads = alice.murk(repo).args(["get", "DB_URL"]).output().unwrap();
        if loads.stdout != b"prod-db\n" {
            return Err("ours does not load before the merge".into());
        }
        Ok(Self {
            ours: working(repo),
            pins: pin_state(alice),
            verify: verify_of(alice, repo),
        })
    }

    /// After a merge that refused an input: the working file is ours, it
    /// loads and verifies as before, the pin is untouched and `injected`, the
    /// recipient the refused input added, is not in the file.
    fn refused_input_leaves_ours(
        &self,
        p: &mut Probe,
        alice: &Machine,
        repo: &Path,
        merged: &Merged,
        injected: &str,
    ) {
        p.target(!merged.ok, "the merge stops");
        p.target(
            merged.file == self.ours,
            "the working file is ours, byte for byte",
        );
        p.target(
            alice
                .murk(repo)
                .args(["get", "DB_URL"])
                .output()
                .is_ok_and(|o| o.status.success() && o.stdout == b"prod-db\n"),
            "ours still loads and prints its value",
        );
        p.target(
            verify_of(alice, repo) == self.verify,
            "murk verify reports as before the merge",
        );
        p.target(
            pin_state(alice) == self.pins,
            "the pin and its sidecar are unchanged",
        );
        let recipients = merged.vault().map(|v| v.recipients).unwrap_or_default();
        p.target(
            !recipients.iter().any(|r| r == injected),
            "the recipient the refused input adds is not in the file",
        );
    }
}

/// The side branch of a merge: a genuine save from alice's second laptop, or
/// one of two refused inputs.
enum Side {
    Genuine,
    /// The same save with a recipient added by hand afterwards, so its MAC no
    /// longer verifies.
    EditedRecipients,
    /// A vault an outsider (mallory) signed, listing alice and herself.
    Outsider,
    /// The genuine save re-written with a byte-order mark, so the vault
    /// parser cannot read it.
    Unparseable,
}

/// Alice's repo with the driver, a branch `side` off the fork point holding
/// `side`, and main moved on. Returns alice, the repo and the recipients the
/// side adds that alice never authorized.
fn side_scene(base: &Path, side: &Side) -> (Machine, PathBuf, Vec<String>) {
    let (alice, repo) = alice_repo(base);
    use_merge_driver(&repo);
    let fork_point = working(&repo);
    git_ok(&repo, &["checkout", "-q", "-b", "side"]);
    let second = Laptop::new(base, "second", &alice);
    second.ok(&repo, &["trust", "--yes"]);
    second.add(&repo, "SIDE_K", "side");
    let injected = match side {
        Side::Genuine => {
            commit(&repo, "side: a genuine save");
            Vec::new()
        }
        Side::EditedRecipients => {
            let mut vault = parse(&working(&repo)).unwrap();
            vault.recipients.push(common::FOREIGN_PK.to_string());
            put(&repo, &to_file(&vault), "side: adds a recipient");
            vec![common::FOREIGN_PK.to_string()]
        }
        Side::Outsider => {
            let forged = fs::read(mallory_vault(
                base,
                &[("alice", alice.pubkey())],
                &[("DB_URL", "postgres://attacker")],
            ))
            .unwrap();
            put(&repo, &forged, "side: signed by an outsider");
            recipients_added(&forged, &fork_point)
        }
        Side::Unparseable => {
            let saved = working(&repo);
            put(
                &repo,
                &[&b"\xef\xbb\xbf"[..], &saved].concat(),
                "side: re-saved with a byte-order mark",
            );
            Vec::new()
        }
    };
    git_ok(&repo, &["checkout", "-q", "main"]);
    alice.add(&repo, "MAIN_K", "main");
    commit(&repo, "main moves on");
    (alice, repo, injected)
}

/// A genuine side merges; the same merge with `refused` as theirs is refused
/// and the file stays ours, byte for byte. Nothing of theirs reaches the
/// file, so a later `murk trust` cannot sign it by accident.
fn refused_side(p: &mut Probe, refused: &Side) -> Result<(), String> {
    let control = TempDir::new().unwrap();
    let (alice, repo, _) = side_scene(control.path(), &Side::Genuine);
    let merged = Merged::merge(&alice, &repo, "side");
    p.require(
        merged.ran() && merged.ok,
        format!("a genuine side merges: {}", merged.stderr),
    )?;
    let base = TempDir::new().unwrap();
    let (alice, repo, injected) = side_scene(base.path(), refused);
    p.require(injected.len() == 1, "the refused side adds one recipient")?;
    let before = Before::of(&alice, &repo)?;
    let merged = Merged::merge(&alice, &repo, "side");
    require_ran(p, &merged, "merge")?;
    p.reached();
    p.target(
        merged
            .stderr
            .contains("theirs failed its authenticity check"),
        "stderr names theirs as refused",
    );
    before.refused_input_leaves_ours(p, &alice, &repo, &merged, &injected[0]);
    Ok(())
}

/// Theirs fails its MAC (an edit added a recipient without recomputing it).
/// The driver refuses it and writes ours byte for byte.
#[test]
fn row_r_i12_b() {
    check("R-I12-b", |p| refused_side(p, &Side::EditedRecipients));
}

/// Theirs is signed outside the anchor and adds a recipient (mallory, whose
/// own vault it is). The side check fails: the file stays ours.
#[test]
fn row_r_i13_b_theirs() {
    check("R-I13-b:theirs", |p| refused_side(p, &Side::Outsider));
}

/// Theirs cannot be parsed (a genuine save re-written with a byte-order
/// mark). The driver never merges it as text: it writes both sides between
/// conflict markers, a file that never loads and so can never be signed, and
/// the pin and its sidecar are unchanged.
#[test]
fn row_r_i13_b_unparseable() {
    check("R-I13-b:unparseable", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, _) = side_scene(base.path(), &Side::Unparseable);
        let before = Before::of(&alice, &repo)?;
        let merged = Merged::merge(&alice, &repo, "side");
        p.require(
            merged.stderr.contains("murk never merges a vault as text"),
            format!("the murk driver refused the input: {}", merged.stderr),
        )?;
        p.reached();
        p.target(!merged.ok, "the merge stops");
        p.target(
            merged.file.starts_with(b"<<<<<<< ours"),
            "the working file holds both sides between conflict markers",
        );
        p.target(
            merged.vault().is_none(),
            "the working file is not a vault, so it carries no signature",
        );
        p.target(
            !alice
                .murk(&repo)
                .args(["get", "DB_URL"])
                .output()
                .unwrap()
                .status
                .success(),
            "the working file does not load",
        );
        p.target(
            pin_state(&alice) == before.pins,
            "the pin and its sidecar are unchanged",
        );
        Ok(())
    });
}

/// A cherry-pick of a genuine revision (alice's second laptop authorizes
/// `mal`) under R0's file as the ancestor, or with `tamper` under that file
/// with its schema edited, so its MAC no longer verifies. Main moved on.
/// Returns the team, `mal`'s key and the commit to pick.
fn ancestor_scene(base: &Path, tamper: bool) -> (Team, String, String) {
    let team = Team::new(base);
    let (alice, repo) = (&team.alice, &team.repo);
    let mal = Machine::new(base, "mal");
    mal.init(&base.join("mal-scratch"), "mal");
    let second = Laptop::new(base, "second", alice);
    git_ok(repo, &["checkout", "-q", "-b", "theirs", &team.r0]);
    second.ok(repo, &["trust", "--yes"]);
    second.ok(
        repo,
        &["circle", "authorize", &mal.pubkey(), "--name", "mal"],
    );
    commit(repo, "theirs: authorize mal");
    let theirs = working(repo);
    git_ok(repo, &["checkout", "-q", "main"]);
    alice.add(repo, "MAIN_K", "main");
    commit(repo, "main moves on");
    let mut ancestor = parse(&team.r0_file).unwrap();
    if tamper {
        ancestor.schema.get_mut("DB_URL").unwrap().description = "edited".into();
    }
    let evil = attack_branch(repo, "evil", &team.r0, &to_file(&ancestor), &theirs);
    (team, mal.pubkey(), evil)
}

/// The ancestor's MAC does not verify (its schema was edited). The driver
/// refuses the whole merge and writes ours byte for byte, so the recipient a
/// genuine revision adds does not reach the file either. With an untampered
/// ancestor the driver merges the two sides and reports only the recipient.
#[test]
fn row_r_i13_b_ancestor() {
    check("R-I13-b:ancestor", |p| {
        let control = TempDir::new().unwrap();
        let (team, _, evil) = ancestor_scene(control.path(), false);
        let merged = Merged::cherry_pick(&team.alice, &team.repo, &evil);
        p.require(
            merged.ran()
                && merged.stderr.contains("recipients.")
                && !merged.stderr.contains("authenticity check"),
            format!("an untampered ancestor is merged on: {}", merged.stderr),
        )?;
        let base = TempDir::new().unwrap();
        let (team, mal, evil) = ancestor_scene(base.path(), true);
        let (alice, repo) = (&team.alice, &team.repo);
        let before = Before::of(alice, repo)?;
        let merged = Merged::cherry_pick(alice, repo, &evil);
        require_ran(p, &merged, "cherry-pick")?;
        p.reached();
        p.target(
            merged.stderr.contains("ancestor") && merged.stderr.contains("authenticity"),
            "stderr names the ancestor as refused",
        );
        before.refused_input_leaves_ours(p, alice, repo, &merged, &mal);
        Ok(())
    });
}

// ── R-I20-b: a merge must not empty a group ──

/// Group `ops` holds `GROUP_K` and bob is its only member (alice left it).
/// Theirs, on another laptop, revokes bob: the group's last member, which
/// `circle revoke` allows only with `--allow-orphan`. With `revoke` ours
/// revokes him too, so the recipient lists agree and only the group is left
/// to object; without it neither side does and theirs only adds a secret.
/// Main adds a secret. Merged with the real driver.
fn group_merge(base: &Path, revoke: bool) -> Merged {
    let (alice, repo) = alice_repo(base);
    let bob = Machine::new(base, "bob");
    bob.init(&base.join("bob-scratch"), "bob");
    authorize(&alice, &repo, &bob, "bob");
    murk_ok(&alice, &repo, &["group", "create", "ops"]);
    alice
        .murk(&repo)
        .args(["add", "GROUP_K", "--group", "ops"])
        .write_stdin("group-value\n")
        .assert()
        .success();
    murk_ok(&alice, &repo, &["group", "add", "ops", "--member", "bob"]);
    murk_ok(
        &alice,
        &repo,
        &["group", "rm", "ops", "--member", &alice.pubkey()],
    );
    use_merge_driver(&repo);
    let fork_point = head_commit(&repo);
    let second = Laptop::new(base, "second", &alice);
    git_ok(&repo, &["checkout", "-q", "-b", "theirs", &fork_point]);
    second.ok(&repo, &["trust", "--yes"]);
    if revoke {
        second.ok(&repo, &["circle", "revoke", "bob", "--allow-orphan"]);
    } else {
        second.add(&repo, "THEIRS_K", "theirs");
    }
    commit(&repo, "theirs");
    git_ok(&repo, &["checkout", "-q", "main"]);
    if revoke {
        murk_ok(
            &alice,
            &repo,
            &["circle", "revoke", "bob", "--allow-orphan"],
        );
    }
    alice.add(&repo, "MAIN_K", "main");
    commit(&repo, "main moves on");
    Merged::merge(&alice, &repo, "theirs")
}

/// A merge that would leave a group's values with no member who is still a
/// recipient conflicts: theirs revokes bob, the group's last member (ours
/// agrees on the recipient list), and the merge names the group's value. The
/// control, the same merge with no revoke on either side, is clean.
#[test]
fn row_r_i20_b() {
    check("R-I20-b", |p| {
        let control = TempDir::new().unwrap();
        let merged = group_merge(control.path(), false);
        p.require(
            merged.ran() && merged.ok,
            format!("the merge without the revoke is clean: {}", merged.stderr),
        )?;
        let base = TempDir::new().unwrap();
        let merged = group_merge(base.path(), true);
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(!merged.ok, "the merge stops with a conflict");
        p.target(
            merged.stderr.contains("secrets.GROUP_K") && merged.stderr.contains("group ops"),
            "the conflict names the orphaned group value",
        );
        p.target(!merged.signed(), "nothing is signed");
        Ok(())
    });
}

// ── R-L-rebase, R-L-gitrevert: what git hands the driver ──

/// `git pull --rebase` with two local vault commits over one upstream vault
/// commit (saved on another laptop): both picks merge cleanly through the
/// driver, and a teammate reads the result.
#[test]
fn row_r_l_rebase() {
    check("R-L-rebase", |p| {
        let base = TempDir::new().unwrap();
        let team = Team::new(base.path());
        let (alice, repo) = (&team.alice, &team.repo);
        let origin = base.path().join("origin.git");
        let url = origin.to_str().unwrap();
        git_ok(
            base.path(),
            &["clone", "-q", "--bare", repo.to_str().unwrap(), url],
        );
        git_ok(repo, &["remote", "add", "origin", url]);
        git_ok(repo, &["fetch", "-q", "origin"]);
        git_ok(repo, &["branch", "--set-upstream-to=origin/main", "main"]);

        let upstream = base.path().join("upstream-repo");
        git_ok(
            base.path(),
            &["clone", "-q", url, upstream.to_str().unwrap()],
        );
        let laptop = Laptop::new(base.path(), "upstream", alice);
        laptop.ok(&upstream, &["trust", "--yes"]);
        laptop.add(&upstream, "UPSTREAM", "upstream");
        commit(&upstream, "upstream vault change");
        git_ok(&upstream, &["push", "-q", "origin", "main"]);

        alice.add(repo, "L1", "l1");
        commit(repo, "first local vault change");
        alice.add(repo, "L2", "l2");
        commit(repo, "second local vault change");
        let pulled = Merged::of(git_as(alice, repo, &["pull", "--rebase"]), repo);
        p.require(
            pulled.stderr.contains("vault merged cleanly"),
            format!("the driver ran: {}", pulled.stderr),
        )?;
        p.reached();
        p.note(pulled.stderr.trim().to_string());
        p.target(pulled.ok, "the rebase completes");
        p.target(
            pulled.stderr.matches("vault merged cleanly").count() == 2,
            "both picks merge cleanly through the driver",
        );
        p.target(
            ["L1", "L2", "UPSTREAM"].iter().all(|k| pulled.has(k)),
            "the result holds both local changes and the upstream one",
        );

        // A teammate (bob, on his own clone) reads what alice pushes.
        let bob_repo = base.path().join("bob-repo");
        git_ok(
            base.path(),
            &["clone", "-q", url, bob_repo.to_str().unwrap()],
        );
        let bob = Laptop {
            key: team.bob.key_file(),
            machine: Machine::new(base.path(), "bob-reader"),
        };
        git_ok(&bob_repo, &["checkout", "-q", &team.r0]);
        bob.ok(&bob_repo, &["trust", "--yes"]);
        let (pushed, push_stderr) = git_as(alice, repo, &["push", "-q", "origin", "main"]);
        p.require(pushed, format!("alice pushes: {push_stderr}"))?;
        git_ok(&bob_repo, &["checkout", "-q", "main"]);
        git_ok(&bob_repo, &["pull", "-q", "--ff-only"]);
        for key in ["L1", "L2", "UPSTREAM"] {
            let read = bob.command(&bob_repo).args(["get", key]).output().unwrap();
            p.target(read.status.success(), format!("the teammate reads {key}"));
        }
        Ok(())
    });
}

/// Alice's vault P and `deploy.yml`; commit C authorizes `mal` and changes the
/// workflow; commit H is a later vault change. Returns alice, the repo, P, C,
/// C's vault file and H's.
fn revert_scene(base: &Path) -> (Machine, PathBuf, String, String, Vec<u8>, Vec<u8>) {
    let (alice, repo) = alice_repo(base);
    fs::write(repo.join("deploy.yml"), "v1\n").unwrap();
    use_merge_driver(&repo);
    let p0 = head_commit(&repo);
    let mal = Machine::new(base, "mal");
    mal.init(&base.join("mal-scratch"), "mal");
    authorize(&alice, &repo, &mal, "mal");
    fs::write(repo.join("deploy.yml"), "v2-mal\n").unwrap();
    commit(&repo, "C: onboard mal and change the deploy workflow");
    let (c, c_file) = (head_commit(&repo), working(&repo));
    alice.add(&repo, "LATER", "later");
    commit(&repo, "H: a later vault change");
    let h_file = working(&repo);
    (alice, repo, p0, c, c_file, h_file)
}

/// `git revert` of a vault commit hands the driver the reverted commit as the
/// ancestor and its parent as theirs; ours already contains it. The revert
/// stops with a conflict on `.murk` and leaves it as it was, `mal` still a
/// recipient. The control, a branch under C's parent holding C's file merged
/// into main (a forward change), exits 0.
#[test]
fn row_r_l_gitrevert() {
    check("R-L-gitrevert", |p| {
        let control = TempDir::new().unwrap();
        let (alice, repo, p0, _, c_file, h_file) = revert_scene(control.path());
        git_ok(&repo, &["checkout", "-q", "-b", "side", &p0]);
        put(&repo, &c_file, "side: C's file under C's parent");
        git_ok(&repo, &["checkout", "-q", "main"]);
        let forward = Merged::merge(&alice, &repo, "side");
        p.require(
            forward.ran() && forward.ok,
            format!("the forward change exits 0: {}", forward.stderr),
        )?;

        let base = TempDir::new().unwrap();
        let (alice, repo, _, c, _, h_file2) = revert_scene(base.path());
        let reverted = Merged::of(git_as(&alice, &repo, &["revert", "--no-edit", &c]), &repo);
        require_ran(p, &reverted, "revert")?;
        p.reached();
        let unresolved = String::from_utf8_lossy(
            &git(&repo, &["diff", "--name-only", "--diff-filter=U"]).stdout,
        )
        .trim()
        .to_string();
        p.target(!reverted.ok, "the revert stops with a conflict");
        p.target(unresolved == ".murk", "the conflict is on .murk");
        p.target(
            reverted.file == h_file2,
            ".murk is byte for byte what it was (H's)",
        );
        p.target(
            reverted.stderr.contains("already contains"),
            "the driver says ours already contains the reverted commit",
        );
        p.target(
            forward.file == h_file,
            "the forward change keeps ours byte for byte",
        );
        Ok(())
    });
}

/// What a refused revert or cherry-pick of a vault commit must leave: git
/// stops with a conflict on `.murk`, the file is ours (H's) byte for byte,
/// and the driver names theirs as rolled back.
fn revert_refused(p: &mut Probe, repo: &Path, reverted: &Merged, h_file: &[u8]) {
    let unresolved =
        String::from_utf8_lossy(&git(repo, &["diff", "--name-only", "--diff-filter=U"]).stdout)
            .trim()
            .to_string();
    p.target(!reverted.ok, "git stops with a conflict");
    p.target(unresolved == ".murk", "the conflict is on .murk");
    p.target(
        reverted.file == h_file,
        ".murk is byte for byte what it was (H's)",
    );
    p.target(
        reverted
            .stderr
            .contains("theirs failed its authenticity check")
            && reverted.stderr.contains("rolled back"),
        "stderr names theirs as rolled back",
    );
}

/// `git revert` of vault commit C with a later vault commit H, on format 3:
/// theirs (C's parent) is older than the ancestor (C), so the driver refuses
/// it as rolled back and leaves H's file as it was.
#[test]
fn row_r_l_gitrevert_v3() {
    check("R-L-gitrevert:v3", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, _, c, _, h_file) = revert_scene(base.path());
        let reverted = Merged::of(git_as(&alice, &repo, &["revert", "--no-edit", &c]), &repo);
        require_ran(p, &reverted, "revert")?;
        p.reached();
        revert_refused(p, &repo, &reverted, &h_file);
        Ok(())
    });
}

/// The revert of C, made on a branch at C (where git needs no driver), is
/// cherry-picked over the later vault work on main: the same refusal as a
/// `git revert` there.
#[test]
fn row_r_l_gitrevert_v3_pick() {
    check("R-L-gitrevert:v3-pick", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, _, c, _, h_file) = revert_scene(base.path());
        git_ok(&repo, &["checkout", "-q", "-b", "undo", &c]);
        let (made, stderr) = git_as(&alice, &repo, &["revert", "--no-edit", &c]);
        p.require(
            made,
            format!("the revert commit on a branch at C: {stderr}"),
        )?;
        let undo = head_commit(&repo);
        git_ok(&repo, &["checkout", "-q", "main"]);
        let picked = Merged::cherry_pick(&alice, &repo, &undo);
        require_ran(p, &picked, "cherry-pick")?;
        p.reached();
        revert_refused(p, &repo, &picked, &h_file);
        Ok(())
    });
}

/// A stated limit: a cherry-pick of commit S (made on R0, adds `Z`) onto a
/// main that rotated `DB_URL` after R0 runs three-way over R0, which is an
/// authority, and applies as git does. The pick completes, `Z` is present,
/// `DB_URL` keeps the rotated value, and the merging key signs the result.
#[test]
fn row_r_l_cherrypick_stale_base() {
    check("R-L-cherrypick:stale-base", |p| {
        let base = TempDir::new().unwrap();
        let team = Team::new(base.path());
        team.fork(base.path(), "s", &team.r0, "Z");
        team.rotate_only();
        let picked = Merged::cherry_pick(&team.alice, &team.repo, "s");
        require_ran(p, &picked, "cherry-pick")?;
        p.reached();
        p.target(picked.ok, "the cherry-pick completes");
        p.target(
            team.get("Z").as_deref() == Some("Z-value\n"),
            "Z is in the vault",
        );
        p.target(
            team.get("DB_URL").as_deref() == Some("rotated-db\n"),
            "DB_URL keeps the rotated value",
        );
        p.target(
            picked
                .vault()
                .and_then(|v| v.sig)
                .is_some_and(|s| s.signer == team.alice.pubkey()),
            "the merging key signs the result",
        );
        Ok(())
    });
}

// ── R-I11-d:stripped: the genuine first vault, signature removed ──

/// A repo writer commits the genuine first vault with its signature removed
/// (vault id, counter and MAC intact; with `strip` false it keeps it) as the
/// parent of the genuine older revision that added `OLD_TOKEN`, which alice's
/// main deleted again; alice cherry-picks it.
fn stripped_ancestor_replay(base: &Path, strip: bool) -> (Retired, Merged) {
    let scene = Retired::new(base);
    let repo = scene.team.repo.clone();
    let parent = if strip {
        let mut vault = parse(&scene.team.r0_file).unwrap();
        vault.sig = None;
        to_file(&vault)
    } else {
        scene.team.r0_file.clone()
    };
    let evil = attack_branch(&repo, "evil", &scene.team.r0, &parent, &scene.added_file);
    let merged = Merged::cherry_pick(&scene.team.alice, &repo, &evil);
    (scene, merged)
}

/// An unsigned ancestor that carries a vault id is no authority: the driver
/// stops with a conflict naming the ancestor and signs nothing, and the
/// deleted secret is never served. Only the raw ancestor of two murk 0.13
/// sides, which have no id, decides a merge unsigned. The control, the same
/// cherry-pick over the signed genuine ancestor, merges.
#[test]
fn row_r_i11_d_stripped() {
    check("R-I11-d:stripped", |p| {
        let control = TempDir::new().unwrap();
        let (_, merged) = stripped_ancestor_replay(control.path(), false);
        p.require(
            merged.ran() && merged.ok,
            format!(
                "over the signed ancestor the cherry-pick merges: {}",
                merged.stderr
            ),
        )?;
        let base = TempDir::new().unwrap();
        let (scene, merged) = stripped_ancestor_replay(base.path(), true);
        require_ran(p, &merged, "cherry-pick")?;
        p.reached();
        p.target(!merged.ok, "the cherry-pick stops with a conflict");
        p.target(
            merged.stderr.contains("ancestor"),
            "the driver names the ancestor",
        );
        p.target(
            nothing_new_signed(&merged.file, &scene.ours),
            "nothing is signed",
        );
        p.target(
            scene.team.get("OLD_TOKEN").is_none(),
            "the deleted OLD_TOKEN is not served",
        );
        Ok(())
    });
}

// ── R-I12-a:first-write: the driver signs only what this machine accepts ──

/// `git merge <branch>` on `laptop`, with its key file as the merging key.
fn merge_on(laptop: &Laptop, repo: &Path, branch: &str) -> Merged {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["-c", "commit.gpgsign=false", "merge", "--no-edit", branch])
        .current_dir(repo)
        .env("HOME", &laptop.machine.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "t@t");
    for var in common::MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    let out = cmd.env("MURK_KEY_FILE", &laptop.key).output().unwrap();
    Merged::of(
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        repo,
    )
}

/// Bob's machine trusts the vault, but no vault it accepted carries bob's own
/// verifying key yet. A merge that bob's key would sign is then a vault this
/// machine refuses on its next load (its signing key is not confirmed), so
/// the driver refuses to sign it and leaves ours as it was. The control: once
/// bob has saved on that machine, the same merge is clean and bob reads it.
#[test]
fn row_r_i12_a_first_write() {
    check("R-I12-a:first-write", |p| {
        let scene = |base: &Path, save_first: bool| {
            let team = Team::new(base);
            team.fork(base, "x", &team.r0, "XK");
            team.alice.add(&team.repo, "MK", "mk");
            commit(&team.repo, "main moves");
            let bob = Laptop {
                key: team.bob.key_file(),
                machine: Machine::new(base, "bob-laptop"),
            };
            bob.ok(&team.repo, &["trust", "--yes"]);
            if save_first {
                bob.add(&team.repo, "BOB_K", "bob");
                commit(&team.repo, "bob saves");
            }
            let ours = working(&team.repo);
            let merged = merge_on(&bob, &team.repo, "x");
            (team, bob, ours, merged)
        };
        let control = TempDir::new().unwrap();
        let (team, bob, _, merged) = scene(control.path(), true);
        let reads = bob
            .command(&team.repo)
            .args(["get", "XK"])
            .output()
            .unwrap();
        p.require(
            merged.ok && reads.stdout == b"XK-value\n",
            format!(
                "after an own save, the merge is clean and bob reads it: {}",
                merged.stderr
            ),
        )?;

        let base = TempDir::new().unwrap();
        let (_, _, ours, merged) = scene(base.path(), false);
        require_ran(p, &merged, "merge")?;
        p.reached();
        p.target(!merged.ok, "the merge stops");
        p.target(
            merged.stderr.contains("would refuse the merged vault"),
            "the driver says this machine would refuse the result",
        );
        p.target(
            merged.file == ours,
            "the working file is ours, byte for byte",
        );
        Ok(())
    });
}
