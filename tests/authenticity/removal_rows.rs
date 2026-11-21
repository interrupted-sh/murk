// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Invariant rows about removed members (see `tests/invariant_rows.tsv`): a
//! key this machine recorded as removed stays removed on every load, merge
//! and save, whatever generation the vault has. Only this machine's own
//! `circle authorize` or `murk trust --re-add` brings it back.
//!
//! The scene is a stale fork: a revision that a trusted signer kept saving
//! on a branch cut before the removal, so it still lists the removed member
//! and has a generation above the removal.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::common::rows::{Probe, check};

/// The history walk's cap (`VAULT_HISTORY_CAP` in `src/git.rs`).
const VAULT_HISTORY_CAP: usize = 10_000;
use super::{Machine, alice_repo, authorize, commit, git, git_ok, head_commit};

// ── Helpers ──

/// A member team: alice (who made the vault), bob and, when asked, carol,
/// with the merge driver set up. R0 lists all of them.
struct Scene {
    _base: TempDir,
    base: PathBuf,
    alice: Machine,
    bob: Machine,
    carol: Machine,
    repo: PathBuf,
    r0: String,
}

impl Scene {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let (alice, repo) = alice_repo(&base);
        let bob = Machine::new(&base, "bob");
        bob.init(&base.join("bob-scratch"), "bob");
        let carol = Machine::new(&base, "carol");
        carol.init(&base.join("carol-scratch"), "carol");
        authorize(&alice, &repo, &bob, "bob");
        authorize(&alice, &repo, &carol, "carol");
        super::use_merge_driver(&repo);
        carol
            .with_key(&repo, &carol.key_file())
            .args(["trust", "--yes"])
            .assert()
            .success();
        Self {
            _base: dir,
            base,
            r0: head_commit(&repo),
            alice,
            bob,
            carol,
            repo,
        }
    }

    /// alice's second machine: its own HOME, alice's key.
    fn laptop(&self, name: &str) -> Machine {
        Machine::new(&self.base, name)
    }

    /// Run murk on alice's second machine `laptop`; it must succeed.
    fn on_laptop(&self, laptop: &Machine, args: &[&str], stdin: Option<&str>) {
        let mut cmd = laptop.with_key(&self.repo, &self.alice.key_file());
        cmd.args(args);
        if let Some(input) = stdin {
            cmd.write_stdin(input.to_string());
        }
        cmd.assert().success();
    }

    /// A stale fork: on branch `name` off `from`, alice's second machine
    /// trusts the vault and saves `saves` times. It still lists bob. Leaves
    /// `main` checked out and returns the fork's file.
    fn stale_fork(&self, name: &str, from: &str, saves: usize) -> Vec<u8> {
        let laptop = self.laptop(&format!("{name}-laptop"));
        git_ok(
            &self.repo,
            &["checkout", "-q", name_or_new(&self.repo, name), name, from],
        );
        self.on_laptop(&laptop, &["trust", "--yes"], None);
        for i in 1..=saves {
            self.on_laptop(
                &laptop,
                &["add", &format!("F{i}")],
                Some(&format!("f{i}\n")),
            );
        }
        commit(&self.repo, &format!("{name}: {saves} saves"));
        let file = working(&self.repo);
        git_ok(&self.repo, &["checkout", "-q", "main"]);
        file
    }

    /// On main, alice revokes bob and rotates `DB_URL`, and commits.
    fn revoke_bob(&self) {
        self.run_ok(&self.alice, &["circle", "revoke", &self.bob.pubkey()]);
        self.alice.add(&self.repo, "DB_URL", "rotated-db");
        commit(&self.repo, "revoke bob, rotate DB_URL");
    }

    /// murk as `who` in the repo, with their key.
    fn cmd(&self, who: &Machine) -> assert_cmd::Command {
        who.with_key(&self.repo, &who.key_file())
    }

    fn run_ok(&self, who: &Machine, args: &[&str]) {
        self.cmd(who).args(args).assert().success();
    }

    fn run(&self, who: &Machine, args: &[&str]) -> std::process::Output {
        self.cmd(who).args(args).output().unwrap()
    }

    /// carol's own save of `key` in the repo, with her key; it must succeed.
    fn carol_add(&self, key: &str, value: &str) {
        self.cmd(&self.carol)
            .args(["add", key])
            .write_stdin(format!("{value}\n"))
            .assert()
            .success();
    }

    /// `who`'s trust pin for the vault, and its sidecar (`Null` when absent).
    fn pin(&self, who: &Machine) -> (serde_json::Value, serde_json::Value) {
        let file = pin_file(who, &self.repo);
        let sidecar = fs::read(file.with_extension("lineage.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        (
            serde_json::from_slice(&fs::read(file).unwrap()).unwrap(),
            sidecar,
        )
    }

    /// Whether `who`'s pin file records bob as removed, and whether it
    /// trusts him.
    fn pin_on_bob(&self, who: &Machine) -> (bool, bool) {
        let (pin, _) = self.pin(who);
        let bob = self.bob.pubkey();
        let removed = pin["removed"].get(&bob).is_some();
        let trusted = pin["trusted"]
            .as_array()
            .is_some_and(|t| t.iter().any(|k| k == &bob));
        (removed, trusted)
    }

    /// Whether `who`'s sidecar copy records bob as removed.
    fn sidecar_on_bob(&self, who: &Machine) -> bool {
        self.pin(who).1["removals"].get(self.bob.pubkey()).is_some()
    }

    /// Whether the working vault lists bob.
    fn lists_bob(&self) -> bool {
        lists(&working(&self.repo), &self.bob.pubkey())
    }
}

/// `-b` for a new branch, nothing for one that exists (checkout takes the
/// start point only with `-b`, so an existing branch is checked out with
/// `-B`, which resets it to `from`).
fn name_or_new<'a>(repo: &Path, name: &str) -> &'a str {
    let exists = git(repo, &["rev-parse", "--verify", "-q", name])
        .status
        .success();
    if exists { "-B" } else { "-b" }
}

/// The working `.murk`.
fn working(repo: &Path) -> Vec<u8> {
    fs::read(repo.join(".murk")).unwrap()
}

/// Commit `file` as `.murk` on the current branch, as a repo writer would.
fn put(repo: &Path, file: &[u8], message: &str) {
    fs::write(repo.join(".murk"), file).unwrap();
    commit(repo, message);
}

/// Whether the vault file `file` lists `key` as a recipient.
fn lists(file: &[u8], key: &str) -> bool {
    let vault: serde_json::Value = serde_json::from_slice(file).unwrap();
    vault["recipients"]
        .as_array()
        .is_some_and(|r| r.iter().any(|k| k == key))
}

/// `who`'s pin file for the vault in `repo` (found by the vault id).
fn pin_file(who: &Machine, repo: &Path) -> PathBuf {
    let vault: serde_json::Value = serde_json::from_slice(&working(repo)).unwrap();
    super::pin_files(who)
        .into_iter()
        .find(|p| {
            serde_json::from_slice::<serde_json::Value>(&fs::read(p).unwrap())
                .is_ok_and(|pin| pin["vault_id"] == vault["vault_id"])
        })
        .expect("a pin for the vault")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Whether `stderr` names bob and the way back (`--re-add`).
fn names_re_add(stderr: &str) -> bool {
    stderr.contains("bob") && stderr.contains("--re-add")
}

/// The stale-fork scene: R0 lists bob. A stale fork of 10 saves and one of 1 save
/// are cut from R0. Then alice revokes bob on main and rotates `DB_URL`.
/// Returns the 10-save and the 1-save files.
fn stale_fork_scene(s: &Scene) -> (Vec<u8>, Vec<u8>) {
    let short = s.stale_fork("short", &s.r0, 1);
    let stale = s.stale_fork("stale", &s.r0, 10);
    s.revoke_bob();
    (stale, short)
}

// ── R-I10-h: a removed member stays removed on this machine ──

/// A repo writer commits a stale fork's genuine file on main. It is signed
/// by alice, has a generation above the removal, and still lists bob.
/// alice's machine, which recorded the removal, refuses it. Its pin keeps
/// bob removed, and its next write does not happen.
#[test]
fn row_r_i10_h_replay() {
    check("R-I10-h:replay", |p: &mut Probe| {
        let s = Scene::new();
        let (stale, short) = stale_fork_scene(&s);
        p.require(
            s.pin_on_bob(&s.alice) == (true, false),
            "alice's pin records bob as removed before the replay",
        )?;
        // Control: the 1-save fork is at or below the removal.
        fs::write(s.repo.join(".murk"), &short).unwrap();
        let control = s.run(&s.alice, &["get", "DB_URL"]);
        p.require(
            !control.status.success() && !text(&control.stdout).contains("prod-db"),
            format!(
                "the 1-save fork is refused: {}",
                text(&control.stderr).trim()
            ),
        )?;
        git_ok(&s.repo, &["checkout", "--", ".murk"]);
        p.require(
            generation(&stale) > generation(&working(&s.repo)),
            "the stale fork's generation is above main's",
        )?;

        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get: {}", stderr.trim()));
        p.target(!get.status.success(), "the load is refused");
        p.target(
            !text(&get.stdout).contains("prod-db"),
            "the old value is not printed",
        );
        p.target(names_re_add(&stderr), "stderr names bob and --re-add");
        let merge_first = stderr.find("merge the branch that holds the removal into this branch");
        p.target(
            merge_first.is_some_and(|m| stderr.find("--re-add").is_some_and(|r| m < r))
                && stderr.contains(READD_SCOPE),
            "the refusal offers merging the removal first, then --re-add with what it does",
        );
        p.target(
            s.pin_on_bob(&s.alice) == (true, false),
            "the pin still records bob as removed and does not trust him",
        );
        let before = working(&s.repo);
        let add = s
            .alice
            .murk(&s.repo)
            .args(["add", "NEW_AFTER"])
            .write_stdin("new\n")
            .output()
            .unwrap();
        p.target(
            !add.status.success() && working(&s.repo) == before,
            "the next write does not happen",
        );
        Ok(())
    });
}

/// alice re-authorizes bob on main with her own save. carol's machine, which
/// recorded the removal, refuses the vault until carol runs `murk trust
/// --re-add`. alice's machine loads it with no command.
#[test]
fn row_r_i10_h_re_add() {
    check("R-I10-h:re-add", |p: &mut Probe| {
        let s = Scene::new();
        s.revoke_bob();
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        p.require(
            s.pin_on_bob(&s.carol).0,
            "carol's pin records bob as removed",
        )?;
        authorize(&s.alice, &s.repo, &s.bob, "bob");
        commit(&s.repo, "re-authorize bob");
        p.require(
            s.pin_on_bob(&s.alice) == (false, true) && !s.sidecar_on_bob(&s.alice),
            "alice's own save clears her record in the pin and the sidecar",
        )?;
        p.require(
            s.run(&s.alice, &["get", "DB_URL"]).status.success(),
            "alice's machine loads her own save with no command",
        )?;

        let first = s.run(&s.carol, &["get", "DB_URL"]);
        p.reached();
        p.note(format!(
            "carol's first load: {}",
            text(&first.stderr).trim()
        ));
        p.target(!first.status.success(), "carol's first load is refused");
        p.target(
            names_re_add(&text(&first.stderr)),
            "the refusal names bob and --re-add",
        );
        let re_add = s.run(&s.carol, &["trust", "--re-add", &s.bob.pubkey(), "--yes"]);
        p.note(format!("re-add: {}", text(&re_add.stderr).trim()));
        p.target(re_add.status.success(), "murk trust --re-add bob succeeds");
        p.target(
            s.run(&s.carol, &["get", "DB_URL"]).status.success(),
            "carol's next load succeeds",
        );
        p.target(
            s.pin_on_bob(&s.carol) == (false, true),
            "carol's pin trusts bob and records no removal",
        );
        Ok(())
    });
}

/// The scene of R-I10-h:merge: after the removal, alice's second machine
/// re-authorizes bob on branch `back`. Main then adds `MAIN_K`. carol's
/// machine recorded the removal. Returns main's file.
fn readd_branch_scene(s: &Scene) -> Vec<u8> {
    s.revoke_bob();
    s.run_ok(&s.carol, &["get", "DB_URL"]);
    let laptop = s.laptop("back-laptop");
    git_ok(&s.repo, &["checkout", "-q", "-b", "back"]);
    s.on_laptop(&laptop, &["trust", "--yes"], None);
    s.on_laptop(
        &laptop,
        &["circle", "authorize", &s.bob.pubkey(), "--name", "bob"],
        None,
    );
    commit(&s.repo, "back: re-authorize bob");
    git_ok(&s.repo, &["checkout", "-q", "main"]);
    s.alice.add(&s.repo, "MAIN_K", "main-k");
    commit(&s.repo, "main: add MAIN_K");
    s.run_ok(&s.carol, &["get", "MAIN_K"]);
    working(&s.repo)
}

/// `git <args>` in the repo as `who` (their HOME and key), with the merge
/// driver: (success, stderr).
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
    for var in super::common::MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    cmd.env("MURK_KEY_FILE", who.key_file());
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `git merge --no-edit <branch>` as `who`.
fn git_merge(who: &Machine, repo: &Path, branch: &str) -> (bool, String) {
    git_as(who, repo, &["merge", "--no-edit", branch])
}

/// carol merges a branch that re-adds bob. Her machine recorded the
/// removal, so the merge stops, leaves main's file and names `--re-add`. Both
/// recoveries end clean: take the other side and re-add bob, then make main's
/// change again; or authorize bob on main first and merge again.
#[test]
fn row_r_i10_h_merge() {
    check("R-I10-h:merge", |p: &mut Probe| {
        let s = Scene::new();
        let main_file = readd_branch_scene(&s);
        let (merged, stderr) = git_merge(&s.carol, &s.repo, "back");
        p.reached();
        p.note(format!("merge: {}", stderr.trim()));
        p.target(!merged, "the merge stops");
        p.target(working(&s.repo) == main_file, ".murk is main's file");
        p.target(names_re_add(&stderr), "stderr names bob and --re-add");
        p.target(s.pin_on_bob(&s.carol).0, "carol's record is unchanged");
        if merged {
            return Ok(());
        }

        // Recovery A: take the other side, re-add bob, redo main's change.
        git_as(&s.carol, &s.repo, &["merge", "--abort"]);
        git_merge(&s.carol, &s.repo, "back");
        git_ok(&s.repo, &["checkout", "--theirs", "--", ".murk"]);
        let re_add = s.run(&s.carol, &["trust", "--re-add", &s.bob.pubkey(), "--yes"]);
        p.note(format!(
            "recovery A, re-add: {}",
            text(&re_add.stderr).trim()
        ));
        let redo = s
            .cmd(&s.carol)
            .args(["add", "MAIN_K"])
            .write_stdin("main-k\n")
            .output()
            .unwrap();
        p.note(format!("recovery A, redo: {}", text(&redo.stderr).trim()));
        git_ok(&s.repo, &["add", ".murk"]);
        let committed = git_as(&s.carol, &s.repo, &["commit", "-q", "--no-edit"]).0;
        let get = s.run(&s.carol, &["get", "MAIN_K"]);
        p.target(
            re_add.status.success() && redo.status.success() && committed,
            "recovery A runs: take theirs, --re-add bob, make main's change again, commit",
        );
        p.target(s.lists_bob(), "recovery A: bob is listed");
        p.target(
            get.status.success() && text(&get.stdout).contains("main-k"),
            "recovery A: main's change is present",
        );
        p.target(
            !s.pin_on_bob(&s.carol).0,
            "recovery A: carol's record is gone",
        );

        // Recovery B, on a fresh copy of the scene: authorize first.
        let s = Scene::new();
        readd_branch_scene(&s);
        let authorized = s
            .run(
                &s.carol,
                &["circle", "authorize", &s.bob.pubkey(), "--name", "bob"],
            )
            .status
            .success();
        commit(&s.repo, "main: authorize bob");
        let (clean, stderr) = git_merge(&s.carol, &s.repo, "back");
        p.note(format!("recovery B, merge: {}", stderr.trim()));
        let signer = serde_json::from_slice::<serde_json::Value>(&working(&s.repo))
            .ok()
            .and_then(|v| v["sig"]["signer"].as_str().map(str::to_string));
        p.target(
            authorized && clean,
            "recovery B: authorize on main, then the merge is clean",
        );
        p.target(s.lists_bob(), "recovery B: bob is listed");
        p.target(
            signer.as_deref() == Some(s.carol.pubkey().as_str()),
            "recovery B: carol signs the result",
        );
        Ok(())
    });
}

/// alice's machine accepted branch `old` before the removal reached it. A
/// vault there lists bob above the removal and loads as current there,
/// because the removal does not apply on `old`. That load leaves the record.
/// The same file on main is then refused.
#[test]
fn row_r_i10_h_record() {
    check("R-I10-h:record", |p: &mut Probe| {
        let s = Scene::new();
        git_ok(&s.repo, &["checkout", "-q", "-b", "old", &s.r0]);
        // alice's own save there gives her machine a mark for `old`.
        s.alice.add(&s.repo, "OLD_K", "old-k");
        commit(&s.repo, "old: add OLD_K");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        s.revoke_bob();
        let old = s.stale_fork("old", "old", 10);
        p.require(lists(&old, &s.bob.pubkey()), "the old branch lists bob")?;

        git_ok(&s.repo, &["checkout", "-q", "old"]);
        let on_old = s.run(&s.alice, &["get", "DB_URL"]);
        p.require(
            on_old.status.success(),
            format!(
                "the old branch loads as before: {}",
                text(&on_old.stderr).trim()
            ),
        )?;
        p.reached();
        p.target(
            s.pin_on_bob(&s.alice).0,
            "after the load on old, the pin still records bob",
        );
        p.target(
            s.sidecar_on_bob(&s.alice),
            "after the load on old, the sidecar still records bob",
        );
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        put(&s.repo, &old, "pr: change");
        let on_main = s.run(&s.alice, &["get", "DB_URL"]);
        p.note(format!("main: {}", text(&on_main.stderr).trim()));
        p.target(!on_main.status.success(), "the file is refused on main");
        Ok(())
    });
}

// ── R-I10-h: a removal reaches a branch through its git history ──

/// The pull-request scene: a stale fork of 10 saves from R0. alice's machine
/// has a mark on main. She revokes bob on branch `revoke-bob` (her own save,
/// over R0) and commits. Leaves `main` checked out, without the removal.
/// Returns the stale fork's file.
fn pr_flow_scene(s: &Scene) -> Vec<u8> {
    let stale = s.stale_fork("stale", &s.r0, 10);
    s.run_ok(&s.alice, &["get", "DB_URL"]);
    git_ok(&s.repo, &["checkout", "-q", "-b", "revoke-bob"]);
    s.revoke_bob();
    git_ok(&s.repo, &["checkout", "-q", "main"]);
    stale
}

/// The pull request is merged into main (a fast-forward), then a repo
/// writer commits the stale fork's file on main.
fn merge_pr_then_replay(s: &Scene, stale: &[u8]) {
    git_ok(&s.repo, &["merge", "-q", "--ff-only", "revoke-bob"]);
    put(&s.repo, stale, "pr: change");
}

/// `who`'s next save (`add NEW_AFTER`): whether it wrote nothing, so no
/// vault written here lists the removed member.
fn next_save_writes_nothing(s: &Scene, who: &Machine) -> bool {
    let before = working(&s.repo);
    let add = s
        .cmd(who)
        .args(["add", "NEW_AFTER"])
        .write_stdin("new\n")
        .output()
        .unwrap();
    !add.status.success() && working(&s.repo) == before
}

/// alice revokes bob on a topic branch; the pull request is merged into
/// main, and a stale fork that still lists bob is then committed on main
/// before alice's machine loads main. Her machine recorded the removal on
/// the topic branch only, but main's history now holds it: the load is
/// refused and the next save does not happen. A removal accepted from
/// another signer's commit reaches a branch whose history holds that commit
/// the same way.
#[test]
fn row_r_i10_h_pr_flow() {
    check("R-I10-h:pr-flow", |p: &mut Probe| {
        let s = Scene::new();
        let stale = pr_flow_scene(&s);
        let (pin, _) = s.pin(&s.alice);
        p.require(
            pin["removed_on"][s.bob.pubkey()] == serde_json::json!(["revoke-bob"]),
            format!(
                "alice's machine records the removal on revoke-bob only: {}",
                pin["removed_on"]
            ),
        )?;
        merge_pr_then_replay(&s, &stale);
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get on main: {}", stderr.trim()));
        p.target(!get.status.success(), "the load on main is refused");
        p.target(
            !text(&get.stdout).contains("prod-db"),
            "the pre-rotation value is not printed",
        );
        p.target(names_re_add(&stderr), "stderr names bob and --re-add");
        p.target(
            next_save_writes_nothing(&s, &s.alice),
            "the next save on main does not happen",
        );

        // carol's machine accepts alice's removal from main's commit. Its
        // branch `next`, marked here before, is then moved onto main's tip
        // and a stale fork is committed there.
        let s = Scene::new();
        let stale = s.stale_fork("stale", &s.r0, 10);
        git_ok(&s.repo, &["checkout", "-q", "-b", "next"]);
        s.carol_add("NEXT_K", "next-k");
        commit(&s.repo, "next: add NEXT_K");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        s.revoke_bob();
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        p.require(
            s.pin_on_bob(&s.carol).0,
            "carol's machine records bob's removal",
        )?;
        git_ok(&s.repo, &["checkout", "-q", "-B", "next", "main"]);
        put(&s.repo, &stale, "next: change");
        let get = s.run(&s.carol, &["get", "DB_URL"]);
        p.note(format!("carol on next: {}", text(&get.stderr).trim()));
        p.target(
            !get.status.success() && names_re_add(&text(&get.stderr)),
            "carol's load on next, whose history holds the removal commit, is refused",
        );
        Ok(())
    });
}

/// The pull-request scene, read on a detached HEAD at main's tip after the
/// merge and the replay: refused.
#[test]
fn row_r_i10_h_pr_flow_detached() {
    check("R-I10-h:pr-flow-detached", |p: &mut Probe| {
        let s = Scene::new();
        let stale = pr_flow_scene(&s);
        merge_pr_then_replay(&s, &stale);
        git_ok(&s.repo, &["checkout", "-q", "--detach"]);
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        p.note(format!("get: {}", text(&get.stderr).trim()));
        p.target(!get.status.success(), "the load is refused");
        p.target(
            !text(&get.stdout).contains("prod-db"),
            "the pre-rotation value is not printed",
        );
        Ok(())
    });
}

/// Control for the own-save shape: alice's machine recorded the removal at
/// the commit her revoke was saved over (R0, which still lists bob). main
/// holds R0 but not the revoke, so the removal has not reached it: main
/// still loads, and a save there is not refused.
#[test]
fn row_r_i10_h_pr_flow_own_save() {
    check("R-I10-h:pr-flow-own-save", |p: &mut Probe| {
        let s = Scene::new();
        pr_flow_scene(&s);
        let (pin, _) = s.pin(&s.alice);
        p.require(
            pin["removed_at_commit"][s.bob.pubkey()] == serde_json::json!(head_commit(&s.repo)),
            "the removal is recorded at main's tip, the commit the revoke was saved over",
        )?;
        p.require(s.lists_bob(), "main's vault lists bob")?;
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        p.note(format!("get: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success() && text(&get.stdout).contains("prod-db"),
            "main, which the removal has not reached, still loads",
        );
        let add = s
            .cmd(&s.alice)
            .args(["add", "MAIN_K"])
            .write_stdin("main-k\n")
            .output()
            .unwrap();
        p.note(format!("add: {}", text(&add.stderr).trim()));
        p.target(
            add.status.success(),
            "a save on main, where bob is still a member, is not refused",
        );
        Ok(())
    });
}

/// Control: carol's machine accepts bob's removal from main's commit. Her
/// branch `old`, cut before it and marked here, never merges it: a vault
/// there that lists bob still loads.
#[test]
fn row_r_i10_h_pr_flow_unmerged() {
    check("R-I10-h:pr-flow-unmerged", |p: &mut Probe| {
        let s = Scene::new();
        git_ok(&s.repo, &["checkout", "-q", "-b", "old"]);
        s.carol_add("OLD_K", "old-k");
        commit(&s.repo, "old: add OLD_K");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        s.revoke_bob();
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        p.require(
            s.pin_on_bob(&s.carol).0,
            "carol's machine records bob's removal",
        )?;
        git_ok(&s.repo, &["checkout", "-q", "old"]);
        p.require(s.lists_bob(), "old's vault lists bob")?;
        let get = s.run(&s.carol, &["get", "OLD_K"]);
        p.reached();
        p.note(format!("get on old: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success() && text(&get.stdout).contains("old-k"),
            "old, which never merged the removal, still loads",
        );
        Ok(())
    });
}

/// What `murk trust --re-add` does, as every refusal that offers it says.
const READD_SCOPE: &str = "it trusts them again on every branch on this machine";

/// Whether `stderr` is the refusal for a removal that applies only because
/// git could not show whether the branch merged it: `why` names the cause
/// and `way` the way out that fits it; the refusal also names bob,
/// `--re-add` and what `--re-add` does.
fn refused_unchecked(stderr: &str, why: &str, way: &str) -> bool {
    stderr.contains("murk cannot tell whether this branch merged that removal")
        && stderr.contains(why)
        && stderr.contains(way)
        && names_re_add(stderr)
        && stderr.contains(READD_SCOPE)
}

/// alice's load on main, which must be refused for the unchecked history
/// `why` with the way out `way`, print nothing on stdout, and leave her
/// next save undone.
fn unchecked_load_refused(s: &Scene, p: &mut Probe, why: &str, way: &str) {
    let get = s.run(&s.alice, &["get", "DB_URL"]);
    p.reached();
    let stderr = text(&get.stderr);
    p.note(format!("get on main: {}", stderr.trim()));
    p.target(
        !get.status.success() && refused_unchecked(&stderr, why, way),
        format!("the load on main is refused, says {why:?} and names {way:?}"),
    );
    p.target(text(&get.stdout).is_empty(), "nothing is printed on stdout");
    p.target(
        next_save_writes_nothing(s, &s.alice),
        "the next save on main does not happen",
    );
}

/// Commit `count` revisions of the vault file on top of the current branch
/// with `git fast-import`, cycling through `blobs`: commits that change the
/// vault file and need no signature, as a repo writer could push.
fn pad_history(repo: &Path, count: usize, blobs: &[Vec<u8>]) -> bool {
    let branch = String::from_utf8(git(repo, &["symbolic-ref", "HEAD"]).stdout).unwrap();
    let branch = branch.trim();
    let mut stream = Vec::new();
    for i in 1..=count {
        let blob = &blobs[i % blobs.len()];
        stream.extend(
            format!(
                "commit {branch}\ncommitter t <t@t> {i} +0000\ndata 4\nfill\n{}M 100644 inline .murk\ndata {}\n",
                if i == 1 { format!("from {branch}^0\n") } else { String::new() },
                blob.len()
            )
            .into_bytes(),
        );
        stream.extend(blob);
        stream.push(b'\n');
    }
    let mut import = std::process::Command::new("git")
        .args(["fast-import", "--quiet", "--force"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        import.stdin.take().unwrap().write_all(&stream).unwrap();
    }
    import.wait().unwrap().success() && git(repo, &["reset", "-q", "--hard"]).status.success()
}

/// Where git cannot show the removal in HEAD's history — here a shallow
/// boundary at main's tip after a squash merge hides the squash and its
/// parent — the vault that lists bob is refused: murk cannot tell a stale
/// fork from a branch that never merged the removal, so it fails closed and
/// names the way out. With the full history the same load is refused as a
/// stale fork.
#[test]
fn row_r_i10_h_pr_flow_unknown() {
    check("R-I10-h:pr-flow-unknown", |p: &mut Probe| {
        let s = Scene::new();
        let stale = pr_flow_scene(&s);
        merge_pr_as(&s, PrMerge::Squash { delete: true });
        put(&s.repo, &stale, "pr: change");
        let shallow = s.repo.join(".git").join("shallow");
        fs::write(&shallow, format!("{}\n", head_commit(&s.repo))).unwrap();
        unchecked_load_refused(
            &s,
            p,
            "this is a shallow clone, and the history murk needs is past its boundary",
            "`git fetch --unshallow`",
        );
        fs::remove_file(&shallow).unwrap();
        let full = s.run(&s.alice, &["get", "DB_URL"]);
        p.target(
            !full.status.success() && !text(&full.stderr).contains("cannot tell"),
            "with the full history the same load is refused as a stale fork",
        );
        Ok(())
    });
}

/// Padding past the cap: after the squash merge of the pull request, a repo
/// writer commits more than `VAULT_HISTORY_CAP` revisions of the vault file
/// (unsigned bytes, alternating two old files), then the stale fork. The
/// walk cannot reach the drop, so the load is refused, never loaded: the
/// refusal says the history is too long to check.
#[test]
fn row_r_i10_h_pr_flow_cap() {
    check("R-I10-h:pr-flow-cap", |p: &mut Probe| {
        let s = Scene::new();
        let stale = pr_flow_scene(&s);
        let r0 = file_at(&s.repo, &s.r0);
        merge_pr_as(&s, PrMerge::Squash { delete: true });
        p.require(
            pad_history(&s.repo, VAULT_HISTORY_CAP + 2, &[r0, stale.clone()]),
            "git fast-import ran",
        )?;
        put(&s.repo, &stale, "pr: change");
        unchecked_load_refused(
            &s,
            p,
            "its history is too long to check",
            "fetching more history cannot help",
        );
        Ok(())
    });
}

/// A junk revision in the walk: alice's machine is marked on `old` (her
/// save there), cut before her removal of bob, which never merges there (so
/// old's vault still lists bob and loads). A repo writer commits a vault file that is
/// not a vault, then old's file again. murk cannot read every revision of
/// old's history, so it cannot rule out that one of them dropped bob: the
/// load is refused, never loaded.
#[test]
fn row_r_i10_h_pr_flow_junk() {
    check("R-I10-h:pr-flow-junk", |p: &mut Probe| {
        let s = Scene::new();
        git_ok(&s.repo, &["checkout", "-q", "-b", "old"]);
        s.alice.add(&s.repo, "OLD_K", "old-k");
        commit(&s.repo, "old: add OLD_K");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        s.revoke_bob();
        git_ok(&s.repo, &["checkout", "-q", "old"]);
        let control = s.run(&s.alice, &["get", "DB_URL"]);
        p.require(
            control.status.success(),
            format!("old loads before the junk: {}", text(&control.stderr)),
        )?;
        let old = working(&s.repo);
        put(&s.repo, b"{\"not\": \"a vault\"}\n", "junk");
        put(&s.repo, &old, "old again");
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get on old: {}", stderr.trim()));
        p.target(
            !get.status.success()
                && refused_unchecked(
                    &stderr,
                    "a vault revision in its history cannot be read",
                    "fetching cannot fix a revision committed that way",
                ),
            "the load on old is refused and says a revision cannot be read",
        );
        p.target(text(&get.stdout).is_empty(), "nothing is printed on stdout");
        Ok(())
    });
}

/// alice's machine marked on `old` (her save there), cut before her
/// removal of bob, which never merges there: old's vault lists bob and
/// loads. Returns the scene and old's file.
fn unmerged_old_scene() -> (Scene, Vec<u8>) {
    let s = Scene::new();
    git_ok(&s.repo, &["checkout", "-q", "-b", "old"]);
    s.alice.add(&s.repo, "OLD_K", "old-k");
    commit(&s.repo, "old: add OLD_K");
    git_ok(&s.repo, &["checkout", "-q", "main"]);
    s.revoke_bob();
    git_ok(&s.repo, &["checkout", "-q", "old"]);
    let old = working(&s.repo);
    (s, old)
}

/// An oversized vault revision in the walk: on the unmerged `old`, a repo
/// writer commits old's own file padded past the 8 MiB read limit, then
/// old's file again. murk does not read a revision that large, so it cannot
/// rule out that one dropped bob: the load is refused, never loaded.
#[test]
fn row_r_i10_h_pr_flow_oversize() {
    check("R-I10-h:pr-flow-oversize", |p: &mut Probe| {
        let (s, old) = unmerged_old_scene();
        let control = s.run(&s.alice, &["get", "OLD_K"]);
        p.require(
            control.status.success(),
            format!(
                "old loads before the big revision: {}",
                text(&control.stderr)
            ),
        )?;
        let mut big = old.clone();
        big.extend(std::iter::repeat_n(b' ', 9 * 1024 * 1024));
        put(&s.repo, &big, "big");
        put(&s.repo, &old, "old again");
        let get = s.run(&s.alice, &["get", "OLD_K"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!(
            "get on old: {}",
            stderr.lines().next().unwrap_or_default()
        ));
        p.target(
            !get.status.success()
                && refused_unchecked(
                    &stderr,
                    "a vault revision in its history cannot be read",
                    "fetching cannot fix",
                )
                && stderr.contains("over 8 MiB"),
            "the load on old is refused and names the 8 MiB limit",
        );
        Ok(())
    });
}

/// A shallow clone whose fetched history holds the whole walk is decided
/// normally: on the unmerged `old`, with the shallow boundary at the commit
/// alice's removal is recorded at (main's tip before her revoke, old's
/// parent), old still loads.
#[test]
fn row_r_i10_h_pr_flow_shallow_decided() {
    check("R-I10-h:pr-flow-shallow-decided", |p: &mut Probe| {
        let (s, _) = unmerged_old_scene();
        let (pin, _) = s.pin(&s.alice);
        let recorded = pin["removed_at_commit"][s.bob.pubkey()]
            .as_str()
            .unwrap_or_default()
            .to_string();
        p.require(!recorded.is_empty(), "the removal is recorded at a commit")?;
        fs::write(s.repo.join(".git").join("shallow"), format!("{recorded}\n")).unwrap();
        let get = s.run(&s.alice, &["get", "OLD_K"]);
        p.reached();
        p.note(format!("get on old: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success() && text(&get.stdout).contains("old-k"),
            "in the shallow clone, old, which never merged the removal, still loads",
        );
        Ok(())
    });
}

/// A vault in a subdirectory (`secrets/.murk`) and a side branch forked
/// before that directory existed, merged into main: at the side branch's
/// fork point there is no `secrets/` at all, which is no vault file there,
/// not a missing object. alice's machine, marked on main, revoked bob on
/// `topic`, never merged; main, which still lists bob, loads.
#[test]
fn row_r_i10_h_pr_flow_subdir() {
    check("R-I10-h:pr-flow-subdir", |p: &mut Probe| {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let repo = base.join("repo");
        fs::create_dir_all(&repo).unwrap();
        git_ok(&repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("README"), "hi\n").unwrap();
        commit(&repo, "R0: no secrets/ yet");
        let r0 = head_commit(&repo);
        let alice = Machine::new(base, "alice");
        let bob = Machine::new(base, "bob");
        bob.init(&base.join("bob-scratch"), "bob");
        let secrets = repo.join("secrets");
        alice.init(&secrets, "alice");
        alice
            .murk(&secrets)
            .args(["circle", "authorize", &bob.pubkey(), "--name", "bob"])
            .assert()
            .success();
        alice.add(&secrets, "DB_URL", "prod-db");
        commit(&repo, "M1: secrets/.murk");
        alice
            .murk(&secrets)
            .args(["get", "DB_URL"])
            .assert()
            .success();
        git_ok(&repo, &["checkout", "-q", "-b", "topic"]);
        alice
            .murk(&secrets)
            .args(["circle", "revoke", &bob.pubkey()])
            .assert()
            .success();
        commit(&repo, "topic: revoke bob");
        git_ok(&repo, &["checkout", "-q", "-b", "sb", &r0]);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(
            secrets.join(".murk"),
            format!(
                "{{\"recipients\":[\"{}\"],\"generation\":1}}\n",
                alice.pubkey()
            ),
        )
        .unwrap();
        commit(&repo, "sb: its own secrets/.murk");
        git_ok(&repo, &["checkout", "-q", "-f", "main"]);
        git(&repo, &["merge", "-q", "--no-commit", "sb"]);
        git_ok(&repo, &["checkout", "-q", "--ours", "--", "secrets/.murk"]);
        commit(&repo, "M2: merge sb, keep main's vault");
        p.require(
            lists(&fs::read(secrets.join(".murk")).unwrap(), &bob.pubkey()),
            "main's vault lists bob",
        )?;
        let get = alice
            .murk(&secrets)
            .args(["get", "DB_URL"])
            .output()
            .unwrap();
        p.reached();
        p.note(format!("get on main: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success() && text(&get.stdout).contains("prod-db"),
            "main, which never merged the removal, loads",
        );
        Ok(())
    });
}

/// A blobless clone of the repository: whether the walk can decide depends
/// on the vault objects it needs, never on the clone being partial.
/// alice's machine works in the clone: marked on main, she revokes bob on
/// `topic` (her own save, never merged). Three more saves then land on main
/// upstream (bob still listed), and alice pulls: the clone has not
/// downloaded those revisions' vault files except the tip's, so murk cannot
/// tell, and says it is a partial clone and how to download them. After
/// `git fetch --refetch --no-filter origin`, main, which never merged the
/// removal, loads.
#[test]
fn row_r_i10_h_pr_flow_partial() {
    check("R-I10-h:pr-flow-partial", |p: &mut Probe| {
        let s = Scene::new();
        let origin = s.base.join("origin.git");
        git_ok(
            &s.base,
            &[
                "clone",
                "-q",
                "--bare",
                s.repo.to_str().unwrap(),
                origin.to_str().unwrap(),
            ],
        );
        git_ok(&origin, &["config", "uploadpack.allowFilter", "true"]);
        git_ok(
            &origin,
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );
        let url = format!("file://{}", origin.display());
        git_ok(
            &s.base,
            &["clone", "-q", "--filter=blob:none", &url, "clone"],
        );
        let clone = s.base.join("clone");
        let alice = |args: &[&str]| {
            s.alice
                .with_key(&clone, &s.alice.key_file())
                .args(args)
                .output()
                .unwrap()
        };
        let trusted = alice(&["trust", "--yes"]);
        p.require(
            trusted.status.success(),
            format!("alice trusts the clone's vault: {}", text(&trusted.stderr)),
        )?;
        let first = alice(&["get", "DB_URL"]);
        p.require(
            first.status.success(),
            format!("alice loads main in the clone: {}", text(&first.stderr)),
        )?;
        git_ok(&clone, &["checkout", "-q", "-b", "topic"]);
        let revoke = alice(&["circle", "revoke", &s.bob.pubkey()]);
        p.require(
            revoke.status.success(),
            format!("alice revokes bob on topic: {}", text(&revoke.stderr)),
        )?;
        commit(&clone, "topic: revoke bob");
        git_ok(&clone, &["checkout", "-q", "main"]);
        for i in 1..=3 {
            s.alice.add(&s.repo, &format!("UP{i}"), "up");
            commit(&s.repo, &format!("main: up {i}"));
        }
        git_ok(&s.repo, &["push", "-q", origin.to_str().unwrap(), "main"]);
        git_ok(&clone, &["pull", "-q", "--ff-only"]);
        p.require(
            lists(&fs::read(clone.join(".murk")).unwrap(), &s.bob.pubkey()),
            "main lists bob",
        )?;
        let get = alice(&["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get in the blobless clone: {}", stderr.trim()));
        p.target(
            !get.status.success()
                && refused_unchecked(
                    &stderr,
                    "this is a partial clone of origin",
                    "`git fetch --refetch --no-filter origin`",
                )
                && stderr.contains("`git config --unset remote.origin.promisor`"),
            "the load is refused as a partial clone, with the commands that download the history",
        );
        git_ok(
            &clone,
            &["fetch", "-q", "--refetch", "--no-filter", "origin"],
        );
        let after = alice(&["get", "DB_URL"]);
        p.target(
            after.status.success(),
            format!(
                "after the full fetch, main, which never merged the removal, loads: {}",
                text(&after.stderr).trim()
            ),
        );
        Ok(())
    });
}

/// The drop reaches main only through a second parent: after the squash
/// merge, the stale fork's branch merges main with `-s ours` (its vault
/// stays the stale fork's, listing bob), and main is fast-forwarded to it.
/// main's first-parent history never drops bob, but its full history does:
/// refused, and the next save does not happen.
#[test]
fn row_r_i10_h_pr_flow_ours_ff() {
    check("R-I10-h:pr-flow-ours-ff", |p: &mut Probe| {
        let s = Scene::new();
        pr_flow_scene(&s);
        merge_pr_as(&s, PrMerge::Squash { delete: true });
        git_ok(&s.repo, &["checkout", "-q", "stale"]);
        git_ok(&s.repo, &["merge", "-q", "-s", "ours", "--no-edit", "main"]);
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        git_ok(&s.repo, &["merge", "-q", "--ff-only", "stale"]);
        p.require(s.lists_bob(), "main's vault is the stale fork's")?;
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get on main: {}", stderr.trim()));
        p.target(
            !get.status.success() && names_re_add(&stderr),
            "the load on main is refused and names --re-add",
        );
        p.target(
            next_save_writes_nothing(&s, &s.alice),
            "the next save on main does not happen",
        );
        Ok(())
    });
}

/// The drop arrives on a topic branch through a second parent: alice's
/// machine is marked on `topic` (her save there), cut before her removal.
/// After the squash merge on main, topic merges main with `-s ours`, so
/// topic's vault still lists bob while its history holds the drop, only
/// through the merge's second parent: refused on topic.
#[test]
fn row_r_i10_h_pr_flow_second_parent() {
    check("R-I10-h:pr-flow-second-parent", |p: &mut Probe| {
        let s = Scene::new();
        git_ok(&s.repo, &["checkout", "-q", "-b", "topic"]);
        s.alice.add(&s.repo, "TOPIC_K", "topic-k");
        commit(&s.repo, "topic: add TOPIC_K");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        git_ok(&s.repo, &["checkout", "-q", "-b", "revoke-bob"]);
        s.revoke_bob();
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        merge_pr_as(&s, PrMerge::Squash { delete: true });
        git_ok(&s.repo, &["checkout", "-q", "topic"]);
        let control = s.run(&s.alice, &["get", "TOPIC_K"]);
        p.require(
            control.status.success(),
            format!("topic loads before the merge: {}", text(&control.stderr)),
        )?;
        git_ok(&s.repo, &["merge", "-q", "-s", "ours", "--no-edit", "main"]);
        p.require(s.lists_bob(), "topic's vault still lists bob")?;
        let get = s.run(&s.alice, &["get", "TOPIC_K"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get on topic: {}", stderr.trim()));
        p.target(
            !get.status.success() && names_re_add(&stderr),
            "the load on topic is refused and names --re-add",
        );
        p.target(text(&get.stdout).is_empty(), "nothing is printed on stdout");
        Ok(())
    });
}

/// Control: a drop on a branch HEAD never merged does not count. carol
/// revokes bob on `side`, which never merges. alice revokes him on her own
/// `revoke-bob`, which never merges either. alice's main, which still lists
/// bob, loads.
#[test]
fn row_r_i10_h_pr_flow_side_unmerged() {
    check("R-I10-h:pr-flow-side-unmerged", |p: &mut Probe| {
        let s = Scene::new();
        s.run_ok(&s.alice, &["get", "DB_URL"]);
        git_ok(&s.repo, &["checkout", "-q", "-b", "side"]);
        s.run_ok(&s.carol, &["circle", "revoke", &s.bob.pubkey()]);
        commit(&s.repo, "side: carol revokes bob");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        git_ok(&s.repo, &["checkout", "-q", "-b", "revoke-bob"]);
        s.revoke_bob();
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        p.require(s.lists_bob(), "main's vault lists bob")?;
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        p.note(format!("get on main: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success() && text(&get.stdout).contains("prod-db"),
            "main, which never merged either drop, still loads",
        );
        // `murk trust --re-add` here says what it sees: main lists bob, and
        // the record goes for every branch.
        let readd = s.run(&s.alice, &["trust", "--yes", "--re-add", &s.bob.pubkey()]);
        let said = text(&readd.stderr);
        p.note(format!("trust --re-add on main: {}", said.trim()));
        p.target(
            readd.status.success()
                && said.contains("the removal does not apply on this branch")
                && !said.contains("does not list")
                && said.contains(READD_SCOPE),
            "murk trust --re-add says main lists bob and that it trusts him again on every branch",
        );
        Ok(())
    });
}

/// Stated limit (decision 10): another machine drops bob on main and adds
/// him back, after the commit alice's later removal of bob (on `release-1`,
/// cut before both, never merged) is recorded at. main's history holds a
/// drop of bob, which murk reads as alice's removal reaching main: main's
/// vault, which lists bob, is refused until alice re-adds him here on
/// purpose, and the refusal says how.
#[test]
fn row_r_i10_h_pr_flow_unrelated_drop() {
    check("R-I10-h:pr-flow-unrelated-drop", |p: &mut Probe| {
        let s = Scene::new();
        s.run_ok(&s.alice, &["get", "DB_URL"]);
        git_ok(&s.repo, &["branch", "release-1"]);
        let laptop = s.laptop("alice2");
        s.on_laptop(&laptop, &["trust", "--yes"], None);
        s.on_laptop(&laptop, &["circle", "revoke", &s.bob.pubkey()], None);
        commit(&s.repo, "main: drop bob");
        s.on_laptop(
            &laptop,
            &["circle", "authorize", &s.bob.pubkey(), "--name", "bob"],
            None,
        );
        commit(&s.repo, "main: re-add bob");
        git_ok(&s.repo, &["checkout", "-q", "release-1"]);
        s.revoke_bob();
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get on main: {}", stderr.trim()));
        p.target(
            !get.status.success() && names_re_add(&stderr),
            "main is refused and the refusal names --re-add (the stated limit)",
        );
        s.run_ok(&s.alice, &["trust", "--yes", "--re-add", &s.bob.pubkey()]);
        p.target(
            s.run(&s.alice, &["get", "DB_URL"]).status.success(),
            "after murk trust --re-add, main loads",
        );
        Ok(())
    });
}

/// How the pull request that revokes bob reaches main.
#[derive(Clone, Copy)]
enum PrMerge {
    /// GitHub's squash merge: one new commit on main; the topic branch kept
    /// or deleted.
    Squash { delete: bool },
    /// A squash merge of a topic branch that also authorizes another member
    /// (dave) after the revoke, which also rotated a value: the squash
    /// commit changes values and other recipients besides dropping bob.
    SquashWithChanges,
    /// A fast-forward, then the topic branch deleted.
    FastForwardDeleted,
    /// A fast-forward, then the topic branch renamed.
    FastForwardRenamed,
    /// A fast-forward, then more work on the topic branch, so its tip is no
    /// longer in main's history.
    FastForwardMovedOn,
    /// GitHub's rebase merge: main has moved on, and the revoke is replayed
    /// onto it as a new commit; the topic branch is kept.
    Rebase,
}

/// Merge `revoke-bob` into main (checked out) as `how` says.
fn merge_pr_as(s: &Scene, how: PrMerge) {
    match how {
        PrMerge::Squash { delete } => {
            git_ok(&s.repo, &["merge", "-q", "--squash", "revoke-bob"]);
            commit(&s.repo, "revoke bob (#1)");
            if delete {
                git_ok(&s.repo, &["branch", "-q", "-D", "revoke-bob"]);
            }
        }
        PrMerge::SquashWithChanges => {
            let dave = Machine::new(&s.base, "dave");
            dave.init(&s.base.join("dave-scratch"), "dave");
            git_ok(&s.repo, &["checkout", "-q", "revoke-bob"]);
            authorize(&s.alice, &s.repo, &dave, "dave");
            commit(&s.repo, "authorize dave");
            git_ok(&s.repo, &["checkout", "-q", "main"]);
            merge_pr_as(s, PrMerge::Squash { delete: true });
        }
        PrMerge::FastForwardDeleted => {
            git_ok(&s.repo, &["merge", "-q", "--ff-only", "revoke-bob"]);
            git_ok(&s.repo, &["branch", "-q", "-D", "revoke-bob"]);
        }
        PrMerge::FastForwardRenamed => {
            git_ok(&s.repo, &["merge", "-q", "--ff-only", "revoke-bob"]);
            git_ok(&s.repo, &["branch", "-q", "-m", "revoke-bob", "rb-merged"]);
        }
        PrMerge::FastForwardMovedOn => {
            git_ok(&s.repo, &["merge", "-q", "--ff-only", "revoke-bob"]);
            git_ok(&s.repo, &["checkout", "-q", "revoke-bob"]);
            fs::write(s.repo.join("NOTES"), "more work on the topic\n").unwrap();
            commit(&s.repo, "topic: more work");
            git_ok(&s.repo, &["checkout", "-q", "main"]);
        }
        PrMerge::Rebase => {
            fs::write(s.repo.join("NOTES"), "main moved on\n").unwrap();
            commit(&s.repo, "main: notes");
            git_ok(
                &s.repo,
                &["-c", "commit.gpgsign=false", "cherry-pick", "revoke-bob"],
            );
        }
    }
}

/// The pull-request scene merged into main as `how` says, then the stale
/// fork committed on main: no commit of alice's revoke is in main's history
/// (or its branch is gone), yet main's vault history drops bob. alice's load
/// on main is refused and her next save does not happen.
fn pr_merge_row(id: &str, how: PrMerge) {
    check(id, |p: &mut Probe| {
        let s = Scene::new();
        let stale = pr_flow_scene(&s);
        merge_pr_as(&s, how);
        p.require(!s.lists_bob(), "main's vault after the merge drops bob")?;
        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get on main: {}", stderr.trim()));
        p.target(!get.status.success(), "the load on main is refused");
        p.target(
            !text(&get.stdout).contains("prod-db"),
            "the pre-rotation value is not printed",
        );
        p.target(names_re_add(&stderr), "stderr names bob and --re-add");
        p.target(
            next_save_writes_nothing(&s, &s.alice),
            "the next save on main does not happen",
        );
        Ok(())
    });
}

#[test]
fn row_r_i10_h_pr_flow_squash() {
    pr_merge_row("R-I10-h:pr-flow-squash", PrMerge::Squash { delete: false });
}

#[test]
fn row_r_i10_h_pr_flow_squash_deleted() {
    pr_merge_row(
        "R-I10-h:pr-flow-squash-deleted",
        PrMerge::Squash { delete: true },
    );
}

#[test]
fn row_r_i10_h_pr_flow_ff_deleted() {
    pr_merge_row("R-I10-h:pr-flow-ff-deleted", PrMerge::FastForwardDeleted);
}

#[test]
fn row_r_i10_h_pr_flow_rebase() {
    pr_merge_row("R-I10-h:pr-flow-rebase", PrMerge::Rebase);
}

#[test]
fn row_r_i10_h_pr_flow_squash_changes() {
    pr_merge_row("R-I10-h:pr-flow-squash-changes", PrMerge::SquashWithChanges);
}

#[test]
fn row_r_i10_h_pr_flow_renamed() {
    pr_merge_row("R-I10-h:pr-flow-renamed", PrMerge::FastForwardRenamed);
}

#[test]
fn row_r_i10_h_pr_flow_moved_on() {
    pr_merge_row("R-I10-h:pr-flow-moved-on", PrMerge::FastForwardMovedOn);
}

/// The teammate case: carol's machine, marked on main and on her topic
/// branch, accepts alice's removal of bob by loading it on the topic branch,
/// after main took the pull request (as a merge commit, or a squash) and she
/// merged main into her topic (a merge commit of her own). Her record's
/// commit is that topic merge commit, which main never holds. A stale fork
/// then committed on main is refused on her machine: main's vault history
/// drops bob after the last vault on her topic's own path that listed him.
fn teammate_row(id: &str, squash: bool) {
    check(id, |p: &mut Probe| {
        let s = Scene::new();
        let stale = s.stale_fork("stale", &s.r0, 10);
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        git_ok(&s.repo, &["checkout", "-q", "-b", "topic"]);
        fs::write(s.repo.join("NOTES"), "carol's topic work\n").unwrap();
        commit(&s.repo, "topic: notes");
        s.carol_add("TOPIC_TMP", "t");
        git_ok(&s.repo, &["checkout", "-q", "--", ".murk"]);
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        git_ok(&s.repo, &["checkout", "-q", "-b", "revoke-bob"]);
        s.revoke_bob();
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        if squash {
            merge_pr_as(&s, PrMerge::Squash { delete: false });
        } else {
            git_ok(
                &s.repo,
                &["merge", "-q", "--no-ff", "-m", "merge PR", "revoke-bob"],
            );
        }
        git_ok(&s.repo, &["checkout", "-q", "topic"]);
        git_ok(
            &s.repo,
            &["merge", "-q", "--no-ff", "-m", "topic: merge main", "main"],
        );
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        let (pin, _) = s.pin(&s.carol);
        let bob = s.bob.pubkey();
        p.require(
            pin["removed_on"][&bob] == serde_json::json!(["topic"])
                && pin["removed_at_commit"][&bob] == serde_json::json!(head_commit(&s.repo)),
            format!(
                "carol's machine records the removal on topic, at topic's merge commit: {} {}",
                pin["removed_on"], pin["removed_at_commit"]
            ),
        )?;
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.carol, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("carol on main: {}", stderr.trim()));
        p.target(
            !get.status.success() && names_re_add(&stderr),
            "carol's load on main is refused and names --re-add",
        );
        p.target(
            !text(&get.stdout).contains("prod-db"),
            "the pre-rotation value is not printed",
        );
        p.target(
            next_save_writes_nothing(&s, &s.carol),
            "carol's next save on main does not happen",
        );
        Ok(())
    });
}

#[test]
fn row_r_i10_h_pr_flow_teammate_merge() {
    teammate_row("R-I10-h:pr-flow-teammate-merge", false);
}

#[test]
fn row_r_i10_h_pr_flow_teammate_squash() {
    teammate_row("R-I10-h:pr-flow-teammate-squash", true);
}

/// alice's machine, marked on main, revokes bob on a detached HEAD at
/// main's tip, so the removal is recorded on no branch. main is then moved
/// to that commit and a stale fork is committed on it: main's vault history
/// drops bob, so the load is refused and the next save does not happen.
#[test]
fn row_r_i10_h_pr_flow_detached_save() {
    check("R-I10-h:pr-flow-detached-save", |p: &mut Probe| {
        let s = Scene::new();
        let stale = s.stale_fork("stale", &s.r0, 10);
        s.run_ok(&s.alice, &["get", "DB_URL"]);
        git_ok(&s.repo, &["checkout", "-q", "--detach"]);
        s.revoke_bob();
        let (pin, _) = s.pin(&s.alice);
        p.require(
            pin["removed_on"][s.bob.pubkey()] == serde_json::json!([]),
            format!(
                "the removal is recorded on no branch: {}",
                pin["removed_on"]
            ),
        )?;
        git_ok(&s.repo, &["branch", "-q", "-f", "main", "HEAD"]);
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get on main: {}", stderr.trim()));
        p.target(
            !get.status.success() && names_re_add(&stderr),
            "the load on main is refused and names --re-add",
        );
        p.target(
            next_save_writes_nothing(&s, &s.alice),
            "the next save on main does not happen",
        );
        Ok(())
    });
}

/// Control for the content arm's bound: alice revoked bob on main once and
/// authorized him again, so main's older history drops bob. She then
/// revokes him again on a topic branch that never merges. main's history
/// since the commit the removal is recorded at holds no drop, so main still
/// loads.
#[test]
fn row_r_i10_h_pr_flow_content_bound() {
    check("R-I10-h:pr-flow-content-bound", |p: &mut Probe| {
        let s = Scene::new();
        s.revoke_bob();
        authorize(&s.alice, &s.repo, &s.bob, "bob");
        commit(&s.repo, "authorize bob again");
        p.require(
            !s.pin_on_bob(&s.alice).0,
            "alice's own authorize cleared her record",
        )?;
        git_ok(&s.repo, &["checkout", "-q", "-b", "revoke-bob"]);
        s.revoke_bob();
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        p.require(s.pin_on_bob(&s.alice).0, "alice records bob removed again")?;
        p.require(s.lists_bob(), "main's vault lists bob")?;
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        p.note(format!("get on main: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success(),
            "main, which never merged the second removal, still loads",
        );
        Ok(())
    });
}

/// Control for the content arm's drop test: carol's branch `old`, cut and
/// marked before dave ever joined, never merges main's add (carol's own) and
/// removal (alice's) of dave, which carol's machine recorded. alice then
/// authorizes dave on `old`. old's history since the fork holds revisions
/// that do not list dave, but none that drops him, so carol's load there
/// still works.
#[test]
fn row_r_i10_h_pr_flow_content_add() {
    check("R-I10-h:pr-flow-content-add", |p: &mut Probe| {
        let s = Scene::new();
        let dave = Machine::new(&s.base, "dave");
        dave.init(&s.base.join("dave-scratch"), "dave");
        git_ok(&s.repo, &["checkout", "-q", "-b", "old"]);
        s.carol_add("OLD_K", "old-k");
        commit(&s.repo, "old: add OLD_K");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        s.run_ok(
            &s.carol,
            &["circle", "authorize", &dave.pubkey(), "--name", "dave"],
        );
        commit(&s.repo, "authorize dave");
        s.run_ok(&s.alice, &["trust", "--yes"]);
        s.run_ok(&s.alice, &["circle", "revoke", &dave.pubkey()]);
        commit(&s.repo, "revoke dave");
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        p.require(
            s.pin(&s.carol).0["removed"].get(dave.pubkey()).is_some(),
            "carol's machine records dave's removal",
        )?;
        git_ok(&s.repo, &["checkout", "-q", "old"]);
        authorize(&s.alice, &s.repo, &dave, "dave");
        commit(&s.repo, "old: authorize dave");
        let get = s.run(&s.carol, &["get", "OLD_K"]);
        p.reached();
        p.note(format!("get on old: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success() && text(&get.stdout).contains("old-k"),
            "old, whose history adds dave but never drops him, still loads",
        );
        Ok(())
    });
}

// ── R-I10-h: a load that is its branch's next state records removals ──

/// carol's machine saved on `feature` more than main has since; it then
/// loads main's revoke of bob, which is main's next state but not above
/// carol's highest counter. It still records the removal, so a stale fork
/// later committed on main is refused there and the next save does not
/// happen.
#[test]
fn row_r_i10_h_branch_current() {
    check("R-I10-h:branch-current", |p: &mut Probe| {
        let s = Scene::new();
        let stale = s.stale_fork("stale", &s.r0, 7);
        git_ok(&s.repo, &["checkout", "-q", "-b", "feature"]);
        for i in 1..=6 {
            s.carol_add(&format!("F{i}"), "f");
        }
        commit(&s.repo, "feature: 6 saves");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        s.revoke_bob();
        let main_generation = generation(&working(&s.repo));
        p.require(
            s.pin(&s.carol).0["generation"].as_u64() > Some(main_generation),
            "carol's highest counter is above main's revoke",
        )?;
        p.require(
            generation(&stale) > main_generation,
            "the stale fork's generation is above main's",
        )?;
        let load = s.run(&s.carol, &["get", "DB_URL"]);
        p.reached();
        p.target(
            load.status.success() && text(&load.stdout).contains("rotated-db"),
            "carol loads main's revoke",
        );
        p.target(
            s.pin_on_bob(&s.carol) == (true, false),
            "carol's machine records bob's removal and does not trust him",
        );
        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.carol, &["get", "DB_URL"]);
        p.note(format!(
            "get after the replay: {}",
            text(&get.stderr).trim()
        ));
        p.target(
            !get.status.success() && names_re_add(&text(&get.stderr)),
            "the stale fork on main is refused and names --re-add",
        );
        p.target(
            next_save_writes_nothing(&s, &s.carol),
            "carol's next save does not happen",
        );
        Ok(())
    });
}

/// carol authorizes dave on `feature`, unmerged, and saves there more than
/// main has since. Her load of main's next state, which does not list dave
/// yet, does not take dave for removed: main never listed him. When she then
/// merges `feature` into main, the merge stops only on the one-sided
/// recipient change (not on a removed key), and feature's side, taken on
/// main, loads there.
#[test]
fn row_r_i10_h_branch_add() {
    check("R-I10-h:branch-add", |p: &mut Probe| {
        let s = Scene::new();
        let dave = Machine::new(&s.base, "dave");
        dave.init(&s.base.join("dave-scratch"), "dave");
        git_ok(&s.repo, &["checkout", "-q", "-b", "feature"]);
        s.run_ok(
            &s.carol,
            &["circle", "authorize", &dave.pubkey(), "--name", "dave"],
        );
        s.carol_add("F1", "f1");
        s.carol_add("F2", "f2");
        commit(&s.repo, "feature: authorize dave");
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        s.alice.add(&s.repo, "MAIN_K", "main-k");
        commit(&s.repo, "main: add MAIN_K");
        p.require(
            s.pin(&s.carol).0["generation"].as_u64() > Some(generation(&working(&s.repo))),
            "carol's highest counter is above main's",
        )?;
        let get = s.run(&s.carol, &["get", "MAIN_K"]);
        p.reached();
        p.target(get.status.success(), "carol loads main's next state");
        let (pin, sidecar) = s.pin(&s.carol);
        let dave_key = dave.pubkey();
        p.target(
            pin["removed"].get(&dave_key).is_none() && sidecar["removals"].get(&dave_key).is_none(),
            "carol's machine does not record dave as removed",
        );
        let (merged, stderr) = git_merge(&s.carol, &s.repo, "feature");
        p.note(format!("merge: {}", stderr.trim()));
        p.target(
            !merged && !stderr.contains("--re-add") && !stderr.contains("removed"),
            "the merge stops on the recipient change, not on a removed key",
        );
        git_ok(&s.repo, &["checkout", "--theirs", "--", ".murk"]);
        let theirs = s.run(&s.carol, &["get", "F1"]);
        p.note(format!(
            "feature's side on main: {}",
            text(&theirs.stderr).trim()
        ));
        p.target(
            theirs.status.success() && lists(&working(&s.repo), &dave_key),
            "feature's side, which lists dave, loads on main",
        );
        Ok(())
    });
}

/// Stated limit: a runner with no pin, anchored only by
/// `MURK_TRUSTED_SIGNERS`, has no removal record. It loads the stale fork.
#[test]
fn row_r_i10_h_pinless() {
    check("R-I10-h:pinless", |p: &mut Probe| {
        let s = Scene::new();
        let (stale, _) = stale_fork_scene(&s);
        put(&s.repo, &stale, "pr: change");
        let (entry, _) = s.alice.signer_entry(&s.repo);
        let runner = Machine::new(&s.base, "runner");
        let get = runner
            .murk(&s.repo)
            .env("MURK_KEY", s.alice.secret_key())
            .env("MURK_TRUSTED_SIGNERS", entry)
            .args(["get", "DB_URL"])
            .output()
            .unwrap();
        p.reached();
        p.note(text(&get.stderr));
        p.target(
            get.status.success() && text(&get.stdout).contains("prod-db"),
            "the runner loads the stale fork and prints the old value (limit 10)",
        );
        Ok(())
    });
}

// ── R-L-oldpin: the sidecar copy of the removal records ──

/// The scene of R-L-oldpin:first-load: the stale-fork scene, but bob's removal is in
/// the pin file only, as a murk 0.15 machine leaves it (no sidecar).
fn removal_without_copy(s: &Scene) -> Vec<u8> {
    let (stale, _) = stale_fork_scene(s);
    let sidecar = pin_file(&s.alice, &s.repo).with_extension("lineage.json");
    let _ = fs::remove_file(sidecar);
    stale
}

/// What a murk 0.15 load of the stale fork does to alice's pin file: the
/// record goes, and bob is trusted again. The sidecar is never opened.
fn older_component_clears(s: &Scene) {
    let file = pin_file(&s.alice, &s.repo);
    let mut pin: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let bob = s.bob.pubkey();
    for field in ["removed", "removed_on", "removed_at_commit"] {
        if let Some(map) = pin[field].as_object_mut() {
            map.remove(&bob);
        }
    }
    pin["trusted"].as_array_mut().unwrap().push(bob.into());
    fs::write(&file, serde_json::to_string_pretty(&pin).unwrap()).unwrap();
}

/// A removal made before the upgrade has no copy in the sidecar. The first
/// load by this release copies it, without a change to the pin file. An
/// older component then clears the pin file's record, and this release still
/// refuses the stale fork.
#[test]
fn row_r_l_oldpin_first_load() {
    check("R-L-oldpin:first-load", |p: &mut Probe| {
        let s = Scene::new();
        let stale = removal_without_copy(&s);
        let file = pin_file(&s.alice, &s.repo);
        let sidecar = file.with_extension("lineage.json");
        p.require(!sidecar.exists(), "no sidecar before the first load")?;
        let pin_before = fs::read(&file).unwrap();
        s.run_ok(&s.alice, &["get", "DB_URL"]);
        p.reached();
        p.target(
            fs::read(&file).unwrap() == pin_before,
            "the first load leaves the pin file's bytes",
        );
        p.target(
            s.sidecar_on_bob(&s.alice),
            "after the first load, the sidecar records bob",
        );
        older_component_clears(&s);
        p.require(
            s.pin_on_bob(&s.alice) == (false, true),
            "the older component cleared the pin file's record",
        )?;
        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        let stderr = text(&get.stderr);
        p.note(format!("get: {}", stderr.trim()));
        p.target(!get.status.success(), "the stale fork is refused");
        p.target(
            !text(&get.stdout).contains("prod-db"),
            "the old value is not printed",
        );
        p.target(
            stderr.contains("older murk component"),
            "stderr says an older murk component cleared the record",
        );
        Ok(())
    });
}

/// Under `MURK_NO_SIGNER_PIN` the pin file's own record still applies, and
/// the copy writes nothing: no sidecar appears, and the pin file is as it
/// was.
#[test]
fn row_r_l_oldpin_no_signer_pin() {
    check("R-L-oldpin:no-signer-pin", |p: &mut Probe| {
        let s = Scene::new();
        let stale = removal_without_copy(&s);
        let file = pin_file(&s.alice, &s.repo);
        let pin_before = fs::read(&file).unwrap();
        put(&s.repo, &stale, "pr: change");
        let (entry, _) = s.alice.signer_entry(&s.repo);
        let get = s
            .alice
            .murk(&s.repo)
            .env("MURK_NO_SIGNER_PIN", "1")
            .env("MURK_TRUSTED_SIGNERS", entry)
            .args(["get", "DB_URL"])
            .output()
            .unwrap();
        p.reached();
        p.note(text(&get.stderr));
        p.target(!get.status.success(), "the stale fork is refused");
        p.target(
            !file.with_extension("lineage.json").exists(),
            "no sidecar is written",
        );
        p.target(
            fs::read(&file).unwrap() == pin_before,
            "the pin file is unchanged",
        );
        Ok(())
    });
}

/// When the sidecar cannot be written (here a read-only pin directory), a
/// load still goes on. murk warns once that it could not copy the records.
#[cfg(unix)]
#[test]
fn row_r_l_oldpin_readonly() {
    use std::os::unix::fs::PermissionsExt;
    check("R-L-oldpin:readonly", |p: &mut Probe| {
        let s = Scene::new();
        removal_without_copy(&s);
        let file = pin_file(&s.alice, &s.repo);
        let dir = file.parent().unwrap().to_path_buf();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        p.require(
            fs::metadata(&dir).is_ok(),
            "the pin directory is readable again",
        )?;
        let stderr = text(&get.stderr);
        p.reached();
        p.note(stderr.clone());
        p.target(
            get.status.success() && text(&get.stdout).contains("rotated-db"),
            "the load succeeds and prints the rotated value",
        );
        p.target(
            stderr.matches("cannot copy the removal records").count() == 1,
            "one warning says the records could not be copied",
        );
        p.target(
            stderr.contains("older murk component"),
            "the warning says an older component can still erase them",
        );
        Ok(())
    });
}

fn generation(file: &[u8]) -> u64 {
    super::generation_of(file)
}

/// The vault file committed at `rev`.
fn file_at(repo: &Path, rev: &str) -> Vec<u8> {
    let out = git(repo, &["show", &format!("{rev}:.murk")]);
    assert!(out.status.success(), "git show {rev}:.murk");
    out.stdout
}

/// Whether nothing new is signed: the file is `ours`, or it has no signature.
fn nothing_new_signed(file: &[u8], ours: &[u8]) -> bool {
    file == ours
        || serde_json::from_slice::<serde_json::Value>(file).is_ok_and(|v| v["sig"].is_null())
}

// ── More R-I10-h arms ──

/// carol consents before the vault lists bob again: `murk trust --re-add`
/// on main's file, which does not list him, clears her record and writes
/// nothing. alice's re-authorization then loads on carol's machine.
#[test]
fn row_r_i10_h_pre_consent() {
    check("R-I10-h:pre-consent", |p: &mut Probe| {
        let s = Scene::new();
        s.revoke_bob();
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        p.require(
            s.pin_on_bob(&s.carol).0 && s.sidecar_on_bob(&s.carol),
            "carol's pin and sidecar record bob as removed",
        )?;
        let before = working(&s.repo);
        let re_add = s.run(&s.carol, &["trust", "--re-add", &s.bob.pubkey(), "--yes"]);
        p.reached();
        p.note(format!("re-add: {}", text(&re_add.stderr).trim()));
        p.target(re_add.status.success(), "murk trust --re-add exits 0");
        p.target(working(&s.repo) == before, "the vault file is unchanged");
        p.target(
            !s.pin_on_bob(&s.carol).0 && !s.sidecar_on_bob(&s.carol),
            "carol's pin and sidecar hold no record for bob",
        );
        authorize(&s.alice, &s.repo, &s.bob, "bob");
        commit(&s.repo, "re-authorize bob");
        let get = s.run(&s.carol, &["get", "DB_URL"]);
        p.note(format!("load: {}", text(&get.stderr).trim()));
        p.target(get.status.success(), "carol loads alice's re-authorization");
        Ok(())
    });
}

/// What a repo writer holding no key builds from `like`: a murk 0.13 file
/// (no vault id or counter), unsigned, whose MAC verifies, with `like`'s
/// recipients. alice's key supplies only the MAC.
fn forged_ancestor(alice: &Machine, like: &[u8]) -> Vec<u8> {
    let identity = murk_cli::crypto::parse_identity(&alice.secret_key()).unwrap();
    let mut vault: murk_cli::types::Vault = serde_json::from_slice(like).unwrap();
    vault.agents.clear();
    vault.sig = None;
    super::common::forgery::reseal_v1(&mut vault, &identity);
    super::common::forgery::strip_v1(&mut vault, &identity);
    let mut text = serde_json::to_string_pretty(&vault).unwrap();
    text.push('\n');
    text.into_bytes()
}

/// A two-way merge: the ancestor is a forged unsigned file that lists bob,
/// and theirs is the genuine re-add of bob above the removal. carol's
/// machine recorded the removal. No ancestor that is not an authority
/// exempts theirs, so it is refused and `.murk` stays ours. Control: the
/// same kind of side over an authority ancestor that lists bob (a branch
/// made before the removal) passes that check and stops on the recipient
/// merge.
#[test]
fn row_r_i10_h_merge_forged() {
    check("R-I10-h:merge-forged", |p: &mut Probe| {
        let s = Scene::new();
        let ours = readd_branch_scene(&s);
        let theirs = file_at(&s.repo, "back");
        let main = head_commit(&s.repo);
        git_ok(&s.repo, &["checkout", "-q", "-b", "atk", &main]);
        put(
            &s.repo,
            &forged_ancestor(&s.alice, &theirs),
            "attacker: parent",
        );
        put(&s.repo, &theirs, "attacker: change");
        let tip = head_commit(&s.repo);
        git_ok(&s.repo, &["checkout", "-q", "main"]);
        let (ok, stderr) = git_as(&s.carol, &s.repo, &["cherry-pick", &tip]);
        p.reached();
        p.note(format!("cherry-pick: {}", stderr.trim()));
        p.target(!ok, "the cherry-pick stops");
        p.target(working(&s.repo) == ours, ".murk is ours, byte for byte");
        p.target(
            stderr.contains("theirs failed its authenticity check") && stderr.contains("bob"),
            "theirs is refused, naming bob",
        );
        git_as(&s.carol, &s.repo, &["cherry-pick", "--abort"]);

        // Control: a branch made before the removal, over its authority
        // ancestor.
        let s = Scene::new();
        s.stale_fork("old", &s.r0, 1);
        s.revoke_bob();
        s.run_ok(&s.carol, &["get", "DB_URL"]);
        let ours = working(&s.repo);
        let (ok, stderr) = git_merge(&s.carol, &s.repo, "old");
        p.note(format!("control merge: {}", stderr.trim()));
        p.target(
            !ok && !stderr.contains("theirs failed its authenticity check")
                && stderr.contains("removed on one side but not the other")
                && nothing_new_signed(&working(&s.repo), &ours),
            "control: over an authority ancestor the side passes and the recipient merge stops",
        );
        Ok(())
    });
}

/// An older murk component clears the pin file's record after this
/// release's own revoke wrote the sidecar copy. This release still refuses
/// the stale fork and says what happened.
#[test]
fn row_r_i10_h_older() {
    check("R-I10-h:older", |p: &mut Probe| {
        let s = Scene::new();
        p.require(
            !s.sidecar_on_bob(&s.alice),
            "the sidecar holds no record before the revoke",
        )?;
        let (stale, _) = stale_fork_scene(&s);
        p.require(
            s.sidecar_on_bob(&s.alice),
            "the revoke wrote the sidecar copy",
        )?;
        older_component_clears(&s);
        p.require(
            s.pin_on_bob(&s.alice) == (false, true) && s.sidecar_on_bob(&s.alice),
            "the pin file has no record and trusts bob; the sidecar has the record",
        )?;
        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        let stderr = text(&get.stderr);
        p.note(format!("get: {}", stderr.trim()));
        p.target(!get.status.success(), "the stale fork is refused");
        p.target(
            !text(&get.stdout).contains("prod-db"),
            "the old value is not printed",
        );
        p.target(
            stderr.contains("older murk component") && stderr.contains("--re-add"),
            "stderr names an older murk component and --re-add",
        );
        let before = working(&s.repo);
        let add = s
            .cmd(&s.alice)
            .args(["add", "NEW_AFTER"])
            .write_stdin("new\n")
            .output()
            .unwrap();
        p.target(
            !add.status.success() && working(&s.repo) == before,
            "the next write does not happen",
        );
        p.target(s.sidecar_on_bob(&s.alice), "the sidecar still records bob");
        Ok(())
    });
}

/// Stated limit: a removal an older component recorded and cleared before
/// this release read the pin has no copy. This release loads the stale fork.
#[test]
fn row_r_i10_h_older_window() {
    check("R-I10-h:older-window", |p: &mut Probe| {
        let s = Scene::new();
        let stale = removal_without_copy(&s);
        older_component_clears(&s);
        put(&s.repo, &stale, "pr: change");
        let get = s.run(&s.alice, &["get", "DB_URL"]);
        p.reached();
        p.note(text(&get.stderr));
        p.target(
            get.status.success() && text(&get.stdout).contains("prod-db"),
            "this release loads the stale fork and prints the old value (limit 10)",
        );
        p.target(
            !s.sidecar_on_bob(&s.alice),
            "the sidecar this read leaves has no record for bob",
        );
        Ok(())
    });
}

/// Stated limit: a runner that keeps its HOME but loads only with
/// `MURK_TRUSTED_SIGNERS` never records the removal, so it loads the stale
/// fork.
#[test]
fn row_r_i10_h_ci_env() {
    check("R-I10-h:ci-env", |p: &mut Probe| {
        let s = Scene::new();
        let (entry, _) = s.alice.signer_entry(&s.repo);
        let runner = Machine::new(&s.base, "runner");
        let load = || {
            runner
                .murk(&s.repo)
                .env("MURK_KEY", s.alice.secret_key())
                .env("MURK_TRUSTED_SIGNERS", &entry)
                .args(["get", "DB_URL"])
                .output()
                .unwrap()
        };
        p.require(load().status.success(), "the runner loads R0")?;
        let (stale, _) = stale_fork_scene(&s);
        p.require(load().status.success(), "the runner loads main's removal")?;
        let removed = || {
            let pin: serde_json::Value =
                serde_json::from_slice(&fs::read(pin_file(&runner, &s.repo)).unwrap()).unwrap();
            pin["removed"].as_object().is_some_and(|m| !m.is_empty())
        };
        p.require(!removed(), "the runner's pin has no removal record")?;
        put(&s.repo, &stale, "pr: change");
        let get = load();
        p.reached();
        p.note(text(&get.stderr));
        p.target(
            get.status.success() && text(&get.stdout).contains("prod-db"),
            "the runner loads the stale fork and prints the old value (limit 10)",
        );
        p.target(!removed(), "the runner's pin still has no removal record");
        Ok(())
    });
}

/// `git merge` as alice, with the driver run under `home` (`None`: no HOME).
fn merge_with_home(s: &Scene, home: Option<&Path>, branch: &str) -> (bool, String) {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["-c", "commit.gpgsign=false", "merge", "--no-edit", branch])
        .current_dir(&s.repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .env_remove("HOME")
        .env_remove("XDG_RUNTIME_DIR");
    for var in super::common::MURK_CONTEXT_VARS {
        cmd.env_remove(var);
    }
    if let Some(home) = home {
        cmd.env("HOME", home);
    }
    cmd.env("MURK_KEY_FILE", s.alice.key_file());
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Stated limit: the merge driver judges by the pin under the HOME git gives
/// it. Merging a branch made before the removal, which still lists bob:
/// under alice's HOME and under another HOME with its own older pin, it
/// stops on the recipient; with an empty HOME or none, no input is trusted
/// and `.murk` stays ours. Nothing is signed, and the other HOME's pin has
/// no record for bob.
#[test]
fn row_r_i10_h_driver_home() {
    check("R-I10-h:driver-home", |p: &mut Probe| {
        let s = Scene::new();
        // A HOME whose pin trusted the vault before the removal.
        let gui = s.base.join("gui-home");
        fs::create_dir_all(&gui).unwrap();
        let gui_machine = Machine { home: gui.clone() };
        gui_machine
            .with_key(&s.repo, &s.alice.key_file())
            .args(["trust", "--yes"])
            .assert()
            .success();
        s.stale_fork("old", &s.r0, 1);
        s.revoke_bob();
        let main = head_commit(&s.repo);
        let ours = working(&s.repo);
        let empty = s.base.join("empty-home");
        fs::create_dir_all(&empty).unwrap();
        let arms: [(&str, Option<&Path>); 4] = [
            ("alice's HOME", Some(&s.alice.home)),
            ("an empty HOME", Some(&empty)),
            ("no HOME", None),
            ("another HOME with an older pin", Some(&gui)),
        ];
        let mut seen = Vec::new();
        for (label, home) in arms {
            git_ok(&s.repo, &["reset", "-q", "--hard", &main]);
            let (ok, stderr) = merge_with_home(&s, home, "old");
            let file = working(&s.repo);
            git(&s.repo, &["merge", "--abort"]);
            p.note(format!("{label}: {}", stderr.trim()));
            seen.push((label, ok, stderr, file));
        }
        p.reached();
        for (label, ok, stderr, file) in &seen {
            p.target(!ok, format!("{label}: the merge stops"));
            let no_pin = label.contains("empty") || label.contains("no HOME");
            if no_pin {
                p.target(
                    stderr.contains("ours failed its authenticity check")
                        && stderr.contains("not trusted on this machine yet")
                        && *file == ours,
                    format!("{label}: with no pin, ours is not trusted and .murk stays ours"),
                );
            } else {
                p.target(
                    stderr.contains("removed on one side but not the other")
                        && !stderr.contains("not trusted on this machine yet"),
                    format!("{label}: it conflicts on the recipient bob only"),
                );
            }
            p.target(
                nothing_new_signed(file, &ours),
                format!("{label}: nothing is signed"),
            );
        }
        let gui_pin: serde_json::Value =
            serde_json::from_slice(&fs::read(pin_file(&gui_machine, &s.repo)).unwrap()).unwrap();
        p.target(
            gui_pin["removed"].get(s.bob.pubkey()).is_none(),
            "the other HOME's pin has no record for bob",
        );
        Ok(())
    });
}

/// Release checklist, stated limit: an older murk component under the same
/// HOME (`MURK_OLDER_BIN`, a murk 0.15.2 or earlier binary) loads the stale fork,
/// prints the old value and saves a vault bob reads. It leaves the sidecar
/// as it was, and this release then refuses the vault.
#[test]
#[ignore = "release checklist: set MURK_OLDER_BIN to a murk 0.15.2 or earlier binary"]
fn row_r_i10_h_older_exposure() {
    check("R-I10-h:older-exposure", |p: &mut Probe| {
        let older = std::env::var("MURK_OLDER_BIN")
            .map_err(|_| "MURK_OLDER_BIN names no older murk".to_string())?;
        let s = Scene::new();
        let (stale, _) = stale_fork_scene(&s);
        // murk verify exits non-zero on the unsigned git commits of this
        // scene; what matters is that it read the pin.
        s.run(&s.alice, &["verify"]);
        p.require(s.sidecar_on_bob(&s.alice), "the sidecar records bob")?;
        let sidecar = pin_file(&s.alice, &s.repo).with_extension("lineage.json");
        let sidecar_before = fs::read(&sidecar).unwrap();
        put(&s.repo, &stale, "pr: change");
        let old = |args: &[&str], stdin: Option<&str>| {
            let mut cmd = std::process::Command::new(&older);
            cmd.args(args).current_dir(&s.repo);
            for var in super::common::MURK_CONTEXT_VARS {
                cmd.env_remove(var);
            }
            cmd.env("HOME", &s.alice.home)
                .env("MURK_KEY_FILE", s.alice.key_file())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            if let Some(input) = stdin {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(input.as_bytes())
                    .unwrap();
            }
            child.wait_with_output().unwrap()
        };
        let get = old(&["get", "DB_URL"], None);
        p.reached();
        p.note(format!("older get: {}", text(&get.stderr).trim()));
        p.target(
            get.status.success() && text(&get.stdout).contains("prod-db"),
            "the older component prints the old value",
        );
        let add = old(&["add", "NEW_AFTER"], Some("newvalue\n"));
        p.note(format!("older add: {}", text(&add.stderr).trim()));
        let bob_trust = s.run(&s.bob, &["trust", "--yes"]);
        let bob_get = s.run(&s.bob, &["get", "NEW_AFTER"]);
        p.target(
            add.status.success()
                && bob_trust.status.success()
                && text(&bob_get.stdout).contains("newvalue"),
            "the older component's save is readable by bob",
        );
        p.target(
            fs::read(&sidecar).unwrap() == sidecar_before,
            "the sidecar is byte-identical",
        );
        let now = s.run(&s.alice, &["get", "DB_URL"]);
        p.note(format!("this release: {}", text(&now.stderr).trim()));
        p.target(!now.status.success(), "this release refuses the vault");
        Ok(())
    });
}
