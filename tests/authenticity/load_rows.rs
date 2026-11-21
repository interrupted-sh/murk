// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Invariant rows about loads and `murk trust`: what a machine accepts when a
//! vault file appears where it reads, and what it records when the user trusts
//! one. Each row's state comes from `tests/invariant_rows.tsv`; see
//! `tests/common/rows.rs` for what a state demands.
//!
//! A row for lineage, format 4 or the vault-identity checks asserts the
//! behaviour those features will have. Its decisive step is not reachable
//! until a save writes format 4, which the row checks before it counts any
//! target, so today it reports "did not reach" and never passes vacuously.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::common::rows::{self, Probe};
use super::{
    BobWroteMain, Machine, agent_get, alice_repo, commit, git, git_ok, granted_repo, head_commit,
    pin_dir,
};

/// What one murk (or other) command did.
struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Run {
    /// stdout and stderr together, for a check on what the command said.
    fn said(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn out(mut cmd: assert_cmd::Command) -> Run {
    let out = cmd.output().unwrap();
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A machine and the key file it signs and reads with: the key is passed
/// explicitly, so the machine works in any checkout.
struct Person {
    machine: Machine,
    key: PathBuf,
}

impl Person {
    /// A second machine for whoever holds the key file `key`.
    fn new(base: &Path, name: &str, key: &Path) -> Self {
        Self {
            machine: Machine::new(base, name),
            key: key.to_path_buf(),
        }
    }

    /// The person `machine` is, with the key `murk init` stored for them.
    fn of(machine: Machine) -> Self {
        let key = machine.key_file();
        Self { machine, key }
    }

    fn home(&self) -> &Path {
        &self.machine.home
    }

    fn murk(&self, dir: &Path) -> assert_cmd::Command {
        self.machine.with_key(dir, &self.key)
    }

    /// `murk <args>` in `dir`.
    fn run(&self, dir: &Path, args: &[&str]) -> Run {
        let mut cmd = self.murk(dir);
        cmd.args(args);
        out(cmd)
    }

    /// `murk <args>` in `dir`, with `value` on stdin.
    fn run_with(&self, dir: &Path, args: &[&str], value: &str) -> Run {
        let mut cmd = self.murk(dir);
        cmd.args(args).write_stdin(format!("{value}\n"));
        out(cmd)
    }

    /// `murk get <name> --vault <vault>` in `dir`.
    fn get(&self, dir: &Path, vault: &str, name: &str) -> Run {
        self.run(dir, &["get", name, "--vault", vault])
    }

    /// `murk trust --yes --vault <vault>` in `dir`.
    fn trust(&self, dir: &Path, vault: &str) -> Run {
        self.run(dir, &["trust", "--yes", "--vault", vault])
    }

    /// `murk add <name> --vault <vault>` in `dir`, writing `value`.
    fn add(&self, dir: &Path, vault: &str, name: &str, value: &str) -> Run {
        self.run_with(dir, &["add", name, "--vault", vault], value)
    }
}

/// The parsed JSON of the file at `path`.
fn json_of(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// The major part of the header version of the vault at `path`.
fn format_of(path: &Path) -> u64 {
    json_of(path)["version"]
        .as_str()
        .and_then(|v| v.split('.').next())
        .and_then(|major| major.parse().ok())
        .unwrap()
}

/// The lineage entry `"<generation>:<revision id>"` of the signed vault at
/// `path`: how a later vault names this revision in its `prev`.
fn entry_of(path: &Path) -> String {
    let vault = murk_cli::read_vault(path.to_str().unwrap()).unwrap();
    format!(
        "{}:{}",
        vault.generation,
        murk_cli::trust::vault_fingerprint(&vault)
    )
}

/// The `prev` entries of the vault at `path` (none for a format that has no
/// such field).
fn prev_of(path: &Path) -> Vec<String> {
    json_of(path)["prev"]
        .as_array()
        .map(|a| a.iter().map(|e| e.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

/// The pin files on `who`'s machine, not counting their lineage sidecars.
fn pins_of(who: &Person) -> Vec<PathBuf> {
    json_files(who, |name| !name.ends_with(".lineage.json"))
}

/// The lineage sidecars (`<hash>.lineage.json`, next to each pin) on
/// `who`'s machine, parsed.
fn sidecars_of(who: &Person) -> Vec<serde_json::Value> {
    json_files(who, |name| name.ends_with(".lineage.json"))
        .iter()
        .map(|p| json_of(p))
        .collect()
}

fn json_files(who: &Person, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(pin_dir(&who.machine))
        .map(|d| {
            d.map(|e| e.unwrap().path())
                .filter(|p| {
                    p.extension().is_some_and(|x| x == "json")
                        && keep(&p.file_name().unwrap().to_string_lossy())
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// What `who`'s sidecars hold under `field` for `branch`: the lineage
/// reference is one entry, the superseded set several.
fn sidecar_values(who: &Person, field: &str, branch: &str) -> Vec<String> {
    sidecars_of(who)
        .iter()
        .flat_map(|s| match &s[field][branch] {
            serde_json::Value::String(entry) => vec![entry.clone()],
            serde_json::Value::Array(all) => all
                .iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// Whether `who`'s machine holds `entry` as its lineage reference on `branch`.
fn has_reference(who: &Person, branch: &str, entry: &str) -> bool {
    sidecar_values(who, "lineage_heads", branch)
        .iter()
        .any(|e| e == entry)
}

/// Whether `who`'s machine holds every one of `entries` as superseded on
/// `branch`: the revisions a deliberate revert undid.
fn has_superseded(who: &Person, branch: &str, entries: &[&str]) -> bool {
    let held = sidecar_values(who, "lineage_superseded", branch);
    entries.iter().all(|e| held.iter().any(|h| h == e))
}

/// The lineage entry of the vault committed as `.murk` at `rev` in `repo`.
fn entry_at(repo: &Path, rev: &str) -> String {
    let scratch = TempDir::new().unwrap();
    let file = scratch.path().join(".murk");
    fs::write(&file, git(repo, &["show", &format!("{rev}:.murk")]).stdout).unwrap();
    entry_of(&file)
}

/// Put the vault committed as `.murk` at `rev` in `repo` over the working
/// file, uncommitted.
fn restore_vault(repo: &Path, rev: &str) {
    fs::write(
        repo.join(".murk"),
        git(repo, &["show", &format!("{rev}:.murk")]).stdout,
    )
    .unwrap();
}

/// `git merge <branch>` in `repo` as `who`, with the murk driver and `who`'s
/// key: (success, stderr).
fn merge(who: &Person, repo: &Path, branch: &str) -> (bool, String) {
    let mut merge = std::process::Command::new("git");
    merge
        .args(["-c", "commit.gpgsign=false", "merge", "--no-edit", branch])
        .current_dir(repo)
        .env("HOME", who.home())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "t@t");
    for var in super::common::MURK_CONTEXT_VARS {
        merge.env_remove(var);
    }
    merge.env("MURK_KEY_FILE", &who.key);
    let out = merge.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Whether a merge's stderr shows the murk driver ran, not only git's own
/// conflict text: the driver ends every run with its verdict.
fn driver_spoke(stderr: &str) -> bool {
    stderr.contains("vault merged cleanly") || stderr.contains("to finish:")
}

/// Whether the vault file at `path` holds a secret called `name`.
fn has_secret(path: &Path, name: &str) -> bool {
    json_of(path)["secrets"].get(name).is_some()
}

/// A scenario step needs a vault saved in format 4, which this build does
/// not write: the row cannot reach its decisive step.
fn require_format_4(p: &Probe, vault: &Path, what: &str) -> Result<(), String> {
    let major = format_of(vault);
    p.require(
        major == 4,
        format!("{what} is format {major}, so the lineage rules have nothing to judge yet"),
    )
}

/// The `get` a poisoned load would answer: the value came out.
fn printed(run: &Run, value: &str) -> bool {
    run.ok && run.stdout.contains(value)
}

/// The command refused, and the poison went nowhere.
fn refused(run: &Run, poison: &str) -> bool {
    !run.ok && !run.said().contains(poison)
}

/// Whether `text` names both paths. A path that ends the other (`.murk` in
/// `staging.murk`) counts only where it stands alone.
fn names_both(text: &str, long: &str, short: &str) -> bool {
    text.contains(long) && text.replace(long, "").contains(short)
}

/// The command's `Run` when it succeeded; a broken setup step otherwise.
fn must(run: Run, what: &str) -> Result<Run, String> {
    if run.ok {
        Ok(run)
    } else {
        Err(format!("{what}: {}", run.said()))
    }
}

// ── R-I15-b ──

/// A grant key file whose anchor names an age signer with no verifying key
/// never verifies a vault, even though the vault registers that signer's key:
/// a registry inside the vault is not an anchor. The control is the same
/// entry with its verifying key, which reads. Both the CLI load and the
/// library check are driven.
#[test]
fn row_r_i15_b() {
    rows::check("R-I15-b", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, key) = granted_repo(base.path(), "1h");
        let (entry, _) = alice.signer_entry(&repo);
        let (signer, verifying_key) = entry.split_once(':').unwrap();
        let anchor_line = format!("# murk-trusted-signer: {entry}");
        let text = fs::read_to_string(&key).unwrap();
        p.require(
            text.contains(&anchor_line),
            "the minted key file anchors alice by signer and verifying key",
        )?;

        // The vault registers the signer's key, so a loader that took the
        // registry for an anchor would accept the keyless entry.
        let vault = murk_cli::read_vault(repo.join(".murk").to_str().unwrap()).unwrap();
        let identity = murk_cli::crypto::parse_identity(&alice.secret_key()).unwrap();
        let meta = murk_cli::decrypt_meta(&vault, &identity).unwrap().unwrap();
        p.require(
            meta.signers.get(signer).is_some_and(|k| k == verifying_key),
            "the vault registers alice's verifying key",
        )?;

        let mut keyed = murk_cli::trust::TrustedSigners::new();
        keyed.insert(signer.to_string(), Some(verifying_key.to_string()));
        p.require(
            murk_cli::trust::verify_anchored(&vault, &keyed).is_ok(),
            "control: the signer with its verifying key verifies the vault",
        )?;
        let read = out(agent_get(base.path(), &repo, &key));
        p.require(
            printed(&read, "prod-db"),
            format!("control: the minted key file reads: {}", read.said()),
        )?;

        fs::write(
            &key,
            text.replace(&anchor_line, &format!("# murk-trusted-signer: {signer}")),
        )
        .unwrap();
        p.reached();
        let keyless = out(agent_get(base.path(), &repo, &key));
        p.note(keyless.stderr.clone());
        p.target(
            refused(&keyless, "prod-db"),
            "a key file naming the signer without its verifying key reads nothing",
        );
        let mut anchor = murk_cli::trust::TrustedSigners::new();
        anchor.insert(signer.to_string(), None);
        p.target(
            murk_cli::trust::verify_anchored(&vault, &anchor).is_err(),
            "an age signer without a verifying key never verifies the vault",
        );
        Ok(())
    });
}

// ── R-I23-a ──

/// A replace ref changes the ancestry git reports. Murk decides whether a
/// vault is from before a removal by asking whether the commit checked out is
/// an ancestor of the commit the removal was recorded at, so a replace ref
/// that grafts Bob's post-removal commit under that commit would make his
/// vault look older than his removal. Bob, removed, signs a vault on a root
/// commit of his own and plants the ref; Alice's machine must still refuse it,
/// exactly as it does without the ref, and the ref must really change what
/// plain git reports (the control).
#[test]
fn row_r_i23_a() {
    rows::check("R-I23-a", |p| {
        let t = BobWroteMain::new();
        t.alice
            .murk(&t.repo)
            .args(["circle", "revoke", "bob"])
            .assert()
            .success();
        let mut recorded = None;
        super::edit_pin(&t.alice, &t.repo, |pin| {
            recorded = pin["removed_at_commit"]
                .as_object()
                .and_then(|m| m.values().next())
                .and_then(|c| c.as_str())
                .map(str::to_string);
        });
        let removal = recorded.ok_or("Alice's pin records no commit for the removal")?;
        commit(&t.repo, "offboard");

        // Bob's vault, signed after the removal, on a commit with no history.
        git_ok(&t.repo, &["checkout", "-q", "--orphan", "evil"]);
        let bob0 = git(&t.repo, &["show", &format!("{}:.murk", t.bob0)]).stdout;
        fs::write(t.repo.join(".murk"), bob0).unwrap();
        let after = t.bob_writes("attacker-db");

        let alice = Person::of(Machine {
            home: t.alice.home.clone(),
        });
        let before = alice.get(&t.repo, ".murk", "DB_URL");
        p.note(before.stderr.clone());
        p.require(
            refused(&before, "attacker-db") && before.stderr.contains("bob"),
            "control: without the ref, Alice refuses Bob's post-removal vault naming him",
        )?;

        // The ref: the removal commit, with `after` as its parent.
        let tree =
            String::from_utf8(git(&t.repo, &["rev-parse", &format!("{removal}^{{tree}}")]).stdout)
                .unwrap();
        let grafted = String::from_utf8(
            git(
                &t.repo,
                &["commit-tree", tree.trim(), "-p", &after, "-m", "graft"],
            )
            .stdout,
        )
        .unwrap();
        git_ok(&t.repo, &["replace", "-f", &removal, grafted.trim()]);
        let ancestor = |hide_replacements: bool| {
            let mut cmd = std::process::Command::new("git");
            cmd.args(["merge-base", "--is-ancestor", &after, &removal])
                .current_dir(&t.repo)
                .env("HOME", &t.repo)
                .env("GIT_CONFIG_NOSYSTEM", "1");
            if hide_replacements {
                cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
            }
            cmd.status().unwrap().success()
        };
        p.require(
            ancestor(false) && !ancestor(true),
            "control: the ref makes Bob's commit an ancestor of the removal commit for plain git, and only the ref does",
        )?;

        p.reached();
        let planted = alice.get(&t.repo, ".murk", "DB_URL");
        p.note(planted.stderr.clone());
        p.target(
            refused(&planted, "attacker-db"),
            "with the replace ref, Alice still refuses Bob's post-removal vault",
        );
        p.today(
            printed(&planted, "attacker-db"),
            "with the replace ref, murk reads Bob's post-removal vault as from before his removal",
        );
        Ok(())
    });
}

/// Bob, removed on Alice's machine, signs a vault on a root commit of his own
/// (branch `evil`, checked out), and Alice's machine refuses it, naming him.
struct BobAfterRemoval {
    t: BobWroteMain,
    alice: Person,
    /// The commit Alice's pin records for Bob's removal.
    removal: String,
    /// Bob's post-removal vault commit, checked out.
    after: String,
}

impl BobAfterRemoval {
    fn new(p: &mut Probe) -> Result<Self, String> {
        let t = BobWroteMain::new();
        t.alice
            .murk(&t.repo)
            .args(["circle", "revoke", "bob"])
            .assert()
            .success();
        let mut recorded = None;
        super::edit_pin(&t.alice, &t.repo, |pin| {
            recorded = pin["removed_at_commit"]
                .as_object()
                .and_then(|m| m.values().next())
                .and_then(|c| c.as_str())
                .map(str::to_string);
        });
        let removal = recorded.ok_or("Alice's pin records no commit for the removal")?;
        commit(&t.repo, "offboard");

        git_ok(&t.repo, &["checkout", "-q", "--orphan", "evil"]);
        let bob0 = git(&t.repo, &["show", &format!("{}:.murk", t.bob0)]).stdout;
        fs::write(t.repo.join(".murk"), bob0).unwrap();
        let after = t.bob_writes("attacker-db");

        let alice = Person::of(Machine {
            home: t.alice.home.clone(),
        });
        let before = alice.get(&t.repo, ".murk", "DB_URL");
        p.note(before.stderr.clone());
        p.require(
            refused(&before, "attacker-db") && before.stderr.contains("bob"),
            "control: Alice refuses Bob's post-removal vault naming him",
        )?;
        Ok(Self {
            t,
            alice,
            removal,
            after,
        })
    }

    /// Whether plain git, with `env` set, reports Bob's commit as an ancestor
    /// of the removal commit.
    fn git_says_ancestor(&self, env: &[(&str, &Path)]) -> bool {
        let mut cmd = std::process::Command::new("git");
        cmd.args(["merge-base", "--is-ancestor", &self.after, &self.removal])
            .current_dir(&self.t.repo)
            .env("HOME", &self.t.repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stderr(std::process::Stdio::null());
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.status().unwrap().success()
    }
}

// ── R-I23-b ──

/// The graft-file form of R-I23-a. A graft line naming Bob's post-removal
/// commit as a parent of the removal commit makes his vault look older than
/// his removal to plain git. Alice's machine must still refuse it, with the
/// graft in the repository's `info/grafts` and with the graft file named by
/// `GIT_GRAFT_FILE` in her environment.
#[test]
fn row_r_i23_b() {
    rows::check("R-I23-b", |p| {
        let s = BobAfterRemoval::new(p)?;
        let line = format!("{} {}\n", s.removal, s.after);

        let in_repo = s.t.repo.join(".git/info/grafts");
        fs::create_dir_all(in_repo.parent().unwrap()).unwrap();
        fs::write(&in_repo, &line).unwrap();
        p.require(
            s.git_says_ancestor(&[]),
            "control: the repository's graft makes Bob's commit an ancestor of the removal commit for plain git",
        )?;
        p.reached();
        let planted = s.alice.get(&s.t.repo, ".murk", "DB_URL");
        p.note(planted.stderr.clone());
        p.target(
            refused(&planted, "attacker-db"),
            "with a graft in info/grafts, Alice still refuses Bob's post-removal vault",
        );
        p.today(
            printed(&planted, "attacker-db"),
            "with a graft in info/grafts, murk reads Bob's post-removal vault as from before his removal",
        );
        fs::remove_file(&in_repo).unwrap();

        let elsewhere = s.t.base.path().join("grafts");
        fs::write(&elsewhere, &line).unwrap();
        p.require(
            s.git_says_ancestor(&[("GIT_GRAFT_FILE", &elsewhere)]),
            "control: GIT_GRAFT_FILE makes Bob's commit an ancestor of the removal commit for plain git",
        )?;
        let mut cmd = s.alice.murk(&s.t.repo);
        cmd.args(["get", "DB_URL", "--vault", ".murk"])
            .env("GIT_GRAFT_FILE", &elsewhere);
        let planted = out(cmd);
        p.note(planted.stderr.clone());
        p.target(
            refused(&planted, "attacker-db"),
            "with GIT_GRAFT_FILE set, Alice still refuses Bob's post-removal vault",
        );
        p.today(
            printed(&planted, "attacker-db"),
            "with GIT_GRAFT_FILE set, murk reads Bob's post-removal vault as from before his removal",
        );
        Ok(())
    });
}

// ── R-I23-c ──

/// Unknown ancestry counts as not-an-ancestor. When the commit Alice's pin
/// records for Bob's removal is not in the repository (a shallow clone, or
/// an object lost or pruned), git cannot say whether the commit checked out
/// is older than the removal, and Alice's machine must treat Bob's vault as
/// from after it.
#[test]
fn row_r_i23_c() {
    rows::check("R-I23-c", |p| {
        let s = BobAfterRemoval::new(p)?;
        let (dir, file) = s.removal.split_at(2);
        fs::remove_file(s.t.repo.join(".git/objects").join(dir).join(file))
            .map_err(|e| format!("the removal commit is not a loose object: {e}"))?;
        p.require(
            !git(&s.t.repo, &["cat-file", "-e", &s.removal])
                .status
                .success(),
            "control: the removal commit is gone from the repository",
        )?;
        p.reached();
        let planted = s.alice.get(&s.t.repo, ".murk", "DB_URL");
        p.note(planted.stderr.clone());
        p.target(
            refused(&planted, "attacker-db") && planted.stderr.contains("bob"),
            "with the removal commit missing, Alice still refuses Bob's post-removal vault, naming him",
        );
        p.today(
            printed(&planted, "attacker-db"),
            "with the removal commit missing, murk reads Bob's post-removal vault as from before his removal",
        );
        Ok(())
    });
}

// ── Two paths that share one vault id ──

/// A prod vault in `repo`, and a byte copy of it in a second checkout
/// `staging` made outside this one, trusted there by the same machine and
/// saved three times there (`STAGING-db-1` to `STAGING-db-3`).
fn copied_vault(base: &Path) -> Result<(Person, PathBuf, PathBuf), String> {
    let (machine, repo) = alice_repo(base);
    let alice = Person::of(machine);
    commit(&repo, "prod");
    let staging = base.join("staging");
    fs::create_dir_all(&staging).unwrap();
    git_ok(&staging, &["init", "-q", "-b", "main"]);
    fs::copy(repo.join(".murk"), staging.join(".murk")).unwrap();
    must(alice.trust(&staging, ".murk"), "trust the copy")?;
    for i in 1..=3 {
        let value = format!("STAGING-db-{i}");
        must(
            alice.add(&staging, ".murk", "DB_URL", &value),
            "save the copy",
        )?;
    }
    Ok((alice, repo, staging))
}

/// Prod saves once after the copy, commits it, and the machine loads that
/// save: its lineage reference is now a revision the copy never saw.
fn prod_saves_after_the_copy(alice: &Person, repo: &Path) -> Result<(), String> {
    must(
        alice.add(repo, ".murk", "DB_URL", "prod-db-2"),
        "prod saves after the copy",
    )?;
    commit(repo, "prod saves after the copy");
    let load = alice.get(repo, ".murk", "DB_URL");
    if printed(&load, "prod-db-2") {
        Ok(())
    } else {
        Err(format!(
            "prod does not load after its own save: {}",
            load.said()
        ))
    }
}

/// One machine that recorded both paths of one vault id in one checkout:
/// `.murk`, and `staging.murk` (a byte copy trusted before anything was
/// committed, then saved three times), with both files tracked.
fn both_paths_recorded(base: &Path) -> Result<(Person, PathBuf), String> {
    let (machine, repo) = alice_repo(base);
    let alice = Person::of(machine);
    fs::copy(repo.join(".murk"), repo.join("staging.murk")).unwrap();
    must(alice.trust(&repo, "staging.murk"), "trust the copy")?;
    for i in 1..=3 {
        let value = format!("STAGING-db-{i}");
        must(
            alice.add(&repo, "staging.murk", "DB_URL", &value),
            "save the copy",
        )?;
    }
    commit(&repo, "prod and staging");
    Ok((alice, repo))
}

/// A byte copy of prod, saved apart from it and swapped in after prod saved
/// again, does not descend from the revision the machine accepted: refused,
/// and the copy's value never comes out. The control is the stated residual
/// (`R-I8-b:residual`), and the copy's own checkout is a separate repository,
/// so only lineage can tell the files apart.
#[test]
fn row_r_i8_b_a() {
    rows::check("R-I8-b:a", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, staging) = copied_vault(base.path())?;
        prod_saves_after_the_copy(&alice, &repo)?;
        require_format_4(p, &repo.join(".murk"), "prod's save after the copy")?;
        let reference = entry_of(&repo.join(".murk"));
        p.require(
            has_reference(&alice, "main", &reference),
            "before the swap, the machine's reference is prod's save after the copy",
        )?;
        fs::copy(staging.join(".murk"), repo.join(".murk")).unwrap();
        p.reached();
        let swapped = alice.get(&repo, ".murk", "DB_URL");
        p.note(swapped.stderr.clone());
        p.target(
            refused(&swapped, "STAGING-db-3"),
            "the swapped-in copy is refused and its value never comes out",
        );
        p.target(
            swapped.stderr.contains("descend"),
            "the refusal says the vault does not descend from the revision accepted here",
        );
        Ok(())
    });
}

/// As `R-I8-b:a`, with the copy also tracked as `staging.murk`: the machine
/// warns that another file shares the vault id, naming it, and the lineage
/// rule still refuses the swapped-in file.
#[test]
fn row_r_i8_b_b() {
    rows::check("R-I8-b:b", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, staging) = copied_vault(base.path())?;
        prod_saves_after_the_copy(&alice, &repo)?;
        require_format_4(p, &repo.join(".murk"), "prod's save after the copy")?;
        let reference = entry_of(&repo.join(".murk"));
        p.require(
            has_reference(&alice, "main", &reference),
            "before the swap, the machine's reference is prod's save after the copy",
        )?;
        fs::copy(staging.join(".murk"), repo.join(".murk")).unwrap();
        fs::copy(staging.join(".murk"), repo.join("staging.murk")).unwrap();
        commit(&repo, "staging, tracked beside prod");
        p.reached();
        let swapped = alice.get(&repo, ".murk", "DB_URL");
        p.note(swapped.stderr.clone());
        p.target(
            refused(&swapped, "STAGING-db-3"),
            "the swapped-in copy is refused and its value never comes out",
        );
        p.target(
            swapped.stderr.contains("staging.murk"),
            "the warning names the other file that shares the vault id",
        );
        p.target(
            swapped.stderr.contains("descend"),
            "the refusal is still the lineage rule: the vault does not descend from the revision accepted here",
        );
        Ok(())
    });
}

/// A machine that recorded both paths of one vault id refuses both while
/// both files are tracked, and each refusal names both paths. Today both
/// load.
#[test]
fn row_r_i8_b_c() {
    rows::check("R-I8-b:c", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo) = both_paths_recorded(base.path())?;
        p.require(
            pins_of(&alice).len() == 2,
            "the machine holds a pin for each path",
        )?;
        p.reached();
        let prod = alice.get(&repo, ".murk", "DB_URL");
        let staging = alice.get(&repo, "staging.murk", "DB_URL");
        p.note(prod.stderr.clone());
        p.note(staging.stderr.clone());
        p.target(
            refused(&prod, "prod-db") && names_both(&prod.stderr, "staging.murk", ".murk"),
            "the prod path is refused, naming both paths",
        );
        p.target(
            refused(&staging, "STAGING-db-3")
                && names_both(&staging.stderr, "staging.murk", ".murk"),
            "the staging path is refused, naming both paths",
        );
        p.today(
            printed(&prod, "prod-db"),
            "the prod path loads although the machine recorded this vault id at another tracked path",
        );
        p.today(
            printed(&staging, "STAGING-db-3"),
            "the staging path loads too",
        );
        Ok(())
    });
}

/// The stated residual: when prod has not saved since the copy was made, the
/// swapped-in copy descends from the revision the machine last accepted, so
/// it is accepted and its value comes out.
#[test]
fn row_r_i8_b_residual() {
    rows::check("R-I8-b:residual", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, staging) = copied_vault(base.path())?;
        let prod = alice.get(&repo, ".murk", "DB_URL");
        p.require(
            printed(&prod, "prod-db"),
            format!("control: prod loads before the swap: {}", prod.said()),
        )?;
        fs::copy(staging.join(".murk"), repo.join(".murk")).unwrap();
        p.reached();
        let swapped = alice.get(&repo, ".murk", "DB_URL");
        p.note(swapped.stderr.clone());
        p.target(
            printed(&swapped, "STAGING-db-3"),
            "with no prod save after the copy, the swapped-in copy is accepted",
        );
        Ok(())
    });
}

/// `murk trust` of a byte copy of a vault this machine pinned at another
/// path is refused, naming both paths and `--shares-identity-with`, and
/// records nothing. The control: a second clone of the repository holds the
/// same vault at the same path, which is not another path of the vault.
#[test]
fn row_r_i8_e_a() {
    rows::check("R-I8-e:a", |p| {
        let base = TempDir::new().unwrap();
        let (machine, repo) = alice_repo(base.path());
        let alice = Person::of(machine);
        commit(&repo, "prod");
        let clone = base.path().join("clone");
        git_ok(
            base.path(),
            &[
                "clone",
                "-q",
                repo.to_str().unwrap(),
                clone.to_str().unwrap(),
            ],
        );
        let there = must(
            alice.trust(&clone, ".murk"),
            "trust the vault in a second clone",
        )?;
        let read = alice.get(&clone, ".murk", "DB_URL");
        p.require(
            printed(&read, "prod-db") && !there.said().contains("--shares-identity-with"),
            "control: a second clone of the repository is trusted and read, and not reported",
        )?;
        let pins_before = pins_of(&alice).len();
        fs::copy(repo.join(".murk"), repo.join("copy.murk")).unwrap();
        p.reached();
        let copy = alice.trust(&repo, "copy.murk");
        p.note(copy.said());
        p.target(!copy.ok, "murk trust refuses a byte copy of a pinned vault");
        p.target(
            names_both(&copy.said(), "copy.murk", ".murk")
                && copy.said().contains("--shares-identity-with"),
            "the refusal names both paths and `--shares-identity-with`",
        );
        p.target(
            pins_of(&alice).len() == pins_before,
            "the refusal records no pin for the copy",
        );
        p.today(copy.ok, "murk trust accepts the copy, silently");
        Ok(())
    });
}

/// A planted copy: a vault file added beside the pinned one. The machine
/// that pinned `.murk` still loads it, with a warning that names the copy. A
/// fresh clone refuses `.murk` until the user names the copy with
/// `--shares-identity-with`, then loads it; the copy itself is refused at
/// every step.
#[test]
fn row_r_i8_e_b() {
    rows::check("R-I8-e:b", |p| {
        let base = TempDir::new().unwrap();
        let (machine, repo) = alice_repo(base.path());
        let alice = Person::of(machine);
        commit(&repo, "prod");
        fs::copy(repo.join(".murk"), repo.join("copy.murk")).unwrap();
        commit(&repo, "a pull request adds a copy of the vault");
        let clone = base.path().join("clone");
        git_ok(
            base.path(),
            &[
                "clone",
                "-q",
                repo.to_str().unwrap(),
                clone.to_str().unwrap(),
            ],
        );
        let fresh = Person::new(base.path(), "fresh", &alice.key);
        let untrusted = fresh.get(&clone, ".murk", "DB_URL");
        p.require(
            refused(&untrusted, "prod-db"),
            "control: a fresh clone reads nothing before murk trust",
        )?;

        p.reached();
        let pinned = alice.get(&repo, ".murk", "DB_URL");
        p.note(pinned.stderr.clone());
        p.target(
            printed(&pinned, "prod-db") && pinned.stderr.contains("copy.murk"),
            "the machine that pinned `.murk` loads it with a warning that names the copy",
        );
        p.today(
            printed(&pinned, "prod-db") && !pinned.stderr.contains("copy.murk"),
            "the machine that pinned `.murk` loads it, saying nothing of the copy",
        );
        let plain = fresh.trust(&clone, ".murk");
        p.note(plain.said());
        p.target(
            !plain.ok
                && names_both(&plain.said(), "copy.murk", ".murk")
                && plain.said().contains("--shares-identity-with"),
            "plain murk trust of `.murk` on a fresh clone is refused, naming both paths and the flag",
        );
        p.today(
            plain.ok,
            "plain murk trust of `.murk` on a fresh clone is accepted",
        );
        p.target(
            refused(&fresh.get(&clone, "copy.murk", "DB_URL"), "prod-db"),
            "the copy is refused before the flag",
        );
        let named = fresh.run(
            &clone,
            &[
                "trust",
                "--yes",
                "--vault",
                ".murk",
                "--shares-identity-with",
                "copy.murk",
            ],
        );
        p.note(named.said());
        p.target(
            named.ok,
            "murk trust accepts `.murk` once the copy is named",
        );
        let loaded = fresh.get(&clone, ".murk", "DB_URL");
        p.target(
            printed(&loaded, "prod-db") && loaded.stderr.contains("copy.murk"),
            "`.murk` then loads, with the warning that names the copy",
        );
        p.target(
            refused(&fresh.get(&clone, "copy.murk", "DB_URL"), "prod-db"),
            "the copy is refused after the flag",
        );
        Ok(())
    });
}

/// A renamed vault is not a second path of one vault: after `git mv` the old
/// path is no longer tracked, and checking out the commit before the rename
/// brings it back while the new path goes away. Every load, before the rename
/// and after it, at either path, is accepted.
#[test]
fn row_r_i8_e_c() {
    rows::check("R-I8-e:c", |p| {
        let base = TempDir::new().unwrap();
        let (machine, repo) = alice_repo(base.path());
        let alice = Person::of(machine);
        commit(&repo, "prod");
        let before_rename = head_commit(&repo);
        let before = alice.get(&repo, ".murk", "DB_URL");
        p.require(
            printed(&before, "prod-db"),
            format!(
                "control: the vault loads before the rename: {}",
                before.said()
            ),
        )?;
        fs::create_dir_all(repo.join("config")).unwrap();
        git_ok(&repo, &["mv", ".murk", "config/.murk"]);
        commit(&repo, "move the vault");
        // The decisive step: the old path is recorded on this machine but no
        // longer tracked, so it is no second copy of the vault and does not
        // stop murk trust at the new path.
        p.reached();
        let trusted = alice.trust(&repo, "config/.murk");
        p.note(trusted.said());
        p.target(trusted.ok, "murk trust accepts the vault at its new path");
        let renamed = alice.get(&repo, "config/.murk", "DB_URL");
        p.note(renamed.stderr.clone());
        p.target(
            printed(&renamed, "prod-db"),
            "the vault loads at its new path",
        );
        git_ok(&repo, &["checkout", "-q", &before_rename]);
        let old = alice.get(&repo, ".murk", "DB_URL");
        p.note(old.stderr.clone());
        p.target(
            printed(&old, "prod-db"),
            "the commit before the rename loads at the old path",
        );
        git_ok(&repo, &["checkout", "-q", "main"]);
        let again = alice.get(&repo, "config/.murk", "DB_URL");
        p.note(again.stderr.clone());
        p.target(
            printed(&again, "prod-db"),
            "the new path loads again after the checkout back",
        );
        Ok(())
    });
}

/// `murk trust --vault .murk --shares-identity-with staging.murk` on a
/// machine that recorded both paths accepts `.murk`, retires `staging.murk`
/// on this machine (its pin and sidecar go), and leaves `.murk` loading and
/// `staging.murk` refused. Today the flag does not exist, so nothing is
/// retired and `staging.murk` keeps loading.
#[test]
fn row_r_i8_e_d() {
    rows::check("R-I8-e:d", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo) = both_paths_recorded(base.path())?;
        p.require(
            pins_of(&alice).len() == 2,
            "the machine holds a pin for each path",
        )?;
        p.reached();
        let retire = alice.run(
            &repo,
            &[
                "trust",
                "--yes",
                "--vault",
                ".murk",
                "--shares-identity-with",
                "staging.murk",
            ],
        );
        p.note(retire.said());
        p.target(
            retire.ok,
            "murk trust names staging.murk as sharing the identity",
        );
        let prod = alice.get(&repo, ".murk", "DB_URL");
        let staging = alice.get(&repo, "staging.murk", "DB_URL");
        p.note(staging.stderr.clone());
        p.target(
            printed(&prod, "prod-db"),
            "`.murk` loads after the other path is retired",
        );
        p.target(
            refused(&staging, "STAGING-db-3"),
            "`staging.murk` is refused after it is retired",
        );
        p.target(
            pins_of(&alice).len() == 1 && sidecars_of(&alice).len() <= 1,
            "staging.murk's pin and sidecar are removed from this machine",
        );
        p.today(
            !retire.ok && printed(&staging, "STAGING-db-3") && pins_of(&alice).len() == 2,
            "nothing is retired: both pins stay and `staging.murk` still loads",
        );
        Ok(())
    });
}

// ── Lineage: a stale fork, a revert, the first format-4 save, format 3 ──

const FORMAT3_KEY: &str = include_str!("../fixtures/v0_15_format3_alice.test-only.key");
const FORMAT3_BASE: &str = include_str!("../fixtures/v0_15_format3_base.murk");
const FORMAT3_STALE_FORK: &str = include_str!("../fixtures/v0_15_format3_stale_fork.murk");

/// The format-3 fixture's key file, written under `base` the way murk wants
/// a key file kept.
fn fixture_key(base: &Path) -> PathBuf {
    let key = base.join("alice.key");
    fs::write(&key, FORMAT3_KEY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    key
}

/// A repository whose `main` holds the format-3 base fixture as `.murk`, with
/// the merge driver set when `driver` says so.
fn format3_repo(base: &Path, driver: bool) -> PathBuf {
    let repo = base.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git_ok(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join(".murk"), FORMAT3_BASE).unwrap();
    if driver {
        super::use_merge_driver(&repo);
    } else {
        commit(&repo, "base");
    }
    repo
}

/// A clone of `repo` at `name` under `base`.
fn clone_of(base: &Path, repo: &Path, name: &str) -> PathBuf {
    let dir = base.join(name);
    git_ok(
        base,
        &["clone", "-q", repo.to_str().unwrap(), dir.to_str().unwrap()],
    );
    dir
}

/// A genuine file from a stale fork, with a counter above what the machine
/// accepted, replaces the vault on `main` after `DB_URL` was rotated. It is
/// signed by a trusted signer and undamaged, but it does not descend from
/// the revision the machine accepted, so it is refused as not descending,
/// the leaked value never comes out, and the rotated value stays. The
/// controls: the first revision replayed on the same machine is refused as
/// rolled back, and a teammate's save on top of main is accepted.
#[test]
fn row_r_i6_d() {
    rows::check("R-I6-d", |p| {
        let base = TempDir::new().unwrap();
        let (machine, repo) = alice_repo(base.path());
        let alice = Person::of(machine);
        commit(&repo, "prod: DB_URL set, later leaked");
        let first = head_commit(&repo);

        // A teammate forks here and saves six times, never touching DB_URL.
        let fork_dir = clone_of(base.path(), &repo, "fork");
        let forker = Person::new(base.path(), "forker", &alice.key);
        must(
            forker.trust(&fork_dir, ".murk"),
            "the fork trusts the vault",
        )?;
        for i in 1..=6 {
            let name = format!("FORK_{i}");
            must(forker.add(&fork_dir, ".murk", &name, "f"), "the fork saves")?;
        }
        let stale = fork_dir.join(".murk");

        // Main moves on: the leaked DB_URL is rotated.
        must(
            alice.add(&repo, ".murk", "DB_URL", "rotated-db"),
            "rotate DB_URL",
        )?;
        must(alice.add(&repo, ".murk", "EXTRA", "x"), "main moves on")?;
        commit(&repo, "rotate DB_URL");
        let tip = head_commit(&repo);

        restore_vault(&repo, &first);
        let rolled_back = alice.get(&repo, ".murk", "DB_URL");
        p.require(
            refused(&rolled_back, "prod-db") && rolled_back.stderr.contains("rolled back"),
            "control: the first revision, replayed on this machine, is refused as rolled back",
        )?;
        restore_vault(&repo, &tip);

        let mate_dir = clone_of(base.path(), &repo, "mate");
        let mate = Person::new(base.path(), "mate", &alice.key);
        must(mate.trust(&mate_dir, ".murk"), "the teammate trusts main")?;
        must(
            mate.add(&mate_dir, ".murk", "MATE_ONLY", "m"),
            "the teammate saves on top of main",
        )?;
        fs::copy(mate_dir.join(".murk"), repo.join(".murk")).unwrap();
        let accepted = alice.get(&repo, ".murk", "DB_URL");
        p.require(
            printed(&accepted, "rotated-db"),
            format!(
                "control: a teammate's save on top of main is accepted: {}",
                accepted.said()
            ),
        )?;
        let descendant = fs::read(repo.join(".murk")).unwrap();

        require_format_4(p, &stale, "the stale fork's file")?;
        fs::copy(&stale, repo.join(".murk")).unwrap();
        p.reached();
        let replay = alice.get(&repo, ".murk", "DB_URL");
        p.note(replay.stderr.clone());
        p.target(
            refused(&replay, "prod-db"),
            "the stale fork's file is refused and the leaked value never comes out",
        );
        p.target(
            replay.stderr.contains("descend"),
            "the refusal says the file does not descend from the revision accepted on this branch",
        );
        fs::write(repo.join(".murk"), descendant).unwrap();
        let kept = alice.get(&repo, ".murk", "DB_URL");
        p.target(printed(&kept, "rotated-db"), "the rotated value is kept");
        Ok(())
    });
}

/// History of one vault on `main`: O, then X1 (adds `X1_ONLY`), then X2
/// (adds `X2_ONLY`). Machine A (the author) accepted all three; the vault in
/// `repo` is X2.
struct Revisions {
    alice: Person,
    repo: PathBuf,
    o: String,
    x1: String,
}

impl Revisions {
    fn new(base: &Path, driver: bool) -> Result<Self, String> {
        let (machine, repo) = alice_repo(base);
        let alice = Person::of(machine);
        if driver {
            super::use_merge_driver(&repo);
        } else {
            commit(&repo, "O");
        }
        let o = head_commit(&repo);
        must(alice.add(&repo, ".murk", "X1_ONLY", "x1-value"), "save X1")?;
        commit(&repo, "X1");
        let x1 = head_commit(&repo);
        must(alice.add(&repo, ".murk", "X2_ONLY", "x2-value"), "save X2")?;
        commit(&repo, "X2");
        Ok(Self { alice, repo, o, x1 })
    }

    /// The deliberate revert: A puts O's vault back, accepts it with
    /// `murk trust`, and saves `N_ONLY` on top.
    fn revert_and_save(&self) -> Result<(), String> {
        restore_vault(&self.repo, &self.o);
        must(
            self.alice.trust(&self.repo, ".murk"),
            "A accepts the older revision",
        )?;
        must(
            self.alice
                .add(&self.repo, ".murk", "N_ONLY", "n-after-revert"),
            "A saves after the revert",
        )?;
        Ok(())
    }
}

/// A deliberate revert by `murk trust` then a save is accepted by a teammate
/// whose reference is a revision the revert undid: the save carries the
/// reverted revisions in its `prev`. The control is a descendant of the older
/// revision that supersedes nothing, which the same teammate refuses.
#[test]
fn row_r_l_revert_a() {
    rows::check("R-L-revert:a", |p| {
        let base = TempDir::new().unwrap();
        let t = Revisions::new(base.path(), false)?;
        let b = Person::new(base.path(), "b", &t.alice.key);
        must(b.trust(&t.repo, ".murk"), "B accepts X2")?;
        let vault = t.repo.join(".murk");
        require_format_4(p, &vault, "X2")?;
        let x2 = entry_of(&vault);
        p.require(
            has_reference(&b, "main", &x2),
            "before the revert, B's reference is X2",
        )?;

        t.revert_and_save()?;
        let first = entry_at(&t.repo, &t.x1);
        p.require(
            has_superseded(&t.alice, "main", &[&x2, &first]),
            "A's sidecar holds X1 and X2 as superseded",
        )?;
        let n = fs::read(&vault).unwrap();

        // The control: the same revert from O on a machine that had nothing to
        // supersede. Its counter is above B's mark, and B refuses it.
        let other_dir = base.path().join("other");
        fs::create_dir_all(&other_dir).unwrap();
        let other = Person::new(base.path(), "other", &t.alice.key);
        fs::write(
            other_dir.join(".murk"),
            git(&t.repo, &["show", &format!("{}:.murk", t.o)]).stdout,
        )
        .unwrap();
        must(
            other.trust(&other_dir, ".murk"),
            "another machine accepts O",
        )?;
        for i in 1..=3 {
            let name = format!("C_ONLY_{i}");
            must(
                other.add(&other_dir, ".murk", &name, "c-fork-value"),
                "it saves",
            )?;
        }
        fs::copy(other_dir.join(".murk"), &vault).unwrap();
        let fork = b.get(&t.repo, ".murk", "C_ONLY_1");
        p.require(
            refused(&fork, "c-fork-value"),
            "control: a descendant of O that supersedes nothing is refused by B",
        )?;

        fs::write(&vault, n).unwrap();
        p.reached();
        let load = b.get(&t.repo, ".murk", "N_ONLY");
        p.note(load.stderr.clone());
        p.target(
            printed(&load, "n-after-revert"),
            "B accepts the revert: its reference X2 is in the save's `prev`",
        );
        Ok(())
    });
}

/// A branch off a reverted revision that still holds the reverted change
/// must not bring it back. Revisions O, X1 (adds `X1_ONLY`) and X2 exist, A
/// reverts to O and saves N, and a revision Y on a branch off X1 keeps
/// `X1_ONLY`. Merging Y into A's branch has the ancestor O, and X1 is a newer
/// entry both sides carry, so the merge conflicts and `X1_ONLY` stays out.
/// The control is a branch off O, which merges cleanly.
#[test]
fn row_r_l_revert_b() {
    rows::check("R-L-revert:b", |p| {
        let base = TempDir::new().unwrap();
        let t = Revisions::new(base.path(), true)?;
        let vault = t.repo.join(".murk");
        require_format_4(p, &vault, "X2")?;
        let x2 = entry_of(&vault);

        // Y: a teammate who saw X1 and not the revert saves on a branch off X1.
        let teammate = Person::new(base.path(), "teammate", &t.alice.key);
        git_ok(&t.repo, &["checkout", "-q", "-b", "side", &t.x1]);
        must(teammate.trust(&t.repo, ".murk"), "the teammate accepts X1")?;
        must(
            teammate.add(&t.repo, ".murk", "Y_ONLY", "y-value"),
            "the teammate saves Y",
        )?;
        commit(&t.repo, "Y");
        // Z: the same teammate, on a branch off O.
        git_ok(&t.repo, &["checkout", "-q", "-b", "clean", &t.o]);
        must(teammate.trust(&t.repo, ".murk"), "the teammate accepts O")?;
        must(
            teammate.add(&t.repo, ".murk", "Z_ONLY", "z-value"),
            "the teammate saves Z",
        )?;
        commit(&t.repo, "Z");

        // A reverts main to O and saves N on top.
        git_ok(&t.repo, &["checkout", "-q", "main"]);
        git_ok(&t.repo, &["reset", "-q", "--hard", &t.o]);
        t.revert_and_save()?;
        commit(&t.repo, "N");
        let n = head_commit(&t.repo);
        let first = entry_at(&t.repo, &t.x1);
        p.require(
            has_superseded(&t.alice, "main", &[&x2, &first]),
            "A's sidecar holds X1 and X2 as superseded",
        )?;

        let (merged, stderr) = merge(&t.alice, &t.repo, "clean");
        p.require(
            merged && stderr.contains("vault merged cleanly") && has_secret(&vault, "Z_ONLY"),
            format!("control: a branch off O merges cleanly through the driver: {stderr}"),
        )?;
        git_ok(&t.repo, &["reset", "-q", "--hard", &n]);

        p.reached();
        let (merged, stderr) = merge(&t.alice, &t.repo, "side");
        p.note(stderr.clone());
        p.target(!merged, "merging Y into the revert is a conflict");
        p.target(
            driver_spoke(&stderr),
            "the murk driver ran: its own verdict is on stderr",
        );
        p.target(
            !has_secret(&vault, "X1_ONLY"),
            "the reverted change stays out of the result",
        );
        Ok(())
    });
}

/// The first save over a format-3 vault writes format 4 whose `prev` holds
/// the parent's entry. Reloading it records it as the lineage reference.
/// A teammate's save on top is accepted, and a genuine format-4 fork that
/// saved from the same format-3 vault and does not descend from the
/// adoption save is refused, though its counter is above the mark.
#[test]
fn row_r_l_adopt() {
    rows::check("R-L-adopt", |p| {
        let base = TempDir::new().unwrap();
        let key = fixture_key(base.path());
        let alice = Person::new(base.path(), "alice", &key);
        let repo = format3_repo(base.path(), false);
        let vault = repo.join(".murk");
        p.require(format_of(&vault) == 3, "the fixture is a format-3 vault")?;
        let parent = entry_of(&vault);

        // The stale fork: another machine adopts the same vault, saves three times.
        let fork_dir = clone_of(base.path(), &repo, "fork");
        let forker = Person::new(base.path(), "forker", &key);
        must(
            forker.trust(&fork_dir, ".murk"),
            "the fork trusts the vault",
        )?;
        for i in 1..=3 {
            let name = format!("F_{i}");
            let value = format!("stale-fork-{i}");
            must(
                forker.add(&fork_dir, ".murk", &name, &value),
                "the fork saves",
            )?;
        }

        must(
            alice.trust(&repo, ".murk"),
            "alice trusts the format-3 vault",
        )?;
        must(
            alice.add(&repo, ".murk", "ADOPTED", "adopted-value"),
            "alice's first save",
        )?;
        require_format_4(p, &vault, "alice's first save over the format-3 vault")?;
        p.reached();
        p.target(
            json_of(&vault)["version"] == "4.0",
            "the adoption save is written as version 4.0",
        );
        p.target(
            prev_of(&vault) == vec![parent],
            "its `prev` holds exactly the parent's entry",
        );
        let reload = alice.get(&repo, ".murk", "DB_URL");
        p.target(
            printed(&reload, "format3-base-db"),
            "alice reloads the adoption save",
        );
        p.target(
            has_reference(&alice, "main", &entry_of(&vault)),
            "the reload records the adoption save as the lineage reference",
        );
        commit(&repo, "adoption save");

        let mate_dir = clone_of(base.path(), &repo, "mate");
        let mate = Person::new(base.path(), "mate", &key);
        must(
            mate.trust(&mate_dir, ".murk"),
            "the teammate trusts the adoption save",
        )?;
        must(
            mate.add(&mate_dir, ".murk", "MATE_ONLY", "mate-value"),
            "the teammate saves on top",
        )?;
        fs::copy(mate_dir.join(".murk"), &vault).unwrap();
        let descendant = fs::read(&vault).unwrap();
        let on_top = alice.get(&repo, ".murk", "ADOPTED");
        p.note(on_top.stderr.clone());
        p.target(
            printed(&on_top, "adopted-value"),
            "a teammate's save on top of the adoption save is accepted",
        );

        fs::copy(fork_dir.join(".murk"), &vault).unwrap();
        let fork = alice.get(&repo, ".murk", "F_1");
        p.note(fork.stderr.clone());
        p.target(
            refused(&fork, "stale-fork-1"),
            "the format-4 fork is refused and its values never come out",
        );
        p.target(
            fork.stderr.contains("descend"),
            "the refusal says the fork does not descend from the revision accepted here",
        );
        fs::write(&vault, descendant).unwrap();
        let kept = alice.get(&repo, ".murk", "ADOPTED");
        p.target(
            printed(&kept, "adopted-value"),
            "the teammate's save still loads after the fork was refused",
        );
        Ok(())
    });
}

/// With a lineage reference, a genuine format-3 file with a higher counter is
/// refused on load, and refused as a changed merge side. The controls: a
/// machine with no reference reads the same file, and a format-4 side that
/// grew from the same base merges cleanly.
#[test]
fn row_r_l_format3() {
    rows::check("R-L-format3", |p| {
        let base = TempDir::new().unwrap();
        let key = fixture_key(base.path());
        let alice = Person::new(base.path(), "alice", &key);
        let repo = format3_repo(base.path(), true);
        let vault = repo.join(".murk");
        let base_commit = head_commit(&repo);

        // A machine that never accepted a format-4 vault has no reference there.
        let plain_dir = clone_of(base.path(), &repo, "plain");
        let plain = Person::new(base.path(), "plain", &key);
        must(
            plain.trust(&plain_dir, ".murk"),
            "the plain machine trusts the base",
        )?;
        fs::write(plain_dir.join(".murk"), FORMAT3_STALE_FORK).unwrap();
        let read = plain.get(&plain_dir, ".murk", "DB_URL");
        p.require(
            printed(&read, "format3-stale-fork-db"),
            format!(
                "control: with no reference, the format-3 file loads: {}",
                read.said()
            ),
        )?;

        // A format-4 side off the base.
        let side_dir = clone_of(base.path(), &repo, "side");
        let side = Person::new(base.path(), "side", &key);
        must(
            side.trust(&side_dir, ".murk"),
            "the side machine trusts the base",
        )?;
        must(
            side.add(&side_dir, ".murk", "SIDE_ONLY", "side-value"),
            "the side machine saves",
        )?;
        let side_file = fs::read(side_dir.join(".murk")).unwrap();

        // Branches: the format-3 fork's file, and the format-4 side.
        git_ok(&repo, &["checkout", "-q", "-b", "fork"]);
        fs::write(&vault, FORMAT3_STALE_FORK).unwrap();
        commit(&repo, "the stale fork's format-3 file");
        git_ok(&repo, &["checkout", "-q", "-b", "format4", &base_commit]);
        fs::write(&vault, side_file).unwrap();
        commit(&repo, "a format-4 side");
        git_ok(&repo, &["checkout", "-q", "main"]);

        // Alice adopts: her first save is format 4, and it is her reference.
        must(alice.trust(&repo, ".murk"), "alice trusts the base")?;
        must(
            alice.add(&repo, ".murk", "ADOPTED", "adopted-value"),
            "alice's first save",
        )?;
        require_format_4(p, &vault, "alice's first save over the format-3 vault")?;
        commit(&repo, "adoption save");
        let adopted = head_commit(&repo);
        let (merged, stderr) = merge(&alice, &repo, "format4");
        p.require(
            merged && stderr.contains("vault merged cleanly"),
            format!("control: a format-4 side off the base merges cleanly: {stderr}"),
        )?;
        git_ok(&repo, &["reset", "-q", "--hard", &adopted]);

        p.reached();
        fs::write(&vault, FORMAT3_STALE_FORK).unwrap();
        let load = alice.get(&repo, ".murk", "DB_URL");
        p.note(load.stderr.clone());
        p.target(
            refused(&load, "format3-stale-fork-db"),
            "the format-3 file is refused on load and its value never comes out",
        );
        p.target(
            load.stderr.contains("format 3") || load.stderr.contains("lineage"),
            "the refusal says the file is a format-3 revision with no lineage",
        );
        git_ok(&repo, &["checkout", "-q", "--", ".murk"]);

        let (merged, stderr) = merge(&alice, &repo, "fork");
        p.note(stderr.clone());
        p.target(!merged, "a format-3 side that changed the vault is refused");
        p.target(
            driver_spoke(&stderr),
            "the murk driver ran: its own verdict is on stderr",
        );
        let result = alice.get(&repo, ".murk", "DB_URL");
        p.target(
            !result.said().contains("format3-stale-fork-db"),
            "the format-3 side's value is not in the working file",
        );
        Ok(())
    });
}

/// R-I22-a: an unsigned vault (written by a key that cannot sign) has no
/// signature to catch an edit, so the MAC alone must. Someone with write
/// access swaps the ciphertexts of two values; the load must fail the
/// integrity check instead of serving one value under the other's name.
#[test]
fn row_r_i22_a() {
    rows::check("R-I22-a", |p| {
        let base = TempDir::new().unwrap();
        let hw = Machine::new(base.path(), "hw");
        let key_file = super::rsa_key_file(base.path());
        let repo = base.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        let as_hw = || {
            let mut cmd = hw.murk(&repo);
            cmd.env("MURK_KEY_FILE", &key_file);
            cmd
        };
        let init = out({
            let mut cmd = as_hw();
            cmd.arg("init").write_stdin("hw\n");
            cmd
        });
        p.require(
            init.ok,
            format!("murk init with the ssh-rsa key: {}", init.said()),
        )?;
        for (key, value) in [("ALPHA", "alpha-value"), ("BETA", "beta-value")] {
            let add = out({
                let mut cmd = as_hw();
                cmd.args(["add", key]).write_stdin(format!("{value}\n"));
                cmd
            });
            p.require(add.ok, format!("add {key}: {}", add.said()))?;
        }
        let path = repo.join(".murk");
        let mut vault: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        p.require(vault.get("sig").is_none(), "an ssh-rsa key cannot sign")?;
        let control = out({
            let mut cmd = as_hw();
            cmd.args(["get", "ALPHA"]);
            cmd
        });
        p.require(
            control.ok && control.stdout == "alpha-value\n",
            format!(
                "control: the untouched unsigned vault loads: {}",
                control.said()
            ),
        )?;

        p.reached();
        let secrets = &mut vault["secrets"];
        let alpha = secrets["ALPHA"]["shared"].take();
        let beta = secrets["BETA"]["shared"].take();
        secrets["ALPHA"]["shared"] = beta;
        secrets["BETA"]["shared"] = alpha;
        fs::write(&path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        let load = out({
            let mut cmd = as_hw();
            cmd.args(["get", "ALPHA"]);
            cmd
        });
        p.note(load.said());
        p.target(!load.ok, "the load of the edited unsigned vault fails");
        p.target(
            !load.stdout.contains("beta-value"),
            "BETA's value never comes out under ALPHA's name",
        );
        p.target(
            load.stderr.contains("tampered"),
            "the error is the integrity check",
        );
        Ok(())
    });
}

// ── Rows whose older tests also hit a second guard ──

/// A replayed older signed revision on a marked branch is refused as rolled
/// back. No removal is involved, so the counter rule is the only defence:
/// the control is the same file on a branch this machine never accepted,
/// where it loads as history.
#[test]
fn row_r_i6_a() {
    rows::check("R-I6-a", |p| {
        let base = TempDir::new().unwrap();
        let (machine, repo) = alice_repo(base.path());
        let alice = Person::of(machine);
        commit(&repo, "v1: DB_URL set");
        let v1 = head_commit(&repo);
        must(
            alice.add(&repo, ".murk", "DB_URL", "rotated-db"),
            "rotate DB_URL",
        )?;
        commit(&repo, "v2: DB_URL rotated");
        restore_vault(&repo, &v1);

        git_ok(&repo, &["checkout", "-q", "-b", "other"]);
        let elsewhere = alice.get(&repo, ".murk", "DB_URL");
        p.require(
            printed(&elsewhere, "prod-db"),
            format!(
                "control: the older revision loads on a branch never accepted here: {}",
                elsewhere.said()
            ),
        )?;
        git_ok(&repo, &["checkout", "-q", "main"]);

        p.reached();
        let replay = alice.get(&repo, ".murk", "DB_URL");
        p.note(replay.stderr.clone());
        p.target(
            refused(&replay, "prod-db"),
            "the older revision is refused on the marked branch and its value never comes out",
        );
        p.target(
            replay.stderr.contains("rolled back"),
            "the refusal says the vault rolled back",
        );
        Ok(())
    });
}

/// A grant key file anchors the signers its vault may be read under. A grant
/// minted while only alice was a signer does not read a vault bob signed
/// after he joined, though bob is a recipient and the grant's record
/// survived his save. The control is the same vault under a key file that
/// also names bob, which reads: the refusal is the anchor, nothing else.
#[test]
fn row_r_i15_a() {
    rows::check("R-I15-a", |p| {
        let base = TempDir::new().unwrap();
        let (alice, repo, key) = granted_repo(base.path(), "1h");
        let bob = Machine::new(base.path(), "bob");
        bob.init(&base.path().join("bob-scratch"), "bob");
        super::authorize(&alice, &repo, &bob, "bob");
        let bob = Person::of(bob);
        must(bob.trust(&repo, ".murk"), "bob trusts the vault")?;
        must(bob.add(&repo, ".murk", "BOB_ONLY", "b"), "bob saves")?;

        let (bob_entry, _) = bob.machine.signer_entry(&repo);
        let alone = fs::read_to_string(&key).unwrap();
        fs::write(&key, format!("{alone}# murk-trusted-signer: {bob_entry}\n")).unwrap();
        let both = out(agent_get(base.path(), &repo, &key));
        p.require(
            printed(&both, "prod-db"),
            format!(
                "control: a key file that anchors bob reads the vault he signed: {}",
                both.said()
            ),
        )?;

        fs::write(&key, alone).unwrap();
        p.reached();
        let read = out(agent_get(base.path(), &repo, &key));
        p.note(read.stderr.clone());
        p.target(
            refused(&read, "prod-db"),
            "a key file that does not name bob reads nothing of the vault he signed",
        );
        p.target(
            read.stderr.contains("not a trusted signer"),
            "the refusal says the signer is not in the key file",
        );
        Ok(())
    });
}

/// A grant key never signs a vault. Alice's machine saw the grant, then the
/// grant holder's own code re-signs the vault as a plain recipient. The
/// refusal must be the one for a grant key that signs: the same vault would
/// also be refused for listing a former grant key without its record and for
/// an untrusted signer, so the message is what shows the grant-signer rule
/// held.
#[test]
fn a_grant_key_that_signs_is_refused_as_a_grant_signer() {
    let base = TempDir::new().unwrap();
    let (alice, repo) = alice_repo(base.path());
    alice.add(&repo, "SENTRY_DSN", "sentry");
    let grant_key = base.path().join("bot.key");
    alice
        .murk(&repo)
        .args(["agent", "grant", "--name", "bot", "--only", "SENTRY_DSN"])
        .arg("--out")
        .arg(&grant_key)
        .assert()
        .success();
    let alice = Person::of(alice);
    let seen = alice.get(&repo, ".murk", "DB_URL");
    assert!(printed(&seen, "prod-db"), "{}", seen.said());

    let mut forge = std::process::Command::new(std::env::current_exe().unwrap());
    for var in super::common::MURK_CONTEXT_VARS {
        forge.env_remove(var);
    }
    let forge = forge
        .args(["--exact", "grant_forgery_child", "--nocapture", "--ignored"])
        .env("FORGE_VAULT", repo.join(".murk"))
        .env("FORGE_GRANT_KEY", &grant_key)
        .env("FORGE_ADD", super::common::FOREIGN_PK)
        .env("HOME", base.path().join("bot-home"))
        .output()
        .unwrap();
    assert!(
        forge.status.success(),
        "{}{}",
        String::from_utf8_lossy(&forge.stdout),
        String::from_utf8_lossy(&forge.stderr)
    );

    rows::decisive("R-I17-a");
    let read = alice.get(&repo, ".murk", "DB_URL");
    assert!(refused(&read, "attacker"), "{}", read.said());
    assert!(
        read.stderr.contains("signed by agent grant key"),
        "{}",
        read.stderr
    );
}
