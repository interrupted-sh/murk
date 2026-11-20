// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Enforce the role × command authorization matrix in `auth_matrix/table.rs`.
//!
//! One fixture vault holds every role (see the table module docs). Each cell
//! copies it into a scratch directory with its own `HOME`, runs the command as
//! the role, and checks:
//!
//! - the exit status matches the expected verdict;
//! - no output carries a fixture value the role may not read;
//! - a refusal leaves the guarded vault file byte-for-byte unchanged;
//! - an allowed read leaves it unchanged, and shows the value the role sees;
//! - an allowed write changes it, and changes the vault's values only as the
//!   row allows: nobody gains access to a value, nobody loses it, plaintexts
//!   stay put, and new keys reach exactly their audience. Values are compared
//!   one by one (shared, group, personal) by decrypting every ciphertext with
//!   every fixture key straight through age.
//!
//! All cells run, then the test fails with the full list of broken cells.
//! Rows that drive `$EDITOR` run on Unix only (see
//! [`table::EDITOR_UNIX_ONLY`]); every other row runs on every platform.
//!
//! The `row_*` tests after the matrix test are trust invariant rows (see
//! `tests/invariant_rows.tsv`) about the CI and grant roles. They need
//! fixtures of their own, a second vault or a spent grant, so they build them
//! rather than add a role to the table.

mod common;
#[path = "auth_matrix/table.rs"]
mod table;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::cast::{self, Tier, Who};
use common::{init_vault, murk_bin};
use table::{Audience, Basis, Check, ROWS, Role, Row, Verdict};
use tempfile::TempDir;

// Fixture values. Every one is unique, so a leak check is a substring search.
const SHARED: &str = "val-shared-cur";
const SHARED_OLD: &str = "val-shared-old";
const OVERRIDE: &str = "val-o-override";
const PRIV: &str = "val-o-private";
const OPS: &str = "val-ops-cur";
const OPS_OLD: &str = "val-ops-old";
const AGENT_OK: &str = "val-agent-ok";
const THEIRS: &str = "val-theirs";

const ALL_VALUES: &[&str] = &[
    SHARED, SHARED_OLD, OVERRIDE, PRIV, OPS, OPS_OLD, AGENT_OK, THEIRS,
];

/// The fixture values a role may see in any output.
fn readable(role: Role) -> &'static [&'static str] {
    match role {
        Role::Owner | Role::GroupMember => &[SHARED, SHARED_OLD, OPS, OPS_OLD, AGENT_OK, THEIRS],
        Role::Member | Role::NonMember => &[SHARED, SHARED_OLD, AGENT_OK, THEIRS],
        Role::OverrideOwner => &[SHARED, SHARED_OLD, OVERRIDE, PRIV, AGENT_OK, THEIRS],
        Role::Grant | Role::GrantAgent => &[AGENT_OK],
        Role::GrantExpired | Role::Revoked | Role::Outsider => &[],
    }
}

/// The value of `key` that `get` returns for a role.
fn visible(role: Role, key: &str) -> &'static str {
    match (role, key) {
        (Role::OverrideOwner, "SHARED") => OVERRIDE,
        (_, "SHARED") => SHARED,
        (_, "OPS") => OPS,
        (_, "PRIV") => PRIV,
        (_, "AGENT_OK") => AGENT_OK,
        _ => panic!("no fixture value for {key}"),
    }
}

struct Fixture {
    _dir: TempDir,
    repo: PathBuf,
    /// Grant key files, copied into each cell's HOME.
    grant_key: PathBuf,
    expired_key: PathBuf,
    ids: BTreeMap<&'static str, Who>,
    /// `MURK_TRUSTED_SIGNERS` naming every recipient.
    signers: String,
}

fn git(repo: &Path, home: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=matrix",
            "-c",
            "user.email=matrix@example.com",
        ])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Fixture {
    fn build() -> Self {
        let dir = TempDir::new().unwrap();
        let repo = dir.path().join("repo");
        let home = dir.path().join("home");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&home).unwrap();

        // `init_vault` roots HOME at the repo. Move its config (the owner's
        // trust pin for this vault) to the fixture's HOME and drop the stored
        // key and `.env`, so the cells find no key and no stray config.
        let (owner_secret, _) = init_vault(&repo);
        fs::rename(repo.join(".config"), home.join(".config")).unwrap();
        fs::remove_dir_all(home.join(".config/murk/keys")).unwrap();
        fs::remove_file(repo.join(".env")).unwrap();

        let mut ids = BTreeMap::new();
        ids.insert("owner", Who::from_secret("owner", &owner_secret));
        for label in [
            "member",
            "gmember",
            "nonmember",
            "override",
            "spare",
            "revoked",
            "outsider",
            "x",
        ] {
            ids.insert(label, Who::generate(label));
        }

        // Every recipient signs some write here or in a cell, and each cell runs
        // the vault at a new path with a fresh HOME (no trust pin), so every
        // command names all recipients as trusted signers, as CI would.
        let signers = std::cell::RefCell::new(String::new());
        let run = |who: &str, args: &[&str], stdin: &str| {
            let mut cmd = murk_bin(&home);
            cmd.current_dir(&repo)
                .env("MURK_KEY", &ids[who].secret)
                .env("MURK_VAULT", "test.murk");
            if !signers.borrow().is_empty() {
                cmd.env("MURK_TRUSTED_SIGNERS", &*signers.borrow());
            }
            let out = cmd.args(args).write_stdin(stdin).output().unwrap();
            assert!(
                out.status.success(),
                "fixture: {who} murk {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };

        // Display names match the labels, so rows can name recipients.
        for label in [
            "member",
            "gmember",
            "nonmember",
            "override",
            "spare",
            "revoked",
        ] {
            run(
                "owner",
                &["circle", "authorize", &ids[label].pubkey, "--name", label],
                "",
            );
        }
        let entries: Vec<String> = [
            "owner",
            "member",
            "gmember",
            "nonmember",
            "override",
            "spare",
        ]
        .iter()
        .map(|who| {
            run(who, &["trust", "--print-key"], "")
                .lines()
                .next()
                .unwrap()
                .trim()
                .to_string()
        })
        .collect();
        *signers.borrow_mut() = entries.join(",");
        run("owner", &["group", "create", "ops"], "");
        run("owner", &["group", "add", "ops", "--member", "gmember"], "");
        run("owner", &["group", "add", "ops", "--member", "spare"], "");
        run("owner", &["group", "create", "idle"], "");
        run(
            "owner",
            &["group", "add", "idle", "--member", "gmember"],
            "",
        );
        run("owner", &["add", "SHARED"], &format!("{SHARED_OLD}\n"));
        run("owner", &["add", "AGENT_OK"], &format!("{AGENT_OK}\n"));
        run(
            "owner",
            &["add", "OPS", "--group", "ops"],
            &format!("{OPS_OLD}\n"),
        );
        run(
            "override",
            &["add", "SHARED", "--group", "me"],
            &format!("{OVERRIDE}\n"),
        );
        run(
            "override",
            &["add", "PRIV", "--group", "me"],
            &format!("{PRIV}\n"),
        );
        for key in ["SHARED", "OPS", "PRIV", "AGENT_OK"] {
            run(
                "owner",
                &["describe", key, "fixture", "--tag", "agents"],
                "",
            );
        }
        run("owner", &["policy", "set", "--allow-tag", "agents"], "");

        let grant_key = home.join("bot.key");
        let expired_key = home.join("old.key");
        let grant_path = grant_key.to_str().unwrap();
        let expired_path = expired_key.to_str().unwrap();
        run(
            "owner",
            &[
                "agent", "grant", "--name", "bot", "--only", "AGENT_OK", "--ttl", "7d", "--out",
                grant_path,
            ],
            "",
        );
        // A vault write after a grant's TTL drops the grant, so the TTL must
        // outlast the fixture's remaining writes; checked below. murk stores
        // `expires_at` truncated to the second, so the grant expires between
        // TTL - 1s after the command starts and TTL after it returns.
        const EXPIRING_TTL: Duration = Duration::from_secs(10);
        let ttl = format!("{}s", EXPIRING_TTL.as_secs());
        let granting = Instant::now();
        run(
            "owner",
            &[
                "agent",
                "grant",
                "--name",
                "old",
                "--only",
                "AGENT_OK",
                "--ttl",
                &ttl,
                "--out",
                expired_path,
            ],
            "",
        );
        let still_valid_until = granting + EXPIRING_TTL - Duration::from_secs(1);
        let expired_at = Instant::now() + EXPIRING_TTL + Duration::from_millis(100);
        run("owner", &["circle", "revoke", "revoked"], "");

        // Commit, then change the shared and group values so `diff` has
        // something to show.
        git(&repo, &home, &["init", "-q"]);
        git(&repo, &home, &["add", "-A"]);
        git(&repo, &home, &["commit", "-q", "-m", "fixture"]);
        let base = fs::read(repo.join("test.murk")).unwrap();
        run(
            "owner",
            &["add", "SHARED", "--group", "everyone"],
            &format!("{SHARED}\n"),
        );
        run(
            "owner",
            &["add", "OPS", "--group", "ops"],
            &format!("{OPS}\n"),
        );

        // Merge-driver inputs: base is the commit, ours the working vault,
        // theirs the commit plus a new key.
        let merge = repo.join(".merge");
        fs::create_dir_all(&merge).unwrap();
        fs::write(merge.join("base.murk"), &base).unwrap();
        fs::write(merge.join("theirs.murk"), &base).unwrap();
        fs::copy(repo.join("test.murk"), merge.join("ours.murk")).unwrap();
        run(
            "owner",
            &["add", "THEIRS", "--vault", ".merge/theirs.murk"],
            &format!("{THEIRS}\n"),
        );

        let read = |path: &Path| fs::read_to_string(path).unwrap();
        ids.insert("grant", Who::from_secret("grant", &read(&grant_key)));
        ids.insert("expired", Who::from_secret("expired", &read(&expired_key)));
        assert!(
            Instant::now() < still_valid_until,
            "the fixture took longer than the expiring grant's TTL, so a later write may have dropped it"
        );
        for vault in ["test.murk", ".merge/ours.murk", ".merge/theirs.murk"] {
            assert!(
                read(&repo.join(vault)).contains(&ids["expired"].pubkey),
                "the expiring grant is missing from {vault}"
            );
        }
        if let Some(wait) = expired_at.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }

        Fixture {
            _dir: dir,
            repo,
            grant_key,
            expired_key,
            ids,
            signers: signers.into_inner(),
        }
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

/// Labels of the fixture keys that are agent grants.
const GRANT_LABELS: &[&str] = &["grant", "expired", "newgrant"];

/// The command that prints the environment, for `{PRINTENV}` in a row.
#[cfg(unix)]
const PRINTENV: &[&str] = &["env"];
#[cfg(windows)]
const PRINTENV: &[&str] = &["cmd", "/C", "set"];

fn matches(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern == value
}

/// Run one cell. `Ok` when it behaves as the table says; `Err` explains how
/// it didn't. The observed verdict is returned either way.
fn run_cell(fx: &Fixture, row: &Row, role: Role) -> (Verdict, Result<(), String>) {
    let cell = TempDir::new().unwrap();
    let repo = cell.path().join("repo");
    let home = cell.path().join("home");
    copy_dir(&fx.repo, &repo);
    fs::create_dir_all(&home).unwrap();
    for (name, contents) in row.files {
        fs::write(repo.join(name), contents).unwrap();
    }

    let guard = repo.join(row.guard);
    let before = fs::read(&guard).unwrap();

    let mut cmd = murk_bin(&home);
    cmd.current_dir(&repo)
        .env("MURK_VAULT", "test.murk")
        .env("MURK_TRUSTED_SIGNERS", &fx.signers);
    match role {
        Role::Grant | Role::GrantAgent | Role::GrantExpired => {
            let src = if role == Role::GrantExpired {
                &fx.expired_key
            } else {
                &fx.grant_key
            };
            let key = home.join("grant.key");
            fs::copy(src, &key).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            cmd.env("MURK_KEY_FILE", &key);
            if role == Role::GrantAgent {
                cmd.env("MURK_AGENT", "1");
            }
        }
        _ => {
            cmd.env("MURK_KEY", &fx.ids[label(role)].secret);
        }
    }
    #[cfg(unix)]
    if row.editor {
        let script = cell.path().join("editor.sh");
        fs::write(&script, "#!/bin/sh\necho val-edited > \"$1\"\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        cmd.env("EDITOR", &script).env_remove("VISUAL");
    }
    let args: Vec<String> = row
        .args
        .iter()
        .flat_map(|a| match *a {
            "{PRINTENV}" => PRINTENV.iter().map(|s| s.to_string()).collect(),
            _ => vec![a.replace("{X}", &fx.ids["x"].pubkey)],
        })
        .collect();
    let out = cmd
        .args(&args)
        .write_stdin(row.stdin)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A conflict is only a verdict for rows that expect one (the merge driver):
    // anywhere else a non-zero exit is a refusal.
    let conflict_row = row.cells.iter().any(|c| c.verdict == Verdict::Conflict);
    let observed = if out.status.success() {
        Verdict::Allow
    } else if conflict_row && stderr.contains("conflict") {
        Verdict::Conflict
    } else {
        Verdict::Refuse
    };
    let expected = row.cells[role.index()].verdict;
    let after = fs::read(&guard).unwrap_or_default();
    let changed = after != before;
    // The line that says why: the first error line, else the last line.
    let reason = |s: &str| {
        s.lines()
            .find(|l| l.contains("error"))
            .or_else(|| s.lines().rev().find(|l| !l.trim().is_empty()))
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let result = (|| {
        let allowed = readable(role);
        let leaked: Vec<&str> = ALL_VALUES
            .iter()
            .copied()
            .filter(|v| !allowed.contains(v) && (stdout.contains(v) || stderr.contains(v)))
            .collect();
        if !leaked.is_empty() {
            return Err(format!("output leaks {leaked:?}"));
        }
        if observed != expected {
            return Err(match observed {
                Verdict::Allow => format!(
                    "allowed (exit 0{})",
                    if changed { ", vault changed" } else { "" }
                ),
                Verdict::Refuse => format!("refused: {}", reason(&stderr)),
                Verdict::Conflict => format!("conflict: {}", reason(&stderr)),
            });
        }
        match observed {
            Verdict::Refuse if changed => return Err("refused but changed the vault".into()),
            // Git keeps whatever a conflicting driver wrote as the conflicted
            // result, and commits nothing, so the scratch copy may change.
            Verdict::Refuse | Verdict::Conflict => return Ok(()),
            Verdict::Allow => {}
        }
        match row.check {
            Check::Read { reveals } => {
                if changed {
                    return Err("a read changed the vault".into());
                }
                if let Some(key) = reveals {
                    let want = visible(role, key);
                    if !stdout.contains(want) {
                        return Err(format!("output lacks {want}"));
                    }
                }
                Ok(())
            }
            Check::Write {
                touches,
                gains,
                losses,
                creates,
            } => {
                if !changed {
                    return Err("allowed but wrote nothing".into());
                }
                // The result must still load: a write that leaves a vault
                // failing its integrity check is not an allowed write. Load as
                // the owner, or the group member when the row removes the owner.
                let loader = if losses.contains(&("*", "owner")) {
                    "gmember"
                } else {
                    "owner"
                };
                let load = murk_bin(&home)
                    .env("MURK_TRUSTED_SIGNERS", &fx.signers)
                    .current_dir(&repo)
                    .env("MURK_KEY", &fx.ids[loader].secret)
                    .args(["export", "--vault", row.guard])
                    .output()
                    .unwrap();
                if !load.status.success() {
                    return Err(format!(
                        "{loader} can't load the result: {}",
                        reason(&String::from_utf8_lossy(&load.stderr))
                    ));
                }
                let mut ids: Vec<Who> = fx.ids.values().cloned().collect();
                for path in [repo.join("newgrant.key")]
                    .into_iter()
                    .chain(agent_key_files(&home, "-newgrant"))
                {
                    if path.exists() {
                        ids.push(Who::from_secret(
                            "newgrant",
                            &fs::read_to_string(&path).unwrap(),
                        ));
                    }
                }
                let pre_vault = cell.path().join("pre.murk");
                fs::write(&pre_vault, &before).unwrap();
                let problems = value_problems(
                    &cast::cells(&pre_vault, &ids),
                    &cast::cells(&guard, &ids),
                    &ids,
                    label(role),
                    Expect {
                        touches,
                        gains,
                        losses,
                        creates,
                    },
                );
                if problems.is_empty() {
                    Ok(())
                } else {
                    Err(problems.join("; "))
                }
            }
        }
    })();
    (observed, result)
}

/// What a row allows a write to do to the vault's values.
struct Expect {
    touches: &'static [&'static str],
    gains: &'static [(&'static str, &'static str)],
    losses: &'static [(&'static str, &'static str)],
    creates: &'static [(&'static str, Audience)],
}

/// Compare every value before and after a write (see [`Check::Write`]).
/// `caller` is the label of the identity that ran the command.
fn value_problems(
    pre: &cast::Cells,
    post: &cast::Cells,
    ids: &[Who],
    caller: &str,
    expect: Expect,
) -> Vec<String> {
    let label_of: BTreeMap<&str, &str> = ids
        .iter()
        .map(|w| (w.pubkey.as_str(), w.label.as_str()))
        .collect();
    let is_grant = |pk: &str| label_of.get(pk).is_some_and(|l| GRANT_LABELS.contains(l));
    // A personal value that belongs to a recipient other than the caller.
    let others_private = |tier: &Tier| match tier {
        Tier::Private(pk) => !is_grant(pk) && label_of.get(pk.as_str()) != Some(&caller),
        _ => false,
    };
    let describe = |key: &str, tier: &Tier| match tier {
        Tier::Shared => format!("{key} (shared)"),
        Tier::Group(g) => format!("{key} (group {g})"),
        Tier::Private(pk) => format!(
            "{key} (personal value of {})",
            label_of.get(pk.as_str()).unwrap_or(&"an unknown key")
        ),
    };
    let gained = |key: &str, who: &str| {
        expect
            .gains
            .iter()
            .any(|(k, w)| matches(k, key) && matches(w, who))
    };
    // A write may drop an expired grant: it can't read anything anyway.
    let lost_ok = |key: &str, who: &str| {
        who == "expired"
            || expect
                .losses
                .iter()
                .any(|(k, w)| matches(k, key) && matches(w, who))
    };
    // Who could read a key's value before: its shared and group values, and
    // grants' copies of them (a recipient's own override is their own value).
    let readers_of = |cells: &cast::Cells, key: &str| -> BTreeSet<String> {
        cells
            .iter()
            .filter(|((k, tier), _)| {
                k == key && !matches!(tier, Tier::Private(pk) if !is_grant(pk))
            })
            .flat_map(|(_, by)| by.keys().cloned())
            .collect()
    };
    let pre_keys: BTreeSet<&str> = pre.keys().map(|(k, _)| k.as_str()).collect();
    let post_keys: BTreeSet<&str> = post.keys().map(|(k, _)| k.as_str()).collect();
    let mut problems = Vec::new();

    // Nobody gains access, and personal values appear only for the caller.
    for ((key, tier), by) in post {
        if !pre_keys.contains(key.as_str()) {
            continue;
        }
        let before: BTreeSet<String> = match pre.get(&(key.clone(), tier.clone())) {
            Some(was) => was.keys().cloned().collect(),
            None if others_private(tier) => {
                problems.push(format!("{} appeared", describe(key, tier)));
                continue;
            }
            None if matches!(tier, Tier::Private(pk) if !is_grant(pk)) => continue,
            None => readers_of(pre, key),
        };
        for who in by.keys().filter(|w| !before.contains(*w)) {
            if !gained(key, who) {
                problems.push(format!("{who} can now read {}", describe(key, tier)));
            }
        }
    }

    // Every value keeps its readers and plaintext unless the command names
    // its key; other recipients' personal values are kept even then.
    for ((key, tier), was) in pre {
        if expect.touches.contains(&key.as_str()) && !others_private(tier) {
            continue;
        }
        let now = post.get(&(key.clone(), tier.clone()));
        for (who, value) in was {
            match now.and_then(|m| m.get(who)) {
                None if !lost_ok(key, who) => {
                    problems.push(format!("{who} lost {}", describe(key, tier)));
                }
                Some(v) if v != value => {
                    problems.push(format!("{} changed for {who}", describe(key, tier)));
                }
                _ => {}
            }
        }
    }

    // New keys: only the listed ones, each encrypted to exactly its audience.
    for key in post_keys.difference(&pre_keys) {
        let Some((_, audience)) = expect.creates.iter().find(|(k, _)| k == key) else {
            problems.push(format!("unexpected new key {key}"));
            continue;
        };
        let cells: Vec<(&Tier, BTreeSet<String>)> = post
            .iter()
            .filter(|((k, _), _)| k == key)
            .map(|((_, tier), by)| (tier, by.keys().cloned().collect()))
            .collect();
        // The audience's readers, taken from an existing value of that tier.
        let audience_readers = |want: &dyn Fn(&Tier) -> bool| -> BTreeSet<String> {
            pre.iter()
                .filter(|((_, tier), _)| want(tier))
                .flat_map(|(_, by)| by.keys().cloned())
                .collect()
        };
        let ok = match (audience, cells.as_slice()) {
            (Audience::Everyone, [(Tier::Shared, by)]) => {
                *by == audience_readers(&|t| matches!(t, Tier::Shared))
            }
            (Audience::Group(g), [(Tier::Group(name), by)]) if name == g => {
                *by == audience_readers(&|t| matches!(t, Tier::Group(n) if n == g))
            }
            (Audience::Me, [(Tier::Private(pk), by)]) => {
                label_of.get(pk.as_str()) == Some(&caller)
                    && by.iter().map(String::as_str).eq([caller])
            }
            _ => false,
        };
        if !ok {
            let got: Vec<String> = cells
                .iter()
                .map(|(tier, by)| format!("{} read by {by:?}", describe(key, tier)))
                .collect();
            problems.push(format!(
                "{key} should be {audience:?}, got {}",
                got.join(", ")
            ));
        }
    }
    for (key, _) in expect.creates {
        if !post_keys.contains(key) {
            problems.push(format!("{key} was not created"));
        }
    }
    problems
}

/// The fixture label of a role's identity.
fn label(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Member => "member",
        Role::GroupMember => "gmember",
        Role::NonMember => "nonmember",
        Role::OverrideOwner => "override",
        Role::Grant | Role::GrantAgent => "grant",
        Role::GrantExpired => "expired",
        Role::Revoked => "revoked",
        Role::Outsider => "outsider",
    }
}

/// Agent key files `murk agent connect` wrote under `home`.
fn agent_key_files(home: &Path, suffix: &str) -> Vec<PathBuf> {
    let dir = home.join(".config/murk/agent-keys");
    fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.to_string_lossy().ends_with(suffix))
                .collect()
        })
        .unwrap_or_default()
}

fn mark(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "yes",
        Verdict::Refuse => "no",
        Verdict::Conflict => "conflict",
    }
}

#[test]
fn every_role_gets_exactly_the_access_the_matrix_grants() {
    let fx = Fixture::build();
    // Rows that drive `$EDITOR` run on Unix only (see `EDITOR_UNIX_ONLY`).
    let runs = |row: &Row| cfg!(unix) || !row.editor;
    let cells: Vec<(usize, Role)> = (0..ROWS.len())
        .filter(|r| runs(&ROWS[*r]))
        .flat_map(|r| Role::ALL.iter().map(move |role| (r, *role)))
        .collect();
    let results = Mutex::new(BTreeMap::new());
    let next = Mutex::new(cells.into_iter());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let Some((r, role)) = next.lock().unwrap().next() else {
                        break;
                    };
                    let outcome = run_cell(&fx, &ROWS[r], role);
                    results.lock().unwrap().insert((r, role.index()), outcome);
                }
            });
        }
    });
    let results = results.into_inner().unwrap();

    // The observed matrix, failing cells marked `!`, for the test log.
    let mut report = String::from("observed (! = differs from the table):\n");
    let mut failures = Vec::new();
    for (r, row) in ROWS.iter().enumerate().filter(|(_, row)| runs(row)) {
        let mut line = format!("{:<50}", row.command);
        for role in Role::ALL {
            let (observed, result) = &results[&(r, role.index())];
            let flag = if result.is_ok() { " " } else { "!" };
            line.push_str(&format!(" {:>8}{flag}", mark(*observed)));
            if let Err(why) = result {
                let cell = row.cells[role.index()];
                let expected = match cell.basis {
                    Basis::UnderReview => {
                        format!("{} (current behaviour, under review)", mark(cell.verdict))
                    }
                    _ => mark(cell.verdict).to_string(),
                };
                failures.push(format!(
                    "{} as {}: expected {expected}, {why}",
                    row.command,
                    role.heading(),
                ));
            }
        }
        report.push_str(&line);
        report.push('\n');
    }
    eprintln!("{report}");
    assert!(
        failures.is_empty(),
        "{} of {} cells broke the matrix:\n{}",
        failures.len(),
        results.len(),
        failures.join("\n")
    );
}

// ── Trust rows ──
//
// Scenarios of `tests/invariant_rows.tsv` that need a fixture of their own (a
// second vault, a spent agent grant) and not a role in the table above.

/// One team's vault for a row. Alice owns it: `repo` is its directory and her
/// `HOME`, so her trust pin is as `murk` left it. With `signers`, every
/// command also runs with `MURK_TRUSTED_SIGNERS` set to them.
struct Org {
    repo: PathBuf,
    alice: Who,
    signers: Option<String>,
}

impl Org {
    /// `murk init` as alice in `root/name`.
    fn new(root: &Path, name: &str, alice: &Who) -> Result<Self, String> {
        let org = Self::at(root, name, alice, None);
        org.must(&["init"], "alice\n")?;
        Ok(org)
    }

    /// An empty directory `root/name` for alice.
    fn at(root: &Path, name: &str, alice: &Who, signers: Option<String>) -> Self {
        let repo = root.join(name);
        fs::create_dir_all(&repo).unwrap();
        Org {
            repo,
            alice: alice.clone(),
            signers,
        }
    }

    /// A copy of `vault` in `root/name`, which alice works on from a machine
    /// that has never seen it (as `signers` anchors the first load).
    fn adopt(root: &Path, name: &str, alice: &Who, signers: &str, vault: &[u8]) -> Self {
        let org = Self::at(root, name, alice, Some(signers.to_string()));
        org.put(vault);
        org
    }

    /// `murk` run as alice in the repo.
    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut cmd = murk_bin(&self.repo);
        cmd.current_dir(&self.repo)
            .env("MURK_KEY", &self.alice.secret);
        if let Some(signers) = &self.signers {
            cmd.env("MURK_TRUSTED_SIGNERS", signers);
        }
        cmd.args(args)
            .write_stdin(stdin)
            .timeout(Duration::from_secs(60))
            .output()
            .unwrap()
    }

    /// `murk` as alice, which must succeed.
    fn must(&self, args: &[&str], stdin: &str) -> Result<Output, String> {
        let out = self.run(args, stdin);
        if out.status.success() {
            Ok(out)
        } else {
            Err(format!(
                "alice: murk {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }

    /// Alice sets `key` to `value`.
    fn add(&self, key: &str, value: &str) -> Result<(), String> {
        self.must(
            &["add", key, "--desc", "d", "--tag", "t"],
            &format!("{value}\n"),
        )
        .map(drop)
    }

    /// Alice's signer entry, as `murk trust --print-key` prints it.
    fn entry(&self) -> Result<String, String> {
        let out = self.must(&["trust", "--print-key"], "")?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .map(str::to_string)
            .filter(|e| !e.is_empty())
            .ok_or_else(|| "no signer entry".to_string())
    }

    fn vault(&self) -> Vec<u8> {
        fs::read(self.repo.join(".murk")).unwrap()
    }

    /// Replace the vault file with `bytes`.
    fn put(&self, bytes: &[u8]) {
        write_checked_out(&self.repo.join(".murk"), bytes);
    }
}

/// Write a vault file as git would check it out: not group-writable, whatever
/// the test process's umask.
fn write_checked_out(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
}

/// Write a key file only its owner can read, which `murk` insists on.
fn write_key_file(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn vault_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("a vault file is JSON")
}

fn generation(bytes: &[u8]) -> u64 {
    vault_json(bytes)["generation"].as_u64().unwrap_or(0)
}

fn vault_id(bytes: &[u8]) -> String {
    vault_json(bytes)["vault_id"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The major number of the vault file's header version.
fn header_major(bytes: &[u8]) -> Option<u64> {
    vault_json(bytes)["version"]
        .as_str()?
        .split('.')
        .next()?
        .parse()
        .ok()
}

fn out_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A machine of its own for one command: a fresh `HOME` (so no trust pin) and
/// a work directory holding `vault` as `.murk`. Names are unique per call.
fn fresh_machine(root: &Path, vault: &[u8]) -> (PathBuf, PathBuf) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let home = root.join(format!("machine-{n}-home"));
    let work = root.join(format!("machine-{n}-work"));
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&work).unwrap();
    write_checked_out(&work.join(".murk"), vault);
    (home, work)
}

/// `murk` on the machine `home`, in `work`, as the holder of `secret` (or of
/// the key file `key_file`), with `env` set.
fn on_machine(
    (home, work): &(PathBuf, PathBuf),
    key: Key<'_>,
    env: &[(&str, &str)],
    args: &[&str],
    stdin: &str,
) -> Output {
    let mut cmd = murk_bin(home);
    cmd.current_dir(work)
        .env_remove("MURK_EXPECTED_VAULT")
        .timeout(Duration::from_secs(60));
    match key {
        Key::Inline(secret) => cmd.env("MURK_KEY", secret),
        Key::File(path) => cmd.env("MURK_KEY_FILE", path),
    };
    for (name, value) in env {
        cmd.env(name, value);
    }
    cmd.args(args).write_stdin(stdin).output().unwrap()
}

/// How a runner presents its key.
#[derive(Clone, Copy)]
enum Key<'a> {
    /// The secret in `MURK_KEY`.
    Inline(&'a str),
    /// A key file, named by `MURK_KEY_FILE`.
    File(&'a Path),
}

/// Two vaults of one team that share a signer (alice), and the CI key `ci`
/// that both authorize: `prod` and, apart from it, `staging`.
struct TwoVaults {
    root: TempDir,
    ci: Who,
    /// `MURK_TRUSTED_SIGNERS`: alice's signer entry.
    signers: String,
    /// An older revision of prod, then its current one.
    prod_old: Vec<u8>,
    prod: Vec<u8>,
    staging: Vec<u8>,
}

impl TwoVaults {
    fn build() -> Result<Self, String> {
        let root = TempDir::new().unwrap();
        let (alice, ci) = (Who::generate("alice"), Who::generate("ci"));
        let prod = Org::new(root.path(), "prod", &alice)?;
        let staging = Org::new(root.path(), "staging", &alice)?;
        for org in [&prod, &staging] {
            org.must(&["circle", "authorize", &ci.pubkey, "--name", "ci"], "")?;
        }
        prod.add("API", "value-of-prod-old")?;
        let prod_old = prod.vault();
        prod.add("API", "value-of-prod")?;
        // Staging is saved at least as often as prod, so its counter is never
        // what makes it unfit.
        staging.add("API", "value-of-staging")?;
        while generation(&staging.vault()) < generation(&prod.vault()) {
            staging.add("API", "value-of-staging")?;
        }
        let signers = prod.entry()?;
        Ok(TwoVaults {
            ci,
            signers,
            prod_old,
            prod: prod.vault(),
            staging: staging.vault(),
            root,
        })
    }

    /// The value of `MURK_EXPECTED_VAULT` that names prod's current revision
    /// as the oldest a runner may load.
    fn expected(&self) -> String {
        format!("{}:{}", vault_id(&self.prod), generation(&self.prod))
    }

    /// A runner's `murk get API` on `machine`.
    fn get(&self, machine: &(PathBuf, PathBuf), expected: &str) -> Output {
        on_machine(
            machine,
            Key::Inline(&self.ci.secret),
            &[
                ("MURK_TRUSTED_SIGNERS", self.signers.as_str()),
                ("MURK_EXPECTED_VAULT", expected),
            ],
            &["get", "API"],
            "",
        )
    }

    /// The runner's machine after it loaded prod once: a pin now exists, and
    /// the load must have worked.
    fn pinned_runner(&self) -> Result<(PathBuf, PathBuf), String> {
        let machine = fresh_machine(self.root.path(), &self.prod);
        let out = self.get(&machine, &self.expected());
        if out.status.success() && out_text(&out.stdout).contains("value-of-prod") {
            Ok(machine)
        } else {
            Err(format!("the runner loads prod: {}", out_text(&out.stderr)))
        }
    }
}

/// A runner with no trust pin and `MURK_EXPECTED_VAULT` naming prod's vault id
/// and current counter refuses another vault's file, though that vault's
/// signer is the one `MURK_TRUSTED_SIGNERS` names. The same runner with a pin
/// refuses it as a different vault; the variable gives a pinless one the same.
#[test]
fn row_r_i8_c_other() {
    common::rows::check("R-I8-c:other", |p| {
        let w = TwoVaults::build()?;
        p.require(
            generation(&w.staging) >= generation(&w.prod)
                && vault_id(&w.staging) != vault_id(&w.prod),
            "staging is another vault with a counter no lower than prod's",
        )?;
        let expected = w.expected();

        // Control: a runner that loaded prod refuses staging's file.
        let pinned = w.pinned_runner()?;
        write_checked_out(&pinned.1.join(".murk"), &w.staging);
        let refused = w.get(&pinned, &expected);
        p.require(
            !refused.status.success()
                && out_text(&refused.stderr).contains("different vault")
                && !out_text(&refused.stdout).contains("value-of-staging"),
            format!(
                "a runner with a pin refuses staging as a different vault: {}",
                out_text(&refused.stderr)
            ),
        )?;

        // Decisive: a runner with no pin, the same variables, staging's file.
        let machine = fresh_machine(w.root.path(), &w.staging);
        let out = w.get(&machine, &expected);
        p.reached();
        p.note(format!(
            "stderr: {}stdout: {}",
            out_text(&out.stderr),
            out_text(&out.stdout)
        ));
        p.target(
            !out.status.success() && !out_text(&out.stdout).contains("value-of-staging"),
            "a pinless runner with MURK_EXPECTED_VAULT refuses another vault's file",
        );
        p.today(
            out.status.success() && out_text(&out.stdout).contains("value-of-staging"),
            "the variable is ignored and the other vault's value prints",
        );
        Ok(())
    });
}

/// A runner with no trust pin and `MURK_EXPECTED_VAULT` naming prod's vault id
/// and current counter refuses an older revision of prod. The same runner
/// with a pin refuses it as rolled back.
#[test]
fn row_r_i8_c_older() {
    common::rows::check("R-I8-c:older", |p| {
        let w = TwoVaults::build()?;
        p.require(
            generation(&w.prod_old) < generation(&w.prod)
                && vault_id(&w.prod_old) == vault_id(&w.prod),
            "prod's older revision has a lower counter and the same vault id",
        )?;
        let expected = w.expected();

        // Control: a runner that loaded prod's current revision refuses the
        // older one as rolled back.
        let pinned = w.pinned_runner()?;
        write_checked_out(&pinned.1.join(".murk"), &w.prod_old);
        let refused = w.get(&pinned, &expected);
        p.require(
            !refused.status.success()
                && out_text(&refused.stderr).contains("rolled back")
                && !out_text(&refused.stdout).contains("value-of-prod-old"),
            format!(
                "a runner with a pin refuses prod's older revision: {}",
                out_text(&refused.stderr)
            ),
        )?;

        // Decisive: a runner with no pin, the same variables, the older file.
        let machine = fresh_machine(w.root.path(), &w.prod_old);
        let out = w.get(&machine, &expected);
        p.reached();
        p.note(format!(
            "stderr: {}stdout: {}",
            out_text(&out.stderr),
            out_text(&out.stdout)
        ));
        p.target(
            !out.status.success() && !out_text(&out.stdout).contains("value-of-prod-old"),
            "a pinless runner with MURK_EXPECTED_VAULT refuses a revision below the minimum",
        );
        p.today(
            out.status.success() && out_text(&out.stdout).contains("value-of-prod-old"),
            "the variable is ignored and the older revision's value prints",
        );
        Ok(())
    });
}

/// `murk verify` prints the vault's `MURK_EXPECTED_VAULT` value alone on
/// standard output, and a pinless runner loads the vault with it. Set but
/// empty, the variable refuses the load instead of turning the check off: a
/// missing CI secret expands to an empty value.
#[test]
fn verify_prints_the_expected_vault_and_an_empty_value_is_refused() {
    let w = TwoVaults::build().unwrap();
    let printed = on_machine(
        &fresh_machine(w.root.path(), &w.prod),
        Key::Inline(&w.ci.secret),
        &[("MURK_TRUSTED_SIGNERS", w.signers.as_str())],
        &["verify"],
        "",
    );
    assert_eq!(
        out_text(&printed.stdout).trim(),
        w.expected(),
        "verify prints the value on stdout: {}",
        out_text(&printed.stderr)
    );
    let machine = fresh_machine(w.root.path(), &w.prod);
    let ok = w.get(&machine, out_text(&printed.stdout).trim());
    assert!(
        ok.status.success() && out_text(&ok.stdout).contains("value-of-prod"),
        "the printed value loads prod: {}",
        out_text(&ok.stderr)
    );
    for empty in ["", "  "] {
        let out = w.get(&fresh_machine(w.root.path(), &w.prod), empty);
        assert!(
            !out.status.success()
                && !out_text(&out.stdout).contains("value-of-prod")
                && out_text(&out.stderr).contains("MURK_EXPECTED_VAULT is set but empty"),
            "{empty:?} is refused: {}",
            out_text(&out.stderr)
        );
    }
}

/// An agent grant reads no trust pin, so `MURK_EXPECTED_VAULT` is its only
/// vault-id and rollback check. With it, a grant load refuses a vault whose
/// id is not the expected one, and a revision below the minimum. The
/// current revision at the minimum loads.
#[test]
fn a_grant_load_meets_murk_expected_vault() {
    let root = TempDir::new().unwrap();
    let alice = Who::generate("alice");
    let prod = Org::new(root.path(), "prod", &alice).unwrap();
    prod.add("API", "value-first").unwrap();
    let key = root.path().join("bot.key");
    prod.must(
        &[
            "agent",
            "grant",
            "--name",
            "bot",
            "--only",
            "API",
            "--ttl",
            "1h",
            "--out",
            key.to_str().unwrap(),
        ],
        "",
    )
    .unwrap();
    prod.add("API", "value-old").unwrap();
    let old = prod.vault();
    prod.add("API", "value-new").unwrap();
    let current = prod.vault();
    let (id, minimum) = (vault_id(&current), generation(&current));
    assert!(generation(&old) < minimum && vault_id(&old) == id);

    let get = |vault: &[u8], expected: &str| {
        let machine = fresh_machine(root.path(), vault);
        on_machine(
            &machine,
            Key::File(&key),
            &[("MURK_EXPECTED_VAULT", expected)],
            &["get", "API"],
            "",
        )
    };
    let expected = format!("{id}:{minimum}");

    let ok = get(&current, &expected);
    assert!(
        ok.status.success() && out_text(&ok.stdout).contains("value-new"),
        "the grant loads the expected vault at the minimum: {}",
        out_text(&ok.stderr)
    );

    let other = get(
        &current,
        &format!("ffeeddccbbaa99887766554433221100:{minimum}"),
    );
    assert!(
        !other.status.success()
            && !out_text(&other.stdout).contains("value-new")
            && out_text(&other.stderr).contains("not the vault that MURK_EXPECTED_VAULT names"),
        "the grant refuses a vault with another id: {}",
        out_text(&other.stderr)
    );

    let older = get(&old, &expected);
    assert!(
        !older.status.success()
            && !out_text(&older.stdout).contains("value-old")
            && out_text(&older.stderr).contains(&format!(
                "generation is {}, and the minimum is {minimum}",
                generation(&old)
            )),
        "the grant refuses a revision below the minimum: {}",
        out_text(&older.stderr)
    );
}

/// A runner with no trust pin whose `MURK_EXPECTED_VAULT` also names a
/// revision (`<id>:<generation>:<revision>`, as `murk verify` prints it for
/// the current one) refuses a genuine file from a stale fork that has a
/// higher counter than the minimum but does not descend from that revision.
/// Without the revision part, the same stale file loads (the stated
/// residual); a descendant of the revision loads either way. Needs format 4.
#[test]
fn row_r_i8_c_fork() {
    common::rows::check("R-I8-c:fork", |p| {
        let root = TempDir::new().unwrap();
        let (alice, ci) = (Who::generate("alice"), Who::generate("ci"));
        let prod = Org::new(root.path(), "prod", &alice)?;
        prod.must(&["circle", "authorize", &ci.pubkey, "--name", "ci"], "")?;
        prod.add("DB_URL", "LEAKED-db-value")?;
        let signers = prod.entry()?;
        let fork_point = prod.vault();

        // A stale fork: a teammate saves on from the fork point, keeping the
        // leaked value, until its counter is well above prod's.
        let stale_org = Org::adopt(root.path(), "stale", &alice, &signers, &fork_point);
        for n in 0..6 {
            stale_org.add(&format!("FORK_{n}"), "f")?;
        }
        let stale = stale_org.vault();

        // Prod rotates the value and moves on; `murk verify` names its tip.
        prod.add("DB_URL", "ROTATED-db-value")?;
        prod.add("EXTRA", "e")?;
        let tip = prod.vault();
        let verify = prod.must(&["verify"], "")?;
        let id = vault_id(&tip);
        let printed = format!("{}{}", out_text(&verify.stdout), out_text(&verify.stderr));
        let with_revision = printed
            .split_whitespace()
            .find(|word| word.starts_with(&format!("{id}:")) && word.matches(':').count() == 2)
            .map(str::to_string);
        prod.add("MORE", "m")?;
        let descendant = prod.vault();
        p.require(
            generation(&stale) > generation(&tip) && generation(&descendant) > generation(&tip),
            "the stale fork and prod's later revision are numbered above prod's tip",
        )?;
        p.require(
            [&tip, &stale, &descendant]
                .iter()
                .all(|v| header_major(v) == Some(4)),
            format!(
                "format 4 vaults (header versions {:?}, {:?}, {:?})",
                header_major(&tip),
                header_major(&stale),
                header_major(&descendant)
            ),
        )?;
        let with_revision = with_revision.ok_or_else(|| {
            format!("murk verify prints no <id>:<generation>:<revision> value: {printed}")
        })?;
        let minimum = format!("{id}:{}", generation(&tip));
        let w = |vault: &[u8], expected: &str| {
            let machine = fresh_machine(root.path(), vault);
            on_machine(
                &machine,
                Key::Inline(&ci.secret),
                &[
                    ("MURK_TRUSTED_SIGNERS", signers.as_str()),
                    ("MURK_EXPECTED_VAULT", expected),
                ],
                &["get", "DB_URL"],
                "",
            )
        };

        // Controls: without the revision the stale fork loads (the residual),
        // and with it a descendant of the revision loads.
        let residual = w(&stale, &minimum);
        p.require(
            residual.status.success() && out_text(&residual.stdout).contains("LEAKED-db-value"),
            format!(
                "without a revision in the variable the stale fork loads: {}",
                out_text(&residual.stderr)
            ),
        )?;
        let forward = w(&descendant, &with_revision);
        p.require(
            forward.status.success() && out_text(&forward.stdout).contains("ROTATED-db-value"),
            format!(
                "a descendant of the named revision loads: {}",
                out_text(&forward.stderr)
            ),
        )?;

        // Decisive: the stale fork against the variable that names the tip.
        let out = w(&stale, &with_revision);
        p.reached();
        p.note(out_text(&out.stderr));
        p.target(
            !out.status.success() && out_text(&out.stderr).contains("not descend"),
            "the stale fork is refused as not descending from the named revision",
        );
        p.target(
            !out_text(&out.stdout).contains("LEAKED-db-value"),
            "the leaked value is not printed",
        );
        Ok(())
    });
}

/// A grant that expired and was revoked, whose key is later listed as an
/// ordinary recipient. Alice's vault holds `S` and `OTHER`; `bot` was a grant
/// for `S` alone.
struct SpentGrant {
    root: TempDir,
    org: Org,
    /// `MURK_TRUSTED_SIGNERS`: alice's signer entry.
    signers: String,
    bot: Who,
    /// The key file as `agent grant` wrote it, and the same key without its
    /// comment lines.
    minted: PathBuf,
    stripped: PathBuf,
    /// The vault before the grant, with the grant's record (expired by now),
    /// and after `agent revoke`.
    before: Vec<u8>,
    live: Vec<u8>,
    revoked: Vec<u8>,
}

impl SpentGrant {
    fn build() -> Result<Self, String> {
        let root = TempDir::new().unwrap();
        let alice = Who::generate("alice");
        let org = Org::new(root.path(), "alice", &alice)?;
        org.add("S", "real-secret-value")?;
        org.add("OTHER", "other-secret")?;
        let before = org.vault();
        let signers = org.entry()?;

        // A grant for S that lives two seconds.
        let minted = root.path().join("bot.key");
        org.must(
            &[
                "agent",
                "grant",
                "--name",
                "bot",
                "--only",
                "S",
                "--ttl",
                "2s",
                "--out",
                minted.to_str().unwrap(),
            ],
            "",
        )?;
        let granted = Instant::now();
        let live = org.vault();
        let text = fs::read_to_string(&minted).unwrap();
        let bot = Who::from_secret("bot", &text);
        let stripped = root.path().join("bot-stripped.key");
        let secret_line: String = text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| format!("{l}\n"))
            .collect();
        write_key_file(&stripped, &secret_line);
        if let Some(wait) =
            (granted + Duration::from_millis(2200)).checked_duration_since(Instant::now())
        {
            std::thread::sleep(wait);
        }
        org.must(&["agent", "revoke", "bot"], "")?;
        let revoked = org.vault();
        Ok(SpentGrant {
            root,
            org,
            signers,
            bot,
            minted,
            stripped,
            before,
            live,
            revoked,
        })
    }

    /// `args` run by the holder of the grant's key on a machine of its own
    /// with `vault` as `.murk`, in each way the holder can present the key.
    /// Returns what each run printed and the vault file it left.
    fn holder(
        &self,
        vault: &[u8],
        args: &[&str],
        stdin: &str,
    ) -> Vec<(&'static str, Output, Vec<u8>)> {
        [
            ("the key file as minted", Key::File(&self.minted)),
            (
                "the key file with its comment lines stripped",
                Key::File(&self.stripped),
            ),
            ("MURK_KEY", Key::Inline(&self.bot.secret)),
        ]
        .into_iter()
        .map(|(how, key)| {
            let machine = fresh_machine(self.root.path(), vault);
            // A key file must not be shared across machines' homes: each run
            // reads the one file in place, which is only read.
            let out = on_machine(
                &machine,
                key,
                &[("MURK_TRUSTED_SIGNERS", self.signers.as_str())],
                args,
                stdin,
            );
            let after = fs::read(machine.1.join(".murk")).unwrap();
            (how, out, after)
        })
        .collect()
    }

    /// `vault` (a revision alice signed) with `extra` listed as an ordinary
    /// recipient who reads every shared value: built with the library, so it
    /// does not depend on `circle authorize` accepting the key.
    fn list_as_recipient(&self, vault: &[u8], extra: &Who) -> Vec<u8> {
        let alice = murk_cli::crypto::parse_identity(&self.org.alice.secret).unwrap();
        let path = self.root.path().join("hand-built.murk");
        fs::write(&path, vault).unwrap();
        let mut vault = murk_cli::read_vault(path.to_str().unwrap()).unwrap();
        let readers: Vec<murk_cli::MurkRecipient> = [&self.org.alice.pubkey, &extra.pubkey]
            .iter()
            .map(|k| murk_cli::crypto::parse_recipient(k).unwrap())
            .collect();
        for entry in vault.secrets.values_mut().filter(|e| !e.shared.is_empty()) {
            let plaintext = murk_cli::decrypt_value(&entry.shared, &alice).unwrap();
            entry.shared = murk_cli::encrypt_value(&plaintext, &readers).unwrap();
        }
        vault.recipients.push(extra.pubkey.clone());
        common::forgery::reseal(&mut vault, &alice);
        murk_cli::vault::write(&path, &vault).unwrap();
        fs::read(&path).unwrap()
    }

    /// Whether `vault`'s meta lists `key` among its `revoked_grants` (the
    /// grant tombstone, which murk does not write yet).
    fn tombstones(&self, vault: &[u8], key: &str) -> bool {
        let alice = murk_cli::crypto::parse_identity(&self.org.alice.secret).unwrap();
        let path = self.root.path().join("tombstone-check.murk");
        fs::write(&path, vault).unwrap();
        let vault = murk_cli::read_vault(path.to_str().unwrap()).unwrap();
        murk_cli::decrypt_meta(&vault, &alice)
            .ok()
            .flatten()
            .and_then(|meta| serde_json::to_value(meta).ok())
            .is_some_and(|meta| {
                meta["revoked_grants"]
                    .as_array()
                    .is_some_and(|keys| keys.iter().any(|k| k == key))
            })
    }

    /// The controls that show the scenario works: the vault that still holds
    /// the grant's record refuses the expired key, the same hand-built vault
    /// lists a key that was never a grant and that key reads and writes it,
    /// and the grant's key cannot read the vault as it stands without being
    /// listed.
    fn controls(&self, p: &common::rows::Probe, from: &[u8]) -> Result<(), String> {
        for (how, out, _) in self.holder(&self.live, &["get", "S"], "") {
            p.require(
                !out.status.success()
                    && out_text(&out.stderr).contains("expired")
                    && !out_text(&out.stdout).contains("real-secret-value"),
                format!(
                    "the vault that holds the grant's record refuses the expired key ({how}): {}",
                    out_text(&out.stderr)
                ),
            )?;
        }
        let dave = Who::generate("dave");
        let listed = self.list_as_recipient(from, &dave);
        let machine = fresh_machine(self.root.path(), &listed);
        let read = on_machine(
            &machine,
            Key::Inline(&dave.secret),
            &[("MURK_TRUSTED_SIGNERS", self.signers.as_str())],
            &["get", "OTHER"],
            "",
        );
        p.require(
            read.status.success() && out_text(&read.stdout).contains("other-secret"),
            format!(
                "a hand-built vault that lists a key that was never a grant is read by it: {}",
                out_text(&read.stderr)
            ),
        )
    }
}

/// A key that was an agent grant, revoked after it expired and then listed as
/// an ordinary recipient, is refused by `circle authorize` and by every load
/// of a vault that lists it, however the holder presents the key: as minted,
/// without its comment lines, or in `MURK_KEY`. Today it reads as an
/// operator: it reads values outside its old scope and writes.
#[test]
fn row_r_i16_a() {
    common::rows::check("R-I16-a", |p| {
        let w = SpentGrant::build()?;
        w.controls(p, &w.revoked)?;
        let listed = w.list_as_recipient(&w.revoked, &w.bot);

        // Decisive: the holder loads a vault that lists the key.
        p.reached();
        let reads = w.holder(&listed, &["get", "S"], "");
        let others = w.holder(&listed, &["get", "OTHER"], "");
        let writes = w.holder(&listed, &["add", "PLANTED", "--desc", "x"], "planted\n");
        for (((how, read, _), (_, other, _)), (_, write, after)) in
            reads.iter().zip(&others).zip(&writes)
        {
            p.note(format!("{how}: get S: {}", out_text(&read.stderr)));
            p.target(
                !read.status.success() && !out_text(&read.stdout).contains("real-secret-value"),
                format!("the key listed as a recipient reads nothing ({how}): get S refused"),
            );
            p.target(
                !other.status.success() && !out_text(&other.stdout).contains("other-secret"),
                format!("the key listed as a recipient reads nothing ({how}): get OTHER refused"),
            );
            p.target(
                !write.status.success() && *after == listed,
                format!("the key listed as a recipient writes nothing ({how}): add refused"),
            );
            p.today(
                read.status.success()
                    && out_text(&read.stdout).contains("real-secret-value")
                    && other.status.success()
                    && out_text(&other.stdout).contains("other-secret")
                    && write.status.success()
                    && *after != listed,
                format!("the key reads S and OTHER and writes PLANTED as an operator ({how})"),
            );
        }

        // Alice, whose pin is at the revoked vault, authorizes the key.
        let authorize = w.org.run(
            &["circle", "authorize", &w.bot.pubkey, "--name", "botop"],
            "",
        );
        p.note(format!("circle authorize: {}", out_text(&authorize.stderr)));
        p.target(
            !authorize.status.success(),
            "circle authorize refuses a key that was an agent grant",
        );
        p.today(
            authorize.status.success(),
            "circle authorize lists the old grant key as a recipient",
        );
        Ok(())
    });
}

/// A runner with no trust pin refuses a vault that lists a key the vault
/// itself records as a revoked grant (its `revoked_grants`), whatever the
/// holder's key file says. Needs the tombstone in the vault.
#[test]
fn row_r_i16_b_pinless() {
    common::rows::check("R-I16-b:pinless", |p| {
        let w = SpentGrant::build()?;
        w.controls(p, &w.revoked)?;
        p.require(
            w.tombstones(&w.revoked, &w.bot.pubkey),
            "the vault alice saved when she revoked the grant lists its key in revoked_grants",
        )?;
        let listed = w.list_as_recipient(&w.revoked, &w.bot);
        p.require(
            w.tombstones(&listed, &w.bot.pubkey),
            "the hand-built vault keeps the revoked_grants set",
        )?;

        p.reached();
        for (how, out, _) in w.holder(&listed, &["get", "S"], "") {
            p.note(format!("{how}: {}", out_text(&out.stderr)));
            p.target(
                !out.status.success() && !out_text(&out.stdout).contains("real-secret-value"),
                format!("a pinless runner refuses the vault by its own revoked_grants ({how})"),
            );
        }
        Ok(())
    });
}

/// A signer who accepts a revision from before the grant with `murk trust`
/// and then saves still writes the grant's key into `revoked_grants`, because
/// the machine remembers the sets it accepted; a hand-built revision on top,
/// which lists the key as a recipient and keeps that set, is refused by a
/// pinless runner. Needs the tombstone in the vault.
#[test]
fn row_r_i16_b_p4() {
    common::rows::check("R-I16-b:p4", |p| {
        let w = SpentGrant::build()?;
        w.controls(p, &w.revoked)?;

        // Alice's machine accepts the revision from before the grant (it
        // reads as rolled back, which `murk trust` resets), then saves.
        w.org.put(&w.before);
        w.org.must(&["trust", "--yes"], "")?;
        w.org.add("AFTER", "after-value")?;
        let honest = w.org.vault();
        p.require(
            w.tombstones(&honest, &w.bot.pubkey),
            "the save after murk trust of the older revision still lists the grant's key in revoked_grants",
        )?;
        let listed = w.list_as_recipient(&honest, &w.bot);
        p.require(
            w.tombstones(&listed, &w.bot.pubkey),
            "the hand-built revision keeps the revoked_grants set",
        )?;

        p.reached();
        for (how, out, _) in w.holder(&listed, &["get", "S"], "") {
            p.note(format!("{how}: {}", out_text(&out.stderr)));
            p.target(
                !out.status.success() && !out_text(&out.stdout).contains("real-secret-value"),
                format!("a pinless runner refuses the revision by its own revoked_grants ({how})"),
            );
        }
        Ok(())
    });
}
