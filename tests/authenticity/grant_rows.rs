// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Invariant rows about revoked agent grants (see `tests/invariant_rows.tsv`):
//! once a key was an agent grant in a vault and its grant record left, murk
//! never lets that key read the vault again, except after `murk trust
//! --re-add` on the machine that writes, for the revocation ids it showed.
//!
//! A vault records each revocation in its meta (`revoked_grants`, a set of
//! random revocation ids per grant key). A machine also keeps the ids it saw
//! and where it saw each grant live (branch and commit) in its trust pin's
//! sidecar.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use tempfile::TempDir;

use super::common::forgery;
use super::common::rows::{Probe, check};
use super::{Machine, alice_repo, authorize, commit, git, git_ok, head_commit};

// ── Helpers ──

/// alice's repo (main, `DB_URL`) with carol as a member who trusted it, and
/// the merge driver set up.
struct Scene {
    _dir: TempDir,
    base: PathBuf,
    alice: Machine,
    carol: Machine,
    repo: PathBuf,
}

impl Scene {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let (alice, repo) = alice_repo(&base);
        let carol = Machine::new(&base, "carol");
        carol.init(&base.join("carol-scratch"), "carol");
        authorize(&alice, &repo, &carol, "carol");
        super::use_merge_driver(&repo);
        let s = Self {
            _dir: dir,
            base,
            alice,
            carol,
            repo,
        };
        s.ok(&s.carol, &["trust", "--yes"], "");
        // alice confirms carol's signing key once, on carol's first save.
        s.add(&s.carol, "CAROL");
        s.ok(&s.alice, &["trust", "--yes"], "");
        commit(&s.repo, "carol's first save");
        s
    }

    /// Another member, authorized by alice and trusting the vault.
    fn member(&self, name: &str) -> Machine {
        let who = Machine::new(&self.base, name);
        who.init(&self.base.join(format!("{name}-scratch")), name);
        authorize(&self.alice, &self.repo, &who, name);
        commit(&self.repo, &format!("authorize {name}"));
        self.ok(&who, &["trust", "--yes"], "");
        // The others confirm the new member's signing key on their first save.
        self.add(&who, &name.to_uppercase());
        self.ok(&self.alice, &["trust", "--yes"], "");
        self.ok(&self.carol, &["trust", "--yes"], "");
        commit(&self.repo, &format!("{name}'s first save"));
        who
    }

    fn run(&self, who: &Machine, args: &[&str], stdin: &str) -> Output {
        who.with_key(&self.repo, &who.key_file())
            .args(args)
            .write_stdin(stdin.to_string())
            .output()
            .unwrap()
    }

    /// murk as `who`, which must succeed.
    fn ok(&self, who: &Machine, args: &[&str], stdin: &str) -> Output {
        let out = self.run(who, args, stdin);
        assert!(out.status.success(), "murk {args:?}: {}", text(&out.stderr));
        out
    }

    /// `who` sets `key`.
    fn add(&self, who: &Machine, key: &str) {
        self.ok(who, &["add", key], "value\n");
    }

    /// alice grants agent `name` `DB_URL` for an hour. Returns the grant's
    /// key and its key file.
    fn grant(&self, name: &str) -> (String, PathBuf) {
        let file = self.base.join(format!("{name}.key"));
        let _ = fs::remove_file(&file);
        self.ok(
            &self.alice,
            &[
                "agent",
                "grant",
                "--name",
                name,
                "--only",
                "DB_URL",
                "--ttl",
                "1h",
                "--out",
                file.to_str().unwrap(),
            ],
            "",
        );
        let secret = fs::read_to_string(&file)
            .unwrap()
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .unwrap()
            .trim()
            .to_string();
        let id: age::x25519::Identity = secret.parse().unwrap();
        (id.to_public().to_string(), file)
    }

    fn git(&self, args: &[&str]) {
        git_ok(&self.repo, args);
    }

    fn head(&self) -> String {
        head_commit(&self.repo)
    }

    fn vault(&self) -> Vec<u8> {
        fs::read(self.repo.join(".murk")).unwrap()
    }

    /// Commit `file` as `.murk` on the branch checked out.
    fn put(&self, file: &[u8], message: &str) {
        fs::write(self.repo.join(".murk"), file).unwrap();
        commit(&self.repo, message);
    }

    fn identity(&self) -> murk_cli::crypto::MurkIdentity {
        murk_cli::crypto::parse_identity(&self.alice.secret_key()).unwrap()
    }

    /// The revocation ids `file`'s meta holds for `key`.
    fn ids(&self, file: &[u8], key: &str) -> BTreeSet<String> {
        let vault = murk_cli::vault::parse(std::str::from_utf8(file).unwrap()).unwrap();
        murk_cli::decrypt_meta(&vault, &self.identity())
            .unwrap()
            .unwrap()
            .revoked_grants
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    /// Whether `file` holds a grant record for `key`.
    fn granted(&self, file: &[u8], key: &str) -> bool {
        let vault = murk_cli::vault::parse(std::str::from_utf8(file).unwrap()).unwrap();
        murk_cli::decrypt_meta(&vault, &self.identity())
            .unwrap()
            .unwrap()
            .grants
            .values()
            .any(|g| g.pubkey == key)
    }

    /// `file` changed by `edit` and signed by alice one generation later:
    /// what an older murk component (or a modified one) of a trusted signer
    /// writes.
    fn resealed(
        &self,
        file: &[u8],
        edit: impl FnOnce(&mut murk_cli::types::Vault, &mut murk_cli::types::Meta),
    ) -> Vec<u8> {
        let identity = self.identity();
        let mut vault = murk_cli::vault::parse(std::str::from_utf8(file).unwrap()).unwrap();
        vault.generation += 1;
        let mut meta = murk_cli::decrypt_meta(&vault, &identity).unwrap().unwrap();
        edit(&mut vault, &mut meta);
        forgery::rewrite_meta(&mut vault, &identity, |m| *m = meta);
        serde_json::to_vec_pretty(&vault).unwrap()
    }

    /// `file` as a murk 0.15 save leaves it: one generation later, without a
    /// revoked grant set.
    fn saved_by_0_15(&self, file: &[u8]) -> Vec<u8> {
        self.resealed(file, |_, meta| meta.revoked_grants.clear())
    }

    /// `file` as a murk 0.15 `agent revoke` of `key` leaves it: the grant
    /// record, recipient entry, scoped copies and `agents` entry gone, and
    /// no revoked grant set.
    fn revoked_by_0_15(&self, file: &[u8], key: &str) -> Vec<u8> {
        self.resealed(file, |vault, meta| {
            vault.recipients.retain(|r| r != key);
            vault.agents.remove(key);
            for entry in vault.secrets.values_mut() {
                entry.private.remove(key);
            }
            meta.grants.retain(|_, g| g.pubkey != key);
            meta.recipients.remove(key);
            meta.revoked_grants.clear();
        })
    }

    /// `file` listing `key` as an ordinary recipient, with every shared value
    /// re-encrypted to it, signed by alice.
    fn listing(&self, file: &[u8], key: &str) -> Vec<u8> {
        let identity = self.identity();
        self.resealed(file, |vault, _| {
            vault.recipients.push(key.to_string());
            let readers: Vec<murk_cli::MurkRecipient> = vault
                .recipients
                .iter()
                .map(|k| murk_cli::crypto::parse_recipient(k).unwrap())
                .collect();
            for entry in vault.secrets.values_mut().filter(|e| !e.shared.is_empty()) {
                let plaintext = murk_cli::decrypt_value(&entry.shared, &identity).unwrap();
                entry.shared = murk_cli::encrypt_value(&plaintext, &readers).unwrap();
            }
        })
    }

    /// `who`'s trust pin sidecar for the vault (`Null` when absent).
    fn sidecar(&self, who: &Machine) -> serde_json::Value {
        let vault: serde_json::Value = serde_json::from_slice(&self.vault()).unwrap();
        super::pin_files(who)
            .into_iter()
            .find(|p| {
                serde_json::from_slice::<serde_json::Value>(&fs::read(p).unwrap())
                    .is_ok_and(|pin| pin["vault_id"] == vault["vault_id"])
            })
            .and_then(|p| fs::read(p.with_extension("lineage.json")).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// The revoked grant records in `who`'s sidecar: the ids seen, the ids
    /// re-admitted and the live sightings.
    fn grant_fields(&self, who: &Machine) -> [serde_json::Value; 3] {
        let sidecar = self.sidecar(who);
        ["revoked_grants_seen", "readmitted_grants", "grants_live_on"]
            .map(|field| sidecar[field].clone())
    }

    /// A runner with no trust pin that trusts alice by `MURK_TRUSTED_SIGNERS`
    /// loads `file` with the key file `key`.
    fn pinless(&self, file: &[u8], key: &Path) -> Output {
        let runner = Machine::new(&self.base, &format!("runner-{}", random_name()));
        let work = runner.home.join("work");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join(".murk"), file).unwrap();
        let (entry, _) = self.alice.signer_entry(&self.repo);
        runner
            .with_key(&work, key)
            .env("MURK_TRUSTED_SIGNERS", entry)
            .args(["get", "DB_URL"])
            .output()
            .unwrap()
    }
}

fn random_name() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed).to_string()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Whether `stderr` names `key` (shortened or whole) and the way back.
fn names_key_and_re_add(stderr: &str, key: &str) -> bool {
    stderr.contains(&key[..8]) && stderr.contains("--re-add")
}

// ── R-I16-b:p4: a reset to before the grant, then a save ──

/// alice's machine saw grant G live on main at commit C (a save after the
/// grant was committed). She resets main to before the grant, accepts that
/// revision with `murk trust`, and saves. The commit checked out is an
/// ancestor of the sighting, so the save gives G a revocation id, and a
/// pinless runner refuses a revision that lists G by the vault's own set.
#[test]
fn row_r_i16_b_p4_reset() {
    check("R-I16-b:p4-reset", |p: &mut Probe| {
        let s = Scene::new();
        let before = s.head();
        let (g, key) = s.grant("bot");
        commit(&s.repo, "grant bot");
        s.add(&s.alice, "Y");
        commit(&s.repo, "a save with the grant live");
        let sighted = s.sidecar(&s.alice)["grants_live_on"][&g]["main"].clone();
        p.require(
            sighted
                .as_str()
                .is_some_and(|c| c != before && !c.is_empty()),
            format!("alice's machine saw G live on main after the grant commit: {sighted}"),
        )?;

        s.git(&["reset", "-q", "--hard", &before]);
        s.ok(&s.alice, &["trust", "--yes"], "");
        p.reached();
        s.add(&s.alice, "AFTER");
        let honest = s.vault();
        p.target(
            !s.ids(&honest, &g).is_empty(),
            "the save after the reset gives G a revocation id",
        );
        let listed = s.listing(&honest, &g);
        let out = s.pinless(&listed, &key);
        p.note(text(&out.stderr));
        p.target(
            !out.status.success() && !text(&out.stdout).contains("prod-db"),
            "a pinless runner refuses a revision that lists G, by its own set",
        );
        Ok(())
    });
}

// ── R-I16-c: recovery by revocation id ──

/// A wrong entry: a revision signed by alice puts bob's key, which was never
/// a grant, in the set (id i1). alice's machine accepts it, and `circle
/// authorize bob` is refused and names `--re-add`. alice re-admits i1 and
/// authorizes bob. A revision that carries only the old id i1 and lists bob
/// then loads with no new consent, and alice's save leaves bob out of the set.
#[test]
fn row_r_i16_c_recovery() {
    check("R-I16-c:recovery", |p: &mut Probe| {
        let s = Scene::new();
        let bob = Machine::new(&s.base, "bob");
        bob.init(&s.base.join("bob-scratch"), "bob");
        let bob_key = bob.pubkey();
        let i1 = "0123456789abcdef0123456789abcdef".to_string();
        let r1 = s.resealed(&s.vault(), |_, meta| {
            meta.revoked_grants
                .insert(bob_key.clone(), BTreeSet::from([i1.clone()]));
        });
        s.put(&r1, "R1: a wrong revocation of bob");
        s.ok(&s.alice, &["get", "DB_URL"], "");

        let refused = s.run(&s.alice, &["circle", "authorize", &bob_key], "");
        p.require(
            !refused.status.success() && names_key_and_re_add(&text(&refused.stderr), &bob_key),
            format!(
                "circle authorize is refused and names --re-add: {}",
                text(&refused.stderr)
            ),
        )?;
        s.ok(&s.alice, &["trust", "--re-add", &bob_key, "--yes"], "");
        p.require(
            s.vault() == r1,
            "--re-add of a key the vault does not list writes nothing",
        )?;
        s.ok(
            &s.alice,
            &["circle", "authorize", &bob_key, "--name", "bob"],
            "",
        );
        let r2 = s.vault();
        p.require(
            s.ids(&r2, &bob_key).is_empty(),
            "R2 lists bob and its set holds no id for him",
        )?;
        commit(&s.repo, "R2: authorize bob");

        // A revision that still carries only the old id i1 and lists bob.
        let old = s.resealed(&r2, |_, meta| {
            meta.revoked_grants
                .insert(bob_key.clone(), BTreeSet::from([i1.clone()]));
        });
        s.put(&old, "a revision with the old id");
        p.reached();
        let load = s.run(&s.alice, &["get", "DB_URL"], "");
        p.target(
            load.status.success(),
            format!("the old id needs no new consent: {}", text(&load.stderr)),
        );
        s.add(&s.alice, "X");
        p.target(
            s.ids(&s.vault(), &bob_key).is_empty(),
            "alice's save leaves bob out of the set",
        );
        Ok(())
    });
}

/// carol's machine re-admits grant G's wrong id i1. On another branch,
/// alice's machine, which never saw i1, revokes G for real, which gives it a
/// new id i2. carol reads only that revision and saves: her save keeps G
/// with i2. Back on main, where G's grant record still stands, carol's save
/// is refused.
#[test]
fn row_r_i16_c_denial() {
    check("R-I16-c:denial", |p: &mut Probe| {
        let s = Scene::new();
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot");
        let granted = s.head();
        s.ok(&s.carol, &["get", "DB_URL"], "");

        let i1 = "0123456789abcdef0123456789abcdef".to_string();
        let r1 = s.resealed(&s.vault(), |_, meta| {
            meta.revoked_grants
                .insert(g.clone(), BTreeSet::from([i1.clone()]));
        });
        s.put(&r1, "R1: a wrong revocation of bot");
        let refused = s.run(&s.carol, &["get", "DB_URL"], "");
        p.require(
            !refused.status.success() && names_key_and_re_add(&text(&refused.stderr), &g),
            format!(
                "carol refuses the grant with the wrong id: {}",
                text(&refused.stderr)
            ),
        )?;
        s.ok(&s.carol, &["trust", "--re-add", &g, "--yes"], "");
        p.require(
            s.ids(&s.vault(), &g).is_empty() && s.granted(&s.vault(), &g),
            "carol signed R1 again without i1, the grant live",
        )?;
        commit(&s.repo, "R1 re-signed by carol");

        s.git(&["checkout", "-q", "-b", "rev", &granted]);
        s.ok(&s.alice, &["agent", "revoke", "bot"], "");
        let i2 = s.ids(&s.vault(), &g);
        p.require(
            i2.len() == 1 && !i2.contains(&i1),
            format!("alice's revoke gives G a new id: {i2:?}"),
        )?;
        commit(&s.repo, "revoke bot");

        p.reached();
        s.add(&s.carol, "X");
        let kept = s.ids(&s.vault(), &g);
        p.target(
            kept == i2,
            format!("carol's save keeps G with the new id: {kept:?}"),
        );
        commit(&s.repo, "carol saves after the revoke");

        s.git(&["checkout", "-q", "main"]);
        let before = s.vault();
        let revived = s.run(&s.carol, &["add", "Z"], "value\n");
        p.note(text(&revived.stderr));
        p.target(
            !revived.status.success() && s.vault() == before,
            "a save that keeps G's grant record is refused on carol's machine",
        );
        Ok(())
    });
}

/// carol's machine saw grant G live on main. It loads alice's revoke (id
/// i1) and saves: the set for G is exactly {i1}, no second id.
#[test]
fn row_r_i16_c_dup() {
    check("R-I16-c:dup", |p: &mut Probe| {
        let s = Scene::new();
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot");
        s.ok(&s.carol, &["get", "DB_URL"], "");
        p.require(
            s.sidecar(&s.carol)["grants_live_on"][&g]["main"].is_string(),
            "carol's machine saw G live on main",
        )?;
        s.ok(&s.alice, &["agent", "revoke", "bot"], "");
        commit(&s.repo, "revoke bot");
        let i1 = s.ids(&s.vault(), &g);
        p.require(i1.len() == 1, "alice's revoke gives G one id")?;

        p.reached();
        s.add(&s.carol, "X");
        let ids = s.ids(&s.vault(), &g);
        p.target(
            ids == i1,
            format!("carol's save keeps exactly alice's id: {ids:?}"),
        );
        Ok(())
    });
}

/// carol's and dave's machines saw grant G live on main. alice revokes G
/// (i1), and alice, carol and dave each re-admit it. carol saves on main,
/// then dave: neither save gives G an id, and each machine loads the result
/// with no command.
#[test]
fn row_r_i16_c_multi() {
    check("R-I16-c:multi", |p: &mut Probe| {
        let s = Scene::new();
        let dave = s.member("dave");
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot");
        s.ok(&s.carol, &["get", "DB_URL"], "");
        s.ok(&dave, &["get", "DB_URL"], "");
        s.ok(&s.alice, &["agent", "revoke", "bot"], "");
        commit(&s.repo, "revoke bot");
        for who in [&s.alice, &s.carol, &dave] {
            s.ok(who, &["trust", "--re-add", &g, "--yes"], "");
        }

        p.reached();
        s.add(&s.carol, "C");
        commit(&s.repo, "carol");
        p.target(
            s.ids(&s.vault(), &g).is_empty(),
            "carol's save gives G no id",
        );
        s.add(&dave, "D");
        commit(&s.repo, "dave");
        p.target(
            s.ids(&s.vault(), &g).is_empty(),
            "dave's save gives G no id",
        );
        for (name, who) in [("alice", &s.alice), ("carol", &s.carol), ("dave", &dave)] {
            let out = s.run(who, &["get", "DB_URL"], "");
            p.target(
                out.status.success(),
                format!("{name} loads the result: {}", text(&out.stderr)),
            );
        }
        Ok(())
    });
}

// ── R-I16-d: a set an older component dropped ──

/// carol's machine accepted alice's revoke of G (id i1) without ever seeing
/// G live. A murk 0.15 save of alice's drops the set and lists G again: carol
/// refuses it by the ids she saw. A 0.15 save that drops only the set loads,
/// and carol's next save writes i1 back.
#[test]
fn row_r_i16_d() {
    check("R-I16-d", |p: &mut Probe| {
        let s = Scene::new();
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot");
        s.ok(&s.alice, &["agent", "revoke", "bot"], "");
        commit(&s.repo, "revoke bot");
        let revoked = s.vault();
        let i1 = s.ids(&revoked, &g);
        s.ok(&s.carol, &["get", "DB_URL"], "");
        p.require(
            s.sidecar(&s.carol)["grants_live_on"].get(&g).is_none(),
            "carol's machine never saw G live",
        )?;

        let relisted = s.saved_by_0_15(&s.listing(&revoked, &g));
        p.require(s.ids(&relisted, &g).is_empty(), "the 0.15 save has no set")?;
        s.put(&relisted, "0.15 save that lists bot");
        p.reached();
        let out = s.run(&s.carol, &["get", "DB_URL"], "");
        p.note(text(&out.stderr));
        p.target(
            !out.status.success() && !text(&out.stdout).contains("prod-db"),
            "carol refuses the vault that lists G, by the ids she saw",
        );

        s.git(&["reset", "-q", "--hard", "HEAD~1"]);
        let dropped = s.saved_by_0_15(&revoked);
        s.put(&dropped, "0.15 save without the set");
        s.add(&s.carol, "X");
        p.target(
            s.ids(&s.vault(), &g) == i1,
            "carol's save writes the same ids back",
        );
        Ok(())
    });
}

// ── R-I16-f: sightings by branch and commit ──

/// alice grants G on `feature` and sees it there. Back on main, which never
/// had G, she saves. `fork` keeps main where `feature` forked, so the commit
/// checked out on main is an ancestor of the sighting.
fn other_branch(p: &mut Probe, fork: bool) -> Result<(), String> {
    let s = Scene::new();
    s.git(&["checkout", "-q", "-b", "feature"]);
    if !fork {
        fs::write(s.repo.join("notes.txt"), "feature\n").unwrap();
        commit(&s.repo, "feature work");
    }
    let (g, key) = s.grant("bot");
    commit(&s.repo, "grant bot on feature");
    s.git(&["checkout", "-q", "main"]);
    if !fork {
        s.add(&s.alice, "MAIN");
        commit(&s.repo, "main moves");
    }

    p.reached();
    s.add(&s.alice, "X");
    commit(&s.repo, "save on main");
    p.target(
        s.ids(&s.vault(), &g).is_empty(),
        "main's set holds no id for G",
    );
    p.target(
        s.sidecar(&s.alice)["revoked_grants_seen"].get(&g).is_none(),
        "alice's machine holds no id for G",
    );
    s.git(&["checkout", "-q", "feature"]);
    for (name, who) in [("alice", &s.alice), ("carol", &s.carol)] {
        let out = s.run(who, &["get", "DB_URL"], "");
        p.target(
            out.status.success() && !text(&out.stderr).contains("revoked"),
            format!("{name} loads feature: {}", text(&out.stderr)),
        );
    }
    let read = s
        .carol
        .murk(&s.repo)
        .env("MURK_KEY_FILE", &key)
        .args(["get", "DB_URL"])
        .output()
        .unwrap();
    p.target(
        read.status.success() && text(&read.stdout).contains("prod-db"),
        format!("G's key reads DB_URL on feature: {}", text(&read.stderr)),
    );
    s.git(&["checkout", "-q", "main"]);
    let (merged, stderr) = super::git_merge(&s.alice, &s.repo, "feature");
    p.note(stderr.clone());
    p.target(
        !merged && stderr.contains("added on one side") && !stderr.contains("revoked"),
        "merging feature conflicts only on the one-sided recipient G",
    );
    Ok(())
}

#[test]
fn row_r_i16_f_other_branch() {
    check("R-I16-f:other-branch", |p: &mut Probe| {
        other_branch(p, false)
    });
}

#[test]
fn row_r_i16_f_fork_main() {
    check("R-I16-f:fork-main", |p: &mut Probe| other_branch(p, true));
}

/// alice revokes grant G on `revoke-bot`, not merged yet. Back on main,
/// where G's grant record still stands, her save is refused, and the
/// refusal says the revocation came from another revision and to merge the
/// branch that revokes the grant first. `--re-add` appears only as the undo
/// of a revoke made by mistake.
#[test]
fn a_revoke_on_an_unmerged_branch_says_to_merge_it_first() {
    let s = Scene::new();
    let (g, _) = s.grant("bot");
    commit(&s.repo, "grant bot");
    s.add(&s.alice, "Y");
    commit(&s.repo, "save on main");
    s.git(&["checkout", "-q", "-b", "revoke-bot"]);
    s.ok(&s.alice, &["agent", "revoke", "bot"], "");
    commit(&s.repo, "revoke bot");
    s.git(&["checkout", "-q", "main"]);

    let before = s.vault();
    let refused = s.run(&s.alice, &["add", "Q"], "value\n");
    let stderr = text(&refused.stderr);
    assert!(!refused.status.success() && s.vault() == before, "{stderr}");
    assert!(
        stderr.contains("does not record the revocation")
            && stderr.contains("Merge the branch that revokes the grant first"),
        "the refusal names merging the revoking branch: {stderr}"
    );
    assert!(
        stderr.contains("only to undo a revoke made by mistake")
            && names_key_and_re_add(&stderr, &g),
        "--re-add is named as the undo of a mistaken revoke: {stderr}"
    );
}

/// alice sees G live on `fix` at a commit of its own. She renames `fix` to
/// `fix-old`, main moves, and she cuts a new `fix` from main and saves on
/// it. The sighting's commit and the commit checked out are not related, so
/// the save gives G no id, and `fix-old` loads with no tombstone message.
#[test]
fn row_r_i16_f_branch_reuse() {
    check("R-I16-f:branch-reuse", |p: &mut Probe| {
        let s = Scene::new();
        s.git(&["checkout", "-q", "-b", "fix"]);
        fs::write(s.repo.join("notes.txt"), "fix\n").unwrap();
        commit(&s.repo, "fix work");
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot on fix");
        s.git(&["branch", "-m", "fix", "fix-old"]);
        s.git(&["checkout", "-q", "main"]);
        s.add(&s.carol, "MAIN");
        s.add(&s.carol, "MAIN2");
        commit(&s.repo, "carol saves on main");
        s.ok(&s.alice, &["get", "DB_URL"], "");
        s.git(&["checkout", "-q", "-b", "fix"]);

        p.reached();
        s.add(&s.alice, "X");
        p.target(
            s.ids(&s.vault(), &g).is_empty(),
            "the save on the new fix gives G no id",
        );
        commit(&s.repo, "new fix");
        s.git(&["checkout", "-q", "fix-old"]);
        let out = s.run(&s.alice, &["get", "DB_URL"], "");
        p.target(
            out.status.success() && !text(&out.stderr).contains("revoked"),
            format!(
                "fix-old loads with no tombstone message: {}",
                text(&out.stderr)
            ),
        );
        Ok(())
    });
}

/// G is live on main and alice saw it there. A murk 0.15 revoke of G (no
/// set) lands on main. alice loads it and saves: her save gives G an id.
#[test]
fn row_r_i16_f_old_revoke() {
    check("R-I16-f:old-revoke", |p: &mut Probe| {
        let s = Scene::new();
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot");
        let old = s.revoked_by_0_15(&s.vault(), &g);
        s.put(&old, "0.15 revoke of bot");
        s.ok(&s.alice, &["get", "DB_URL"], "");

        p.reached();
        s.add(&s.alice, "X");
        p.target(
            !s.ids(&s.vault(), &g).is_empty(),
            "alice's save gives G an id",
        );
        Ok(())
    });
}

/// Control (S2-2): G is revoked on main by this release, and alice loads
/// main. Branch `pr`, cut before the revoke and never accepted on alice's
/// machine, still holds G's grant record. Its load reads as history with a
/// warning; `murk trust` there is refused and names `--re-add`; `murk add`
/// writes nothing; a merge of `pr` into main conflicts and signs nothing.
#[test]
fn row_r_i16_f_cross_branch() {
    check("R-I16-f:cross-branch", |p: &mut Probe| {
        let s = Scene::new();
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot");
        s.git(&["checkout", "-q", "-b", "pr"]);
        fs::write(s.repo.join("notes.txt"), "pr\n").unwrap();
        commit(&s.repo, "pr work");
        s.add(&s.carol, "PR");
        commit(&s.repo, "carol saves on pr");
        s.git(&["checkout", "-q", "main"]);
        s.ok(&s.alice, &["agent", "revoke", "bot"], "");
        commit(&s.repo, "revoke bot");
        s.ok(&s.alice, &["get", "DB_URL"], "");
        s.git(&["checkout", "-q", "pr"]);

        p.reached();
        let load = s.run(&s.alice, &["get", "DB_URL"], "");
        p.target(
            load.status.success() && names_key_and_re_add(&text(&load.stderr), &g),
            format!("pr reads as history with a warning: {}", text(&load.stderr)),
        );
        let trust = s.run(&s.alice, &["trust", "--yes"], "");
        p.target(
            !trust.status.success() && names_key_and_re_add(&text(&trust.stderr), &g),
            format!("murk trust on pr is refused: {}", text(&trust.stderr)),
        );
        let before = s.vault();
        let add = s.run(&s.alice, &["add", "X"], "value\n");
        p.target(
            !add.status.success() && s.vault() == before,
            "murk add on pr writes nothing",
        );
        s.git(&["checkout", "-q", "main"]);
        let main = s.vault();
        let (merged, stderr) = super::git_merge(&s.alice, &s.repo, "pr");
        p.note(stderr.clone());
        p.target(!merged, "merging pr into main conflicts");
        let after = s.vault();
        let load = s.run(&s.alice, &["get", "DB_URL"], "");
        p.target(
            after == main || !load.status.success(),
            format!(
                "the merge signs nothing: .murk keeps main's vault, or holds a merge this machine refuses: {}",
                text(&load.stderr)
            ),
        );
        Ok(())
    });
}

/// Control (residual 6): sightings follow branch names and commits.
/// (a) After a rename, a reset to before G and a save there mint nothing.
/// (b) A new branch of the old name cut at the sighting's parent mints an
/// id, which `--re-add` clears. (c) After a rebase, a murk 0.15 revoke of G
/// and a save mint nothing.
#[test]
fn row_r_i16_f_residual() {
    check("R-I16-f:residual", |p: &mut Probe| {
        // (a) and (b)
        let s = Scene::new();
        s.git(&["checkout", "-q", "-b", "feature"]);
        fs::write(s.repo.join("notes.txt"), "feature\n").unwrap();
        commit(&s.repo, "feature work");
        let sighting = s.head();
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot on feature");
        s.git(&["branch", "-m", "feature", "feature-old"]);
        s.git(&["reset", "-q", "--hard", &sighting]);
        s.ok(&s.alice, &["trust", "--yes"], "");
        p.reached();
        s.add(&s.alice, "A");
        p.target(
            s.ids(&s.vault(), &g).is_empty(),
            "(a) a reset under the new name mints nothing",
        );
        s.git(&[
            "checkout",
            "-q",
            "-f",
            "-b",
            "feature",
            &format!("{sighting}~1"),
        ]);
        s.ok(&s.alice, &["trust", "--yes"], "");
        s.add(&s.alice, "B");
        p.target(
            !s.ids(&s.vault(), &g).is_empty(),
            "(b) a new branch of the old name at the sighting's parent mints an id",
        );
        s.ok(&s.alice, &["trust", "--re-add", &g, "--yes"], "");
        s.add(&s.alice, "C");
        p.target(
            s.ids(&s.vault(), &g).is_empty(),
            "(b) after --re-add, the next save gives G no id",
        );

        // (c)
        let s = Scene::new();
        s.git(&["checkout", "-q", "-b", "feature"]);
        fs::write(s.repo.join("notes.txt"), "feature\n").unwrap();
        commit(&s.repo, "feature work");
        let (g, _) = s.grant("bot");
        commit(&s.repo, "grant bot on feature");
        s.git(&["checkout", "-q", "main"]);
        fs::write(s.repo.join("other.txt"), "main\n").unwrap();
        commit(&s.repo, "main moves");
        s.git(&["checkout", "-q", "feature"]);
        let rebase = git(
            &s.repo,
            &["-c", "commit.gpgsign=false", "rebase", "-q", "main"],
        );
        p.require(rebase.status.success(), text(&rebase.stderr))?;
        let old = s.revoked_by_0_15(&s.vault(), &g);
        s.put(&old, "0.15 revoke of bot");
        s.ok(&s.alice, &["get", "DB_URL"], "");
        s.add(&s.alice, "C");
        p.target(
            s.ids(&s.vault(), &g).is_empty(),
            "(c) after a rebase, a 0.15 revoke and a save mint nothing",
        );
        Ok(())
    });
}

// ── R-I16-g: current loads refuse, history loads warn ──

/// G is revoked on main by this release, and carol's machine loaded the
/// revocation (it never saw G live). The arms load older revisions on a
/// detached HEAD, or the same vault as main's current state.
struct Revoked {
    s: Scene,
    g: String,
    granted: String,
}

fn revoked_scene() -> Revoked {
    let s = Scene::new();
    let (g, _) = s.grant("bot");
    commit(&s.repo, "grant bot");
    let granted = s.head();
    s.ok(&s.alice, &["agent", "revoke", "bot"], "");
    commit(&s.repo, "revoke bot");
    s.ok(&s.carol, &["get", "DB_URL"], "");
    Revoked { s, g, granted }
}

/// (a) A detached HEAD at the revision that holds G's grant record (and so
/// lists G as a recipient) reads as history: the value prints, a warning
/// names G, and the sidecar's revoked grant records are unchanged (a
/// history load may still record the grant key in `pin.grants`).
#[test]
fn row_r_i16_g_history() {
    check("R-I16-g:history", history_load);
}

/// R-I16-g:history with the rule that a recipient with its own grant
/// record is not a plain recipient as the guard under test.
#[test]
fn row_r_i16_g_history_own() {
    check("R-I16-g:history-own", history_load);
}

fn history_load(p: &mut Probe) -> Result<(), String> {
    let Revoked { s, g, granted } = revoked_scene();
    s.git(&["checkout", "-q", "--detach", &granted]);
    let fields = s.grant_fields(&s.carol);
    p.reached();
    let out = s.run(&s.carol, &["get", "DB_URL"], "");
    p.target(
        out.status.success() && text(&out.stdout).contains("prod-db"),
        format!("the history load succeeds: {}", text(&out.stderr)),
    );
    p.target(
        names_key_and_re_add(&text(&out.stderr), &g) && text(&out.stderr).contains("history"),
        "the warning names G and says it was read as history",
    );
    p.target(
        s.grant_fields(&s.carol) == fields,
        "the sidecar's revoked grant records are unchanged",
    );
    Ok(())
}

/// (b) The same grant, in a vault alice signed above the revocation, loaded
/// as main's current state: refused, and the message names G and --re-add.
#[test]
fn row_r_i16_g_current() {
    check("R-I16-g:current", |p: &mut Probe| {
        let Revoked { s, g, granted } = revoked_scene();
        let file = s.vault_at(&granted);
        let top = super::generation_of(&s.vault());
        let current = s.resealed(&file, |vault, _| vault.generation = top + 1);
        s.put(&current, "the grant again, above the revocation");
        p.reached();
        let out = s.run(&s.carol, &["get", "DB_URL"], "");
        p.target(
            !out.status.success() && names_key_and_re_add(&text(&out.stderr), &g),
            format!("the current load is refused: {}", text(&out.stderr)),
        );
        Ok(())
    });
}

/// (c) A detached HEAD at a vault alice signed that lists G as a recipient
/// with no grant record: refused, history or not.
#[test]
fn row_r_i16_g_plain() {
    check("R-I16-g:plain", |p: &mut Probe| {
        let Revoked { s, g, .. } = revoked_scene();
        let listed = s.listing(&s.vault(), &g);
        s.git(&["checkout", "-q", "-b", "side"]);
        s.put(&listed, "lists bot without its grant");
        let at = s.head();
        s.git(&["checkout", "-q", "--detach", &at]);
        p.reached();
        let out = s.run(&s.carol, &["get", "DB_URL"], "");
        p.target(
            !out.status.success() && names_key_and_re_add(&text(&out.stderr), &g),
            format!("the plain recipient is refused: {}", text(&out.stderr)),
        );
        Ok(())
    });
}

/// (d) On the detached HEAD of (a), `murk add` is refused and the vault
/// file is unchanged.
#[test]
fn row_r_i16_g_save() {
    check("R-I16-g:save", |p: &mut Probe| {
        let Revoked { s, granted, .. } = revoked_scene();
        s.git(&["checkout", "-q", "--detach", &granted]);
        let before = s.vault();
        p.reached();
        let out = s.run(&s.carol, &["add", "X"], "value\n");
        p.note(text(&out.stderr));
        p.target(
            !out.status.success() && s.vault() == before,
            "a save that keeps the revoked grant writes nothing",
        );
        Ok(())
    });
}

impl Scene {
    /// The vault file committed at `rev`.
    fn vault_at(&self, rev: &str) -> Vec<u8> {
        let out = git(&self.repo, &["show", &format!("{rev}:.murk")]);
        assert!(out.status.success());
        out.stdout
    }
}
