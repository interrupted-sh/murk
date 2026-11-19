// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `murk verify --signature-only`: the keyless check of the vault signature
//! against `MURK_TRUSTED_SIGNERS`, for a pull-request check in CI.

use std::fs;
use std::path::Path;

use assert_fs::TempDir;
use predicates::prelude::*;

mod common;
use common::{init_vault, murk, murk_bin};

/// A real unencrypted ssh-ed25519 keypair (twin of `SSH_ED25519_SK` in
/// `src/testutil.rs`).
const SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----";
const SSH_ED25519_PK: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";

const VAULT: &str = "test.murk";
const MERGE_HINT: &str = "murk setup-merge-driver";

/// Run git in `dir` with a fixed identity, no user or system config and no
/// commit signing. Returns whether it succeeded.
fn git(dir: &Path, args: &[&str]) -> bool {
    std::process::Command::new("git")
        .args(["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"])
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .expect("spawn git")
        .status
        .success()
}

fn git_ok(dir: &Path, args: &[&str]) {
    assert!(git(dir, args), "git {args:?} failed");
}

fn add(dir: &Path, key: &str, name: &str) {
    murk(dir, key)
        .args(["add", name, "--vault", VAULT])
        .write_stdin("v\n")
        .assert()
        .success();
}

/// The trusted-signer entry for `key` (`murk trust --print-key`).
fn signer_entry(dir: &Path, key: &str) -> String {
    let out = murk(dir, key)
        .args(["trust", "--print-key", "--vault", VAULT])
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// `murk verify --signature-only` in `dir`, with `HOME` at `home`, no key in
/// the environment (`murk_bin` strips `MURK_KEY` and `MURK_KEY_FILE`), and
/// `signers` as `MURK_TRUSTED_SIGNERS` when given.
fn check(dir: &Path, home: &Path, signers: Option<&str>) -> assert_cmd::assert::Assert {
    let mut cmd = murk_bin(home);
    cmd.current_dir(dir)
        .args(["verify", "--signature-only", "--vault", VAULT]);
    if let Some(signers) = signers {
        cmd.env("MURK_TRUSTED_SIGNERS", signers);
    }
    cmd.assert()
}

/// A git repo on `main` with a signed vault holding `A`, `M` and `Z`, and a
/// branch `feat` that adds `B`. When `both` is set, `main` then adds `Y`, so
/// the two branches change the vault in separate places. Returns the repo,
/// alice's key and her trusted-signer entry.
fn diverged(both: bool) -> (TempDir, String, String) {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    let entry = signer_entry(dir.path(), &key);
    for name in ["A", "M", "Z"] {
        add(dir.path(), &key, name);
    }
    git_ok(dir.path(), &["init", "-q"]);
    git_ok(dir.path(), &["add", VAULT]);
    git_ok(dir.path(), &["commit", "-qm", "base"]);
    git_ok(dir.path(), &["checkout", "-qb", "feat"]);
    add(dir.path(), &key, "B");
    git_ok(dir.path(), &["commit", "-qam", "feat"]);
    git_ok(dir.path(), &["checkout", "-q", "main"]);
    if both {
        add(dir.path(), &key, "Y");
        git_ok(dir.path(), &["commit", "-qam", "main"]);
    } else {
        fs::write(dir.path().join("README"), "x").unwrap();
        git_ok(dir.path(), &["add", "README"]);
        git_ok(dir.path(), &["commit", "-qm", "readme"]);
    }
    (dir, key, entry)
}

fn show(dir: &Path, rev: &str) -> Vec<u8> {
    let out = std::process::Command::new("git")
        .args(["show", &format!("{rev}:{VAULT}")])
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .output()
        .unwrap();
    assert!(out.status.success());
    out.stdout
}

/// Rewrite the vault's JSON in place.
fn edit_vault(dir: &Path, f: impl FnOnce(&mut serde_json::Value)) {
    let path = dir.join(VAULT);
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    f(&mut v);
    fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

#[test]
fn branch_only_change_by_a_trusted_signer_passes_without_a_key() {
    let (dir, _, entry) = diverged(false);
    git_ok(dir.path(), &["merge", "-q", "--no-ff", "feat", "-m", "merge"]);
    assert_eq!(fs::read(dir.path().join(VAULT)).unwrap(), show(dir.path(), "feat"));

    // A CI runner: an empty HOME, so no stored key and no trust pin.
    let home = TempDir::new().unwrap();
    check(dir.path(), home.path(), Some(&entry))
        .success()
        .stderr(predicate::str::contains(
            "ok signature verified by trusted signer age1",
        ))
        .stdout(predicate::str::is_empty());
    assert!(!home.path().join(".config/murk").exists());

    // Plain verify on the same runner needs a key, as before.
    murk_bin(home.path())
        .current_dir(dir.path())
        .env("MURK_TRUSTED_SIGNERS", &entry)
        .args(["verify", "--vault", VAULT])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("MURK_KEY not set"));
}

/// A text merge that takes one side's hunks where both changed and the other
/// side's elsewhere yields a vault equal to neither side, and its signature
/// does not verify.
#[test]
fn strategy_option_text_merges_fail_with_the_merge_hint() {
    for side in ["ours", "theirs"] {
        let (dir, _, entry) = diverged(true);
        git_ok(
            dir.path(),
            &["merge", "-q", "-X", side, "feat", "-m", "merge"],
        );
        let merged = fs::read(dir.path().join(VAULT)).unwrap();
        assert_ne!(merged, show(dir.path(), "HEAD^1"), "-X {side}");
        assert_ne!(merged, show(dir.path(), "feat"), "-X {side}");

        let home = TempDir::new().unwrap();
        check(dir.path(), home.path(), Some(&entry))
            .code(1)
            .stderr(predicate::str::contains("signature does not verify"))
            .stderr(predicate::str::contains(MERGE_HINT));
    }
}

#[test]
fn union_merge_fails_as_a_parse_error_with_the_merge_hint() {
    let (dir, _, entry) = diverged(true);
    fs::write(
        dir.path().join(".git/info/attributes"),
        format!("{VAULT} merge=union\n"),
    )
    .unwrap();
    git_ok(dir.path(), &["merge", "-q", "feat", "-m", "merge"]);

    let home = TempDir::new().unwrap();
    check(dir.path(), home.path(), Some(&entry))
        .code(1)
        .stderr(predicate::str::contains("vault parse error"))
        .stderr(predicate::str::contains(MERGE_HINT));
}

#[test]
fn unsigned_untrusted_and_unset_signers_fail_with_their_reason() {
    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(dir.path(), &key, "A");
    let entry = signer_entry(dir.path(), &key);
    let home = TempDir::new().unwrap();

    check(dir.path(), home.path(), None)
        .code(1)
        .stderr(predicate::str::contains("MURK_TRUSTED_SIGNERS is not set"));

    check(dir.path(), home.path(), Some(SSH_ED25519_PK))
        .code(1)
        .stderr(predicate::str::contains(
            "which is not in MURK_TRUSTED_SIGNERS",
        ));

    edit_vault(dir.path(), |v| {
        v.as_object_mut().unwrap().remove("sig");
    });
    check(dir.path(), home.path(), Some(&entry))
        .code(1)
        .stderr(predicate::str::contains("vault test.murk is unsigned"));

    // A 2.x vault keeps its signature in the encrypted meta.
    edit_vault(dir.path(), |v| v["version"] = "2.0".into());
    check(dir.path(), home.path(), Some(&entry))
        .code(1)
        .stderr(predicate::str::contains(
            "a check without a key cannot verify it",
        ));
}

#[cfg(unix)]
#[test]
fn ssh_and_age_signers_both_verify() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (alice_key, _) = init_vault(&dir);
    let alice = signer_entry(dir.path(), &alice_key);
    murk(&dir, &alice_key)
        .args(["circle", "authorize", SSH_ED25519_PK, "--name", "bob", "--vault", VAULT])
        .assert()
        .success();
    let signers = format!("{alice},{SSH_ED25519_PK}");
    let home = TempDir::new().unwrap();

    check(dir.path(), home.path(), Some(&signers))
        .success()
        .stderr(predicate::str::contains("trusted signer age1"));

    let bob_key_file = dir.path().join("bob_ed25519");
    fs::write(&bob_key_file, SSH_ED25519_SK).unwrap();
    fs::set_permissions(&bob_key_file, fs::Permissions::from_mode(0o600)).unwrap();
    murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &bob_key_file)
        .args(["add", "TOKEN", "--vault", VAULT])
        .write_stdin("v\n")
        .assert()
        .success();

    check(dir.path(), home.path(), Some(&signers))
        .success()
        .stderr(predicate::str::contains("trusted signer AAAAC3Nz"));
    // Only alice trusted: bob's write is refused.
    check(dir.path(), home.path(), Some(&alice))
        .code(1)
        .stderr(predicate::str::contains("which is not in MURK_TRUSTED_SIGNERS"));
}

/// The vault's own stored key sits in HOME, but murk config there is
/// unreadable: plain verify fails on it, the keyless check never opens it.
#[cfg(unix)]
#[test]
fn stored_key_in_home_is_never_read() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    add(dir.path(), &key, "A");
    let entry = signer_entry(dir.path(), &key);

    // HOME is `dir`: the stored key is found with no key in the environment.
    murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["verify", "--vault", VAULT])
        .assert()
        .success();

    let config = dir.path().join(".config/murk");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o000)).unwrap();
    let plain = murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["verify", "--vault", VAULT])
        .output()
        .unwrap();
    let keyless = check(dir.path(), dir.path(), Some(&entry)).get_output().clone();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(plain.status.code(), Some(1), "plain verify must need the key");
    assert!(
        keyless.status.success(),
        "{}",
        String::from_utf8_lossy(&keyless.stderr)
    );
}
