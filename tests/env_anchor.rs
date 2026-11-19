// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A load anchored by `MURK_TRUSTED_SIGNERS` on a machine that has a trust
//! pin only narrows the pin. The variable names signers for this one process;
//! what outlives it, the pin, must not learn to trust them: a later load
//! without the variable judges the vault as if the variable had never been
//! set, and the fields that widen what the machine accepts are left alone.
//!
//! Each row builds a revision signed by carol, who the pin does not trust,
//! loads it on alice's pinned machine with carol's signer entry in the
//! variable, and compares the pin before and after.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Output;

use common::cast::Who;
use common::machines::copy_dir;
use common::{init_vault, murk_bin};
use serde_json::Value;
use tempfile::TempDir;

const VAULT: &str = "test.murk";

/// A vault written by murk 0.13.0, recipients alice and bob, and alice's key
/// (the file starts with a `#` comment line).
const V0_13_VAULT: &str = include_str!("fixtures/v0_13_rollback_leaked.murk");
const V0_13_ALICE_KEY: &str = include_str!("fixtures/v0_13_rollback_alice.test-only.key");

/// Pin fields an environment-anchored load may change: they only narrow what
/// the machine accepts later (counters, the fingerprint at the mark, keys seen
/// as grants, "was signed", a vault id that was empty), and the lineage
/// sidecar's marks.
const MAY_CHANGE: &[&str] = &[
    "generation",
    "head",
    "branches",
    "branch_heads",
    "grants",
    "was_signed",
    "vault_id",
    "revoked_grants_seen",
    "lineage_head",
    "lineage_heads",
];

/// `murk` with key `secret` on the machine whose `HOME` is `home`, in `work`,
/// with `env` on top.
fn murk_cmd(home: &Path, work: &Path, secret: &str, env: &[(&str, &str)]) -> assert_cmd::Command {
    let mut cmd = murk_bin(home);
    cmd.current_dir(work)
        .env("MURK_KEY", secret)
        .env("MURK_VAULT", VAULT);
    for (name, value) in env {
        cmd.env(name, value);
    }
    cmd
}

fn run(home: &Path, work: &Path, secret: &str, env: &[(&str, &str)], args: &[&str]) -> Output {
    murk_cmd(home, work, secret, env)
        .args(args)
        .output()
        .unwrap()
}

/// `run` with `value` and a newline on stdin.
fn run_with_stdin(
    home: &Path,
    work: &Path,
    secret: &str,
    env: &[(&str, &str)],
    args: &[&str],
    value: &str,
) -> Output {
    murk_cmd(home, work, secret, env)
        .args(args)
        .write_stdin(format!("{value}\n"))
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Run a command that must succeed.
fn must(out: Output, what: &str) -> Result<Output, String> {
    if out.status.success() {
        Ok(out)
    } else {
        Err(format!("{what}: {}", text(&out.stderr)))
    }
}

/// The signer entry `murk trust --print-key` prints for `secret`.
fn signer_entry(home: &Path, work: &Path, secret: &str) -> Result<String, String> {
    let out = must(
        run(home, work, secret, &[], &["trust", "--print-key"]),
        "trust --print-key",
    )?;
    text(&out.stdout)
        .lines()
        .next()
        .map(str::to_string)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| "no signer entry".to_string())
}

/// One command of a scripted history: who runs it (their secret key), the
/// arguments, and the value on stdin.
type Step<'a> = (&'a str, &'a [&'a str], &'a str);

/// The vault `base` after `steps`, run one after another on a scratch machine
/// of their own (a fresh `HOME`, so no pin of the real machine is touched),
/// anchored by `signers` for the first load.
fn history(
    root: &Path,
    tag: &str,
    base: &[u8],
    signers: &str,
    steps: &[Step<'_>],
) -> Result<Vec<u8>, String> {
    let home = root.join(format!("{tag}-home"));
    let work = root.join(format!("{tag}-work"));
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&work).unwrap();
    write_vault(&work.join(VAULT), base);
    for (secret, args, stdin) in steps {
        must(
            run_with_stdin(
                &home,
                &work,
                secret,
                &[("MURK_TRUSTED_SIGNERS", signers)],
                args,
                stdin,
            ),
            &format!("{tag}: murk {args:?}"),
        )?;
    }
    Ok(fs::read(work.join(VAULT)).unwrap())
}

/// Write a vault file as git would check it out: not group-writable, whatever
/// the test process's umask.
fn write_vault(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

/// Every pin file under `home` (lock files aside), parsed, by file name.
fn pins(home: &Path) -> BTreeMap<String, Value> {
    let dir = home.join(".config/murk/signer-pins");
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                .map(|e| {
                    let json = serde_json::from_slice(&fs::read(e.path()).unwrap())
                        .expect("a pin file is JSON");
                    (e.file_name().to_string_lossy().into_owned(), json)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What differs between two pin snapshots outside [`MAY_CHANGE`], as
/// `file: field`. A file that appears or vanishes is a difference.
fn pin_changes(before: &BTreeMap<String, Value>, after: &BTreeMap<String, Value>) -> Vec<String> {
    let mut changes = Vec::new();
    for name in before.keys().chain(after.keys()).collect::<Vec<_>>() {
        let (Some(was), Some(now)) = (before.get(name), after.get(name)) else {
            changes.push(format!("{name}: appeared or vanished"));
            continue;
        };
        let empty = serde_json::Map::new();
        let (was, now) = (
            was.as_object().unwrap_or(&empty),
            now.as_object().unwrap_or(&empty),
        );
        for field in was.keys().chain(now.keys()).collect::<Vec<_>>() {
            if !MAY_CHANGE.contains(&field.as_str()) && was.get(field) != now.get(field) {
                changes.push(format!("{name}: {field}"));
            }
        }
    }
    changes.sort();
    changes.dedup();
    changes
}

/// The major number of the header version of the vault file `bytes`.
fn header_major(bytes: &[u8]) -> Option<u64> {
    let vault: Value = serde_json::from_slice(bytes).ok()?;
    vault["version"].as_str()?.split('.').next()?.parse().ok()
}

fn generation(bytes: &[u8]) -> u64 {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v["generation"].as_u64())
        .unwrap_or(0)
}

/// Alice's machine: `HOME` and the vault's directory are `dir`, where she ran
/// `murk init` and saved once, so her pin trusts her alone. Returns her key,
/// her signer entry, and the vault's bytes.
fn alice_machine(dir: &Path) -> Result<(String, String, Vec<u8>), String> {
    let (secret, _) = init_vault(dir);
    must(
        run_with_stdin(dir, dir, &secret, &[], &["add", "K1", "--desc", "d"], "k1"),
        "alice adds K1",
    )?;
    let entry = signer_entry(dir, dir, &secret)?;
    Ok((secret, entry, fs::read(dir.join(VAULT)).unwrap()))
}

/// A load of key `key` as the holder of `secret` on the machine whose `HOME`
/// is `home`, from the vault in `work`, with `env`.
fn load(home: &Path, work: &Path, secret: &str, env: &[(&str, &str)], key: &str) -> Output {
    run(home, work, secret, env, &["get", key])
}

/// The environment loads a vault signed by carol, whom alice's pin does not
/// trust, without widening the pin: the load prints the value, and a plain
/// load of the same vault afterwards is refused. The pin differs from before
/// only in the fields an environment-anchored load may change.
#[test]
fn row_r_i4_a() {
    common::rows::check("R-I4-a", |p| {
        let root = TempDir::new().unwrap();
        let alice_dir = root.path().join("alice");
        fs::create_dir_all(&alice_dir).unwrap();
        let (alice, alice_entry, a1) = alice_machine(&alice_dir)?;
        let carol = Who::generate("carol");
        let c1 = history(
            root.path(),
            "carol",
            &a1,
            &alice_entry,
            &[
                (
                    &alice,
                    &["circle", "authorize", &carol.pubkey, "--name", "carol"],
                    "",
                ),
                (&carol.secret, &["add", "S2", "--desc", "d"], "carol-s2"),
            ],
        )?;
        let carol_entry = signer_entry(root.path(), &alice_dir, &carol.secret)?;
        write_vault(&alice_dir.join(VAULT), &c1);

        // Control: alice's pin does not trust carol, so without the variable
        // her revision is refused.
        let pin_before = pins(&alice_dir);
        let plain = load(&alice_dir, &alice_dir, &alice, &[], "S2");
        p.require(
            !plain.status.success()
                && text(&plain.stderr).contains("not a trusted signer")
                && !text(&plain.stdout).contains("carol-s2"),
            format!(
                "alice's machine refuses carol's revision without the variable: {}",
                text(&plain.stderr)
            ),
        )?;
        p.require(
            pins(&alice_dir) == pin_before,
            "a refused load leaves the pin alone",
        )?;

        // Control: with carol named in the variable the load prints the value.
        let env = load(
            &alice_dir,
            &alice_dir,
            &alice,
            &[("MURK_TRUSTED_SIGNERS", &carol_entry)],
            "S2",
        );
        p.require(
            env.status.success() && text(&env.stdout).contains("carol-s2"),
            format!(
                "the environment-anchored load prints carol's value: {}",
                text(&env.stderr)
            ),
        )?;
        let pin_after_env = pins(&alice_dir);
        p.require(
            pin_after_env != pin_before,
            "the load advanced the pin's counters (so the comparison below sees a write)",
        )?;

        // Decisive: the same vault, without the variable.
        let again = load(&alice_dir, &alice_dir, &alice, &[], "S2");
        p.reached();
        p.note(text(&again.stderr));
        p.target(
            !again.status.success()
                && text(&again.stderr).contains("not a trusted signer")
                && !text(&again.stdout).contains("carol-s2"),
            "a later load without the variable still refuses carol, and prints no value",
        );
        let widened = pin_changes(&pin_before, &pin_after_env);
        p.note(format!(
            "pin fields changed outside the allowed list: {widened:?}"
        ));
        p.target(
            widened.is_empty(),
            "the pin changed only in the fields an environment-anchored load may change",
        );
        p.target(
            pin_after_env.values().all(|pin| {
                !pin["trusted"]
                    .as_array()
                    .is_some_and(|t| t.iter().any(|k| k.as_str() == Some(carol.pubkey.as_str())))
            }),
            "carol is not among the pin's trusted signers",
        );
        Ok(())
    });
}

/// An accepted murk 0.13 copy of the vault, recorded in the pin by
/// `murk trust`, survives an environment-anchored load of a newer revision
/// carol signed: that load must not drop or change which copy may be
/// written. Today the load removes the record.
#[test]
fn row_r_i4_a_pre_upgrade() {
    common::rows::check("R-I4-a:pre-upgrade", |p| {
        let root = TempDir::new().unwrap();
        let alice = V0_13_ALICE_KEY
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .expect("the fixture key")
            .trim()
            .to_string();
        let carol = Who::generate("carol");
        let machine = root.path().join("machine");
        let work = root.path().join("machine-work");
        fs::create_dir_all(&machine).unwrap();
        fs::create_dir_all(&work).unwrap();

        // Alice's machine accepts the 0.13 copy with `murk trust`.
        write_vault(&work.join(VAULT), V0_13_VAULT.as_bytes());
        must(
            run(&machine, &work, &alice, &[], &["trust", "--yes"]),
            "alice trusts the 0.13 copy",
        )?;
        let accepted = pins(&machine);
        p.require(
            accepted
                .values()
                .any(|pin| pin["accepted_pre_upgrade"].get("").is_some()),
            "murk trust recorded the accepted 0.13 copy in the pin",
        )?;
        let alice_entry = signer_entry(&machine, &work, &alice)?;

        // Another machine upgrades the copy: alice authorizes carol, and carol
        // saves, so the newest revision is carol's, in the current format.
        let c = history(
            root.path(),
            "carol",
            V0_13_VAULT.as_bytes(),
            &alice_entry,
            &[
                (&alice, &["trust", "--yes"], ""),
                (
                    &alice,
                    &["circle", "authorize", &carol.pubkey, "--name", "carol"],
                    "",
                ),
                (&carol.secret, &["add", "S2", "--desc", "d"], "carol-s2"),
            ],
        )?;
        let carol_entry = signer_entry(root.path(), &work, &carol.secret)?;
        write_vault(&work.join(VAULT), &c);
        let plain = load(&machine, &work, &alice, &[], "S2");
        p.require(
            !plain.status.success() && text(&plain.stderr).contains("not a trusted signer"),
            format!(
                "alice's machine refuses carol's revision without the variable: {}",
                text(&plain.stderr)
            ),
        )?;

        // Decisive: the environment-anchored load of carol's revision.
        let before = pins(&machine);
        let env = load(
            &machine,
            &work,
            &alice,
            &[("MURK_TRUSTED_SIGNERS", &carol_entry)],
            "S2",
        );
        p.require(
            env.status.success() && text(&env.stdout).contains("carol-s2"),
            format!(
                "the environment-anchored load prints carol's value: {}",
                text(&env.stderr)
            ),
        )?;
        p.reached();
        let after = pins(&machine);
        let changed = pin_changes(&before, &after);
        p.note(format!(
            "pin fields changed outside the allowed list: {changed:?}"
        ));
        let record = |pins: &BTreeMap<String, Value>| {
            pins.values()
                .map(|pin| pin["accepted_pre_upgrade"].clone())
                .collect::<Vec<_>>()
        };
        p.target(
            record(&before) == record(&after),
            "the accepted 0.13 copy is recorded exactly as before",
        );
        p.target(
            changed.is_empty(),
            "the pin changed only in the fields an environment-anchored load may change",
        );
        p.today(
            record(&before).iter().all(|r| r.get("").is_some())
                && record(&after).iter().all(|r| r.is_null()),
            "the load removes the record of the accepted 0.13 copy",
        );
        Ok(())
    });
}

/// With lineage, an environment-anchored load never moves the lineage
/// reference to a revision of a signer the pin does not trust. Alice's pin
/// holds her revision A1 as the reference. The environment loads carol's
/// revision, which descends from it. Alice then saves on from A1 elsewhere,
/// to a revision with a higher counter than carol's that does not descend
/// from carol's, and the pinned machine accepts it. Needs format 4.
#[test]
fn row_r_i4_a_lineage() {
    common::rows::check("R-I4-a:lineage", |p| {
        let root = TempDir::new().unwrap();
        let alice_dir = root.path().join("alice");
        fs::create_dir_all(&alice_dir).unwrap();
        let (alice, alice_entry, a1) = alice_machine(&alice_dir)?;
        let carol = Who::generate("carol");
        let c1 = history(
            root.path(),
            "carol",
            &a1,
            &alice_entry,
            &[
                (
                    &alice,
                    &["circle", "authorize", &carol.pubkey, "--name", "carol"],
                    "",
                ),
                (&carol.secret, &["add", "S2", "--desc", "d"], "carol-s2"),
            ],
        )?;
        let a2 = history(
            root.path(),
            "alice-on",
            &a1,
            &alice_entry,
            &[
                (&alice, &["add", "K3", "--desc", "d"], "k3-one"),
                (&alice, &["add", "K3", "--desc", "d"], "k3-two"),
                (&alice, &["add", "K3", "--desc", "d"], "k3-three"),
            ],
        )?;
        let carol_entry = signer_entry(root.path(), &alice_dir, &carol.secret)?;
        p.require(
            generation(&a2) > generation(&c1),
            "alice's revision has a higher counter than carol's",
        )?;
        // A format-4 vault records its lineage in the signed header. Until
        // murk writes it, the scenario cannot be built.
        p.require(
            header_major(&a1) == Some(4)
                && header_major(&c1) == Some(4)
                && header_major(&a2) == Some(4),
            format!(
                "format 4 vaults (header versions: {:?}, {:?}, {:?})",
                header_major(&a1),
                header_major(&c1),
                header_major(&a2)
            ),
        )?;

        // Control: without the environment load, alice's pinned machine
        // accepts her own descendant of A1.
        let spare = root.path().join("spare");
        copy_dir(&alice_dir.join(".config"), &spare.join(".config"));
        write_vault(&alice_dir.join(VAULT), &a2);
        let control = load(&spare, &alice_dir, &alice, &[], "K3");
        p.require(
            control.status.success() && text(&control.stdout).contains("k3-three"),
            format!(
                "a machine that never loaded carol's revision accepts alice's: {}",
                text(&control.stderr)
            ),
        )?;

        // The environment loads carol's revision, which descends from A1.
        write_vault(&alice_dir.join(VAULT), &c1);
        let before = pins(&alice_dir);
        let env = load(
            &alice_dir,
            &alice_dir,
            &alice,
            &[("MURK_TRUSTED_SIGNERS", &carol_entry)],
            "S2",
        );
        p.require(
            env.status.success() && text(&env.stdout).contains("carol-s2"),
            format!("the environment-anchored load: {}", text(&env.stderr)),
        )?;

        // Decisive: alice's revision, which does not descend from carol's.
        write_vault(&alice_dir.join(VAULT), &a2);
        let after_env = pins(&alice_dir);
        let accepted = load(&alice_dir, &alice_dir, &alice, &[], "K3");
        p.reached();
        p.note(text(&accepted.stderr));
        p.target(
            accepted.status.success() && text(&accepted.stdout).contains("k3-three"),
            "alice's revision is accepted: the reference did not move to carol's",
        );
        let changed = pin_changes(&before, &after_env);
        p.target(
            changed.is_empty(),
            "the pin and its sidecar changed only in the fields an environment-anchored load may change",
        );
        Ok(())
    });
}
