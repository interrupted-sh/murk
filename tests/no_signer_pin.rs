// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `MURK_NO_SIGNER_PIN`: the switch that keeps murk from writing a trust pin
//! (a read-only home, an ephemeral runner) must not also switch off the
//! rollback check of a pin that already exists.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Output;

use common::{init_vault, murk};

const VAULT: &str = "test.murk";

/// `murk` as the key holder in `dir` (also its `HOME`), with `env` set on top.
fn run(dir: &Path, key: &str, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = murk(dir, key);
    cmd.env("MURK_VAULT", VAULT);
    for (name, value) in env {
        cmd.env(name, value);
    }
    cmd.args(args).output().unwrap()
}

/// Every file of the trust pin directory under `home` (lock files aside), by
/// name, with its bytes.
fn pin_files(home: &Path) -> BTreeMap<String, Vec<u8>> {
    let dir = home.join(".config/murk/signer-pins");
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().extension().is_none_or(|x| x != "lock"))
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        fs::read(e.path()).unwrap(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A machine with a trust pin refuses a rolled-back vault even when
/// `MURK_NO_SIGNER_PIN` and `MURK_TRUSTED_SIGNERS` are both set, and leaves
/// the pin untouched. The rolled-back file is the vault as it was one write
/// ago; the same file without the variable is refused as rolled back.
#[test]
fn row_r_i24_a() {
    common::rows::check("R-I24-a", |p| {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let (key, _) = init_vault(dir);
        let vault = dir.join(VAULT);
        let add = |value: &str| {
            let out = murk(dir, &key)
                .env("MURK_VAULT", VAULT)
                .args(["add", "API", "--desc", "d"])
                .write_stdin(format!("{value}\n"))
                .output()
                .unwrap();
            assert!(out.status.success(), "add API: {}", stderr(&out));
        };
        add("old-api-value");
        let rolled_back = fs::read(&vault).unwrap();
        add("new-api-value");
        let newer = fs::read(&vault).unwrap();

        let print_key = run(dir, &key, &[], &["trust", "--print-key"]);
        p.require(print_key.status.success(), "murk trust --print-key")?;
        let entry = stdout(&print_key).lines().next().unwrap_or("").to_string();
        p.require(!entry.is_empty(), "a signer entry to name in the variable")?;

        // Control: the current file loads, and the pin records its counter.
        let current = run(dir, &key, &[], &["get", "API"]);
        p.require(
            current.status.success() && stdout(&current).contains("new-api-value"),
            "the pinned machine loads its own current vault",
        )?;
        let pin = pin_files(dir);
        p.require(!pin.is_empty(), "this machine wrote a trust pin")?;

        // Control: without the variable the rolled-back file is refused.
        fs::write(&vault, &rolled_back).unwrap();
        let plain = run(dir, &key, &[], &["get", "API"]);
        p.require(
            !plain.status.success()
                && stderr(&plain).contains("rolled back")
                && !stdout(&plain).contains("old-api-value"),
            format!(
                "a pinned machine refuses a rolled-back vault: {}",
                stderr(&plain)
            ),
        )?;
        p.require(pin_files(dir) == pin, "a refused load leaves the pin alone")?;

        // Decisive: the same file with the variable that turns the pin off.
        let off = run(
            dir,
            &key,
            &[
                ("MURK_NO_SIGNER_PIN", "1"),
                ("MURK_TRUSTED_SIGNERS", &entry),
            ],
            &["get", "API"],
        );
        p.reached();
        p.note(format!(
            "MURK_NO_SIGNER_PIN=1 + MURK_TRUSTED_SIGNERS: exit {:?}, stdout {:?}, stderr {:?}",
            off.status.code(),
            stdout(&off).trim(),
            stderr(&off).trim()
        ));
        p.target(
            !off.status.success() && stderr(&off).contains("rolled back"),
            "an existing pin still refuses the rolled-back vault as rolled back",
        );
        p.target(
            !stdout(&off).contains("old-api-value"),
            "the rolled-back value is not printed",
        );
        p.target(
            pin_files(dir) == pin,
            "the pin file is left exactly as it was",
        );
        p.today(
            off.status.success() && stdout(&off).contains("old-api-value"),
            "the variable switches the rollback check off and the old value prints",
        );
        p.today(
            pin_files(dir) == pin,
            "the pin file is not written by that load either",
        );

        // The current file still loads under the variable (it only writes no
        // pin), so a refusal above is about the rollback, not the variable.
        fs::write(&vault, &newer).unwrap();
        let back = run(
            dir,
            &key,
            &[
                ("MURK_NO_SIGNER_PIN", "1"),
                ("MURK_TRUSTED_SIGNERS", &entry),
            ],
            &["get", "API"],
        );
        p.require(
            back.status.success() && stdout(&back).contains("new-api-value"),
            format!(
                "the current vault loads under MURK_NO_SIGNER_PIN: {}",
                stderr(&back)
            ),
        )?;
        Ok(())
    });
}
