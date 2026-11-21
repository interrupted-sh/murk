// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Invariant rows for vault format 4 (the `prev` lineage list, signed view 3,
//! MAC `blake3v9:`) and the lineage sidecar that sits next to the trust pin.
//! `tests/invariant_rows.tsv` holds each row's state.
//!
//! None of that exists yet, so the rows that need it are `pending`: each
//! asserts the target behaviour, and requires a format-4 vault (or the
//! sidecar) before its decisive step, so it reports "did not reach" until the
//! feature is built and never passes without making its attack. R-L-compat
//! holds today: a vault from a newer format is refused as newer.
//!
//! A format-4 vault is edited by hand with three helpers built on murk's
//! public API: a JSON value that keeps the file's key order (the signed
//! message is the file in that order), a re-MAC that takes the MAC a load
//! expects from its own integrity error, and a re-sign with the signer's key.
//! An edit sealed that way leaves only the gate under test between the file
//! and an accepted load. Loads run without a pin (a fresh `HOME`,
//! `MURK_NO_SIGNER_PIN`, `MURK_TRUSTED_SIGNERS`), so a re-signed copy of the
//! same generation is never refused as a fork. The format-3 control is a
//! checked-in vault, because a build that writes format 4 cannot make one.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use base64::Engine;
use common::rows::Probe;
use common::{FOREIGN_PK, init_vault, murk, murk_bin};
use murk_cli::crypto::{MurkIdentity, parse_identity, parse_recipient};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tempfile::TempDir;

const VAULT: &str = "test.murk";
const TOKEN: &str = "TOKEN";
/// TOKEN's value in the vaults this file builds.
const VALUE: &str = "token-value-6d1f93";

/// A vault written by a murk 0.15.2 build: header `3.0`, signed view 2,
/// recipient alice only, one secret `TOKEN` (`fixture-token-value-4711`).
const FORMAT3_VAULT: &str = include_str!("fixtures/v0_15_format3_compat.murk");
const FORMAT3_KEY: &str = include_str!("fixtures/v0_15_format3_compat.test-only.key");
const FORMAT3_VALUE: &str = "fixture-token-value-4711";

/// A real unencrypted ssh-ed25519 keypair (test-only; twin of the constants in
/// `tests/authenticity.rs`).
const SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\nagAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\nAAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n-----END OPENSSH PRIVATE KEY-----\n";
const SSH_ED25519_PK: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN";

// ── a JSON value that keeps the file's key order ──

/// A parsed vault file. Objects keep their keys in file order: murk writes
/// the struct's field order, and the signed message is the file in that order,
/// so re-serializing must not sort anything.
#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(serde_json::Number),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Serialize for Json {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Json::Null => s.serialize_unit(),
            Json::Bool(b) => s.serialize_bool(*b),
            Json::Num(n) => n.serialize(s),
            Json::Str(t) => s.serialize_str(t),
            Json::Arr(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Json::Obj(fields) => {
                let mut map = s.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = Json;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
                Ok(Json::Null)
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> Result<Json, E> {
                Ok(Json::Bool(b))
            }
            fn visit_i64<E: de::Error>(self, n: i64) -> Result<Json, E> {
                Ok(Json::Num(n.into()))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Json, E> {
                Ok(Json::Num(n.into()))
            }
            fn visit_f64<E: de::Error>(self, n: f64) -> Result<Json, E> {
                serde_json::Number::from_f64(n)
                    .map(Json::Num)
                    .ok_or_else(|| E::custom("not a finite number"))
            }
            fn visit_str<E: de::Error>(self, t: &str) -> Result<Json, E> {
                Ok(Json::Str(t.to_string()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Json::Arr(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry::<String, Json>()? {
                    fields.push(entry);
                }
                Ok(Json::Obj(fields))
            }
        }
        d.deserialize_any(Any)
    }
}

impl Json {
    fn num(n: u64) -> Json {
        Json::Num(n.into())
    }

    fn text(s: &str) -> Json {
        Json::Str(s.to_string())
    }

    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        match self {
            Json::Obj(fields) => fields.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value at `path`, which must exist.
    fn at(&mut self, path: &[&str]) -> &mut Json {
        let mut node = self;
        for key in path {
            node = node
                .get_mut(key)
                .unwrap_or_else(|| panic!("no {key:?} on the way down {path:?}"));
        }
        node
    }

    fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    fn u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => n.as_u64(),
            _ => None,
        }
    }

    /// Replace `key` where it is, or add it at the end.
    fn set(&mut self, key: &str, value: Json) {
        let Json::Obj(fields) = self else {
            panic!("set {key:?} on something that is not an object")
        };
        match fields.iter_mut().find(|(k, _)| k == key) {
            Some((_, slot)) => *slot = value,
            None => fields.push((key.to_string(), value)),
        }
    }

    /// Add `key` right after `after` (at the end when `after` is absent).
    fn insert_after(&mut self, after: &str, key: &str, value: Json) {
        let Json::Obj(fields) = self else {
            panic!("insert {key:?} into something that is not an object")
        };
        let at = fields
            .iter()
            .position(|(k, _)| k == after)
            .map_or(fields.len(), |i| i + 1);
        fields.insert(at, (key.to_string(), value));
    }

    fn remove(&mut self, key: &str) {
        if let Json::Obj(fields) = self {
            fields.retain(|(k, _)| k != key);
        }
    }

    fn compact(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialize JSON")
    }
}

// ── reading and sealing a vault ──

fn parse(bytes: &[u8]) -> Json {
    serde_json::from_slice(bytes).expect("a vault is JSON")
}

fn header_version(vault: &Json) -> String {
    vault
        .get("version")
        .and_then(Json::str)
        .expect("a version")
        .to_string()
}

fn major(vault: &Json) -> u32 {
    header_version(vault)
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .expect("a numeric major version")
}

fn generation(vault: &Json) -> u64 {
    vault
        .get("generation")
        .and_then(Json::u64)
        .expect("a generation")
}

/// The signed view the vault's own signature names.
fn view_of(vault: &Json) -> u32 {
    let view = vault
        .get("sig")
        .and_then(|s| s.get("v"))
        .and_then(Json::u64)
        .expect("a signature view");
    u32::try_from(view).expect("a small view number")
}

fn prev(vault: &Json) -> Vec<String> {
    match vault.get("prev") {
        Some(Json::Arr(items)) => items
            .iter()
            .map(|e| e.str().expect("a prev entry is text").to_string())
            .collect(),
        _ => Vec::new(),
    }
}

fn set_prev(vault: &mut Json, entries: &[String]) {
    let list = entries.iter().map(|e| Json::text(e)).collect();
    vault.set("prev", Json::Arr(list));
}

/// A lineage entry: `<generation>:<fp>`.
fn entry(generation: u64, fp: &str) -> String {
    format!("{generation}:{fp}")
}

fn split_entry(e: &str) -> (u64, &str) {
    let (generation, fp) = e.split_once(':').expect("a <generation>:<fp> entry");
    (generation.parse().expect("a decimal generation"), fp)
}

/// The same fp with its last digit changed, still 32 lowercase hex.
fn other_fp(fp: &str) -> String {
    let (head, last) = fp.split_at(fp.len() - 1);
    format!("{head}{}", if last == "0" { "1" } else { "0" })
}

/// `vault_fingerprint`: what identifies a signed revision.
fn fp(vault: &Json) -> String {
    let typed: murk_cli::types::Vault =
        serde_json::from_slice(&vault.compact()).expect("a vault header");
    murk_cli::trust::vault_fingerprint(&typed)
}

/// The message a signature covers: the tag of its view, then the file in file
/// order without `sig`. View 2 is what a format-3 build computes, which has
/// no `prev`.
fn signed_message(vault: &Json, view: u32) -> Vec<u8> {
    let mut body = vault.clone();
    body.remove("sig");
    if view == 2 {
        body.remove("prev");
        body.remove("prev_floor");
    }
    let mut message = format!("murk.vault.sig.v{view}\n").into_bytes();
    message.extend(body.compact());
    message
}

/// Sign the vault as `id` in `view`, replacing `sig`.
fn resign(vault: &mut Json, id: &MurkIdentity, view: u32) {
    let sig = id
        .signing_key()
        .expect("an identity that signs")
        .sign(&signed_message(vault, view));
    let signer = id.pubkey_string().expect("a public key");
    vault.set(
        "sig",
        Json::Obj(vec![
            ("signer".into(), Json::Str(signer)),
            ("v".into(), Json::num(u64::from(view))),
            ("sig".into(), Json::Str(sig)),
        ]),
    );
}

/// Decrypt the meta, change it and encrypt it back to the recipients murk
/// writes it to (every header recipient but an agent grant). The MAC inside
/// it stays as it was.
fn edit_meta(vault: &mut Json, id: &MurkIdentity, change: impl FnOnce(&mut Json)) {
    let blob = vault
        .get("meta")
        .and_then(Json::str)
        .expect("a meta blob")
        .to_string();
    let plain = murk_cli::decrypt_value(&blob, id).expect("the key reads the meta");
    let mut meta: Json = serde_json::from_slice(&plain).expect("the meta is JSON");
    change(&mut meta);
    let grants: Vec<String> = match meta.get("grants") {
        Some(Json::Obj(grants)) => grants
            .iter()
            .filter_map(|(_, g)| Some(g.get("pubkey")?.str()?.to_string()))
            .collect(),
        _ => Vec::new(),
    };
    let Some(Json::Arr(listed)) = vault.get("recipients") else {
        panic!("a recipient list")
    };
    let recipients: Vec<_> = listed
        .iter()
        .filter_map(Json::str)
        .filter(|r| !grants.iter().any(|g| g == r))
        .map(|r| parse_recipient(r).expect("a recipient"))
        .collect();
    let sealed = murk_cli::encrypt_value(&meta.compact(), &recipients).expect("encrypt the meta");
    vault.set("meta", Json::Str(sealed));
}

/// Decrypt the agent grant record in `agents`, change it and encrypt it back
/// to the grant's key alone, as murk writes it.
fn edit_agents(vault: &mut Json, grant: &MurkIdentity, change: impl FnOnce(&mut Json)) {
    let (pubkey, blob) = match vault.get("agents") {
        Some(Json::Obj(agents)) => agents
            .first()
            .map(|(k, b)| (k.clone(), b.str().expect("a blob").to_string()))
            .expect("one grant blob"),
        _ => panic!("the vault has no agent blobs"),
    };
    let plain = murk_cli::decrypt_value(&blob, grant).expect("the grant key reads its record");
    let mut record: Json = serde_json::from_slice(&plain).expect("the record is JSON");
    change(&mut record);
    let sealed = murk_cli::encrypt_value(
        &record.compact(),
        &[parse_recipient(&pubkey).expect("the grant's key")],
    )
    .expect("encrypt the record");
    vault.at(&["agents"]).set(&pubkey, Json::Str(sealed));
}

/// Put the MAC a load expects into the meta. The expected MAC is read from
/// the integrity error of a load, so it follows whichever scheme the build
/// uses. A vault whose MAC already verifies is left alone.
fn remac(vault: &mut Json, id: &MurkIdentity) {
    let typed: murk_cli::types::Vault =
        serde_json::from_slice(&vault.compact()).expect("a vault header");
    let Err(e) = murk_cli::decrypt_vault(&typed, id) else {
        return;
    };
    let text = e.to_string();
    let Some((_, rest)) = text.split_once("(expected ") else {
        // Not a MAC mismatch: the MAC is right and something else is not.
        return;
    };
    let expected = rest
        .split_once(", got ")
        .map(|(mac, _)| mac.to_string())
        .expect("a MAC mismatch names both MACs");
    edit_meta(vault, id, |meta| meta.set("mac", Json::Str(expected)));
}

/// Re-MAC, then re-sign: the edit stands as if a key holder had made it.
fn reseal(vault: &mut Json, id: &MurkIdentity, view: u32) {
    remac(vault, id);
    resign(vault, id, view);
}

// ── a vault on disk and loads of it ──

/// What a `get` of TOKEN did.
struct Load {
    ok: bool,
    out: String,
    err: String,
    value: String,
}

impl Load {
    /// The load succeeded and printed the secret.
    fn loaded(&self) -> bool {
        self.ok && self.out.contains(&self.value)
    }

    /// The load failed and the secret stayed out of the output.
    fn refused(&self) -> bool {
        !self.ok && !self.out.contains(&self.value)
    }

    /// The refusal names a stale MAC or signature rather than a format rule.
    fn seal_failure(&self) -> bool {
        self.err.contains("signature is invalid") || self.err.contains("(expected ")
    }

    fn summary(&self) -> String {
        let line = self
            .err
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("(no message)");
        line.chars().take(180).collect()
    }
}

enum Key {
    Age(String),
    File(PathBuf),
}

/// A vault in a directory of its own, written by one signer, and the means to
/// load it without a pin as that signer.
struct Fixture {
    label: &'static str,
    dir: TempDir,
    key: Key,
    /// The signer's `MURK_TRUSTED_SIGNERS` entry.
    entry: String,
    value: &'static str,
    /// The key file of the agent grant `bot`, when the vault has one.
    grant: Option<PathBuf>,
}

fn write_key_file(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn age_secret(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .expect("an age secret key")
        .to_string()
}

fn add(dir: &Path, secret: &str, name: &str, value: &str) {
    murk(dir, secret)
        .args(["add", name, "--vault", VAULT])
        .write_stdin(format!("{value}\n"))
        .assert()
        .success();
}

impl Fixture {
    /// A vault alice (an age key) wrote with four saves: TOKEN, OTHER, and
    /// when `grant` is set an agent grant `bot` that reads TOKEN. A format-4
    /// build gives it a `prev` of three entries.
    fn age(grant: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let (secret, _) = init_vault(dir.path());
        add(dir.path(), &secret, TOKEN, VALUE);
        add(dir.path(), &secret, "OTHER", "other-value");
        let grant = grant.then(|| {
            let key_file = dir.path().join("bot.key");
            murk(dir.path(), &secret)
                .args(["agent", "grant", "--name", "bot", "--only", TOKEN, "--out"])
                .arg(&key_file)
                .args(["--vault", VAULT])
                .assert()
                .success();
            key_file
        });
        Self::new("age", dir, Key::Age(secret), VALUE, grant)
    }

    /// A vault whose signer is an ssh-ed25519 key (bob, authorized by alice
    /// and the writer of the last two saves).
    fn ssh() -> Self {
        let dir = TempDir::new().unwrap();
        let (alice, _) = init_vault(dir.path());
        murk(dir.path(), &alice)
            .args(["circle", "authorize", SSH_ED25519_PK, "--name", "bob"])
            .args(["--vault", VAULT])
            .assert()
            .success();
        let key_file = dir.path().join("bob_ed25519");
        write_key_file(&key_file, SSH_ED25519_SK);
        for (name, value) in [(TOKEN, VALUE), ("OTHER", "other-value")] {
            murk_bin(dir.path())
                .current_dir(dir.path())
                .env("MURK_KEY_FILE", &key_file)
                .args(["add", name, "--vault", VAULT])
                .write_stdin(format!("{value}\n"))
                .assert()
                .success();
        }
        Self::new("ssh-ed25519", dir, Key::File(key_file), VALUE, None)
    }

    /// The checked-in format-3 vault, in a directory of its own.
    fn legacy() -> Self {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(VAULT), FORMAT3_VAULT).unwrap();
        let secret = age_secret(FORMAT3_KEY);
        Self::new(
            "format-3 fixture",
            dir,
            Key::Age(secret),
            FORMAT3_VALUE,
            None,
        )
    }

    fn new(
        label: &'static str,
        dir: TempDir,
        key: Key,
        value: &'static str,
        grant: Option<PathBuf>,
    ) -> Self {
        let mut fixture = Self {
            label,
            dir,
            key,
            entry: String::new(),
            value,
            grant,
        };
        let out = fixture
            .machine()
            .args(["trust", "--print-key", "--vault", VAULT])
            .output()
            .unwrap();
        assert!(out.status.success(), "murk trust --print-key: {out:?}");
        fixture.entry = String::from_utf8(out.stdout).unwrap().trim().to_string();
        fixture
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join(VAULT)
    }

    fn json(&self) -> Json {
        parse(&fs::read(self.path()).unwrap())
    }

    fn put(&self, vault: &Json) {
        let text = serde_json::to_string_pretty(vault).unwrap();
        fs::write(self.path(), format!("{text}\n")).unwrap();
    }

    fn identity(&self) -> MurkIdentity {
        let text = match &self.key {
            Key::Age(secret) => secret.clone(),
            Key::File(path) => fs::read_to_string(path).unwrap(),
        };
        parse_identity(&text).expect("a signing identity")
    }

    fn grant_identity(&self) -> MurkIdentity {
        let file = self.grant.as_ref().expect("a grant key file");
        parse_identity(&age_secret(&fs::read_to_string(file).unwrap())).expect("the grant's key")
    }

    /// `murk` as the signer, on the machine that wrote the vault (its `HOME`
    /// holds the signer's pin).
    fn machine(&self) -> Command {
        let mut cmd = murk_bin(self.dir.path());
        cmd.current_dir(self.dir.path());
        self.use_key(&mut cmd);
        cmd
    }

    fn use_key(&self, cmd: &mut Command) {
        match &self.key {
            Key::Age(secret) => cmd.env("MURK_KEY", secret),
            Key::File(path) => cmd.env("MURK_KEY_FILE", path),
        };
    }

    /// `murk` as a CI runner: an empty `HOME`, no pin written, trust only
    /// from the signer entry.
    fn pinless(&self) -> Command {
        let home = self.dir.path().join("pinless-home");
        fs::create_dir_all(&home).unwrap();
        let mut cmd = murk_bin(&home);
        cmd.current_dir(self.dir.path())
            .env("MURK_NO_SIGNER_PIN", "1")
            .env("MURK_TRUSTED_SIGNERS", &self.entry);
        self.use_key(&mut cmd);
        cmd
    }

    fn get(&self, mut cmd: Command) -> Load {
        let out = cmd.args(["get", TOKEN, "--vault", VAULT]).output().unwrap();
        Load {
            ok: out.status.success(),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
            value: self.value.to_string(),
        }
    }

    /// Load the vault as the signer, with no pin.
    fn load(&self) -> Load {
        self.get(self.pinless())
    }

    /// Load the vault with the agent grant's key, which anchors its trust in
    /// the key file.
    fn grant_load(&self) -> Load {
        let home = self.dir.path().join("pinless-home");
        fs::create_dir_all(&home).unwrap();
        let mut cmd = murk_bin(&home);
        cmd.current_dir(self.dir.path()).env(
            "MURK_KEY_FILE",
            self.grant.as_ref().expect("a grant key file"),
        );
        self.get(cmd)
    }

    /// Edit a copy of the vault, run `then` against it, and put the original
    /// back.
    fn with_edit<T>(&self, edit: impl FnOnce(&mut Json), then: impl FnOnce(&Self) -> T) -> T {
        let original = fs::read(self.path()).unwrap();
        let mut vault = parse(&original);
        edit(&mut vault);
        self.put(&vault);
        let result = then(self);
        fs::write(self.path(), original).unwrap();
        result
    }
}

/// One edit that must be refused. For an edit sealed so that only a format
/// rule stands in its way, also check the refusal does not come from a stale
/// MAC or signature.
fn refuse(p: &mut Probe, what: &str, load: &Load, by_a_format_rule: bool) {
    p.target(load.refused(), format!("{what} is refused"));
    if by_a_format_rule {
        p.target(
            load.refused() && !load.seal_failure(),
            format!("{what} is refused by a format rule, not by a stale MAC or signature"),
        );
    }
    p.note(format!("{what}: {}", load.summary()));
}

// ── the places an unknown field can sit ──

#[derive(Clone, Copy, Debug)]
enum Site {
    /// The header's top level.
    Top,
    /// The `sig` object.
    Sig,
    /// A schema entry, an object nested in the header.
    Schema,
    /// The decrypted meta's top level.
    Meta,
    /// A grant's entry in the meta, an object nested in the meta.
    MetaGrant,
    /// An agent grant's decrypted record.
    AgentsRecord,
    /// The `grant` object nested in that record.
    AgentsGrant,
}

const SITES_IN_ANY_VAULT: [Site; 4] = [Site::Top, Site::Sig, Site::Schema, Site::Meta];
const SITES_WITH_A_GRANT: [Site; 3] = [Site::MetaGrant, Site::AgentsRecord, Site::AgentsGrant];

/// Load a copy of the vault with `unknown_field` added at `site`. A field
/// outside what the MAC and the signature cover needs no sealing; the meta
/// and the agent blobs are ciphertext the signature covers, so their copies
/// are signed again (the blobs are in the MAC too).
fn load_with_unknown_field(fx: &Fixture, site: Site) -> Load {
    let id = fx.identity();
    let view = view_of(&fx.json());
    let extra = || Json::num(1);
    match site {
        Site::Top => fx.with_edit(|v| v.set("unknown_field", extra()), Fixture::load),
        Site::Sig => fx.with_edit(
            |v| v.at(&["sig"]).set("unknown_field", extra()),
            Fixture::load,
        ),
        Site::Schema => fx.with_edit(
            |v| v.at(&["schema", TOKEN]).set("unknown_field", extra()),
            Fixture::load,
        ),
        Site::Meta => fx.with_edit(
            |v| {
                edit_meta(v, &id, |m| m.set("unknown_field", extra()));
                resign(v, &id, view);
            },
            Fixture::load,
        ),
        Site::MetaGrant => fx.with_edit(
            |v| {
                edit_meta(v, &id, |m| {
                    m.at(&["grants", "bot"]).set("unknown_field", extra());
                });
                resign(v, &id, view);
            },
            Fixture::load,
        ),
        Site::AgentsRecord => fx.with_edit(
            |v| {
                edit_agents(v, &fx.grant_identity(), |r| r.set("unknown_field", extra()));
                reseal(v, &id, view);
            },
            Fixture::grant_load,
        ),
        Site::AgentsGrant => fx.with_edit(
            |v| {
                edit_agents(v, &fx.grant_identity(), |r| {
                    r.at(&["grant"]).set("unknown_field", extra());
                });
                reseal(v, &id, view);
            },
            Fixture::grant_load,
        ),
    }
}

// ── signature text that is not canonical ──

const BASE64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The signature text without its `=` padding.
fn padding_stripped(sig: &str) -> String {
    sig.trim_end_matches('=').to_string()
}

/// The same 64 bytes with a trailing bit set in the last character: 64 bytes
/// are 86 characters and `==`, and the last character carries two data bits
/// and four bits that must be zero.
fn trailing_bit_set(sig: &str) -> String {
    let body = sig.trim_end_matches('=');
    let (head, last) = body.split_at(body.len() - 1);
    let index = BASE64_ALPHABET.find(last).expect("a base64 character");
    let flipped = char::from(BASE64_ALPHABET.as_bytes()[index | 1]);
    format!("{head}{flipped}{}", &sig[body.len()..])
}

/// What a decoder that ignores padding and trailing bits reads.
fn lenient_decode(text: &str) -> Vec<u8> {
    use base64::alphabet::STANDARD;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
    .decode(text)
    .expect("lenient base64")
}

/// The signature's text.
fn signature_text(vault: &Json) -> String {
    vault
        .get("sig")
        .and_then(|s| s.get("sig"))
        .and_then(Json::str)
        .expect("signature text")
        .to_string()
}

/// Other text for the same signature bytes, which a strict decoder refuses.
fn non_canonical_signatures(sig: &str) -> [(&'static str, String); 2] {
    let variants = [
        ("its padding dropped", padding_stripped(sig)),
        ("a trailing bit set", trailing_bit_set(sig)),
    ];
    assert!(variants.iter().all(|(_, text)| text != sig));
    variants
}

// ── R-L-sig ──

/// Every edit of a format-4 vault's `prev`, signed view, header or unknown
/// fields is refused, and equal content signs to an equal fp. Each edit is
/// sealed (re-MACed and re-signed by the key holder) where only a format rule
/// can refuse it, and the control arms show that the same sealing of an
/// unedited vault loads, that an unknown field on a format-3 vault still
/// loads, and that the file's signature is what the edits are measured
/// against.
#[test]
fn row_r_l_sig() {
    common::rows::check("R-L-sig", |p| {
        // Controls that hold on a format-3 vault, whatever this build writes.
        let legacy = Fixture::legacy();
        let legacy_id = legacy.identity();
        let untouched = legacy.json();
        let mut again = untouched.clone();
        resign(&mut again, &legacy_id, 2);
        p.require(
            fp(&again) == fp(&untouched),
            "re-signing the format-3 fixture reproduces murk's signature, so the editing helpers sign as murk does",
        )?;
        p.require(
            legacy.load().loaded(),
            "the untouched format-3 fixture loads",
        )?;
        for site in SITES_IN_ANY_VAULT {
            let load = load_with_unknown_field(&legacy, site);
            p.require(
                load.loaded(),
                format!(
                    "an unknown field at {site:?} of a format-3 vault still loads: {}",
                    load.summary()
                ),
            )?;
        }

        // The signature text has one encoding: the same 64 bytes written with
        // the padding dropped, or with a trailing bit set, are refused. A
        // format-3 vault shows the decoder today.
        let legacy_sig = signature_text(&untouched);
        for (what, text) in non_canonical_signatures(&legacy_sig) {
            p.require(
                lenient_decode(&text) == lenient_decode(&legacy_sig),
                format!("the signature with {what} is the same 64 bytes in other text"),
            )?;
            let load = legacy.with_edit(
                |v| v.at(&["sig"]).set("sig", Json::Str(text)),
                Fixture::load,
            );
            p.note(format!(
                "format-3 signature with {what}: {}",
                if load.refused() {
                    "refused"
                } else {
                    "ACCEPTED"
                }
            ));
        }

        let age = Fixture::age(true);
        let ssh = Fixture::ssh();
        let built = major(&age.json());
        if built == 3 {
            // Until this build writes format 4, its own vaults are the
            // control for the sites a checked-in vault cannot reach (an agent
            // grant expires): the same fields still load.
            for site in SITES_WITH_A_GRANT {
                let load = load_with_unknown_field(&age, site);
                p.require(
                    load.loaded(),
                    format!(
                        "an unknown field at {site:?} of a format-3 vault still loads: {}",
                        load.summary()
                    ),
                )?;
            }
        }

        // The decisive prerequisite: a vault in format 4.
        p.require(
            built == 4 && major(&ssh.json()) == 4,
            format!(
                "this build writes format {built} vaults, so there is no format-4 vault to edit"
            ),
        )?;
        p.require(age.load().loaded(), "the untouched format-4 vault loads")?;
        let id = age.identity();
        let original = age.json();
        let own = generation(&original);
        let entries = prev(&original);
        p.require(
            entries.len() >= 2,
            "a format-4 vault of four saves has at least two prev entries",
        )?;
        p.require(
            view_of(&original) == 3,
            "a format-4 vault carries a view-3 signature",
        )?;
        p.require(
            age.with_edit(|v| reseal(v, &id, 3), Fixture::load).loaded(),
            "re-MACing and re-signing an unedited format-4 vault loads, so a sealed edit is refused for its content",
        )?;
        p.require(
            age.with_edit(
                |v| {
                    edit_meta(v, &id, |_| {});
                    resign(v, &id, 3);
                },
                Fixture::load,
            )
            .loaded(),
            "re-encrypting the meta unchanged and signing again loads",
        )?;
        p.reached();

        // prev: any entry edit is refused; with the MAC recomputed, the
        // signature is what refuses it.
        let (g0, fp0) = split_entry(&entries[0]);
        let flip = |v: &mut Json| {
            let mut changed = entries.clone();
            changed[0] = entry(g0, &other_fp(fp0));
            set_prev(v, &changed);
        };
        refuse(
            p,
            "an edited prev entry",
            &age.with_edit(flip, Fixture::load),
            false,
        );
        let sig_only = age.with_edit(
            |v| {
                flip(v);
                remac(v, &id);
            },
            Fixture::load,
        );
        refuse(
            p,
            "an edited prev entry under a recomputed MAC",
            &sig_only,
            false,
        );
        p.target(
            sig_only.err.contains("signature"),
            "the signature covers prev: with the MAC recomputed, the refusal names the signature",
        );

        // Signed view against header major.
        let view2 = age.with_edit(|v| resign(v, &id, 2), Fixture::load);
        refuse(p, "view 2 on a 4.x vault", &view2, false);
        let view3_on_3x = legacy.with_edit(|v| resign(v, &legacy_id, 3), Fixture::load);
        refuse(p, "view 3 on a 3.x vault", &view3_on_3x, false);
        let mut on_3x = legacy.json();
        let legacy_own = generation(&on_3x);
        on_3x.insert_after(
            "generation",
            "prev",
            Json::Arr(vec![Json::text(&entry(
                legacy_own - 1,
                "0123456789abcdef0123456789abcdef",
            ))]),
        );
        let prev_on_3x = legacy.with_edit(|v| *v = on_3x, Fixture::load);
        refuse(p, "a prev on a 3.x header", &prev_on_3x, true);

        // The shape of prev.
        let sealed = |change: &dyn Fn(&mut Json)| {
            age.with_edit(
                |v| {
                    change(v);
                    reseal(v, &id, 3);
                },
                Fixture::load,
            )
        };
        refuse(
            p,
            "unsorted prev entries",
            &sealed(&|v| {
                let mut swapped = entries.clone();
                swapped.swap(0, 1);
                set_prev(v, &swapped);
            }),
            true,
        );
        refuse(
            p,
            "a prev entry whose fp repeats an earlier one",
            &sealed(&|v| {
                let mut repeated = entries.clone();
                repeated[1] = entry(split_entry(&entries[1]).0, fp0);
                set_prev(v, &repeated);
            }),
            true,
        );
        for (what, generation) in [
            ("a prev entry at the vault's own generation", own),
            ("a prev entry above the vault's own generation", own + 5),
        ] {
            refuse(
                p,
                what,
                &sealed(&|v| {
                    let mut raised = entries.clone();
                    raised[0] = entry(generation, fp0);
                    set_prev(v, &raised);
                }),
                true,
            );
        }

        // prev_floor, the signed header field that bounds which prev entries
        // a merge may rely on.
        let floor_edit = |v: &mut Json| match v.get("prev_floor").and_then(Json::u64) {
            Some(n) => v.set("prev_floor", Json::num(n + 1)),
            None => v.insert_after("prev", "prev_floor", Json::num(1)),
        };
        refuse(
            p,
            "an edited prev_floor",
            &age.with_edit(floor_edit, Fixture::load),
            false,
        );
        refuse(
            p,
            "a prev_floor above the vault's own generation",
            &sealed(&|v| {
                if v.get("prev_floor").is_some() {
                    v.set("prev_floor", Json::num(own + 1));
                } else {
                    v.insert_after("prev", "prev_floor", Json::num(own + 1));
                }
            }),
            true,
        );

        // Signature text that is not canonical: the same signature bytes in
        // other text would give the revision a second fp.
        for (what, text) in non_canonical_signatures(&signature_text(&original)) {
            refuse(
                p,
                &format!("signature text with {what}"),
                &age.with_edit(
                    |v| v.at(&["sig"]).set("sig", Json::Str(text)),
                    Fixture::load,
                ),
                false,
            );
        }

        // Unknown fields on a 4.x vault, at every site.
        for site in SITES_IN_ANY_VAULT.into_iter().chain(SITES_WITH_A_GRANT) {
            refuse(
                p,
                &format!("an unknown field at {site:?} of a 4.x vault"),
                &load_with_unknown_field(&age, site),
                true,
            );
        }

        // Determinism: the same content signed twice by one key has one fp.
        for fx in [&age, &ssh] {
            let before = fx.json();
            let mut twice = before.clone();
            resign(&mut twice, &fx.identity(), 3);
            p.target(
                fp(&twice) == fp(&before),
                format!(
                    "one content signed twice by one {} key gives an equal fp",
                    fx.label
                ),
            );
        }
        Ok(())
    });
}

// ── R-L-mac ──

/// A change of `prev` or of the meta's `revoked_grants` fails the `blake3v9:`
/// MAC even under a valid signature, and `blake3v8:` on a 4.x header is
/// refused. Each edit is signed again by the key holder so that only the MAC
/// can refuse it; the untouched vault, and the same signing of an unedited
/// copy, load.
#[test]
fn row_r_l_mac() {
    common::rows::check("R-L-mac", |p| {
        let fx = Fixture::age(false);
        let built = major(&fx.json());
        p.require(
            built == 4,
            format!(
                "this build writes format {built} vaults, so there is no format-4 vault to edit"
            ),
        )?;
        let id = fx.identity();
        let original = fx.json();
        let entries = prev(&original);
        p.require(!entries.is_empty(), "a format-4 vault has a prev entry")?;
        p.require(fx.load().loaded(), "the untouched format-4 vault loads")?;
        p.require(
            fx.with_edit(|v| resign(v, &id, 3), Fixture::load).loaded(),
            "signing an unedited copy again loads, so a signed edit is refused for its content",
        )?;
        p.require(
            fx.with_edit(
                |v| {
                    edit_meta(v, &id, |_| {});
                    resign(v, &id, 3);
                },
                Fixture::load,
            )
            .loaded(),
            "re-encrypting the meta unchanged and signing again loads",
        )?;
        p.reached();

        let (g0, fp0) = split_entry(&entries[0]);
        let prev_change = fx.with_edit(
            |v| {
                let mut changed = entries.clone();
                changed[0] = entry(g0, &other_fp(fp0));
                set_prev(v, &changed);
                resign(v, &id, 3);
            },
            Fixture::load,
        );
        p.target(
            prev_change.refused() && prev_change.err.contains("(expected "),
            "a change of prev under a valid signature fails the MAC",
        );
        p.note(format!("prev change: {}", prev_change.summary()));

        let revoked_change = fx.with_edit(
            |v| {
                edit_meta(v, &id, |meta| {
                    let mut revoked: Vec<String> = match meta.get("revoked_grants") {
                        Some(Json::Arr(items)) => items
                            .iter()
                            .filter_map(Json::str)
                            .map(str::to_string)
                            .collect(),
                        _ => Vec::new(),
                    };
                    revoked.push(FOREIGN_PK.to_string());
                    revoked.sort();
                    revoked.dedup();
                    meta.set(
                        "revoked_grants",
                        Json::Arr(revoked.iter().map(|k| Json::text(k)).collect()),
                    );
                });
                resign(v, &id, 3);
            },
            Fixture::load,
        );
        p.target(
            revoked_change.refused() && revoked_change.err.contains("(expected "),
            "a change of revoked_grants under a valid signature fails the MAC",
        );
        p.note(format!(
            "revoked_grants change: {}",
            revoked_change.summary()
        ));

        let downgraded = fx.with_edit(
            |v| {
                edit_meta(v, &id, |meta| {
                    let mac = meta
                        .get("mac")
                        .and_then(Json::str)
                        .expect("a MAC")
                        .to_string();
                    let tail = mac.split_once(':').map_or(mac.as_str(), |(_, tail)| tail);
                    meta.set("mac", Json::Str(format!("blake3v8:{tail}")));
                });
                resign(v, &id, 3);
            },
            Fixture::load,
        );
        p.target(downgraded.refused(), "blake3v8 on a 4.x header is refused");
        p.note(format!("blake3v8 on 4.x: {}", downgraded.summary()));
        Ok(())
    });
}

// ── R-L-compat ──

/// A vault from a newer format is refused as newer, not misread: a 5.0 header
/// (with its MAC and signature made valid, so only the version check stands
/// in its way) and a view-4 signature on a 3.x vault. A 3.0 vault, and the
/// same sealing of an unedited copy, load.
#[test]
fn row_r_l_compat() {
    common::rows::check("R-L-compat", |p| {
        let fx = Fixture::legacy();
        let id = fx.identity();
        let original = fx.json();
        p.require(
            header_version(&original) == "3.0" && view_of(&original) == 2,
            "the fixture is a 3.0 vault with a view-2 signature",
        )?;
        p.require(fx.load().loaded(), "a 3.0 vault loads")?;
        p.require(
            fx.with_edit(|v| reseal(v, &id, 2), Fixture::load).loaded(),
            "re-MACing and re-signing an unedited 3.0 vault loads, so a sealed edit is refused for its content",
        )?;
        p.reached();

        let newer_header = fx.with_edit(
            |v| {
                v.set("version", Json::text("5.0"));
                reseal(v, &id, 2);
            },
            Fixture::load,
        );
        p.target(newer_header.refused(), "a 5.0 header is refused");
        p.target(
            newer_header.err.contains("unsupported vault version")
                || newer_header.err.contains("newer murk"),
            format!(
                "the 5.0 header is refused as an unsupported version, not as tampering: {}",
                newer_header.summary()
            ),
        );
        let newer_view = fx.with_edit(|v| v.at(&["sig"]).set("v", Json::num(4)), Fixture::load);
        p.target(
            newer_view.refused(),
            "a view-4 signature on a 3.x vault is refused",
        );
        p.target(
            newer_view.err.contains("newer murk"),
            format!(
                "the view-4 signature is refused as written by a newer murk, not as tampering: {}",
                newer_view.summary()
            ),
        );
        Ok(())
    });
}

// ── the pin, its sidecar and a machine's saves ──

/// Add each of `names` to the vault in `dir` (a machine whose `HOME` is `dir`).
fn save_each(dir: &Path, secret: &str, names: &[&str]) {
    for name in names {
        add(dir, secret, name, &format!("v-{name}"));
    }
}

/// The pin file under `home`, and where its lineage sidecar belongs.
fn pin_files(home: &Path) -> Result<(PathBuf, PathBuf), String> {
    let dir = home.join(".config").join("murk").join("signer-pins");
    let mut pins: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|e| format!("no pin directory {}: {e}", dir.display()))?
        .map(|e| e.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".json") && !n.ends_with(".lineage.json"))
        })
        .collect();
    if pins.len() != 1 {
        return Err(format!(
            "want one pin under {}, found {pins:?}",
            dir.display()
        ));
    }
    let pin = pins.remove(0);
    let sidecar = pin.with_extension("lineage.json");
    Ok((pin, sidecar))
}

/// What murk 0.15 does to a pin it accepts a vault with: read it into its
/// pin type and write it back (the type has no lineage field, so any the pin
/// file held would be lost), after changing a mark as accepting a format-3
/// vault on a branch this release has not adopted does.
fn rewrite_pin_as_0_15(pin: &Path) {
    let mut parsed: murk_cli::pins::TrustPin =
        serde_json::from_str(&fs::read_to_string(pin).unwrap()).expect("a pin");
    parsed.branches.insert("old".to_string(), 1);
    parsed.v = murk_cli::pins::PIN_VERSION;
    fs::write(pin, serde_json::to_string_pretty(&parsed).unwrap()).unwrap();
}

/// A `get` of `name` as `secret` on the machine in `dir`.
fn get_on(dir: &Path, secret: &str, name: &str) -> (bool, String) {
    let out = murk(dir, secret)
        .args(["get", name, "--vault", VAULT])
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

// ── R-L-oldpin ──

/// A pin rewritten as murk 0.15 writes it keeps the lineage sidecar. A
/// machine saves and so records a lineage reference in `<hash>.lineage.json`
/// next to its pin; the pin is read into its 0.15 type and written back with
/// a changed mark, as a 0.15 component sharing the `HOME` does. The sidecar's
/// bytes stay as they were, and a genuine stale-fork file above the mark is
/// still refused, as it was before the rewrite.
#[test]
fn row_r_l_oldpin() {
    common::rows::check("R-L-oldpin", |p| {
        let home = TempDir::new().unwrap();
        let (secret, _) = init_vault(home.path());
        save_each(home.path(), &secret, &[TOKEN]); // generation 2
        let fork_base = fs::read(home.path().join(VAULT)).unwrap();
        save_each(home.path(), &secret, &["MAIN"]); // generation 3: what this machine accepts
        let main_line = fs::read(home.path().join(VAULT)).unwrap();

        // A genuine fork of generation 2, two saves further on: above the
        // mark, signed by the same key, not a descendant of generation 3.
        let other = TempDir::new().unwrap();
        fs::write(other.path().join(VAULT), &fork_base).unwrap();
        murk(other.path(), &secret)
            .args(["trust", "--yes", "--vault", VAULT])
            .assert()
            .success();
        save_each(other.path(), &secret, &["FORK_ONE", "FORK_TWO"]);
        let stale_fork = fs::read(other.path().join(VAULT)).unwrap();
        let main = parse(&main_line);
        let fork = parse(&stale_fork);
        p.require(
            generation(&fork) > generation(&main)
                && fork.get("vault_id") == main.get("vault_id")
                && fork.get("sig").and_then(|s| s.get("signer"))
                    == main.get("sig").and_then(|s| s.get("signer")),
            "the stale fork is the same vault, signed by the same key, above the accepted generation",
        )?;

        let (pin, sidecar) = pin_files(home.path())?;
        p.require(
            sidecar.is_file(),
            format!(
                "this release records a lineage sidecar at {}",
                sidecar.display()
            ),
        )?;
        let sidecar_before = fs::read(&sidecar).unwrap();
        let reference = entry(generation(&main), &fp(&main));
        p.require(
            String::from_utf8_lossy(&sidecar_before).contains(&reference),
            format!("the sidecar holds the lineage reference {reference}"),
        )?;
        let vault_path = home.path().join(VAULT);
        let load_fork = |home: &Path| {
            fs::write(home.join(VAULT), &stale_fork).unwrap();
            let (ok, out) = get_on(home, &secret, "FORK_TWO");
            fs::write(home.join(VAULT), &main_line).unwrap();
            !ok && !out.contains("v-FORK_TWO")
        };
        p.require(
            load_fork(home.path()),
            "before the rewrite the stale fork is refused as not descending from the accepted revision",
        )?;
        p.require(
            fs::read(&vault_path).unwrap() == main_line,
            "the accepted revision is back in place",
        )?;

        let pin_before = fs::read(&pin).unwrap();
        rewrite_pin_as_0_15(&pin);
        p.reached();
        p.require(
            fs::read(&pin).unwrap() != pin_before,
            "the 0.15 rewrite changed the pin file",
        )?;

        p.target(
            fs::read(&sidecar).ok().as_deref() == Some(&sidecar_before[..]),
            "the sidecar's bytes are unchanged by the 0.15 rewrite of the pin",
        );
        p.target(
            load_fork(home.path()),
            "the stale fork is still refused after the 0.15 rewrite",
        );
        let (ok, out) = get_on(home.path(), &secret, TOKEN);
        p.target(
            ok && out.contains("v-TOKEN"),
            "the accepted revision still loads after the 0.15 rewrite",
        );
        Ok(())
    });
}

// ── R-L-prevgen ──

/// A save after `murk trust` of an older revision (which lowers the counter
/// outside git) writes a `prev` with no entry at or above its own generation,
/// though the sidecar's superseded set holds such entries. The machine saves
/// six times, accepts the vault as it was at generation 3 with `murk trust`,
/// and saves again; the file written is generation 4, loads, and its `prev`
/// holds only entries below 4, among them the older revision it was saved
/// over.
#[test]
fn row_r_l_prevgen() {
    common::rows::check("R-L-prevgen", |p| {
        let home = TempDir::new().unwrap();
        let (secret, _) = init_vault(home.path());
        save_each(home.path(), &secret, &[TOKEN, "B"]); // generation 3
        let vault_path = home.path().join(VAULT);
        let older = fs::read(&vault_path).unwrap();
        save_each(home.path(), &secret, &["C", "D", "E"]); // generation 6
        let older_vault = parse(&older);
        let older_generation = generation(&older_vault);
        p.require(
            generation(&parse(&fs::read(&vault_path).unwrap())) > older_generation + 1,
            "the machine's line is well ahead of the older revision",
        )?;

        // Accept the older revision: refused as rolled back until `murk trust`.
        fs::write(&vault_path, &older).unwrap();
        p.require(
            !get_on(home.path(), &secret, TOKEN).0,
            "the older revision is refused as rolled back",
        )?;
        murk(home.path(), &secret)
            .args(["trust", "--yes", "--vault", VAULT])
            .assert()
            .success();
        p.require(
            get_on(home.path(), &secret, TOKEN).0,
            "murk trust accepts the older revision",
        )?;

        let (_, sidecar) = pin_files(home.path())?;
        p.require(
            sidecar.is_file(),
            format!(
                "this release records a lineage sidecar at {}",
                sidecar.display()
            ),
        )?;
        let record: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&sidecar).unwrap())
                .expect("a sidecar is JSON");
        let superseded: Vec<&str> = record["lineage_superseded"][""]
            .as_array()
            .map(|a| a.iter().filter_map(|e| e.as_str()).collect())
            .unwrap_or_default();
        p.require(
            superseded
                .iter()
                .any(|e| split_entry(e).0 > older_generation + 1),
            format!("lineage_superseded holds entries above the older revision's generation: {superseded:?}"),
        )?;

        let save = murk(home.path(), &secret)
            .args(["add", "F", "--vault", VAULT])
            .write_stdin("v-F\n")
            .output()
            .unwrap();
        p.reached();
        p.target(
            save.status.success(),
            "the save after murk trust is written",
        );
        p.note(String::from_utf8_lossy(&save.stderr).trim().to_string());
        let written = parse(&fs::read(&vault_path).unwrap());
        let own = generation(&written);
        let entries = prev(&written);
        p.target(
            own == older_generation + 1,
            format!("the save is numbered one past the older revision ({own})"),
        );
        p.target(
            get_on(home.path(), &secret, "F").0,
            "the vault the save wrote validates and loads",
        );
        p.target(
            !entries.is_empty() && entries.iter().all(|e| split_entry(e).0 < own),
            format!("no prev entry at or above generation {own}: {entries:?}"),
        );
        p.target(
            entries.contains(&entry(older_generation, &fp(&older_vault))),
            "prev keeps the older revision the save was made over",
        );
        Ok(())
    });
}
