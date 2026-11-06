// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A key holder's own code against a vault: re-MAC and re-sign a vault whose
//! header was edited by hand, so a test can write vaults murk itself refuses
//! to write (a generation above the limit, say) and check that loads refuse
//! them for that reason, not for a broken MAC.
//!
//! Built only on murk's public API. The MAC scheme is private to the crate,
//! so the expected MAC is read from the integrity error a load of the edited
//! vault reports.

// Each integration binary compiles this module; most use only part of it.
#![allow(dead_code)]

use murk_cli::crypto::MurkIdentity;
use murk_cli::types::{Meta, Vault, VaultSignature};
use std::collections::{BTreeMap, BTreeSet};

/// The MAC a load of `vault` expects, read from its integrity error, or
/// `None` when the stored one is right.
fn expected_mac(vault: &Vault, identity: &MurkIdentity) -> Option<String> {
    let e = murk_cli::decrypt_vault(vault, identity).err()?.to_string();
    let expected = e
        .split_once("(expected ")
        .and_then(|(_, rest)| rest.split_once(", got "))
        .map(|(mac, _)| mac.to_string())
        .unwrap_or_else(|| panic!("not a MAC mismatch: {e}"));
    Some(expected)
}

/// Encrypt `meta` into `vault`, to every recipient but agent grants, as murk
/// writes it.
fn write_meta(vault: &mut Vault, meta: &Meta) {
    let grants: BTreeSet<&str> = meta.grants.values().map(|g| g.pubkey.as_str()).collect();
    let recipients: Vec<murk_cli::MurkRecipient> = vault
        .recipients
        .iter()
        .filter(|r| !grants.contains(r.as_str()))
        .map(|r| murk_cli::crypto::parse_recipient(r).unwrap())
        .collect();
    vault.meta = murk_cli::encrypt_value(&serde_json::to_vec(meta).unwrap(), &recipients).unwrap();
}

/// Remove the view-1 signature from a murk 0.13 `vault`'s meta, as a repo
/// writer (or a key that cannot sign) would leave it. The MAC does not cover
/// the signature, so the vault still verifies. `identity` must read the meta.
pub fn strip_v1(vault: &mut Vault, identity: &MurkIdentity) {
    let mut meta = murk_cli::decrypt_meta(vault, identity)
        .unwrap()
        .expect("the key reads the vault meta");
    assert!(meta.sig.take().is_some(), "a view-1 signature to strip");
    write_meta(vault, &meta);
}

/// Recompute the MAC (in the meta) and the signature of `vault` as
/// `identity`, which must read the meta and be able to sign.
pub fn reseal(vault: &mut Vault, identity: &MurkIdentity) {
    let mut meta = murk_cli::decrypt_meta(vault, identity)
        .unwrap()
        .expect("the key reads the vault meta");
    if let Some(mac) = expected_mac(vault, identity) {
        meta.mac = mac;
    }
    write_meta(vault, &meta);
    // Signed view v2: the domain tag, then the vault serialized without its
    // signature.
    vault.sig = None;
    let mut message = b"murk.vault.sig.v2\n".to_vec();
    serde_json::to_writer(&mut message, &*vault).unwrap();
    vault.sig = Some(VaultSignature {
        signer: identity.pubkey_string().unwrap(),
        v: 2,
        sig: identity.signing_key().unwrap().sign(&message),
    });
    assert!(
        murk_cli::decrypt_vault(vault, identity).is_ok(),
        "the resealed vault verifies"
    );
}

/// Rewrite `vault` as murk 0.13 wrote it: header version `2.0`, no vault id
/// or counter, re-MACed, and a view-1 signature by `identity` inside the
/// meta. murk 0.14 never writes one; this stands in for a revision an older
/// murk wrote. The signed message mirrors `signature::signing_message` (view
/// 1) byte for byte. `identity` must read the meta and be able to sign.
pub fn reseal_v1(vault: &mut Vault, identity: &MurkIdentity) {
    #[derive(serde::Serialize)]
    struct SignedView<'a> {
        v: u32,
        version: &'a str,
        recipients: Vec<&'a str>,
        schema: &'a BTreeMap<String, murk_cli::types::SchemaEntry>,
        secrets: &'a BTreeMap<String, murk_cli::types::SecretEntry>,
        policy: &'a Option<murk_cli::types::Policy>,
        groups: &'a BTreeMap<String, Vec<String>>,
        grants: &'a BTreeMap<String, murk_cli::types::GrantEntry>,
        github_pins: BTreeMap<&'a str, &'a Vec<String>>,
        signers: &'a BTreeMap<String, String>,
    }

    vault.version = "2.0".into();
    vault.vault_id.clear();
    vault.generation = 0;
    vault.sig = None;
    let mut meta = murk_cli::decrypt_meta(vault, identity)
        .unwrap()
        .expect("the key reads the vault meta");
    meta.sig = None;
    write_meta(vault, &meta);
    if let Some(mac) = expected_mac(vault, identity) {
        meta.mac = mac;
    }
    let mut recipients: Vec<&str> = vault.recipients.iter().map(String::as_str).collect();
    recipients.sort_unstable();
    let view = SignedView {
        v: 1,
        version: &vault.version,
        recipients,
        schema: &vault.schema,
        secrets: &vault.secrets,
        policy: &vault.policy,
        groups: &meta.groups,
        grants: &meta.grants,
        github_pins: meta
            .github_pins
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect(),
        signers: &meta.signers,
    };
    let mut message = b"murk.vault.sig.v1\n".to_vec();
    serde_json::to_writer(&mut message, &view).unwrap();
    let sig = VaultSignature {
        signer: identity.pubkey_string().unwrap(),
        v: 1,
        sig: identity.signing_key().unwrap().sign(&message),
    };
    meta.sig = Some(sig);
    write_meta(vault, &meta);
    assert!(
        murk_cli::decrypt_vault(vault, identity).is_ok(),
        "the 0.13-format vault verifies"
    );
}
