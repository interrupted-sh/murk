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
use murk_cli::types::{Vault, VaultSignature};
use std::collections::BTreeSet;

/// Recompute the MAC (in the meta) and the signature of `vault` as
/// `identity`, which must read the meta and be able to sign.
pub fn reseal(vault: &mut Vault, identity: &MurkIdentity) {
    let mut meta = murk_cli::decrypt_meta(vault, identity)
        .unwrap()
        .expect("the key reads the vault meta");
    if let Err(e) = murk_cli::decrypt_vault(vault, identity) {
        let e = e.to_string();
        let expected = e
            .split_once("(expected ")
            .and_then(|(_, rest)| rest.split_once(", got "))
            .map(|(mac, _)| mac.to_string())
            .unwrap_or_else(|| panic!("not a MAC mismatch: {e}"));
        meta.mac = expected;
    }
    // The meta goes to every recipient but agent grants, as murk writes it.
    let grants: BTreeSet<&str> = meta.grants.values().map(|g| g.pubkey.as_str()).collect();
    let recipients: Vec<murk_cli::MurkRecipient> = vault
        .recipients
        .iter()
        .filter(|r| !grants.contains(r.as_str()))
        .map(|r| murk_cli::crypto::parse_recipient(r).unwrap())
        .collect();
    vault.meta = murk_cli::encrypt_value(&serde_json::to_vec(&meta).unwrap(), &recipients).unwrap();
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
