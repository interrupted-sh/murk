// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Python bindings for murk via PyO3.
//!
//! ```python
//! import murk
//!
//! vault = murk.load()              # finds your key like the CLI, .murk from cwd
//! vault.get("DATABASE_URL")        # decrypt a single value
//! vault.export()                   # dict of all key/values
//! murk.get("DATABASE_URL")         # one-liner convenience
//! vault.add("NEW_KEY", "value")    # experimental: store a secret (shared)
//! ```
//!
//! Every call that reads the vault applies the same trust rules as the CLI
//! (`crate::load_vault`): a vault this machine does not trust raises
//! `murk.TrustError`, with the message the CLI prints. The experimental
//! writes (`Vault.add`, `Vault.describe`, `murk.add`) reload the vault through
//! the same check before they change it.

use std::collections::HashMap;
use std::path::Path;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::{MurkError, SecretTier, env, export, policy, types};

pyo3::create_exception!(
    murk,
    TrustError,
    PyRuntimeError,
    "The vault was refused: not trusted on this machine, or tampered with."
);

/// A refusal of the vault itself (trust or integrity) raises `TrustError`;
/// anything else `RuntimeError`.
fn load_error(e: &MurkError) -> PyErr {
    match e {
        MurkError::Trust(_) | MurkError::Integrity(_) => TrustError::new_err(e.to_string()),
        _ => PyRuntimeError::new_err(e.to_string()),
    }
}

/// Any other failure raises `RuntimeError`.
fn fail(reason: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(reason.to_string())
}

/// A loaded and decrypted murk vault.
#[pyclass]
struct Vault {
    inner: types::Vault,
    decrypted: types::Murk,
    pubkey: String,
    path: String,
}

#[pymethods]
impl Vault {
    /// Get a single decrypted secret value. Resolution order: a personal scoped
    /// override, then a named-group value we can read, then the shared value.
    ///
    /// The returned `String` is a plain Python-owned copy — once it crosses
    /// the FFI boundary the plaintext is outside murk's zeroization.
    ///
    /// When the loaded identity is a granted agent, the vault's agent policy is
    /// enforced before the value is returned — the same gate the CLI applies at
    /// `agent exec`. Raises `RuntimeError` if policy forbids the key. For an
    /// operator identity this is a no-op.
    fn get(&self, key: &str) -> PyResult<Option<String>> {
        let value = crate::get_secret(&self.decrypted, key, &self.pubkey).map(str::to_string);
        // Only enforce when there is a value to hand back: a key the agent
        // cannot decrypt is already inaccessible, so policy is moot.
        if value.is_some() {
            policy::enforce_agent_policy(
                &self.inner,
                &self.decrypted,
                &self.pubkey,
                &[key.to_string()],
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        }
        Ok(value)
    }

    /// Export all secrets as a dict. Scoped values override shared values.
    ///
    /// For a granted agent, the vault's agent policy is enforced over the full
    /// key set first (mirroring `murk agent exec`): if any resolvable key is
    /// outside the policy, the whole export raises `RuntimeError` rather than
    /// returning a partial dict. For an operator identity this is a no-op.
    fn export(&self) -> PyResult<HashMap<String, String>> {
        let resolved = export::resolve_secrets(&self.inner, &self.decrypted, &self.pubkey, &[]);
        let keys: Vec<String> = resolved.keys().cloned().collect();
        policy::enforce_agent_policy(&self.inner, &self.decrypted, &self.pubkey, &keys)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        // Python dicts own plain Strings — zeroization ends at the FFI boundary.
        Ok(resolved
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect())
    }

    /// List all key names.
    fn keys(&self) -> Vec<String> {
        self.inner.schema.keys().cloned().collect()
    }

    /// Number of secrets in the vault.
    fn __len__(&self) -> usize {
        self.inner.schema.len()
    }

    /// Get a value by key (dict-style access).
    fn __getitem__(&self, key: &str) -> PyResult<String> {
        self.get(key)?
            .ok_or_else(|| PyRuntimeError::new_err(format!("key not found: {key}")))
    }

    /// Check if a key exists.
    fn __contains__(&self, key: &str) -> bool {
        self.inner.schema.contains_key(key)
    }

    fn __repr__(&self) -> String {
        format!(
            "Vault({} secrets, {} recipients)",
            self.inner.schema.len(),
            self.inner.recipients.len()
        )
    }

    /// Warnings about this vault that did not stop the load — the ones the
    /// CLI prints as `warn …` (an unsigned vault read by a key that cannot
    /// sign, a legacy MAC, a trust pin that could not be written).
    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.decrypted.warnings.clone()
    }

    /// Experimental. Store a secret. Mirrors `murk add`: the value is encrypted
    /// to the tier's recipients and the vault is re-signed and written back to
    /// disk under an exclusive lock, so it is safe against concurrent writers.
    ///
    /// `tier` selects the destination: `"everyone"` (shared to all recipients),
    /// `"me"` (a personal value encrypted to the caller only), or a group name
    /// (encrypted to that group's members; the caller must be a member). Giving
    /// a tier moves an existing key there. Without one, an existing key keeps
    /// its tier, and a new key is shared (`"everyone"`). A key held by a group
    /// the caller is not a member of can't be written (except as a `"me"`
    /// override), and a key holding only other recipients' overrides needs an
    /// explicit tier: otherwise the call raises `RuntimeError`.
    ///
    /// The write reloads the vault from disk through the same trust check as
    /// `load()`: a vault this machine does not trust raises `TrustError` and
    /// nothing is written. An agent grant can't write: the call raises
    /// `RuntimeError` ("agent grants are read-only"). When the operator has
    /// opted into self-scope, the key must satisfy the vault's agent policy.
    ///
    /// The caller holds the plaintext as a Python `str` before this call. It is
    /// copied into Rust and zeroized on neither side. See THREAT_MODEL.md.
    ///
    /// The wait for the vault lock, the decryption and the save run without
    /// the GIL, so other Python threads keep running.
    #[pyo3(signature = (key, value, *, tier=None, desc=None, tags=None))]
    fn add(
        slf: &Bound<'_, Self>,
        key: &str,
        value: &str,
        tier: Option<&str>,
        desc: Option<&str>,
        tags: Option<Vec<String>>,
    ) -> PyResult<()> {
        let path = slf.borrow().path.clone();
        let written = slf
            .py()
            .detach(|| add_at(&path, key, value, tier, desc, tags))?;
        slf.borrow_mut().refresh(written);
        Ok(())
    }

    /// Experimental. Set a secret's description, and optionally its tags and
    /// example, in the vault schema. Mirrors `murk describe`. The value is not
    /// touched: a key with no value becomes a documented but unset entry.
    /// Non-empty `tags` replace the existing tags.
    ///
    /// The trust, grant and policy checks are the same as in `add`, and so is
    /// the release of the GIL.
    #[pyo3(signature = (key, description, *, tags=None, example=None))]
    fn describe(
        slf: &Bound<'_, Self>,
        key: &str,
        description: &str,
        tags: Option<Vec<String>>,
        example: Option<&str>,
    ) -> PyResult<()> {
        let path = slf.borrow().path.clone();
        let written = slf
            .py()
            .detach(|| describe_at(&path, key, description, tags, example))?;
        slf.borrow_mut().refresh(written);
        Ok(())
    }
}

impl Vault {
    /// Take the state a write saved as this handle's snapshot, so later reads
    /// see the write and any concurrent changes its fresh load picked up.
    fn refresh(&mut self, written: Written) {
        self.inner = written.vault;
        self.decrypted = written.murk;
        self.pubkey = written.pubkey;
    }
}

/// The vault a write saved, decrypted, and the key that saved it.
struct Written {
    vault: types::Vault,
    murk: types::Murk,
    pubkey: String,
}

/// `vault_path` made absolute against the current directory. Symlinks are not
/// resolved, so the symlink refusal still sees a link. A handle keeps this
/// path, so it names the vault it loaded after the process changes directory.
fn absolute_path(vault_path: &str) -> PyResult<String> {
    std::path::absolute(vault_path)
        .map_err(fail)?
        .into_os_string()
        .into_string()
        .map_err(|_| fail("the vault path is not valid UTF-8"))
}

/// Store a secret in the vault at `path`: `Vault.add` without the GIL.
fn add_at(
    path: &str,
    key: &str,
    value: &str,
    tier: Option<&str>,
    desc: Option<&str>,
    tags: Option<Vec<String>>,
) -> PyResult<Written> {
    if !crate::is_valid_key_name(key) {
        return Err(fail(format!(
            "invalid key name: {key}. Keys must start with a letter or underscore and contain only [A-Za-z0-9_]"
        )));
    }
    let tier = tier.map(SecretTier::parse);
    let tags = tags.unwrap_or_default();

    // Lock, then load fresh from disk so a concurrent write isn't clobbered:
    // the same read-modify-write as `murk add` and the Node binding.
    let _lock = crate::vault::lock(Path::new(path)).map_err(fail)?;
    let (mut vault, murk, identity) = crate::load_vault(path).map_err(|e| load_error(&e))?;
    crate::ensure_writable(&murk).map_err(fail)?;
    let pubkey = identity.pubkey_string().map_err(fail)?;
    let original = murk.clone();
    let mut current = murk;

    crate::set_secret(
        &mut vault,
        &mut current,
        key,
        value,
        desc,
        None,
        tier.as_ref(),
        &tags,
        &pubkey,
    )
    .map_err(fail)?;

    // Check the agent policy over the resulting key before saving, so a
    // forbidden write leaves the vault on disk untouched.
    policy::enforce_agent_policy(&vault, &current, &pubkey, &[key.to_string()]).map_err(fail)?;

    crate::save_vault(path, &mut vault, &original, &current).map_err(|e| load_error(&e))?;
    Ok(Written {
        vault,
        murk: current,
        pubkey,
    })
}

/// Describe a key in the vault at `path`: `Vault.describe` without the GIL.
fn describe_at(
    path: &str,
    key: &str,
    description: &str,
    tags: Option<Vec<String>>,
    example: Option<&str>,
) -> PyResult<Written> {
    let tags = tags.unwrap_or_default();

    let _lock = crate::vault::lock(Path::new(path)).map_err(fail)?;
    let (mut vault, murk, identity) = crate::load_vault(path).map_err(|e| load_error(&e))?;
    crate::ensure_writable(&murk).map_err(fail)?;
    let pubkey = identity.pubkey_string().map_err(fail)?;
    let original = murk.clone();
    let current = murk;

    crate::require_group_access(&vault, &current, key, &pubkey).map_err(|e| load_error(&e))?;

    crate::describe_key(&mut vault, key, description, example, &tags, None, None);

    policy::enforce_agent_policy(&vault, &current, &pubkey, &[key.to_string()]).map_err(fail)?;

    crate::save_vault(path, &mut vault, &original, &current).map_err(|e| load_error(&e))?;
    Ok(Written {
        vault,
        murk: current,
        pubkey,
    })
}

/// Load a murk vault. Finds the key the same way the CLI does: `MURK_KEY`,
/// `MURK_KEY_FILE`, or the key file `murk init` stored. Raises `TrustError`
/// when this machine does not trust the vault.
#[pyfunction]
#[pyo3(signature = (vault_path=".murk"))]
fn load(vault_path: &str) -> PyResult<Vault> {
    let path = absolute_path(vault_path)?;
    // The load itself uses the path as given, so its messages match the CLI's.
    let (vault, murk, identity) = crate::load_vault(vault_path).map_err(|e| load_error(&e))?;
    let pubkey = identity
        .pubkey_string()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(Vault {
        inner: vault,
        decrypted: murk,
        pubkey,
        path,
    })
}

/// One-liner: load the vault and get a single key.
#[pyfunction]
#[pyo3(signature = (key, vault_path=".murk"))]
fn get(key: &str, vault_path: &str) -> PyResult<Option<String>> {
    let v = load(vault_path)?;
    v.get(key)
}

/// One-liner: load the vault and export all secrets as a dict.
#[pyfunction]
#[pyo3(signature = (vault_path=".murk"))]
fn export_all(vault_path: &str) -> PyResult<HashMap<String, String>> {
    let v = load(vault_path)?;
    v.export()
}

/// Experimental. One-liner: load the vault and store a secret. See `Vault.add`.
#[pyfunction]
#[pyo3(signature = (key, value, vault_path=".murk", *, tier=None, desc=None, tags=None))]
fn add(
    py: Python<'_>,
    key: &str,
    value: &str,
    vault_path: &str,
    tier: Option<&str>,
    desc: Option<&str>,
    tags: Option<Vec<String>>,
) -> PyResult<()> {
    // The load refuses an untrusted vault with the CLI's message. The write
    // then reloads it under the lock, as `Vault.add` does.
    let path = load(vault_path)?.path;
    py.detach(|| add_at(&path, key, value, tier, desc, tags))
        .map(drop)
}

/// Whether murk can find a key for `./.murk`: MURK_KEY, MURK_KEY_FILE or the key
/// file `murk init` stored. This does not read the vault, so True does not mean
/// load() succeeds. It does not check whether a secret exists; use
/// `key in vault` / Vault.keys for that.
#[pyfunction]
fn has_identity() -> bool {
    env::resolve_key().is_ok()
}

/// Python module definition.
#[pymodule]
fn murk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::set_component("murk-secrets python binding", env!("CARGO_PKG_VERSION"));
    m.add_class::<Vault>()?;
    m.add("TrustError", m.py().get_type::<TrustError>())?;
    m.add_function(wrap_pyfunction!(load, m)?)?;
    m.add_function(wrap_pyfunction!(get, m)?)?;
    m.add_function(wrap_pyfunction!(export_all, m)?)?;
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(has_identity, m)?)?;
    Ok(())
}
