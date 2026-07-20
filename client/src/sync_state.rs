//! Per-directory sync base marker for `dmage sync`.
//!
//! Stored device-level alongside `tokens.json` (via [`Config::default_dir`]) —
//! **never** inside the project repo. Keyed by (server, app, env, canonical
//! working directory). Holds only the last-synced revision number, a content
//! hash and the synced file name — no plaintext secrets (consistent with the
//! "content_hash is local-only" spec decision).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SyncStore {
    /// composite key (see `key`) → entry
    entries: HashMap<String, SyncEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEntry {
    /// Remote revision the local file was last synced to.
    pub base_rev: u64,
    /// sha256 (hex) of the local file bytes at that sync.
    pub hash: String,
    /// Local file name that was synced (so the bare-`dmage` hint reads the right file).
    pub file: String,
}

fn store_path() -> PathBuf {
    Config::default_dir().join("sync_state.json")
}

fn key(server_hash: &str, app: &str, env: &str, dir: &str) -> String {
    // NUL separator — can't appear in any component.
    format!("{server_hash}\u{0}{app}\u{0}{env}\u{0}{dir}")
}

pub fn load(server_hash: &str, app: &str, env: &str, dir: &str) -> Option<SyncEntry> {
    let store = load_store().ok()?;
    store.entries.get(&key(server_hash, app, env, dir)).cloned()
}

pub fn save(
    server_hash: &str,
    app: &str,
    env: &str,
    dir: &str,
    entry: SyncEntry,
) -> Result<(), SyncStateError> {
    let mut store = load_store()?;
    store.entries.insert(key(server_hash, app, env, dir), entry);
    let path = store_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data =
        serde_json::to_string_pretty(&store).map_err(|e| SyncStateError::Other(e.to_string()))?;
    std::fs::write(path, data)?;
    Ok(())
}

fn load_store() -> Result<SyncStore, SyncStateError> {
    let path = store_path();
    if !path.exists() {
        return Ok(SyncStore::default());
    }
    let data = std::fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(|e| SyncStateError::Other(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum SyncStateError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
