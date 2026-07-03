//! AK storage with TTL (spec A.7).
//!
//! Stores AK in a local file. OS keychain requires code-signed binaries
//! on macOS, so file storage is used as the reliable default.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct AkStore {
    ak: String,
    expiry: u64,
    /// AK generation (spec L); pre-rotation caches default to 1.
    #[serde(default = "crate::types::default_key_gen")]
    key_gen: u64,
}

fn ak_file_path(server_hash: &str) -> PathBuf {
    crate::config::Config::default_dir().join(format!("ak_{server_hash}.json"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Store AK with expiry.
pub fn store_ak(server_hash: &str, ak: &[u8; 32], ttl_secs: u64) -> Result<(), KeychainError> {
    store_ak_gen(server_hash, ak, 1, ttl_secs)
}

/// Store AK with its key generation (spec L).
pub fn store_ak_gen(
    server_hash: &str,
    ak: &[u8; 32],
    key_gen: u64,
    ttl_secs: u64,
) -> Result<(), KeychainError> {
    let store = AkStore {
        ak: B64.encode(ak),
        expiry: now_secs() + ttl_secs,
        key_gen,
    };
    let path = ak_file_path(server_hash);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string(&store).map_err(|e| KeychainError::Other(e.to_string()))?;
    std::fs::write(&path, data)?;

    // Restrict file permissions (owner-only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Load AK, checking expiry. Returns None if expired or missing.
pub fn load_ak(server_hash: &str) -> Result<Option<[u8; 32]>, KeychainError> {
    Ok(load_ak_gen(server_hash)?.map(|(ak, _)| ak))
}

/// Load AK with its key generation. Returns None if expired or missing.
pub fn load_ak_gen(server_hash: &str) -> Result<Option<([u8; 32], u64)>, KeychainError> {
    let path = ak_file_path(server_hash);
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read_to_string(&path)?;
    let store: AkStore =
        serde_json::from_str(&data).map_err(|e| KeychainError::Other(e.to_string()))?;

    if now_secs() > store.expiry {
        let _ = std::fs::remove_file(&path);
        return Ok(None);
    }

    decode_ak(&store.ak).map(|ak| Some((ak, store.key_gen)))
}

/// Delete stored AK.
pub fn delete_ak(server_hash: &str) -> Result<(), KeychainError> {
    let _ = std::fs::remove_file(ak_file_path(server_hash));
    Ok(())
}

fn decode_ak(b64: &str) -> Result<[u8; 32], KeychainError> {
    let bytes = B64
        .decode(b64)
        .map_err(|e| KeychainError::Other(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| KeychainError::Other("AK must be 32 bytes".into()))
}

/// Compute a short hash of server URL for storage key naming.
pub fn server_hash(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(url.as_bytes());
    hex::encode(&hash[..8])
}

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Other(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}
