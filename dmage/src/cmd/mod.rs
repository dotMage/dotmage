//! CLI command implementations.

pub mod app_rm;
pub mod apps;
pub mod auth;
pub mod clean;
pub mod diff;
pub mod env;
pub mod exec;
pub mod gen_token;
pub mod history;
pub mod init;
pub mod lock;
pub mod pull;
pub mod push;
pub mod rollback;
pub mod status;
pub mod token_cmd;
pub mod upgrade;

pub mod gen_ci_token;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use dotmage_client::backend::Backend;
use dotmage_client::backend_fs::FsBackend;
use dotmage_client::backend_http::HttpBackend;
use dotmage_client::config::Config;
use dotmage_client::keychain;
use dotmage_client::token;
use std::process::ExitCode;

/// Shared context for all commands.
pub struct Context {
    pub config: Config,
    pub backend: Box<dyn Backend>,
    pub active_env: String,
    pub quiet: bool,
    #[allow(dead_code)]
    pub json: bool,
    /// Cached AK (loaded on demand).
    ak: Option<[u8; 32]>,
}

impl Context {
    pub fn load(env_override: Option<String>, quiet: bool, json: bool) -> Result<Self, CliError> {
        let config = Config::load().map_err(|e| CliError::Config(e.to_string()))?;
        let active_env = env_override.unwrap_or_else(|| config.active_env.clone());

        // Check for DOTMAGE_CI_TOKEN env var (CI mode)
        if let Ok(ci_token) = std::env::var("DOTMAGE_CI_TOKEN") {
            return Self::load_from_ci_token(&config, active_env, quiet, json, &ci_token);
        }

        let backend: Box<dyn Backend> = if let Some(ref url) = config.server_url {
            // HTTP mode — connect to server
            let server_hash = keychain::server_hash(url);
            let device_token = token::load_tokens(&server_hash)
                .ok()
                .flatten()
                .map(|t| t.device_token)
                .unwrap_or_default();
            Box::new(HttpBackend::new(url, &device_token))
        } else {
            // Local mode — FsBackend
            Box::new(FsBackend::new(config.fs_root()))
        };

        Ok(Self {
            config,
            backend,
            active_env,
            quiet,
            json,
            ak: None,
        })
    }

    fn load_from_ci_token(
        config: &Config,
        active_env: String,
        quiet: bool,
        json: bool,
        ci_token: &str,
    ) -> Result<Self, CliError> {
        let blob = ci_token.strip_prefix("dmage_ci_").unwrap_or(ci_token);
        let decoded = B64URL
            .decode(blob)
            .map_err(|e| CliError::Other(format!("invalid CI token: {e}")))?;
        let payload: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| CliError::Other(format!("invalid CI token payload: {e}")))?;

        let device_token = payload["t"]
            .as_str()
            .ok_or_else(|| CliError::Other("CI token missing device_token".into()))?;
        let ak_b64 = payload["k"]
            .as_str()
            .ok_or_else(|| CliError::Other("CI token missing AK".into()))?;

        // Server URL from token, fallback to config
        let url = payload["s"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| config.server_url.clone())
            .ok_or_else(|| CliError::Config("CI token missing server URL".into()))?;

        let ak_bytes = B64
            .decode(ak_b64)
            .map_err(|e| CliError::Other(format!("invalid AK in CI token: {e}")))?;
        let ak: [u8; 32] = ak_bytes
            .try_into()
            .map_err(|_| CliError::Other("AK must be 32 bytes".into()))?;

        let mut ci_config = config.clone();
        ci_config.server_url = Some(url.clone());
        let backend: Box<dyn Backend> = Box::new(HttpBackend::new(&url, device_token));

        Ok(Self {
            config: ci_config,
            backend,
            active_env,
            quiet,
            json,
            ak: Some(ak),
        })
    }

    /// Get AK from keychain cache. Returns error code 3 if not available.
    pub fn require_ak(&mut self) -> Result<[u8; 32], CliError> {
        if let Some(ak) = self.ak {
            return Ok(ak);
        }

        let server_hash = keychain::server_hash(&self.config.server_id());
        match keychain::load_ak(&server_hash) {
            Ok(Some(ak)) => {
                self.ak = Some(ak);
                Ok(ak)
            }
            Ok(None) => Err(CliError::NotAuthenticated),
            Err(e) => Err(CliError::Keychain(e.to_string())),
        }
    }

    /// Switch to server mode: save URL, recreate backend.
    pub fn set_server(&mut self, url: &str) -> Result<(), CliError> {
        self.config.server_url = Some(url.to_string());
        self.config
            .save()
            .map_err(|e| CliError::Config(e.to_string()))?;

        let server_hash = keychain::server_hash(url);
        let device_token = token::load_tokens(&server_hash)
            .ok()
            .flatten()
            .map(|t| t.device_token)
            .unwrap_or_default();
        self.backend = Box::new(HttpBackend::new(url, &device_token));
        Ok(())
    }

    /// Recreate HTTP backend with fresh tokens from disk (after registration).
    pub fn refresh_backend(&mut self) -> Result<(), CliError> {
        if let Some(ref url) = self.config.server_url {
            let server_hash = keychain::server_hash(url);
            let device_token = token::load_tokens(&server_hash)
                .ok()
                .flatten()
                .map(|t| t.device_token)
                .unwrap_or_default();
            self.backend = Box::new(HttpBackend::new(url, &device_token));
        }
        Ok(())
    }

    pub fn print(&self, msg: &str) {
        if !self.quiet {
            println!("  {msg}");
        }
    }

    pub fn success(&self, msg: &str) {
        if !self.quiet {
            println!("  \x1b[32m✓\x1b[0m {msg}");
        }
    }
}

/// Count KEY=VALUE lines in .env content (comments and blanks excluded).
pub fn count_env_keys(data: &[u8]) -> usize {
    String::from_utf8_lossy(data)
        .lines()
        .filter(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('#') && l.contains('=')
        })
        .count()
}

/// Empty-push guard: a file with 0 keys is almost always an accident
/// (truncated file, wrong CWD) that would wipe remote secrets on next pull.
pub fn empty_guard(file: &str, data: &[u8], allow_empty: bool) -> Result<(), CliError> {
    if !allow_empty && count_env_keys(data) == 0 {
        return Err(CliError::Other(format!(
            "{file} is empty (0 keys) — refusing to push.\n         if this is intentional, re-run with --allow-empty"
        )));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Config(String),
    #[error("not authenticated — run: dmage auth")]
    NotAuthenticated,
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("{0}")]
    Backend(#[from] dotmage_client::backend::BackendError),
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl CliError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            CliError::NotAuthenticated => ExitCode::from(3),
            CliError::Backend(dotmage_client::backend::BackendError::Conflict(_)) => {
                ExitCode::from(4)
            }
            CliError::Backend(dotmage_client::backend::BackendError::NotFound(_)) => {
                ExitCode::from(1)
            }
            _ => ExitCode::from(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_has_zero_keys() {
        assert_eq!(count_env_keys(b""), 0);
        assert_eq!(count_env_keys(b"\n\n  \n"), 0);
    }

    #[test]
    fn comments_only_has_zero_keys() {
        assert_eq!(count_env_keys(b"# a comment\n  # another\n"), 0);
    }

    #[test]
    fn empty_value_counts_as_key() {
        assert_eq!(count_env_keys(b"FOO=\n"), 1);
        assert_eq!(count_env_keys(b"A=1\nB=2\n# c\n"), 2);
    }

    #[test]
    fn empty_guard_blocks_without_flag() {
        assert!(empty_guard(".env", b"# only comments\n", false).is_err());
        assert!(empty_guard(".env", b"", false).is_err());
    }

    #[test]
    fn empty_guard_respects_allow_empty() {
        assert!(empty_guard(".env", b"", true).is_ok());
        assert!(empty_guard(".env", b"A=1\n", false).is_ok());
    }
}
