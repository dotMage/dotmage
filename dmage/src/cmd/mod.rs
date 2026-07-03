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
pub mod server;
pub mod status;
pub mod token_cmd;
pub mod upgrade;

pub mod gen_ci_token;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use dotmage_client::backend::Backend;
use dotmage_client::backend_fs::FsBackend;
use dotmage_client::backend_http::HttpBackend;
use dotmage_client::config::{Config, ResolvedVia};
use dotmage_client::container::{self, Decoded, FileFormat, FileMeta};
use dotmage_client::keychain;
use dotmage_client::token;
use dotmage_client::types::RevSpec;
use dotmage_crypto::{blob, secret};
use std::process::ExitCode;

/// Shared context for all commands.
pub struct Context {
    pub config: Config,
    pub backend: Box<dyn Backend>,
    pub active_env: String,
    /// Resolved server (name, how it was picked). None = local mode.
    /// The resolved URL lives in `config.server_url` for the duration of the run.
    pub server: Option<(String, ResolvedVia)>,
    pub quiet: bool,
    #[allow(dead_code)]
    pub json: bool,
    /// Cached AK (loaded on demand).
    ak: Option<[u8; 32]>,
}

impl Context {
    pub fn load(
        env_override: Option<String>,
        server_override: Option<String>,
        quiet: bool,
        json: bool,
    ) -> Result<Self, CliError> {
        let mut config = Config::load().map_err(|e| CliError::Config(e.to_string()))?;
        if config.migrate_legacy() {
            config.save().map_err(|e| CliError::Config(e.to_string()))?;
        }
        let active_env = env_override.unwrap_or_else(|| config.active_env.clone());

        // Check for DOTMAGE_CI_TOKEN env var (CI mode)
        if let Ok(ci_token) = std::env::var("DOTMAGE_CI_TOKEN") {
            return Self::load_from_ci_token(&config, active_env, quiet, json, &ci_token);
        }

        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let resolved = config
            .resolve_server(server_override.as_deref(), &cwd)
            .map_err(|e| CliError::Config(e.to_string()))?;

        let (backend, server): (Box<dyn Backend>, _) = match resolved {
            Some(r) => {
                config.server_url = Some(r.url.clone());
                let server_hash = keychain::server_hash(&r.url);
                let device_token = token::load_tokens(&server_hash)
                    .ok()
                    .flatten()
                    .map(|t| t.device_token)
                    .unwrap_or_default();
                (
                    Box::new(HttpBackend::new(&r.url, &device_token)),
                    Some((r.name, r.via)),
                )
            }
            None => (Box::new(FsBackend::new(config.fs_root())), None),
        };

        Ok(Self {
            config,
            backend,
            active_env,
            server,
            quiet,
            json,
            ak: None,
        })
    }

    /// Resolve the app name: explicit argument, or the current directory's basename.
    pub fn app_name(&self, explicit: Option<&str>) -> Result<String, CliError> {
        if let Some(name) = explicit {
            return Ok(name.to_string());
        }
        std::env::current_dir()
            .ok()
            .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                CliError::Other("cannot infer app name from directory — pass it explicitly".into())
            })
    }

    /// `" → name (host)"` suffix for mutating-command output.
    /// Empty with 0–1 configured servers: a solo user never sees multi-server UI.
    pub fn server_suffix(&self) -> String {
        if self.config.servers.len() > 1 {
            if let (Some((name, _)), Some(url)) = (&self.server, &self.config.server_url) {
                return format!("  \x1b[90m→ {name} ({})\x1b[0m", host_of(url));
            }
        }
        String::new()
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
            server: Some(("ci".into(), ResolvedVia::CiToken)),
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

    /// Pull a revision, decrypt it, and unwrap the file container.
    /// Returns (rev_number, decoded payload with metadata).
    pub fn pull_decoded(&mut self, app: &str, rev: &RevSpec) -> Result<(u64, Decoded), CliError> {
        let ak = self.require_ak()?;
        let env_name = self.active_env.clone();
        let revision = self.backend.pull_revision(app, &env_name, rev)?;
        let decoded_blob =
            blob::decode_blob(&revision.blob).map_err(|e| CliError::Crypto(e.to_string()))?;
        let plaintext =
            secret::decrypt_secret(&ak, &decoded_blob, app, &env_name, revision.rev_number)
                .map_err(|e| CliError::Crypto(e.to_string()))?;
        Ok((revision.rev_number, container::decode(&plaintext)))
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

/// Strip scheme and trailing slash from a URL for compact display.
pub fn host_of(url: &str) -> &str {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
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

/// Empty-push guard: an empty file is almost always an accident
/// (truncated file, wrong CWD) that would wipe remote secrets on next pull.
/// env format: 0 parsed keys; other formats: 0 bytes.
pub fn empty_guard(
    file: &str,
    data: &[u8],
    format: FileFormat,
    allow_empty: bool,
) -> Result<(), CliError> {
    if allow_empty {
        return Ok(());
    }
    let what = match format {
        FileFormat::Env if count_env_keys(data) == 0 => "0 keys",
        _ if data.is_empty() => "0 bytes",
        _ => return Ok(()),
    };
    Err(CliError::Other(format!(
        "{file} is empty ({what}) — refusing to push.\n         if this is intentional, re-run with --allow-empty"
    )))
}

/// Detect the content format from a file name (extension family), falling
/// back to a UTF-8 sniff of the content.
pub fn detect_format(file_name: &str, data: &[u8]) -> FileFormat {
    let base = file_name.to_ascii_lowercase();
    if base == ".env" || base.starts_with(".env.") || base.ends_with(".env") {
        return FileFormat::Env;
    }
    let ext = base.rsplit('.').next().unwrap_or("");
    match ext {
        "xml" | "json" | "yaml" | "yml" | "toml" | "ini" | "properties" | "conf" | "cfg"
        | "txt" => FileFormat::Text,
        _ => {
            if std::str::from_utf8(data).is_ok() {
                FileFormat::Text
            } else {
                FileFormat::Binary
            }
        }
    }
}

/// Human description of a payload for success messages:
/// `12 keys` for env, `4.2 KB, text` otherwise.
pub fn describe_payload(meta: &FileMeta, data: &[u8]) -> String {
    match meta.format {
        FileFormat::Env => format!("{} keys", count_env_keys(data)),
        _ => format!("{}, {}", human_size(data.len()), meta.format.as_str()),
    }
}

pub fn human_size(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// File basename for storage in the container manifest.
pub fn file_basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
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
        assert!(empty_guard(".env", b"# only comments\n", FileFormat::Env, false).is_err());
        assert!(empty_guard(".env", b"", FileFormat::Env, false).is_err());
        assert!(empty_guard("a.xml", b"", FileFormat::Text, false).is_err());
    }

    #[test]
    fn empty_guard_respects_allow_empty() {
        assert!(empty_guard(".env", b"", FileFormat::Env, true).is_ok());
        assert!(empty_guard(".env", b"A=1\n", FileFormat::Env, false).is_ok());
        // non-env: content without KEY=VALUE lines is fine, only 0 bytes blocks
        assert!(empty_guard("a.xml", b"<x/>", FileFormat::Text, false).is_ok());
    }

    #[test]
    fn format_detection() {
        assert_eq!(detect_format(".env", b""), FileFormat::Env);
        assert_eq!(detect_format(".env.production", b""), FileFormat::Env);
        assert_eq!(detect_format("dataSources.xml", b"<x/>"), FileFormat::Text);
        assert_eq!(detect_format("cfg.yaml", b""), FileFormat::Text);
        assert_eq!(detect_format("blob.bin", &[0xff, 0xfe]), FileFormat::Binary);
        assert_eq!(detect_format("noext", b"plain text"), FileFormat::Text);
    }
}
