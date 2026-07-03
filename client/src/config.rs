//! Configuration file (~/.config/dotmage/config.toml) handling.
//!
//! Multi-server config (v2): named servers with optional directory mappings,
//! resolved per invocation like git's `includeIf` — flag > env var > path match
//! > active default. A single-server config behaves exactly like v1.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A named server entry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerEntry {
    /// Server base URL.
    pub url: String,
    /// Directories mapped to this server (`~` is expanded at match time).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Device name for this machine on this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

/// Resolved dotMage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Legacy single-server URL (v1). Migrated into `servers` on load;
    /// at runtime holds the RESOLVED url (never persisted once servers exist).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// Name of the fallback server for unmapped directories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_server: Option<String>,
    /// Named servers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub servers: BTreeMap<String, ServerEntry>,
    /// Device name for this machine.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Active environment (per-project or global default).
    #[serde(default = "default_env")]
    pub active_env: String,
    /// TTL for keychain cache in seconds (default 7 days).
    #[serde(default = "default_ttl")]
    pub key_ttl_secs: u64,
    /// List of protected environment names.
    #[serde(default = "default_protected")]
    pub protected_envs: Vec<String>,
    /// Path to FsBackend root (for local mode).
    #[serde(default)]
    pub fs_backend_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: None,
            active_server: None,
            servers: BTreeMap::new(),
            device_name: None,
            active_env: default_env(),
            key_ttl_secs: default_ttl(),
            protected_envs: default_protected(),
            fs_backend_path: None,
        }
    }
}

fn default_env() -> String {
    "dev".into()
}

fn default_ttl() -> u64 {
    7 * 24 * 3600 // 7 days
}

fn default_protected() -> Vec<String> {
    vec!["prod".into(), "production".into()]
}

/// How a server was picked for this invocation (for status/error messages).
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedVia {
    Flag,
    EnvVar,
    PathMatch(PathBuf),
    ActiveDefault,
    CiToken,
}

/// Outcome of server resolution.
#[derive(Debug, Clone)]
pub struct ResolvedServer {
    pub name: String,
    pub url: String,
    pub via: ResolvedVia,
}

impl Config {
    /// Default config directory: ~/.config/dotmage/
    pub fn default_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("dotmage")
    }

    pub fn default_path() -> PathBuf {
        Self::default_dir().join("config.toml")
    }

    /// Load from default path, returning defaults if file doesn't exist.
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load_from(&path)
    }

    /// Load from a specific path.
    pub fn load_from(path: &PathBuf) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path)?;
        toml::from_str(&data).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Save config to default path. The runtime-resolved `server_url` is never
    /// persisted alongside named servers.
    pub fn save(&self) -> Result<(), ConfigError> {
        let mut to_save = self.clone();
        if !to_save.servers.is_empty() {
            to_save.server_url = None;
        }
        let path = Self::default_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data =
            toml::to_string_pretty(&to_save).map_err(|e| ConfigError::Parse(e.to_string()))?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Migrate a legacy v1 config (`server_url = "..."`) into `servers.default`.
    /// One-way, idempotent. Returns true if anything changed (caller saves).
    pub fn migrate_legacy(&mut self) -> bool {
        match self.server_url.take() {
            Some(url) if self.servers.is_empty() => {
                self.servers.insert(
                    "default".into(),
                    ServerEntry {
                        url,
                        paths: Vec::new(),
                        device_name: self.device_name.clone(),
                    },
                );
                self.active_server = Some("default".into());
                true
            }
            Some(_) => true, // stale legacy key next to named servers — drop it
            None => false,
        }
    }

    /// Resolve which server this invocation talks to:
    /// `flag` > `DOTMAGE_SERVER` > path match (longest prefix) > active/default.
    /// `Ok(None)` = local mode (no servers configured).
    pub fn resolve_server(
        &self,
        flag: Option<&str>,
        cwd: &Path,
    ) -> Result<Option<ResolvedServer>, ConfigError> {
        if let Some(name) = flag {
            return self.lookup(name, ResolvedVia::Flag).map(Some);
        }
        if let Ok(name) = std::env::var("DOTMAGE_SERVER") {
            if !name.is_empty() {
                return self.lookup(&name, ResolvedVia::EnvVar).map(Some);
            }
        }
        if let Some(resolved) = self.match_path(cwd)? {
            return Ok(Some(resolved));
        }
        if let Some(name) = &self.active_server {
            if let Ok(r) = self.lookup(name, ResolvedVia::ActiveDefault) {
                return Ok(Some(r));
            }
        }
        match self.servers.len() {
            0 => Ok(None),
            1 => {
                let (name, entry) = self.servers.iter().next().unwrap();
                Ok(Some(ResolvedServer {
                    name: name.clone(),
                    url: entry.url.clone(),
                    via: ResolvedVia::ActiveDefault,
                }))
            }
            _ => Err(ConfigError::Ambiguous {
                candidates: self.servers.keys().cloned().collect(),
            }),
        }
    }

    fn lookup(&self, name: &str, via: ResolvedVia) -> Result<ResolvedServer, ConfigError> {
        self.servers
            .get(name)
            .map(|e| ResolvedServer {
                name: name.to_string(),
                url: e.url.clone(),
                via,
            })
            .ok_or_else(|| ConfigError::UnknownServer {
                name: name.to_string(),
                known: self.servers.keys().cloned().collect(),
            })
    }

    /// Longest canonical-prefix match of `cwd` against all mapped paths.
    /// An exact tie between two different servers is an error, not a coin flip.
    fn match_path(&self, cwd: &Path) -> Result<Option<ResolvedServer>, ConfigError> {
        let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());

        let mut best_depth = 0usize;
        let mut best: Vec<(String, String, PathBuf)> = Vec::new(); // (name, url, matched path)

        for (name, entry) in &self.servers {
            for p in &entry.paths {
                let expanded = expand_tilde(p);
                let canon = expanded.canonicalize().unwrap_or(expanded);
                if cwd.starts_with(&canon) {
                    let depth = canon.components().count();
                    match depth.cmp(&best_depth) {
                        std::cmp::Ordering::Greater => {
                            best_depth = depth;
                            best = vec![(name.clone(), entry.url.clone(), canon)];
                        }
                        std::cmp::Ordering::Equal => {
                            best.push((name.clone(), entry.url.clone(), canon))
                        }
                        std::cmp::Ordering::Less => {}
                    }
                }
            }
        }

        best.dedup_by(|a, b| a.0 == b.0);
        match best.len() {
            0 => Ok(None),
            1 => {
                let (name, url, path) = best.remove(0);
                Ok(Some(ResolvedServer {
                    name,
                    url,
                    via: ResolvedVia::PathMatch(path),
                }))
            }
            _ => Err(ConfigError::Ambiguous {
                candidates: best.into_iter().map(|(n, _, _)| n).collect(),
            }),
        }
    }

    /// Resolve the FsBackend root directory.
    pub fn fs_root(&self) -> PathBuf {
        self.fs_backend_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| Self::default_dir().join("local"))
    }

    /// Resolve the server identifier for keychain.
    pub fn server_id(&self) -> String {
        self.server_url.clone().unwrap_or_else(|| "local".into())
    }

    /// Check if an environment name is protected (prod-guard).
    pub fn is_protected_env(&self, env: &str) -> bool {
        self.protected_envs.iter().any(|p| p == env)
    }
}

/// Expand a leading `~` / `~/` to the user's home directory.
pub fn expand_tilde(p: &str) -> PathBuf {
    if p == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
}

/// Render a path `~/`-relative when it is under the home directory.
pub fn contract_tilde(p: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(rest) = p.strip_prefix(&home) {
            return format!("~/{}", rest.display());
        }
    }
    p.display().to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unknown server '{name}' — known: {}", known.join(", "))]
    UnknownServer { name: String, known: Vec<String> },
    #[error("cannot pick a server — candidates: {}. Use --server <name> or: dmage server use <name>", candidates.join(", "))]
    Ambiguous { candidates: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str, paths: &[&str]) -> ServerEntry {
        ServerEntry {
            url: url.into(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            device_name: None,
        }
    }

    #[test]
    fn legacy_config_migrates_once() {
        let mut cfg = Config {
            server_url: Some("https://a.example".into()),
            ..Default::default()
        };
        assert!(cfg.migrate_legacy());
        assert_eq!(cfg.active_server.as_deref(), Some("default"));
        assert_eq!(cfg.servers["default"].url, "https://a.example");
        assert!(cfg.server_url.is_none());
        assert!(!cfg.migrate_legacy()); // idempotent
    }

    #[test]
    fn no_servers_resolves_to_local_mode() {
        let cfg = Config::default();
        assert!(cfg
            .resolve_server(None, Path::new("/anywhere"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn single_server_is_implicit_default() {
        let mut cfg = Config::default();
        cfg.servers.insert("work".into(), entry("https://w", &[]));
        let r = cfg
            .resolve_server(None, Path::new("/anywhere"))
            .unwrap()
            .unwrap();
        assert_eq!(r.name, "work");
        assert_eq!(r.via, ResolvedVia::ActiveDefault);
    }

    #[test]
    fn flag_beats_everything() {
        let mut cfg = Config::default();
        cfg.servers
            .insert("a".into(), entry("https://a", &["/tmp"]));
        cfg.servers.insert("b".into(), entry("https://b", &[]));
        cfg.active_server = Some("a".into());
        let r = cfg
            .resolve_server(Some("b"), Path::new("/tmp"))
            .unwrap()
            .unwrap();
        assert_eq!(r.name, "b");
        assert_eq!(r.via, ResolvedVia::Flag);
    }

    #[test]
    fn unknown_flag_name_errors_with_candidates() {
        let mut cfg = Config::default();
        cfg.servers.insert("work".into(), entry("https://w", &[]));
        let err = cfg
            .resolve_server(Some("wrok"), Path::new("/"))
            .unwrap_err();
        assert!(err.to_string().contains("wrok") && err.to_string().contains("work"));
    }

    #[test]
    fn longest_path_prefix_wins() {
        let dir = std::env::temp_dir().join("dmage-cfg-test");
        let nested = dir.join("work").join("oss");
        std::fs::create_dir_all(&nested).unwrap();

        let mut cfg = Config::default();
        cfg.servers.insert(
            "work".into(),
            entry("https://w", &[dir.join("work").to_str().unwrap()]),
        );
        cfg.servers.insert(
            "oss".into(),
            entry("https://o", &[nested.to_str().unwrap()]),
        );

        let r = cfg.resolve_server(None, &nested).unwrap().unwrap();
        assert_eq!(r.name, "oss");
        let r = cfg
            .resolve_server(None, &dir.join("work"))
            .unwrap()
            .unwrap();
        assert_eq!(r.name, "work");
    }

    #[test]
    fn unmapped_cwd_with_two_servers_and_no_default_is_ambiguous() {
        let mut cfg = Config::default();
        cfg.servers.insert("a".into(), entry("https://a", &[]));
        cfg.servers.insert("b".into(), entry("https://b", &[]));
        assert!(matches!(
            cfg.resolve_server(None, Path::new("/anywhere")),
            Err(ConfigError::Ambiguous { .. })
        ));
        cfg.active_server = Some("b".into());
        let r = cfg
            .resolve_server(None, Path::new("/anywhere"))
            .unwrap()
            .unwrap();
        assert_eq!(r.name, "b");
    }
}
