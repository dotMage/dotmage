//! `dmage upgrade` — self-update from GitHub releases.
//!
//! Trust chain: pinned repo over HTTPS → release → SHA256SUMS → binary.
//! A release without SHA256SUMS is refused. Package-manager installs
//! (Homebrew, cargo) are delegated to their package manager.
// TODO(minisign): sign SHA256SUMS and verify with an embedded public key.

use sha2::{Digest, Sha256};
use std::path::Path;

use super::{CliError, Context};

const REPO: &str = "dotMage/dotmage";
const CURRENT: &str = env!("CARGO_PKG_VERSION");

pub fn run(
    ctx: &Context,
    check_only: bool,
    version: Option<&str>,
    force: bool,
    yes: bool,
    channel: &str,
) -> Result<(), CliError> {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| CliError::Other(format!("cannot locate current binary: {e}")))?;

    let channel = match channel {
        "stable" | "dev" => channel,
        other => {
            return Err(CliError::Other(format!(
                "unknown channel '{other}' — use stable or dev"
            )))
        }
    };
    let release = fetch_release(version, channel)?;
    let target = release.version.clone();

    ctx.print(&format!("current  v{CURRENT}"));
    ctx.print(&format!("latest   v{target}"));

    if check_only {
        if semver_gt(&target, CURRENT) {
            ctx.print("run: dmage upgrade");
        } else {
            ctx.print("up to date");
        }
        return Ok(());
    }

    if let Some(hint) = managed_install_hint(&exe) {
        ctx.print("this dmage is managed by a package manager.");
        ctx.print(&format!("upgrade with: {hint}"));
        return Ok(());
    }

    if !force {
        if target == CURRENT {
            ctx.print("already up to date");
            return Ok(());
        }
        if semver_gt(CURRENT, &target) {
            return Err(CliError::Other(format!(
                "v{target} is older than the current v{CURRENT} — pass --force to downgrade"
            )));
        }
    }

    let asset_name = platform_asset()?;

    if !yes {
        eprint!("  upgrade v{CURRENT} → v{target}? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            return Err(CliError::Other("aborted".into()));
        }
    }

    // Integrity first: a release without SHA256SUMS is not installable.
    let sums_url = release.asset_url("SHA256SUMS").ok_or_else(|| {
        CliError::Other(format!(
            "release v{target} has no SHA256SUMS — refusing to install unverifiable binaries"
        ))
    })?;
    let asset_url = release
        .asset_url(asset_name)
        .ok_or_else(|| CliError::Other(format!("release v{target} has no asset {asset_name}")))?;

    let client = download_client()?;
    let sums = client
        .get(&sums_url)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
        .map_err(|e| CliError::Other(format!("downloading SHA256SUMS: {e}")))?;
    let expected = parse_sha256sums(&sums, asset_name)
        .ok_or_else(|| CliError::Other(format!("SHA256SUMS has no entry for {asset_name}")))?;

    ctx.print(&format!("downloading {asset_name}..."));
    let binary = client
        .get(&asset_url)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.bytes())
        .map_err(|e| CliError::Other(format!("downloading {asset_name}: {e}")))?;

    let actual = hex::encode(Sha256::digest(&binary));
    if actual != expected {
        return Err(CliError::Other(format!(
            "sha256 mismatch for {asset_name}:\n         expected {expected}\n         got      {actual}\n         binary NOT installed"
        )));
    }
    ctx.print("sha256 verified");

    // All work happens on a temp file in the same directory (same filesystem →
    // atomic rename); the running binary is untouched until the final swap.
    let tmp = exe.with_file_name(format!(".dmage-upgrade-{}", std::process::id()));
    let install = install_binary(&binary, &tmp, &exe, &target);
    if install.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    install?;

    refresh_update_cache(&target);

    ctx.success(&format!(
        "upgraded to v{target} — notes: https://github.com/{REPO}/releases/tag/v{target}"
    ));
    Ok(())
}

fn install_binary(binary: &[u8], tmp: &Path, exe: &Path, target: &str) -> Result<(), CliError> {
    std::fs::write(tmp, binary).map_err(|e| perm_hint(e, exe))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o755))?;
    }

    // Sanity check: the downloaded binary must run and report the target version.
    let out = std::process::Command::new(tmp)
        .arg("--version")
        .output()
        .map_err(|e| CliError::Other(format!("downloaded binary does not run: {e}")))?;
    let reported = String::from_utf8_lossy(&out.stdout);
    if !reported.contains(target) {
        return Err(CliError::Other(format!(
            "downloaded binary reports '{}', expected v{target} — not installed",
            reported.trim()
        )));
    }

    #[cfg(unix)]
    std::fs::rename(tmp, exe).map_err(|e| perm_hint(e, exe))?;

    #[cfg(windows)]
    {
        self_replace::self_replace(tmp).map_err(|e| perm_hint(e, exe))?;
        let _ = std::fs::remove_file(tmp);
    }

    Ok(())
}

fn perm_hint(e: std::io::Error, exe: &Path) -> CliError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        CliError::Other(format!(
            "no write permission for {} — try: sudo dmage upgrade",
            exe.display()
        ))
    } else {
        CliError::Io(e)
    }
}

/// Detect installs owned by a package manager; self-replacing those would be
/// silently reverted (or corrupt bookkeeping) on the manager's next upgrade.
fn managed_install_hint(exe: &Path) -> Option<&'static str> {
    let p = exe.to_string_lossy();
    if p.contains("/Cellar/") || p.contains("/homebrew/") || p.contains("/linuxbrew/") {
        return Some("brew upgrade dotmage");
    }
    if p.contains("/.cargo/bin/") {
        return Some("cargo install --git https://github.com/dotMage/dotmage.git --force");
    }
    if p.contains("/target/debug/") || p.contains("/target/release/") {
        return Some("cargo build (dev build — not self-updating)");
    }
    None
}

fn platform_asset() -> Result<&'static str, CliError> {
    let name = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "dmage-macos-aarch64"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "dmage-macos-x86_64"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "dmage-linux-x86_64"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "dmage-linux-aarch64"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "dmage-windows-x86_64.exe"
    } else {
        return Err(CliError::Other(
            "no prebuilt binary for this platform — build from source".into(),
        ));
    };
    Ok(name)
}

fn parse_sha256sums(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, name) = line.split_once(char::is_whitespace)?;
        (name.trim().trim_start_matches('*') == asset).then(|| hash.to_string())
    })
}

struct Release {
    version: String,
    assets: Vec<(String, String)>, // (name, download url)
}

impl Release {
    fn asset_url(&self, name: &str) -> Option<String> {
        self.assets
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, u)| u.clone())
    }
}

fn fetch_release(version: Option<&str>, channel: &str) -> Result<Release, CliError> {
    // dev channel: /releases/latest hides prereleases, so list and pick the
    // newest by semver (prereleases included).
    let url = match (version, channel) {
        (Some(v), _) => format!(
            "https://api.github.com/repos/{REPO}/releases/tags/v{}",
            v.trim_start_matches('v')
        ),
        (None, "dev") => format!("https://api.github.com/repos/{REPO}/releases?per_page=30"),
        (None, _) => format!("https://api.github.com/repos/{REPO}/releases/latest"),
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| CliError::Other(e.to_string()))?;

    let resp = client
        .get(&url)
        .header("User-Agent", "dmage-cli")
        .send()
        .map_err(|e| CliError::Other(format!("cannot reach GitHub: {e}")))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(CliError::Other(format!(
            "release not found: {}",
            version.unwrap_or("latest")
        )));
    }
    if resp.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(CliError::Other(
            "GitHub API rate limit hit — try again later".into(),
        ));
    }
    let resp = resp
        .error_for_status()
        .map_err(|e| CliError::Other(e.to_string()))?;

    #[derive(serde::Deserialize)]
    struct GhAsset {
        name: String,
        browser_download_url: String,
    }
    #[derive(serde::Deserialize)]
    struct GhRelease {
        tag_name: String,
        #[serde(default)]
        draft: bool,
        #[serde(default)]
        assets: Vec<GhAsset>,
    }

    let gh: GhRelease = if version.is_none() && channel == "dev" {
        let list: Vec<GhRelease> = resp
            .json()
            .map_err(|e| CliError::Other(format!("bad release JSON: {e}")))?;
        list.into_iter()
            .filter(|r| !r.draft)
            .max_by(|a, b| {
                let (va, vb) = (
                    a.tag_name.trim_start_matches('v'),
                    b.tag_name.trim_start_matches('v'),
                );
                if semver_gt(va, vb) {
                    std::cmp::Ordering::Greater
                } else if semver_gt(vb, va) {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok_or_else(|| CliError::Other("no releases found".into()))?
    } else {
        resp.json()
            .map_err(|e| CliError::Other(format!("bad release JSON: {e}")))?
    };

    Ok(Release {
        version: gh.tag_name.trim_start_matches('v').to_string(),
        assets: gh
            .assets
            .into_iter()
            .map(|a| (a.name, a.browser_download_url))
            .collect(),
    })
}

fn download_client() -> Result<reqwest::blocking::Client, CliError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| CliError::Other(e.to_string()))
}

fn refresh_update_cache(latest: &str) {
    #[derive(serde::Serialize)]
    struct UpdateCache<'a> {
        checked_at: u64,
        latest_version: &'a str,
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cache = UpdateCache {
        checked_at: now,
        latest_version: latest,
    };
    if let Ok(json) = serde_json::to_string(&cache) {
        let path = dotmage_client::config::Config::default_dir().join("update_check.json");
        let _ = std::fs::write(path, json);
    }
}

/// Compare two semver strings, prerelease-aware. Returns true if `a` is newer
/// than `b`. Per semver: `2.2.0 > 2.2.0-dev.3 > 2.2.0-dev.2 > 2.1.0`.
pub fn semver_gt(a: &str, b: &str) -> bool {
    fn parse(s: &str) -> ((u32, u32, u32), Option<&str>) {
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let mut parts = core.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
        (
            (
                parts.next().unwrap_or(0),
                parts.next().unwrap_or(0),
                parts.next().unwrap_or(0),
            ),
            pre,
        )
    }
    let ((ca, pa), (cb, pb)) = (parse(a), parse(b));
    if ca != cb {
        return ca > cb;
    }
    match (pa, pb) {
        (None, None) => false,
        (None, Some(_)) => true,  // release > its prereleases
        (Some(_), None) => false, // prerelease < the release
        (Some(pa), Some(pb)) => prerelease_gt(pa, pb),
    }
}

/// Semver §11 prerelease ordering: dot-separated identifiers, numeric compared
/// numerically and lower than alphanumeric; more identifiers wins a tie.
fn prerelease_gt(a: &str, b: &str) -> bool {
    let mut ia = a.split('.');
    let mut ib = b.split('.');
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return false,
            (Some(_), None) => return true,
            (None, Some(_)) => return false,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                match ord {
                    std::cmp::Ordering::Equal => continue,
                    std::cmp::Ordering::Greater => return true,
                    std::cmp::Ordering::Less => return false,
                }
            }
        }
    }
}

/// Banner update check: GitHub latest-release lookup with a 24h on-disk cache.
/// Returns the newer version if one exists; silent on any error.
pub fn check_for_update() -> Option<String> {
    let cache_path = dotmage_client::config::Config::default_dir().join("update_check.json");

    #[derive(serde::Serialize, serde::Deserialize)]
    struct UpdateCache {
        checked_at: u64,
        latest_version: String,
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    if let Ok(data) = std::fs::read_to_string(&cache_path) {
        if let Ok(cache) = serde_json::from_str::<UpdateCache>(&data) {
            if now.saturating_sub(cache.checked_at) < 86400 {
                return if semver_gt(&cache.latest_version, CURRENT) {
                    Some(cache.latest_version)
                } else {
                    None
                };
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;

    let resp = client
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .header("User-Agent", "dmage-cli")
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    #[derive(serde::Deserialize)]
    struct GhRelease {
        tag_name: String,
    }

    let release: GhRelease = resp.json().ok()?;
    let latest = release.tag_name.trim_start_matches('v').to_string();

    let cache = UpdateCache {
        checked_at: now,
        latest_version: latest.clone(),
    };
    if let Ok(json) = serde_json::to_string(&cache) {
        let _ = std::fs::write(&cache_path, json);
    }

    if semver_gt(&latest, CURRENT) {
        Some(latest)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_ordering() {
        assert!(semver_gt("1.10.0", "1.9.0"));
        assert!(semver_gt("2.0.0", "1.99.99"));
        assert!(!semver_gt("1.2.1", "1.2.1"));
        assert!(!semver_gt("1.2.0", "1.2.1"));
        // prerelease ordering (semver §11): 2.2.0 > 2.2.0-dev.3 > 2.2.0-dev.2 > 2.1.0
        assert!(semver_gt("2.2.0", "2.2.0-dev.3"));
        assert!(!semver_gt("2.2.0-dev.3", "2.2.0"));
        assert!(semver_gt("2.2.0-dev.3", "2.2.0-dev.2"));
        assert!(semver_gt("2.2.0-dev.10", "2.2.0-dev.9")); // numeric, not lexical
        assert!(semver_gt("2.2.0-dev.1", "2.1.0"));
        assert!(!semver_gt("2.2.0-dev.1", "2.2.0-dev.1"));
        assert!(semver_gt("2.2.0-dev.1.1", "2.2.0-dev.1")); // more identifiers wins
    }

    #[test]
    fn sha256sums_parsing() {
        let sums = "abc123  dmage-linux-x86_64\ndef456  dmage-macos-aarch64\n";
        assert_eq!(
            parse_sha256sums(sums, "dmage-macos-aarch64").as_deref(),
            Some("def456")
        );
        assert_eq!(parse_sha256sums(sums, "missing"), None);
        // BSD-style "*name" marker
        let bsd = "abc123 *dmage-linux-x86_64\n";
        assert_eq!(
            parse_sha256sums(bsd, "dmage-linux-x86_64").as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn managed_paths_detected() {
        assert!(
            managed_install_hint(Path::new("/opt/homebrew/Cellar/dotmage/1.2.1/bin/dmage"))
                .is_some()
        );
        assert!(managed_install_hint(Path::new("/Users/x/.cargo/bin/dmage")).is_some());
        assert!(managed_install_hint(Path::new("/x/target/debug/dmage")).is_some());
        assert!(managed_install_hint(Path::new("/usr/local/bin/dmage")).is_none());
    }
}
