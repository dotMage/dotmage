//! `dmage open` — open the web admin panel in the browser, already logged in.
//!
//! Resolves the server like push/pull, asks `/health` where the admin panel
//! lives, mints a one-time 5-min login token (the same enrollment token as
//! `dmage token`), and opens the browser at `{web}/#token=…`. The token rides
//! in the URL *fragment*, not the query: fragments never reach the server (so
//! they stay out of access logs), and the web app strips it from history on
//! load. It's single-use and short-lived regardless.

use dotmage_client::backend_http::HttpBackend;
use dotmage_client::types::HealthInfo;

use super::{CliError, Context};

pub fn run(ctx: &Context, print: bool) -> Result<(), CliError> {
    let backend = ctx
        .backend
        .as_any()
        .downcast_ref::<HttpBackend>()
        .ok_or_else(|| {
            CliError::Other("no server configured (local mode) — nothing to open".into())
        })?;
    let server_url = ctx
        .config
        .server_url
        .as_deref()
        .ok_or_else(|| CliError::Other("no server configured — run: dmage auth".into()))?;

    let health = backend.health()?;
    let web_base = resolve_web_url(server_url, &health);
    let (token, _expires_at) = backend.gen_enroll_token("web-admin", "5m")?;
    let url = format!("{web_base}/#token={token}");

    // The URL carries a one-time, 5-min login token. Printing it is the
    // headless/SSH path — copy it into a browser on your own machine.
    if print {
        println!("{url}");
        return Ok(());
    }

    match open_browser(&url) {
        Ok(()) => {
            ctx.success(&format!("Opening admin panel — {web_base}"));
            ctx.print("Logging you in automatically (one-time link, valid 5 min).");
        }
        Err(e) => {
            ctx.print(&format!(
                "Couldn't launch a browser ({e}). Open this link yourself (one-time, 5 min):"
            ));
            println!("\n  {url}\n");
        }
    }
    Ok(())
}

/// Build the admin panel base URL the browser should open.
///
/// Priority:
/// 1. `web_url` override — the only reliable signal for a reverse proxy
///    (subpath, subdomain, custom port). Set via `DOTMAGE_WEB_URL`.
/// 2. A TLS endpoint on the default port (`https://host`, no explicit port) is
///    almost certainly behind a proxy that terminates TLS and serves the panel
///    at the *same origin*. Open that origin — appending `:web_port` (9471)
///    would hit a closed port, which is exactly what domain users ran into.
/// 3. A direct deployment (plain `http`, or an explicit API port on the host):
///    the web container listens on `web_port` on that same host.
/// 4. Nothing to go on — open the origin the CLI already talks to.
fn resolve_web_url(server_url: &str, health: &HealthInfo) -> String {
    let server_url = server_url.trim_end_matches('/');

    if let Some(url) = health.web_url.as_deref() {
        if !url.is_empty() {
            return url.trim_end_matches('/').to_string();
        }
    }

    let (scheme, rest) = server_url.split_once("://").unwrap_or(("http", server_url));
    let authority = rest.split('/').next().unwrap_or(rest);
    let host_port = authority.rsplit_once(':');
    let explicit_port = host_port.and_then(|(_, p)| p.parse::<u16>().ok());
    let host = host_port.map_or(authority, |(h, _)| h);

    // A reverse proxy can't be probed for topology, so treat a bare HTTPS host
    // as same-origin and never guess a port for it. `DOTMAGE_WEB_URL` is the
    // escape hatch for panels on a subpath/subdomain.
    if scheme == "https" && explicit_port.is_none_or(|p| p == 443) {
        return format!("https://{host}");
    }

    if let Some(port) = health.web_port {
        return format!("{scheme}://{host}:{port}");
    }

    format!("{scheme}://{authority}")
}

#[cfg(target_os = "macos")]
fn open_browser(url: &str) -> Result<(), CliError> {
    spawn_opener("open", &[url])
}

#[cfg(target_os = "linux")]
fn open_browser(url: &str) -> Result<(), CliError> {
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err(CliError::Other("no display (headless session)".into()));
    }
    spawn_opener("xdg-open", &[url])
}

#[cfg(target_os = "windows")]
fn open_browser(url: &str) -> Result<(), CliError> {
    // `start` is a cmd builtin; the empty "" is its window-title argument.
    spawn_opener("cmd", &["/C", "start", "", url])
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn open_browser(_url: &str) -> Result<(), CliError> {
    Err(CliError::Other("unsupported platform".into()))
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn spawn_opener(cmd: &str, args: &[&str]) -> Result<(), CliError> {
    use std::process::{Command, Stdio};
    let status = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| CliError::Other(e.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Other(format!("{cmd} exited with {status}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(web_url: Option<&str>, web_port: Option<u16>) -> HealthInfo {
        HealthInfo {
            status: "ok".into(),
            version: "2.0.0".into(),
            account_exists: true,
            features: vec![],
            server_name: None,
            web_url: web_url.map(str::to_string),
            web_port,
        }
    }

    #[test]
    fn web_url_override_wins() {
        let h = health(Some("https://admin.corp.com/"), Some(9471));
        assert_eq!(
            resolve_web_url("http://h:9470", &h),
            "https://admin.corp.com"
        );
    }

    #[test]
    fn web_port_reuses_cli_host_on_direct_http() {
        // Direct docker deployment: API on one port, web on web_port, same host.
        let h = health(None, Some(9471));
        assert_eq!(
            resolve_web_url("http://1.2.3.4:9470", &h),
            "http://1.2.3.4:9471"
        );
    }

    #[test]
    fn https_domain_opens_same_origin() {
        // The domain bug: a TLS host behind a proxy — never append web_port.
        let h = health(None, Some(9471));
        assert_eq!(
            resolve_web_url("https://secrets.corp.com", &h),
            "https://secrets.corp.com"
        );
        assert_eq!(
            resolve_web_url("https://secrets.corp.com/", &h),
            "https://secrets.corp.com"
        );
        // An explicit :443 is still the default TLS port → same origin.
        assert_eq!(
            resolve_web_url("https://secrets.corp.com:443", &h),
            "https://secrets.corp.com"
        );
    }

    #[test]
    fn web_url_override_beats_https_heuristic() {
        // A panel on a subpath still resolves, because the override wins.
        let h = health(Some("https://secrets.corp.com/admin"), Some(9471));
        assert_eq!(
            resolve_web_url("https://secrets.corp.com", &h),
            "https://secrets.corp.com/admin"
        );
    }

    #[test]
    fn falls_back_to_origin() {
        let h = health(None, None);
        assert_eq!(
            resolve_web_url("http://1.2.3.4:9470/", &h),
            "http://1.2.3.4:9470"
        );
    }
}
