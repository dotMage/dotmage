//! `dmage server` — manage named servers and their directory mappings.

use dotmage_client::config::{contract_tilde, expand_tilde};
use dotmage_client::keychain;
use dotmage_client::token;

use super::{host_of, CliError, Context};

pub enum ServerCmd {
    List,
    Add {
        name: String,
        url: String,
        paths: Vec<String>,
    },
    Map {
        name: String,
        path: String,
    },
    Unmap {
        name: String,
        path: String,
    },
    Rm {
        name: String,
        yes: bool,
    },
    Use {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
}

pub fn run(ctx: &mut Context, cmd: ServerCmd) -> Result<(), CliError> {
    match cmd {
        ServerCmd::List => list(ctx),
        ServerCmd::Add { name, url, paths } => add(ctx, &name, &url, paths),
        ServerCmd::Map { name, path } => map(ctx, &name, &path),
        ServerCmd::Unmap { name, path } => unmap(ctx, &name, &path),
        ServerCmd::Rm { name, yes } => rm(ctx, &name, yes),
        ServerCmd::Use { name } => set_use(ctx, &name),
        ServerCmd::Rename { old, new } => rename(ctx, &old, &new),
    }
}

/// Auth state of a server, probed from local credential stores.
pub fn auth_state(url: &str) -> &'static str {
    let hash = keychain::server_hash(url);
    let has_ak = keychain::load_ak(&hash).ok().flatten().is_some();
    if has_ak {
        return "\x1b[32m● authenticated\x1b[0m";
    }
    let has_token = token::load_tokens(&hash).ok().flatten().is_some();
    if has_token {
        "\x1b[33m● locked (run: dmage auth)\x1b[0m"
    } else {
        "\x1b[31m● not connected\x1b[0m"
    }
}

fn list(ctx: &Context) -> Result<(), CliError> {
    if ctx.config.servers.is_empty() {
        ctx.print("no servers configured (local mode) — add one: dmage auth --server <url>");
        return Ok(());
    }
    for (name, entry) in &ctx.config.servers {
        let marker = if ctx.config.active_server.as_deref() == Some(name) {
            "*"
        } else {
            " "
        };
        let paths = if entry.paths.is_empty() {
            String::new()
        } else {
            format!("   \x1b[90m{}\x1b[0m", entry.paths.join(", "))
        };
        println!(
            "  {marker} {name:<12} {:<28} {}{paths}",
            host_of(&entry.url),
            auth_state(&entry.url)
        );
    }
    Ok(())
}

fn add(ctx: &mut Context, name: &str, url: &str, paths: Vec<String>) -> Result<(), CliError> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(CliError::Other(format!("'{url}' is not a URL")));
    }
    let existed = ctx.config.servers.contains_key(name);
    let entry = ctx.config.servers.entry(name.to_string()).or_default();
    entry.url = url.to_string();
    for p in paths {
        let normalized = normalize_path(&p);
        if !entry.paths.contains(&normalized) {
            entry.paths.push(normalized);
        }
    }
    if ctx.config.active_server.is_none() {
        ctx.config.active_server = Some(name.to_string());
    }
    ctx.config
        .save()
        .map_err(|e| CliError::Config(e.to_string()))?;
    ctx.success(&format!(
        "{} server '{name}' → {}",
        if existed { "updated" } else { "added" },
        host_of(url)
    ));
    if !existed {
        ctx.print(&format!("authenticate with: dmage auth --server {name}"));
    }
    Ok(())
}

fn map(ctx: &mut Context, name: &str, path: &str) -> Result<(), CliError> {
    ensure_known(ctx, name)?;
    let normalized = normalize_path(path);

    for (other, entry) in &ctx.config.servers {
        if other != name && entry.paths.contains(&normalized) {
            ctx.print(&format!(
                "\x1b[33mwarning:\x1b[0m {normalized} is already mapped to '{other}' — longest prefix wins at resolve time"
            ));
        }
    }

    let entry = ctx.config.servers.get_mut(name).unwrap();
    if entry.paths.contains(&normalized) {
        ctx.print(&format!("{normalized} is already mapped to '{name}'"));
        return Ok(());
    }
    entry.paths.push(normalized.clone());
    ctx.config
        .save()
        .map_err(|e| CliError::Config(e.to_string()))?;
    ctx.success(&format!("{normalized} → {name}"));
    Ok(())
}

fn unmap(ctx: &mut Context, name: &str, path: &str) -> Result<(), CliError> {
    ensure_known(ctx, name)?;
    let normalized = normalize_path(path);
    let entry = ctx.config.servers.get_mut(name).unwrap();
    let before = entry.paths.len();
    entry.paths.retain(|p| p != &normalized && p != path);
    if entry.paths.len() == before {
        return Err(CliError::Other(format!(
            "'{name}' has no mapping for {normalized}"
        )));
    }
    ctx.config
        .save()
        .map_err(|e| CliError::Config(e.to_string()))?;
    ctx.success(&format!("unmapped {normalized} from '{name}'"));
    Ok(())
}

fn rm(ctx: &mut Context, name: &str, yes: bool) -> Result<(), CliError> {
    ensure_known(ctx, name)?;
    if !yes {
        eprint!("  Remove server '{name}' (local tokens + cached key are wiped)? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            return Err(CliError::Other("aborted".into()));
        }
    }

    let entry = ctx.config.servers.remove(name).unwrap();

    // Wipe credentials only if no other server shares this URL (shared server_hash).
    let url_shared = ctx.config.servers.values().any(|e| e.url == entry.url);
    if !url_shared {
        let hash = keychain::server_hash(&entry.url);
        let _ = keychain::delete_ak(&hash);
        let _ = token::delete_tokens(&hash);
    }

    if ctx.config.active_server.as_deref() == Some(name) {
        ctx.config.active_server = None;
        if ctx.config.servers.len() == 1 {
            // exactly one left — make it the default so resolution stays unambiguous
            ctx.config.active_server = ctx.config.servers.keys().next().cloned();
        }
    }
    ctx.config
        .save()
        .map_err(|e| CliError::Config(e.to_string()))?;
    ctx.success(&format!("removed server '{name}'"));
    if ctx.config.active_server.is_none() && !ctx.config.servers.is_empty() {
        ctx.print("no default server — pick one: dmage server use <name>");
    }
    Ok(())
}

fn set_use(ctx: &mut Context, name: &str) -> Result<(), CliError> {
    ensure_known(ctx, name)?;
    ctx.config.active_server = Some(name.to_string());
    ctx.config
        .save()
        .map_err(|e| CliError::Config(e.to_string()))?;
    ctx.success(&format!("default server: {name}"));
    Ok(())
}

fn rename(ctx: &mut Context, old: &str, new: &str) -> Result<(), CliError> {
    ensure_known(ctx, old)?;
    if ctx.config.servers.contains_key(new) {
        return Err(CliError::Other(format!("server '{new}' already exists")));
    }
    let entry = ctx.config.servers.remove(old).unwrap();
    ctx.config.servers.insert(new.to_string(), entry);
    if ctx.config.active_server.as_deref() == Some(old) {
        ctx.config.active_server = Some(new.to_string());
    }
    ctx.config
        .save()
        .map_err(|e| CliError::Config(e.to_string()))?;
    ctx.success(&format!("renamed '{old}' → '{new}'"));
    Ok(())
}

fn ensure_known(ctx: &Context, name: &str) -> Result<(), CliError> {
    if ctx.config.servers.contains_key(name) {
        return Ok(());
    }
    Err(CliError::Other(format!(
        "unknown server '{name}' — known: {}",
        ctx.config
            .servers
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

/// Absolute-ize and `~`-contract a path for stable storage in config.toml.
fn normalize_path(p: &str) -> String {
    let expanded = expand_tilde(p);
    let abs = if expanded.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(&expanded))
            .unwrap_or(expanded)
    } else {
        expanded
    };
    let canon = abs.canonicalize().unwrap_or(abs);
    contract_tilde(&canon)
}
