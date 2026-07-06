//! `dmage clean` — wipe local dotMage data from this device.
//!
//! Without `--server` this wipes EVERYTHING (all servers + config + local
//! storage). To remove a single server, `--server <name>` scopes it — or use
//! `dmage server rm <name>`, which does the same per-server wipe.

use dotmage_client::config::Config;
use dotmage_client::keychain;
use dotmage_client::token;

use super::{CliError, Context};

pub fn run(ctx: &Context, server: Option<&str>) -> Result<(), CliError> {
    match server {
        Some(name) => clean_one(ctx, name),
        None => clean_all(ctx),
    }
}

/// Scoped wipe: one server's cached key + tokens + config entry. Other servers
/// and the active default are left intact.
fn clean_one(ctx: &Context, name: &str) -> Result<(), CliError> {
    let entry = ctx
        .config
        .servers
        .get(name)
        .ok_or_else(|| {
            let known: Vec<_> = ctx.config.servers.keys().cloned().collect();
            CliError::Other(format!(
                "unknown server '{name}' — known: {}",
                known.join(", ")
            ))
        })?
        .clone();

    eprint!(
        "  Wipe server '{name}' ({}) from this device? [y/N] ",
        entry.url
    );
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        return Err(CliError::Other("aborted".into()));
    }

    let hash = keychain::server_hash(&entry.url);
    let _ = keychain::delete_ak(&hash);
    let _ = token::delete_tokens(&hash);

    let mut config = ctx.config.clone();
    config.servers.remove(name);
    if config.active_server.as_deref() == Some(name) {
        config.active_server = if config.servers.len() == 1 {
            config.servers.keys().next().cloned()
        } else {
            None
        };
    }
    config.save().map_err(|e| CliError::Config(e.to_string()))?;

    ctx.success(&format!("removed server '{name}' from this device"));
    if config.active_server.is_none() && !config.servers.is_empty() {
        ctx.print("no default server — pick one: dmage server use <name>");
    }
    Ok(())
}

/// Global wipe: everything.
fn clean_all(ctx: &Context) -> Result<(), CliError> {
    let config_dir = Config::default_dir();

    let server_count = ctx.config.servers.len();
    if server_count > 1 {
        eprintln!(
            "\x1b[33m  note:\x1b[0m you have {server_count} servers. This wipes ALL of them."
        );
        eprintln!("  \x1b[90mto remove just one: dmage server rm <name>  (or: dmage clean --server <name>)\x1b[0m");
    }

    eprint!(
        "\x1b[33m  This will delete ALL local dotMage data:\x1b[0m\n\
         \x1b[90m  - Cached keys (every server)\n\
         - Device tokens (every server)\n\
         - Config (server list, mappings)\n\
         - Local storage\x1b[0m\n\
         \n\
         Type 'yes' to confirm: "
    );

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("  aborted");
        return Ok(());
    }

    // Delete AKs for every configured server + local mode (belt and braces —
    // the config-dir removal below covers the default layout).
    for entry in ctx.config.servers.values() {
        let _ = keychain::delete_ak(&keychain::server_hash(&entry.url));
    }
    let _ = keychain::delete_ak(&keychain::server_hash(&ctx.config.server_id()));

    // Delete entire config directory
    if config_dir.exists() {
        std::fs::remove_dir_all(&config_dir)?;
    }

    println!("\x1b[32m  ✓\x1b[0m All local data removed.");
    Ok(())
}
