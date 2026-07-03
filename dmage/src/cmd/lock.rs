//! `dmage lock` / `dmage logout` — clear keychain / tokens.

use dotmage_client::keychain;
use dotmage_client::token;

use super::{CliError, Context};

/// Server URL-ids to act on: the resolved one, or all configured with --all.
fn target_ids(ctx: &Context, all: bool) -> Vec<(String, String)> {
    if all && !ctx.config.servers.is_empty() {
        ctx.config
            .servers
            .iter()
            .map(|(name, e)| (name.clone(), e.url.clone()))
            .collect()
    } else {
        let name = ctx
            .server
            .as_ref()
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| "local".into());
        vec![(name, ctx.config.server_id())]
    }
}

pub fn run(ctx: &Context, all: bool) -> Result<(), CliError> {
    for (name, id) in target_ids(ctx, all) {
        let server_hash = keychain::server_hash(&id);
        keychain::delete_ak(&server_hash).map_err(|e| CliError::Keychain(e.to_string()))?;
        if ctx.config.servers.len() > 1 {
            ctx.print(&format!("Key removed from keychain ({name})."));
        } else {
            ctx.print("Key removed from keychain.");
        }
    }
    Ok(())
}

pub fn run_logout(ctx: &Context, all: bool) -> Result<(), CliError> {
    for (name, id) in target_ids(ctx, all) {
        let server_hash = keychain::server_hash(&id);
        keychain::delete_ak(&server_hash).map_err(|e| CliError::Keychain(e.to_string()))?;
        token::delete_tokens(&server_hash)
            .map_err(|e: token::TokenError| CliError::Other(e.to_string()))?;
        if ctx.config.servers.len() > 1 {
            ctx.print(&format!("Logged out of '{name}' on this device."));
        } else {
            ctx.print("Logged out on this device.");
        }
    }
    Ok(())
}
