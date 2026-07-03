//! `dmage status` — show sync status.

use dotmage_client::config::{contract_tilde, ResolvedVia};

use super::{host_of, CliError, Context};

pub fn run(ctx: &Context) -> Result<(), CliError> {
    if let (Some((name, via)), Some(url)) = (&ctx.server, &ctx.config.server_url) {
        if ctx.config.servers.len() > 1 {
            let why = match via {
                ResolvedVia::Flag => "--server flag".to_string(),
                ResolvedVia::EnvVar => "DOTMAGE_SERVER".to_string(),
                ResolvedVia::PathMatch(p) => format!("matched path {}", contract_tilde(p)),
                ResolvedVia::ActiveDefault => "default".to_string(),
                ResolvedVia::CiToken => "CI token".to_string(),
            };
            println!("server: {name} ({}) — {why}", host_of(url));
        } else {
            println!("server: {}", host_of(url));
        }
    }

    let apps = ctx.backend.list_apps()?;

    if apps.is_empty() {
        ctx.print("no apps");
        return Ok(());
    }

    println!("{:<16} {:<8} {:<10} UPDATED", "APP", "ENV", "LATEST");
    for app in &apps {
        let envs = ctx.backend.list_envs(&app.name)?;
        for env in &envs {
            println!(
                "{:<16} {:<8} rev {:<6} {}",
                app.name,
                env.name,
                env.latest_rev,
                if env.updated_at.is_empty() {
                    "-"
                } else {
                    &env.updated_at[..std::cmp::min(19, env.updated_at.len())]
                }
            );
        }
    }
    Ok(())
}
