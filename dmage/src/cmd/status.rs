//! `dmage status` — show sync status.

use dotmage_client::config::{contract_tilde, ResolvedVia};
use dotmage_client::types::EnvInfo;

use super::{host_of, CliError, Context};

pub fn run(ctx: &Context) -> Result<(), CliError> {
    if ctx.json {
        return run_json(ctx);
    }

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

fn run_json(ctx: &Context) -> Result<(), CliError> {
    let server = match (&ctx.server, &ctx.config.server_url) {
        (Some((name, via)), Some(url)) => Some((name.clone(), host_of(url), via)),
        _ => None,
    };

    let mut apps_out = Vec::new();
    for app in ctx.backend.list_apps()? {
        let envs = ctx.backend.list_envs(&app.name)?;
        apps_out.push((app.name, envs));
    }

    println!("{}", render_json(server, &apps_out));
    Ok(())
}

/// JSON contract (spec §5, semver) — fields spelled out, see apps.rs.
/// `resolved_via` vocabulary is part of the contract: flag|env|path|default|ci.
fn render_json(
    server: Option<(String, &str, &ResolvedVia)>,
    apps: &[(String, Vec<EnvInfo>)],
) -> String {
    let server_json = match server {
        None => serde_json::Value::Null,
        Some((name, host, via)) => {
            let via_str = match via {
                ResolvedVia::Flag => "flag",
                ResolvedVia::EnvVar => "env",
                ResolvedVia::PathMatch(_) => "path",
                ResolvedVia::ActiveDefault => "default",
                ResolvedVia::CiToken => "ci",
            };
            serde_json::json!({ "name": name, "host": host, "resolved_via": via_str })
        }
    };
    let apps_json: Vec<serde_json::Value> = apps
        .iter()
        .map(|(name, envs)| {
            serde_json::json!({
                "name": name,
                "environments": envs.iter().map(|e| serde_json::json!({
                    "name": e.name,
                    "latest_rev": e.latest_rev,
                    "updated_at": e.updated_at,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "server": server_json,
        "apps": apps_json,
    }))
    .expect("json object serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_mode_has_null_server_and_empty_apps() {
        let v: serde_json::Value = serde_json::from_str(&render_json(None, &[])).unwrap();
        assert!(v["server"].is_null());
        assert_eq!(v["apps"], serde_json::json!([]));
    }

    #[test]
    fn contract_fields() {
        let via = ResolvedVia::PathMatch("/x".into());
        let apps = vec![(
            "myapp".to_string(),
            vec![EnvInfo {
                name: "dev".into(),
                latest_rev: 7,
                updated_at: "2026-07-16T10:00:00Z".into(),
            }],
        )];
        let out = render_json(Some(("work".into(), "secrets.corp.com", &via)), &apps);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["server"]["resolved_via"], "path");
        assert_eq!(v["apps"][0]["environments"][0]["latest_rev"], 7);
    }
}
