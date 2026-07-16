//! `dmage apps` — list all applications.

use dotmage_client::types::AppInfo;

use super::{CliError, Context};

pub fn run(ctx: &Context) -> Result<(), CliError> {
    let mut apps = ctx.backend.list_apps()?;
    apps.sort_by(|a, b| a.name.cmp(&b.name));

    if ctx.json {
        println!("{}", render_json(&apps));
        return Ok(());
    }

    if apps.is_empty() {
        ctx.print("no apps");
        return Ok(());
    }

    let mut current_folder: Option<&str> = None;
    let mut first = true;

    for app in &apps {
        let (folder, short_name) = match app.name.rsplit_once('/') {
            Some((f, n)) => (Some(f), n),
            None => (None, app.name.as_str()),
        };

        // Print folder header if changed
        if folder != current_folder {
            if !first {
                println!();
            }
            if let Some(f) = folder {
                println!("  \x1b[36m{f}/\x1b[0m");
            }
            current_folder = folder;
        }

        let prefix = if folder.is_some() { "    " } else { "  " };
        let envs = app.environments.len();
        let updated = if app.updated_at.is_empty() {
            "-".to_string()
        } else {
            app.updated_at[..std::cmp::min(19, app.updated_at.len())].to_string()
        };
        println!("{prefix}{:<20} {envs:<3} envs   {updated}", short_name);
        first = false;
    }
    Ok(())
}

/// JSON contract (spec §5, semver): fields are spelled out here rather than
/// derived from the transport type, so transport changes can't leak into the
/// contract unnoticed.
fn render_json(apps: &[AppInfo]) -> String {
    let items: Vec<serde_json::Value> = apps
        .iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "environments": a.environments,
                "updated_at": a.updated_at,
            })
        })
        .collect();
    serde_json::to_string_pretty(&items).expect("json array serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_renders_as_empty_array() {
        assert_eq!(render_json(&[]), "[]");
    }

    #[test]
    fn contract_fields() {
        let apps = vec![AppInfo {
            name: "backend/api".into(),
            environments: vec!["dev".into(), "prod".into()],
            updated_at: "2026-07-16T10:00:00Z".into(),
        }];
        let v: serde_json::Value = serde_json::from_str(&render_json(&apps)).unwrap();
        assert_eq!(v[0]["name"], "backend/api");
        assert_eq!(v[0]["environments"][1], "prod");
        assert_eq!(v[0]["updated_at"], "2026-07-16T10:00:00Z");
    }
}
