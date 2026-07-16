//! `dmage env` — manage environments.

use dotmage_client::container;
use dotmage_client::types::RevSpec;
use dotmage_crypto::blob;
use dotmage_crypto::secret;

use super::{CliError, Context};

pub enum EnvCmd {
    List(String),
    New(String, String, Option<String>),
    Rm(String, String, bool),
}

pub fn run(ctx: &mut Context, action: Option<EnvCmd>) -> Result<(), CliError> {
    match action {
        None => {
            // Show active environment
            println!("active: {}", ctx.active_env);
            Ok(())
        }
        Some(EnvCmd::List(app)) => {
            let envs = ctx.backend.list_envs(&app)?;
            if envs.is_empty() {
                ctx.print("no environments");
                return Ok(());
            }
            println!("{:<12} {:<10} UPDATED", "NAME", "LATEST");
            for env in &envs {
                let marker = if env.name == ctx.active_env { " *" } else { "" };
                println!(
                    "{:<12} rev {:<6} {}{}",
                    env.name,
                    env.latest_rev,
                    if env.updated_at.is_empty() {
                        "-"
                    } else {
                        &env.updated_at[..std::cmp::min(19, env.updated_at.len())]
                    },
                    marker,
                );
            }
            Ok(())
        }
        Some(EnvCmd::New(app, name, copy_from)) => {
            // Copy happens client-side: blobs are AEAD-bound to app|env|rev,
            // so the server can't re-bind ciphertext to a new environment —
            // we decrypt the source here and re-encrypt for the new env.
            let source = match copy_from {
                None => None,
                Some(src) => {
                    let envs = ctx.backend.list_envs(&app)?;
                    let info = envs.iter().find(|e| e.name == src).ok_or_else(|| {
                        CliError::Other(format!("source env '{src}' not found in app '{app}'"))
                    })?;
                    if info.latest_rev == 0 {
                        None // empty source — nothing to copy
                    } else {
                        let (_, decoded) = ctx.pull_decoded_in(&app, &src, &RevSpec::Latest)?;
                        Some((src, decoded))
                    }
                }
            };

            ctx.backend.create_env(&app, &name)?;

            match source {
                None => {
                    ctx.print(&format!("Created environment '{name}' in app '{app}'."));
                }
                Some((src, decoded)) => {
                    let ak = ctx.require_ak()?;
                    let payload = container::encode(&decoded.meta, &decoded.data);
                    let encrypted = secret::encrypt_secret(&ak, &payload, &app, &name, 1)
                        .map_err(|e| CliError::Crypto(e.to_string()))?;
                    ctx.backend
                        .push_revision(&app, &name, &blob::encode_blob(&encrypted), 0)?;
                    ctx.success(&format!(
                        "Created environment '{name}' in app '{app}' (rev 1 copied from '{src}')."
                    ));
                }
            }
            Ok(())
        }
        Some(EnvCmd::Rm(app, name, yes)) => {
            if ctx.config.is_protected_env(&name) && !yes {
                eprint!("This will DELETE protected env '{name}'. Type '{name}' to confirm: ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim() != name {
                    return Err(CliError::Other("aborted".into()));
                }
            } else if !yes {
                eprint!("Delete env '{name}' from '{app}'? [y/N] ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    return Err(CliError::Other("aborted".into()));
                }
            }

            ctx.backend.delete_env(&app, &name)?;
            ctx.print(&format!("Deleted environment '{name}' from app '{app}'."));
            Ok(())
        }
    }
}
